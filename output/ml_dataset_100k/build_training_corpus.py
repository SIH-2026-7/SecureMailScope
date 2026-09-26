"""Reproducible synthetic SESSION-LEVEL training corpus; not packet/live traffic.

Uses the application's SessionRecord, evaluate() and extract_features() contracts.
Scenario labels are specified before evaluation; rule findings validate consistency.
Run: backend/.venv/Scripts/python.exe dataset_generation/build_training_corpus.py
"""
import argparse
import csv
import hashlib
import json
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.models.schemas import SessionRecord
from backend.app.core.rule_engine import evaluate, ORDINAL
from backend.app.ml.features import FEATURES, extract_features

EXTRA_FEATURES = ['certificate_observed', 'tls_observed', 'certificate_expired', 'certificate_not_yet_valid', 'certificate_extensions_valid', 'certificate_weak_key', 'client_offered_higher_version']
RAW_FEATURES = [f for f in FEATURES if f not in ('num_rule_findings', 'max_finding_severity_ordinal')] + EXTRA_FEATURES
PROFILES = {
    'Low': ['modern_tls'],
    'Medium': ['self_signed', 'weak_signature', 'bad_extensions', 'lower_version', 'unused_starttls'],
    'High': ['expired', 'not_yet_valid', 'hostname_mismatch', 'weak_key', 'legacy_tls', 'static_rsa'],
    'Critical': ['obsolete_ssl', 'weak_cipher', 'auth_before_tls', 'failed_starttls'],
}
ORDER = {'Info': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
CIPHERS = ['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256']

def make_session(rng, label, index):
    profile = rng.choice(PROFILES[label])
    protocol = rng.choice(['SMTP', 'IMAP', 'POP3'])
    implicit = rng.choice([False, True]) if profile not in ('unused_starttls', 'failed_starttls', 'auth_before_tls') else False
    port = ({'SMTP':465,'IMAP':993,'POP3':995} if implicit else {'SMTP':587,'IMAP':143,'POP3':110})[protocol]
    sid = f'synthetic-{index:06d}'
    ev = dict(frame_no=1, timestamp=1789812000.0, stream_id=sid)
    version = 'TLS1.3' if profile in ('modern_tls', 'auth_before_tls') and rng.random() < .12 else 'TLS1.2'
    cipher = rng.choice(CIPHERS) if version == 'TLS1.2' else rng.choice(['TLS_AES_128_GCM_SHA256','TLS_AES_256_GCM_SHA384','TLS_CHACHA20_POLY1305_SHA256'])
    bits = rng.choice([2048,3072,4096])
    days = rng.randint(1,825)
    s = SessionRecord(session_id=sid,protocol=protocol,client_ip='192.0.2.10',server_ip='198.51.100.25',server_port=port,evidence=ev,complete=True,
        starttls_advertised=not implicit,starttls_requested=not implicit,starttls_used=not implicit,
        tls=dict(version=version,cipher_suite=cipher,offered_versions=[version],server_hello=True,encrypted_records_observed=True,ocsp_stapling_acknowledged=bool(rng.getrandbits(1))))
    if version != 'TLS1.3':
        s.certificate=dict(expired=False,not_yet_valid=False,hostname_match=True,trust_status='trusted',self_signed=False,weak_key=False,weak_signature=False,extensions_valid=True,
            days_until_expiry=days,key_bits=bits,chain=[{'synthetic':True} for _ in range(rng.choice([2,3,4]))],fingerprint_sha256=hashlib.sha256(sid.encode()).hexdigest(),evidence=ev)
    c=s.certificate
    if profile=='self_signed': c.update(self_signed=True,trust_status='validation_failed',chain=[{'synthetic':True}])
    elif profile=='weak_signature': c.update(weak_signature=True,trust_status='validation_failed')
    elif profile=='bad_extensions': c.update(extensions_valid=False,trust_status='validation_failed')
    elif profile=='lower_version': s.tls['offered_versions']=['TLS1.2','TLS1.3']
    elif profile in ('unused_starttls','failed_starttls'):
        s.certificate=None;s.tls={};s.starttls_used=False
        s.starttls_requested=profile=='failed_starttls'
        s.plaintext_after_starttls=profile=='failed_starttls'
        s.auth_before_tls=profile=='failed_starttls'
    elif profile=='expired': c.update(expired=True,days_until_expiry=-rng.randint(1,730),trust_status='validation_failed')
    elif profile=='not_yet_valid': c.update(not_yet_valid=True,trust_status='validation_failed')
    elif profile=='hostname_mismatch': c.update(hostname_match=False,trust_status='validation_failed')
    elif profile=='weak_key': c.update(weak_key=True,key_bits=rng.choice([1024,1536]))
    elif profile=='legacy_tls':
        s.tls.update(version=rng.choice(['TLS1.0','TLS1.1']),cipher_suite='TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',offered_versions=['TLS1.2'])
    elif profile=='static_rsa':s.tls['cipher_suite']=rng.choice(['TLS_RSA_WITH_AES_128_GCM_SHA256','TLS_RSA_WITH_AES_256_CBC_SHA'])
    elif profile=='obsolete_ssl':s.tls.update(version='SSLv3',offered_versions=['SSLv3'],cipher_suite='TLS_RSA_WITH_AES_128_CBC_SHA')
    elif profile=='weak_cipher':s.tls['cipher_suite']=rng.choice(['TLS_RSA_WITH_RC4_128_SHA','TLS_RSA_WITH_3DES_EDE_CBC_SHA','TLS_RSA_WITH_NULL_SHA','TLS_RSA_EXPORT_WITH_RC4_40_MD5'])
    elif profile=='auth_before_tls':s.auth_before_tls=True # exposed auth followed by a later successful TLS upgrade
    # This is structural metadata, not a fabricated packet or command transcript.
    s.commands=[{} for _ in range(rng.randint(8,180))]
    s.findings=evaluate(s)
    actual=max((f.severity for f in s.findings),key=ORDER.get,default='Low')
    assert actual==label,(profile,actual,label)
    return s,profile

def build(output, per_class=7500, seed=26159, train_fraction=None):
    if train_fraction is not None and not 0 < train_fraction < 1:
        raise ValueError("train_fraction must be between 0 and 1")
    output.mkdir(parents=True,exist_ok=True)
    rng=random.Random(seed);rows=[];seen=set();attempts=0
    for label in PROFILES:
        accepted=0
        split_accepted=Counter()
        quotas={"train":round(per_class*train_fraction),"test":per_class-round(per_class*train_fraction)} if train_fraction is not None else None
        while accepted<per_class:
            attempts+=1
            if attempts>per_class*200:raise RuntimeError('Diversity budget exhausted')
            s,profile=make_session(rng,label,len(rows)+1)
            f=dict(zip(FEATURES,extract_features(s)))
            c=s.certificate or {}
            f.update(certificate_observed=int(bool(c)),tls_observed=int(bool(s.tls.get('version'))),certificate_expired=int(c['expired']) if c else -1,certificate_not_yet_valid=int(c['not_yet_valid']) if c else -1,certificate_extensions_valid=int(c['extensions_valid']) if c else -1,certificate_weak_key=int(c['weak_key']) if c else -1,client_offered_higher_version=int(any(ORDINAL.get(v,-2)>ORDINAL.get(s.tls.get('version'),99) for v in s.tls.get('offered_versions',[]))))
            # Deduplicate features BEFORE labels/IDs/split metadata: no padding by IDs.
            signature=tuple(f[k] for k in RAW_FEATURES)
            if signature in seen:continue
            # Repeated deployment templates remain in exactly one split.
            config='|'.join(map(str,[profile,s.protocol,s.server_port,s.tls.get('version','none'),s.tls.get('cipher_suite','none'),(s.certificate or {}).get('key_bits',0),(s.certificate or {}).get('chain',[]).__len__()]))
            group=hashlib.sha256(config.encode()).hexdigest()[:16]
            bucket=int(group,16)%100
            split=('train' if bucket<round(train_fraction*100) else 'test') if train_fraction is not None else ('train' if bucket<70 else 'validation' if bucket<85 else 'test')
            if quotas and split_accepted[split]>=quotas[split]:continue
            seen.add(signature)
            split_accepted[split]+=1
            rows.append({**f,'severity_label':label,'scenario':profile,'session_id':s.session_id,'protocol':s.protocol,'server_port':s.server_port,'is_anomaly':int(label!='Low'),'finding_ids':'|'.join(x.rule_id for x in s.findings),'configuration_group':group,'split':split,'feature_sha256':hashlib.sha256(json.dumps(signature).encode()).hexdigest(),'provenance':'synthetic_session_metadata'})
            accepted+=1
        print(label,accepted,flush=True)
    rng.shuffle(rows)
    def write_csv(path, data):
        with path.open('w',newline='',encoding='utf-8') as f:
            w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(data)
    write_csv(output/'dataset.csv',rows)
    split_names=('train','test') if train_fraction is not None else ('train','validation','test')
    for split in split_names:
        subset=[r for r in rows if r['split']==split]
        assert set(r['severity_label'] for r in subset)==set(PROFILES)
        write_csv(output/f'{split}.csv',subset)
    meta={'schema_version':1,'seed':seed,'total_rows':len(rows),'unique_model_feature_vectors':len(seen),'features_compatible_with_app':FEATURES,'recommended_model_features':RAW_FEATURES,'exclude_from_model':['severity_label','is_anomaly','scenario','session_id','protocol','server_port','finding_ids','configuration_group','split','feature_sha256','provenance','num_rule_findings','max_finding_severity_ordinal'],'labels':dict(Counter(r['severity_label'] for r in rows)),'scenarios':dict(Counter(r['scenario'] for r in rows)),'split_counts':dict(Counter(r['split'] for r in rows)),'split_class_counts':{split:dict(Counter(r['severity_label'] for r in rows if r['split']==split)) for split in split_names},'dataset_sha256':hashlib.sha256((output/'dataset.csv').read_bytes()).hexdigest(),'limitations':['Synthetic session metadata, not independently observed live traffic or raw PCAP captures.','Certificate fields are simulated validator outputs; fingerprints are synthetic identifiers, not real certificate evidence.','Labels are predefined scenario-policy labels checked against existing rules; not independently expert-annotated real-world labels.','is_anomaly is a non-Low severity proxy, not ground truth for novelty or maliciousness.','Split holds out configuration groups, not entire scenario families.','28 recommended features omit two direct rule outputs and add seven observed evidence fields absent from the legacy 23-feature model.','TLS1.3 certificates remain absent. Incomplete sessions are excluded from severity training.','Low means no configured finding observed, not verified endpoint security.','Dataset diversity is simulated; record count is not evidence of real-world generalization.']}
    meta['split_policy']='Exact per-class quotas with disjoint configuration hash groups' if train_fraction is not None else 'Configuration hash groups, approximately 70/15/15'
    meta['train_fraction_requested']=train_fraction
    (output/'metadata.json').write_text(json.dumps(meta,indent=2),encoding='utf-8')
    assert len(rows)>=25000
    print(json.dumps({k:meta[k] for k in ('total_rows','unique_model_feature_vectors','split_counts','labels')},indent=2))

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,default=ROOT/'output/ml_dataset_30k');ap.add_argument('--per-class',type=int,default=7500);ap.add_argument('--seed',type=int,default=26159);ap.add_argument('--train-fraction',type=float,default=None);a=ap.parse_args();build(a.output,a.per_class,a.seed,a.train_fraction)
