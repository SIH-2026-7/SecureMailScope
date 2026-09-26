"""Validate corpus and train isolated candidate models; never overwrite deployed models."""
import argparse
import hashlib
import json
import pickle
import sys
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, average_precision_score, roc_auc_score
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from dataset_generation.build_training_corpus import RAW_FEATURES, FEATURES, PROFILES

def run(folder):
    d=pd.read_csv(folder/'dataset.csv')
    meta=json.loads((folder/'metadata.json').read_text())
    parts={n:pd.read_csv(folder/f'{n}.csv') for n in meta['split_counts']}
    assert len(d)>=25000 and len(d)==sum(map(len,parts.values()))
    assert not d[RAW_FEATURES].isna().any().any()
    assert np.isfinite(d[RAW_FEATURES].to_numpy()).all()
    assert d.session_id.is_unique and not d[RAW_FEATURES].duplicated().any()
    assert set(d.severity_label)==set(PROFILES)
    assert set(d.scenario)=={p for profiles in PROFILES.values() for p in profiles}
    for name,a in parts.items():
        assert set(a.severity_label)==set(PROFILES)
        assert set(a['split'])=={name}
        for other,b in parts.items():
            if name!=other:
                assert not set(a.configuration_group)&set(b.configuration_group)
                assert not set(a.feature_sha256)&set(b.feature_sha256)
    meta=json.loads((folder/'metadata.json').read_text())
    assert hashlib.sha256((folder/'dataset.csv').read_bytes()).hexdigest()==meta['dataset_sha256']
    t=parts['train'];test=parts['test']
    model=RandomForestClassifier(n_estimators=200,max_depth=14,min_samples_leaf=2,class_weight='balanced',random_state=26159,n_jobs=-1)
    model.fit(t[RAW_FEATURES],t.severity_label)
    anomaly=IsolationForest(n_estimators=200,contamination=.05,random_state=26159,n_jobs=-1)
    anomaly.fit(t.loc[t.severity_label=='Low',RAW_FEATURES])
    # Comparison exposes reliance of existing 23-input classifier on rule outputs.
    baseline=RandomForestClassifier(n_estimators=100,max_depth=14,min_samples_leaf=2,class_weight='balanced',random_state=26159,n_jobs=-1)
    baseline.fit(t[FEATURES],t.severity_label)
    metrics={'scope':'Synthetic configuration-group holdout; not real-world accuracy','validation_checks':'Passed row count, numeric schema, unique IDs/features, all classes, all profiles, split disjointness and checksum','recommended_features':RAW_FEATURES,'train_rows':len(t),'validation_rows':len(parts.get('validation',[])),'test_rows':len(test),'normal_training_rows':int((t.severity_label=='Low').sum())}
    for n,part in parts.items():
        if n=='train':continue
        pred=model.predict(part[RAW_FEATURES]);truth=part.severity_label
        anomaly_score=-anomaly.decision_function(part[RAW_FEATURES]);flags=anomaly.predict(part[RAW_FEATURES])==-1
        proxy=(truth!='Low').astype(int).to_numpy()
        metrics[n]={'random_forest':classification_report(truth,pred,output_dict=True,zero_division=0),'confusion_labels':['Low','Medium','High','Critical'],'confusion_matrix':confusion_matrix(truth,pred,labels=['Low','Medium','High','Critical']).tolist(),'anomaly_proxy_average_precision':float(average_precision_score(proxy,anomaly_score)),'anomaly_proxy_roc_auc':float(roc_auc_score(proxy,anomaly_score)),'anomaly_proxy_report':classification_report(proxy,flags.astype(int),output_dict=True,zero_division=0),'normal_false_positive_rate':float(flags[proxy==0].mean()),'precision_at_100':float(proxy[np.argsort(-anomaly_score)[:100]].mean())}
    metrics['dataset_sha256']=meta['dataset_sha256']
    metrics['test_used_for_tuning']=False
    metrics['isolation_forest_parameters']={'n_estimators':200,'contamination':0.05,'max_samples':256,'random_state':26159}
    metrics['legacy_23_feature_test']=classification_report(test.severity_label,baseline.predict(test[FEATURES]),output_dict=True,zero_division=0)
    metrics['feature_importances']=dict(sorted(zip(RAW_FEATURES,model.feature_importances_.tolist()),key=lambda x:-x[1]))
    metrics['limitations']=['Test scenarios belong to the same synthetic scenario families as training; deployment templates are held out.','Anomaly metrics use non-Low severity as a proxy, not independently labeled novel attacks.','Candidate models require the 28 listed inputs; current app supplies 23. No deployment or app-model replacement was performed.','The 23-feature comparison includes direct rule outputs and must not be cited as independent ML detection.']
    (folder/'evaluation.json').write_text(json.dumps(metrics,indent=2),encoding='utf-8')
    with (folder/'candidate_models.pkl').open('wb') as f:pickle.dump({'classifier':model,'anomaly':anomaly,'features':RAW_FEATURES,'status':'synthetic_candidate_not_deployed'},f)
    print(json.dumps({'checks':metrics['validation_checks'],'test_accuracy':metrics['test']['random_forest']['accuracy'],'test_macro_f1':metrics['test']['random_forest']['macro avg']['f1-score'],'anomaly_normal_false_positive_rate':metrics['test']['normal_false_positive_rate'],'anomaly_proxy_average_precision':metrics['test']['anomaly_proxy_average_precision']},indent=2))

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--folder',type=Path,default=ROOT/'output/ml_dataset_30k');run(ap.parse_args().folder)
