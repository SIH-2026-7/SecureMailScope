from datetime import datetime, timezone
import ipaddress
import certifi
from functools import lru_cache
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError


@lru_cache(maxsize=1)
def trust_store():
    with open(certifi.where(), 'rb') as handle:
        return Store(x509.load_pem_x509_certificates(handle.read()))


def matches(pattern, hostname):
    pattern, hostname = pattern.lower().rstrip('.'), hostname.lower().rstrip('.')
    return pattern == hostname or (pattern.startswith('*.') and hostname.count('.') == pattern.count('.') and hostname.endswith(pattern[1:]))


def validate_certificates(ders, ev, hostname, timestamp):
    if not ders:
        return None
    certs = [x509.load_der_x509_certificate(der) for der in ders]
    leaf, when = certs[0], datetime.fromtimestamp(timestamp, timezone.utc)
    def extension(kind):
        try:
            return leaf.extensions.get_extension_for_class(kind).value
        except x509.ExtensionNotFound:
            return None
    san_ext = extension(x509.SubjectAlternativeName)
    sans = san_ext.get_values_for_type(x509.DNSName) if san_ext else []
    ip_sans = [str(ip) for ip in san_ext.get_values_for_type(x509.IPAddress)] if san_ext else []
    key = leaf.public_key()
    algorithm = leaf.signature_hash_algorithm
    signature = algorithm.name if algorithm else 'EdDSA'
    hostname_match = None if not hostname else any(matches(san, hostname) for san in sans) or hostname in ip_sans
    trust = 'unknown_no_hostname'
    if hostname:
        try:
            try:
                subject = x509.IPAddress(ipaddress.ip_address(hostname))
            except ValueError:
                subject = x509.DNSName(hostname)
            PolicyBuilder().store(trust_store()).time(when).build_server_verifier(subject).verify(leaf, certs[1:])
            trust = 'trusted'
        except (VerificationError, ValueError):
            trust = 'validation_failed'
    bc, eku = extension(x509.BasicConstraints), extension(x509.ExtendedKeyUsage)
    return dict(evidence=ev, fingerprint_sha256=leaf.fingerprint(hashes.SHA256()).hex(),
                subject=leaf.subject.rfc4514_string(), issuer=leaf.issuer.rfc4514_string(),
                sans=sans + ip_sans, hostname=hostname, hostname_match=hostname_match,
                not_before=leaf.not_valid_before_utc.isoformat(), not_after=leaf.not_valid_after_utc.isoformat(),
                expired=when > leaf.not_valid_after_utc, not_yet_valid=when < leaf.not_valid_before_utc,
                days_until_expiry=(leaf.not_valid_after_utc - when).days,
                key_type=type(key).__name__, key_bits=getattr(key, 'key_size', None),
                weak_key=isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048 or isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name not in ('secp256r1', 'secp384r1', 'secp521r1'),
                signature_algorithm=signature, weak_signature=signature.lower() in ('sha1', 'md5'),
                self_signed=leaf.subject == leaf.issuer, trust_status=trust,
                revocation_status='unknown_offline',
                extensions_valid=bool(bc is not None and not bc.ca and eku is not None and ExtendedKeyUsageOID.SERVER_AUTH in eku),
                chain=[dict(subject=c.subject.rfc4514_string(), issuer=c.issuer.rfc4514_string(), fingerprint_sha256=c.fingerprint(hashes.SHA256()).hex()) for c in certs])
