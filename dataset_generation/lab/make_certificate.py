import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

scenario = os.environ.get('SCENARIO', 'hardened')
hostname = os.environ.get('HOSTNAME', scenario)
key = rsa.generate_private_key(public_exponent=65537, key_size=1024 if scenario == 'weak_key' else 2048)
name = 'wrong.example.test' if scenario == 'san_mismatch' else hostname
subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
now = datetime.utcnow()
cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=365))
        .not_valid_after(now + timedelta(days=-1 if 'expired' in scenario else 180))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .sign(key, hashes.SHA1() if scenario == 'sha1_sig' else hashes.SHA256()))
open('/etc/ssl/lab.key', 'wb').write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
open('/etc/ssl/lab.crt', 'wb').write(cert.public_bytes(serialization.Encoding.PEM))
