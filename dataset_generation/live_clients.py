"""Run only inside the Compose lab; credentials are disposable local fixtures."""
import argparse
import imaplib
import poplib
import smtplib
import ssl
import time


def run(host, protocol, plaintext=False):
    if host not in {'hardened', 'imap_hardened', 'pop3_hardened', 'tls13_alt', 'cleartext_auth', 'imap_cleartext', 'pop3_cleartext', 'expired_cert', 'imap_expired', 'san_mismatch', 'self_signed', 'weak_key', 'sha1_sig', 'static_rsa', 'pop3_static_rsa', 'tls10_weak', 'tls11', 'starttls_stripped'}:
        raise ValueError('Choose a named, isolated Compose lab service.')
    # Insecure client verification is restricted to deliberately broken lab endpoints.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1
    context.set_ciphers('ALL:@SECLEVEL=0')
    if protocol == 'SMTP':
        with smtplib.SMTP(host, 25, timeout=10) as client:
            client.ehlo()
            if not plaintext:
                client.starttls(context=context); client.ehlo()
            client.login('demo', 'lab-only-password')
            client.sendmail('demo@example.test', ['demo@example.test'], 'Subject: Lab message\r\n\r\nSynthetic content only.')
    elif protocol == 'IMAP':
        with imaplib.IMAP4(host, 143, timeout=10) as client:
            if not plaintext:
                client.starttls(context)
            client.login('demo', 'lab-only-password'); client.select('INBOX'); client.search(None, 'ALL')
    else:
        client = poplib.POP3(host, 110, timeout=10)
        try:
            if not plaintext:
                client.stls(context=context)
            client.user('demo'); client.pass_('lab-only-password'); client.stat()
        finally:
            client.quit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('scenario')
    parser.add_argument('--protocol', choices=['SMTP', 'IMAP', 'POP3'], default='SMTP')
    parser.add_argument('--sessions', type=int, default=20)
    args = parser.parse_args()
    for i in range(args.sessions):
        try:
            run(args.scenario, args.protocol, 'cleartext' in args.scenario or args.scenario == 'starttls_stripped')
            print(f'Session {i + 1}: complete')
        except Exception as exc:
            print(f'Session {i + 1}: failed ({type(exc).__name__}); inspect captured negotiation evidence')
        time.sleep(.1 + (i % 5) * .05)
