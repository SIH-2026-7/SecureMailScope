#!/bin/sh
set -eu
python3 /make_certificate.py
chmod 600 /etc/ssl/lab.key
id demo >/dev/null 2>&1 || useradd -m demo
echo 'demo:lab-only-password' | chpasswd
mkdir -p /home/demo/Maildir/new /home/demo/Maildir/cur /home/demo/Maildir/tmp
chown -R demo:demo /home/demo/Maildir
cat > /etc/dovecot/local.conf <<EOF
protocols = imap pop3
listen = *
mail_location = maildir:~/Maildir
disable_plaintext_auth = no
auth_mechanisms = plain login
ssl = yes
ssl_cert = </etc/ssl/lab.crt
ssl_key = </etc/ssl/lab.key
ssl_min_protocol = TLSv1.2
ssl_cipher_list = DEFAULT:@SECLEVEL=0
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
EOF
postconf -e "myhostname = ${HOSTNAME}.example.test" 'mydestination = $myhostname, localhost, example.test' 'inet_interfaces = all' 'home_mailbox = Maildir/' 'smtpd_sasl_type = dovecot' 'smtpd_sasl_path = private/auth' 'smtpd_sasl_auth_enable = yes' 'smtpd_tls_cert_file = /etc/ssl/lab.crt' 'smtpd_tls_key_file = /etc/ssl/lab.key' 'smtpd_tls_security_level = may' 'smtpd_tls_auth_only = yes' 'smtpd_tls_protocols = >=TLSv1.2' 'smtpd_tls_loglevel = 0'
case "$SCENARIO" in
  *cleartext*) postconf -e 'smtpd_tls_security_level = none' 'smtpd_tls_auth_only = no'; echo 'ssl = no' >> /etc/dovecot/local.conf ;;
  *hardened*|tls13_alt) postconf -e 'smtpd_tls_security_level = encrypt' 'smtpd_tls_mandatory_protocols = >=TLSv1.3'; echo 'ssl_min_protocol = TLSv1.3' >> /etc/dovecot/local.conf; echo 'disable_plaintext_auth = yes' >> /etc/dovecot/local.conf ;;
  tls10_weak|export_cipher|des_cipher) postconf -e 'smtpd_tls_protocols = TLSv1' 'tls_low_cipherlist = ALL:@SECLEVEL=0' 'smtpd_tls_ciphers = low'; echo 'ssl_min_protocol = TLSv1' >> /etc/dovecot/local.conf ;;
  tls11) postconf -e 'smtpd_tls_protocols = TLSv1.1'; echo 'ssl_min_protocol = TLSv1.1' >> /etc/dovecot/local.conf ;;
  *static_rsa*) postconf -e 'smtpd_tls_protocols = TLSv1.2' 'tls_medium_cipherlist = AES128-SHA:@SECLEVEL=0' 'smtpd_tls_ciphers = medium'; echo 'ssl_cipher_list = AES128-SHA:@SECLEVEL=0' >> /etc/dovecot/local.conf ;;
  *) postconf -e 'smtpd_tls_protocols = TLSv1.2' ;;
esac
dovecot
exec postfix start-fg
