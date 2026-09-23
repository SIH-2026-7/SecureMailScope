FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends postfix dovecot-imapd dovecot-pop3d openssl python3 python3-cryptography tcpdump iproute2 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
COPY make_certificate.py /make_certificate.py
RUN chmod +x /entrypoint.sh
CMD ["/entrypoint.sh"]
