FROM debian:12-slim

RUN apt-get update -qq && apt-get install -y --no-install-recommends -qq \
        nginx-light openssh-server supervisor sudo \
        python3 python3-venv python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd /var/log/supervisor /var/www/evidence /opt/shared

RUN python3 -m venv /opt/venv
RUN /opt/venv/bin/pip install -q --no-cache-dir --retries 10 --timeout 120 \
        scapy==2.6.1 cryptography==43.0.3

COPY docker/generate_flags.py /opt/shared/generate_flags.py
COPY docker/flagcrypto.py /opt/shared/flagcrypto.py
COPY docker/make_evidence.py /opt/make_evidence.py
COPY docker/entrypoint.sh /opt/entrypoint.sh
COPY docker/supervisord.conf /etc/supervisor/conf.d/ctf.conf
COPY docker/nginx-default.conf /etc/nginx/sites-available/default
RUN chmod +x /opt/entrypoint.sh

RUN useradd -m -s /bin/bash svc-monitor

EXPOSE 22 80

ENTRYPOINT ["/opt/entrypoint.sh"]
