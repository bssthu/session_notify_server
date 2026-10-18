FROM nginx:1.30.5-alpine

# One deployment unit owns Nginx, ACME state, scheduling and reload. The root
# master/Certbot can preserve legacy key groups; Nginx workers remain unprivileged.
RUN apk add --no-cache python3 py3-pip openssl ca-certificates \
    && python3 -m venv /opt/certbot \
    && /opt/certbot/bin/pip install --no-cache-dir certbot==5.8.0
COPY gateway.py certbot_runner.py /opt/gateway/
ENV PATH="/opt/certbot/bin:$PATH" PYTHONUNBUFFERED=1
USER 0:0
ENTRYPOINT ["python", "/opt/gateway/gateway.py"]
CMD ["serve"]
