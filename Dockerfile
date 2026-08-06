FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*
# /data is a bind mount (docker-compose.yml); git refuses to operate in it
# ("detected dubious ownership") unless explicitly told the ownership is
# fine. Baked into the image, not set ad-hoc in a running container, since
# root's $HOME/.gitconfig doesn't survive a container recreation. Wildcard
# (a real git-config value, not a glob) because multi-tenant mode creates a
# fresh repo under /data/tenants/<slug>/ per tenant -- enumerating exact
# paths here would need a rebuild every time a tenant is added.
RUN git config --system --add safe.directory '*'
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY atlas_mcp ./atlas_mcp
ENV ATLAS_ROOT=/data PORT=8787 PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 8787
HEALTHCHECK --interval=30s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8787/healthz')"
CMD ["python", "-m", "atlas_mcp.app"]
