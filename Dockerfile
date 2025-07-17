FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt /app
RUN pip install -r requirements.txt

# Create /data directory for persistent storage
RUN mkdir -p /data/static
COPY metadata.json /data/
COPY plugins/ /data/plugins/
COPY templates/ /data/templates/
COPY static/ /data/static/

ENV PORT=8001
EXPOSE 8001

CMD ["datasette", "serve", "/data/CAMPD.db", "--host", "0.0.0.0", "--port", "8001", "--metadata", "/data/metadata.json", "--template-dir", "/data/templates", "--plugins-dir", "/data/plugins", "--static", "static:/data/static"]