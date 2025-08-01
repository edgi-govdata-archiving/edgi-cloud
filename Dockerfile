FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install -r requirements.txt

ENV PORT=8001
ENV EDGI_DATA_DIR=/data
ENV EDGI_STATIC_DIR=/app/static
ENV PORTAL_DB_PATH=/data/portal.db
ENV FLY_APP_NAME='edgi-cloud'

EXPOSE 8001

CMD ["datasette", "serve", "portal.db", "--host", "0.0.0.0", "--port", "8001", "--metadata", "metadata.json", "--template-dir", "templates", "--static", "static:static", "--plugins-dir", "plugins"]