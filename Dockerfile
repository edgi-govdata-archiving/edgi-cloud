FROM python:3.11-slim

WORKDIR /app

# Copy and install requirements first
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy only essential files to /app
COPY metadata.json .
COPY plugins/ ./plugins/
COPY templates/ ./templates/
COPY static/ ./static/
COPY portal.db .
COPY data/ ./data/

ENV PORT=8001
EXPOSE 8001

# Serve portal.db from /app and user databases from /data volume
CMD datasette serve portal.db --host 0.0.0.0 --port 8001 --metadata metadata.json --template-dir templates --static static:static --plugins-dir plugins