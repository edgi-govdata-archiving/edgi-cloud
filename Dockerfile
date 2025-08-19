FROM python:3.11-slim

WORKDIR /app

# Copy and install requirements
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy application files
COPY metadata.json .
COPY plugins/ ./plugins/
COPY templates/ ./templates/
COPY static/ ./static/
COPY init_db.py .

# Create data directory
RUN mkdir -p /data && chmod 755 /data

# Environment variables
ENV PORT=8001
ENV EDGI_DATA_DIR=/data
ENV EDGI_STATIC_DIR=/static
ENV PORTAL_DB_PATH=/data/portal.db

EXPOSE 8001

# Create startup script
RUN echo '#!/bin/bash\n\
set -e\n\
echo "🚀 Starting EDGI Cloud Portal..."\n\
echo "📍 Data directory: $EDGI_DATA_DIR"\n\
echo "📍 Portal DB path: $PORTAL_DB_PATH"\n\
\n\
# Initialize database if needed\n\
if [ ! -f "$PORTAL_DB_PATH" ]; then\n\
  echo "🌱 Initializing database..."\n\
  python init_db.py\n\
  if [ -f "$PORTAL_DB_PATH" ]; then\n\
    echo "✅ Database created successfully"\n\
    echo "📊 Size: $(du -h $PORTAL_DB_PATH | cut -f1)"\n\
  else\n\
    echo "❌ Database creation failed"\n\
    exit 1\n\
  fi\n\
else\n\
  echo "📊 Using existing database"\n\
fi\n\
\n\
# Start Datasette\n\
echo "🚀 Starting Datasette..."\n\
exec datasette serve "$PORTAL_DB_PATH" \\\n\
  --host 0.0.0.0 \\\n\
  --port "$PORT" \\\n\
  --metadata metadata.json \\\n\
  --template-dir templates \\\n\
  --static static:static \\\n\
  --plugins-dir plugins\n\
' > /app/start.sh && chmod +x /app/start.sh

CMD ["/app/start.sh"]