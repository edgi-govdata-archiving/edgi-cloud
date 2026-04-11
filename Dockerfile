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
COPY migrate_db.py .

# Create data directory
RUN mkdir -p /data && chmod 755 /data

# Environment variables
ENV PORT=8001
ENV RESETTE_DATA_DIR=/data
ENV RESETTE_STATIC_DIR=/static
ENV PORTAL_DB_PATH=/data/portal.db

EXPOSE 8001

# Create startup script with dynamic metadata generation and extended timeouts
RUN echo '#!/bin/bash\n\
  set -e\n\
  echo "🚀 Starting EDGI Cloud Portal..."\n\
  echo "📁 Data directory: $RESETTE_DATA_DIR"\n\
  echo "🗄 Portal DB path: $PORTAL_DB_PATH"\n\
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
  echo "🔄 Running migration check..."\n\
  python migrate_db.py\n\
  fi\n\
  \n\
  # Generate dynamic metadata for all registered databases\n\
  echo "🔧 Generating dynamic metadata..."\n\
  python plugins/generate_metadata.py\n\
  if [ -f "/app/metadata.json" ]; then\n\
  echo "✅ Metadata generated successfully"\n\
  echo "📄 Size: $(du -h /app/metadata.json | cut -f1)"\n\
  else\n\
  echo "⚠️  Using fallback metadata"\n\
  fi\n\
  \n\
  # Start Datasette with extended timeouts and proxy forwarding\n\
  echo "🚀 Starting Datasette with extended timeouts and proxy forwarding..."\n\
  exec datasette serve "$PORTAL_DB_PATH" \\\n\
  --host 0.0.0.0 \\\n\
  --port "$PORT" \\\n\
  --metadata metadata.json \\\n\
  --template-dir templates \\\n\
  --static static:static \\\n\
  --plugins-dir plugins \\\n\
  --setting base_url "${APP_URL:-https://resette.envirodatagov.org}/" \\\n\
  --setting max_returned_rows 3000000 \\\n\
  --setting sql_time_limit_ms 360000 \\\n\
  --setting allow_download on \\\n\
  ' > /app/start.sh && chmod +x /app/start.sh

CMD ["/app/start.sh"]
