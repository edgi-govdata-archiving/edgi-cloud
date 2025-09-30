#!/bin/bash
# cleanup-env.sh - Reset environment to use config.toml defaults

echo "Unsetting EDGI Cloud Portal environment variables..."

unset PORTAL_DB_PATH
unset RESETTE_DATA_DIR
unset RESETTE_STATIC_DIR
unset CSRF_SECRET_KEY
unset DEFAULT_PASSWORD
unset APP_URL
unset DEBUG
unset MAX_FILE_SIZE
unset MAX_IMG_SIZE
unset MAINTENANCE_MODE
unset REGISTRATION_ENABLED

echo "Environment variables cleared. Your config.toml will now be used for defaults."

# Verify they're unset
echo "Checking cleared variables:"
env | grep -E "(PORTAL|RESETTE|CSRF|DEFAULT_PASSWORD|APP_URL)" || echo "All cleared!"
