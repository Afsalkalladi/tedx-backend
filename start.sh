#!/bin/bash
# 🚀 TEDx Backend Start Script for Render
# This script starts the application on Render

set -e  # Exit on any error

echo "🚀 Starting TEDx Backend..."

# Run migrations
echo "🔄 Running database migrations..."
python manage.py migrate --noinput

# Create superuser if environment variable is set
if [ ! -z "$CREATE_SUPERUSER" ] && [ "$CREATE_SUPERUSER" = "true" ]; then
    echo "👤 Creating superuser..."
    python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(is_superuser=True).exists():
    User.objects.create_superuser('admin@tedx.com', 'admin', 'secure-admin-password')
    print('✅ Superuser created')
else:
    print('ℹ️ Superuser already exists')
"
fi

# Start Gunicorn server
echo "🌐 Starting Gunicorn server..."
exec gunicorn auth_api.wsgi:application \
    --bind 0.0.0.0:$PORT \
    --workers ${WEB_CONCURRENCY:-3} \
    --timeout 60 \
    --keep-alive 5 \
    --max-requests 1000 \
    --max-requests-jitter 100 \
    --log-level info \
    --access-logfile - \
    --error-logfile -
