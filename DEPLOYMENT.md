# 🚀 TEDx Authentication API - Production Configuration
# Optimized configuration for Render deployment

## Build Command (Render)
```bash
pip install --upgrade pip && pip install -r requirements.txt && python manage.py collectstatic --noinput
```

## Start Command (Render)
```bash
sh -c "python manage.py migrate --noinput && gunicorn auth_api.wsgi:application --bind 0.0.0.0:$PORT --workers 3 --timeout 60"
```

## Environment Variables Required:
- SECRET_KEY (auto-generated)
- DEBUG=False
- DATABASE_URL (auto-populated)
- GOOGLE_CLIENT_ID (manual)
- GOOGLE_CLIENT_SECRET (manual)
- CORS_ALLOWED_ORIGINS (manual)
- ALLOWED_HOSTS=.onrender.com

## Performance Optimizations:
- PostgreSQL connection pooling
- WhiteNoise static file compression
- Gunicorn with 3 workers
- HTTP keep-alive connections
- Request limit protection

## Security Features:
- HTTPS enforcement
- HSTS headers
- Content security policies
- Secure cookies
- XSS protection
