#!/bin/bash
# 🚀 TEDx Backend Deployment Script for Render
# This script runs during deployment on Render

set -e  # Exit on any error

echo "🔧 Starting TEDx Backend deployment..."

# Install dependencies
echo "📦 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Collect static files
echo "📂 Collecting static files..."
python manage.py collectstatic --noinput

# Check if migrations are needed
echo "🔄 Checking migrations..."
python manage.py showmigrations

echo "✅ Build process completed successfully!"
echo "🚀 Ready for deployment!"
