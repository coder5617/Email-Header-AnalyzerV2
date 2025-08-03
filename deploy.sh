#!/bin/bash

echo "🚀 Email Header Analyzer Pro v2.0 - Quick Deploy"
echo "==============================================="

# Check if setup is complete
if grep -r "TODO: Insert.*code here" src/ &>/dev/null; then
    echo "❌ Setup incomplete. Please insert artifact code first."
    echo "📖 See ARTIFACT_MAPPING.md for instructions."
    exit 1
fi

# Ensure .env exists
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "✅ Created .env from template"
    else
        echo "❌ No .env.example found"
        exit 1
    fi
fi

echo "🏗️  Building and deploying..."

# Build and deploy
docker-compose down 2>/dev/null || true
docker-compose up -d --build

echo "⏳ Waiting for application to start..."
sleep 10

# Check if application is running
if curl -f http://localhost:8501/_stcore/health &>/dev/null; then
    echo ""
    echo "🎉 Deployment successful!"
    echo "🌐 Application available at: http://localhost:8501"
    echo "📊 Monitor with: docker-compose logs -f email-analyzer"
else
    echo ""
    echo "❌ Deployment may have issues. Check logs:"
    echo "   docker-compose logs email-analyzer"
fi
