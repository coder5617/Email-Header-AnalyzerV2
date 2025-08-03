#!/bin/bash

echo "🔍 Email Header Analyzer Pro v2.0 - Deployment Verification"
echo "============================================================"

# Check Docker
echo "🐳 Checking Docker..."
if command -v docker &> /dev/null; then
    echo "✅ Docker installed: $(docker --version)"
else
    echo "❌ Docker not found. Please install Docker first."
    exit 1
fi

# Check Docker Compose
echo "🐳 Checking Docker Compose..."
if command -v docker-compose &> /dev/null; then
    echo "✅ Docker Compose installed: $(docker-compose --version)"
else
    echo "❌ Docker Compose not found. Please install Docker Compose."
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ docker-compose.yml not found. Please run this script from the project root."
    exit 1
fi

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "⚠️  .env file not found. Creating from .env.example..."
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "✅ .env file created. Edit it to add your API keys if needed."
    else
        echo "❌ .env.example not found."
        exit 1
    fi
else
    echo "✅ .env file found"
fi

# Check critical Python files
echo "🐍 Checking Python files..."
critical_files=(
    "src/email_header_analyzer/config.py"
    "src/email_header_analyzer/database.py"
    "src/email_header_analyzer/core/enhanced_parser.py"
    "src/email_header_analyzer/ui/streamlit_app.py"
    "main.py"
)

all_files_ready=true
for file in "${critical_files[@]}"; do
    if [ -f "$file" ]; then
        if grep -q "TODO: Insert.*code here" "$file" 2>/dev/null; then
            echo "⚠️  $file - Still contains placeholder"
            all_files_ready=false
        else
            echo "✅ $file - Ready"
        fi
    else
        echo "❌ $file - Missing"
        all_files_ready=false
    fi
done

if [ "$all_files_ready" = true ]; then
    echo ""
    echo "🎉 All files ready for deployment!"
    echo ""
    echo "🚀 To deploy:"
    echo "   docker-compose up -d --build"
    echo ""
    echo "🌐 Access application at:"
    echo "   http://localhost:8501"
    echo ""
    echo "📊 Monitor logs:"
    echo "   docker-compose logs -f email-analyzer"
else
    echo ""
    echo "📋 Please complete file setup before deployment."
    echo "📖 See ARTIFACT_MAPPING.md for detailed instructions."
fi
