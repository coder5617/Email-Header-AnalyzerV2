#!/bin/bash

# Email Header Analyzer Pro v2.0 - Complete Setup Script with File Creation
# This script creates ALL necessary files and directories

set -e

echo "🚀 Email Header Analyzer Pro v2.0 - Complete Setup"
echo "=================================================="

# Create project directory
PROJECT_DIR="email-header-analyzer-pro"
if [ -d "$PROJECT_DIR" ]; then
    echo "⚠️  Directory $PROJECT_DIR already exists. Remove it? (y/N)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        rm -rf "$PROJECT_DIR"
    else
        echo "❌ Setup cancelled."
        exit 1
    fi
fi

mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

echo "📁 Creating directory structure..."

# Create all directories
mkdir -p src/email_header_analyzer/{core,utils,ui}
mkdir -p tests/sample_headers
mkdir -p .github/workflows
mkdir -p data/{cache,backups}
mkdir -p logs
mkdir -p reports
mkdir -p temp

echo "📄 Creating all __init__.py files..."

# Root src/__init__.py
cat > src/__init__.py << 'EOF'
"""Email Header Analyzer Pro v2.0 - Root package"""
__version__ = "2.0.0"
__author__ = "Security Analysis Team"
__description__ = "Comprehensive email header analysis with threat intelligence"
EOF

# Main package __init__.py
cat > src/email_header_analyzer/__init__.py << 'EOF'
"""
Email Header Analyzer Pro - Main package
Comprehensive email security analysis toolkit
"""

import logging

# Package metadata
__version__ = "2.0.0"
__author__ = "Security Analysis Team"
__description__ = "Comprehensive email header analysis with threat intelligence"

# Setup logging for the package
logger = logging.getLogger(__name__)

# Core imports with error handling for development
__all__ = ['config', 'database']

try:
    from .config import config
    logger.debug("Configuration module loaded successfully")
except ImportError as e:
    logger.warning(f"Configuration module not available: {e}")
    config = None

try:
    from .database import database
    logger.debug("Database module loaded successfully")
except ImportError as e:
    logger.warning(f"Database module not available: {e}")
    database = None

try:
    from .core.enhanced_parser import EnhancedEmailHeaderParser
    __all__.append('EnhancedEmailHeaderParser')
    logger.debug("Enhanced parser loaded successfully")
except ImportError as e:
    logger.debug(f"Enhanced parser not yet available: {e}")

try:
    from .external_apis import api_manager
    __all__.append('api_manager')
    logger.debug("API manager loaded successfully")
except ImportError as e:
    logger.debug(f"API manager not yet available: {e}")
EOF

# Core package __init__.py
cat > src/email_header_analyzer/core/__init__.py << 'EOF'
"""
Core analysis modules for email header processing
"""

import logging

logger = logging.getLogger(__name__)

# All available core modules
__all__ = [
    'EnhancedAuthenticationAnalyzer',
    'EnhancedRoutingAnalyzer', 
    'EnhancedSpoofingDetector',
    'EnhancedGeographicAnalyzer',
    'EnhancedContentAnalyzer',
    'EnhancedEmailHeaderParser',
    'EnhancedDNSHelper'
]

# Import core modules with graceful error handling
_modules_loaded = []

try:
    from .enhanced_authentication import EnhancedAuthenticationAnalyzer
    _modules_loaded.append('EnhancedAuthenticationAnalyzer')
except ImportError as e:
    logger.debug(f"EnhancedAuthenticationAnalyzer not available: {e}")

try:
    from .enhanced_routing import EnhancedRoutingAnalyzer
    _modules_loaded.append('EnhancedRoutingAnalyzer')
except ImportError as e:
    logger.debug(f"EnhancedRoutingAnalyzer not available: {e}")

try:
    from .enhanced_spoofing import EnhancedSpoofingDetector
    _modules_loaded.append('EnhancedSpoofingDetector')
except ImportError as e:
    logger.debug(f"EnhancedSpoofingDetector not available: {e}")

try:
    from .enhanced_geographic import EnhancedGeographicAnalyzer
    _modules_loaded.append('EnhancedGeographicAnalyzer')
except ImportError as e:
    logger.debug(f"EnhancedGeographicAnalyzer not available: {e}")

try:
    from .enhanced_content import EnhancedContentAnalyzer
    _modules_loaded.append('EnhancedContentAnalyzer')
except ImportError as e:
    logger.debug(f"EnhancedContentAnalyzer not available: {e}")

try:
    from .enhanced_parser import EnhancedEmailHeaderParser
    _modules_loaded.append('EnhancedEmailHeaderParser')
except ImportError as e:
    logger.debug(f"EnhancedEmailHeaderParser not available: {e}")

try:
    from .enhanced_dns_helper import EnhancedDNSHelper
    _modules_loaded.append('EnhancedDNSHelper')
except ImportError as e:
    logger.debug(f"EnhancedDNSHelper not available: {e}")

logger.info(f"Core modules loaded: {', '.join(_modules_loaded)}")
EOF

# Utils package __init__.py
cat > src/email_header_analyzer/utils/__init__.py << 'EOF'
"""
Utility modules for email header analysis
"""

import logging

logger = logging.getLogger(__name__)

# All available utility functions
__all__ = [
    'is_valid_ipv4',
    'is_private_ip', 
    'extract_ip_from_received',
    'extract_ips_from_headers',
    'is_valid_email',
    'extract_email_domain',
    'extract_email_address',
    'ReportGenerator',
    'validate_domain_format',
    'extract_display_name',
    'normalize_email_address',
    'is_disposable_email_domain',
    'is_free_email_service'
]

# Import IP utilities
try:
    from .ip_helper import (
        is_valid_ipv4, 
        is_private_ip, 
        extract_ip_from_received, 
        extract_ips_from_headers,
        classify_ip_type,
        get_ip_network_info
    )
    __all__.extend(['classify_ip_type', 'get_ip_network_info'])
    logger.debug("IP helper utilities loaded successfully")
except ImportError as e:
    logger.warning(f"IP helper utilities not available: {e}")

# Import email validators
try:
    from .validators import (
        is_valid_email, 
        extract_email_domain, 
        extract_email_address,
        validate_domain_format,
        extract_display_name,
        normalize_email_address,
        is_disposable_email_domain,
        is_free_email_service
    )
    logger.debug("Email validators loaded successfully")
except ImportError as e:
    logger.warning(f"Email validators not available: {e}")

# Import DNS helper
try:
    from .dns_helper import dns_helper, DNSHelper
    __all__.extend(['dns_helper', 'DNSHelper'])
    logger.debug("DNS helper loaded successfully")
except ImportError as e:
    logger.debug(f"DNS helper not available: {e}")

# Import report generator
try:
    from .report_generator import ReportGenerator
    logger.debug("Report generator loaded successfully")
except ImportError as e:
    logger.debug(f"Report generator not available: {e}")
EOF

# UI package __init__.py
cat > src/email_header_analyzer/ui/__init__.py << 'EOF'
"""
User interface modules for Email Header Analyzer Pro
"""

import logging

logger = logging.getLogger(__name__)

__all__ = ['run_streamlit_app']

def run_streamlit_app():
    """
    Run the Streamlit application
    This function can be called to start the web interface programmatically
    """
    try:
        from .streamlit_app import main
        main()
    except ImportError as e:
        logger.error(f"Streamlit app not available: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to start Streamlit app: {e}")
        raise
EOF

# Tests __init__.py
cat > tests/__init__.py << 'EOF'
"""
Test suite for Email Header Analyzer Pro v2.0
"""

import os
import sys
from pathlib import Path

# Add src directory to path for testing
test_dir = Path(__file__).parent
src_dir = test_dir.parent / "src"
sys.path.insert(0, str(src_dir))

__version__ = "2.0.0"
__test_data_dir__ = test_dir / "sample_headers"

# Test utilities
def get_sample_header(filename: str) -> str:
    """Load sample header file for testing"""
    sample_path = __test_data_dir__ / filename
    if sample_path.exists():
        return sample_path.read_text(encoding='utf-8')
    else:
        raise FileNotFoundError(f"Sample header file not found: {filename}")

def get_all_sample_headers() -> dict:
    """Get all available sample headers"""
    samples = {}
    if __test_data_dir__.exists():
        for file_path in __test_data_dir__.glob("*.txt"):
            samples[file_path.stem] = file_path.read_text(encoding='utf-8')
    return samples

__all__ = ['get_sample_header', 'get_all_sample_headers']
EOF

echo "📄 Creating code placeholder files..."

# Function to create code placeholders with clear instructions
create_code_placeholder() {
    local file_path="$1"
    local artifact_name="$2"
    local description="$3"
    
    cat > "$file_path" << EOF
"""
$description
================================================================

SETUP INSTRUCTIONS:
1. Find the artifact named: "$artifact_name"
2. Copy the ENTIRE content from that artifact
3. Replace THIS ENTIRE FILE with that content

File: $file_path
================================================================
"""

# TODO: Replace this entire file with the artifact code
# Artifact name: $artifact_name

if __name__ == "__main__":
    print("⚠️  This is a placeholder file.")
    print("📄 Please replace with artifact: $artifact_name")
EOF
}

# Create all placeholder files with artifact mapping
create_code_placeholder "main.py" "Fixed Main Entry Point" "Main application entry point"
create_code_placeholder "requirements.in" "Updated Requirements with Enhanced Dependencies" "Python dependencies"
create_code_placeholder "Dockerfile" "Updated Dockerfile with Enhanced Dependencies" "Docker container configuration"
create_code_placeholder "docker-compose.yml" "Updated Docker Compose with Volumes and Environment" "Docker Compose configuration"
create_code_placeholder ".env.example" "Updated Environment Configuration Example" "Environment configuration template"

# Core application files
create_code_placeholder "src/email_header_analyzer/config.py" "Enhanced Configuration Management" "Configuration management system"
create_code_placeholder "src/email_header_analyzer/database.py" "Database Layer for Historical Analysis" "Database layer for historical analysis"
create_code_placeholder "src/email_header_analyzer/external_apis.py" "Enhanced External API Integrations" "External API integrations"

# Core analysis modules
create_code_placeholder "src/email_header_analyzer/core/enhanced_parser.py" "Enhanced Email Header Parser" "Main email header parser"
create_code_placeholder "src/email_header_analyzer/core/enhanced_authentication.py" "Enhanced Authentication Analyzer" "Authentication analysis module"
create_code_placeholder "src/email_header_analyzer/core/enhanced_routing.py" "Enhanced Routing Analyzer" "Routing analysis module"
create_code_placeholder "src/email_header_analyzer/core/enhanced_spoofing.py" "Enhanced Spoofing Detector" "Spoofing detection module"
create_code_placeholder "src/email_header_analyzer/core/enhanced_geographic.py" "Enhanced Geographic Analyzer with External APIs" "Geographic analysis module"
create_code_placeholder "src/email_header_analyzer/core/enhanced_content.py" "Enhanced Content Analyzer" "Content analysis module"
create_code_placeholder "src/email_header_analyzer/core/enhanced_dns_helper.py" "Enhanced DNS Helper in Core Directory" "DNS analysis utilities"

# Utility modules
create_code_placeholder "src/email_header_analyzer/utils/validators.py" "Enhanced Validators with Email Address Extraction" "Email validation utilities"
create_code_placeholder "src/email_header_analyzer/utils/report_generator.py" "Report Generator for Multiple Formats" "Report generation system"

# DNS helper wrapper
cat > src/email_header_analyzer/utils/dns_helper.py << 'EOF'
"""
DNS helper utilities - imports the enhanced DNS helper
Provides backward compatibility with existing code
"""

import logging

logger = logging.getLogger(__name__)

# Import the enhanced DNS helper
try:
    from email_header_analyzer.core.enhanced_dns_helper import EnhancedDNSHelper
    
    # Create global instance for backward compatibility with existing code
    dns_helper = EnhancedDNSHelper()
    
    # Legacy class for compatibility
    class DNSHelper:
        """Legacy DNS helper class for backward compatibility"""
        
        def __init__(self):
            self.enhanced = EnhancedDNSHelper()
        
        def get_spf_record(self, domain):
            """Get SPF record (legacy method)"""
            return self.enhanced.get_spf_record(domain)
        
        def get_mx_records(self, domain):
            """Get MX records (legacy method)"""
            return self.enhanced.get_mx_records(domain)
    
    # Export both new and legacy interfaces
    __all__ = ['EnhancedDNSHelper', 'DNSHelper', 'dns_helper']
    
    logger.debug("DNS helper loaded successfully")
    
except ImportError as e:
    logger.error(f"Failed to import enhanced DNS helper: {e}")
    
    # Fallback basic DNS helper for development
    import dns.resolver
    
    class BasicDNSHelper:
        def __init__(self):
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = 5
        
        def get_spf_record(self, domain):
            try:
                answers = self.resolver.resolve(domain, 'TXT')
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if txt.startswith('v=spf1'):
                        return txt
            except:
                pass
            return None
        
        def get_mx_records(self, domain):
            try:
                answers = self.resolver.resolve(domain, 'MX')
                return [{"priority": r.preference, "exchange": str(r.exchange).rstrip('.')} 
                       for r in answers]
            except:
                return []
    
    dns_helper = BasicDNSHelper()
    DNSHelper = BasicDNSHelper
    __all__ = ['DNSHelper', 'dns_helper']
EOF

# UI module
create_code_placeholder "src/email_header_analyzer/ui/streamlit_app.py" "Enhanced Streamlit Application with Modern UI" "Streamlit web interface"

# Copy your existing ip_helper.py if it exists, otherwise create enhanced version
if [ -f "../src/utils/ip_helper.py" ]; then
    cp "../src/utils/ip_helper.py" "src/email_header_analyzer/utils/ip_helper.py"
    echo "✅ Copied existing ip_helper.py"
else
    # Create enhanced version
    cat > src/email_header_analyzer/utils/ip_helper.py << 'EOF'
"""
Enhanced IP helper utilities with comprehensive validation and extraction
"""

import ipaddress
import re
import logging

logger = logging.getLogger(__name__)

def is_valid_ipv4(ip_string: str) -> bool:
    """Validate IPv4 address format"""
    try:
        ipaddress.IPv4Address(ip_string)
        return True
    except ipaddress.AddressValueError:
        return False
    except Exception as e:
        logger.debug(f"IP validation error: {e}")
        return False

def is_private_ip(ip_string: str) -> bool:
    """Check if IP address is private or reserved"""
    try:
        ip_obj = ipaddress.IPv4Address(ip_string)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ipaddress.AddressValueError:
        return False
    except Exception as e:
        logger.debug(f"Private IP check error: {e}")
        return False

def extract_ip_from_received(received_header: str) -> str:
    """Extract IP address from Received header"""
    if not received_header:
        return None
    
    # Try multiple patterns to extract IP
    ip_patterns = [
        r'\[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]',  # [192.168.1.1]
        r'from\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',  # from 192.168.1.1
        r'\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)',  # (192.168.1.1)
        r'\b([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b'   # standalone IP
    ]
    
    for pattern in ip_patterns:
        match = re.search(pattern, received_header)
        if match:
            ip = match.group(1)
            if is_valid_ipv4(ip):
                return ip
    
    return None

def extract_ips_from_headers(headers: dict) -> list:
    """Extract all IP addresses from email headers"""
    ips = []
    
    # Extract from Received headers
    received_headers = headers.get("Received", [])
    if isinstance(received_headers, str):
        received_headers = [received_headers]
    
    for received in received_headers:
        ip = extract_ip_from_received(received)
        if ip and ip not in ips:
            ips.append(ip)
    
    # Extract from X-Originating-IP header
    x_orig_ip = headers.get("X-Originating-IP", "")
    if x_orig_ip:
        # Remove brackets if present
        cleaned_ip = x_orig_ip.strip("[]() ")
        if is_valid_ipv4(cleaned_ip) and cleaned_ip not in ips:
            ips.append(cleaned_ip)
    
    return ips

def classify_ip_type(ip_string: str) -> str:
    """Classify IP address type"""
    try:
        ip_obj = ipaddress.IPv4Address(ip_string)
        
        if ip_obj.is_loopback:
            return "loopback"
        elif ip_obj.is_private:
            return "private"
        elif ip_obj.is_link_local:
            return "link_local"
        elif ip_obj.is_multicast:
            return "multicast"
        elif ip_obj.is_reserved:
            return "reserved"
        else:
            return "public"
            
    except ipaddress.AddressValueError:
        return "invalid"
EOF
fi

echo "📄 Creating configuration files..."

# Create comprehensive README
cat > README.md << 'EOF'
# Email Header Analyzer Pro v2.0

## 🚀 Quick Setup Instructions

### STEP 1: Insert Code from Artifacts
Replace placeholder files with artifact code using the mapping in `ARTIFACT_MAPPING.md`

### STEP 2: Deploy with Docker
```bash
# Copy .env.example to .env and configure API keys
cp .env.example .env
nano .env

# Build and deploy
docker-compose up -d --build

# Access application
open http://localhost:8501
```

### STEP 3: Verify Deployment
```bash
# Check application logs
docker-compose logs -f email-analyzer

# Verify health
curl http://localhost:8501/_stcore/health
```

## 📖 Complete Documentation
After inserting artifact code, the README.md will contain comprehensive documentation.

## 🆘 Need Help?
1. Run `./verify_deployment.sh` to check setup
2. Check `ARTIFACT_MAPPING.md` for file mapping
3. Review Docker logs for errors
EOF

# Create detailed artifact mapping
cat > ARTIFACT_MAPPING.md << 'EOF'
# Artifact Code Mapping Guide

## 📋 Complete File-to-Artifact Mapping

Replace each placeholder file with the corresponding artifact code:

### 🔧 Infrastructure & Configuration
| File | Artifact Name | Description |
|------|---------------|-------------|
| `main.py` | "Fixed Main Entry Point" | Application entry point with CLI support |
| `requirements.in` | "Updated Requirements with Enhanced Dependencies" | Python package dependencies |
| `Dockerfile` | "Updated Dockerfile with Enhanced Dependencies" | Docker container configuration |
| `docker-compose.yml` | "Updated Docker Compose with Volumes and Environment" | Docker stack deployment |
| `.env.example` | "Updated Environment Configuration Example" | Environment configuration template |
| `README.md` | "Comprehensive README for Email Header Analyzer Pro" | Complete documentation |

### 🏗️ Core Application Architecture  
| File | Artifact Name | Description |
|------|---------------|-------------|
| `src/email_header_analyzer/config.py` | "Enhanced Configuration Management" | Configuration system with validation |
| `src/email_header_analyzer/database.py` | "Database Layer for Historical Analysis" | SQLite database with caching |
| `src/email_header_analyzer/external_apis.py` | "Enhanced External API Integrations" | API integrations with rate limiting |

### 🔍 Core Analysis Modules
| File | Artifact Name | Description |
|------|---------------|-------------|
| `src/email_header_analyzer/core/enhanced_parser.py` | "Enhanced Email Header Parser" | Main orchestrator for all analysis |
| `src/email_header_analyzer/core/enhanced_authentication.py` | "Enhanced Authentication Analyzer" | SPF/DKIM/DMARC analysis with DNS |
| `src/email_header_analyzer/core/enhanced_routing.py` | "Enhanced Routing Analyzer" | Email routing path analysis |
| `src/email_header_analyzer/core/enhanced_spoofing.py` | "Enhanced Spoofing Detector" | BEC and impersonation detection |
| `src/email_header_analyzer/core/enhanced_geographic.py` | "Enhanced Geographic Analyzer with External APIs" | Geographic threat intelligence |
| `src/email_header_analyzer/core/enhanced_content.py` | "Enhanced Content Analyzer" | Social engineering detection |
| `src/email_header_analyzer/core/enhanced_dns_helper.py` | "Enhanced DNS Helper in Core Directory" | Real-time DNS analysis |

### 🛠️ Utility Modules
| File | Artifact Name | Description |
|------|---------------|-------------|
| `src/email_header_analyzer/utils/validators.py` | "Enhanced Validators with Email Address Extraction" | Email validation utilities |
| `src/email_header_analyzer/utils/report_generator.py` | "Report Generator for Multiple Formats" | PDF/HTML/CSV report generation |

### 💻 User Interface
| File | Artifact Name | Description |
|------|---------------|-------------|
| `src/email_header_analyzer/ui/streamlit_app.py` | "Enhanced Streamlit Application with Modern UI" | Modern web interface |

## 🔄 Setup Process

### 1. Copy Artifact Code
For each file above:
1. Open the corresponding artifact in your conversation
2. Copy the ENTIRE content
3. Replace the placeholder file content completely
4. Save the file

### 2. Verify Setup
```bash
# Run verification script
./verify_deployment.sh

# Check for remaining placeholders
grep -r "TODO: Insert.*code here" src/ || echo "✅ All code inserted"
```

### 3. Deploy Application
```bash
# Configure environment (optional API keys)
cp .env.example .env
nano .env

# Build and deploy
docker-compose up -d --build

# Verify deployment
curl http://localhost:8501/_stcore/health
```

## ⚠️ Important Notes

- **Complete Replacement**: Replace ENTIRE file contents, not just parts
- **API Keys Optional**: Application works without API keys (reduced functionality)
- **Order Matters**: Core modules should be created before UI components
- **File Paths**: Maintain exact file paths as specified in the mapping

## 🆘 Troubleshooting

### Import Errors
```bash
# Check Python path
python -c "import sys; print('\n'.join(sys.path))"

# Verify module structure
find src/ -name "__init__.py" -exec echo "Found: {}" \;
```

### Docker Issues
```bash
# Check Docker status
docker-compose ps

# View detailed logs
docker-compose logs email-analyzer

# Rebuild containers
docker-compose down && docker-compose up -d --build
```
EOF

# Create GitIgnore
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Virtual environments
venv/
env/
ENV/

# Environment variables
.env
.env.local
.env.production

# Database
data/geoip/
data/*.db
data/*.sqlite
data/*.sqlite3

# Logs
logs/
*.log

# Temporary files
temp/
tmp/
*.tmp

# Cache
.cache/
data/cache/

# Reports (optional - comment out if you want to keep reports in git)
reports/*.pdf
reports/*.html

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Docker
.dockerignore

# Backup files
*.backup
*.bak
data/backups/
EOF

# Create setup verification script
cat > verify_deployment.sh << 'EOF'
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
EOF

chmod +x verify_deployment.sh

# Create quick deployment script
cat > deploy.sh << 'EOF'
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
EOF

chmod +x deploy.sh

# Copy existing files if they exist
echo "📄 Copying existing project files..."
if [ -f "../setup.py" ]; then
    cp ../setup.py .
    echo "✅ Copied setup.py"
fi

if [ -f "../.gitattributes" ]; then
    cp ../.gitattributes .
    echo "✅ Copied .gitattributes"
fi

if [ -d "../.github" ]; then
    cp -r ../.github/* .github/ 2>/dev/null || true
    echo "✅ Copied GitHub workflows"
fi

if [ -d "../tests" ]; then
    cp -r ../tests/* tests/ 2>/dev/null || true
    echo "✅ Copied existing tests"
fi

echo ""
echo "🎉 SETUP COMPLETE!"
echo "=================="
echo ""
echo "📁 Project created in: $(pwd)"
echo ""
echo "📋 Next Steps:"
echo "1. 📝 Insert artifact code using ARTIFACT_MAPPING.md guide"
echo "2. ⚙️  Configure API keys in .env file (optional)"
echo "3. 🚀 Deploy: ./deploy.sh"
echo "4. 🌐 Access: http://localhost:8501"
echo ""
echo "🔍 Verification Commands:"
echo "• Check setup progress: ./verify_deployment.sh"
echo "• View file mapping: cat ARTIFACT_MAPPING.md"
echo "• Quick deploy: ./deploy.sh"
echo ""
echo "📖 Files ready for artifact code insertion:"
find src/ -name "*.py" | grep -v __init__ | wc -l | xargs echo "   Python modules:"
echo "   Configuration files: 4"
echo "   Documentation files: 2"
echo ""
echo "🎯 Total artifacts to insert: 17"
