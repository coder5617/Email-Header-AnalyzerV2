# Email Header Analyzer Pro v2.0

A comprehensive, enterprise-grade email header analysis tool designed for cybersecurity professionals, IT administrators, and security analysts. This tool provides deep analysis of email headers with threat intelligence integration, historical tracking, and professional reporting capabilities.

## 🚀 Features

### Core Analysis Capabilities
- **📧 Email Authentication Analysis**: Comprehensive SPF, DKIM, DMARC verification with alignment checks
- **🌍 Geographic Intelligence**: IP geolocation with threat intelligence from multiple sources
- **🎭 Advanced Spoofing Detection**: Domain spoofing, display name impersonation, and BEC detection
- **🔄 Routing Analysis**: SMTP hop analysis with anomaly detection and timing analysis
- **📄 Content Analysis**: Subject line analysis and social engineering detection
- **🔒 Real-time DNS Analysis**: MX, SPF, DKIM, DMARC record validation

### Threat Intelligence Integration
- **IPInfo.io**: Geographic and ISP data
- **AbuseIPDB**: IP reputation and abuse reports  
- **VirusTotal**: IP and domain reputation analysis
- **DNS Blacklists**: Multi-source blacklist checking

### Enterprise Features
- **📊 Historical Analysis**: SQLite database for tracking and trend analysis
- **📈 Professional Reports**: PDF, HTML, CSV, and JSON export formats
- **⚡ High Performance**: Async API calls with intelligent caching
- **🔧 Configurable**: Extensive configuration options via environment variables
- **📱 Modern UI**: Clean, responsive Streamlit interface with real-time updates

## 🛠️ Installation & Setup

### Prerequisites
- Ubuntu Server 20.04+ (recommended)
- Docker and Docker Compose
- 4GB RAM minimum (8GB recommended)
- 10GB disk space

### Quick Start with Docker Compose

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd email-header-analyzer
   ```

2. **Create environment configuration:**
   ```bash
   cp .env.example .env
   nano .env
   ```

3. **Configure API keys in `.env`:**
   ```bash
   # External API Configuration (Optional but recommended)
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   IPINFO_TOKEN=your_ipinfo_token_here
   
   # Analysis Configuration
   ENABLE_GEO_ANALYSIS=true
   ENABLE_DNS_ANALYSIS=true
   ENABLE_BLACKLIST_CHECKS=true
   DEFAULT_TIMEOUT=10
   
   # Logging Configuration
   LOG_LEVEL=INFO
   LOG_DIR=logs
   
   # Database Configuration
   DATABASE_PATH=data/email_analyzer.db
   DATABASE_BACKUP=true
   
   # Report Configuration
   COMPANY_NAME="Your Security Team"
   ```

4. **Build and start the application:**
   ```bash
   docker-compose up -d --build
   ```

5. **Access the application:**
   Open your browser and navigate to `http://your-server-ip:8501`

### Manual Installation (Alternative)

1. **Install Python dependencies:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Set up environment:**
   ```bash
   export PYTHONPATH=/path/to/email-header-analyzer/src
   ```

3. **Run the application:**
   ```bash
   streamlit run src/email_header_analyzer/ui/streamlit_app.py --server.port=8501 --server.address=0.0.0.0
   ```

## 📋 API Key Setup

### Getting API Keys (All Optional)

#### IPInfo.io (Geographic Data)
1. Visit [ipinfo.io](https://ipinfo.io/signup)
2. Sign up for a free account (50,000 requests/month)
3. Copy your access token to `IPINFO_TOKEN` in `.env`

#### AbuseIPDB (IP Reputation)
1. Visit [AbuseIPDB](https://www.abuseipdb.com/api)
2. Create a free account (1,000 requests/day)
3. Generate an API key
4. Add to `ABUSEIPDB_API_KEY` in `.env`

#### VirusTotal (Domain/IP Analysis)
1. Visit [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Create a free account (4 requests/minute)
3. Go to your API key section
4. Add to `VIRUSTOTAL_API_KEY` in `.env`

## 🎯 Usage Guide

### Basic Analysis

1. **Access the Web Interface:**
   - Navigate to `http://your-server:8501`
   - The interface will load with analysis options

2. **Input Email Headers:**
   - **Paste Headers**: Copy and paste raw email headers
   - **Upload File**: Upload .txt, .eml, or .msg files
   - **Load from History**: Select from previous analyses

3. **Configure Analysis:**
   - **Comprehensive**: Full analysis with all features
   - **Quick Scan**: Fast analysis of key indicators
   - **Authentication Only**: Focus on SPF/DKIM/DMARC
   - **Geographic Only**: IP and location analysis

4. **Review Results:**
   - Overall risk assessment with color-coded indicators
   - Detailed analysis across multiple tabs
   - Actionable recommendations
   - Historical comparison data

### Advanced Features

#### Historical Analysis
- View recent analyses with risk trending
- Search by sender, date range, or risk level
- Export historical data for reporting
- Database statistics and cleanup tools

#### Report Generation
- **PDF Reports**: Professional formatted reports
- **HTML Reports**: Interactive web-based reports  
- **CSV Export**: Data for spreadsheet analysis
- **JSON Export**: Machine-readable format

#### API Integration
The tool can be integrated with other security tools:

```bash
# Command-line usage
python src/main.py --mode=cli --header="Raw headers here"

# Or from file
python src/main.py --mode=cli --file=headers.txt
```

## 🔧 Configuration Options

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ABUSEIPDB_API_KEY` | None | AbuseIPDB API key for IP reputation |
| `VIRUSTOTAL_API_KEY` | None | VirusTotal API key for threat intelligence |
| `IPINFO_TOKEN` | None | IPInfo.io token for geographic data |
| `DEFAULT_TIMEOUT` | 10 | API request timeout in seconds |
| `ENABLE_GEO_ANALYSIS` | true | Enable geographic analysis |
| `ENABLE_DNS_ANALYSIS` | true | Enable DNS record analysis |
| `ENABLE_BLACKLIST_CHECKS` | true | Enable DNS blacklist checking |
| `LOG_LEVEL` | INFO | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `DATABASE_PATH` | data/email_analyzer.db | SQLite database file path |
| `COMPANY_NAME` | Security Analysis Team | Company name for reports |

### Analysis Configuration

The tool automatically adjusts analysis depth based on:
- Available API keys
- System performance
- User preferences
- Historical patterns

## 🚨 Troubleshooting

### Common Issues

#### Application Won't Start
```bash
# Check Docker logs
docker-compose logs email-analyzer

# Verify port availability
netstat -tlnp | grep 8501

# Check permissions
ls -la data/ logs/
```

#### Database Issues
```bash
# Check database permissions
ls -la data/email_analyzer.db

# Reset database (WARNING: loses all data)
rm data/email_analyzer.db
docker-compose restart
```

#### API Rate Limiting
- **AbuseIPDB**: 1,000 requests/day (free)
- **VirusTotal**: 4 requests/minute (free)
- **IPInfo.io**: 50,000 requests/month (free)

The tool automatically handles rate limiting with intelligent caching.

#### Memory Issues
```bash
# Check memory usage
docker stats email-analyzer

# Increase memory limit in docker-compose.yml
services:
  email-analyzer:
    deploy:
      resources:
        limits:
          memory: 2G
```

### Log Analysis
```bash
# View application logs
docker-compose logs -f email-analyzer

# Check log files
tail -f logs/email_analyzer.log

# Debug mode
LOG_LEVEL=DEBUG docker-compose restart
```

## 🔒 Security Considerations

### Data Privacy
- Email headers may contain sensitive information
- All data is stored locally in SQLite database
- No external transmission except to configured APIs
- Regular database cleanup available

### Network Security
- Application runs on localhost by default
- Configure firewall rules for remote access
- Use HTTPS proxy (nginx/Apache) for production
- API keys stored in environment variables only

### Access Control
- No built-in authentication (add reverse proxy auth)
- Consider VPN access for remote users
- Regular security updates recommended
- Monitor log files for unauthorized access

## 📊 Performance Optimization

### System Requirements
- **Minimum**: 2 CPU cores, 4GB RAM, 10GB storage
- **Recommended**: 4 CPU cores, 8GB RAM, 50GB storage
- **High Volume**: 8+ CPU cores, 16GB+ RAM, SSD storage

### Optimization Tips
1. **Enable caching** for frequently analyzed domains/IPs
2. **Regular database cleanup** to maintain performance
3. **Monitor API usage** to avoid rate limits
4. **Use SSD storage** for better database performance

## 🤝 Support and Contributing

### Getting Help
1. Check this README for common solutions
2. Review application logs for error details
3. Check Docker container status and logs
4. Verify API key configuration and limits

### Feature Requests
The tool is designed for extensibility:
- Additional threat intelligence sources
- Custom analysis modules
- Enhanced reporting formats
- Integration with SIEM systems

## 📄 License and Legal

This tool is for authorized security analysis only. Users are responsible for:
- Compliance with local privacy laws
- Proper handling of email data
- Appropriate use of external APIs
- Security of API keys and credentials

## 🔄 Updates and Maintenance

### Regular Maintenance
```bash
# Update application
git pull origin main
docker-compose down
docker-compose up -d --build

# Database cleanup (keeps last 90 days)
docker exec email-analyzer python -c "
from email_header_analyzer.database import database
database.cleanup_old_records(days=90)
"

# Log rotation (if needed)
find logs/ -name "*.log" -mtime +30 -delete
```

### Version Information
- **Current Version**: 2.0.0
- **Python**: 3.13+
- **Streamlit**: 1.39+
- **Docker**: 20.10+

---

## Quick Reference Commands

```bash
# Start application
docker-compose up -d

# View logs
docker-compose logs -f

# Stop application  
docker-compose down

# Update and restart
git pull && docker-compose up -d --build

# Database backup
docker exec email-analyzer cp /app/data/email_analyzer.db /app/data/backup_$(date +%Y%m%d).db

# Check API status
curl http://localhost:8501/_stcore/health
```

For additional support or advanced configuration, consult the source code documentation in the `src/` directory.
