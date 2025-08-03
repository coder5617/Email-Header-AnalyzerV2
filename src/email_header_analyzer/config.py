"""
Enhanced configuration management for Email Header Analyzer
Centralized settings with validation and environment variable support
"""

import os
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

@dataclass
class DatabaseConfig:
    """Database configuration settings"""
    path: str = field(default_factory=lambda: os.getenv("DATABASE_PATH", "data/email_analyzer.db"))
    backup_enabled: bool = field(default_factory=lambda: os.getenv("DATABASE_BACKUP", "true").lower() == "true")
    backup_interval_hours: int = field(default_factory=lambda: int(os.getenv("DATABASE_BACKUP_INTERVAL", "24")))

@dataclass
class ExternalAPIConfig:
    """External API configuration and rate limiting"""
    abuseipdb_api_key: Optional[str] = field(default_factory=lambda: os.getenv("ABUSEIPDB_API_KEY"))
    virustotal_api_key: Optional[str] = field(default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY"))
    ipinfo_token: Optional[str] = field(default_factory=lambda: os.getenv("IPINFO_TOKEN"))
    
    # Rate limiting settings
    api_request_timeout: int = field(default_factory=lambda: int(os.getenv("API_TIMEOUT", "10")))
    max_retries: int = field(default_factory=lambda: int(os.getenv("MAX_RETRIES", "3")))
    retry_delay: float = field(default_factory=lambda: float(os.getenv("RETRY_DELAY", "1.0")))
    
    # Cache settings
    cache_duration_hours: int = field(default_factory=lambda: int(os.getenv("CACHE_DURATION", "24")))

@dataclass
class AnalysisConfig:
    """Analysis behavior configuration"""
    enable_geo_analysis: bool = field(default_factory=lambda: os.getenv("ENABLE_GEO_ANALYSIS", "true").lower() == "true")
    enable_dns_analysis: bool = field(default_factory=lambda: os.getenv("ENABLE_DNS_ANALYSIS", "true").lower() == "true")
    enable_blacklist_checks: bool = field(default_factory=lambda: os.getenv("ENABLE_BLACKLIST_CHECKS", "true").lower() == "true")
    enable_content_analysis: bool = field(default_factory=lambda: os.getenv("ENABLE_CONTENT_ANALYSIS", "true").lower() == "true")
    
    # DNS settings
    dns_timeout: int = field(default_factory=lambda: int(os.getenv("DNS_TIMEOUT", "5")))
    dns_nameservers: list = field(default_factory=lambda: os.getenv("DNS_NAMESERVERS", "8.8.8.8,1.1.1.1").split(","))
    
    # Scoring thresholds
    high_risk_threshold: int = field(default_factory=lambda: int(os.getenv("HIGH_RISK_THRESHOLD", "70")))
    medium_risk_threshold: int = field(default_factory=lambda: int(os.getenv("MEDIUM_RISK_THRESHOLD", "40")))

@dataclass
class LoggingConfig:
    """Logging configuration"""
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    log_dir: str = field(default_factory=lambda: os.getenv("LOG_DIR", "logs"))
    log_file: str = field(default_factory=lambda: os.getenv("LOG_FILE", "email_analyzer.log"))
    max_log_size_mb: int = field(default_factory=lambda: int(os.getenv("MAX_LOG_SIZE_MB", "10")))
    backup_count: int = field(default_factory=lambda: int(os.getenv("LOG_BACKUP_COUNT", "5")))
    enable_console_logging: bool = field(default_factory=lambda: os.getenv("ENABLE_CONSOLE_LOGGING", "true").lower() == "true")

@dataclass
class UIConfig:
    """User interface configuration"""
    page_title: str = field(default_factory=lambda: os.getenv("PAGE_TITLE", "Email Header Analyzer Pro"))
    theme: str = field(default_factory=lambda: os.getenv("UI_THEME", "light"))
    items_per_page: int = field(default_factory=lambda: int(os.getenv("UI_ITEMS_PER_PAGE", "25")))
    auto_refresh_interval: int = field(default_factory=lambda: int(os.getenv("AUTO_REFRESH_INTERVAL", "30")))

@dataclass
class ReportConfig:
    """Report generation configuration"""
    output_dir: str = field(default_factory=lambda: os.getenv("REPORT_OUTPUT_DIR", "reports"))
    include_raw_headers: bool = field(default_factory=lambda: os.getenv("REPORT_INCLUDE_RAW", "false").lower() == "true")
    pdf_template: str = field(default_factory=lambda: os.getenv("PDF_TEMPLATE", "default"))
    company_logo: Optional[str] = field(default_factory=lambda: os.getenv("COMPANY_LOGO"))
    company_name: str = field(default_factory=lambda: os.getenv("COMPANY_NAME", "Security Analysis Team"))

class AppConfig:
    """Main application configuration class"""
    
    def __init__(self):
        self.database = DatabaseConfig()
        self.external_apis = ExternalAPIConfig()
        self.analysis = AnalysisConfig()
        self.logging = LoggingConfig()
        self.ui = UIConfig()
        self.reports = ReportConfig()
        
        # Validate configuration
        self._validate_config()
        
        # Setup directories
        self._setup_directories()
        
        # Configure logging
        self._setup_logging()
    
    def _validate_config(self):
        """Validate configuration settings"""
        errors = []
        
        # Check API keys if features are enabled
        if self.analysis.enable_geo_analysis and not self.external_apis.ipinfo_token:
            logging.warning("Geographic analysis enabled but no IPInfo token provided")
        
        # Validate thresholds
        if self.analysis.high_risk_threshold <= self.analysis.medium_risk_threshold:
            errors.append("High risk threshold must be greater than medium risk threshold")
        
        # Validate timeouts
        if self.external_apis.api_request_timeout <= 0:
            errors.append("API timeout must be positive")
        
        if errors:
            raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
    
    def _setup_directories(self):
        """Create necessary directories"""
        directories = [
            self.logging.log_dir,
            self.reports.output_dir,
            os.path.dirname(self.database.path),
            "temp",
            "data/cache"
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
    
    def _setup_logging(self):
        """Configure application logging"""
        from logging.handlers import RotatingFileHandler
        
        # Create logger
        logger = logging.getLogger()
        logger.setLevel(getattr(logging, self.logging.log_level.upper()))
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # File handler with rotation
        log_file_path = Path(self.logging.log_dir) / self.logging.log_file
        file_handler = RotatingFileHandler(
            log_file_path,
            maxBytes=self.logging.max_log_size_mb * 1024 * 1024,
            backupCount=self.logging.backup_count
        )
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        # Console handler
        if self.logging.enable_console_logging:
            console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter(
                '%(levelname)s - %(name)s - %(message)s'
            )
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)
        
        logging.info("Logging configured successfully")
    
    def get_api_headers(self, service: str) -> Dict[str, str]:
        """Get appropriate headers for external API calls"""
        headers = {
            "User-Agent": "EmailHeaderAnalyzer/2.0",
            "Accept": "application/json"
        }
        
        if service == "abuseipdb" and self.external_apis.abuseipdb_api_key:
            headers["Key"] = self.external_apis.abuseipdb_api_key
        elif service == "virustotal" and self.external_apis.virustotal_api_key:
            headers["x-apikey"] = self.external_apis.virustotal_api_key
        elif service == "ipinfo" and self.external_apis.ipinfo_token:
            headers["Authorization"] = f"Bearer {self.external_apis.ipinfo_token}"
        
        return headers
    
    def is_api_enabled(self, service: str) -> bool:
        """Check if an external API service is properly configured"""
        api_keys = {
            "abuseipdb": self.external_apis.abuseipdb_api_key,
            "virustotal": self.external_apis.virustotal_api_key,
            "ipinfo": self.external_apis.ipinfo_token
        }
        
        return bool(api_keys.get(service))
    
    def get_risk_level(self, score: int) -> str:
        """Determine risk level based on score"""
        if score >= self.analysis.high_risk_threshold:
            return "HIGH"
        elif score >= self.analysis.medium_risk_threshold:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_risk_color(self, score: int) -> str:
        """Get color code for risk level"""
        risk_level = self.get_risk_level(score)
        return {
            "HIGH": "#dc3545",    # Red
            "MEDIUM": "#fd7e14",  # Orange
            "LOW": "#28a745"      # Green
        }.get(risk_level, "#6c757d")  # Gray default

# Global configuration instance
config = AppConfig()
