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
