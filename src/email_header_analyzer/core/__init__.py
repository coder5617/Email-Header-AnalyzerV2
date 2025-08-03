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
