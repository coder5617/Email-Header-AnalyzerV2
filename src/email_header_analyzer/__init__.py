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
