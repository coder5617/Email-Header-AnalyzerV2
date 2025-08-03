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
