"""
Enhanced validators for email addresses and domains with comprehensive validation
"""

import re
import logging
from typing import Optional
from email_validator import validate_email, EmailNotValidError

logger = logging.getLogger(__name__)

def is_valid_email(email_address: str) -> bool:
    """Validate email address format"""
    try:
        validate_email(email_address)
        return True
    except EmailNotValidError:
        return False
    except Exception as e:
        logger.error(f"Email validation error: {e}")
        return False

def extract_email_address(header: str) -> Optional[str]:
    """Extract email address from email header (handles display names)"""
    if not header:
        return None
    
    header = header.strip()
    
    # Pattern for "Display Name" <email@domain.com>
    display_name_pattern = r'^"?([^"<]*?)"?\s*<([^>]+)>$'
    match = re.match(display_name_pattern, header)
    
    if match:
        return match.group(2).strip()
    
    # Pattern for simple email format
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    match = re.search(email_pattern, header)
    
    if match:
        return match.group(0)
    
    # If header looks like a simple email address
    if '@' in header and '.' in header:
        # Remove any angle brackets
        cleaned = header.strip('<>')
        if is_valid_email(cleaned):
            return cleaned
    
    return None

def extract_email_domain(header: str) -> Optional[str]:
    """Extract domain from email header"""
    email_address = extract_email_address(header)
    
    if email_address and '@' in email_address:
        domain = email_address.split('@')[-1].strip()
        return domain if domain else None
    
    return None

def validate_domain_format(domain: str) -> bool:
    """Validate domain format"""
    if not domain:
        return False
    
    # Basic domain format validation
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    
    if not re.match(domain_pattern, domain):
        return False
    
    # Check length constraints
    if len(domain) > 253:
        return False
    
    # Check label length (each part between dots)
    labels = domain.split('.')
    for label in labels:
        if len(label) > 63 or len(label) == 0:
            return False
    
    return True

def extract_display_name(header: str) -> Optional[str]:
    """Extract display name from email header"""
    if not header:
        return None
    
    header = header.strip()
    
    # Pattern for "Display Name" <email@domain.com>
    display_name_pattern = r'^"?([^"<]+?)"?\s*<[^>]+>$'
    match = re.match(display_name_pattern, header)
    
    if match:
        display_name = match.group(1).strip()
        return display_name if display_name else None
    
    return None

def normalize_email_address(email_address: str) -> str:
    """Normalize email address for comparison"""
    if not email_address:
        return ""
    
    # Convert to lowercase
    normalized = email_address.lower().strip()
    
    # Remove angle brackets if present
    normalized = normalized.strip('<>')
    
    return normalized

def is_disposable_email_domain(domain: str) -> bool:
    """Check if domain is a known disposable email service"""
    # Common disposable email domains
    disposable_domains = {
        '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
        'mailinator.com', 'yopmail.com', 'throwaway.email',
        'temp-mail.org', 'getairmail.com', 'emailondeck.com'
    }
    
    return domain.lower() in disposable_domains

def is_free_email_service(domain: str) -> bool:
    """Check if domain is a free email service"""
    free_email_domains = {
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
        'aol.com', 'icloud.com', 'protonmail.com', 'mail.com',
        'zoho.com', 'yandex.com', 'gmx.com'
    }
    
    return domain.lower() in free_email_domains