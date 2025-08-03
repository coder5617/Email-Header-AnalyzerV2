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

def get_ip_network_info(ip_string: str) -> dict:
    """Get network information for IP address"""
    try:
        ip_obj = ipaddress.IPv4Address(ip_string)
        
        return {
            "ip": str(ip_obj),
            "type": classify_ip_type(ip_string),
            "is_valid": True,
            "is_private": ip_obj.is_private,
            "is_public": not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local),
            "version": 4
        }
        
    except ipaddress.AddressValueError:
        return {
            "ip": ip_string,
            "type": "invalid", 
            "is_valid": False,
            "is_private": False,
            "is_public": False,
            "version": None
        }

# Legacy function aliases for backward compatibility
def extract_sender_ips(headers):
    """Legacy alias for extract_ips_from_headers"""
    return extract_ips_from_headers(headers)
