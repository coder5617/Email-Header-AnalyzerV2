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
