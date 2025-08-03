# src/email_header_analyzer/core/enhanced_dns_helper.py

"""
Enhanced DNS helper with comprehensive SPF, DKIM, DMARC analysis and caching
Includes real-time DNS lookups with proper error handling and validation
"""

import dns.resolver
import dns.exception
import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from email_header_analyzer.config import config
from email_header_analyzer.database import database, DomainRecord

logger = logging.getLogger(__name__)

class EnhancedDNSHelper:
    """Enhanced DNS helper with comprehensive email authentication analysis"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = config.analysis.dns_timeout
        self.resolver.lifetime = config.analysis.dns_timeout
        
        # Set custom nameservers if configured
        if config.analysis.dns_nameservers:
            self.resolver.nameservers = config.analysis.dns_nameservers
    
    def get_spf_record(self, domain: str) -> Optional[str]:
        """Get SPF record for domain"""
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if txt_record.startswith('v=spf1'):
                    return txt_record
            return None
        except dns.exception.DNSException:
            return None
    
    def get_dmarc_record(self, domain: str) -> Optional[str]:
        """Get DMARC record for domain"""
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if txt_record.startswith('v=DMARC1'):
                    return txt_record
            return None
        except dns.exception.DNSException:
            return None
    
    def get_mx_records(self, domain: str) -> List[Dict[str, Any]]:
        """Get MX records with enhanced information"""
        try:
            answers = self.resolver.resolve(domain, 'MX')
            mx_records = []
            
            for rdata in answers:
                mx_host = str(rdata.exchange).rstrip('.')
                mx_record = {
                    "priority": rdata.preference,
                    "exchange": mx_host
                }
                mx_records.append(mx_record)
            
            # Sort by priority
            mx_records.sort(key=lambda x: x["priority"])
            logger.debug(f"Found {len(mx_records)} MX records for {domain}")
            return mx_records
            
        except dns.exception.DNSException as e:
            logger.warning(f"MX lookup failed for {domain}: {e}")
            return [{"error": str(e)}]
    
    def analyze_spf_comprehensive(self, domain: str) -> Dict[str, Any]:
        """Comprehensive SPF record analysis"""
        spf_analysis = {
            "domain": domain,
            "record": None,
            "valid": False,
            "mechanisms": [],
            "dns_lookups": 0,
            "warnings": [],
            "errors": [],
            "score": 0
        }
        
        try:
            spf_record = self.get_spf_record(domain)
            if not spf_record:
                spf_analysis["errors"].append("No SPF record found")
                return spf_analysis
            
            spf_analysis["record"] = spf_record
            spf_analysis["valid"] = True
            
            # Parse SPF mechanisms
            mechanisms = spf_record.split()[1:]  # Skip v=spf1
            spf_analysis["mechanisms"] = mechanisms
            
            # Count DNS lookups
            for mechanism in mechanisms:
                if any(mechanism.startswith(prefix) for prefix in ['include:', 'a:', 'mx:', 'exists:']):
                    spf_analysis["dns_lookups"] += 1
                elif mechanism in ['a', 'mx']:
                    spf_analysis["dns_lookups"] += 1
            
            # Validate SPF record
            if spf_analysis["dns_lookups"] > 10:
                spf_analysis["errors"].append(f"Too many DNS lookups: {spf_analysis['dns_lookups']}")
            
            # Calculate score
            spf_analysis["score"] = self._calculate_spf_score(spf_analysis)
            
        except Exception as e:
            logger.error(f"SPF analysis failed for {domain}: {e}")
            spf_analysis["errors"].append(f"Analysis failed: {str(e)}")
        
        return spf_analysis
    
    def analyze_dmarc_comprehensive(self, domain: str) -> Dict[str, Any]:
        """Comprehensive DMARC record analysis"""
        dmarc_analysis = {
            "domain": domain,
            "record": None,
            "valid": False,
            "policy": None,
            "alignment": {"spf": "r", "dkim": "r"},
            "warnings": [],
            "errors": [],
            "score": 0
        }
        
        try:
            dmarc_record = self.get_dmarc_record(domain)
            if not dmarc_record:
                dmarc_analysis["errors"].append("No DMARC record found")
                return dmarc_analysis
            
            dmarc_analysis["record"] = dmarc_record
            dmarc_analysis["valid"] = True
            
            # Parse DMARC policy
            parts = dmarc_record.split(';')
            for part in parts:
                part = part.strip()
                if '=' in part:
                    key, value = part.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == 'p':
                        dmarc_analysis["policy"] = value
                    elif key == 'aspf':
                        dmarc_analysis["alignment"]["spf"] = value
                    elif key == 'adkim':
                        dmarc_analysis["alignment"]["dkim"] = value
            
            # Calculate score
            dmarc_analysis["score"] = self._calculate_dmarc_score(dmarc_analysis)
            
        except Exception as e:
            logger.error(f"DMARC analysis failed for {domain}: {e}")
            dmarc_analysis["errors"].append(f"Analysis failed: {str(e)}")
        
        return dmarc_analysis
    
    def discover_dkim_records(self, domain: str) -> Dict[str, Any]:
        """Discover DKIM records using common selectors"""
        dkim_analysis = {
            "domain": domain,
            "selectors_found": [],
            "selectors_tested": [],
            "records": {},
            "score": 0
        }
        
        common_selectors = [
            "default", "selector1", "selector2", "google", "k1", "k2",
            "dkim", "mail", "email", "s1", "s2"
        ]
        
        for selector in common_selectors:
            dkim_analysis["selectors_tested"].append(selector)
            
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                answers = self.resolver.resolve(dkim_domain, 'TXT')
                
                record_parts = []
                for rdata in answers:
                    record_parts.append(str(rdata).strip('"'))
                
                full_record = ''.join(record_parts)
                if 'v=DKIM1' in full_record or 'k=' in full_record:
                    dkim_analysis["selectors_found"].append(selector)
                    dkim_analysis["records"][selector] = full_record
                    
            except dns.exception.DNSException:
                continue
        
        dkim_analysis["score"] = len(dkim_analysis["selectors_found"]) * 20
        return dkim_analysis
    
    def _calculate_spf_score(self, analysis: Dict[str, Any]) -> int:
        """Calculate SPF security score"""
        score = 40 if analysis["valid"] else 0
        score -= len(analysis["errors"]) * 10
        score -= len(analysis["warnings"]) * 5
        return max(0, min(100, score))
    
    def _calculate_dmarc_score(self, analysis: Dict[str, Any]) -> int:
        """Calculate DMARC security score"""
        score = 30 if analysis["valid"] else 0
        
        policy_scores = {"reject": 40, "quarantine": 25, "none": 10}
        score += policy_scores.get(analysis["policy"], 0)
        
        score -= len(analysis["errors"]) * 15
        return max(0, min(100, score))
