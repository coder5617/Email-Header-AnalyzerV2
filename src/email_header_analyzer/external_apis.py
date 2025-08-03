"""
Enhanced external API integrations for IP reputation, geographic data, and threat intelligence
Includes rate limiting, caching, and error handling
"""

import time
import asyncio
import aiohttp
import requests
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from email_header_analyzer.config import config
from email_header_analyzer.database import database, IPRecord

logger = logging.getLogger(__name__)

@dataclass
class APIResponse:
    """Standardized API response container"""
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    response_time: Optional[float] = None
    cached: bool = False

class RateLimiter:
    """Simple rate limiter for API calls"""
    
    def __init__(self, calls_per_minute: int = 60):
        self.calls_per_minute = calls_per_minute
        self.calls = []
    
    def can_make_call(self) -> bool:
        """Check if we can make an API call within rate limits"""
        now = time.time()
        # Remove calls older than 1 minute
        self.calls = [call_time for call_time in self.calls if now - call_time < 60]
        
        return len(self.calls) < self.calls_per_minute
    
    def record_call(self):
        """Record an API call"""
        self.calls.append(time.time())
    
    def wait_time(self) -> float:
        """Get time to wait before next call"""
        if self.can_make_call():
            return 0
        
        if self.calls:
            oldest_call = min(self.calls)
            return max(0, 60 - (time.time() - oldest_call))
        return 0

class IPInfoAPI:
    """IPInfo.io API integration for geographic and ISP data"""
    
    def __init__(self):
        self.base_url = "https://ipinfo.io"
        self.rate_limiter = RateLimiter(calls_per_minute=50)  # Free tier limit
        self.session = requests.Session()
        self.session.headers.update(config.get_api_headers("ipinfo"))
    
    def get_ip_info(self, ip: str) -> APIResponse:
        """Get comprehensive IP information"""
        start_time = time.time()
        
        try:
            # Check cache first
            cached_record = database.get_ip_record(ip)
            if cached_record and database.is_record_fresh(cached_record.last_updated):
                logger.debug(f"Using cached data for IP {ip}")
                return APIResponse(
                    success=True,
                    data=self._ip_record_to_dict(cached_record),
                    cached=True,
                    response_time=time.time() - start_time
                )
            
            # Check rate limits
            if not self.rate_limiter.can_make_call():
                wait_time = self.rate_limiter.wait_time()
                logger.warning(f"Rate limit hit, waiting {wait_time:.1f} seconds")
                time.sleep(wait_time)
            
            # Make API call
            url = f"{self.base_url}/{ip}/json"
            response = self.session.get(url, timeout=config.external_apis.api_request_timeout)
            
            response_time = time.time() - start_time
            self.rate_limiter.record_call()
            
            # Log API usage
            database.log_api_usage(
                service="ipinfo",
                endpoint=url,
                response_time=response_time,
                status_code=response.status_code
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Cache the result
                ip_record = IPRecord(
                    ip=ip,
                    country=data.get("country"),
                    city=data.get("city"),
                    region=data.get("region"),
                    isp=data.get("org"),
                    organization=data.get("org"),
                    last_updated=datetime.now()
                )
                database.save_ip_record(ip_record)
                
                return APIResponse(
                    success=True,
                    data=data,
                    response_time=response_time
                )
            else:
                error_msg = f"IPInfo API error: {response.status_code}"
                logger.error(error_msg)
                return APIResponse(success=False, error=error_msg, response_time=response_time)
                
        except Exception as e:
            error_msg = f"IPInfo API exception: {str(e)}"
            logger.error(error_msg)
            database.log_api_usage(
                service="ipinfo",
                endpoint=f"{self.base_url}/{ip}/json",
                error_message=error_msg
            )
            return APIResponse(success=False, error=error_msg, response_time=time.time() - start_time)
    
    def _ip_record_to_dict(self, record: IPRecord) -> Dict[str, Any]:
        """Convert IPRecord to dictionary format"""
        return {
            "ip": record.ip,
            "country": record.country,
            "city": record.city,
            "region": record.region,
            "org": record.isp,
            "cached": True
        }

class AbuseIPDBAPI:
    """AbuseIPDB API integration for IP reputation and abuse reports"""
    
    def __init__(self):
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.rate_limiter = RateLimiter(calls_per_minute=100)
        self.session = requests.Session()
        self.session.headers.update(config.get_api_headers("abuseipdb"))
    
    def check_ip(self, ip: str, max_age_days: int = 90) -> APIResponse:
        """Check IP reputation and abuse reports"""
        start_time = time.time()
        
        try:
            # Check cache first
            cached_record = database.get_ip_record(ip)
            if (cached_record and cached_record.blacklist_status and 
                database.is_record_fresh(cached_record.last_updated, hours=12)):
                logger.debug(f"Using cached AbuseIPDB data for IP {ip}")
                return APIResponse(
                    success=True,
                    data=cached_record.blacklist_status,
                    cached=True,
                    response_time=time.time() - start_time
                )
            
            # Check rate limits
            if not self.rate_limiter.can_make_call():
                wait_time = self.rate_limiter.wait_time()
                logger.warning(f"AbuseIPDB rate limit hit, waiting {wait_time:.1f} seconds")
                time.sleep(wait_time)
            
            # Make API call
            url = f"{self.base_url}/check"
            params = {
                "ipAddress": ip,
                "maxAgeInDays": max_age_days,
                "verbose": ""
            }
            
            response = self.session.get(url, params=params, timeout=config.external_apis.api_request_timeout)
            
            response_time = time.time() - start_time
            self.rate_limiter.record_call()
            
            # Log API usage
            database.log_api_usage(
                service="abuseipdb",
                endpoint=url,
                response_time=response_time,
                status_code=response.status_code
            )
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                
                # Update cache
                if cached_record:
                    cached_record.is_malicious = data.get("abuseConfidencePercentage", 0) > 25
                    cached_record.reputation_score = 100 - data.get("abuseConfidencePercentage", 0)
                    cached_record.blacklist_status = data
                    cached_record.last_updated = datetime.now()
                    database.save_ip_record(cached_record)
                else:
                    ip_record = IPRecord(
                        ip=ip,
                        is_malicious=data.get("abuseConfidencePercentage", 0) > 25,
                        reputation_score=100 - data.get("abuseConfidencePercentage", 0),
                        blacklist_status=data,
                        last_updated=datetime.now()
                    )
                    database.save_ip_record(ip_record)
                
                return APIResponse(
                    success=True,
                    data=data,
                    response_time=response_time
                )
            else:
                error_msg = f"AbuseIPDB API error: {response.status_code}"
                logger.error(error_msg)
                return APIResponse(success=False, error=error_msg, response_time=response_time)
                
        except Exception as e:
            error_msg = f"AbuseIPDB API exception: {str(e)}"
            logger.error(error_msg)
            database.log_api_usage(
                service="abuseipdb",
                endpoint=f"{self.base_url}/check",
                error_message=error_msg
            )
            return APIResponse(success=False, error=error_msg, response_time=time.time() - start_time)

class VirusTotalAPI:
    """VirusTotal API integration for IP and domain reputation"""
    
    def __init__(self):
        self.base_url = "https://www.virustotal.com/api/v3"
        self.rate_limiter = RateLimiter(calls_per_minute=4)  # Free tier limit
        self.session = requests.Session()
        self.session.headers.update(config.get_api_headers("virustotal"))
    
    def check_ip(self, ip: str) -> APIResponse:
        """Check IP reputation on VirusTotal"""
        start_time = time.time()
        
        try:
            # Check cache first
            cached_record = database.get_ip_record(ip)
            if (cached_record and cached_record.blacklist_status and 
                "virustotal" in cached_record.blacklist_status and
                database.is_record_fresh(cached_record.last_updated, hours=24)):
                logger.debug(f"Using cached VirusTotal data for IP {ip}")
                return APIResponse(
                    success=True,
                    data=cached_record.blacklist_status.get("virustotal", {}),
                    cached=True,
                    response_time=time.time() - start_time
                )
            
            # Check rate limits
            if not self.rate_limiter.can_make_call():
                wait_time = self.rate_limiter.wait_time()
                logger.warning(f"VirusTotal rate limit hit, waiting {wait_time:.1f} seconds")
                time.sleep(wait_time)
            
            # Make API call
            url = f"{self.base_url}/ip_addresses/{ip}"
            response = self.session.get(url, timeout=config.external_apis.api_request_timeout)
            
            response_time = time.time() - start_time
            self.rate_limiter.record_call()
            
            # Log API usage
            database.log_api_usage(
                service="virustotal",
                endpoint=url,
                response_time=response_time,
                status_code=response.status_code
            )
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                
                # Extract relevant information
                vt_data = {
                    "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                    "reputation": attributes.get("reputation", 0),
                    "harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                    "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0)
                }
                
                # Update cache
                if cached_record:
                    if not cached_record.blacklist_status:
                        cached_record.blacklist_status = {}
                    cached_record.blacklist_status["virustotal"] = vt_data
                    cached_record.last_updated = datetime.now()
                    database.save_ip_record(cached_record)
                else:
                    ip_record = IPRecord(
                        ip=ip,
                        blacklist_status={"virustotal": vt_data},
                        last_updated=datetime.now()
                    )
                    database.save_ip_record(ip_record)
                
                return APIResponse(
                    success=True,
                    data=vt_data,
                    response_time=response_time
                )
            else:
                error_msg = f"VirusTotal API error: {response.status_code}"
                logger.error(error_msg)
                return APIResponse(success=False, error=error_msg, response_time=response_time)
                
        except Exception as e:
            error_msg = f"VirusTotal API exception: {str(e)}"
            logger.error(error_msg)
            database.log_api_usage(
                service="virustotal",
                endpoint=f"{self.base_url}/ip_addresses/{ip}",
                error_message=error_msg
            )
            return APIResponse(success=False, error=error_msg, response_time=time.time() - start_time)
    
    def check_domain(self, domain: str) -> APIResponse:
        """Check domain reputation on VirusTotal"""
        start_time = time.time()
        
        try:
            # Check cache first
            cached_record = database.get_domain_record(domain)
            if (cached_record and cached_record.reputation_score is not None and
                database.is_record_fresh(cached_record.last_updated, hours=24)):
                logger.debug(f"Using cached VirusTotal domain data for {domain}")
                return APIResponse(
                    success=True,
                    data={"reputation": cached_record.reputation_score},
                    cached=True,
                    response_time=time.time() - start_time
                )
            
            # Check rate limits
            if not self.rate_limiter.can_make_call():
                wait_time = self.rate_limiter.wait_time()
                logger.warning(f"VirusTotal rate limit hit, waiting {wait_time:.1f} seconds")
                time.sleep(wait_time)
            
            # Make API call
            url = f"{self.base_url}/domains/{domain}"
            response = self.session.get(url, timeout=config.external_apis.api_request_timeout)
            
            response_time = time.time() - start_time
            self.rate_limiter.record_call()
            
            # Log API usage
            database.log_api_usage(
                service="virustotal",
                endpoint=url,
                response_time=response_time,
                status_code=response.status_code
            )
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                
                reputation = attributes.get("reputation", 0)
                analysis_stats = attributes.get("last_analysis_stats", {})
                
                # Calculate suspicion score
                malicious = analysis_stats.get("malicious", 0)
                suspicious = analysis_stats.get("suspicious", 0)
                total_scans = sum(analysis_stats.values()) if analysis_stats else 1
                
                suspicion_score = ((malicious + suspicious) / total_scans) * 100 if total_scans > 0 else 0
                
                vt_data = {
                    "reputation": reputation,
                    "last_analysis_stats": analysis_stats,
                    "suspicion_score": suspicion_score
                }
                
                # Update cache
                if cached_record:
                    cached_record.reputation_score = reputation
                    cached_record.is_suspicious = suspicion_score > 10
                    cached_record.last_updated = datetime.now()
                    database.save_domain_record(cached_record)
                
                return APIResponse(
                    success=True,
                    data=vt_data,
                    response_time=response_time
                )
            else:
                error_msg = f"VirusTotal domain API error: {response.status_code}"
                logger.error(error_msg)
                return APIResponse(success=False, error=error_msg, response_time=response_time)
                
        except Exception as e:
            error_msg = f"VirusTotal domain API exception: {str(e)}"
            logger.error(error_msg)
            database.log_api_usage(
                service="virustotal",
                endpoint=f"{self.base_url}/domains/{domain}",
                error_message=error_msg
            )
            return APIResponse(success=False, error=error_msg, response_time=time.time() - start_time)

class DNSBlacklistChecker:
    """Check IPs against various DNS blacklists"""
    
    def __init__(self):
        self.blacklists = [
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "dnsbl.sorbs.net",
            "pbl.spamhaus.org",
            "sbl.spamhaus.org",
            "xbl.spamhaus.org",
            "cbl.abuseat.org",
            "psbl.surriel.com",
            "ubl.unsubscore.com",
            "dnsbl-1.uceprotect.net"
        ]
    
    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP against multiple DNS blacklists"""
        import socket
        
        try:
            # Reverse the IP for DNS queries
            reversed_ip = ".".join(reversed(ip.split(".")))
            
            results = {}
            blacklisted_count = 0
            
            for blacklist in self.blacklists:
                try:
                    query = f"{reversed_ip}.{blacklist}"
                    socket.gethostbyname(query)
                    results[blacklist] = True
                    blacklisted_count += 1
                except socket.gaierror:
                    results[blacklist] = False
                except Exception as e:
                    logger.warning(f"Error checking {blacklist}: {e}")
                    results[blacklist] = None
            
            return {
                "blacklists": results,
                "total_lists": len(self.blacklists),
                "blacklisted_count": blacklisted_count,
                "blacklisted_percentage": (blacklisted_count / len(self.blacklists)) * 100,
                "is_blacklisted": blacklisted_count > 0
            }
            
        except Exception as e:
            logger.error(f"DNS blacklist check failed for {ip}: {e}")
            return {
                "error": str(e),
                "is_blacklisted": False
            }

class ExternalAPIManager:
    """Unified manager for all external API integrations"""
    
    def __init__(self):
        self.ipinfo = IPInfoAPI() if config.is_api_enabled("ipinfo") else None
        self.abuseipdb = AbuseIPDBAPI() if config.is_api_enabled("abuseipdb") else None
        self.virustotal = VirusTotalAPI() if config.is_api_enabled("virustotal") else None
        self.dns_blacklist = DNSBlacklistChecker()
    
    async def analyze_ip_comprehensive(self, ip: str) -> Dict[str, Any]:
        """Perform comprehensive IP analysis using all available services"""
        results = {
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "services_used": [],
            "errors": []
        }
        
        # IPInfo for geographic data
        if self.ipinfo:
            try:
                ipinfo_result = self.ipinfo.get_ip_info(ip)
                if ipinfo_result.success:
                    results["geographic"] = ipinfo_result.data
                    results["services_used"].append("ipinfo")
                else:
                    results["errors"].append(f"IPInfo: {ipinfo_result.error}")
            except Exception as e:
                results["errors"].append(f"IPInfo exception: {str(e)}")
        
        # AbuseIPDB for reputation
        if self.abuseipdb:
            try:
                abuse_result = self.abuseipdb.check_ip(ip)
                if abuse_result.success:
                    results["reputation"] = abuse_result.data
                    results["services_used"].append("abuseipdb")
                else:
                    results["errors"].append(f"AbuseIPDB: {abuse_result.error}")
            except Exception as e:
                results["errors"].append(f"AbuseIPDB exception: {str(e)}")
        
        # VirusTotal for additional reputation data
        if self.virustotal:
            try:
                vt_result = self.virustotal.check_ip(ip)
                if vt_result.success:
                    results["virustotal"] = vt_result.data
                    results["services_used"].append("virustotal")
                else:
                    results["errors"].append(f"VirusTotal: {vt_result.error}")
            except Exception as e:
                results["errors"].append(f"VirusTotal exception: {str(e)}")
        
        # DNS Blacklist checks
        try:
            blacklist_result = self.dns_blacklist.check_ip(ip)
            results["blacklists"] = blacklist_result
            results["services_used"].append("dns_blacklists")
        except Exception as e:
            results["errors"].append(f"DNS Blacklists: {str(e)}")
        
        return results
    
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze domain reputation"""
        results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "services_used": [],
            "errors": []
        }
        
        # VirusTotal domain check
        if self.virustotal:
            try:
                vt_result = self.virustotal.check_domain(domain)
                if vt_result.success:
                    results["virustotal"] = vt_result.data
                    results["services_used"].append("virustotal")
                else:
                    results["errors"].append(f"VirusTotal: {vt_result.error}")
            except Exception as e:
                results["errors"].append(f"VirusTotal exception: {str(e)}")
        
        return results
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get status of all external services"""
        return {
            "ipinfo": {
                "enabled": self.ipinfo is not None,
                "api_key_configured": config.is_api_enabled("ipinfo")
            },
            "abuseipdb": {
                "enabled": self.abuseipdb is not None,
                "api_key_configured": config.is_api_enabled("abuseipdb")
            },
            "virustotal": {
                "enabled": self.virustotal is not None,
                "api_key_configured": config.is_api_enabled("virustotal")
            },
            "dns_blacklists": {
                "enabled": True,
                "blacklists_count": len(self.dns_blacklist.blacklists)
            }
        }

# Global API manager instance
api_manager = ExternalAPIManager()
