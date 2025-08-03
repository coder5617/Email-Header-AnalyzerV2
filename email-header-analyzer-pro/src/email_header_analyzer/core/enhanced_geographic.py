"""
Enhanced geographic analyzer with external API integrations and detailed analysis
"""

import logging
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
from email_header_analyzer.utils.ip_helper import extract_ips_from_headers
from email_header_analyzer.external_apis import api_manager
from email_header_analyzer.config import config

logger = logging.getLogger(__name__)

class EnhancedGeographicAnalyzer:
    """Enhanced geographic analyzer with comprehensive IP analysis"""
    
    def __init__(self):
        self.api_manager = api_manager
        self.suspicious_countries = [
            "CN", "RU", "KP", "IR"  # Common sources of malicious traffic
        ]
        self.suspicious_asns = [
            # Known hosting providers frequently used for malicious activities
            "AS13335",  # Cloudflare (legitimate but often abused)
            "AS16509",  # Amazon (legitimate but often abused)
        ]
    
    def analyze(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive geographic analysis"""
        logger.info("Starting enhanced geographic analysis")
        
        # Extract IPs from headers
        sender_ips = extract_ips_from_headers(headers)
        
        if not sender_ips:
            return {
                "sender_ips": [],
                "analysis": {},
                "risk_factors": ["No sender IPs found"],
                "risk_score": 50,
                "issues": ["Unable to determine sender location"]
            }
        
        # Analyze each IP
        analysis_results = {}
        for ip in sender_ips:
            analysis_results[ip] = self._analyze_ip_comprehensive(ip)
        
        # Generate summary analysis
        summary = self._generate_summary_analysis(sender_ips, analysis_results)
        
        return {
            "sender_ips": sender_ips,
            "analysis": analysis_results,
            "summary": summary,
            "risk_factors": summary.get("risk_factors", []),
            "risk_score": summary.get("risk_score", 0),
            "issues": summary.get("issues", []),
            "recommendations": summary.get("recommendations", [])
        }
    
    def _analyze_ip_comprehensive(self, ip: str) -> Dict[str, Any]:
        """Perform comprehensive analysis of a single IP"""
        logger.debug(f"Analyzing IP: {ip}")
        
        analysis = {
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "geographic": {},
            "reputation": {},
            "blacklists": {},
            "risk_score": 0,
            "risk_factors": [],
            "is_suspicious": False
        }
        
        try:
            # Use async analysis for better performance
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            comprehensive_analysis = loop.run_until_complete(
                self.api_manager.analyze_ip_comprehensive(ip)
            )
            
            loop.close()
            
            # Process geographic data
            if "geographic" in comprehensive_analysis:
                analysis["geographic"] = self._process_geographic_data(
                    comprehensive_analysis["geographic"]
                )
            
            # Process reputation data
            if "reputation" in comprehensive_analysis:
                analysis["reputation"] = self._process_reputation_data(
                    comprehensive_analysis["reputation"]
                )
            
            # Process VirusTotal data
            if "virustotal" in comprehensive_analysis:
                analysis["virustotal"] = comprehensive_analysis["virustotal"]
            
            # Process blacklist data
            if "blacklists" in comprehensive_analysis:
                analysis["blacklists"] = comprehensive_analysis["blacklists"]
            
            # Calculate risk score and factors
            risk_analysis = self._calculate_ip_risk(analysis)
            analysis.update(risk_analysis)
            
        except Exception as e:
            logger.error(f"Comprehensive IP analysis failed for {ip}: {e}")
            analysis["error"] = str(e)
            analysis["risk_score"] = 50  # Neutral score on error
        
        return analysis
    
    def _process_geographic_data(self, geo_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process and enhance geographic data"""
        processed = {
            "country": geo_data.get("country"),
            "country_code": geo_data.get("country"),
            "city": geo_data.get("city"),
            "region": geo_data.get("region"),
            "isp": geo_data.get("org"),
            "organization": geo_data.get("org"),
            "timezone": geo_data.get("timezone"),
            "coordinates": None,
            "is_suspicious_location": False
        }
        
        # Extract coordinates if available
        loc = geo_data.get("loc", "")
        if loc and "," in loc:
            try:
                lat, lon = loc.split(",")
                processed["coordinates"] = {
                    "latitude": float(lat),
                    "longitude": float(lon)
                }
            except (ValueError, TypeError):
                pass
        
        # Check for suspicious locations
        country_code = processed.get("country_code", "")
        if country_code in self.suspicious_countries:
            processed["is_suspicious_location"] = True
        
        return processed
    
    def _process_reputation_data(self, rep_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process reputation data from AbuseIPDB"""
        processed = {
            "abuse_confidence": rep_data.get("abuseConfidencePercentage", 0),
            "usage_type": rep_data.get("usageType"),
            "is_public": rep_data.get("isPublic", False),
            "is_whitelisted": rep_data.get("isWhitelisted", False),
            "country_code": rep_data.get("countryCode"),
            "total_reports": rep_data.get("totalReports", 0),
            "num_distinct_users": rep_data.get("numDistinctUsers", 0),
            "last_reported": rep_data.get("lastReportedAt"),
            "categories": rep_data.get("categories", []),
            "is_malicious": rep_data.get("abuseConfidencePercentage", 0) > 25
        }
        
        return processed
    
    def _calculate_ip_risk(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate risk score and identify risk factors for an IP"""
        risk_score = 0
        risk_factors = []
        
        # Geographic risk factors
        geo_data = analysis.get("geographic", {})
        if geo_data.get("is_suspicious_location"):
            risk_score += 30
            country = geo_data.get("country", "Unknown")
            risk_factors.append(f"Located in high-risk country: {country}")
        
        # Reputation risk factors
        rep_data = analysis.get("reputation", {})
        abuse_confidence = rep_data.get("abuse_confidence", 0)
        
        if abuse_confidence > 75:
            risk_score += 40
            risk_factors.append(f"High abuse confidence: {abuse_confidence}%")
        elif abuse_confidence > 50:
            risk_score += 25
            risk_factors.append(f"Moderate abuse confidence: {abuse_confidence}%")
        elif abuse_confidence > 25:
            risk_score += 15
            risk_factors.append(f"Low abuse confidence: {abuse_confidence}%")
        
        if rep_data.get("total_reports", 0) > 10:
            risk_score += 20
            risk_factors.append(f"Multiple abuse reports: {rep_data['total_reports']}")
        
        # VirusTotal risk factors
        vt_data = analysis.get("virustotal", {})
        if vt_data:
            malicious_count = vt_data.get("malicious", 0)
            suspicious_count = vt_data.get("suspicious", 0)
            
            if malicious_count > 0:
                risk_score += 35
                risk_factors.append(f"Flagged as malicious by {malicious_count} engines")
            elif suspicious_count > 0:
                risk_score += 20
                risk_factors.append(f"Flagged as suspicious by {suspicious_count} engines")
        
        # Blacklist risk factors
        blacklist_data = analysis.get("blacklists", {})
        if blacklist_data.get("is_blacklisted"):
            blacklisted_count = blacklist_data.get("blacklisted_count", 0)
            risk_score += min(blacklisted_count * 10, 30)
            risk_factors.append(f"Listed on {blacklisted_count} DNS blacklists")
        
        # Usage type risk factors
        usage_type = rep_data.get("usage_type", "").lower()
        if "hosting" in usage_type or "datacenter" in usage_type:
            risk_score += 10
            risk_factors.append("Hosted on datacenter/hosting provider")
        
        return {
            "risk_score": min(risk_score, 100),
            "risk_factors": risk_factors,
            "is_suspicious": risk_score > 30
        }
    
    def _generate_summary_analysis(self, ips: List[str], 
                                 analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary analysis from individual IP analyses"""
        summary = {
            "total_ips": len(ips),
            "countries": set(),
            "cities": set(),
            "organizations": set(),
            "risk_score": 0,
            "risk_factors": [],
            "issues": [],
            "recommendations": [],
            "high_risk_ips": [],
            "blacklisted_ips": [],
            "reputation_summary": {
                "clean": 0,
                "suspicious": 0,
                "malicious": 0
            }
        }
        
        total_risk = 0
        
        for ip, analysis in analysis_results.items():
            if "error" in analysis:
                summary["issues"].append(f"Analysis failed for IP {ip}")
                continue
            
            # Collect geographic information
            geo_data = analysis.get("geographic", {})
            if geo_data.get("country"):
                summary["countries"].add(geo_data["country"])
            if geo_data.get("city"):
                summary["cities"].add(geo_data["city"])
            if geo_data.get("organization"):
                summary["organizations"].add(geo_data["organization"])
            
            # Aggregate risk scores
            ip_risk = analysis.get("risk_score", 0)
            total_risk += ip_risk
            
            # Categorize IPs by risk
            if ip_risk > 70:
                summary["high_risk_ips"].append(ip)
                summary["reputation_summary"]["malicious"] += 1
            elif ip_risk > 40:
                summary["reputation_summary"]["suspicious"] += 1
            else:
                summary["reputation_summary"]["clean"] += 1
            
            # Track blacklisted IPs
            if analysis.get("blacklists", {}).get("is_blacklisted"):
                summary["blacklisted_ips"].append(ip)
            
            # Collect risk factors
            summary["risk_factors"].extend(analysis.get("risk_factors", []))
        
        # Calculate overall risk score
        summary["risk_score"] = int(total_risk / len(ips)) if ips else 0
        
        # Generate issues
        if summary["high_risk_ips"]:
            summary["issues"].append(f"{len(summary['high_risk_ips'])} high-risk IPs detected")
        
        if summary["blacklisted_ips"]:
            summary["issues"].append(f"{len(summary['blacklisted_ips'])} IPs on blacklists")
        
        if len(summary["countries"]) > 3:
            summary["issues"].append(f"Email routed through {len(summary['countries'])} countries")
        
        # Generate recommendations
        if summary["high_risk_ips"]:
            summary["recommendations"].append("Investigate high-risk sender IPs")
        
        if summary["blacklisted_ips"]:
            summary["recommendations"].append("Block or quarantine emails from blacklisted IPs")
        
        if len(summary["countries"]) > 2:
            summary["recommendations"].append("Review routing path for suspicious geography")
        
        # Convert sets to lists for JSON serialization
        summary["countries"] = list(summary["countries"])
        summary["cities"] = list(summary["cities"])
        summary["organizations"] = list(summary["organizations"])
        
        return summary
    
    def get_ip_timeline(self, headers: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate timeline of email routing with geographic data"""
        timeline = []
        
        received_headers = headers.get("Received", [])
        if isinstance(received_headers, str):
            received_headers = [received_headers]
        
        # Process in reverse order (original sender first)
        for i, received in enumerate(reversed(received_headers)):
            hop = {
                "hop_number": i + 1,
                "raw_header": received,
                "timestamp": self._extract_timestamp(received),
                "from_ip": None,
                "geographic": None,
                "analysis": None
            }
            
            # Extract IP from received header
            from email_header_analyzer.utils.ip_helper import extract_ip_from_received
            ip = extract_ip_from_received(received)
            
            if ip:
                hop["from_ip"] = ip
                # Get geographic data for this IP
                ip_analysis = self._analyze_ip_comprehensive(ip)
                hop["geographic"] = ip_analysis.get("geographic", {})
                hop["analysis"] = {
                    "risk_score": ip_analysis.get("risk_score", 0),
                    "is_suspicious": ip_analysis.get("is_suspicious", False)
                }
            
            timeline.append(hop)
        
        return timeline
    
    def _extract_timestamp(self, received_header: str) -> Optional[str]:
        """Extract timestamp from Received header"""
        import re
        from email.utils import parsedate_to_datetime
        
        # Look for timestamp at the end of Received header
        timestamp_pattern = r';?\s*([A-Za-z]{3},?\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s*[+-]?\d{4})'
        match = re.search(timestamp_pattern, received_header)
        
        if match:
            try:
                dt = parsedate_to_datetime(match.group(1))
                return dt.isoformat()
            except Exception:
                pass
        
        return None
