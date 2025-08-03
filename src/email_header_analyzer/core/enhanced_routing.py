"""
Enhanced routing analyzer with comprehensive hop analysis and anomaly detection
"""

import re
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime
from email.utils import parsedate_to_datetime
from email_header_analyzer.utils.ip_helper import extract_ip_from_received, is_private_ip, is_valid_ipv4

logger = logging.getLogger(__name__)

class EnhancedRoutingAnalyzer:
    """Enhanced email routing analyzer with detailed hop analysis"""
    
    def __init__(self):
        self.suspicious_patterns = [
            r'localhost',
            r'127\.0\.0\.1',
            r'192\.168\.',
            r'10\.',
            r'172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'unknown',
            r'none'
        ]
    
    def analyze(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive routing analysis"""
        logger.info("Starting enhanced routing analysis")
        
        received_headers = headers.get("Received", [])
        if isinstance(received_headers, str):
            received_headers = [received_headers]
        
        if not received_headers:
            return {
                "hops": [],
                "total_hops": 0,
                "suspicious_hops": [],
                "routing_path": [],
                "timing_analysis": {},
                "geographic_path": [],
                "issues": ["No Received headers found"],
                "recommendations": ["Verify email routing path"],
                "risk_score": 50
            }
        
        # Parse all hops
        hops = self._parse_all_hops(received_headers)
        
        # Analyze timing
        timing_analysis = self._analyze_timing(hops)
        
        # Identify suspicious hops
        suspicious_hops = self._identify_suspicious_hops(hops)
        
        # Generate routing path
        routing_path = self._generate_routing_path(hops)
        
        # Identify issues and calculate risk
        issues = self._identify_routing_issues(hops, suspicious_hops, timing_analysis)
        risk_score = self._calculate_routing_risk(hops, suspicious_hops, issues)
        
        # Generate recommendations
        recommendations = self._generate_routing_recommendations(issues, suspicious_hops)
        
        return {
            "hops": hops,
            "total_hops": len(hops),
            "suspicious_hops": suspicious_hops,
            "routing_path": routing_path,
            "timing_analysis": timing_analysis,
            "issues": issues,
            "recommendations": recommendations,
            "risk_score": risk_score,
            "analysis_summary": self._generate_routing_summary(hops, suspicious_hops, risk_score)
        }
    
    def _parse_all_hops(self, received_headers: List[str]) -> List[Dict[str, Any]]:
        """Parse all routing hops from Received headers"""
        hops = []
        
        for index, header in enumerate(received_headers):
            hop = self._parse_single_hop(header, index)
            if hop:
                hops.append(hop)
        
        return hops
    
    def _parse_single_hop(self, header: str, index: int) -> Optional[Dict[str, Any]]:
        """Parse a single routing hop"""
        try:
            hop = {
                "index": index,
                "raw": header.strip(),
                "from_host": None,
                "from_ip": None,
                "by_host": None,
                "by_ip": None,
                "timestamp": None,
                "protocol": None,
                "with_info": None,
                "for_info": None,
                "id": None,
                "is_suspicious": False,
                "issues": []
            }
            
            # Extract 'from' information
            from_match = re.search(r'from\s+([^\s\[\(]+)(?:\s*[\[\(]([^\]\)]+)[\]\)])?', header, re.IGNORECASE)
            if from_match:
                hop["from_host"] = from_match.group(1)
                if from_match.group(2):
                    potential_ip = from_match.group(2)
                    if is_valid_ipv4(potential_ip):
                        hop["from_ip"] = potential_ip
            
            # Extract 'by' information
            by_match = re.search(r'by\s+([^\s\[\(]+)(?:\s*[\[\(]([^\]\)]+)[\]\)])?', header, re.IGNORECASE)
            if by_match:
                hop["by_host"] = by_match.group(1)
                if by_match.group(2):
                    potential_ip = by_match.group(2)
                    if is_valid_ipv4(potential_ip):
                        hop["by_ip"] = potential_ip
            
            # Extract timestamp
            timestamp_match = re.search(r';\s*(.+)$', header)
            if timestamp_match:
                hop["timestamp"] = self._parse_timestamp(timestamp_match.group(1).strip())
            
            # Extract protocol
            with_match = re.search(r'with\s+(\w+)', header, re.IGNORECASE)
            if with_match:
                hop["protocol"] = with_match.group(1).upper()
            
            # Extract ID
            id_match = re.search(r'id\s+([^\s;]+)', header, re.IGNORECASE)
            if id_match:
                hop["id"] = id_match.group(1)
            
            # Extract 'for' information
            for_match = re.search(r'for\s+<?([^>\s;]+)>?', header, re.IGNORECASE)
            if for_match:
                hop["for_info"] = for_match.group(1)
            
            # If no IP found in structured format, try general IP extraction
            if not hop["from_ip"]:
                extracted_ip = extract_ip_from_received(header)
                if extracted_ip:
                    hop["from_ip"] = extracted_ip
            
            return hop
            
        except Exception as e:
            logger.error(f"Error parsing hop {index}: {e}")
            return None
    
    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse timestamp from Received header"""
        try:
            return parsedate_to_datetime(timestamp_str)
        except Exception as e:
            logger.debug(f"Failed to parse timestamp '{timestamp_str}': {e}")
            return None
    
    def _analyze_timing(self, hops: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze timing patterns in email routing"""
        timing_analysis = {
            "total_transit_time": None,
            "hop_delays": [],
            "suspicious_delays": [],
            "timestamp_issues": [],
            "chronological_order": True
        }
        
        # Extract valid timestamps
        timestamped_hops = [hop for hop in hops if hop.get("timestamp")]
        
        if len(timestamped_hops) < 2:
            timing_analysis["timestamp_issues"].append("Insufficient timestamps for timing analysis")
            return timing_analysis
        
        # Sort by index (reverse chronological order in headers)
        timestamped_hops.sort(key=lambda x: x["index"])
        
        # Calculate delays between hops
        for i in range(len(timestamped_hops) - 1):
            current_hop = timestamped_hops[i]
            next_hop = timestamped_hops[i + 1]
            
            current_time = current_hop["timestamp"]
            next_time = next_hop["timestamp"]
            
            if current_time and next_time:
                # Check chronological order
                if next_time < current_time:
                    timing_analysis["chronological_order"] = False
                    timing_analysis["timestamp_issues"].append(
                        f"Timestamp inconsistency at hop {next_hop['index']}"
                    )
                
                # Calculate delay
                delay = (next_time - current_time).total_seconds()
                
                hop_delay = {
                    "from_hop": current_hop["index"],
                    "to_hop": next_hop["index"],
                    "delay_seconds": delay,
                    "is_suspicious": delay > 3600 or delay < 0  # More than 1 hour or negative
                }
                
                timing_analysis["hop_delays"].append(hop_delay)
                
                if hop_delay["is_suspicious"]:
                    timing_analysis["suspicious_delays"].append(hop_delay)
        
        # Calculate total transit time
        if timestamped_hops:
            first_hop = timestamped_hops[0]
            last_hop = timestamped_hops[-1]
            
            if first_hop["timestamp"] and last_hop["timestamp"]:
                total_time = (last_hop["timestamp"] - first_hop["timestamp"]).total_seconds()
                timing_analysis["total_transit_time"] = total_time
        
        return timing_analysis
    
    def _identify_suspicious_hops(self, hops: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify suspicious routing hops"""
        suspicious_hops = []
        
        for hop in hops:
            issues = []
            
            # Check for suspicious hostnames
            from_host = hop.get("from_host", "")
            if from_host:
                for pattern in self.suspicious_patterns:
                    if re.search(pattern, from_host, re.IGNORECASE):
                        issues.append(f"Suspicious hostname pattern: {pattern}")
            
            # Check for private IPs in external routing
            from_ip = hop.get("from_ip")
            if from_ip and is_private_ip(from_ip):
                # Only suspicious if not in first few hops (could be legitimate internal routing)
                if hop["index"] > 2:
                    issues.append("Private IP in external routing path")
            
            # Check for missing critical information
            if not from_host and not from_ip:
                issues.append("Missing sender information")
            
            if not hop.get("by_host"):
                issues.append("Missing receiving server information")
            
            # Check for unusual protocols
            protocol = hop.get("protocol", "")
            if protocol and protocol not in ["SMTP", "ESMTP", "LMTP"]:
                issues.append(f"Unusual protocol: {protocol}")
            
            # Check for localhost or loopback
            if from_host and ("localhost" in from_host.lower() or "127.0.0.1" in from_host):
                issues.append("Localhost in routing path")
            
            # Check for generic or suspicious hostnames
            if from_host and any(suspicious in from_host.lower() for suspicious in ["unknown", "none", "temp", "test"]):
                issues.append("Generic or suspicious hostname")
            
            if issues:
                hop_copy = hop.copy()
                hop_copy["issues"] = issues
                hop_copy["is_suspicious"] = True
                suspicious_hops.append(hop_copy)
        
        return suspicious_hops
    
    def _generate_routing_path(self, hops: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate simplified routing path"""
        routing_path = []
        
        for hop in hops:
            path_entry = {
                "hop_number": hop["index"] + 1,
                "server": hop.get("from_host") or hop.get("from_ip") or "Unknown",
                "ip": hop.get("from_ip"),
                "timestamp": hop.get("timestamp").isoformat() if hop.get("timestamp") else None,
                "is_suspicious": hop.get("is_suspicious", False)
            }
            routing_path.append(path_entry)
        
        return routing_path
    
    def _identify_routing_issues(self, hops: List[Dict[str, Any]], 
                               suspicious_hops: List[Dict[str, Any]],
                               timing_analysis: Dict[str, Any]) -> List[str]:
        """Identify routing-related issues"""
        issues = []
        
        # Too many hops
        if len(hops) > 15:
            issues.append(f"Excessive number of hops: {len(hops)} (typical: 3-8)")
        elif len(hops) > 10:
            issues.append(f"High number of hops: {len(hops)}")
        
        # Too few hops (could indicate header manipulation)
        if len(hops) < 2:
            issues.append("Unusually few routing hops (possible header manipulation)")
        
        # Suspicious hops
        if suspicious_hops:
            issues.append(f"{len(suspicious_hops)} suspicious routing hops detected")
        
        # Timing issues
        if not timing_analysis.get("chronological_order"):
            issues.append("Timestamp inconsistencies in routing path")
        
        if timing_analysis.get("suspicious_delays"):
            issues.append(f"{len(timing_analysis['suspicious_delays'])} suspicious timing delays")
        
        # Total transit time issues
        total_time = timing_analysis.get("total_transit_time")
        if total_time:
            if total_time > 86400:  # More than 24 hours
                issues.append(f"Excessive total transit time: {total_time/3600:.1f} hours")
            elif total_time < 0:
                issues.append("Negative total transit time (timestamp issues)")
        
        # Missing critical routing information
        missing_info_count = sum(1 for hop in hops if not hop.get("from_host") and not hop.get("from_ip"))
        if missing_info_count > 0:
            issues.append(f"{missing_info_count} hops missing sender information")
        
        # Check for routing loops
        seen_ips = set()
        seen_hosts = set()
        for hop in hops:
            ip = hop.get("from_ip")
            host = hop.get("from_host")
            
            if ip and ip in seen_ips:
                issues.append(f"Routing loop detected: IP {ip} appears multiple times")
            if host and host in seen_hosts:
                issues.append(f"Routing loop detected: Host {host} appears multiple times")
            
            if ip:
                seen_ips.add(ip)
            if host:
                seen_hosts.add(host)
        
        return issues
    
    def _calculate_routing_risk(self, hops: List[Dict[str, Any]], 
                              suspicious_hops: List[Dict[str, Any]],
                              issues: List[str]) -> int:
        """Calculate routing risk score"""
        risk_score = 0
        
        # Base score for suspicious hops
        if suspicious_hops:
            risk_score += min(len(suspicious_hops) * 15, 60)
        
        # Issues-based scoring
        risk_score += len(issues) * 10
        
        # Hop count risk
        hop_count = len(hops)
        if hop_count > 15:
            risk_score += 30
        elif hop_count > 10:
            risk_score += 15
        elif hop_count < 2:
            risk_score += 25
        
        # Private IP usage risk
        private_ip_hops = sum(1 for hop in hops 
                            if hop.get("from_ip") and is_private_ip(hop["from_ip"]) and hop["index"] > 2)
        risk_score += private_ip_hops * 10
        
        # Missing information risk
        missing_info_hops = sum(1 for hop in hops 
                              if not hop.get("from_host") and not hop.get("from_ip"))
        risk_score += missing_info_hops * 5
        
        return min(risk_score, 100)
    
    def _generate_routing_recommendations(self, issues: List[str], 
                                        suspicious_hops: List[Dict[str, Any]]) -> List[str]:
        """Generate routing-related recommendations"""
        recommendations = []
        
        if suspicious_hops:
            recommendations.append("Investigate suspicious routing hops for potential threats")
        
        if any("excessive" in issue.lower() or "high number" in issue.lower() for issue in issues):
            recommendations.append("Review email routing configuration to reduce hop count")
        
        if any("timestamp" in issue.lower() for issue in issues):
            recommendations.append("Verify server time synchronization in email infrastructure")
        
        if any("missing" in issue.lower() for issue in issues):
            recommendations.append("Ensure all mail servers properly log routing information")
        
        if any("loop" in issue.lower() for issue in issues):
            recommendations.append("Check mail routing configuration for loops")
        
        if any("private ip" in issue.lower() for issue in issues):
            recommendations.append("Review use of private IPs in external email routing")
        
        return recommendations
    
    def _generate_routing_summary(self, hops: List[Dict[str, Any]], 
                                suspicious_hops: List[Dict[str, Any]],
                                risk_score: int) -> Dict[str, Any]:
        """Generate routing analysis summary"""
        return {
            "total_hops": len(hops),
            "suspicious_hops_count": len(suspicious_hops),
            "risk_score": risk_score,
            "risk_level": "HIGH" if risk_score > 70 else "MEDIUM" if risk_score > 40 else "LOW",
            "has_private_ips": any(hop.get("from_ip") and is_private_ip(hop["from_ip"]) for hop in hops),
            "has_timing_issues": any("timestamp" in str(hop.get("issues", [])).lower() for hop in hops),
            "routing_complexity": "HIGH" if len(hops) > 10 else "MEDIUM" if len(hops) > 6 else "LOW",
            "issues": issues,
            "suspicious_hops": suspicious_hops
        }