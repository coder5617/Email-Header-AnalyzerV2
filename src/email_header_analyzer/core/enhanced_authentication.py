"""
Enhanced authentication analyzer with comprehensive SPF, DKIM, DMARC analysis
Includes alignment checks and detailed scoring
"""

import re
import logging
from typing import Any, Dict, List, Optional

# Import utilities with proper error handling
try:
    from email_header_analyzer.utils.validators import extract_email_domain
except ImportError:
    # Fallback function if utils not available
    def extract_email_domain(header: str) -> Optional[str]:
        import re
        if not header or '@' not in header:
            return None
        match = re.search(r'<([^>]+)>', header)
        email = match.group(1) if match else header
        return email.split('@')[-1].strip() if '@' in email else None

try:
    from email_header_analyzer.core.enhanced_dns_helper import EnhancedDNSHelper
    dns_helper = EnhancedDNSHelper()
except ImportError:
    # Fallback DNS helper
    import dns.resolver
    class FallbackDNSHelper:
        def __init__(self):
            self.resolver = dns.resolver.Resolver()
        def analyze_spf_comprehensive(self, domain):
            return {"domain": domain, "valid": False, "record": None}
        def analyze_dmarc_comprehensive(self, domain):
            return {"domain": domain, "valid": False, "record": None}
        def discover_dkim_records(self, domain):
            return {"domain": domain, "selectors_found": []}
    dns_helper = FallbackDNSHelper()

logger = logging.getLogger(__name__)

class EnhancedAuthenticationAnalyzer:
    """Enhanced email authentication analyzer with detailed SPF, DKIM, DMARC analysis"""
    
    def __init__(self):
        self.dns_helper = dns_helper
    
    def analyze(self, headers: Dict[str, Any], parsed_headers: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform comprehensive authentication analysis"""
        logger.info("Starting comprehensive authentication analysis")
        
        # Extract key domains
        from_domain = self._extract_from_domain(headers)
        return_path_domain = self._extract_return_path_domain(headers)
        
        # Analyze each authentication method
        spf_analysis = self._analyze_spf_comprehensive(headers, return_path_domain)
        dkim_analysis = self._analyze_dkim_comprehensive(headers)
        dmarc_analysis = self._analyze_dmarc_comprehensive(headers, from_domain)
        
        # Check alignment
        alignment_analysis = self._analyze_alignment(
            from_domain, return_path_domain, spf_analysis, dkim_analysis, dmarc_analysis
        )
        
        # Calculate overall scores
        overall_score = self._calculate_overall_score(spf_analysis, dkim_analysis, dmarc_analysis, alignment_analysis)
        
        # Identify issues and recommendations
        issues = self._identify_issues(spf_analysis, dkim_analysis, dmarc_analysis, alignment_analysis)
        recommendations = self._generate_recommendations(spf_analysis, dkim_analysis, dmarc_analysis)
        
        return {
            "domains": {
                "from_domain": from_domain,
                "return_path_domain": return_path_domain
            },
            "spf": spf_analysis,
            "dkim": dkim_analysis,
            "dmarc": dmarc_analysis,
            "alignment": alignment_analysis,
            "overall_score": overall_score,
            "risk_level": self._get_risk_level(overall_score),
            "issues": issues,
            "recommendations": recommendations,
            "summary": self._generate_summary(spf_analysis, dkim_analysis, dmarc_analysis, overall_score)
        }
    
    def _extract_from_domain(self, headers: Dict[str, Any]) -> Optional[str]:
        """Extract domain from From header"""
        from_header = headers.get("From", "")
        return extract_email_domain(from_header)
    
    def _extract_return_path_domain(self, headers: Dict[str, Any]) -> Optional[str]:
        """Extract domain from Return-Path header"""
        return_path = headers.get("Return-Path", "")
        if return_path:
            # Remove angle brackets
            return_path = return_path.strip('<>')
            return extract_email_domain(return_path)
        return None
    
    def _analyze_spf_comprehensive(self, headers: Dict[str, Any], return_path_domain: str) -> Dict[str, Any]:
        """Comprehensive SPF analysis with DNS lookups"""
        spf_analysis = {
            "status": "not_found",
            "result": None,
            "details": None,
            "record": None,
            "domain": return_path_domain,
            "dns_analysis": None,
            "score": 0,
            "issues": [],
            "warnings": []
        }
        
        # Check Received-SPF header
        received_spf = headers.get("Received-SPF", "")
        if received_spf:
            spf_analysis["status"] = "found"
            spf_analysis["details"] = received_spf
            
            # Extract result
            spf_results = ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"]
            for result in spf_results:
                if result in received_spf.lower():
                    spf_analysis["result"] = result
                    break
        
        # Perform DNS analysis if domain is available
        if return_path_domain:
            try:
                dns_analysis = self.dns_helper.analyze_spf_comprehensive(return_path_domain)
                spf_analysis["dns_analysis"] = dns_analysis
                spf_analysis["record"] = dns_analysis.get("record")
                
                if dns_analysis.get("valid"):
                    spf_analysis["status"] = "found"
                    if not spf_analysis["result"]:
                        # Infer result from DNS analysis if not in headers
                        spf_analysis["result"] = "unknown"
                
            except Exception as e:
                logger.error(f"SPF DNS analysis failed for {return_path_domain}: {e}")
                spf_analysis["issues"].append(f"DNS lookup failed: {str(e)}")
        
        # Calculate SPF score
        spf_analysis["score"] = self._calculate_spf_score(spf_analysis)
        
        return spf_analysis
    
    def _analyze_dkim_comprehensive(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive DKIM analysis"""
        dkim_analysis = {
            "status": "not_found",
            "signatures": [],
            "domains": [],
            "selectors": [],
            "results": {},
            "dns_analysis": {},
            "score": 0,
            "issues": [],
            "warnings": []
        }
        
        # Parse DKIM-Signature headers
        dkim_signatures = headers.get("DKIM-Signature", [])
        if isinstance(dkim_signatures, str):
            dkim_signatures = [dkim_signatures]
        
        for signature in dkim_signatures:
            parsed_sig = self._parse_dkim_signature(signature)
            if parsed_sig:
                dkim_analysis["signatures"].append(parsed_sig)
                
                domain = parsed_sig.get("domain")
                selector = parsed_sig.get("selector")
                
                if domain and domain not in dkim_analysis["domains"]:
                    dkim_analysis["domains"].append(domain)
                
                if selector:
                    dkim_analysis["selectors"].append(f"{selector}.{domain}")
        
        # Check Authentication-Results for DKIM results
        auth_results = headers.get("Authentication-Results", "")
        if auth_results:
            dkim_results = self._parse_dkim_auth_results(auth_results)
            dkim_analysis["results"].update(dkim_results)
        
        # Perform DNS analysis for each domain
        for domain in dkim_analysis["domains"]:
            try:
                dns_analysis = self.dns_helper.discover_dkim_records(domain)
                dkim_analysis["dns_analysis"][domain] = dns_analysis
            except Exception as e:
                logger.error(f"DKIM DNS analysis failed for {domain}: {e}")
                dkim_analysis["issues"].append(f"DNS lookup failed for {domain}: {str(e)}")
        
        # Update status
        if dkim_analysis["signatures"] or dkim_analysis["domains"]:
            dkim_analysis["status"] = "found"
        
        # Calculate DKIM score
        dkim_analysis["score"] = self._calculate_dkim_score(dkim_analysis)
        
        return dkim_analysis
    
    def _analyze_dmarc_comprehensive(self, headers: Dict[str, Any], from_domain: str) -> Dict[str, Any]:
        """Comprehensive DMARC analysis"""
        dmarc_analysis = {
            "status": "not_found",
            "result": None,
            "domain": from_domain,
            "record": None,
            "dns_analysis": None,
            "policy": None,
            "alignment": {},
            "score": 0,
            "issues": [],
            "warnings": []
        }
        
        # Check Authentication-Results for DMARC result
        auth_results = headers.get("Authentication-Results", "")
        if auth_results:
            dmarc_match = re.search(r"dmarc=([^;,\s]+)", auth_results, re.IGNORECASE)
            if dmarc_match:
                dmarc_analysis["status"] = "found"
                dmarc_analysis["result"] = dmarc_match.group(1)
        
        # Perform DNS analysis if domain is available
        if from_domain:
            try:
                dns_analysis = self.dns_helper.analyze_dmarc_comprehensive(from_domain)
                dmarc_analysis["dns_analysis"] = dns_analysis
                dmarc_analysis["record"] = dns_analysis.get("record")
                dmarc_analysis["policy"] = dns_analysis.get("policy")
                dmarc_analysis["alignment"] = dns_analysis.get("alignment", {})
                
                if dns_analysis.get("valid"):
                    dmarc_analysis["status"] = "found"
                    if not dmarc_analysis["result"]:
                        # Infer result if not in headers
                        dmarc_analysis["result"] = "unknown"
                
            except Exception as e:
                logger.error(f"DMARC DNS analysis failed for {from_domain}: {e}")
                dmarc_analysis["issues"].append(f"DNS lookup failed: {str(e)}")
        
        # Calculate DMARC score
        dmarc_analysis["score"] = self._calculate_dmarc_score(dmarc_analysis)
        
        return dmarc_analysis
    
    def _analyze_alignment(self, from_domain: str, return_path_domain: str, 
                          spf_analysis: Dict, dkim_analysis: Dict, dmarc_analysis: Dict) -> Dict[str, Any]:
        """Analyze SPF and DKIM alignment for DMARC"""
        alignment = {
            "spf_aligned": False,
            "dkim_aligned": False,
            "spf_alignment_mode": "relaxed",
            "dkim_alignment_mode": "relaxed",
            "overall_aligned": False,
            "issues": []
        }
        
        # Get alignment modes from DMARC policy
        if dmarc_analysis.get("alignment"):
            spf_mode = dmarc_analysis["alignment"].get("spf", "r")
            dkim_mode = dmarc_analysis["alignment"].get("dkim", "r")
            
            alignment["spf_alignment_mode"] = "strict" if spf_mode == "s" else "relaxed"
            alignment["dkim_alignment_mode"] = "strict" if dkim_mode == "s" else "relaxed"
        
        # Check SPF alignment
        if from_domain and return_path_domain and spf_analysis.get("result") == "pass":
            if alignment["spf_alignment_mode"] == "strict":
                alignment["spf_aligned"] = from_domain.lower() == return_path_domain.lower()
            else:  # relaxed mode
                # In relaxed mode, organizational domains must match
                alignment["spf_aligned"] = self._domains_align_relaxed(from_domain, return_path_domain)
        
        # Check DKIM alignment
        if from_domain and dkim_analysis.get("domains"):
            for dkim_domain in dkim_analysis["domains"]:
                # Check if this DKIM signature passes
                dkim_result = dkim_analysis.get("results", {}).get(dkim_domain, "unknown")
                if dkim_result == "pass":
                    if alignment["dkim_alignment_mode"] == "strict":
                        if from_domain.lower() == dkim_domain.lower():
                            alignment["dkim_aligned"] = True
                            break
                    else:  # relaxed mode
                        if self._domains_align_relaxed(from_domain, dkim_domain):
                            alignment["dkim_aligned"] = True
                            break
        
        # Overall alignment (either SPF or DKIM must be aligned)
        alignment["overall_aligned"] = alignment["spf_aligned"] or alignment["dkim_aligned"]
        
        # Identify alignment issues
        if not alignment["spf_aligned"] and spf_analysis.get("result") == "pass":
            alignment["issues"].append("SPF passes but domain not aligned")
        
        if not alignment["dkim_aligned"] and dkim_analysis.get("status") == "found":
            alignment["issues"].append("DKIM signature present but domain not aligned")
        
        if not alignment["overall_aligned"]:
            alignment["issues"].append("Neither SPF nor DKIM properly aligned")
        
        return alignment
    
    def _parse_dkim_signature(self, signature: str) -> Optional[Dict[str, Any]]:
        """Parse DKIM signature header"""
        try:
            parsed = {}
            
            # Extract domain (d=)
            domain_match = re.search(r"d=([^;]+)", signature)
            if domain_match:
                parsed["domain"] = domain_match.group(1).strip()
            
            # Extract selector (s=)
            selector_match = re.search(r"s=([^;]+)", signature)
            if selector_match:
                parsed["selector"] = selector_match.group(1).strip()
            
            # Extract algorithm (a=)
            algo_match = re.search(r"a=([^;]+)", signature)
            if algo_match:
                parsed["algorithm"] = algo_match.group(1).strip()
            
            # Extract canonicalization (c=)
            canon_match = re.search(r"c=([^;]+)", signature)
            if canon_match:
                parsed["canonicalization"] = canon_match.group(1).strip()
            
            # Extract headers (h=)
            headers_match = re.search(r"h=([^;]+)", signature)
            if headers_match:
                parsed["headers"] = [h.strip() for h in headers_match.group(1).split(':')]
            
            return parsed if parsed else None
            
        except Exception as e:
            logger.error(f"Failed to parse DKIM signature: {e}")
            return None
    
    def _parse_dkim_auth_results(self, auth_results: str) -> Dict[str, str]:
        """Parse DKIM results from Authentication-Results header"""
        results = {}
        
        # Find all DKIM results
        dkim_pattern = r"dkim=([^;,\s]+)(?:.*?header\.d=([^;,\s]+))?"
        matches = re.finditer(dkim_pattern, auth_results, re.IGNORECASE)
        
        for match in matches:
            result = match.group(1)
            domain = match.group(2) if match.group(2) else "unknown"
            results[domain] = result
        
        return results
    
    def _domains_align_relaxed(self, domain1: str, domain2: str) -> bool:
        """Check if domains align in relaxed mode (organizational domain match)"""
        if not domain1 or not domain2:
            return False
        
        # Simple organizational domain check - get last two parts
        def get_org_domain(domain):
            parts = domain.lower().split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
            return domain.lower()
        
        return get_org_domain(domain1) == get_org_domain(domain2)
    
    def _calculate_spf_score(self, spf_analysis: Dict[str, Any]) -> int:
        """Calculate SPF score"""
        score = 0
        
        # Base score for having SPF
        if spf_analysis["status"] == "found":
            score += 30
        
        # Score based on result
        result_scores = {
            "pass": 40,
            "neutral": 20,
            "softfail": 10,
            "fail": -20,
            "temperror": 5,
            "permerror": -10,
            "none": 0
        }
        
        result = spf_analysis.get("result")
        if result:
            score += result_scores.get(result, 0)
        
        # DNS analysis bonus
        if spf_analysis.get("dns_analysis", {}).get("valid"):
            score += 20
        
        # Deduct for issues
        score -= len(spf_analysis.get("issues", [])) * 10
        score -= len(spf_analysis.get("warnings", [])) * 5
        
        return max(0, min(100, score))
    
    def _calculate_dkim_score(self, dkim_analysis: Dict[str, Any]) -> int:
        """Calculate DKIM score"""
        score = 0
        
        # Base score for having DKIM signatures
        if dkim_analysis["status"] == "found":
            score += 40
        
        # Score for valid signatures
        passing_results = sum(1 for result in dkim_analysis.get("results", {}).values() 
                             if result == "pass")
        score += passing_results * 15
        
        # Score for multiple domains
        score += min(len(dkim_analysis.get("domains", [])), 3) * 10
        
        # DNS analysis bonus
        for domain_analysis in dkim_analysis.get("dns_analysis", {}).values():
            if domain_analysis.get("selectors_found"):
                score += 10
        
        # Deduct for issues
        score -= len(dkim_analysis.get("issues", [])) * 10
        
        return max(0, min(100, score))
    
    def _calculate_dmarc_score(self, dmarc_analysis: Dict[str, Any]) -> int:
        """Calculate DMARC score"""
        score = 0
        
        # Base score for having DMARC
        if dmarc_analysis["status"] == "found":
            score += 30
        
        # Score based on result
        result_scores = {
            "pass": 40,
            "fail": -20,
            "temperror": 5,
            "permerror": -10
        }
        
        result = dmarc_analysis.get("result")
        if result:
            score += result_scores.get(result, 0)
        
        # Policy strength bonus
        policy = dmarc_analysis.get("policy")
        policy_scores = {
            "reject": 20,
            "quarantine": 15,
            "none": 5
        }
        if policy:
            score += policy_scores.get(policy, 0)
        
        # Strict alignment bonus
        alignment = dmarc_analysis.get("alignment", {})
        if alignment.get("spf") == "s":
            score += 5
        if alignment.get("dkim") == "s":
            score += 5
        
        # Deduct for issues
        score -= len(dmarc_analysis.get("issues", [])) * 10
        
        return max(0, min(100, score))
    
    def _calculate_overall_score(self, spf_analysis: Dict, dkim_analysis: Dict, 
                               dmarc_analysis: Dict, alignment_analysis: Dict) -> int:
        """Calculate overall authentication score"""
        # Weighted average of individual scores
        spf_score = spf_analysis.get("score", 0)
        dkim_score = dkim_analysis.get("score", 0)
        dmarc_score = dmarc_analysis.get("score", 0)
        
        # DMARC gets higher weight as it's the policy framework
        overall = (spf_score * 0.3 + dkim_score * 0.3 + dmarc_score * 0.4)
        
        # Alignment bonus
        if alignment_analysis.get("overall_aligned"):
            overall += 10
        else:
            overall -= 15
        
        return max(0, min(100, int(overall)))
    
    def _get_risk_level(self, score: int) -> str:
        """Get risk level based on score"""
        if score >= 80:
            return "LOW"
        elif score >= 60:
            return "MEDIUM"
        elif score >= 40:
            return "HIGH"
        else:
            return "CRITICAL"
    
    def _identify_issues(self, spf_analysis: Dict, dkim_analysis: Dict, 
                        dmarc_analysis: Dict, alignment_analysis: Dict) -> List[str]:
        """Identify authentication issues"""
        issues = []
        
        # SPF issues
        if spf_analysis["status"] == "not_found":
            issues.append("No SPF record found")
        elif spf_analysis.get("result") == "fail":
            issues.append("SPF check failed")
        elif spf_analysis.get("result") == "softfail":
            issues.append("SPF soft failure (suspicious)")
        
        # Add SPF-specific issues
        issues.extend(spf_analysis.get("issues", []))
        
        # DKIM issues
        if dkim_analysis["status"] == "not_found":
            issues.append("No DKIM signatures found")
        elif not any(result == "pass" for result in dkim_analysis.get("results", {}).values()):
            issues.append("No valid DKIM signatures")
        
        # Add DKIM-specific issues
        issues.extend(dkim_analysis.get("issues", []))
        
        # DMARC issues
        if dmarc_analysis["status"] == "not_found":
            issues.append("No DMARC record found")
        elif dmarc_analysis.get("result") == "fail":
            issues.append("DMARC check failed")
        elif dmarc_analysis.get("policy") == "none":
            issues.append("DMARC policy set to 'none' (monitoring only)")
        
        # Add DMARC-specific issues
        issues.extend(dmarc_analysis.get("issues", []))
        
        # Alignment issues
        issues.extend(alignment_analysis.get("issues", []))
        
        return issues
    
    def _generate_recommendations(self, spf_analysis: Dict, dkim_analysis: Dict, 
                                dmarc_analysis: Dict) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # SPF recommendations
        if spf_analysis["status"] == "not_found":
            recommendations.append("Implement SPF record for the sending domain")
        elif spf_analysis.get("result") in ["fail", "softfail"]:
            recommendations.append("Review and fix SPF record configuration")
        
        # DKIM recommendations
        if dkim_analysis["status"] == "not_found":
            recommendations.append("Implement DKIM signing for outbound emails")
        elif not dkim_analysis.get("domains"):
            recommendations.append("Ensure DKIM signatures include proper domain information")
        
        # DMARC recommendations
        if dmarc_analysis["status"] == "not_found":
            recommendations.append("Implement DMARC policy starting with 'p=none'")
        elif dmarc_analysis.get("policy") == "none":
            recommendations.append("Consider upgrading DMARC policy to 'quarantine' or 'reject'")
        
        # Alignment recommendations
        if dmarc_analysis.get("alignment", {}).get("spf") == "r":
            recommendations.append("Consider strict SPF alignment (aspf=s) for enhanced security")
        if dmarc_analysis.get("alignment", {}).get("dkim") == "r":
            recommendations.append("Consider strict DKIM alignment (adkim=s) for enhanced security")
        
        return recommendations
    
    def _generate_summary(self, spf_analysis: Dict, dkim_analysis: Dict, 
                         dmarc_analysis: Dict, overall_score: int) -> Dict[str, Any]:
        """Generate authentication summary"""
        return {
            "overall_score": overall_score,
            "risk_level": self._get_risk_level(overall_score),
            "authentication_methods": {
                "spf": {
                    "present": spf_analysis["status"] == "found",
                    "result": spf_analysis.get("result"),
                    "score": spf_analysis.get("score", 0)
                },
                "dkim": {
                    "present": dkim_analysis["status"] == "found",
                    "domains_count": len(dkim_analysis.get("domains", [])),
                    "score": dkim_analysis.get("score", 0)
                },
                "dmarc": {
                    "present": dmarc_analysis["status"] == "found",
                    "policy": dmarc_analysis.get("policy"),
                    "result": dmarc_analysis.get("result"),
                    "score": dmarc_analysis.get("score", 0)
                }
            },
            "total_issues": (len(spf_analysis.get("issues", [])) + 
                           len(dkim_analysis.get("issues", [])) + 
                           len(dmarc_analysis.get("issues", []))),
            "recommendation": self._get_overall_recommendation(overall_score)
        }
    
    def _get_overall_recommendation(self, score: int) -> str:
        """Get overall recommendation based on score"""
        if score >= 80:
            return "Email authentication is properly configured"
        elif score >= 60:
            return "Good authentication setup with room for improvement"
        elif score >= 40:
            return "Authentication needs attention - multiple issues detected"
        else:
            return "Poor authentication configuration - immediate action required"
