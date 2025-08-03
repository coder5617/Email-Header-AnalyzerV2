"""
Enhanced email header parser with comprehensive analysis capabilities
"""

import email
import email.header
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

from email_header_analyzer.core.enhanced_authentication import EnhancedAuthenticationAnalyzer
from email_header_analyzer.core.enhanced_routing import EnhancedRoutingAnalyzer
from email_header_analyzer.core.enhanced_spoofing import EnhancedSpoofingDetector
from email_header_analyzer.core.enhanced_geographic import EnhancedGeographicAnalyzer
from email_header_analyzer.core.enhanced_content import EnhancedContentAnalyzer

logger = logging.getLogger(__name__)

class EnhancedEmailHeaderParser:
    """Enhanced email header parser with comprehensive analysis"""
    
    def __init__(self):
        self.authentication_analyzer = EnhancedAuthenticationAnalyzer()
        self.routing_analyzer = EnhancedRoutingAnalyzer()
        self.spoofing_detector = EnhancedSpoofingDetector()
        self.geographic_analyzer = EnhancedGeographicAnalyzer()
        self.content_analyzer = EnhancedContentAnalyzer()
    
    def parse_headers(self, raw_headers: str) -> Dict[str, Any]:
        """Parse raw email headers into structured format"""
        logger.info("Parsing email headers")
        
        if not raw_headers.strip():
            raise ValueError("No email headers provided")
        
        try:
            # Parse using Python's email library
            msg = email.message_from_string(raw_headers)
            parsed_headers = {}
            
            # Process each header
            for name, value in msg.items():
                decoded_value = self._decode_header_value(value)
                
                # Handle multiple headers with same name
                if name in parsed_headers:
                    if not isinstance(parsed_headers[name], list):
                        parsed_headers[name] = [parsed_headers[name]]
                    parsed_headers[name].append(decoded_value)
                else:
                    parsed_headers[name] = decoded_value
            
            logger.info(f"Successfully parsed {len(parsed_headers)} headers")
            return parsed_headers
            
        except Exception as e:
            logger.error(f"Header parsing failed: {e}")
            raise ValueError(f"Failed to parse email headers: {str(e)}")
    
    def _decode_header_value(self, value: str) -> str:
        """Decode header value handling various encodings"""
        try:
            decoded_parts = email.header.decode_header(value)
            decoded_value = ""
            
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_value += part.decode(encoding, errors='ignore')
                    else:
                        # Try common encodings
                        for enc in ['utf-8', 'latin-1', 'ascii']:
                            try:
                                decoded_value += part.decode(enc)
                                break
                            except UnicodeDecodeError:
                                continue
                        else:
                            # Fallback to utf-8 with errors ignored
                            decoded_value += part.decode('utf-8', errors='ignore')
                else:
                    decoded_value += str(part)
            
            return decoded_value.strip()
            
        except Exception as e:
            logger.warning(f"Header decoding failed: {e}")
            return str(value)
    
    def analyze_headers_comprehensive(self, raw_headers: str, 
                                    config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Perform comprehensive analysis of email headers"""
        logger.info("Starting comprehensive header analysis")
        
        analysis_config = config or {}
        start_time = datetime.now()
        
        try:
            # Parse headers
            parsed_headers = self.parse_headers(raw_headers)
            
            # Initialize results structure
            results = {
                "analysis_metadata": {
                    "timestamp": start_time.isoformat(),
                    "analysis_mode": analysis_config.get("analysis_mode", "comprehensive"),
                    "version": "2.0.0"
                },
                "parsed_headers": parsed_headers,
                "authentication": {},
                "routing": {},
                "spoofing": {},
                "geographic": {},
                "content": {},
                "summary": {}
            }
            
            # Perform analysis based on configuration
            analysis_mode = analysis_config.get("analysis_mode", "comprehensive")
            
            if analysis_mode in ["comprehensive", "authentication_only"]:
                logger.info("Performing authentication analysis")
                results["authentication"] = self.authentication_analyzer.analyze(
                    parsed_headers, parsed_headers
                )
            
            if analysis_mode in ["comprehensive", "quick_scan"]:
                logger.info("Performing routing analysis")
                results["routing"] = self.routing_analyzer.analyze(parsed_headers)
                
                logger.info("Performing spoofing analysis")
                results["spoofing"] = self.spoofing_detector.analyze(parsed_headers)
                
                if analysis_config.get("enable_content", True):
                    logger.info("Performing content analysis")
                    results["content"] = self.content_analyzer.analyze(parsed_headers)
            
            if analysis_mode in ["comprehensive", "geographic_only"] and analysis_config.get("enable_geographic", True):
                logger.info("Performing geographic analysis")
                results["geographic"] = self.geographic_analyzer.analyze(parsed_headers)
            
            # Generate summary
            results["summary"] = self._generate_comprehensive_summary(results, parsed_headers)
            
            # Calculate processing time
            processing_time = (datetime.now() - start_time).total_seconds()
            results["analysis_metadata"]["processing_time_seconds"] = processing_time
            
            logger.info(f"Comprehensive analysis completed in {processing_time:.2f} seconds")
            return results
            
        except Exception as e:
            logger.error(f"Comprehensive analysis failed: {e}")
            return {
                "error": str(e),
                "analysis_metadata": {
                    "timestamp": start_time.isoformat(),
                    "failed": True,
                    "error_message": str(e)
                }
            }
    
    def _generate_comprehensive_summary(self, results: Dict[str, Any], 
                                      parsed_headers: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive analysis summary"""
        logger.info("Generating analysis summary")
        
        summary = {
            "email_metadata": self._extract_email_metadata(parsed_headers),
            "security_assessment": self._assess_security(results),
            "risk_factors": self._collect_risk_factors(results),
            "recommendations": self._generate_recommendations(results),
            "critical_issues": self._identify_critical_issues(results),
            "compliance_status": self._assess_compliance(results)
        }
        
        return summary
    
    def _extract_email_metadata(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key email metadata"""
        metadata = {
            "from_address": headers.get("From", ""),
            "to_address": headers.get("To", ""),
            "subject": headers.get("Subject", ""),
            "date": headers.get("Date", ""),
            "message_id": headers.get("Message-ID", ""),
            "return_path": headers.get("Return-Path", ""),
            "reply_to": headers.get("Reply-To", ""),
            "total_headers": len(headers),
            "has_attachments": "Content-Type" in headers and "multipart" in headers.get("Content-Type", "").lower()
        }
        
        # Parse date
        if metadata["date"]:
            try:
                from email.utils import parsedate_to_datetime
                metadata["parsed_date"] = parsedate_to_datetime(metadata["date"]).isoformat()
            except Exception:
                metadata["parsed_date"] = None
        
        return metadata
    
    def _assess_security(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall security posture"""
        security_scores = {}
        
        # Authentication security
        auth_data = results.get("authentication", {})
        security_scores["authentication"] = auth_data.get("overall_score", 0)
        
        # Anti-spoofing security
        spoof_data = results.get("spoofing", {})
        security_scores["anti_spoofing"] = max(0, 100 - spoof_data.get("risk_score", 0))
        
        # Geographic security
        geo_data = results.get("geographic", {})
        geo_risk = geo_data.get("summary", {}).get("risk_score", 0)
        security_scores["geographic"] = max(0, 100 - geo_risk)
        
        # Routing security
        routing_data = results.get("routing", {})
        routing_issues = len(routing_data.get("issues", []))
        security_scores["routing"] = max(0, 100 - (routing_issues * 20))
        
        # Content security
        content_data = results.get("content", {})
        content_risk = content_data.get("risk_score", 0)
        security_scores["content"] = max(0, 100 - content_risk)
        
        # Calculate overall score
        valid_scores = [score for score in security_scores.values() if score > 0]
        overall_score = int(sum(valid_scores) / len(valid_scores)) if valid_scores else 0
        
        return {
            "overall_score": overall_score,
            "individual_scores": security_scores,
            "security_level": self._get_security_level(overall_score),
            "pass_threshold": overall_score >= 70
        }
    
    def _get_security_level(self, score: int) -> str:
        """Get security level based on score"""
        if score >= 90:
            return "EXCELLENT"
        elif score >= 80:
            return "GOOD"
        elif score >= 70:
            return "ACCEPTABLE"
        elif score >= 50:
            return "POOR"
        else:
            return "CRITICAL"
    
    def _collect_risk_factors(self, results: Dict[str, Any]) -> List[str]:
        """Collect all identified risk factors"""
        risk_factors = []
        
        # Authentication risks
        auth_data = results.get("authentication", {})
        auth_issues = auth_data.get("issues", [])
        risk_factors.extend([f"Auth: {issue}" for issue in auth_issues])
        
        # Spoofing risks
        spoof_data = results.get("spoofing", {})
        spoof_issues = spoof_data.get("issues", [])
        risk_factors.extend([f"Spoofing: {issue}" for issue in spoof_issues])
        
        # Geographic risks
        geo_data = results.get("geographic", {})
        geo_risks = geo_data.get("risk_factors", [])
        risk_factors.extend([f"Geographic: {risk}" for risk in geo_risks])
        
        # Routing risks
        routing_data = results.get("routing", {})
        routing_issues = routing_data.get("issues", [])
        risk_factors.extend([f"Routing: {issue}" for issue in routing_issues])
        
        # Content risks
        content_data = results.get("content", {})
        content_issues = content_data.get("issues", [])
        risk_factors.extend([f"Content: {issue}" for issue in content_issues])
        
        return risk_factors
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Authentication recommendations
        auth_data = results.get("authentication", {})
        auth_recs = auth_data.get("recommendations", [])
        recommendations.extend(auth_recs)
        
        # Geographic recommendations
        geo_data = results.get("geographic", {})
        geo_recs = geo_data.get("recommendations", [])
        recommendations.extend(geo_recs)
        
        # General security recommendations
        auth_score = auth_data.get("overall_score", 0)
        if auth_score < 50:
            recommendations.append("Implement comprehensive email authentication (SPF, DKIM, DMARC)")
        
        spoof_risk = results.get("spoofing", {}).get("risk_score", 0)
        if spoof_risk > 70:
            recommendations.append("Implement additional anti-spoofing measures")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations
    
    def _identify_critical_issues(self, results: Dict[str, Any]) -> List[str]:
        """Identify critical security issues"""
        critical_issues = []
        
        # Authentication failures
        auth_data = results.get("authentication", {})
        if auth_data.get("overall_score", 0) < 30:
            critical_issues.append("Severe authentication failures detected")
        
        # High spoofing risk
        spoof_data = results.get("spoofing", {})
        if spoof_data.get("risk_score", 0) > 80:
            critical_issues.append("High probability of email spoofing")
        
        # Blacklisted IPs
        geo_data = results.get("geographic", {})
        blacklisted_ips = geo_data.get("summary", {}).get("blacklisted_ips", [])
        if blacklisted_ips:
            critical_issues.append(f"Email from {len(blacklisted_ips)} blacklisted IP(s)")
        
        # High-risk countries
        high_risk_ips = geo_data.get("summary", {}).get("high_risk_ips", [])
        if high_risk_ips:
            critical_issues.append(f"Email routed through {len(high_risk_ips)} high-risk IP(s)")
        
        # Routing anomalies
        routing_data = results.get("routing", {})
        suspicious_hops = routing_data.get("suspicious_hops", [])
        if len(suspicious_hops) > 2:
            critical_issues.append("Multiple suspicious routing hops detected")
        
        return critical_issues
    
    def _assess_compliance(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess compliance with email security standards"""
        compliance = {
            "spf_compliant": False,
            "dkim_compliant": False,
            "dmarc_compliant": False,
            "overall_compliant": False,
            "standards_met": [],
            "standards_failed": []
        }
        
        auth_data = results.get("authentication", {})
        
        # SPF compliance
        spf_data = auth_data.get("spf", {})
        if spf_data.get("status") == "found" and spf_data.get("result") == "pass":
            compliance["spf_compliant"] = True
            compliance["standards_met"].append("SPF")
        else:
            compliance["standards_failed"].append("SPF")
        
        # DKIM compliance
        dkim_data = auth_data.get("dkim", {})
        if dkim_data.get("status") == "found" and dkim_data.get("domains"):
            compliance["dkim_compliant"] = True
            compliance["standards_met"].append("DKIM")
        else:
            compliance["standards_failed"].append("DKIM")
        
        # DMARC compliance
        dmarc_data = auth_data.get("dmarc", {})
        if (dmarc_data.get("status") == "found" and 
            dmarc_data.get("result") == "pass" and
            auth_data.get("alignment", {}).get("overall_aligned")):
            compliance["dmarc_compliant"] = True
            compliance["standards_met"].append("DMARC")
        else:
            compliance["standards_failed"].append("DMARC")
        
        # Overall compliance (all three must pass)
        compliance["overall_compliant"] = (
            compliance["spf_compliant"] and 
            compliance["dkim_compliant"] and 
            compliance["dmarc_compliant"]
        )
        
        return compliance
