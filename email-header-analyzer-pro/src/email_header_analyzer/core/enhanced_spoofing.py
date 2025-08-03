"""
Enhanced spoofing detector with comprehensive BEC and impersonation detection
"""

import re
import logging
from typing import Any, Dict, List, Optional
from email_header_analyzer.utils.validators import extract_email_domain, extract_email_address

logger = logging.getLogger(__name__)

class EnhancedSpoofingDetector:
    """Enhanced spoofing detection with BEC and executive impersonation analysis"""
    
    def __init__(self):
        # Executive titles and common impersonation targets
        self.executive_titles = [
            'ceo', 'chief executive', 'president', 'cfo', 'chief financial',
            'coo', 'chief operating', 'cto', 'chief technology', 'ciso',
            'chief information security', 'vp', 'vice president', 'director',
            'manager', 'head of', 'senior', 'executive', 'founder'
        ]
        
        # BEC-related keywords and phrases
        self.bec_keywords = {
            'urgent_payment': [
                'urgent payment', 'wire transfer', 'payment request', 'invoice payment',
                'urgent transfer', 'immediate payment', 'process payment', 'make payment'
            ],
            'confidential': [
                'confidential', 'private', 'sensitive', 'classified', 'restricted',
                'do not share', 'between us', 'keep this quiet', 'internal only'
            ],
            'authority': [
                'approved by', 'authorized by', 'on behalf of', 'representing',
                'acting for', 'mandate from', 'instruction from', 'order from'
            ],
            'urgency': [
                'asap', 'immediately', 'urgent', 'rush', 'time sensitive',
                'deadline', 'before close', 'end of day', 'critical'
            ],
            'financial': [
                'bank details', 'account number', 'routing number', 'swift code',
                'banking information', 'payment details', 'wire instructions'
            ]
        }
        
        # Common spoofing domains and patterns
        self.spoofing_patterns = [
            r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$',  # Free domains
            r'\d+\.', r'-\d+\.', r'_\d+\.',  # Numeric patterns
            r'[0o1l]{2,}',  # Character substitution
            r'[.-]{2,}',  # Multiple separators
        ]
        
        # Legitimate domain variations that might be spoofed
        self.common_domains = [
            'gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com',
            'amazon.com', 'microsoft.com', 'google.com', 'apple.com',
            'paypal.com', 'ebay.com', 'facebook.com', 'twitter.com'
        ]
    
    def analyze(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive spoofing analysis"""
        logger.info("Starting enhanced spoofing analysis")
        
        analysis = {
            "domain_spoofing": self._analyze_domain_spoofing(headers),
            "display_name_spoofing": self._analyze_display_name_spoofing(headers),
            "executive_impersonation": self._analyze_executive_impersonation(headers),
            "bec_indicators": self._analyze_bec_indicators(headers),
            "lookalike_domains": self._analyze_lookalike_domains(headers),
            "header_inconsistencies": self._analyze_header_inconsistencies(headers),
            "risk_score": 0,
            "issues": [],
            "recommendations": []
        }
        
        # Calculate overall risk score
        analysis["risk_score"] = self._calculate_spoofing_risk(analysis)
        
        # Collect issues and recommendations
        analysis["issues"] = self._collect_spoofing_issues(analysis)
        analysis["recommendations"] = self._generate_spoofing_recommendations(analysis)
        
        return analysis
    
    def _analyze_domain_spoofing(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze domain-level spoofing indicators"""
        from_header = headers.get("From", "")
        return_path = headers.get("Return-Path", "")
        reply_to = headers.get("Reply-To", "")
        
        from_domain = extract_email_domain(from_header)
        return_path_domain = extract_email_domain(return_path)
        reply_to_domain = extract_email_domain(reply_to)
        
        analysis = {
            "from_domain": from_domain,
            "return_path_domain": return_path_domain,
            "reply_to_domain": reply_to_domain,
            "domain_mismatch": False,
            "suspicious_domains": [],
            "free_email_service": False,
            "newly_registered": False,
            "issues": []
        }
        
        # Check for domain mismatches
        if from_domain and return_path_domain and from_domain != return_path_domain:
            analysis["domain_mismatch"] = True
            analysis["issues"].append(f"Domain mismatch: From ({from_domain}) vs Return-Path ({return_path_domain})")
        
        if from_domain and reply_to_domain and from_domain != reply_to_domain:
            analysis["issues"].append(f"Domain mismatch: From ({from_domain}) vs Reply-To ({reply_to_domain})")
        
        # Check for suspicious domain patterns
        for domain in [from_domain, return_path_domain, reply_to_domain]:
            if domain and self._is_suspicious_domain(domain):
                analysis["suspicious_domains"].append(domain)
        
        # Check for free email services
        free_email_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com']
        if from_domain and from_domain.lower() in free_email_domains:
            analysis["free_email_service"] = True
        
        return analysis
    
    def _analyze_display_name_spoofing(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze display name spoofing"""
        from_header = headers.get("From", "")
        
        analysis = {
            "display_name": None,
            "email_address": None,
            "contains_email": False,
            "executive_keywords": [],
            "impersonation_indicators": [],
            "unicode_spoofing": False,
            "issues": []
        }
        
        # Extract display name and email
        display_match = re.match(r'^"?([^"<]+?)"?\s*<([^>]+)>$', from_header.strip())
        if display_match:
            analysis["display_name"] = display_match.group(1).strip()
            analysis["email_address"] = display_match.group(2).strip()
        else:
            # Simple email format
            if "@" in from_header:
                analysis["email_address"] = from_header.strip()
            else:
                analysis["display_name"] = from_header.strip()
        
        display_name = analysis["display_name"]
        if display_name:
            # Check if display name contains an email address
            if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', display_name):
                analysis["contains_email"] = True
                analysis["issues"].append("Display name contains email address")
            
            # Check for executive titles
            display_lower = display_name.lower()
            for title in self.executive_titles:
                if title in display_lower:
                    analysis["executive_keywords"].append(title)
            
            # Check for impersonation indicators
            if any(keyword in display_lower for keyword in ['on behalf', 'for', 'representing']):
                analysis["impersonation_indicators"].append("Authority impersonation phrases")
            
            # Check for Unicode spoofing
            if any(ord(char) > 127 for char in display_name):
                analysis["unicode_spoofing"] = True
                analysis["issues"].append("Unicode characters in display name (possible spoofing)")
        
        return analysis
    
    def _analyze_executive_impersonation(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze executive impersonation attempts"""
        from_header = headers.get("From", "")
        subject = headers.get("Subject", "")
        
        analysis = {
            "executive_indicators": [],
            "authority_language": [],
            "impersonation_risk": "LOW",
            "confidence_score": 0
        }
        
        # Check From header for executive indicators
        from_lower = from_header.lower()
        subject_lower = subject.lower()
        
        # Executive title detection
        executive_count = 0
        for title in self.executive_titles:
            if title in from_lower:
                analysis["executive_indicators"].append(f"Executive title in From: {title}")
                executive_count += 1
        
        # Authority language detection
        authority_phrases = [
            'need you to', 'require you to', 'asking you to', 'want you to',
            'can you help', 'need your help', 'urgent request', 'immediate action'
        ]
        
        for phrase in authority_phrases:
            if phrase in subject_lower:
                analysis["authority_language"].append(f"Authority phrase in Subject: {phrase}")
        
        # Calculate confidence score
        confidence = 0
        confidence += executive_count * 25
        confidence += len(analysis["authority_language"]) * 15
        
        analysis["confidence_score"] = min(confidence, 100)
        
        # Determine risk level
        if confidence >= 50:
            analysis["impersonation_risk"] = "HIGH"
        elif confidence >= 25:
            analysis["impersonation_risk"] = "MEDIUM"
        
        return analysis
    
    def _analyze_bec_indicators(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Business Email Compromise indicators"""
        subject = headers.get("Subject", "")
        from_header = headers.get("From", "")
        
        analysis = {
            "keywords_found": [],
            "categories": [],
            "risk_level": "LOW",
            "confidence_score": 0,
            "financial_keywords": [],
            "urgency_keywords": [],
            "authority_keywords": []
        }
        
        text_to_analyze = f"{subject} {from_header}".lower()
        
        # Check each BEC category
        for category, keywords in self.bec_keywords.items():
            found_keywords = []
            for keyword in keywords:
                if keyword in text_to_analyze:
                    found_keywords.append(keyword)
                    analysis["keywords_found"].append(keyword)
            
            if found_keywords:
                analysis["categories"].append(category)
                
                # Categorize keywords
                if category == 'financial':
                    analysis["financial_keywords"].extend(found_keywords)
                elif category == 'urgency':
                    analysis["urgency_keywords"].extend(found_keywords)
                elif category == 'authority':
                    analysis["authority_keywords"].extend(found_keywords)
        
        # Calculate confidence score
        confidence = 0
        confidence += len(analysis["financial_keywords"]) * 30
        confidence += len(analysis["urgency_keywords"]) * 20
        confidence += len(analysis["authority_keywords"]) * 25
        confidence += len(set(analysis["categories"])) * 15
        
        analysis["confidence_score"] = min(confidence, 100)
        
        # Determine risk level
        if confidence >= 60:
            analysis["risk_level"] = "HIGH"
        elif confidence >= 30:
            analysis["risk_level"] = "MEDIUM"
        
        return analysis
    
    def _analyze_lookalike_domains(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze lookalike domain usage"""
        from_domain = extract_email_domain(headers.get("From", ""))
        
        analysis = {
            "domain": from_domain,
            "is_lookalike": False,
            "target_domain": None,
            "similarity_score": 0,
            "techniques_used": []
        }
        
        if not from_domain:
            return analysis
        
        # Check against common domains
        for common_domain in self.common_domains:
            similarity = self._calculate_domain_similarity(from_domain, common_domain)
            if similarity > analysis["similarity_score"]:
                analysis["similarity_score"] = similarity
                analysis["target_domain"] = common_domain
        
        # Determine if it's a lookalike (high similarity but not exact match)
        if analysis["similarity_score"] > 0.8 and from_domain != analysis["target_domain"]:
            analysis["is_lookalike"] = True
            analysis["techniques_used"] = self._identify_spoofing_techniques(from_domain, analysis["target_domain"])
        
        return analysis
    
    def _analyze_header_inconsistencies(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze header inconsistencies that might indicate spoofing"""
        analysis = {
            "inconsistencies": [],
            "missing_headers": [],
            "suspicious_headers": [],
            "risk_score": 0
        }
        
        # Check for missing standard headers
        standard_headers = ["From", "To", "Subject", "Date", "Message-ID"]
        for header in standard_headers:
            if header not in headers:
                analysis["missing_headers"].append(header)
        
        # Check for suspicious header values
        message_id = headers.get("Message-ID", "")
        if message_id:
            # Check for generic or suspicious Message-ID patterns
            if re.search(r'^<\d+\.\d+@', message_id):
                analysis["suspicious_headers"].append("Generic Message-ID pattern")
        
        # Check Date header
        date_header = headers.get("Date", "")
        if date_header:
            try:
                from email.utils import parsedate_to_datetime
                from datetime import datetime, timezone
                
                parsed_date = parsedate_to_datetime(date_header)
                now = datetime.now(timezone.utc)
                
                # Check for future dates
                if parsed_date > now:
                    analysis["inconsistencies"].append("Date header is in the future")
                
                # Check for very old dates (more than 1 year)
                if (now - parsed_date).days > 365:
                    analysis["inconsistencies"].append("Date header is more than 1 year old")
                    
            except Exception:
                analysis["inconsistencies"].append("Invalid Date header format")
        
        # Calculate risk score
        risk_score = 0
        risk_score += len(analysis["inconsistencies"]) * 20
        risk_score += len(analysis["missing_headers"]) * 10
        risk_score += len(analysis["suspicious_headers"]) * 15
        
        analysis["risk_score"] = min(risk_score, 100)
        
        return analysis
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain has suspicious characteristics"""
        domain_lower = domain.lower()
        
        # Check against suspicious patterns
        for pattern in self.spoofing_patterns:
            if re.search(pattern, domain_lower):
                return True
        
        # Check for excessive length
        if len(domain) > 50:
            return True
        
        # Check for excessive subdomains
        if domain.count('.') > 3:
            return True
        
        # Check for suspicious character combinations
        if re.search(r'[0o1l]{3,}', domain_lower):  # Multiple confusing characters
            return True
        
        return False
    
    def _calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity between two domains using Levenshtein distance"""
        def levenshtein_distance(s1: str, s2: str) -> int:
            if len(s1) < len(s2):
                return levenshtein_distance(s2, s1)
            
            if len(s2) == 0:
                return len(s1)
            
            previous_row = list(range(len(s2) + 1))
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            
            return previous_row[-1]
        
        # Calculate similarity as 1 - (distance / max_length)
        distance = levenshtein_distance(domain1.lower(), domain2.lower())
        max_length = max(len(domain1), len(domain2))
        
        if max_length == 0:
            return 0.0
        
        return 1.0 - (distance / max_length)
    
    def _identify_spoofing_techniques(self, spoofed_domain: str, target_domain: str) -> List[str]:
        """Identify spoofing techniques used in lookalike domain"""
        techniques = []
        
        spoofed_lower = spoofed_domain.lower()
        target_lower = target_domain.lower()
        
        # Character substitution
        char_substitutions = {
            'o': '0', '0': 'o', 'l': '1', '1': 'l', 'i': '1',
            'e': '3', 'a': '@', 's': ', 'g': '9'
        }
        
        for original, substitute in char_substitutions.items():
            if original in target_lower and substitute in spoofed_lower:
                techniques.append(f"Character substitution: {original} → {substitute}")
        
        # Subdomain addition
        if target_lower in spoofed_lower and spoofed_lower != target_lower:
            techniques.append("Subdomain addition")
        
        # TLD substitution
        target_tld = target_lower.split('.')[-1]
        spoofed_tld = spoofed_lower.split('.')[-1]
        if target_tld != spoofed_tld:
            techniques.append(f"TLD substitution: .{target_tld} → .{spoofed_tld}")
        
        # Character insertion/deletion
        if len(spoofed_lower) != len(target_lower):
            if len(spoofed_lower) > len(target_lower):
                techniques.append("Character insertion")
            else:
                techniques.append("Character deletion")
        
        # Homograph attack (Unicode characters that look similar)
        if any(ord(char) > 127 for char in spoofed_domain):
            techniques.append("Unicode homograph attack")
        
        return techniques
    
    def _calculate_spoofing_risk(self, analysis: Dict[str, Any]) -> int:
        """Calculate overall spoofing risk score"""
        risk_score = 0
        
        # Domain spoofing risk
        domain_analysis = analysis["domain_spoofing"]
        if domain_analysis["domain_mismatch"]:
            risk_score += 30
        if domain_analysis["suspicious_domains"]:
            risk_score += 25
        
        # Display name spoofing risk
        display_analysis = analysis["display_name_spoofing"]
        if display_analysis["contains_email"]:
            risk_score += 20
        if display_analysis["unicode_spoofing"]:
            risk_score += 15
        risk_score += len(display_analysis["executive_keywords"]) * 10
        
        # Executive impersonation risk
        exec_analysis = analysis["executive_impersonation"]
        if exec_analysis["impersonation_risk"] == "HIGH":
            risk_score += 40
        elif exec_analysis["impersonation_risk"] == "MEDIUM":
            risk_score += 25
        
        # BEC indicators risk
        bec_analysis = analysis["bec_indicators"]
        if bec_analysis["risk_level"] == "HIGH":
            risk_score += 35
        elif bec_analysis["risk_level"] == "MEDIUM":
            risk_score += 20
        
        # Lookalike domain risk
        lookalike_analysis = analysis["lookalike_domains"]
        if lookalike_analysis["is_lookalike"]:
            risk_score += 30
        
        # Header inconsistencies risk
        header_analysis = analysis["header_inconsistencies"]
        risk_score += header_analysis["risk_score"] * 0.5  # Weight header inconsistencies less
        
        return min(risk_score, 100)
    
    def _collect_spoofing_issues(self, analysis: Dict[str, Any]) -> List[str]:
        """Collect all spoofing-related issues"""
        issues = []
        
        # Domain spoofing issues
        domain_issues = analysis["domain_spoofing"]["issues"]
        issues.extend([f"Domain: {issue}" for issue in domain_issues])
        
        # Display name spoofing issues
        display_issues = analysis["display_name_spoofing"]["issues"]
        issues.extend([f"Display Name: {issue}" for issue in display_issues])
        
        # Executive impersonation
        exec_analysis = analysis["executive_impersonation"]
        if exec_analysis["impersonation_risk"] in ["HIGH", "MEDIUM"]:
            issues.append(f"Executive impersonation risk: {exec_analysis['impersonation_risk']}")
        
        # BEC indicators
        bec_analysis = analysis["bec_indicators"]
        if bec_analysis["keywords_found"]:
            issues.append(f"BEC keywords detected: {', '.join(bec_analysis['keywords_found'][:3])}")
        
        # Lookalike domains
        lookalike_analysis = analysis["lookalike_domains"]
        if lookalike_analysis["is_lookalike"]:
            issues.append(f"Lookalike domain targeting: {lookalike_analysis['target_domain']}")
        
        # Header inconsistencies
        header_analysis = analysis["header_inconsistencies"]
        if header_analysis["inconsistencies"]:
            issues.extend([f"Header: {issue}" for issue in header_analysis["inconsistencies"]])
        
        return issues
    
    def _generate_spoofing_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate spoofing-related recommendations"""
        recommendations = []
        
        # Domain-based recommendations
        if analysis["domain_spoofing"]["domain_mismatch"]:
            recommendations.append("Verify sender authenticity due to domain mismatch")
        
        if analysis["domain_spoofing"]["suspicious_domains"]:
            recommendations.append("Block or quarantine emails from suspicious domains")
        
        # Executive impersonation recommendations
        if analysis["executive_impersonation"]["impersonation_risk"] == "HIGH":
            recommendations.append("Implement executive impersonation protection policies")
            recommendations.append("Verify requests through alternative communication channels")
        
        # BEC recommendations
        if analysis["bec_indicators"]["risk_level"] in ["HIGH", "MEDIUM"]:
            recommendations.append("Apply additional scrutiny for potential BEC attempt")
            recommendations.append("Verify financial requests through established procedures")
        
        # Lookalike domain recommendations
        if analysis["lookalike_domains"]["is_lookalike"]:
            recommendations.append("Block lookalike domains at email gateway")
            recommendations.append("Implement domain similarity detection")
        
        # General recommendations
        if analysis["risk_score"] > 70:
            recommendations.append("Block or quarantine this email immediately")
        elif analysis["risk_score"] > 40:
            recommendations.append("Flag for manual review before delivery")
        
        return recommendations
