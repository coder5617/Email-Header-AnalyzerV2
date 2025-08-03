"""
Enhanced content analyzer with comprehensive subject line and social engineering detection
"""

import re
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class EnhancedContentAnalyzer:
    """Enhanced content analyzer for email subject and social engineering detection"""
    
    def __init__(self):
        # Social engineering keywords by category
        self.social_engineering_patterns = {
            'urgency': [
                'urgent', 'asap', 'immediately', 'right away', 'time sensitive',
                'deadline', 'expires today', 'last chance', 'act now', 'hurry',
                'quick', 'rush', 'emergency', 'critical', 'important'
            ],
            'fear': [
                'suspended', 'blocked', 'disabled', 'terminated', 'cancelled',
                'expired', 'compromised', 'security alert', 'violation',
                'unauthorized', 'breach', 'hacked', 'fraud', 'scam'
            ],
            'curiosity': [
                'surprising', 'shocking', 'unbelievable', 'amazing', 'incredible',
                'you won\'t believe', 'secret', 'confidential', 'exclusive',
                'private', 'hidden', 'revealed', 'exposed'
            ],
            'authority': [
                'approved', 'authorized', 'official', 'verified', 'certified',
                'government', 'legal', 'court', 'police', 'fbi', 'irs',
                'bank', 'security team', 'it department', 'compliance'
            ],
            'greed': [
                'free', 'win', 'winner', 'prize', 'reward', 'bonus',
                'discount', 'offer', 'deal', 'save', 'earn', 'profit',
                'money', 'cash', 'refund', 'claim', 'gift'
            ],
            'help': [
                'help', 'assist', 'support', 'favor', 'need you', 'please',
                'request', 'ask', 'require', 'depend on', 'count on'
            ]
        }
        
        # Financial/payment related keywords
        self.financial_keywords = [
            'payment', 'invoice', 'wire', 'transfer', 'bank', 'account',
            'routing', 'swift', 'iban', 'payroll', 'salary', 'bonus',
            'refund', 'credit', 'debit', 'transaction', 'billing'
        ]
        
        # Phishing indicators
        self.phishing_indicators = [
            'verify account', 'confirm identity', 'update information',
            'click here', 'download now', 'open attachment', 'sign in',
            'login', 'password', 'credentials', 'authenticate', 'validate'
        ]
        
        # Malware indicators
        self.malware_indicators = [
            'download', 'install', 'update', 'patch', 'software',
            'antivirus', 'security update', 'system update', 'driver',
            'codec', 'player', 'viewer'
        ]
        
        # Suspicious patterns
        self.suspicious_patterns = [
            r'[A-Z]{3,}',  # Excessive capitals
            r'!{2,}',      # Multiple exclamations
            r'\?{2,}',     # Multiple questions
            r'\${1,}',     # Dollar signs
            r'%{1,}',      # Percentage signs
            r'[0-9]{4,}',  # Long numbers
        ]
    
    def analyze(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive content analysis"""
        logger.info("Starting enhanced content analysis")
        
        subject = headers.get("Subject", "")
        from_header = headers.get("From", "")
        
        analysis = {
            "subject_analysis": self._analyze_subject_comprehensive(subject),
            "social_engineering": self._analyze_social_engineering(subject, from_header),
            "phishing_indicators": self._analyze_phishing_indicators(subject),
            "malware_indicators": self._analyze_malware_indicators(subject),
            "financial_indicators": self._analyze_financial_indicators(subject),
            "language_analysis": self._analyze_language_patterns(subject),
            "encoding_analysis": self._analyze_encoding(subject),
            "risk_score": 0,
            "issues": [],
            "recommendations": []
        }
        
        # Calculate overall risk score
        analysis["risk_score"] = self._calculate_content_risk(analysis)
        
        # Collect issues and recommendations
        analysis["issues"] = self._collect_content_issues(analysis)
        analysis["recommendations"] = self._generate_content_recommendations(analysis)
        
        return analysis
    
    def _analyze_subject_comprehensive(self, subject: str) -> Dict[str, Any]:
        """Comprehensive subject line analysis"""
        if not subject:
            return {
                "subject": "",
                "length": 0,
                "is_empty": True,
                "issues": ["Empty subject line"]
            }
        
        analysis = {
            "subject": subject,
            "length": len(subject),
            "is_empty": False,
            "word_count": len(subject.split()),
            "character_analysis": self._analyze_characters(subject),
            "capitalization": self._analyze_capitalization(subject),
            "punctuation": self._analyze_punctuation(subject),
            "suspicious_patterns": self._find_suspicious_patterns(subject),
            "issues": []
        }
        
        # Length analysis
        if analysis["length"] > 100:
            analysis["issues"].append("Unusually long subject line")
        elif analysis["length"] < 5:
            analysis["issues"].append("Unusually short subject line")
        
        # Word count analysis
        if analysis["word_count"] > 15:
            analysis["issues"].append("Too many words in subject")
        
        # Suspicious patterns
        if analysis["suspicious_patterns"]:
            analysis["issues"].append("Suspicious patterns in subject")
        
        return analysis
    
    def _analyze_social_engineering(self, subject: str, from_header: str) -> Dict[str, Any]:
        """Analyze social engineering tactics"""
        text = f"{subject} {from_header}".lower()
        
        analysis = {
            "categories_detected": [],
            "keywords_found": {},
            "tactics_score": {},
            "overall_score": 0,
            "primary_tactic": None
        }
        
        # Check each category
        for category, keywords in self.social_engineering_patterns.items():
            found_keywords = []
            for keyword in keywords:
                if keyword in text:
                    found_keywords.append(keyword)
            
            if found_keywords:
                analysis["categories_detected"].append(category)
                analysis["keywords_found"][category] = found_keywords
                
                # Calculate category score (more keywords = higher score)
                category_score = min(len(found_keywords) * 20, 100)
                analysis["tactics_score"][category] = category_score
        
        # Calculate overall score
        if analysis["tactics_score"]:
            analysis["overall_score"] = max(analysis["tactics_score"].values())
            analysis["primary_tactic"] = max(analysis["tactics_score"], 
                                           key=analysis["tactics_score"].get)
        
        return analysis
    
    def _analyze_phishing_indicators(self, subject: str) -> Dict[str, Any]:
        """Analyze phishing indicators in content"""
        subject_lower = subject.lower()
        
        analysis = {
            "indicators_found": [],
            "risk_level": "LOW",
            "confidence_score": 0
        }
        
        # Check for phishing keywords
        for indicator in self.phishing_indicators:
            if indicator in subject_lower:
                analysis["indicators_found"].append(indicator)
        
        # Calculate confidence score
        confidence = len(analysis["indicators_found"]) * 25
        analysis["confidence_score"] = min(confidence, 100)
        
        # Determine risk level
        if confidence >= 50:
            analysis["risk_level"] = "HIGH"
        elif confidence >= 25:
            analysis["risk_level"] = "MEDIUM"
        
        return analysis
    
    def _analyze_malware_indicators(self, subject: str) -> Dict[str, Any]:
        """Analyze malware-related indicators"""
        subject_lower = subject.lower()
        
        analysis = {
            "indicators_found": [],
            "risk_level": "LOW",
            "confidence_score": 0
        }
        
        # Check for malware keywords
        for indicator in self.malware_indicators:
            if indicator in subject_lower:
                analysis["indicators_found"].append(indicator)
        
        # Calculate confidence score
        confidence = len(analysis["indicators_found"]) * 30
        analysis["confidence_score"] = min(confidence, 100)
        
        # Determine risk level
        if confidence >= 60:
            analysis["risk_level"] = "HIGH"
        elif confidence >= 30:
            analysis["risk_level"] = "MEDIUM"
        
        return analysis
    
    def _analyze_financial_indicators(self, subject: str) -> Dict[str, Any]:
        """Analyze financial/payment related indicators"""
        subject_lower = subject.lower()
        
        analysis = {
            "keywords_found": [],
            "risk_level": "LOW",
            "confidence_score": 0,
            "bec_potential": False
        }
        
        # Check for financial keywords
        for keyword in self.financial_keywords:
            if keyword in subject_lower:
                analysis["keywords_found"].append(keyword)
        
        # Calculate confidence score
        confidence = len(analysis["keywords_found"]) * 20
        analysis["confidence_score"] = min(confidence, 100)
        
        # Check for BEC potential (financial keywords + urgency)
        urgency_words = self.social_engineering_patterns['urgency']
        has_urgency = any(word in subject_lower for word in urgency_words)
        
        if analysis["keywords_found"] and has_urgency:
            analysis["bec_potential"] = True
            confidence += 30
        
        # Determine risk level
        if confidence >= 60:
            analysis["risk_level"] = "HIGH"
        elif confidence >= 30:
            analysis["risk_level"] = "MEDIUM"
        
        return analysis
    
    def _analyze_language_patterns(self, subject: str) -> Dict[str, Any]:
        """Analyze language patterns and quality"""
        analysis = {
            "grammar_issues": [],
            "spelling_issues": [],
            "language_quality": "GOOD",
            "non_english_chars": 0,
            "repeated_chars": [],
            "word_repetition": {}
        }
        
        if not subject:
            return analysis
        
        # Check for repeated characters
        for match in re.finditer(r'(.)\1{2,}', subject):
            char = match.group(1)
            count = len(match.group(0))
            analysis["repeated_chars"].append(f"'{char}' repeated {count} times")
        
        # Check for non-English characters
        analysis["non_english_chars"] = sum(1 for char in subject if ord(char) > 127)
        
        # Check for word repetition
        words = subject.lower().split()
        word_counts = {}
        for word in words:
            if len(word) > 3:  # Only check words longer than 3 characters
                word_counts[word] = word_counts.get(word, 0) + 1
        
        repeated_words = {word: count for word, count in word_counts.items() if count > 1}
        analysis["word_repetition"] = repeated_words
        
        # Basic grammar/quality assessment
        if analysis["repeated_chars"]:
            analysis["grammar_issues"].append("Excessive character repetition")
        
        if repeated_words:
            analysis["grammar_issues"].append("Word repetition detected")
        
        if analysis["non_english_chars"] > len(subject) * 0.3:
            analysis["grammar_issues"].append("High percentage of non-English characters")
        
        # Assess overall language quality
        if len(analysis["grammar_issues"]) >= 3:
            analysis["language_quality"] = "POOR"
        elif len(analysis["grammar_issues"]) >= 1:
            analysis["language_quality"] = "FAIR"
        
        return analysis
    
    def _analyze_encoding(self, subject: str) -> Dict[str, Any]:
        """Analyze text encoding and character usage"""
        analysis = {
            "encoding_type": "ASCII",
            "unicode_chars": 0,
            "suspicious_chars": [],
            "homograph_risk": False
        }
        
        if not subject:
            return analysis
        
        # Count Unicode characters
        unicode_count = 0
        suspicious_chars = []
        
        for char in subject:
            char_code = ord(char)
            if char_code > 127:
                unicode_count += 1
                
                # Check for suspicious Unicode characters (homographs)
                if char_code in range(0x0400, 0x04FF):  # Cyrillic
                    suspicious_chars.append(f"Cyrillic: {char}")
                elif char_code in range(0x0370, 0x03FF):  # Greek
                    suspicious_chars.append(f"Greek: {char}")
                elif char_code in range(0x1D400, 0x1D7FF):  # Mathematical symbols
                    suspicious_chars.append(f"Math symbol: {char}")
        
        analysis["unicode_chars"] = unicode_count
        analysis["suspicious_chars"] = suspicious_chars
        
        # Determine encoding type
        if unicode_count > 0:
            analysis["encoding_type"] = "Unicode"
        
        # Assess homograph risk
        if suspicious_chars:
            analysis["homograph_risk"] = True
        
        return analysis
    
    def _analyze_characters(self, text: str) -> Dict[str, Any]:
        """Analyze character distribution in text"""
        analysis = {
            "uppercase_count": 0,
            "lowercase_count": 0,
            "digit_count": 0,
            "special_count": 0,
            "space_count": 0,
            "uppercase_ratio": 0.0
        }
        
        for char in text:
            if char.isupper():
                analysis["uppercase_count"] += 1
            elif char.islower():
                analysis["lowercase_count"] += 1
            elif char.isdigit():
                analysis["digit_count"] += 1
            elif char.isspace():
                analysis["space_count"] += 1
            else:
                analysis["special_count"] += 1
        
        # Calculate uppercase ratio
        total_letters = analysis["uppercase_count"] + analysis["lowercase_count"]
        if total_letters > 0:
            analysis["uppercase_ratio"] = analysis["uppercase_count"] / total_letters
        
        return analysis
    
    def _analyze_capitalization(self, text: str) -> Dict[str, Any]:
        """Analyze capitalization patterns"""
        analysis = {
            "is_all_caps": text.isupper() and len(text) > 3,
            "is_all_lowercase": text.islower() and len(text) > 3,
            "excessive_caps": False,
            "caps_percentage": 0.0
        }
        
        if text:
            caps_count = sum(1 for char in text if char.isupper())
            analysis["caps_percentage"] = (caps_count / len(text)) * 100
            analysis["excessive_caps"] = analysis["caps_percentage"] > 50
        
        return analysis
    
    def _analyze_punctuation(self, text: str) -> Dict[str, Any]:
        """Analyze punctuation usage"""
        analysis = {
            "exclamation_count": text.count('!'),
            "question_count": text.count('?'),
            "excessive_punctuation": False,
            "multiple_exclamations": '!!' in text,
            "multiple_questions": '??' in text
        }
        
        # Check for excessive punctuation
        total_punct = analysis["exclamation_count"] + analysis["question_count"]
        if total_punct > 3 or analysis["multiple_exclamations"] or analysis["multiple_questions"]:
            analysis["excessive_punctuation"] = True
        
        return analysis
    
    def _find_suspicious_patterns(self, text: str) -> List[str]:
        """Find suspicious patterns in text"""
        patterns_found = []
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, text):
                patterns_found.append(pattern)
        
        return patterns_found
    
    def _calculate_content_risk(self, analysis: Dict[str, Any]) -> int:
        """Calculate overall content risk score"""
        risk_score = 0
        
        # Social engineering risk
        se_score = analysis["social_engineering"]["overall_score"]
        risk_score += se_score * 0.4
        
        # Phishing indicators risk
        phishing_score = analysis["phishing_indicators"]["confidence_score"]
        risk_score += phishing_score * 0.3
        
        # Malware indicators risk
        malware_score = analysis["malware_indicators"]["confidence_score"]
        risk_score += malware_score * 0.3
        
        # Financial indicators risk
        financial_score = analysis["financial_indicators"]["confidence_score"]
        risk_score += financial_score * 0.25
        
        # Subject analysis penalties
        subject_issues = len(analysis["subject_analysis"]["issues"])
        risk_score += subject_issues * 10
        
        # Language quality penalties
        lang_analysis = analysis["language_analysis"]
        if lang_analysis["language_quality"] == "POOR":
            risk_score += 20
        elif lang_analysis["language_quality"] == "FAIR":
            risk_score += 10
        
        # Encoding risks
        if analysis["encoding_analysis"]["homograph_risk"]:
            risk_score += 25
        
        return min(int(risk_score), 100)
    
    def _collect_content_issues(self, analysis: Dict[str, Any]) -> List[str]:
        """Collect all content-related issues"""
        issues = []
        
        # Subject issues
        subject_issues = analysis["subject_analysis"]["issues"]
        issues.extend([f"Subject: {issue}" for issue in subject_issues])
        
        # Social engineering issues
        se_analysis = analysis["social_engineering"]
        if se_analysis["categories_detected"]:
            issues.append(f"Social engineering tactics: {', '.join(se_analysis['categories_detected'])}")
        
        # Phishing issues
        phishing_analysis = analysis["phishing_indicators"]
        if phishing_analysis["risk_level"] in ["HIGH", "MEDIUM"]:
            issues.append(f"Phishing indicators detected: {phishing_analysis['risk_level']} risk")
        
        # Malware issues
        malware_analysis = analysis["malware_indicators"]
        if malware_analysis["risk_level"] in ["HIGH", "MEDIUM"]:
            issues.append(f"Malware indicators detected: {malware_analysis['risk_level']} risk")
        
        # Financial issues
        financial_analysis = analysis["financial_indicators"]
        if financial_analysis["bec_potential"]:
            issues.append("Potential Business Email Compromise (BEC) detected")
        
        # Language issues
        lang_analysis = analysis["language_analysis"]
        if lang_analysis["language_quality"] == "POOR":
            issues.append("Poor language quality detected")
        
        # Encoding issues
        if analysis["encoding_analysis"]["homograph_risk"]:
            issues.append("Homograph attack risk detected")
        
        return issues
    
    def _generate_content_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate content-related recommendations"""
        recommendations = []
        
        risk_score = analysis["risk_score"]
        
        if risk_score > 80:
            recommendations.append("Block email immediately - high content risk")
        elif risk_score > 60:
            recommendations.append("Quarantine for manual review")
        elif risk_score > 40:
            recommendations.append("Flag as suspicious content")
        
        # Specific recommendations based on analysis
        if analysis["social_engineering"]["overall_score"] > 60:
            recommendations.append("Train users on social engineering awareness")
        
        if analysis["phishing_indicators"]["risk_level"] == "HIGH":
            recommendations.append("Implement additional phishing protection")
        
        if analysis["financial_indicators"]["bec_potential"]:
            recommendations.append("Verify financial requests through alternative channels")
        
        if analysis["encoding_analysis"]["homograph_risk"]:
            recommendations.append("Implement homograph attack detection")
        
        return recommendations
