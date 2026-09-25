import re
from typing import Dict, List, Tuple

class NLPThreatClassifier:
    """AI/NLP-based threat classification"""

    def __init__(self):
        # Urgency and fear keywords
        self.urgency_patterns = [
            r"\b(urgent|immediately|asap|right now|instant)\b",
            r"\b(verify now|act now|click here|confirm immediately)\b",
            r"\b(suspended|terminated|closed|blocked|locked)\b",
            r"\b(24 hours|one day|limited time|expire)\b"
        ]

        # Authority impersonation
        self.authority_patterns = [
            r"\b(CEO|CFO|President|Director|Manager|HR|IT Department)\b",
            r"\b(Bank|Police|Government|IRS|Tax Department)\b",
            r"\b(Security Team|Fraud Department|Compliance)\b"
        ]

        # Financial request patterns
        self.financial_patterns = [
            r"\b(wire transfer|bank account|payment|invoice)\b",
            r"\b(routing number|account number|SWIFT|IBAN)\b",
            r"\b(gift card|bitcoin|cryptocurrency|payment method)\b",
            r"\b(update payment|change bank|new account)\b"
        ]

        # Credential harvesting
        self.credential_patterns = [
            r"\b(password|username|login|credentials|OTP)\b",
            r"\b(reset password|verify account|confirm identity)\b",
            r"\b(click link|sign in|log in|authenticate)\b"
        ]

        # Social engineering
        self.social_engineering_patterns = [
            r"\b(confidential|private|do not share)\b",
            r"\b(help me|need assistance|quick question)\b",
            r"\b(congratulations|you won|selected|lottery)\b"
        ]

    def analyze_email_text(self, subject: str, body: str) -> Dict[str, Any]:
        """Analyze email text for threat indicators"""
        text = f"{subject} {body}".lower()

        results = {
            "urgency_score": self._count_patterns(text, self.urgency_patterns),
            "authority_score": self._count_patterns(text, self.authority_patterns),
            "financial_score": self._count_patterns(text, self.financial_patterns),
            "credential_score": self._count_patterns(text, self.credential_patterns),
            "social_engineering_score": self._count_patterns(text, self.social_engineering_patterns),
            "detected_patterns": []
        }

        # Calculate overall NLP threat score (0-100)
        total_score = (
            results["urgency_score"] * 20 +
            results["authority_score"] * 15 +
            results["financial_score"] * 25 +
            results["credential_score"] * 25 +
            results["social_engineering_score"] * 15
        )

        results["nlp_threat_score"] = min(total_score, 100)
        results["threat_level"] = self._get_threat_level(results["nlp_threat_score"])
        results["primary_threat_type"] = self._get_primary_threat_type(results)

        return results

    def _count_patterns(self, text: str, patterns: List[str]) -> int:
        """Count how many patterns match"""
        count = 0
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                count += 1
        return count

    def _get_threat_level(self, score: int) -> str:
        """Get threat level from score"""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        else:
            return "safe"

    def _get_primary_threat_type(self, results: Dict) -> str:
        """Determine primary threat type"""
        scores = {
            "urgency": results["urgency_score"],
            "authority_impersonation": results["authority_score"],
            "financial_fraud": results["financial_score"],
            "credential_harvesting": results["credential_score"],
            "social_engineering": results["social_engineering_score"]
        }

        primary = max(scores, key=scores.get)
        return primary if scores[primary] > 0 else "none"

    def detect_bec_indicators(self, subject: str, body: str, headers: Dict) -> Dict[str, Any]:
        """Detect Business Email Compromise indicators"""
        indicators = {
            "is_ceo_fraud": False,
            "is_invoice_fraud": False,
            "is_payment_diversion": False,
            "confidence": 0,
            "reasons": []
        }

        text = f"{subject} {body}".lower()

        # CEO fraud detection
        if re.search(r"\b(ceo|cfo|president|boss|executive)\b", text):
            if re.search(r"\b(urgent|confidential|quick|help)\b", text):
                indicators["is_ceo_fraud"] = True
                indicators["reasons"].append("CEO impersonation with urgency")
                indicators["confidence"] += 40

        # Invoice fraud
        if re.search(r"\b(invoice|payment|bill|receipt)\b", text):
            if re.search(r"\b(urgent|overdue|immediate)\b", text):
                indicators["is_invoice_fraud"] = True
                indicators["reasons"].append("Urgent invoice/payment request")
                indicators["confidence"] += 30

        # Payment diversion
        if re.search(r"\b(change bank|new account|update payment|different account)\b", text):
            indicators["is_payment_diversion"] = True
            indicators["reasons"].append("Payment account change request")
            indicators["confidence"] += 50

        # Check for external sender claiming to be internal
        from_domain = headers.get("from", "").split("@")[-1] if "@" in headers.get("from", "") else ""
        reply_domain = headers.get("reply_to", "").split("@")[-1] if "@" in headers.get("reply_to", "") else ""

        if from_domain and reply_domain and from_domain != reply_domain:
            indicators["confidence"] += 20
            indicators["reasons"].append("From/Reply-To domain mismatch")

        indicators["confidence"] = min(indicators["confidence"], 100)
        indicators["is_bec"] = indicators["confidence"] >= 50

        return indicators

    def generate_nlp_findings(self, nlp_results: Dict, bec_results: Dict) -> List[str]:
        """Generate human-readable findings from NLP analysis"""
        findings = []

        # Add NLP-based findings
        if nlp_results["urgency_score"] >= 2:
            findings.append(f"High urgency language detected ({nlp_results['urgency_score']} indicators)")

        if nlp_results["financial_score"] >= 2:
            findings.append(f"Financial request patterns detected ({nlp_results['financial_score']} indicators)")

        if nlp_results["credential_score"] >= 2:
            findings.append(f"Credential harvesting attempt ({nlp_results['credential_score']} indicators)")

        if nlp_results["authority_score"] >= 1:
            findings.append(f"Authority impersonation ({nlp_results['authority_score']} indicators)")

        # Add BEC findings
        if bec_results["is_bec"]:
            findings.append(f"BEC detected: {', '.join(bec_results['reasons'][:2])}")

        if bec_results["is_ceo_fraud"]:
            findings.append("CEO/CFO fraud pattern detected")

        if bec_results["is_payment_diversion"]:
            findings.append("Payment diversion attempt detected")

        return findings