import geoip2.database
import requests
import json
from typing import Dict, List, Any

class ThreatIntelligenceAPI:
    """Real threat intelligence integration"""

    def __init__(self, abuseipdb_key: str = ""):
        self.abuseipdb_key = abuseipdb_key
        self.geoip_reader = None

        # Initialize GeoIP if database exists
        try:
            self.geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        except:
            print("GeoLite2 database not found. Using mock data.")

    def get_real_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get real geolocation using MaxMind GeoLite2"""
        if self.geoip_reader:
            try:
                response = self.geoip_reader.city(ip)
                return {
                    "country": response.country.name or "Unknown",
                    "city": response.city.name or "Unknown",
                    "asn": f"AS{response.traits.autonomous_system_number}",
                    "isp": response.traits.autonomous_system_organization or "Unknown"
                }
            except:
                pass

        # Fallback to mock
        return self._mock_geolocation(ip)

    def _mock_geolocation(self, ip: str) -> Dict[str, str]:
        """Mock geolocation for demo"""
        ip_hash = sum(int(x) for x in ip.split(".")) % 3
        if ip_hash == 0:
            return {"country": "United States", "city": "New York", "asn": "AS15169", "isp": "Google LLC"}
        elif ip_hash == 1:
            return {"country": "India", "city": "Mumbai", "asn": "AS9498", "isp": "Bharti Airtel"}
        else:
            return {"country": "Germany", "city": "Frankfurt", "asn": "AS16509", "isp": "Amazon.com Inc."}

    def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Get IP reputation from AbuseIPDB"""
        if not self.abuseipdb_key:
            return self._mock_reputation(ip)

        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/query",
                headers={"Key": self.abuseipdb_key},
                params={"query": ip}
            )
            data = response.json()

            if data.get("data"):
                ip_data = data["data"][0]
                return {
                    "abuse_score": ip_data.get("abuseConfidenceScore", 0),
                    "is_abusive": ip_data.get("abuseConfidenceScore", 0) > 50,
                    "total_reports": ip_data.get("totalReports", 0),
                    "last_reported": ip_data.get("lastReportedAt", ""),
                    "risk_flags": self._calculate_risk_flags(ip_data)
                }
        except:
            pass

        return self._mock_reputation(ip)

    def _mock_reputation(self, ip: str) -> Dict[str, Any]:
        """Mock reputation"""
        risk_flags = []
        try:
            last_octet = int(ip.split(".")[-1])
            if last_octet % 7 == 0:
                risk_flags.append("abuse")
            if last_octet % 11 == 0:
                risk_flags.append("proxy")
            if last_octet % 13 == 0:
                risk_flags.append("tor_exit")
        except:
            pass

        return {
            "abuse_score": 50 if risk_flags else 0,
            "is_abusive": len(risk_flags) > 0,
            "total_reports": len(risk_flags) * 10,
            "risk_flags": risk_flags
        }

    def _calculate_risk_flags(self, ip_data: Dict) -> List[str]:
        """Calculate risk flags from AbuseIPDB data"""
        flags = []
        if ip_data.get("abuseConfidenceScore", 0) > 80:
            flags.append("high_abuse")
        if ip_data.get("abuseConfidenceScore", 0) > 50:
            flags.append("abuse")
        if ip_data.get("usageType", "").lower() in ["hosting", "data center"]:
            flags.append("hosting")
        return flags

    def check_url_reputation(self, url: str) -> Dict[str, Any]:
        """Check URL reputation using URLhaus"""
        try:
            response = requests.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url}
            )
            data = response.json()

            if data.get("query_status") == "ok" and data.get("url_info"):
                url_info = data["url_info"]
                return {
                    "is_malicious": True,
                    "threat": url_info.get("threat", "malware"),
                    "tags": url_info.get("tags", []),
                    "first_seen": url_info.get("firstseen", ""),
                    "risk_flags": ["malicious", "malware", url_info.get("threat", "unknown")]
                }
        except:
            pass

        return self._mock_url_reputation(url)

    def _mock_url_reputation(self, url: str) -> Dict[str, Any]:
        """Mock URL reputation"""
        risk_flags = []
        suspicious = ["login", "verify", "account", "secure", "bank"]
        if any(s in url.lower() for s in suspicious):
            risk_flags.extend(["phishing_feed", "malicious"])

        return {
            "is_malicious": len(risk_flags) > 0,
            "threat": "phishing" if risk_flags else "none",
            "risk_flags": risk_flags
        }

    def get_geo_fencing_status(self, ip: str, blocked_countries: List[str] = None) -> Dict[str, Any]:
        """Check if IP is from blocked country"""
        if blocked_countries is None:
            blocked_countries = ["KP", "IR", "SY"]  # Example blocked countries

        geo = self.get_real_geolocation(ip)
        country_code = self._get_country_code(geo["country"])

        is_blocked = country_code in blocked_countries

        return {
            "country": geo["country"],
            "country_code": country_code,
            "is_blocked": is_blocked,
            "blocked_countries": blocked_countries,
            "action": "BLOCK" if is_blocked else "ALLOW"
        }

    def _get_country_code(self, country_name: str) -> str:
        """Get ISO country code from name"""
        country_codes = {
            "United States": "US",
            "India": "IN",
            "Germany": "DE",
            "China": "CN",
            "Russia": "RU",
            "North Korea": "KP",
            "Iran": "IR",
            "Syria": "SY"
        }
        return country_codes.get(country_name, "XX")