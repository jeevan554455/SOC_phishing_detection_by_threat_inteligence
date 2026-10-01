"""Local IOC extraction + explainable phishing triage.
No URLs are executed and no attachments are uploaded.
"""
import base64
import ipaddress
import re
from urllib.parse import urlparse
import requests

URL_RE = re.compile(r'https?://[^\s<>"\')\]]+', re.I)
EMAIL_RE = re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', re.I)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')
MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
ATTACH_RE = re.compile(r'(?i)\b[\w.-]+\.(?:zip|rar|7z|exe|scr|js|vbs|ps1|docm|xlsm|lnk)\b')

SIGNALS = [
    (r'\burgent\b|\bimmediately\b|\bwithin 24 hours\b', 15, "Urgency language"),
    (r'\bverify\b|\bverification\b|\bconfirm your account\b|\bpassword reset\b', 15, "Credential/verification request"),
    (r'\bsuspended\b|\brestricted\b|\blocked\b', 15, "Account restriction threat"),
    (r'\binvoice\b|\bpayment\b|\bdocument\b|\battachment\b', 10, "Attachment/payment lure"),
]

def unique(items):
    return sorted(set(items), key=str.lower)

def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def url_score(url):
    score, signals = 0, []
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        if p.scheme != "https":
            score += 10; signals.append("URL is not HTTPS")
        if "@" in url:
            score += 15; signals.append("URL contains @ userinfo")
        if host.startswith("xn--") or ".xn--" in host:
            score += 15; signals.append("Possible punycode domain")
        if len(host) > 45:
            score += 5; signals.append("Unusually long hostname")
        if host.count(".") >= 3:
            score += 5; signals.append("Deeply nested subdomain")
    except ValueError:
        pass
    return score, signals

def analyze_text(text):
    urls = unique(URL_RE.findall(text))
    emails = unique(EMAIL_RE.findall(text))
    ips = unique(x for x in IP_RE.findall(text) if valid_ip(x))
    sha256 = unique(SHA256_RE.findall(text))
    sha1 = unique(SHA1_RE.findall(text))
    md5 = unique(MD5_RE.findall(text))
    attachments = unique(ATTACH_RE.findall(text))

    score, signals = 0, []
    for pattern, points, label in SIGNALS:
        if re.search(pattern, text, re.I):
            score += points
            signals.append(label)

    for url in urls:
        points, found = url_score(url)
        score += points
        signals.extend(found)

    if attachments:
        score += min(20, 8 * len(attachments))
        signals.append("Potentially risky attachment extension detected")

    if re.search(r'paypa1|micr0soft|g00gle|secure-login|account-verify', " ".join(urls), re.I):
        score += 20
        signals.append("Possible brand impersonation or deceptive URL")

    score = min(score, 100)
    if score >= 70:
        verdict, severity = "HIGH RISK", "High"
    elif score >= 40:
        verdict, severity = "SUSPICIOUS", "Medium"
    else:
        verdict, severity = "LOW SIGNAL", "Low"

    return {
        "verdict": verdict,
        "severity": severity,
        "risk_score": score,
        "signals": unique(signals),
        "iocs": {
            "urls": urls, "ips": ips, "emails": emails,
            "sha256": sha256, "sha1": sha1, "md5": md5,
            "attachments": attachments
        }
    }

def vt_get(path, api_key):
    response = requests.get(
        "https://www.virustotal.com/api/v3/" + path,
        headers={"x-apikey": api_key},
        timeout=10
    )
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()

def enrich_with_virustotal(iocs, api_key):
    """Reputation lookups only. Does not upload files."""
    result = {"status": "ok", "urls": [], "ips": [], "hashes": []}

    for url in iocs["urls"][:5]:
        key = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        data = vt_get(f"urls/{key}", api_key)
        if data:
            a = data["data"]["attributes"]
            stats = a.get("last_analysis_stats", {})
            result["urls"].append({
                "indicator": url,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0)
            })

    for ip in iocs["ips"][:5]:
        data = vt_get(f"ip_addresses/{ip}", api_key)
        if data:
            a = data["data"]["attributes"]
            stats = a.get("last_analysis_stats", {})
            result["ips"].append({
                "indicator": ip,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0)
            })

    for h in (iocs["sha256"] + iocs["sha1"] + iocs["md5"])[:10]:
        data = vt_get(f"files/{h}", api_key)
        if data:
            a = data["data"]["attributes"]
            stats = a.get("last_analysis_stats", {})
            result["hashes"].append({
                "indicator": h,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0)
            })
    return result
