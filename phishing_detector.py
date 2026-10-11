import re
from urllib.parse import urlparse
import tldextract

COMMON_PHISHING_KEYWORDS = [
    "login", "verify", "secure", "update", "password", "confirm",
    "bank", "invoice", "alert", "urgent", "click", "account",
    "suspicious", "signin", "validate"
]

COMMON_SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "xyz", "top"]

def normalize_url(url: str) -> str:
    if not url:
        return ""
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url
    return url

def get_url_features(url: str):
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    domain_info = tldextract.extract(parsed.netloc)

    return {
        "original": url,
        "normalized": normalized,
        "scheme": parsed.scheme,
        "hostname": parsed.netloc,
        "domain": domain_info.domain,
        "subdomain": domain_info.subdomain,
        "suffix": domain_info.suffix,
        "path": parsed.path,
        "query": parsed.query,
        "port": parsed.port,
    }

def score_url(url: str) -> tuple[int, str]:
    if not url or not url.strip():
        return 0, "safe"

    features = get_url_features(url)
    score = 0
    hostname = features["hostname"].lower()
    domain = features["domain"].lower()
    path = features["path"].lower()

    # 1) Suspicious protocol / missing HTTPS
    if features["scheme"] != "https":
        score += 15

    # 2) Very short or typo-squatted domain
    if len(domain) < 4:
        score += 10

    # 3) IP address
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        score += 30

    # 4) High-risk keywords in URL
    if any(k in path for k in ["login", "verify", "update", "secure", "password"]):
        score += 20

    # 5) Suspicious TLD
    if features["suffix"] in COMMON_SUSPICIOUS_TLDS:
        score += 20

    # 6) Multiple subdomains
    if len(features["subdomain"].split(".")) > 2:
        score += 15

    # 7) Mixed characters / brand impersonation behavior
    if re.search(r"[-_]{2,}", hostname):
        score += 10

    # 8) Keywords in domain name
    if any(k in hostname for k in ["login", "verify", "secure", "account", "update"]):
        score += 20

    # 9) Random-looking hostnames
    if re.search(r"[0-9]{3,}", hostname) and len(hostname) > 12:
        score += 10

    # 10) Very long URL
    if len(normalize_url(url)) > 100:
        score += 10

    # Label logic
    if score >= 70:
        label = "phishing"
    elif score >= 35:
        label = "suspicious"
    else:
        label = "safe"

    return score, label

def score_email_text(text: str) -> tuple[int, str]:
    if not text:
        return 0, "safe"

    lower_text = text.lower()
    score = 0

    # Suspicious words in email content
    for keyword in COMMON_PHISHING_KEYWORDS:
        if keyword in lower_text:
            score += 8

    # Urgency / pressure phrases
    urgency_patterns = ["urgent", "immediately", "act now", "within 24 hours", "verify now"]
    for pattern in urgency_patterns:
        if pattern in lower_text:
            score += 12

    # Link-like patterns
    urls = re.findall(r"https?://[^\s]+", text)
    if urls:
        score += 10
        for url in urls:
            url_score, _ = score_url(url)
            score += min(url_score // 4, 25)

    # Generic scam signals
    if "click here" in lower_text:
        score += 15

    if "password reset" in lower_text:
        score += 15

    if "invoice" in lower_text:
        score += 10

    if score >= 70:
        label = "phishing"
    elif score >= 35:
        label = "suspicious"
    else:
        label = "safe"

    return score, label