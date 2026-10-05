import re
import requests

from flask import redirect, render_template, session
from functools import wraps
from urllib.parse import urlparse


def apology(message, code=400):
    """Render message as an apology to user."""

    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function

'''Used AI partially for logic'''
# Common URL shortening services, often abused to hide the real destination
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly",
}

# TLDs frequently associated with disposable / low-cost phishing domains
SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click", ".work"}

# Keywords commonly stuffed into phishing links to look "official"
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "bank", "password", "webscr", "ebayisapi", "suspend",
}

# A short list of high-value brands frequently spoofed via lookalike domains
COMMON_BRANDS = {
    "paypal", "google", "apple", "microsoft", "amazon", "facebook",
    "netflix", "instagram", "bankofamerica", "chase", "wellsfargo",
}

IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def detect_phishing(url):
    reasons = []

    parse_target = url if "://" in url else "http://" + url
    parsed = urlparse(parse_target)
    hostname = (parsed.hostname or "").lower()
    full_url = url.lower()

    # 1. IP address used instead of a domain name
    if IPV4_RE.match(hostname):
        reasons.append("uses a raw IP address instead of a domain name")

    # 2. '@' symbol in the URL (browsers ignore everything before it)
    if "@" in url:
        reasons.append("contains an '@' symbol, which can hide the real destination")

    # 3. Hyphens in the hostname (e.g. paypal-secure-login.com)
    if hostname.count("-") >= 1:
        reasons.append("hostname contains a hyphen, often used to mimic real brands")

    # 4. Excessive URL length
    if len(url) > 75:
        reasons.append("URL is unusually long")

    # 5. Excessive number of subdomains
    if hostname.count(".") > 3:
        reasons.append("hostname has an unusually high number of subdomains")

    # 6. Known URL shortener
    if hostname in SHORTENERS:
        reasons.append("uses a URL shortening service, which can mask the real link")

    # 7. Not using HTTPS
    if parsed.scheme != "https":
        reasons.append("does not use HTTPS")

    # 8. Suspicious keywords anywhere in the URL
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in full_url:
            reasons.append(f"contains the suspicious keyword '{keyword}'")
            break

    # 9. Suspicious top-level domain
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            reasons.append(f"uses the suspicious top-level domain '{tld}'")
            break

    # 10. Brand name present but not as the actual registered domain (simple typosquat check)
    domain_parts = hostname.split(".")
    registrable = domain_parts[-2] if len(domain_parts) >= 2 else hostname
    for brand in COMMON_BRANDS:
        if brand in hostname and brand != registrable:
            reasons.append(f"mentions '{brand}' but is not the official '{brand}' domain")
            break

    score = len(reasons)
    result = "phishy" if score >= 2 else "safe"

    return result, score, reasons
