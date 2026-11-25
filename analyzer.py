import re
import socket
import ipaddress
from dataclasses import dataclass
from math import log2
from urllib.parse import urlparse, parse_qs, unquote, urljoin

import requests


# =========================================================
# Phishing / Tracking indicators
# =========================================================

SUSPICIOUS_WORDS = {
    "login": 5, "signin": 5, "sign-in": 5,
    "verify": 7, "verification": 7,
    "account": 4, "secure": 4, "security": 4,
    "update": 5, "confirm": 5, "confirmation": 5,
    "password": 8, "credential": 8, "credentials": 8,
    "wallet": 7, "crypto": 5, "bank": 7,
    "paypal": 7, "instagram": 6, "facebook": 6,
    "google": 6, "microsoft": 6, "apple": 6,
    "telegram": 6, "discord": 6,
    "free": 3, "gift": 4, "bonus": 4,
    "claim": 4, "prize": 5, "urgent": 5,
    "suspended": 7, "unlock": 6,
    "recover": 5, "reset": 5, "authenticate": 6,
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
    "cutt.ly", "rb.gy", "shorturl.at", "ow.ly", "buff.ly",
    "rebrand.ly", "tiny.cc", "lnkd.in", "t.ly", "s.id",
    "short.io", "soo.gd", "v.gd", "tiny.one",
}

# Tracking / IP logger services and common indicators.
TRACKING_DOMAINS = {
    "grabify.link",
    "grabify.icu",
    "iplogger.org",
    "iplogger.com",
    "iplogger.co",
    "2no.co",
    "yip.su",
    "blasze.com",
    "ip-tracker.org",
    "ps3cfw.com",
    "bmwforum.co",
    "freegiftcards.co",
    "ed.tc",
    "spottyfly.com",
}

# Strong, tool-specific indicators (scored as critical).
TRACKING_PATTERNS = {
    "grabify", "iplogger", "2no.co",
    "yip.su", "blasze", "ip-tracker", "iptrack",
    "clicktracker",
}

# Generic words that appear on countless legitimate URLs (order-tracking,
# visitor-info, logger docs...). Weak signal only: never "critical".
GENERIC_TRACKING_PATTERNS = {
    "tracking", "visitor", "track.php", "logger",
}

PHISHING_TOOL_PATTERNS = {
    "zphisher", "shellphish", "blackeye", "socialfish",
    "camphish", "hiddeneye",
}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".msi",
    ".apk", ".jar", ".ps1", ".vbs", ".hta",
}

# One single source of truth for brands and their legitimate domains
# (previously there were three inconsistent copies of this data).
BRANDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "google.co.in", "gmail.com", "youtube.com", "gstatic.com"},
    "facebook": {"facebook.com", "fb.com", "messenger.com"},
    "instagram": {"instagram.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com",
                  "microsoftonline.com", "office365.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "netflix": {"netflix.com"},
    "telegram": {"telegram.org", "t.me"},
    "discord": {"discord.com", "discord.gg"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "linkedin": {"linkedin.com"},
    "github": {"github.com", "github.io", "githubusercontent.com"},
}

# Provider infrastructure domains that contain a brand name only because the
# provider owns them (bucket.s3.amazonaws.com). Only the part of the hostname
# BEFORE these suffixes is checked for brand impersonation.
BRAND_INFRA_DOMAINS = {
    "amazonaws.com", "googleapis.com", "googleusercontent.com",
    "azurewebsites.net", "windows.net", "fbcdn.net",
}

# Short/common brand words that must match as whole words
# ("pineapple.com" is not "apple").
BOUNDARY_BRANDS = {"apple", "steam"}

# Suspicious words that are ordinary English words and must match as whole words.
AMBIGUOUS_WORDS = {
    "free", "gift", "bank", "apple", "claim", "prize",
    "reset", "bonus", "unlock", "recover", "crypto",
}

# Temporary tunnel / free hosting services. Legitimate for developers, but they
# are also where most phishing kits (Zphisher, etc.) are served from.
TUNNEL_DOMAINS = {
    "trycloudflare.com", "ngrok.io", "ngrok.app", "ngrok-free.app",
    "ngrok-free.dev", "ngrok.dev", "loclx.io", "lhr.life", "localhost.run",
    "serveo.net", "loca.lt", "pinggy.link", "pinggy.io", "tunnelmole.net",
    "devtunnels.ms", "telebit.io", "playit.gg",
}

MAX_URL_LENGTH = 4096
MAX_BODY_BYTES = 1_000_000
MAX_REDIRECTS = 10
REQUEST_TIMEOUT = 7

REDIRECT_PARAMETERS = {
    "redirect", "redirect_uri", "redirect_url", "url",
    "next", "return", "returnurl", "return_url",
    "continue", "target", "dest", "destination",
    "forward", "go", "link", "redirect_to", "return_to",
    "redir", "goto",
}

USER_AGENT = (
    "PhishingURLDetector/2.0 "
    "(defensive security research; URL analysis)"
)


# =========================================================
# Basic helpers
# =========================================================

def normalize_url(url):
    """Normalize user input into a parseable HTTP(S) URL."""
    if not url:
        return None

    url = url.strip()

    # Reject oversized input and any whitespace/control characters inside the URL.
    if len(url) > MAX_URL_LENGTH or re.search(r"[\x00-\x20\x7f]", url):
        return None

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in {"http", "https"}:
            return None

        if not parsed.netloc or not parsed.hostname:
            return None

        parsed.port  # raises ValueError on an invalid port

        return url
    except Exception:
        return None


def calculate_entropy(text):
    if not text:
        return 0.0

    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1

    length = len(text)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * log2(probability)

    return round(entropy, 2)


def is_ip_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except (ValueError, TypeError):
        return False


def resolve_host_ips(host):
    """Resolve a host to all of its IPv4/IPv6 addresses ([] on failure)."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        return []

    ips = []
    for info in infos:
        ip = info[4][0].split("%")[0]
        if ip not in ips:
            ips.append(ip)
    return ips


def resolve_domain(host):
    ips = resolve_host_ips(host)
    return ips[0] if ips else None


def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def looks_like_obfuscated_ip(host):
    """Detect decimal/hex/octal IPs such as 2130706433 or 0x7f.1."""
    if not host or is_ip_address(host):
        return False
    if not re.fullmatch(r"[0-9a-fx.]+", host):
        return False
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


class UnsafeTarget(Exception):
    """Raised when a URL (or a redirect hop) points to a non-public address."""


@dataclass
class FetchResult:
    url: str
    status_code: int
    headers: object
    redirects: list
    text: str


def ensure_public_host(host):
    """SSRF guard: refuse loopback, private, link-local and reserved targets."""
    ips = [host] if is_ip_address(host) else resolve_host_ips(host)

    if not ips:
        raise requests.ConnectionError(f"Could not resolve {host}")

    for ip in ips:
        if not is_public_ip(ip):
            raise UnsafeTarget(f"{host} resolves to a non-public address ({ip})")


def fetch_page(url, timeout=REQUEST_TIMEOUT):
    """
    Fetch a page safely.

    - every hop (including redirects) is checked against the SSRF guard
    - redirects are followed manually
    - the body is capped at MAX_BODY_BYTES
    """
    redirects = []
    current = url

    for _ in range(MAX_REDIRECTS + 1):
        parsed = urlparse(current)

        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise requests.exceptions.InvalidURL(f"Unsupported URL: {current[:100]}")

        ensure_public_host(parsed.hostname.lower())

        response = requests.get(
            current,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": USER_AGENT},
        )

        try:
            location = response.headers.get("Location")

            if response.status_code in {301, 302, 303, 307, 308} and location:
                redirects.append(current)
                current = urljoin(current, location)
                continue

            body = b""
            for chunk in response.iter_content(chunk_size=16384):
                body += chunk
                if len(body) >= MAX_BODY_BYTES:
                    break

            charset = re.search(
                r"charset=([\w-]+)",
                response.headers.get("Content-Type", ""),
                re.I,
            )
            try:
                text = body.decode(charset.group(1) if charset else "utf-8", errors="replace")
            except LookupError:
                text = body.decode("utf-8", errors="replace")

            return FetchResult(
                url=current,
                status_code=response.status_code,
                headers=response.headers,
                redirects=redirects,
                text=text,
            )
        finally:
            response.close()

    raise requests.exceptions.TooManyRedirects("Too many redirects")


def base_domain(host):
    """
    Lightweight registrable-domain approximation.

    This intentionally avoids an extra dependency such as tldextract.
    It handles the common cases used by this detector.
    """
    if not host or is_ip_address(host):
        return host

    parts = host.lower().strip(".").split(".")

    if len(parts) < 2:
        return host.lower()

    common_two_part_suffixes = {
        "co.uk", "org.uk", "ac.uk",
        "co.in", "com.au", "co.jp",
        "co.nz", "com.br", "com.cn",
    }

    suffix = ".".join(parts[-2:])
    if suffix in common_two_part_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def domain_matches(host, domain):
    host = host.lower().rstrip(".")
    domain = domain.lower().lstrip(".")

    return host == domain or host.endswith("." + domain)


def official_brand_for_host(host):
    """Return the brand whose official domain matches host, if any."""
    host = (host or "").lower().rstrip(".")
    for brand, official_domains in BRANDS.items():
        if any(domain_matches(host, official) for official in official_domains):
            return brand
    return None


def find_terms(text, terms):
    """Whole-word search, so 'free' does not match 'carefree'."""
    return [
        term for term in terms
        if re.search(r"(?<![a-z])" + re.escape(term) + r"(?![a-z])", text)
    ]


def brand_hits_for_host(host):
    """Brands mentioned in a hostname that does not belong to that brand."""
    full = (host or "").lower().rstrip(".")
    search = full

    for infra in BRAND_INFRA_DOMAINS:
        if domain_matches(full, infra):
            search = full[: -len(infra)].rstrip(".")
            break

    hits = []
    for brand, official_domains in BRANDS.items():
        if brand in BOUNDARY_BRANDS:
            present = bool(re.search(rf"(?<![a-z]){brand}(?![a-z])", search))
        else:
            present = brand in search

        if present and not any(domain_matches(full, d) for d in official_domains):
            hits.append(brand)

    return hits


def add_finding(findings, score, reason, severity="medium", category=None):
    # Reasons can contain attacker-controlled text (page titles, redirect
    # targets). Strip control characters so they cannot inject terminal escapes.
    reason = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", str(reason))[:400]
    findings.append({
        "reason": reason,
        "severity": severity,
        "score": score,
        "category": category or "URL analysis",
    })


def contains_any(text, values):
    return [value for value in values if value in text]


# =========================================================
# Page/content analysis
# =========================================================

PASSWORD_INPUT_RE = re.compile(
    r"<input[^>]+(?:type\s*=\s*[\"']?password"
    r"|name\s*=\s*[\"']?(?:pass|passwd|password|pwd)[\"'\s>])",
    re.I,
)


def count_password_inputs(html):
    return len(PASSWORD_INPUT_RE.findall(html))


def analyze_page_content(response, findings):
    """Analyze returned HTML and same-site child pages for phishing indicators."""
    if not response:
        return 0

    try:
        content = response.text or ""
    except Exception:
        return 0

    if not content:
        return 0

    html = content.lower()
    sample = html[:1_000_000]
    score = 0

    page_host = (urlparse(response.url).hostname or "").lower()

    title_match = re.search(r"<title[^>]*>(.*?)</title>", sample, re.I | re.S)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""

    if title:
        title_words = find_terms(title, SUSPICIOUS_WORDS.keys())
        # A legitimate brand's own title (e.g. Instagram's title on instagram.com)
        # should not be treated as suspicious merely because it contains its brand name.
        official_brand = official_brand_for_host(page_host)
        if official_brand:
            title_words = [w for w in title_words if w != official_brand]
        if title_words:
            add_finding(
                findings, 4,
                "Suspicious security/login terminology appears in the page title: "
                + ", ".join(sorted(set(title_words))),
                "medium", "Page content",
            )
            score += 4

    # Strong fingerprints of known phishing kits/frameworks.
    framework_signatures = {
        "kasroudra": "Known KasRoudra/Zphisher-related signature found in page content.",
        "designed as phishing page": "Page explicitly identifies itself as a phishing page.",
        "zphisher": "Known Zphisher signature found in page content.",
        "shellphish": "Known ShellPhish signature found in page content.",
        "blackeye": "Known BlackEye phishing-tool signature found in page content.",
        "setoolkit": "Known Social-Engineer Toolkit signature found in page content.",
    }

    password_inputs = count_password_inputs(sample)
    form_count = len(re.findall(r"<form\b", sample, re.I))

    # A tool name on its own is also found on security blogs, READMEs and
    # training pages. It is only "critical" when the page really has a login form.
    for signature, message in framework_signatures.items():
        if signature in sample:
            if password_inputs:
                add_finding(findings, 40, message, "critical", "Phishing framework fingerprint")
                score += 40
            else:
                add_finding(
                    findings, 10,
                    message + " (no password field found; may be educational/security content)",
                    "medium", "Phishing framework fingerprint",
                )
                score += 10

    page_brands = list(BRANDS)

    # Do NOT treat every brand name appearing anywhere in a page as
    # impersonation. Large legitimate sites commonly contain references to
    # other brands in scripts, links, metadata, or embedded resources.
    # Stronger evidence is a brand appearing in the page title while the
    # actual host is NOT that brand's official domain.
    title_brands = find_terms(title, page_brands)

    # A brand in the page title is an impersonation signal only when the
    # current hostname is not an official domain for that brand.  Do not
    # treat unrelated brand names found elsewhere in a legitimate page as
    # evidence of impersonation.
    detected_brands = []
    for brand in title_brands:
        official_domains = BRANDS.get(brand, set())
        if not any(
            domain_matches(page_host, official_domain)
            for official_domain in official_domains
        ):
            detected_brands.append(brand)

    # Many phishing kits put the brand in headings/body text, not the <title>.
    # If the page has a password field on a host that is not the brand's own
    # domain and mentions a brand at least twice, treat it as impersonation.
    if password_inputs and not detected_brands:
        visible = re.sub(r"<(script|style)\b.*?</\1>", " ", sample, flags=re.S)
        alt_text = " ".join(re.findall(r'alt\s*=\s*["\']([^"\']*)', visible))
        visible = re.sub(r"<[^>]+>", " ", visible) + " " + alt_text

        for brand in page_brands:
            mentions = len(re.findall(rf"(?<![a-z]){brand}(?![a-z])", visible))
            is_official = any(
                domain_matches(page_host, d) for d in BRANDS.get(brand, set())
            )
            if mentions >= 2 and not is_official:
                detected_brands.append(brand)

    credential_terms = find_terms(
        sample,
        {
            "password", "passwd", "passcode", "username", "user name",
            "email address", "verification code", "one-time code", "otp",
            "two-factor authentication", "2fa", "security code",
        },
    )

    if detected_brands and (password_inputs or form_count or credential_terms):
        add_finding(
            findings, 25,
            "Page imitates a recognizable brand while requesting login/credential information: "
            + ", ".join(sorted(set(detected_brands))),
            "critical", "Brand impersonation",
        )
        score += 25

    if password_inputs:
        add_finding(
            findings, 2,
            f"Page contains {password_inputs} password input field(s).",
            "low", "Page content",
        )
        score += 2

    if password_inputs and form_count:
        add_finding(
            findings, 2,
            "A password field is combined with a form submission.",
            "low", "Credential collection",
        )
        score += 2

    if credential_terms and form_count:
        add_finding(
            findings, 1,
            "Credential-related terms appear together with an HTML form; this alone is not proof of phishing.",
            "low", "Credential collection",
        )
        score += 1

    login_language = contains_any(
        sample,
        {
            "sign in to continue", "login to continue", "verify your account",
            "confirm your account", "account has been suspended",
            "your account will be", "session has expired", "enter your password",
            "enter your credentials",
        },
    )

    if login_language:
        add_finding(
            findings, 8,
            "Page contains common credential-harvesting/login language: "
            + ", ".join(sorted(set(login_language))),
            "high", "Page content",
        )
        score += 8

    form_actions = re.findall(
        r'<form[^>]*\baction\s*=\s*["\']([^"\']+)["\']', sample, re.I
    )

    external_actions = []
    for action in form_actions:
        action = unquote(action.strip())
        if not action:
            continue
        parsed_action = urlparse(action)
        if parsed_action.hostname:
            action_host = parsed_action.hostname.lower()
            if page_host and base_domain(action_host) != base_domain(page_host):
                external_actions.append(action_host)

    if external_actions:
        add_finding(
            findings, 15,
            "Form submission points to an external host: "
            + ", ".join(sorted(set(external_actions))[:5]),
            "high", "Credential collection",
        )
        score += 15

    # Detect client-side redirects such as document.location = "login.html".
    js_targets = re.findall(
        r'(?:location(?:\.href|\.replace)?|document\.location)\s*=\s*["\']([^"\']+)["\']',
        sample, re.I,
    )
    # location.replace("x") / location.assign("x")
    js_targets += re.findall(
        r'location\.(?:replace|assign)\s*\(\s*["\']([^"\']+)["\']',
        sample, re.I,
    )
    # <meta http-equiv="refresh" content="0; url=x">
    js_targets += re.findall(
        r'<meta[^>]+http-equiv\s*=\s*["\']?refresh[^>]+content\s*=\s*["\'][^"\']*url\s*=\s*([^"\'>\s]+)',
        sample, re.I,
    )

    if js_targets:
        add_finding(
            findings, 1,
            "Client-side JavaScript redirects to: "
            + ", ".join(dict.fromkeys(js_targets[:5])),
            "low", "Page behavior",
        )
        score += 1

    # Follow a small number of same-site HTML targets. This catches phishing kits
    # where the root page is only a JavaScript wrapper and the real phishing page
    # is /login.html or /mobile.html.
    if js_targets:
        try:
            visited = set()
            base_url = response.url

            for target in js_targets[:5]:
                target_url = urljoin(base_url, target)
                parsed_target = urlparse(target_url)

                if parsed_target.scheme not in {"http", "https"}:
                    continue

                target_host = (parsed_target.hostname or "").lower()
                if page_host and not domain_matches(target_host, page_host):
                    continue

                target_url = target_url.split("#", 1)[0]
                if target_url in visited:
                    continue
                visited.add(target_url)

                try:
                    child_response = fetch_page(target_url)
                except (requests.RequestException, UnsafeTarget):
                    continue

                if child_response.status_code != 200:
                    continue

                child_html = (child_response.text or "").lower()[:1_000_000]
                if not child_html:
                    continue

                child_title_match = re.search(
                    r"<title[^>]*>(.*?)</title>", child_html, re.I | re.S
                )
                child_title = (
                    re.sub(r"\s+", " ", child_title_match.group(1)).strip()
                    if child_title_match else ""
                )

                child_has_login = bool(count_password_inputs(child_html))

                for signature, message in framework_signatures.items():
                    if signature in child_html:
                        severity, points = (
                            ("critical", 40) if child_has_login else ("medium", 10)
                        )
                        add_finding(
                            findings, points,
                            f"Child page {target} — {message}",
                            severity, "Child-page phishing fingerprint",
                        )
                        score += points

                child_host = (urlparse(child_response.url).hostname or "").lower()
                child_official_brand = official_brand_for_host(child_host)
                child_title_brands = find_terms(child_title, page_brands)
                child_brands = [
                    b for b in child_title_brands
                    if not any(
                        domain_matches(child_host, official_domain)
                        for official_domain in BRANDS.get(b, set())
                    )
                ]
                child_passwords = count_password_inputs(child_html)
                child_forms = len(re.findall(r"<form\b", child_html, re.I))
                child_credentials = find_terms(
                    child_html,
                    {"password", "username", "email address", "login", "sign in", "log in"},
                )

                if child_brands and (child_passwords or child_forms or child_credentials):
                    add_finding(
                        findings, 25,
                        f"Child page {target} imitates a brand and contains credential/login elements: "
                        + ", ".join(sorted(set(child_brands))),
                        "critical", "Child-page brand impersonation",
                    )
                    score += 25

                if child_passwords:
                    add_finding(
                        findings, 2,
                        f"Child page {target} contains {child_passwords} password input field(s).",
                        "low", "Child-page credential collection",
                    )
                    score += 2

                if child_passwords and child_forms:
                    add_finding(
                        findings, 2,
                        f"Child page {target} combines password input with an HTML form.",
                        "low", "Child-page credential collection",
                    )
                    score += 2

                if (
                    child_title
                    and child_official_brand is None
                    and find_terms(child_title, page_brands)
                ):
                    add_finding(
                        findings, 8,
                        f"Child page {target} has a recognizable brand in its title: {child_title[:120]}",
                        "medium", "Child-page content",
                    )
                    score += 8

        except Exception:
            # Never let optional child-page inspection break the main analyzer.
            pass

    encoded_scripts = len(re.findall(
        r"(?:atob\s*\(|fromcharcode|eval\s*\(|javascript:|data:text/html)",
        sample, re.I,
    ))

    if encoded_scripts >= 4:
        add_finding(
            findings, 7,
            "Page contains multiple signs of script/URL obfuscation.",
            "medium", "Page content",
        )
        score += 7

    return score


# =========================================================
# Main analyzer
# =========================================================

def analyze_url(url, network_check=True):
    """
    Defensive phishing URL analyzer.

    Returns:
        success
        score
        verdict
        level
        findings
        technical information
    """

    original_url = url
    url = normalize_url(url)

    if not url:
        return {
            "success": False,
            "error": "Invalid HTTP/HTTPS URL.",
        }

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    full_lower = unquote(url).lower()
    path = parsed.path or ""
    query = parsed.query or ""

    findings = []
    score = 0

    # -----------------------------------------------------
    # 1. HTTPS
    # -----------------------------------------------------

    if parsed.scheme.lower() == "http":
        add_finding(
            findings,
            8,
            "Website uses HTTP instead of HTTPS.",
            "medium",
            "Transport security",
        )
        score += 8

    # -----------------------------------------------------
    # 2. IP address
    # -----------------------------------------------------

    if is_ip_address(host):
        add_finding(
            findings,
            18,
            "URL uses an IP address instead of a normal domain.",
            "high",
            "Host analysis",
        )
        score += 18

    elif looks_like_obfuscated_ip(host):
        add_finding(
            findings,
            18,
            "Host is an obfuscated IP address (decimal/hex/octal notation).",
            "high",
            "Host analysis",
        )
        score += 18

    # -----------------------------------------------------
    # 3. URL length
    # -----------------------------------------------------

    url_length = len(url)

    if url_length > 250:
        add_finding(
            findings,
            14,
            f"Very long URL ({url_length} characters).",
            "high",
            "URL structure",
        )
        score += 14
    elif url_length > 120:
        add_finding(
            findings,
            7,
            f"Long URL ({url_length} characters).",
            "medium",
            "URL structure",
        )
        score += 7

    # -----------------------------------------------------
    # 4. Userinfo / @
    # -----------------------------------------------------

    if "@" in parsed.netloc:
        add_finding(
            findings,
            28,
            "URL contains user-information ('@') before the hostname, "
            "which can hide the actual destination host.",
            "high",
            "URL structure",
        )
        score += 28

    # -----------------------------------------------------
    # 5. Excessive subdomains
    # -----------------------------------------------------

    parts = [p for p in host.split(".") if p]

    # Count real subdomains only (www.example.co.uk has 1, an IP has 0).
    if is_ip_address(host):
        subdomain_count = 0
    else:
        subdomain_count = max(0, len(parts) - len(base_domain(host).split(".")))

    if subdomain_count >= 3:
        add_finding(
            findings,
            12,
            "Unusually large number of subdomains.",
            "high",
            "Host analysis",
        )
        score += 12
    elif subdomain_count == 2:
        add_finding(
            findings,
            5,
            "Multiple subdomains detected.",
            "low",
            "Host analysis",
        )
        score += 5

    # -----------------------------------------------------
    # 6. Hyphens
    # -----------------------------------------------------

    hyphen_count = host.count("-")

    if hyphen_count >= 3:
        add_finding(
            findings,
            8,
            "Domain contains many hyphens.",
            "medium",
            "Host analysis",
        )
        score += 8

    # -----------------------------------------------------
    # 7. Suspicious characters
    # -----------------------------------------------------

    suspicious_chars = re.findall(r"[%_=+]", url)

    if len(suspicious_chars) >= 6:
        add_finding(
            findings,
            8,
            "URL contains many encoded or suspicious characters.",
            "medium",
            "URL structure",
        )
        score += 8

    # -----------------------------------------------------
    # 8. Double slash in path
    # -----------------------------------------------------

    if "//" in path:
        add_finding(
            findings,
            5,
            "Path contains unusual double-slash characters.",
            "low",
            "URL structure",
        )
        score += 5

    # -----------------------------------------------------
    # 9. Suspicious words
    # -----------------------------------------------------

    detected_words = [
        word for word in SUSPICIOUS_WORDS
        if (word not in AMBIGUOUS_WORDS and word in full_lower)
        or (word in AMBIGUOUS_WORDS and find_terms(full_lower, [word]))
    ]

    # Brand names in their own official domain are not phishing evidence by themselves.
    official_brand = official_brand_for_host(host)
    if official_brand:
        detected_words = [w for w in detected_words if w != official_brand]

    if detected_words:
        unique_words = sorted(set(detected_words))
        points = min(
            sum(SUSPICIOUS_WORDS[w] for w in unique_words),
            25,
        )

        add_finding(
            findings,
            points,
            "Suspicious keywords detected: "
            + ", ".join(unique_words),
            "medium",
            "URL semantics",
        )
        score += points

    # -----------------------------------------------------
    # 10. URL shortener
    # -----------------------------------------------------

    if any(domain_matches(host, shortener) for shortener in SHORTENERS):
        add_finding(
            findings,
            20,
            "Known URL-shortening service detected; the final destination "
            "may be hidden.",
            "high",
            "URL reputation",
        )
        score += 20

    # -----------------------------------------------------
    # 10b. Temporary tunnel hosting
    # -----------------------------------------------------

    is_tunnel_host = any(domain_matches(host, d) for d in TUNNEL_DOMAINS)

    if is_tunnel_host:
        add_finding(
            findings,
            20,
            "Hosted on a temporary tunnel/free-hosting domain "
            "(commonly used to deliver phishing pages).",
            "high",
            "Hosting analysis",
        )
        score += 20

    # -----------------------------------------------------
    # 11. Tracking / IP logger
    # -----------------------------------------------------

    tracking_hits = set()

    if any(domain_matches(host, domain) for domain in TRACKING_DOMAINS):
        tracking_hits.add("known tracking/IP-logger domain")

    for pattern in TRACKING_PATTERNS:
        if pattern in full_lower:
            tracking_hits.add(pattern)

    if tracking_hits:
        add_finding(
            findings,
            35,
            "Possible tracking/IP-logger indicator detected: "
            + ", ".join(sorted(tracking_hits)),
            "critical",
            "Tracking analysis",
        )
        score += 35

    else:
        generic_hits = sorted(
            p for p in GENERIC_TRACKING_PATTERNS if p in full_lower
        )
        if generic_hits:
            add_finding(
                findings,
                5,
                "URL contains generic tracking-related words: "
                + ", ".join(generic_hits),
                "low",
                "Tracking analysis",
            )
            score += 5

    # -----------------------------------------------------
    # 12. Phishing-tool signatures
    # -----------------------------------------------------

    tool_hits = [
        pattern for pattern in PHISHING_TOOL_PATTERNS
        if pattern in full_lower
    ]

    if tool_hits:
        add_finding(
            findings,
            35,
            "Known phishing-tool signature detected in the URL: "
            + ", ".join(sorted(set(tool_hits))),
            "critical",
            "Tool signature",
        )
        score += 35

    # -----------------------------------------------------
    # 13. Credential combination
    # -----------------------------------------------------

    credential_words = {
        "login", "signin", "sign-in",
        "password", "credential", "credentials",
        "verify", "account", "authenticate",
    }

    credential_hits = [
        word for word in credential_words
        if word in full_lower
    ]

    if len(credential_hits) >= 3:
        add_finding(
            findings,
            15,
            "Multiple credential/phishing-related terms appear together.",
            "high",
            "URL semantics",
        )
        score += 15

    # -----------------------------------------------------
    # 14. Redirect parameters
    # -----------------------------------------------------

    query_params = parse_qs(query, keep_blank_values=True)
    suspicious_parameters = []

    for parameter in query_params:
        parameter_lower = parameter.lower()

        # Exact match only: substring matching flagged "category" (contains "go").
        if parameter_lower in REDIRECT_PARAMETERS:
            suspicious_parameters.append(parameter)

    if suspicious_parameters:
        add_finding(
            findings,
            10,
            "Redirect-style URL parameters detected: "
            + ", ".join(sorted(set(suspicious_parameters))),
            "medium",
            "Redirect analysis",
        )
        score += 10

    # Also inspect parameter values for embedded URLs.
    embedded_urls = []

    for values in query_params.values():
        for value in values:
            decoded = unquote(value)
            if re.search(r"https?://", decoded, re.I):
                embedded_urls.append(decoded)

    if embedded_urls:
        add_finding(
            findings,
            8,
            "Query parameters contain embedded URL destinations.",
            "medium",
            "Redirect analysis",
        )
        score += 8

    # -----------------------------------------------------
    # 15. Encoding
    # -----------------------------------------------------

    encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", url))

    if encoded_count >= 8:
        add_finding(
            findings,
            8,
            "Heavy URL encoding detected.",
            "medium",
            "URL structure",
        )
        score += 8

    # -----------------------------------------------------
    # 16. Random-looking host
    # -----------------------------------------------------

    hostname_without_tld = base_domain(host).split(".")[0]

    if (
        len(hostname_without_tld) > 15
        and calculate_entropy(hostname_without_tld) > 3.8
    ):
        add_finding(
            findings,
            6,
            "Domain contains a high-entropy/random-looking hostname.",
            "medium",
            "Host analysis",
        )
        score += 6

    # -----------------------------------------------------
    # 17. Suspicious file extension
    # -----------------------------------------------------

    lower_path = path.lower()

    for extension in SUSPICIOUS_EXTENSIONS:
        if lower_path.endswith(extension):
            add_finding(
                findings,
                15,
                f"Suspicious executable/download extension detected: {extension}",
                "high",
                "Payload analysis",
            )
            score += 15
            break

    # -----------------------------------------------------
    # 18. Brand impersonation
    # -----------------------------------------------------

    brand_hits = brand_hits_for_host(host)

    if brand_hits:
        add_finding(
            findings,
            20,
            "Possible brand impersonation detected: "
            + ", ".join(sorted(set(brand_hits))),
            "high",
            "Brand analysis",
        )
        score += 20

    # -----------------------------------------------------
    # 19. Lookalike brand spelling
    # -----------------------------------------------------

    compact_host = re.sub(r"[^a-z0-9]", "", host)

    lookalikes = {
        "paypa1": "paypal",
        "paypai": "paypal",
        "facebo0k": "facebook",
        "facebok": "facebook",
        "micros0ft": "microsoft",
        "g00gle": "google",
        "go0gle": "google",
        "instagrarn": "instagram",
        "instagramm": "instagram",
        "arnazon": "amazon",
        "amaz0n": "amazon",
    }

    for fake, real in lookalikes.items():
        if (
            fake in compact_host
            and real not in compact_host
            and not official_brand_for_host(host)
        ):
            add_finding(
                findings,
                18,
                f"Possible lookalike/typosquatting of {real}.",
                "high",
                "Brand analysis",
            )
            score += 18
            break

    # -----------------------------------------------------
    # 19b. IDN / punycode homographs
    # -----------------------------------------------------

    if any(label.startswith("xn--") for label in parts) or not host.isascii():
        add_finding(
            findings,
            20,
            "Domain uses internationalized (IDN/punycode) characters, "
            "which can imitate trusted brands (homograph attack).",
            "high",
            "Host analysis",
        )
        score += 20

    # -----------------------------------------------------
    # 20. DNS resolution
    # -----------------------------------------------------

    resolved_ip = host if is_ip_address(host) else None
    resolved_ips = [host] if is_ip_address(host) else []

    if network_check and host and not is_ip_address(host):
        resolved_ips = resolve_host_ips(host)
        resolved_ip = resolved_ips[0] if resolved_ips else None

        if not resolved_ip:
            add_finding(
                findings,
                10,
                "Domain could not be resolved through DNS.",
                "medium",
                "Network analysis",
            )
            score += 10

    # Never fetch loopback/private/reserved targets (SSRF protection).
    non_public_ips = [ip for ip in resolved_ips if not is_public_ip(ip)]
    live_check = network_check and not non_public_ips

    if network_check and non_public_ips:
        add_finding(
            findings,
            10,
            f"Host resolves to a private/reserved address ({non_public_ips[0]}); "
            "live HTTP analysis was skipped for safety.",
            "medium",
            "Network analysis",
        )
        score += 10

    # -----------------------------------------------------
    # 21. Live HTTP analysis
    # -----------------------------------------------------

    http_status = None
    final_url = url
    redirect_count = 0
    page_content_score = 0
    http_analysis_state = "skipped_private" if non_public_ips else "not_checked"

    if live_check:
        try:
            response = fetch_page(url)

            http_status = response.status_code
            final_url = response.url
            redirect_count = len(response.redirects)
            http_analysis_state = "reachable"

            # A non-success final HTTP response means the requested resource
            # was not successfully analyzed. Do not interpret 4xx/5xx as
            # evidence that the URL is safe.
            if http_status >= 400:
                add_finding(
                    findings,
                    0,
                    f"Target returned HTTP {http_status}; the requested resource could not be reliably analyzed.",
                    "info",
                    "HTTP availability",
                )
                http_analysis_state = "inconclusive_http"

            # Redirect chain
            if redirect_count >= 3:
                add_finding(
                    findings,
                    12,
                    f"Multiple redirects detected ({redirect_count}).",
                    "high",
                    "Redirect analysis",
                )
                score += 12
            elif redirect_count >= 1:
                add_finding(
                    findings,
                    3,
                    f"HTTP redirect detected ({redirect_count} redirect(s)).",
                    "low",
                    "Redirect analysis",
                )
                score += 3

            # HTTPS -> HTTP downgrade
            if (
                url.startswith("https://")
                and final_url.startswith("http://")
            ):
                add_finding(
                    findings,
                    12,
                    "Redirect changes HTTPS to HTTP.",
                    "high",
                    "Transport security",
                )
                score += 12

            # Analyze final destination hostname.
            final_host = (urlparse(final_url).hostname or "").lower()

            if final_host and final_host != host:
                if any(
                    domain_matches(final_host, domain)
                    for domain in TRACKING_DOMAINS
                ):
                    add_finding(
                        findings,
                        30,
                        "Redirect chain ends at a known tracking/IP-logger domain.",
                        "critical",
                        "Redirect analysis",
                    )
                    score += 30

                final_tool_hits = [
                    pattern
                    for pattern in PHISHING_TOOL_PATTERNS
                    if pattern in final_url.lower()
                ]

                if final_tool_hits:
                    add_finding(
                        findings,
                        30,
                        "Redirect destination contains a known phishing-tool signature: "
                        + ", ".join(sorted(set(final_tool_hits))),
                        "critical",
                        "Redirect analysis",
                    )
                    score += 30

            # Page content analysis
            content_type = response.headers.get("Content-Type", "").lower()

            if "text/html" in content_type or "<html" in (response.text[:1000].lower()):
                try:
                    page_content_score = analyze_page_content(response, findings)
                    score += page_content_score
                except Exception:
                    # A parsing problem must never crash the whole analysis.
                    pass

                final_is_tunnel = any(
                    domain_matches(final_host, d) for d in TUNNEL_DOMAINS
                )
                if (is_tunnel_host or final_is_tunnel) and count_password_inputs(
                    response.text[:MAX_BODY_BYTES].lower()
                ):
                    add_finding(
                        findings,
                        25,
                        "A password/login form is served from a temporary tunnel domain "
                        "- a typical credential-phishing delivery setup.",
                        "critical",
                        "Credential collection",
                    )
                    score += 25

        except requests.TooManyRedirects:
            http_analysis_state = "inconclusive_redirects"
            add_finding(
                findings,
                12,
                f"Excessive redirect chain (more than {MAX_REDIRECTS} redirects).",
                "high",
                "Redirect analysis",
            )
            score += 12

        except UnsafeTarget as exc:
            http_analysis_state = "inconclusive_connection"
            add_finding(
                findings,
                10,
                f"A redirect leads to a private/internal address; analysis stopped ({exc}).",
                "high",
                "Redirect analysis",
            )
            score += 10

        except requests.RequestException:
            # A connection failure is not automatically malicious and is not
            # evidence of safety. The result must remain inconclusive.
            http_analysis_state = "inconclusive_connection"
            add_finding(
                findings,
                0,
                "Target could not be reached for live HTTP analysis; safety could not be established.",
                "info",
                "HTTP availability",
            )

    # -----------------------------------------------------
    # 22. Final scoring
    # -----------------------------------------------------

    score = max(0, min(100, score))

    # Strong indicators should never end up as "LIKELY SAFE"
    critical_findings = [
        finding for finding in findings
        if finding["severity"] == "critical"
    ]

    # A target that could not be successfully fetched must never become
    # "LIKELY SAFE" merely because no page-content indicators were available.
    # HTTP 4xx/5xx and connection failures are availability states, not safety
    # verdicts. Strong indicators found before the failed request can still
    # produce a malicious verdict.
    if critical_findings or score >= 70:
        verdict = "MALICIOUS / HIGH RISK"
        level = "critical"
    elif score >= 45:
        verdict = "SUSPICIOUS"
        level = "high"
    elif score >= 25:
        verdict = "SUSPICIOUS"
        level = "medium"
    elif http_analysis_state in {
        "inconclusive_http", "inconclusive_connection",
        "inconclusive_redirects", "skipped_private",
    }:
        verdict = "INCONCLUSIVE / UNAVAILABLE"
        level = "inconclusive"
    else:
        verdict = "LIKELY SAFE"
        level = "low"

    findings.sort(
        key=lambda item: item["score"],
        reverse=True,
    )

    official_brand = official_brand_for_host(host)

    # Keep the three concepts separate in the result. An official domain is
    # trusted for identity, not automatically trusted for behavior.
    domain_trust = "official brand domain" if official_brand else "unknown/unverified domain"

    category_scores = {}
    for finding in findings:
        category = finding.get("category", "URL analysis")
        category_scores[category] = category_scores.get(category, 0) + finding.get("score", 0)

    return {
        "success": True,
        "url": original_url,
        "normalized_url": url,
        "domain": host,
        "ip": resolved_ip,
        "score": score,
        "verdict": verdict,
        "level": level,
        "http_status": http_status,
        "http_analysis_state": http_analysis_state,
        "final_url": final_url,
        "url_length": url_length,
        "https": parsed.scheme.lower() == "https",
        "redirect_count": redirect_count,
        "page_content_score": page_content_score,
        "official_brand": official_brand,
        "domain_trust": domain_trust,
        "category_scores": category_scores,
        "findings": findings,
    }
