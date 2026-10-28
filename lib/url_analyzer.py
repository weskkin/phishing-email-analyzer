import re
import base64
import requests
from urllib.parse import urlparse

SUSPICIOUS_TLDS = ['.xyz', '.top', '.buzz', '.click', '.tk', '.ml', '.ga', '.cf', '.gq', '.work']
SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly']

def extract_urls(body_plain, body_html):
    found_urls = set()
    anchor_mismatches = []
    generic_url_regex = r'https?://[^\s<>"\'\)\]\}]+'

    # plain text extraction
    if body_plain:
        for match in re.findall(generic_url_regex, body_plain):
            found_urls.add(match)

    # HTML extraction with anchor tag inspection
    if body_html:
        # regex to find <a href="DESTINATION">TEXT</a>
        a_tag_pattern = r'<a\s+(?:[^>]*?\s+)?href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>'
        for href, text in re.findall(a_tag_pattern, body_html, re.IGNORECASE | re.DOTALL):
            found_urls.add(href)
            # Check for anchor text disguise
            # Does the text itself look like a URL?
            clean_text = text.strip()
            if clean_text.startswith(('http://', 'https://', 'www.')):
                text_domain = urlparse(clean_text if clean_text.startswith('http') else 'http://' + clean_text).netloc.lower()
                href_domain = urlparse(href).netloc.lower()
                # If the displayed domain doesn't match the destination domain -> Phishing disguise!
                if text_domain and href_domain and text_domain != href_domain:
                    anchor_mismatches.append({
                        'display_text': clean_text,
                        'destination_url': href,
                        'display_domain': text_domain,
                        'dest_domain': href_domain
                    })

        # also grab any standalone URLs in HTML not wrapped in <a> tags
        for match in re.findall(generic_url_regex, body_html):
            found_urls.add(match)

        return list(found_urls), anchor_mismatches

def unshorten_url(url, timeout=5):
    """
    Follows HTTP redirects to reveal the true destination of shortened URLs
    """

    try:
        parsed = urlparse(url)
        if any(parsed.netloc.endswith(s) for s in SHORTENERS):
            resp = requests.head(url, allow_redirects=True, timeout=timeout)
            return resp.url
    except Exception:
        pass
    return url

def audit_url_heuristics(url):
    """
    Checks a single URL for structural and lexical phishing indicators
    """

    flags = []
    parsed = urlparse(url)
    hostname = parsed.hostname or ''

    # Check 1: Raw IP address used as hostname
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
        flags.append({
            'severity': 'HIGH',
            'type': 'IP_BASED_URL',
            'message': f"URL uses raw IP address instead of domain name: {url}"
        })

    # Check 2: Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            flags.append({
                'severity': 'MEDIUM',
                'type': 'SUSPICIOUS_TLD',
                'message': f"URL contains high-risk TLD ({tld}): {url}"
            })

    # Check 3: Embedded credentials / @ redirect trick
    if '@' in url:
        flags.append({
            'severity': 'HIGH',
            'type': 'AT_SYMBOL_URL',
            'message': f"URL contains '@' symbol (possible credential spoofing/redirect): {url}"
        })

    # Check 4: Excessive length (often used in payload obfuscation)
    if len(url) > 180:
        flags.append({
            'severity': 'LOW',
            'type': 'LONG_URL',
            'message': f"Abnormally long URL ({len(url)} chars): {url[:50]}..."
        })
    return flags

def check_virustotal_url(url, api_key):
    """
    Queries VirusTotal API v3 for URL reputation stats
    """

    if not api_key:
        return None
    try:
        # Base64 encode the URL without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key}
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            return {
                'url': url,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0)
            }
    except Exception:
        pass
    return None

def analyze_urls(body_plain, body_html, api_key=None):
    """
    Main runner for Phase 3 URL Analysis
    """

    flags = []
    urls, anchor_mismatches = extract_urls(body_plain, body_html)

    # 1. Flag anchor tag deception
    for mismatch in anchor_mismatches:
        flags.append({
            'severity': 'CRITICAL',
            'type': 'DECEPTIVE_HYPERLINK',
            'message': (f"Disguised Link: Text displays '{mismatch['display_text']}' "
                        f"but links to '{mismatch['destination_url']}'")
        })

    # 2. Run heuristics on each discovered URL
    vt_results = []
    for raw_url in urls:
        resolved_url = unshorten_url(raw_url)
        flags.extend(audit_url_heuristics(resolved_url))

        # Check VirusTotal if API key is provided
        if api_key:
            vt_stat = check_virustotal_url(resolved_url, api_key)
            if vt_stat:
                vt_results.append(vt_stat)
                if vt_stat['malicious'] > 0:
                    flags.append({
                        'severity': 'CRITICAL',
                        'type': 'VIRUSTOTAL_MALICIOUS_URL',
                        'message': f"VirusTotal flagged URL as malicious ({vt_stat['malicious']} engines): {resolved_url}"
                    })
    return urls, flags, vt_results
