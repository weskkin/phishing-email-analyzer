import re
from email.utils import parseaddr

def extract_domain(email_str):
    if not email_str:
        return ''
    
    _, address = parseaddr(email_str)

    if '@' in address:
        return address.split('@')[-1].lower().strip('>')

    return ''

def extract_origin_ip(received_hops):
    if not received_hops:
        return None

    # earliest hop is at the end of the list
    earliest_hop = received_hops[-1]

    # regex to find an IPv4 address inside brackets or parentheses
    ip_pattern = r'(?:\[|\()(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\]|\))'
    matches = re.findall(ip_pattern, earliest_hop)

    if matches:
        return matches[0]

    # fallback : search for any standalone IP in that hop
    standalone_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    matches = re.findall(standalone_pattern, earliest_hop)

    return matches[0] if matches else None

def check_header_mismatches(headers):
    flags = []

    from_dom = extract_domain(headers.get('from', ''))
    reply_dom = extract_domain(headers.get('reply_to', ''))
    return_dom = extract_domain(headers.get('return_path', ''))

    if not from_dom:
        flags.append({
            'severity': 'HIGH',
            'type': 'MISSING_FROM',
            'message': 'No valid sender domain found in From header'
        })
        return flags

    # Check 1: From vs. Reply-To
    if reply_dom and reply_dom != from_dom:
        flags.append({
            'severity': 'HIGH',
            'type': 'REPLY_TO_MISMATCH',
            'message': f"Reply-To domain ({reply_dom}) does not match From domain ({from_dom})"
        })

    # Check 2: From vs. Return-Path
    if return_dom and return_dom != from_dom:
        flags.append({
            'severity': 'MEDIUM',
            'type': 'RETURN_PATH_MISMATCH',
            'message': f"Return-Path domain ({return_dom}) does not match From domain ({from_dom})"
        })

    return flags

def check_authentication(auth_header):
    flags = []

    if not auth_header:
        flags.append({
            'severity': 'LOW',
            'type': 'NO_AUTH_HEADER',
            'message': 'No Authentication-Results header found'
        })
        return flags

    auth_lower = auth_header.lower()

    # DMARC checks
    if 'dmarc=fail' in auth_lower:
        flags.append({
            'severity': 'CRITICAL',
            'type': 'DMARC_FAIL',
            'message': 'DMARC authentication failed (Domain alignment or policy violation)'
        })
    elif 'dmarc=pass' in auth_lower:
        pass  # Clean
    elif 'dmarc=none' in auth_lower:
        flags.append({
            'severity': 'LOW',
            'type': 'DMARC_NONE',
            'message': 'DMARC policy is set to none (monitoring only)'
        })

    # SPF checks
    if 'spf=fail' in auth_lower:
        flags.append({
            'severity': 'HIGH',
            'type': 'SPF_FAIL',
            'message': 'SPF hard fail: sending server is not authorized'
        })
    elif 'spf=softfail' in auth_lower:
        flags.append({
            'severity': 'MEDIUM',
            'type': 'SPF_SOFTFAIL',
            'message': 'SPF softfail: sending server is likely unauthorized'
        })

    # DKIM checks
    if 'dkim=fail' in auth_lower:
        flags.append({
            'severity': 'HIGH',
            'type': 'DKIM_FAIL',
            'message': 'DKIM signature verification failed (body or headers altered)'
        })

    return flags

def analyze_headers(headers):
    """
    Main runner for Phase 2 header analysis
    """

    all_flags = []
    all_flags.extend(check_header_mismatches(headers))
    all_flags.extend(check_authentication(headers.get('auth_results', '')))

    origin_ip = extract_origin_ip(headers.get('received', []))

    return all_flags, origin_ip