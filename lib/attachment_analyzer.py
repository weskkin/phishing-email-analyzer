import hashlib
import requests

# known dangerous file extensions
DANGEROUS_EXTENSIONS = [
    # executables & scripts
    '.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.wsf', 
    '.msi', '.dll', '.com', '.pif', '.cpl',
    # macro-enabled office files
    '.docm', '.xlsm', '.pptm',
    # container / disk images (often bypass Mark-of-the-Web inspection)
    '.iso', '.img', '.vhd', '.vhdx'
]

# common benign extensions that attackers masquerade as
DISGUISED_TARGET_EXTENSIONS = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.png', '.jpg', '.txt']

def calculate_hashes(raw_bytes):
    if not raw_bytes:
        return {'md5': '', 'sha1': '', 'sha256': ''}
    return {
        'md5': hashlib.md5(raw_bytes).hexdigest(),
        'sha1': hashlib.sha1(raw_bytes).hexdigest(),
        'sha256': hashlib.sha256(raw_bytes).hexdigest(),
    }

def check_double_extension(filename):
    parts = filename.lower().rsplit('.', 2)
    if len(parts) >= 3:
        fake_ext = '.' + parts[1]
        real_ext = '.' + parts[2]
        if fake_ext in DISGUISED_TARGET_EXTENSIONS and real_ext in DANGEROUS_EXTENSIONS:
            return {
                'severity': 'CRITICAL',
                'type': 'DOUBLE_EXTENSION',
                'message': f"Double extension detected: '{filename}' masks executable ({real_ext}) as document ({fake_ext})"
            }
    return None

def check_magic_bytes_mismatch(filename, raw_bytes):
    """
    Detects if an executable is masquerading under a non-executable extension.
    """
    if len(raw_bytes) < 4:
        return None

    lower_name = filename.lower()
    # check if file claims to be a document or image
    is_claimed_doc = any(lower_name.endswith(ext) for ext in DISGUISED_TARGET_EXTENSIONS)
    
    # check if raw bytes start with 'MZ' (Windows Portable Executable magic bytes)
    is_pe_executable = raw_bytes.startswith(b'MZ')

    if is_claimed_doc and is_pe_executable:
        return {
            'severity': 'CRITICAL',
            'type': 'MAGIC_BYTE_MISMATCH',
            'message': f"File '{filename}' claims to be a document, but its binary header is a Windows Executable (MZ header)"
        }
    return None

def check_virustotal_hash(sha256, api_key):
    """
    Queries VirusTotal API v3 for a file's SHA256 reputation
    """
    if not api_key or not sha256:
        return None

    try:
        headers = {"x-apikey": api_key}
        resp = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=headers, timeout=10)

        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            return {
                'sha256': sha256,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0)
            }
    except Exception:
        pass
    return None

def analyze_attachments(attachments, api_key=None):
    """
    Main runner for Phase 4 Attachment Analysis
    """
    flags = []
    audited_attachments = []

    for att in attachments:
        filename = att.get('filename', 'unnamed')
        raw_bytes = att.get('data', b'')
        mime_type = att.get('content_type', '')

        hashes = calculate_hashes(raw_bytes)

        # 1. Dangerous extension check
        ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        if ext in DANGEROUS_EXTENSIONS:
            flags.append({
                'severity': 'HIGH',
                'type': 'DANGEROUS_EXTENSION',
                'message': f"Attachment '{filename}' uses high-risk executable or script extension ({ext})"
            })

        # 2. Double extension check
        double_ext_flag = check_double_extension(filename)
        if double_ext_flag:
            flags.append(double_ext_flag)

        # 3. Magic bytes inspection
        magic_flag = check_magic_bytes_mismatch(filename, raw_bytes)
        if magic_flag:
            flags.append(magic_flag)

        # 4. Threat Intel (VirusTotal Hash Lookup)
        vt_hash_stat = None
        if api_key and hashes['sha256']:
            vt_hash_stat = check_virustotal_hash(hashes['sha256'], api_key)
            if vt_hash_stat and vt_hash_stat['malicious'] > 0:
                flags.append({
                    'severity': 'CRITICAL',
                    'type': 'VIRUSTOTAL_MALICIOUS_HASH',
                    'message': f"VirusTotal flagged attachment hash as MALICIOUS ({vt_hash_stat['malicious']} engines)"
                })

        audited_attachments.append({
            'filename': filename,
            'mime_type': mime_type,
            'size': len(raw_bytes),
            'hashes': hashes,
            'vt_stat': vt_hash_stat
        })

    return audited_attachments, flags