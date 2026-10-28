import sys
import os
from dotenv import load_dotenv
from colorama import Fore, Style, init

init(autoreset=True)

from lib.parser import parse_eml
from lib.header_analyzer import analyze_headers
from lib.url_analyzer import analyze_urls
from lib.attachment_analyzer import analyze_attachments
from lib.scorer import calculate_risk

def print_flag(flag):
    sev = flag['severity']
    if sev == 'CRITICAL':
        color = Fore.LIGHTRED_EX
    elif sev == 'HIGH':
        color = Fore.RED
    elif sev == 'MEDIUM':
        color = Fore.YELLOW
    else:
        color = Fore.CYAN
    print(f"  {color}[{sev}] {flag['type']}: {flag['message']}{Style.RESET_ALL}")

def main():
    if len(sys.argv) < 2:
        print(f"{Fore.YELLOW}Usage: python analyzer.py <path_to_email.eml>{Style.RESET_ALL}")
        sys.exit(1)

    # load environment variables
    load_dotenv()
    vt_api_key = os.getenv('VT_API_KEY')

    filepath = sys.argv[1]
    print(f"\n{Fore.CYAN}[*] Parsing: {filepath} ...{Style.RESET_ALL}")

    headers, body_plain, body_html, attachments = parse_eml(filepath)

    print("=" * 60)
    print("  EXTRACTED HEADERS")
    print("=" * 60)
    print(f"From         : {headers['from']}")
    print(f"To           : {headers['to']}")
    print(f"Reply-To     : {headers['reply_to']}")
    print(f"Return-Path  : {headers['return_path']}")
    print(f"Subject      : {headers['subject']}")
    print(f"Date         : {headers['date']}")
    print(f"Auth-Results : {headers['auth_results']}")
    print(f"Total Hops   : {len(headers['received'])}")

    # ------------------ Headers Analysis ------------------
    header_flags, origin_ip = analyze_headers(headers)
    print("\n" + "=" * 60)
    print("  HEADER SECURITY AUDIT")
    print("=" * 60)
    print(f"Originating IP : {origin_ip or 'Could not determine'}")
    print(f"Flags Triggered: {len(header_flags)}\n")
    for flag in header_flags:
        print_flag(flag)
    # ----------------------------------------------------------

    # ------------------ URL & Link Analysis ------------------
    urls, url_flags, vt_results = analyze_urls(body_plain, body_html, api_key=vt_api_key)
    print("\n" + "=" * 60)
    print("  URL & LINK SECURITY AUDIT")
    print("=" * 60)
    print(f"Unique URLs Extracted : {len(urls)}")
    print(f"Flags Triggered       : {len(url_flags)}\n")
    for u in urls:
        print(f"  [Discovered URL] {u}")
    print()
    for flag in url_flags:
        print_flag(flag)
    # ----------------------------------------------------------

    # ------------------ Attachment Analysis ------------------
    audited_attachments, attachment_flags = analyze_attachments(attachments, api_key=vt_api_key)
    print("\n" + "=" * 60)
    print(f"  ATTACHMENT SECURITY AUDIT ({len(audited_attachments)})")
    print("=" * 60)
    print(f"Flags Triggered: {len(attachment_flags)}\n")
    for att in audited_attachments:
        print(f"  Filename : {att['filename']}")
        print(f"  MIME     : {att['mime_type']}")
        print(f"  Size     : {att['size']} bytes")
        print(f"  SHA256   : {att['hashes']['sha256']}")
        if att['vt_stat']:
            print(f"  VT Hits  : {att['vt_stat']['malicious']} malicious detections")
        print()
    for flag in attachment_flags:
        print_flag(flag)
    # ----------------------------------------------------------

    # ------------------ Executive Triage Summary ------------------
    score, verdict, recommendation, all_flags = calculate_risk(header_flags, url_flags, attachment_flags)

    print("\n" + "=" * 60)
    print(f"{Fore.LIGHTBLUE_EX}  EXECUTIVE TRIAGE SUMMARY{Style.RESET_ALL}")
    print("=" * 60)

    if score >= 70:
        score_color = Fore.LIGHTRED_EX
    elif score >= 35:
        score_color = Fore.YELLOW
    elif score >= 15:
        score_color = Fore.CYAN
    else:
        score_color = Fore.GREEN

    print(f"Risk Score    : {score_color}{score}/100{Style.RESET_ALL}")
    print(f"Verdict       : {score_color}{verdict}{Style.RESET_ALL}")
    print(f"Flags Total   : {len(all_flags)} (Critical: {sum(1 for f in all_flags if f['severity'] == 'CRITICAL')}, High: {sum(1 for f in all_flags if f['severity'] == 'HIGH')}, Medium: {sum(1 for f in all_flags if f['severity'] == 'MEDIUM')})")
    print(f"Action Needed : {recommendation}")
    print("=" * 60 + "\n")

if __name__ == '__main__':
    main()