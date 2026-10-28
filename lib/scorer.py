def calculate_risk(header_flags, url_flags, attachment_flags):
    """
    Computes a cumulative risk score (0-100) and assigns an actionable triage verdict
    """
    all_flags = header_flags + url_flags + attachment_flags
    raw_score = 0

    severity_weights = {
        'CRITICAL': 35,
        'HIGH': 20,
        'MEDIUM': 10,
        'LOW': 5
    }

    for flag in all_flags:
        severity = flag.get('severity', 'LOW')
        raw_score += severity_weights.get(severity, 5)

    # cap score at 100
    score = min(raw_score, 100)

    # Assign verdict based on score thresholds
    if score >= 70:
        verdict = "MALICIOUS / HIGH RISK"
        recommendation = "Block sender domain/IP, purge email from all inboxes, and reset user credentials if clicked."
    elif score >= 35:
        verdict = "SUSPICIOUS / MEDIUM RISK"
        recommendation = "Quarantine email and route to Tier 2 SOC analyst for manual inspection."
    elif score >= 15:
        verdict = "LOW RISK"
        recommendation = "Deliver with external warning banner; minor configuration anomalies detected."
    else:
        verdict = "CLEAN / BENIGN"
        recommendation = "No security indicators identified. Safe to deliver."

    return score, verdict, recommendation, all_flags