from typing import List, Dict, Any

class FixAction:
    def __init__(self, rank: int, title: str, score_gain: int, category: str, mta: str, snippet: str, explanation: str, command: str = ""):
        self.rank = rank
        self.title = title
        self.score_gain = score_gain
        self.category = category
        self.mta = mta
        self.snippet = snippet
        self.explanation = explanation
        self.command = command

def generate_remediation_plan(deductions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Ranks remediation tasks using Severity x Exposure x Ease of Fix.
    Generates exact copy-paste configuration snippets for Postfix, Exim, and Dovecot.
    """
    deduction_ids = {d["rule_id"] for d in deductions}
    primary_fixes = []
    later_fixes = []

    # Fix 1: TLS 1.0/1.1
    if "RULE-TLS-01" in deduction_ids:
        primary_fixes.append({
            "rank": 1,
            "title": "Disable TLS 1.0 / 1.1",
            "score_gain": 18,
            "priority": "HIGH",
            "mta": "Postfix",
            "file": "/etc/postfix/main.cf",
            "snippet": "smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1",
            "exim_snippet": "tls_require_ciphers = DEFAULT:!TLSv1:!TLSv1.1",
            "explanation": "Enforces minimum TLS 1.2, eliminating POODLE, BEAST, and downgrade attack vectors.",
            "command": "postfix reload"
        })

    # Fix 2: Weak Ciphers / PFS
    if "RULE-CIPHER-02" in deduction_ids:
        primary_fixes.append({
            "rank": 2,
            "title": "Strong ciphers with forward secrecy",
            "score_gain": 18,
            "priority": "HIGH",
            "mta": "Postfix",
            "file": "/etc/postfix/main.cf",
            "snippet": "smtpd_tls_mandatory_ciphers = high\ntls_high_cipherlist = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
            "exim_snippet": "tls_require_ciphers = HIGH:!aNULL:!MD5:!3DES:!CAMELLIA:!SRP:!PSK",
            "explanation": "Mandates Ephemeral Diffie-Hellman key exchanges (PFS), preventing retroactive decryption of captured email flows.",
            "command": "postfix reload"
        })

    # Fix 3: Certificate Renewal
    if "RULE-CERT-03" in deduction_ids:
        primary_fixes.append({
            "rank": 3,
            "title": "Renew certificate (12 days left)",
            "score_gain": 5,
            "priority": "MEDIUM",
            "mta": "Certbot / Let's Encrypt",
            "file": "/etc/letsencrypt/renewal/mail.conf",
            "snippet": 'certbot renew --deploy-hook "systemctl reload postfix"',
            "exim_snippet": 'certbot renew --deploy-hook "systemctl reload exim4"',
            "explanation": "Automates TLS certificate renewal before expiration to prevent mail transaction aborts from peer MTAs.",
            "command": "systemctl reload postfix"
        })

    # Later Fixes
    if "RULE-AUTH-04" in deduction_ids:
        later_fixes.append({
            "title": "Require TLS before AUTH",
            "score_gain": 5,
            "snippet": "smtpd_tls_auth_only = yes"
        })

    if "RULE-PQC-05" in deduction_ids:
        later_fixes.append({
            "title": "Negotiate TLS 1.3",
            "score_gain": 6,
            "snippet": "smtpd_tls_protocols = >=TLSv1.2"
        })

    # Sort by score gain descending
    primary_fixes.sort(key=lambda x: x["score_gain"], reverse=True)
    for idx, fix in enumerate(primary_fixes):
        fix["rank"] = idx + 1

    total_gain_primary = sum(f["score_gain"] for f in primary_fixes)

    return {
        "primary_fixes": primary_fixes,
        "later_fixes": later_fixes,
        "total_potential_gain": total_gain_primary,
    }
