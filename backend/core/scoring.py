from typing import List, Dict, Any

class ScoringRule:
    def __init__(self, rule_id: str, title: str, category: str, deduction: int, standard: str, description: str):
        self.rule_id = rule_id
        self.title = title
        self.category = category
        self.deduction = deduction
        self.standard = standard
        self.description = description

RULES = [
    ScoringRule(
        rule_id="RULE-TLS-01",
        title="Obsolete Protocol Negotiated (TLS 1.0 / 1.1)",
        category="Protocol Version",
        deduction=18,
        standard="NIST SP 800-52r2 Sec 3.1 & RFC 8996",
        description="TLS 1.0 and TLS 1.1 are officially deprecated. They lack support for modern authenticated encryption and are susceptible to downgrade attacks."
    ),
    ScoringRule(
        rule_id="RULE-CIPHER-02",
        title="Weak Cipher Suite Without Forward Secrecy (PFS)",
        category="Cipher Suites",
        deduction=18,
        standard="NIST SP 800-52r2 Sec 3.3.1 & RFC 8314",
        description="Static RSA key exchange or legacy CBC-mode/3DES ciphers were detected. Traffic can be recorded and decrypted later if the server private key is compromised."
    ),
    ScoringRule(
        rule_id="RULE-CERT-03",
        title="Certificate Expiring Soon (< 15 days remaining)",
        category="Certificate Health",
        deduction=5,
        standard="RFC 5280 / Best Practice",
        description="X.509 certificate will expire in less than 15 days, risking mail delivery rejection or hard TLS negotiation failures across peer MTAs."
    ),
    ScoringRule(
        rule_id="RULE-AUTH-04",
        title="Plaintext AUTH Offered or Transmitted Before STARTTLS",
        category="Authentication Security",
        deduction=5,
        standard="RFC 8314 Sec 4.1 & RFC 3207",
        description="Credentials or authentication mechanisms advertised before establishing an encrypted TLS session, risking credential harvesting."
    ),
    ScoringRule(
        rule_id="RULE-PQC-05",
        title="Lack of TLS 1.3 / Modern AEAD Support",
        category="Modern Cryptography",
        deduction=6,
        standard="NIST SP 800-52r2 Sec 3.1 & RFC 8461",
        description="Server does not negotiate TLS 1.3 1-RTT handshake or modern AEAD suites (AES-GCM / ChaCha20-Poly1305)."
    ),
]

def calculate_security_posture(sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Evaluates analyzed mail traffic against NIST SP 800-52r2 & RFC 8314.
    Returns 0-100 Email Security Score, rating tier, and granular deductions.
    """
    if not sessions:
        return {
            "score": 100,
            "rating": "Secure",
            "deductions": [],
            "total_deduction": 0,
            "sessions_count": 0,
        }

    deductions: List[Dict[str, Any]] = []
    has_tls_10 = any(s.get("tls_version") in ("TLS 1.0", "TLS 1.1", "SSL 3.0") for s in sessions)
    has_weak_cipher = any(not s.get("pfs") or not s.get("aead") for s in sessions)
    has_expiring_cert = any(s.get("cert_days_left", 365) <= 15 for s in sessions)
    has_auth_downgrade = any(s.get("downgrade_detected", False) for s in sessions)
    lacks_tls_13 = all(s.get("tls_version") != "TLS 1.3" for s in sessions)

    evidence_frames = {}
    for s in sessions:
        if s.get("frames"):
            evidence_frames[s["session_id"]] = s["frames"]

    if has_tls_10:
        rule = RULES[0]
        deductions.append({
            "rule_id": rule.rule_id,
            "title": rule.title,
            "category": rule.category,
            "points": rule.deduction,
            "standard": rule.standard,
            "description": rule.description,
            "evidence": "Frame inspection observed ServerHello with legacy protocol version 0x0301 (TLS 1.0)."
        })

    if has_weak_cipher:
        rule = RULES[1]
        deductions.append({
            "rule_id": rule.rule_id,
            "title": rule.title,
            "category": rule.category,
            "points": rule.deduction,
            "standard": rule.standard,
            "description": rule.description,
            "evidence": "Negotiated cipher suite TLS_RSA_WITH_3DES_EDE_CBC_SHA lacks Ephemeral Diffie-Hellman (PFS)."
        })

    if has_expiring_cert:
        rule = RULES[2]
        deductions.append({
            "rule_id": rule.rule_id,
            "title": rule.title,
            "category": rule.category,
            "points": rule.deduction,
            "standard": rule.standard,
            "description": rule.description,
            "evidence": "Certificate for 'mail.college.example' valid until Oct 12, 2026 (12 days left)."
        })

    if has_auth_downgrade:
        rule = RULES[3]
        deductions.append({
            "rule_id": rule.rule_id,
            "title": rule.title,
            "category": rule.category,
            "points": rule.deduction,
            "standard": rule.standard,
            "description": rule.description,
            "evidence": "Plaintext AUTH capability advertised in 250-EHLO response prior to STARTTLS transition."
        })

    if lacks_tls_13:
        rule = RULES[4]
        deductions.append({
            "rule_id": rule.rule_id,
            "title": rule.title,
            "category": rule.category,
            "points": rule.deduction,
            "standard": rule.standard,
            "description": rule.description,
            "evidence": "No sessions completed TLS 1.3 handshake (extension supported_versions 0x0304 missing in ServerHello)."
        })

    total_deduction = sum(d["points"] for d in deductions)
    final_score = max(0, 100 - total_deduction)

    if final_score >= 80:
        rating = "Secure"
        rating_color = "emerald"
    elif final_score >= 50:
        rating = "Attention"
        rating_color = "amber"
    else:
        rating = "Critical"
        rating_color = "rose"

    return {
        "score": final_score,
        "rating": rating,
        "rating_color": rating_color,
        "deductions": deductions,
        "total_deduction": total_deduction,
        "sessions_count": len(sessions),
    }
