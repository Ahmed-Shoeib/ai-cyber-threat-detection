"""
Maps our three threat types to their corresponding MITRE ATT&CK technique,
plus a plain-language explanation and a recommended first response.

MITRE ATT&CK is a public knowledge base of real-world attacker behavior,
organized into Tactics (the attacker's goal) and Techniques (how that goal
is achieved). We use it here so our alerts speak the same language a real
SOC analyst would expect, instead of inventing our own labels.
"""

MITRE_MAPPING = {
    "brute_force": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "technique_explanation": (
            "The attacker is systematically guessing passwords by trying "
            "many login attempts in a short time, hoping one succeeds."
        ),
        "recommended_response": (
            "Temporarily block or rate-limit the source IP, verify whether "
            "the targeted account was compromised (check for a successful "
            "login shortly after the burst), and consider enabling account "
            "lockout or multi-factor authentication."
        ),
    },
    "port_scan": {
        "tactic": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "technique_explanation": (
            "The attacker is probing which network services/ports are open "
            "on a target system, typically to plan a follow-up attack "
            "against whatever they find exposed."
        ),
        "recommended_response": (
            "Check whether the source IP is a known/authorized scanner "
            "(e.g., internal vulnerability management tool). If not, block "
            "the IP at the firewall and review which of the scanned ports "
            "are actually open and necessary."
        ),
    },
    "sql_injection": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "technique_explanation": (
            "The attacker is testing whether a web application's input "
            "handling can be manipulated to interact with its backend "
            "database in unintended ways, potentially exposing or altering data."
        ),
        "recommended_response": (
            "Review the targeted endpoint's input validation and use of "
            "parameterized queries. Check application/database logs for "
            "signs the request actually succeeded, and consider a web "
            "application firewall (WAF) rule for this pattern."
        ),
    },
}


def get_mitre_info(detection_type: str) -> dict:
    """
    Returns the MITRE mapping dictionary for a given detection type.
    Falls back to an 'Unknown' entry if we ever see an unmapped type,
    so alert generation never crashes on an unexpected threat.
    """
    return MITRE_MAPPING.get(
        detection_type,
        {
            "tactic": "Unknown",
            "technique_id": "N/A",
            "technique_name": "Unmapped",
            "technique_explanation": "No MITRE mapping defined for this detection type.",
            "recommended_response": "Manually review this detection.",
        },
    )