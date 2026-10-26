"""Explainable rule scoring; scores are not probabilities."""
from __future__ import annotations

THRESHOLDS = {"caution": 25, "high": 55}


def evaluate_rules(features: dict) -> dict:
    findings = []
    def add(rule_id, title, explanation, severity, evidence, points):
        findings.append({"rule_id": rule_id, "title": title, "explanation": explanation,
                         "severity": severity, "evidence": str(evidence), "points": points})

    if features.get("is_ip_address"):
        add("URL001", "IP address used as host", "An IP address is used instead of a domain name. This can be legitimate, but deserves extra scrutiny.", "high", features.get("hostname"), 30)
    if features.get("has_url_credentials") or features.get("contains_at_symbol"):
        add("URL002", "Credential or @-symbol confusion", "Credentials or an @ symbol can make the true destination harder to recognize.", "high", "@ symbol or user-info present", 25)
    if features.get("is_known_shortener"):
        add("URL003", "URL shortener detected", "A shortened URL hides the final destination until expanded. Shorteners are also used legitimately.", "medium", features.get("hostname"), 12)
    if features.get("url_length", 0) >= 120:
        add("URL004", "Long URL", "The URL is unusually long and may be harder to inspect manually; length alone is not proof of phishing.", "low", f"{features['url_length']} characters", 8)
    if features.get("hostname_length", 0) >= 50 or features.get("subdomain_count_approx", 0) >= 4:
        add("URL005", "Complex hostname", "The hostname has many characters or subdomain labels, which can obscure the destination.", "medium", features.get("hostname"), 15)
    if features.get("hostname_hyphen_count", 0) >= 3:
        add("URL006", "Many hostname hyphens", "Multiple hyphens in a hostname can be used in deceptive-looking domains, though they also occur on legitimate sites.", "low", f"{features['hostname_hyphen_count']} hyphens", 8)
    if features.get("hostname_digit_count", 0) >= 5 and not features.get("is_ip_address"):
        add("URL007", "Many digits in hostname", "The hostname contains many digits, which may warrant checking the domain carefully.", "low", f"{features['hostname_digit_count']} digits", 8)
    if features.get("has_suspicious_encoding"):
        add("URL008", "Potentially evasive URL encoding", "The URL includes selected encoded control or delimiter characters that can make inspection harder.", "medium", "encoded character pattern found", 12)
    if features.get("has_misleading_hostname_pattern"):
        add("URL009", "Security-themed hostname wording", "Words such as login, verify, or secure appear in the hostname. This is only a weak signal and can be legitimate.", "low", features.get("hostname"), 6)
    if features.get("uses_uncommon_tld"):
        add("URL010", "Uncommon top-level domain", "The hostname uses a TLD on this application's small review list. TLD choice alone does not establish maliciousness.", "low", features.get("tld"), 5)
    if not features.get("uses_https"):
        add("URL011", "HTTPS not used", "The URL uses HTTP rather than HTTPS, so transport encryption is not indicated. HTTPS alone would not prove legitimacy.", "low", "scheme=http", 5)

    score = min(100, sum(x["points"] for x in findings))
    if features.get("url_length", 0) < 8 or not features.get("hostname"):
        category = "INSUFFICIENT EVIDENCE"
        explanation = "There is not enough URL structure to produce a useful assessment."
    elif score >= THRESHOLDS["high"]:
        category = "HIGH RISK"
        explanation = "Several structural warning signs were observed. Avoid entering credentials or sensitive information unless independently verified."
    elif score >= THRESHOLDS["caution"]:
        category = "CAUTION"
        explanation = "Some structural warning signs were observed. Verify the domain through a trusted route before interacting."
    else:
        category = "LOW OBSERVED RISK"
        explanation = "Few configured structural warning signs were observed. This does not mean the URL is safe or free of phishing."
    return {"findings": findings, "rule_score": score, "risk_category": category, "explanation": explanation,
            "thresholds": dict(THRESHOLDS)}