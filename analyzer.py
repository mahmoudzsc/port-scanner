# analyzer.py

from vulnerabilities import VULN_DB, HIGH_RISK_PORTS

def analyze_results(results):
    risk_summary = {
        "total_hosts": 0,
        "total_open_ports": 0,
        "high_risk_ports": [],
        "detected_vulnerabilities": 0,
        "notes": [],
        "recommendations": []
    }

    seen_hosts = set()
    current_host = None

    # First pass: collect all unique hosts, skipping None entries
    for entry in [r for r in results if r is not None]:
        if isinstance(entry, dict) and "host" in entry:
            current_host = entry["host"]
            seen_hosts.add(current_host)

    risk_summary["total_hosts"] = len(seen_hosts) if seen_hosts else 1  # Default to 1 for single-target scans

    # Second pass: analyze ports and vulnerabilities, skipping None entries
    for entry in [r for r in results if r is not None]:
        if isinstance(entry, dict):
            # Use current_host for entries without host (e.g., port results)
            if "host" in entry:
                current_host = entry["host"]

            # Analyze ports with "open" or "open|filtered" state
            if entry.get("state") in ("open", "open|filtered"):
                risk_summary["total_open_ports"] += 1
                if "risk" in entry and entry["risk"]:
                    risk_summary["high_risk_ports"].append(f"Port {entry['port']}: {entry['risk']}")
                if "banner" in entry and entry["banner"]:
                    banner = entry["banner"].lower()
                    for sig in VULN_DB:
                        if sig in banner:
                            risk_summary["detected_vulnerabilities"] += 1
                            risk_summary["notes"].append(
                                f"{current_host}:{entry['port']} matches {sig} -> {VULN_DB[sig]}"
                            )

    # Add recommendations based on findings
    if risk_summary["high_risk_ports"]:
        risk_summary["recommendations"] = ["Restrict access to high-risk ports.", "Update services to latest versions."]
    else:
        risk_summary["recommendations"] = ["No high-risk ports detected. Maintain current security practices."]

    return risk_summary