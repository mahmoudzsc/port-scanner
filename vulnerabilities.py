# vulnerabilities.py

# High-risk ports with explanations
HIGH_RISK_PORTS = {
    21: "High (FTP - insecure file transfer)",
    22: "Medium (SSH - brute-force or outdated versions)",
    23: "High (Telnet - unencrypted remote login)",
    25: "Medium (SMTP - open relay, spam abuse)",
    80: "Medium (HTTP - outdated web servers)",
    110: "Medium (POP3 - insecure mail access)",
    139: "High (NetBIOS - potential remote code execution)",
    143: "Medium (IMAP - mail access vulnerabilities)",
    445: "High (SMB - WannaCry, EternalBlue exploits)",
    3306: "High (MySQL - SQL injection, weak auth)",
    3389: "High (RDP - remote desktop exploits)"
}

# Optional: basic static vulnerability database used in analyzer.py
VULN_DB = {
    "apache/2.4.49": "CVE-2021-41773 - Path traversal and remote code execution",
    "nginx/1.18.0": "CVE-2021-23017 - 1-byte memory overwrite in resolver",
    "openssh/7.2": "CVE-2016-0777 - Information disclosure via roaming feature",
    "mysql/5.7": "CVE-2016-6662 - Remote root code execution",
    "vsftpd/2.3.4": "Backdoor vulnerability - known malicious version"
}
