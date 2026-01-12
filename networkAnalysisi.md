# Network Security Analysis and Incident Response Report

**Project Title:** Network Security Analysis and Incident Response Evaluation

**Analyst Names:**

- Adejuwonlo Adeola Okanlawon
- Paseda Temiloluwa Iyanuoluwa
- Adu Opemiposi Stephen
- John Alakuko
- Yohanna Paul Sheawaza
- Ogunsola Feyisola Abraham

**Date of Submission:** October 25, 2025

**Confidentiality Notice:**  
This document is classified as **Internal/Confidential** and is intended solely for the management and technical teams of the client organization. Unauthorized distribution is prohibited.

---

## 2. Executive Summary

This report details the findings from an investigation into a sophisticated, multi-vector attack identified through packet capture (pcap) analysis. The analysis confirmed a **Critical-severity** security posture issue due to the discovery of three major concurrent threats:

1. Successful credential compromise via brute-force attacks against the insecure File Transfer Protocol (FTP).
2. Internal lateral movement shown by stealth scanning and command-and-control (C2) communication between internal hosts.
3. Multiple attacking sources originating from several internal IP addresses, suggesting a widespread compromise or an organized internal threat.

The most critical finding is the pervasive use of an insecure, legacy protocol (FTP) that allows credential exposure. Immediate decommissioning of FTP services and migration to secure alternatives (SFTP/FTPS), combined with mandatory Multi-Factor Authentication (MFA), is strongly recommended.

---

## 3. Introduction

This project was initiated to assess the network security posture and evaluate incident handling capabilities through detailed analysis of network packet captures. The goal was to identify and analyze malicious or suspicious network traffic indicating active threats.

**Tools Used:**

- Wireshark for deep packet inspection

**Frameworks Applied:**

- CyBOK Incident Response Model
- SANS Incident Handler’s Handbook (aligned with NIST SP 800-61)

**Analysis Duration:**

- PCAPs analyzed on October 15, 2025

---

## 4. Objectives and Scope

### Objectives

1. Detect and analyze malicious or suspicious network activities.
2. Assess the immediate impact and severity of identified threats.
3. Evaluate the effectiveness of the CyBOK Incident Response Model.
4. Provide actionable mitigation and remediation recommendations.

### Scope

- Analysis limited strictly to provided PCAP files.
- Internal IP range observed: `192.168.56.0/24`.

**Out of Scope:**

- Host-based logs
- Endpoint Detection and Response (EDR) data
- Firewall logs beyond PCAP content

---

## 5. Methodology

The analysis followed a structured approach:

- **Data Collection:** PCAP files as the sole data source.
- **Tools & Techniques:** Wireshark with filters such as:
  - `ftp.request.command == "PASS"`
  - `tcp.flags.syn == 1 && tcp.flags.ack == 0`
- **Analytical Frameworks Applied:**
  - **CyBOK Incident Response Model** for lifecycle analysis
  - **SANS IR Framework** for practical SOC comparison
- **Indicators Checked:**
  - High connection frequency
  - Clear-text credential exposure
  - Brute-force login failures
  - Unauthorized reconnaissance
- **Validation:** Manual inspection of decoded protocol data in Wireshark.

---

## 6. Findings and Analysis

The analysis revealed multiple security incidents across two captures, indicating a significant internal compromise.

| Capture | Threat Type              | Attacker IP    | Target IP      | Packet Range | Description                                                 | Severity |
| ------- | ------------------------ | -------------- | -------------- | ------------ | ----------------------------------------------------------- | -------- |
| 1       | Brute Force Attack       | 192.168.56.102 | 192.168.56.101 | 135–81189    | Repeated FTP login attempts exposing clear-text credentials | High     |
| 2       | Stealth Scanning         | 192.168.56.102 | 192.168.56.101 | 1–56473      | Systematic port probing indicating reconnaissance           | Medium   |
| 2       | Control Communication    | 192.168.56.102 | 192.168.56.101 | 15–2202      | Patterned packets suggesting C2 activity                    | High     |
| 2       | Repeated FTP Brute Force | 192.168.56.101 | 192.168.56.102 | 15–14209     | Bi-directional brute-force activity                         | High     |
| 2       | Brute Force (New Host)   | 192.168.56.1   | 192.168.56.101 | 102–14131    | Additional brute-force attempt                              | High     |
| 2       | Suspicious Logins        | 192.168.56.102 | 192.168.56.101 | 14140–14205  | Possible successful login after brute force                 | High     |

### Interpretation and Impact

1. **Critical FTP Vulnerability:** FTP credential compromise enabled unauthorized access.
2. **Confirmed Lateral Movement:** Stealth scanning and C2 traffic confirm attacker foothold.
3. **Overall Severity:** Elevated to **Critical** due to credential theft and internal spread.

---

## 7. Incident Response Evaluation

### 7.1 CyBOK Incident Response Model Analysis

| Phase                               | Benefit                         | SOC Action                                         |
| ----------------------------------- | ------------------------------- | -------------------------------------------------- |
| Preparation                         | Secure tooling and policies     | FTP replacement would have prevented attack        |
| Detection & Analysis                | Threat validation and scoping   | Pivot to additional logs and malware analysis      |
| Containment, Eradication & Recovery | Stop threat and restore systems | Isolate hosts, revoke credentials, rebuild systems |
| Post-Incident Activity              | Long-term improvement           | Document failures and enforce MFA & segmentation   |

---

### 7.2 SANS Model Comparison

- **Similarities:** Both cover the full incident lifecycle.
- **Differences:**
  - SANS focuses on tactical execution.
  - CyBOK emphasizes strategic and knowledge-based improvement.
- **Best Practice:** Use SANS for operations and CyBOK for governance and policy.

---

## 8. Mitigation and Recommendations

| Recommendation            | Type                | Description                             |
| ------------------------- | ------------------- | --------------------------------------- |
| Decommission FTP          | Critical Technical  | Replace with SFTP or FTPS               |
| Enforce MFA               | Critical Policy     | Prevent password-only compromise        |
| Isolate Compromised Hosts | Immediate Technical | Disconnect and rebuild infected systems |
| Deploy IPS                | Long-term Technical | Automated detection and blocking        |
| Improve Segmentation      | Long-term Technical | Limit lateral movement via VLANs        |

---

## 9. Lessons Learned / Post-Incident Review

- **Detection Latency:** Monitoring failed to alert on brute-force patterns.
- **Protocol Governance Gap:** FTP usage was the primary failure.
- **Poor Segmentation:** Enabled unrestricted internal movement.

---

## 10. Conclusion

The analysis confirms a **Critical-severity compromise** involving credential theft and internal reconnaissance. The root cause is the reliance on insecure FTP. Implementing the recommended mitigations, particularly FTP removal and MFA enforcement, will significantly improve the organization’s security posture and transition it from reactive to proactive defense.

---

## 11. Appendices

- Raw PCAP Analysis Screenshots (C1, C2, C3, C21, C22, C23, C24, C25)

---

## 12. References

- CyBOK v1.1 – Incident Response Chapter
- SANS Institute Incident Handler’s Handbook
- NIST SP 800-61r2 – Computer Security Incident Handling Guide
- Wireshark Documentation
