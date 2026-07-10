# Cybersecurity_Risk_Analysis

## Project Overview
This project analyzes network and user activity logs to identify cybersecurity threats, monitor data exfiltration risk, assess authentication/encryption practices, and track threat trends over time. It combines network traffic data, threat classification data, and user behavior data to surface security gaps and support ongoing monitoring.

## Dataset Description
Three tables make up the core dataset:
- **network_logs**: Raw network traffic data — source/destination IP and port, protocol, timestamp, traffic type, data volume, packet size, HTTP status code, firewall rule, VPN status, MFA status, credential used, data classification, and encryption algorithm.
- **network_logs_2**: Threat and incident data linked to network logs — threat type, connection status, severity level, flagged status, device type, application, asset classification, session ID, TTL, user behavior score, incident category, cloud service info, and indicator-of-compromise (IoC) flag.
- **user_activity**: User behavior data — activity count, suspicious activity flag, last activity timestamp, browser, number of downloads, and emails sent.

Data cleaning steps checked for duplicates across key fields, identified and filled missing `Encryption_Algorithm` values as 'Unknown', and added derived categorical columns (`Traffic_Category`, `Severity_Category`) for easier analysis.

## Key Findings
- **Risk levels were quantified across the network**: threats were bucketed into Low/Medium/High risk categories, with counts calculated for each to show the overall risk distribution.
- **Device and traffic patterns were profiled**: most frequently used login devices and the traffic type carrying the most data volume were both identified, useful for understanding where monitoring should focus.
- **Repeated failed authentication attempts were isolated by source IP**, along with the VPN status, firewall rules, and data classification involved — a direct way to spot potential brute-force or credential-stuffing activity.
- **Data exfiltration risk was cross-checked against data sensitivity**: the analysis specifically flags cases where "Confidential" or "Highly Confidential" data intersects with a data exfiltration flag — the highest-priority alert category in the dataset.
- **Threats were correlated with user behavior scores**, helping identify whether unusual account activity coincides with specific threat types.
- **MFA and VPN status were checked specifically for High/Critical severity threats**, showing whether the most dangerous incidents are occurring on properly secured connections or not.
- **Encryption algorithm usage was audited for sensitive data**, surfacing whether confidential data is consistently protected with strong encryption or left inconsistently secured.
- **Trends over time were tracked** for severity levels, and for critical/high-severity events by month and by protocol, showing whether risk is increasing, decreasing, or concentrated in specific protocols.

## Recommendation / Tool
Three reusable stored procedures were built to operationalize ongoing monitoring:

1. **`fetch_critical_high_trends()`** — Returns monthly counts of High/Critical severity threats broken down by protocol, so security teams can track whether risk is rising for specific protocols over time.
2. **`fetch_high_critical_MFA_VPN()`** — Returns MFA and VPN status for every High/Critical severity event, making it easy to spot whether serious threats are slipping through despite (or due to the absence of) these safeguards.
3. **`fetch_encryption_frequency()`** — Returns how often each encryption algorithm is used specifically for Confidential data, helping confirm whether sensitive data protection standards are being followed consistently.

These procedures can be called on a recurring basis (daily/weekly/monthly) to give security teams an up-to-date view without re-running manual queries each time.

## Real Business Impact
- **Speeds up incident triage**: Instead of manually cross-referencing network logs and threat data, security analysts get pre-built queries that immediately surface the highest-priority cases — like confidential data exfiltration or high-severity threats with weak MFA/VPN protection.
- **Turns encryption and MFA compliance into a measurable, trackable metric** rather than an assumption — if sensitive data is found using weak or no encryption, that's a concrete, fixable gap rather than a guess.
- **Enables proactive rather than reactive security posture**: tracking severity trends by month and protocol means the business can catch a rising threat pattern early, before it escalates into a major breach.
- **Prioritizes limited security resources**: by isolating repeated failed login attempts by source IP and correlating threats with abnormal user behavior scores, teams can focus investigation effort on the accounts and sources most likely to represent real threats — not spread thin across all activity.
- **Supports audit and compliance needs**: the encryption frequency and data classification queries provide a ready-made evidence trail showing how sensitive data is being protected, which is directly useful for security audits or regulatory reporting.

## Tools & Technology
- SQL (mix of PostgreSQL syntax e.g. `to_char`, `DATE_TRUNC`, and MySQL syntax e.g. `DELIMITER`, `GROUP_CONCAT`, `DATE_FORMAT`)
- Joins across three related tables to combine network, threat, and user behavior context
- Stored procedures for repeatable threat and compliance monitoring

## Notes
- The script mixes PostgreSQL-specific functions (`to_char`, `DATE_TRUNC`) with MySQL-specific syntax (`DELIMITER`, `GROUP_CONCAT`, `SERIAL PRIMARY KEY`, `DATE_FORMAT`) — this won't run as-is on either engine without picking one and adjusting the other half. Worth standardizing on a single database engine before sharing.
- Line 215 (`ork_logs`) appears to be a typo/leftover fragment from `network_logs` — the query above it also references `network_logs` on line 214, so this looks like an accidental duplicate line that should be removed.
