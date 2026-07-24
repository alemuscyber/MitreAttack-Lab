# MITRE ATT&CK Technique Simulation & Detection Engineering
This lab simulates real attacker behavior on an isolated Azure VM using Atomic Red Team, then build working detections for each teachnique in Microsoft Sentinel -- from raw KQL queries through to live, automated *Analytics Rules* that generate real incidents.

The Mitre Att&ck techniques covered are the following:
| Technique |           Tactic          |                          Detection Logic                              |
|:---------:|:-------------------------:|:---------------------------------------------------------------------:|
| T1110.001 |   Brute Force P.W Guess   |             5+ failed logons from one account in 5 min                |
|   T1018   |  Remote System Discovery  |  2+ distinct recon commands (net/ping/arp) from one account in 5 min  |
| T1059.001 |  Powershell Command Exec  |              PowerShell script block execution events                 | 
