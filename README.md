# Verenox Security Lab — Active Directory, Detection & Cloud IAM

A self-directed security lab, **built in an isolated lab environment**, that stands up a small Windows Active Directory domain, generates and investigates real security telemetry, analyzes malicious network traffic, and exploits — then detects and remediates — an AWS IAM privilege-escalation path.

Fictional company: **Verenox Aerospace Supply**. All users, passwords, and data are synthetic.

---

## Architecture

```
            verenox.lab domain  (isolated VirtualBox NAT network)
   +------------------------+        +---------------------------+
   |  VRX-DC01 (DC)         |<------>|  win-endpoint (client)    |
   |  Windows Server 2025   |  joins |  Windows 11 LTSC          |
   |  AD DS · DNS · KDC      |        |  domain-joined, GPOs apply|
   |  192.168.100.10        |        |  192.168.100.30           |
   +------------------------+        +---------------------------+
```

See `01-diagram/` for the full diagram.

---

## What I built

### Active Directory & auditing
- Promoted **VRX-DC01** to a domain controller for `verenox.lab`; configured DNS and verified health with `dcdiag`.
- Joined **win-endpoint** to the domain and built an OU structure (Users/dept, Workstations, Admins, ServiceAccounts).
- Created **10 users and groups** with PowerShell.
- Authored **two GPOs**: a password/lockout policy and an **Advanced Audit Policy** (with command-line process auditing) so events **4624 / 4625 / 4688 / 4672** are logged.
- Generated failed and successful logons and **correlated one failed domain logon across two hosts**: event **4625** on the client (Logon Type 2) and event **4771** on the DC (Kerberos pre-auth failure, status `0x18`) from the same source IP.

### PowerShell security scripting
Three scripts (`03-scripts/`), each exporting CSV evidence:
- `Get-FailedLogons.ps1` — failed logons (event 4625) by user and logon type, reading fields by name via XML.
- `Get-LocalAdmins.ps1` — local Administrators membership, showing `Domain Admins` nested into the local group.
- `Get-RunningServices.ps1` — running services with their account and executable path; flags services in unusual locations.

### Network traffic analysis
- Captured and read my own DNS / HTTP / TLS traffic (`04-pcap/`).
- Analyzed a malicious PCAP and determined from packets alone that it was **a web server under an automated scan**, not an infected host: 622 HTTP requests (615 × 404), a webshell-hunting wordlist, two failed RCE attempts (ThinkCMF, command injection), and refused connections to TCP 8080/8983. Proved the attacks failed by searching for the expected MD5 marker strings. Write-up and MITRE ATT&CK mapping in `04-pcap/web-attack-analysis.md`.

### AWS IAM security
- Deployed an intentionally vulnerable IAM environment (265 resources) with **Terraform** into a dedicated throwaway account.
- Exploited the **`iam:CreatePolicyVersion`** self-escalation path: a role whose only permission was `CreatePolicyVersion` on `Resource: *`, scoped to a policy attached to itself. Rewrote that policy's default version to `*:*` and confirmed administrator access.
- Documented the **CloudTrail detection** (`CreatePolicyVersion` with `setAsDefault:true` whose new document grants `*`) and the **least-privilege fix** (scope the resource, apply a permission boundary). See `05-iam-terraform/iam-notes.md`.
- Practiced the full Terraform lifecycle and an **encrypted S3 remote-state backend with locking**.

---

## Repo layout

```
.
├── README.md
├── 01-diagram/            architecture diagram
├── 02-ad-setup/           OU/user screenshots, GPO export, event correlation (4625 + 4771)
├── 03-scripts/            3 PowerShell scripts
│   └── output/            their CSV output
├── 04-pcap/               own-traffic capture, malware PCAP write-up + screenshots
├── 05-iam-terraform/      iam-notes.md (privesc path, detection, fix)
├── 06-terraform/          main.tf, remote-state + plan screenshots
└── evidence/              supporting screenshots
```

---

## Skills shown

Active Directory · Group Policy · Windows audit policy & event logs (4624/4625/4688/4672/4771) · PowerShell · Kerberos · Wireshark / packet analysis · MITRE ATT&CK mapping · AWS IAM · IAM privilege escalation · CloudTrail-based detection · least privilege · Terraform / infrastructure-as-code

---

## Honest limitations

- All work is in an isolated lab; findings and data are synthetic.
- The IAM work was performed in a dedicated throwaway AWS account and fully torn down afterward.
