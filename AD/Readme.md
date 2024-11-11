## Methodology for Active Direcctory

## Table of Contents
- [Start with Nmap Scanning](#start-with-nmap-scanning)
- [SMB Enumeration](#smb-enumeration)
- [Remote Shell Access via Ports](#remote-shell-access-via-ports)
- [LLMNR](#llmnr)
- [SMB Relay](#smb-relay)
- [IPV6 Dns takeover mitm6](#ipv6-dns-takeover-mitm6)
- [Password Spraying](#password-spraying)
- [Domain Enumeration](#domain-enumeration)
- [Pass Attacks](#pass-attacks)
- [Kerberoasting](#kerberoasting)
- [Golden Ticket](#golden-ticket)
- [Mimikatz](#mimikatz)
- [Miscellaneous (Troubleshooting and Tips)](#miscellaneous-(troubleshooting-and-tips)
- [Resources](#resources)

# Start with Nmap Scanning
<table>
  <tr>
   <th>Tool</th>
    <th style="width: 1200px;">Command</th>
    <th>Description</th>
     <th>Flags Description</th>
    <th>Example</th>
  </tr>
  <tr>
   <td>Nmap</td>
    <td><code>nmap -A -T4 &lt;IP_ADDR&gt;</code></td>
    <td>This command performs an aggressive scan with OS detection, version detection, script scanning, and traceroute.</td>
    <td>
      <ul>
        <li>-A: Enables OS detection, version detection, script scanning, and traceroute.</li>
        <li>-T4: Sets timing template to 4 for faster scan.</li>
      </ul>
    </td>
    <td><code>nmap -A -T4 10.10.11.42</code></td>
  </tr>
</table>

   Nmap has several timing templates (T0 to T5), where T0 is the slowest and stealthiest, and T5 is the fastest but most intrusive. T4 is generally considered aggressive but not as reckless as T5.

# SMB Enumeration
## 1. smbclient
**Description**:
smbclient is a command-line tool that is part of the Samba suite, used to interact with SMB/CIFS shares.

---
   <table>
  <thead>
    <tr>
      <th><strong>Tool</strong></th>
      <th><strong>Command</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>Flag Description</strong></th>
      <th><strong>Example</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>SMB Client</td>
      <td><code>smbclient -L \\\\ip\\</code></td>
      <td>Lists the available shares on the target SMB server.</td>
      <td><strong>-L:</strong> Lists the available shares on the target SMB server.<br><strong>\\\\ip\\:</strong> Replace ip with the target's IP address.</td>
      <td><code>smbclient -L \\\\192.168.1.1\\</code></td>
    </tr>
    <tr>
      <td>SMB Client</td>
      <td><code>smbclient \\\\ip\\share_name -U username</code></td>
      <td>Access a specific SMB share.</td>
      <td><strong>\\\\ip\\share_name:</strong> Replace ip with the target IP and share_name with the name of the share you want to access.<br><strong>-U username:</strong> Specifies the username. You will be prompted for the password.</td>
      <td><code>smbclient \\192.168.1.1\\Documents -U guest</code></td>
    </tr>
    <tr>
      <td>SMB Client (Interactive)</td>
      <td><code>smbclient \\ip\\SharedFolder -U username</code></td>
      <td>Starts an interactive session with the SMB share.</td>
      <td>No additional flags. After login, use typical file system commands like <code>ls</code>, <code>get</code>, <code>put</code>, etc.</td>
      <td><code>smbclient \\192.168.1.1\\SharedFolder -U username</code><br>Then: <br><code>smb: \> ls</code><br><code>smb: \> get file.txt</code></td>
    </tr>
  </tbody>
</table>

## 2. smbmap
**Description**:
smbmap is a tool that allows you to enumerate SMB shares, check permissions, and gain insight into the files and directories within those shares.

---
   <table>
  <thead>
    <tr>
      <th><strong>Tool</strong></th>
      <th><strong>Command</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>Flag Description</strong></th>
      <th><strong>Example</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>smbmap</td>
      <td><code>smbmap -H &lt;ip&gt; -u &lt;username&gt; -p &lt;password&gt;</code></td>
      <td>Basic usage to connect to a target SMB server and enumerate shares.</td>
      <td><strong>-H &lt;ip&gt;:</strong> The target host's IP address.<br><strong>-u &lt;username&gt;:</strong> The username to authenticate with.<br><strong>-p &lt;password&gt;:</strong> The password to authenticate with.</td>
      <td><code>smbmap -H 192.168.1.1 -u guest -p guest</code></td>
    </tr>
    <tr>
      <td>smbmap</td>
      <td><code>smbmap -H &lt;ip&gt; -u &lt;username&gt; -p &lt;password&gt; -R &lt;path_to_share&gt;</code></td>
      <td>Check a specific SMB share by listing its contents.</td>
      <td><strong>-R &lt;path_to_share&gt;:</strong> Specifies the path to the SMB share you want to access.</td>
      <td><code>smbmap -H 192.168.1.1 -u guest -p guest -R /Documents</code></td>
    </tr>
    <tr>
      <td>smbmap</td>
      <td><code>smbmap -H &lt;ip&gt; -u &lt;username&gt; -p &lt;password&gt;</code></td>
      <td>List all available shares and check their permissions (read/write).</td>
      <td>No additional flags. Lists shares and shows the associated permissions.</td>
      <td><code>smbmap -H 192.168.1.1 -u guest -p guest</code></td>
    </tr>
  </tbody>
</table>

## 3. enum4linux 
**Description**:
enum4linux is a powerful tool for gathering information from SMB servers. It is primarily used for enumerating users, shares, and other details related to Windows systems. It uses the SMB protocol to interact with the target.

---
 <table>
  <thead>
    <tr>
      <th><strong>Tool</strong></th>
      <th><strong>Command</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>Flag Description</strong></th>
      <th><strong>Example</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>enum4linux</td>
      <td><code>enum4linux -a &lt;IPADDR&gt;</code></td>
      <td>Performs an aggressive scan to gather information about the target, including users, shares, OS info, etc.</td>
      <td><strong>-a:</strong> Aggressive scan, retrieves as much information as possible (users, shares, etc.).<br><strong>IPADDR:</strong> Replace with the target IP address.</td>
      <td><code>enum4linux -a 192.168.1.1</code></td>
    </tr>
    <tr>
      <td>enum4linux</td>
      <td><code>enum4linux -U &lt;ip&gt;</code></td>
      <td>Retrieve a list of user accounts from the target machine.</td>
      <td><strong>-U:</strong> Enumerates users on the target SMB server.</td>
      <td><code>enum4linux -U 192.168.1.1</code></td>
    </tr>
    <tr>
      <td>enum4linux</td>
      <td><code>enum4linux -S &lt;ip&gt;</code></td>
      <td>Enumerates SMB shares available on the target machine.</td>
      <td><strong>-S:</strong> Enumerates the SMB shares on the target machine.</td>
      <td><code>enum4linux -S 192.168.1.1</code></td>
    </tr>
    <tr>
      <td>enum4linux</td>
      <td><code>enum4linux -P &lt;ip&gt;</code></td>
      <td>Checks the target machine for available passwords (if any).</td>
      <td><strong>-P:</strong> Enumerates passwords for users (if configured).</td>
      <td><code>enum4linux -P 192.168.1.1</code></td>
    </tr>
  </tbody>
</table>

## 4. Other Useful SMB Scanning Tools
**Description**:
While the above tools are some of the most commonly used for SMB scanning, there are a few more that can be helpful in Active Directory (AD) environments.

---

### nmap SMB scripts
**Description**:
Nmap has a set of SMB-related NSE (Nmap Scripting Engine) scripts that can be used to enumerate SMB shares, users, and more.

---
<table>
  <thead>
    <tr>
      <th><strong>Tool</strong></th>
      <th><strong>Command</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>Flag Description</strong></th>
      <th><strong>Example</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Nmap NSE</td>
      <td><code>nmap -p 445 --script smb-enum-shares,smb-enum-users &lt;ip&gt;</code></td>
      <td>Uses Nmap's SMB enumeration scripts to list shares and users on the target SMB server.</td>
      <td><strong>--script smb-enum-shares:</strong> Enumerates the SMB shares on the target.<br><strong>--script smb-enum-users:</strong> Enumerates the SMB users on the target.</td>
      <td><code>nmap -p 445 --script smb-enum-shares,smb-enum-users 192.168.1.1</code></td>
    </tr>
    <tr>
      <td>Nmap NSE</td>
      <td><code>nmap -p 445 --script smb-os-fingerprint &lt;ip&gt;</code></td>
      <td>Uses the SMB OS fingerprinting script to determine the operating system version of the target machine.</td>
      <td><strong>--script smb-os-fingerprint:</strong> Attempts to determine the operating system of the target via SMB.</td>
      <td><code>nmap -p 445 --script smb-os-fingerprint 192.168.1.1</code></td>
    </tr>
    <tr>
      <td>Nmap NSE</td>
      <td><code>nmap -p 445 --script smb-vuln* &lt;ip&gt;</code></td>
      <td>Run SMB vulnerability scanning scripts to identify known SMB vulnerabilities.</td>
      <td><strong>--script smb-vuln*:</strong> Runs a series of SMB vulnerability scripts.</td>
      <td><code>nmap -p 445 --script smb-vuln* 192.168.1.1</code></td>
    </tr>
     <tr>
      <td>rpcclient</td>
      <td><code>rpcclient -U &lt;username&gt;%&lt;password&gt; &lt;target-ip&gt;</code></td>
      <td>Connects to the target machine using the SMB RPC protocol and allows various enumeration commands.</td>
      <td><strong>-U &lt;username&gt;%&lt;password&gt;:</strong> Specifies username and password for authentication.<br><strong>&lt;target-ip&gt;:</strong> The IP address of the target machine.</td>
      <td><code>rpcclient -U guest%guest 192.168.1.1</code></td>
     </tr>
     <tr>
      <td>Impacket</td>
      <td><code>smbclient.py &lt;domain&gt;/&lt;username&gt;:&lt;password&gt;@&lt;target-ip&gt;</code></td>
      <td>Impacket's smbclient script to authenticate and interact with SMB shares.</td>
      <td><strong>&lt;domain&gt;/&lt;username&gt;:&lt;password&gt;@&lt;target-ip&gt;:</strong> Specifies domain, username, password, and the target IP.</td>
      <td><code>smbclient.py DOMAIN/guest:guest@192.168.1.1</code></td>
    </tr>
    <tr>
      <td>Impacket</td>
      <td><code>smbexec.py &lt;target-ip&gt; -u &lt;username&gt; -p &lt;password&gt;</code></td>
      <td>Impacket's smbexec script to execute commands on the target via SMB.</td>
      <td><strong>-u &lt;username&gt;:</strong> Username for authentication.<br><strong>-p &lt;password&gt;:</strong> Password for authentication.</td>
      <td><code>smbexec.py 192.168.1.1 -u guest -p guest</code></td>
    </tr>
     <tr>
      <td>Hydra</td>
      <td><code>hydra -l &lt;username&gt; -P &lt;password-list&gt; smb://&lt;target-ip&gt;</code></td>
      <td>Performs a password brute force attack on SMB.</td>
      <td><strong>-l &lt;username&gt;:</strong> Username for authentication.<br><strong>-P &lt;password-list&gt;:</strong> Path to the password list.<br><strong>smb://&lt;target-ip&gt;:</strong> Target IP for the SMB service.</td>
      <td><code>hydra -l guest -P /path/to/passwords.txt smb://192.168.1.1</code></td>
    </tr>
  </tbody>
</table>

# Remote Shell Access via Ports

This document provides an overview of different ports and services where you can potentially obtain remote shell access if valid credentials are available. It also includes useful tools, commands, and examples for each port.

---

## 1. Port 445 - SMB (Server Message Block)
**Description**:  
SMB is commonly used for file and printer sharing on Windows systems. However, SMB can also be an attack vector if vulnerabilities like EternalBlue or weak configurations are present. If valid credentials are obtained, remote code execution may be possible via SMB, especially using tools like **Impacket's `smbexec.py`** or **wmiexec.py**.

- **Remote Shell Access**: Yes (if SMB is vulnerable or accessible with valid credentials)
- **Creds Required**: Yes (valid credentials for SMB)

**Tools & Commands**:

<table>
  <thead>
    <tr>
      <th><strong>Tool</strong></th>
      <th><strong>Command</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>Flag Description</strong></th>
      <th><strong>Example</strong></th>
      <th><strong>Remote Shell (Y/N)</strong></th>
      <th><strong>Creds Required (Y/N)</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Impacket (`smbexec.py`)</td>
      <td><code>smbexec.py &lt;domain&gt;/&lt;username&gt;:&lt;password&gt;@&lt;ip&gt;</code></td>
      <td>Executes remote commands over SMB once authenticated.</td>
      <td><strong>&lt;domain&gt;/&lt;username&gt;:&lt;password&gt;@&lt;ip&gt;:</strong> Specify domain, username, password, and IP address.</td>
      <td><code>smbexec.py DOMAIN/guest:guest@192.168.1.1</code></td>
      <td>Yes</td>
      <td>Yes</td>
    </tr>
    <tr>
      <td>Impacket (`wmiexec.py`)</td>
      <td><code>wmiexec.py &lt;domain&gt;/&lt;username&gt;:&lt;password&gt;@&lt;ip&gt;</code></td>
      <td>Executes remote commands via WMI over SMB.</td>
      <td><strong>&lt;domain&gt;/&lt;username&gt;:&lt;password&gt;@&lt;ip&gt;:</strong> Specify domain, username, password, and IP address.</td>
      <td><code>wmiexec.py DOMAIN/guest:guest@192.168.1.1</code></td>
      <td>Yes</td>
      <td>Yes</td>
    </tr>
  </tbody>
</table>

---

## 2. Port 593 - RPC over HTTP / WinRM (Windows Remote Management)
**Description**:  
WinRM allows remote management of Windows machines via HTTP. If WinRM is enabled and properly configured, you can interact with the target system and potentially execute commands remotely. Tools like **Evil-WinRM** can be used for this purpose.

- **Remote Shell Access**: Yes (if WinRM is enabled and configured to allow remote management)
- **Creds Required**: Yes (valid credentials for WinRM)

**Tools & Commands**:

<table>
  <thead>
    <tr>
      <th><strong>Tool</strong></th>
      <th><strong>Command</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>Flag Description</strong></th>
      <th><strong>Example</strong></th>
      <th><strong>Remote Shell (Y/N)</strong></th>
      <th><strong>Creds Required (Y/N)</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Evil-WinRM</td>
      <td><code>evil-winrm -i &lt;ip&gt; -u &lt;username&gt; -p &lt;password&gt;</code></td>
      <td>Interacts with WinRM to get remote shell access.</td>
      <td><strong>-i &lt;ip&gt;:</strong> Target IP address<br><strong>-u &lt;username&gt;:</strong> Username<br><strong>-p &lt;password&gt;:</strong> Password</td>
      <td><code>evil-winrm -i 192.168.1.1 -u guest -p guest</code></td>
      <td>Yes</td>
      <td>Yes</td>
    </tr>
  </tbody>
</table>

---

## 3. Port 3389 - RDP (Remote Desktop Protocol)
**Description**:  
RDP is used for remote desktop access to Windows systems. If RDP is enabled, it can offer full remote shell access to the system once the credentials are known. Tools like **xrdp** or **RDP brute-forcing tools** can be used for attack.

- **Remote Shell Access**: Yes (if RDP is open and accessible)
- **Creds Required**: Yes (valid credentials for RDP)

**Tools & Commands**:

<table>
  <thead>
    <tr>
      <th><strong>Tool</strong></th>
      <th><strong>Command</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>Flag Description</strong></th>
      <th><strong>Example</strong></th>
      <th><strong>Remote Shell (Y/N)</strong></th>
      <th><strong>Creds Required (Y/N)</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>RDP</td>
      <td><code>rdesktop &lt;ip&gt;</code></td>
      <td>Connects to a remote Windows machine using RDP.</td>
      <td><strong>&lt;ip&gt;:</strong> Target IP address of the RDP server.</td>
      <td><code>rdesktop 192.168.1.1</code></td>
      <td>Yes</td>
      <td>Yes</td>
    </tr>
  </tbody>
</table>

---

## 4. Port 22 - SSH (Secure Shell)
**Description**:  
SSH is a widely used protocol for secure remote access to Unix/Linux systems. If SSH is open and the correct credentials are available, a remote shell can be obtained. SSH is a typical target for brute-forcing attacks.

- **Remote Shell Access**: Yes (if SSH is open and credentials are available)
- **Creds Required**: Yes (valid credentials for SSH)

**Tools & Commands**:

<table>
  <thead>
    <tr>
      <th><strong>Tool</strong></th>
      <th><strong>Command</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>Flag Description</strong></th>
      <th><strong>Example</strong></th>
      <th><strong>Remote Shell (Y/N)</strong></th>
      <th><strong>Creds Required (Y/N)</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>SSH</td>
      <td><code>ssh &lt;username&gt;@&lt;ip&gt;</code></td>
      <td>Connects to a remote Unix/Linux machine via SSH.</td>
      <td><strong>&lt;username&gt;:</strong> Username for SSH login<br><strong>&lt;ip&gt;:</strong> Target machine IP</td>
      <td><code>ssh user@192.168.1.1</code></td>
      <td>Yes</td>
      <td>Yes</td>
    </tr>
  </tbody>
</table>

---

## 5. Port 23 - Telnet
**Description**:  
Telnet is an old and insecure protocol used to provide remote access to systems. While it is considered insecure and rarely enabled by default, some systems might still have Telnet open. Credentials would be required to access the remote shell.

- **Remote Shell Access**: Yes (if Telnet is open and accessible)
- **Creds Required**: Yes (valid credentials for Telnet)

**Tools & Commands**:

<table>
  <thead>
    <tr>
      <th><strong>Tool</strong></th>
      <th><strong>Command</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>Flag Description</strong></th>
      <th><strong>Example</strong></th>
      <th><strong>Remote Shell (Y/N)</strong></th>
      <th><strong>Creds Required (Y/N)</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Telnet</td>
      <td><code>telnet &lt;ip&gt;</code></td>
      <td>Connects to a remote system via Telnet (insecure).</td>
      <td><strong>&lt;ip&gt;:</strong> Target IP address</td>
      <td><code>telnet 192.168.1.1</code></td>
      <td>Yes</td>
      <td>Yes</td>
    </tr>
  </tbody>
</table>

---
Be aware that security configurations and protections (like firewalls and strong access control lists) may prevent remote shell access even if the ports are open. Always ensure you have proper authorization before attempting any remote access.


## LLMNR

## SMB Relay

## IPV6 Dns takeover mitm6

## Password Spraying 

## Domain Enumeration

## Pass Attacks

## Kerberoasting 

# Golden Ticket

## Mimikatz


## Miscellaneous (Troubleshooting and Tips)

### 1. How to Add an IP to `/etc/hosts` Easily?

To add an IP address and hostname to your `/etc/hosts` file quickly, use the following command:

```bash
echo "10.10.10.100 active.htb" | sudo tee -a /etc/hosts > /dev/null
```
Explanation:
* echo "10.10.10.100 active.htb": The IP address and hostname you want to add.
* | sudo tee -a /etc/hosts: tee appends (-a) the output to the /etc/hosts file with elevated privileges.
* &gt; /dev/null: Redirects the output to /dev/null so nothing is displayed in the terminal.
* This ensures that the new entry is added without overwriting any existing data in /etc/hosts.

### 2. How to Link Applications So They Can Be Run from Anywhere in Kali Linux?

To link applications so they can be executed from any terminal session in Kali Linux, you need to add their directory to your system’s $PATH environment variable. Here’s how:

1. Find the Directory: First, locate the directory containing the application. For example, if the application is in /opt/some-app/, you’ll add this path to your $PATH.

2. Edit .bashrc or .zshrc: Open the .bashrc (for Bash shell) or .zshrc (for Zsh shell) in your home directory:

```bash
nano ~/.bashrc
```
3. Add the Directory to $PATH: Add this line at the end of the file:

```bash
export PATH=$PATH:/opt/some-app/
```
4. Apply the Changes: To apply the changes without restarting your terminal, run:
```bash
source ~/.bashrc
```
Now, you should be able to run the application from anywhere in your terminal.

### 3. Why Are My Commands Not Showing Up Automatically in New Terminal Windows?
By default, commands executed in one terminal window won’t show up in another window until the session ends and the history file (~/.bash_history) is updated. To ensure commands are shared across multiple terminal windows:

1. Modify .bashrc to Enable Immediate History Sync: Open your ~/.bashrc file:

```bash
nano ~/.bashrc
```
2. Add the Following Lines to Sync History Across Sessions:
```bash
export HISTCONTROL=ignoredups  # Ignore duplicate commands in history
export HISTSIZE=1000           # Set history size
export HISTFILESIZE=2000       # Set the maximum size of the history file
shopt -s histappend            # Append to history file, don't overwrite
PROMPT_COMMAND="history -a; history -n"  # Append history after each command and re-read history
```
3. Apply Changes: After modifying .bashrc, apply the changes by running:
```bash
source ~/.bashrc
```
Now, commands typed in one terminal session will be immediately available in others.

# Resources
* https://www.hackingarticles.in/a-detailed-guide-on-kerbrute/
* https://www.hackingarticles.in/a-detailed-guide-on-evil-winrm/
* https://unix.stackexchange.com/questions/3809/how-can-i-make-a-program-executable-from-everywhere
* https://www.hackingarticles.in/msfvenom-cheatsheet-windows-exploitation/
* https://www.hackingarticles.in/metasploit-for-pentester-mimikatz/
* https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/organizing-information-with-tables
* https://stackoverflow.com/questions/19950648/how-to-write-lists-inside-a-markdown-table
* https://github.com/NoorQureshi/kali-linux-cheatsheet/blob/master/README.md#nmap-commands
* https://github.com/irgoncalves/smbclient_cheatsheet
* https://github.com/Kitsun3Sec/Pentest-Cheat-Sheets/tree/master
* https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet





