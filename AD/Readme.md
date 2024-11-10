## Methodology for Active Direcctory

# Start with Scanning
* Tools : Nmap
* Command :  nmap -A -T4 IP_ADDR
* Example : nmap -A -T4 10.10.11.42
* Flags:
    1. -A: This is an "aggressive" scan option. It enables several advanced features in Nmap:
        * OS Detection: Nmap attempts to determine the operating system of the target.
        * Version Detection: It checks the versions of the services running on open ports.
        * Script Scanning: Nmap runs a set of default scripts that can help identify potential vulnerabilities and other information about the target.
        * Traceroute: It attempts to map out the network path to the target.
    2. -T4: This flag sets the timing template to "4", which speeds up the scan but can be more detectable by intrusion detection systems (IDS) or firewalls. It strikes a balance between speed and stealth.

   Nmap has several timing templates (T0 to T5), where T0 is the slowest and stealthiest, and T5 is the fastest but most intrusive. T4 is generally considered aggressive but not as reckless as T5.

# SMB scanning
* Tools : smbclient, smbmap, enum4linux,..
1. smbclient: smbclient is a command-line tool that is part of the Samba suite, used to interact with SMB/CIFS shares.
   1. List shares on a target SMB server:
       * Command : smbclient -L \\\\ip\\
       * -L: Lists the available shares on the target SMB server.
       * \\ip\\: Replace ip with the target's IP address.
       * Example: smbclient -L \\\\192.168.1.1\\
       * This command will list the shared folders on the target machine at IP 192.168.1.1.
   2. Access a specific SMB share:
       * Command : smbclient \\\\ip\\share_name -U username
       * \\ip\\share_name: Replace ip with the target IP and share_name with the name of the share you want to access.
       * -U username: Use this to specify a username. You will be prompted for the password.
       * Example: smbclient \\\\192.168.1.1\\Documents -U guest
       * This will attempt to connect to the Documents share on 192.168.1.1 using the guest user.
   3. Interactive session: Once logged in, you can interact with the share and use typical file system commands like ls, get, put, cd, etc.
       * Example: smbclient \\\\192.168.1.1\\SharedFolder -U username
       * Then, once you're logged in:
            * smb: \> ls
            * smb: \> get file.txt
2. smbmap
smbmap is a tool that allows you to enumerate SMB shares, check permissions, and gain insight into the files and directories within those shares.

Basic usage:


smbmap -H <ip> -u <username> -p <password>
-H <ip>: The target host's IP address.
-u <username>: The username to authenticate with.
-p <password>: The password to authenticate with.
Example:


smbmap -H 192.168.1.1 -u guest -p guest
List shares and check permissions:


smbmap -H <ip> -u <username> -p <password>
This command will list all available shares on the target and show the read/write permissions for each share.

Check a specific share:
smbmap -H <ip> -u <username> -p <password> -R /path/to/share
This will list the contents of a specific folder in the SMB share.

3. enum4linux
enum4linux is a powerful tool for gathering information from SMB servers. It is primarily used for enumerating users, shares, and other details related to Windows systems. It uses the SMB protocol to interact with the target.

Basic usage:


enum4linux -a <ip>
-a: This flag performs an aggressive scan, retrieving as much information as possible, including users, shares, and other AD-related data.
<ip>: Replace with the target IP address.
Example:


enum4linux -a 192.168.1.1
This command will attempt to gather information such as:

User accounts and groups
SMB shares
Operating system information
Domain information
Get information about users:


enum4linux -U <ip>
This retrieves a list of user accounts from the target machine.
Enumerate shares:

enum4linux -S <ip>
This command enumerates SMB shares available on the target.
4. Other Useful SMB Scanning Tools
While the above tools are some of the most commonly used for SMB scanning, there are a few more that can be helpful in Active Directory (AD) environments:

nmap SMB scripts: Nmap has a set of SMB-related NSE (Nmap Scripting Engine) scripts that can be used to enumerate SMB shares, users, and more.

Example:


nmap -p 445 --script smb-enum-shares,smb-enum-users <ip>
smb-enum-shares: Enumerates SMB shares.
smb-enum-users: Enumerates SMB users.
Impacket: A collection of Python classes for working with network protocols. The smbclient.py and smbexec.py scripts are useful for SMB enumeration and exploitation.

Example:


smbclient.py <domain>/<username>:<password>@<target-ip>

# Remote shell

Potential Remote Shell Access
From the ports listed, Port 445 (SMB) and Port 593 (RPC over HTTP/WinRM) are the most likely candidates for obtaining a remote shell, given you have valid credentials.

Port 445 (SMB):
SMB is a frequent attack vector in CTFs and penetration testing. If SMB is vulnerable (e.g., due to an unpatched vulnerability like EternalBlue), you could gain remote code execution. Alternatively, tools like Impacket's wmiexec.py or smbexec.py can be used to run commands remotely over SMB.

Port 593 (WinRM):
If WinRM is enabled, it allows for remote management of Windows systems, and you can interact with it using tools like Evil-WinRM. If you have the correct credentials (even if they are low-privilege), you may be able to open a remote shell using WinRM.

Further Steps
WinRM: Try using Evil-WinRM if you have valid credentials.


evil-winrm -i <ip> -u <username> -p <password>
SMB: If SMB is accessible and you're able to authenticate, you can try tools like Impacket's smbexec.py to execute commands remotely.


smbexec.py <domain>/<username>:<password>@<ip>
If these services (especially SMB and WinRM) are configured securely, getting a remote shell may be more difficult, but you can still gather useful information through enumeration, misconfigurations, or by escalating privileges once you've accessed a low-privileged account.

Summary
Ports 445 (SMB) and 593 (WinRM) are the most likely to provide a remote shell.
Port 135 (RPC) can potentially be leveraged for remote code execution if a vulnerable service is running.
The other ports (53, 88, 389, 636, 3268, 3269) are primarily for enumeration and information gathering, but they do not directly provide a way to get a remote shell.


# LLMNR

# SMB Relay

# IPV6/mitmm6

# Password Spraying 

# Domain Enumeration

# Pass Attacks

# Kerberoasting 

# Golden Ticket

# Mimikatz

# Misc
How to add the ip to /etc/hosts file easily
echo "10.10.10.100  active.htb" >> /etc/hosts

How to link the applications so that they can run from anywhere


# Resources
* https://www.hackingarticles.in/a-detailed-guide-on-kerbrute/
* https://www.hackingarticles.in/a-detailed-guide-on-evil-winrm/
* https://unix.stackexchange.com/questions/3809/how-can-i-make-a-program-executable-from-everywhere
* https://www.hackingarticles.in/msfvenom-cheatsheet-windows-exploitation/
* https://www.hackingarticles.in/metasploit-for-pentester-mimikatz/






