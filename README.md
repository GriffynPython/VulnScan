# VulnScan
A vulnerability scanner that uses all scanning tools to scan a vulnerable/target device and parses the output of the various scans into one log that can be accessed by the attacker/hacker.
The various tools used here are:

nmap- to scan the network and version of the target.

nikto-to check the network space.

sqlmap-to identify sql injections.

gobuster- to check for sub-directories present in the wesbsite.

searchsploit- checks for any exploits that are capable of exploiting the software version that the vulnerable device has in metasploit.

Checks CVE/exploit-db to check for any exploit that can help in exploiting the target machine.

Also contains attacks for MITM attacks.- arpspoof tool.

Also contains a reverse/bind shell and netcat. 
