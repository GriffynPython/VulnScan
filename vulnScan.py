import os
import subprocess
import shlex
import json
import datetime
import re
import argparse
import logging
from bs4 import BeautifulSoup
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib import colors
from colorama import Fore, Style  # For colored output (optional)
import concurrent.futures  # For concurrency


# --- Logging Setup ---
logging.basicConfig(filename="vulnscan.log", level=logging.INFO, 
                    format="%(asctime)s - %(levelname)s - %(message)s")

# --- Banner Display ---
def display_banner():
    # ... (same as before)
  banner = f"""
    ███████  ██████  ███    ███ ███████ ███████ ███████ 
    ██       ██    ██ ████  ████ ██      ██      ██      
    ███████  ███████ ██ ██  ██ ███████ ███████ ███████ 
          ██ ██    ██ ██  ██ ██ ██           ██      ██      
    ███████  ██    ██ ██   ████ ███████ ███████ ███████ 
                                                            
        {Fore.GREEN}VulnScan{Style.RESET_ALL} - Automated Penetration Testing Tool
              Version 1.0 (Example)
        Author: {Fore.BLUE}Aarav Saklani{Style.RESET_ALL} (Example)
    """  # Customize your banner
    print(banner)
    print("-" * 50)  # Separator

# ... (Scanner and Cracking modules - same as before - improve parsing as needed) ...
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

""" ... (Add other scanner modules - gobuster, etc.) ..."""
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
# --- Vulnerability Database Integration (Example - Requires API Key) ---
# (Replace with actual API call and parsing)


# --- Improved Argument Parsing ---
def setup_arguments(parser):
    tools = {
        # ... (same as before)
    }

    for tool_name, tool_data in tools.items():
        if tool_name in ["searchsploit", "john", "aircrack"]:
            if tool_name == "searchsploit":
                parser.add_argument(f"--{tool_name}", help=f"Enable {tool_name} (specify keyword)")
            elif tool_name == "john":
                parser.add_argument(f"--{tool_name}", help=f"Enable {tool_name} (specify hash file)")
            elif tool_name == "aircrack":
                parser.add_argument(f"--{tool_name}", help=f"Enable {tool_name} (specify capture file)")
        elif tool_name in ["hydra"]:
            parser.add_argument(f"--{tool_name}", action="store_true", help=f"Enable {tool_name}")
        else:
            parser.add_argument(f"--{tool_name}", action="store_true", help=f"Enable {tool_name}")
            
    parser.add_argument("-i", "--ip", required=True, help="Target IP address")
    parser.add_argument("-w", "--website", help="Target website (optional)")
    parser.add_argument("--wordlist", help="Wordlist file (required for cracking tools)")
    parser.add_argument("--report-format", default="txt", choices=["txt", "html", "pdf"], help="Report format")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads for concurrent scans") # Concurrency
    return tools


# --- Run Tool with Error Handling and Logging ---
def run_tool(tool_name, tool_data):
    try:
        logging.info(f"Starting {tool_name} against {tool_data['args']}")
        output, findings = tool_data["func"](*tool_data["args"])
        if findings:
            logging.info(f"{tool_name} completed successfully.")
            return findings
        else:
            logging.warning(f"{tool_name} returned no results.")
            return []
    except Exception as e:
        logging.error(f"Error running {tool_name}: {e}")
        return []


# --- Reporting Module (Improved) ---
def generate_report(target_info, findings, output_format="txt"):
    try:
        if output_format == "txt":
            report_content = generate_text_report(target_info, findings)  # Call text report function
            with open("pentest_report.txt", "w") as f:
                f.write(report_content)
            print("[+] Report generated as pentest_report.txt")

        elif output_format == "html":
            report_content = generate_html_report(target_info, findings)  # Call HTML report function
            with open("pentest_report.html", "w") as f:
                f.write(report_content)
            print("[+] Report generated as pentest_report.html")

        elif output_format == "pdf":
            generate_pdf_report(target_info, findings)  # Call PDF report function (already handles file writing)

        else:
            logging.warning(f"Invalid report format: {output_format}")

    except Exception as e:
        logging.error(f"Report generation error: {e}")


def generate_text_report(target_info, findings):  # New function for text reports
    report_content = f"Penetration Testing Report - {datetime.datetime.now()}\n"
    report_content += f"Target: {target_info['ip']} ({target_info['website'] or 'N/A'})\n\n"

    if findings:
        report_content += "Identified Vulnerabilities:\n"
        for finding in findings:
            report_content += f"  Type: {finding['type']}\n"  # Simplified for text report
            for key, value in finding.items():  # Add other details
                if key != 'type':
                    report_content += f"    {key}: {value}\n"
            report_content += "\n"

    else:
        report_content += "No vulnerabilities identified.\n"

    report_content += "\nRecommendations:\n"  # Add recommendations
    report_content += "- Perform manual verification of findings.\n"
    report_content += "- Consult security best practices for remediation.\n"
    report_content += "- Prioritize patching high-severity vulnerabilities.\n"
    report_content += "- Use Metasploit (or other tools) for manual exploitation (if appropriate and with permission).\n"

    return report_content

# ... (generate_html_report and generate_pdf_report functions - same as before)


def generate_html_report(target_info, findings):
    report_content = f"""
    <html>
    <head><title>Penetration Testing Report</title></head>
    <body>
    <h1>Penetration Testing Report - {datetime.datetime.now()}</h1>
    <h2>Target: {target_info['ip']} ({target_info['website'] or 'N/A'})</h2>

    """

    if findings:
        report_content += "<h2>Identified Vulnerabilities:</h2>"
        report_content += "<table><tr><th>Type</th><th>Details</th></tr>" # Table for findings
        for finding in findings:
            details_str = ""
            for key, value in finding.items():
                if key != 'type':
                    details_str += f"{key}={value}<br>"  # Include all details
            report_content += f"<tr><td>{finding['type']}</td><td>{details_str}</td></tr>"

        report_content += "</table>"

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


def generate_pdf_report(target_info, findings):
    try:
        doc = SimpleDocTemplate("pentest_report.pdf")
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph(f"Penetration Testing Report - {datetime.datetime.now()}", styles['h1']))
        story.append(Paragraph(f"Target: {target_info['ip']} ({target_info['website'] or 'N/A'})", styles['h2']))
        story.append(Spacer(1, 0.2 * inch))

        if findings:
            story.append(Paragraph("Identified Vulnerabilities:", styles['h3']))

            data = [["Type", "Details"]]  # Table data
            for finding in findings:
                details_str = ""
                for key, value in finding.items():
                    if key != 'type':
                        details_str += f"{key}={value}\n"
                data.append([finding['type'], details_str])

            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),  # Header background
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Header text color
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),  # Center align
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),  # Header font
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),  # Header bottom padding
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),  # Row background
                ('GRID', (0, 0), (-1, -1), 1, colors.black)  # Table border
            ]))

            story.append(table)


        else:
            story.append(Paragraph("No vulnerabilities identified.", styles['Normal']))

        # ... (Recommendations - same as before)

        doc.build(story)
        print("[+] Report generated as pentest_report.pdf")

    except Exception as e:
        print(f"[-] PDF report generation error: {e}")



def main():
    display_banner()
    parser = argparse.ArgumentParser(description="Automated Penetration Testing Tool")
    tools = setup_arguments(parser) # Set up arguments and get the tools dict
    args = parser.parse_args()

    # --- Argument Validation ---
    if not args.wordlist and any(tools[tool]["enabled"] for tool in ["hydra", "john", "aircrack"]):
        parser.error("--wordlist is required for Hydra, John the Ripper, and Aircrack-ng")

    ip = args.ip
    website = args.website or get_website_from_ip(ip)
    target_info = {"ip": ip, "website": website}
    all_findings = []

    # --- Enable and Set Arguments (same as before) ---
    for tool_name, tool_data in tools.items():
        if getattr(args, tool_name):
            tools[tool_name]["enabled"] = True
            # ... (Set arguments based on tool - same as before)

    # --- Concurrent Tool Execution ---
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for tool_name, tool_data in tools.items():
            if tool_data["enabled"]:
                print(f"[+] Starting {tool_name}...")
                futures.append(executor.submit(run_tool, tool_name, tool_data))

        for future in concurrent.futures.as_completed(futures):
            findings = future.result()
            if findings:
                all_findings.extend(findings)

    # --- Report Generation ---
    generate_report(target_info, all_findings
args.report_format)  # Generate the report

    print("[+] Penetration testing complete.")

if __name__ == "__main__":
    main()

# ... (get_website_from_ip function - same as before) ...
