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

# ... (Scanner and Cracking modules - same as before - improve parsing as needed) ...

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
        # ... (same as before - improved HTML and PDF report generation - see below)
    except Exception as e:
        logging.error(f"Report generation error: {e}")


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
