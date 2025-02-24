import subprocess
import os
import argparse
import json  # For comparing JSON report output (if needed)
import re  # For regular expressions (for more robust checking)

def run_test_combination(combination, ip_address, wordlist=None, report_format="txt"):
    """Runs a test combination and checks for basic success and specific findings."""

    print(f"\n--- Testing combination: {combination} ---")

    script_path = os.path.join(os.path.dirname(__file__), "vulnscan.py")  # Path to your script
    if not os.path.exists(script_path):
        print(f"Error: Script '{script_path}' not found.")
        return False

    command = ["python", script_path, "-i", ip_address, "--report-format", report_format]

    if wordlist:
        command.append("--wordlist")
        command.append(wordlist)

    for tool in combination:
        if isinstance(tool, tuple):  # Tool with argument (e.g., searchsploit)
            command.append(f"--{tool[0]}")
            command.append(tool[1])
        else:
            command.append(f"--{tool}")

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        #print(result.stdout)  # Print output for debugging (comment out for cleaner output)

        # --- Basic Success Check ---
        if "Penetration testing complete" not in result.stdout:
            print(f"Test Failed: 'Penetration testing complete' not found.")
            return False

        # --- Tool-Specific Checks (Crucial - Improve these!) ---
        if "nmap" in combination:
            if not re.search(r"PORT\s+STATE\s+SERVICE", result.stdout):  # Check for Nmap table header
                print("Nmap check failed: Could not find port table header.")
                return False
            # Add more specific Nmap checks (open ports, services, etc.) using regex

        if "nikto" in combination:
            if not re.search(r"\+ Target:", result.stdout):  # Check for Nikto target line
                print("Nikto check failed: Could not find target line.")
                return False
            # Add checks for specific Nikto findings using regex

        if "gobuster" in combination:
            if not re.search(r"Status:", result.stdout):  # Check for Gobuster status lines
                print("Gobuster check failed: Could not find status lines.")
                return False
            # Check for specific directories found by Gobuster

        if "sqlmap" in combination:
            if not re.search(r"sqlmap identified the following injection points:", result.stdout):
                print("SQLMap check failed: Could not find injection points message.")
                return False

        if "searchsploit" in combination:
            if not re.search(r"EDB-ID \| DESCRIPTION", result.stdout):  # Check for Searchsploit table header
                print("Searchsploit check failed: Could not find table header.")
                return False

        if "hydra" in combination:
            if not re.search(r"login:", result.stdout):  # Check for Hydra login attempts
                print("Hydra check failed: Could not find login attempts.")
                return False

        if "john" in combination:
            if not re.search(r":", result.stdout): # Check for John cracked passwords
                print("John check failed: Could not find cracked passwords.")
                return False

        if "aircrack" in combination:
            if not re.search(r"\[00:00:00\]", result.stdout): # Check for aircrack output
                print("Aircrack check failed: Could not find aircrack output.")
                return False

        if report_format == "html":
            if not re.search(r"<title>Penetration Testing Report</title>", result.stdout):  # Check for HTML title
                print("HTML report check failed: Could not find title tag.")
                return False
            # Add more checks for HTML report structure/content

        if report_format == "pdf":
            print("PDF report check (basic) - needs more detailed parsing (using a PDF library).")  # Requires a PDF library

        print(f"Test Passed for {combination}") # Indicate test passed
        return True

    except subprocess.CalledProcessError as e:
        print(f"Test Failed (subprocess error): {e}")
        print(e.stderr)  # Print stderr for debugging
        return False

    except Exception as e:
        print(f"Test Failed (exception): {e}")
        return False


def main():
    # ... (Argument parsing - same as before) ...

    # --- Test Combinations ---
    test_combinations = [
        ["nmap"],
        ["nikto"],
        ["gobuster"],
        ["sqlmap"],
        ["searchsploit", ("searchsploit", "apache")],  # Example with argument
        ["hydra"],
        ["john", ("john", "hashes.txt")],  # Example with hash file
        ["aircrack", ("aircrack", "capture.cap")],  # Example with capture file
        ["nmap", "nikto"],
        ["nmap", "gobuster", "sqlmap"],
        ["hydra", "john", ("john", "hashes.txt")],
        ["nmap", "nikto", ("searchsploit", "linux")],
        # ... Add more combinations as needed
    ]

    all_tests_passed = True
    for combination in test_combinations:
        if not run_test_combination(combination, ip_address, wordlist_file, report_format):
            all_tests_passed = False

    if all_tests_passed:
        print("\nAll tests passed.")
    else:
        print("\nSome tests failed.")


if __name__ == "__main__":
    main()
