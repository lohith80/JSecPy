#!/usr/bin/env python

import argparse
import sys
from pathlib import Path
from prettytable import PrettyTable
from termcolor import colored

from src.analyzer import analyze_java_file
from src.suggestions import generate_suggestions
from utils.file_io import read_file, write_file

#Parsing the arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="This tool analyzes Java files for security vulnerabilities and provides recommendations for resolving them based on the OWASP Top 10 Vulnerabilities list.")
    parser.add_argument("java_file", help="The path to the Java file to be analyzed")
    parser.add_argument("-output", help="The path to the output file where the results will be stored. If not provided, results will be printed to the console.")
    args = parser.parse_args()
    return args

#Validating the Java file
def validate_java_file(java_file_path: Path):
    if not java_file_path.exists() or java_file_path.suffix != ".java":
        print("Error: Invalid Java file path. Please provide a valid Java file.")
        sys.exit(1)

#Designing the output
def get_colored(text, color, use_color):
    if use_color:
        return colored(text, color)
    else:
        return text

#Generating the vulnerability summary
def generate_vulnerability_summary(vulnerabilities):
    summary = "Vulnerability Summary:\n"

    # Calculate the total number of potential vulnerabilities
    total_vulnerabilities = len(vulnerabilities)
    summary += f"- Total number of potential vulnerabilities: {total_vulnerabilities}\n"

    # Count the occurrences of each vulnerability type
    vulnerability_counts = {}
    for vulnerability in vulnerabilities:
        vuln_name = vulnerability['name']
        if vuln_name in vulnerability_counts:
            vulnerability_counts[vuln_name] += 1
        else:
            vulnerability_counts[vuln_name] = 1

    # Add the counts to the summary
    for vuln_name, count in vulnerability_counts.items():
        summary += f"- {vuln_name}: {count}\n"

    return summary

#Main function
def main():
    args = parse_arguments()
    java_file = Path(args.java_file)
    validate_java_file(java_file)
    java_code = read_file(java_file)

    vulnerabilities = analyze_java_file(java_code)
    suggestions = generate_suggestions(vulnerabilities)

    if not vulnerabilities:
        output_str = "No vulnerabilities found in the Java file."
    else:
        vuln_table = PrettyTable()
        vuln_table.field_names = ["OWASP Rank", "Vulnerability Type", "Affected Library", "Risk Level"]
        vuln_table.align["OWASP Rank"] = "m"
        vuln_table.align["Vulnerability Type"] = "l"
        vuln_table.align["Affected Library"] = "l"
        vuln_table.align["Risk Level"] = "m"
        grouped_vulnerabilities = {}
        for vulnerability in vulnerabilities:
            key = (vulnerability['owasp_rank'], vulnerability['name'], vulnerability['risk_level'])
            if key in grouped_vulnerabilities:
                grouped_vulnerabilities[key].append(vulnerability['description'])
            else:
                grouped_vulnerabilities[key] = [vulnerability['description']]

        for (owasp_rank, name, risk_level), descriptions in grouped_vulnerabilities.items():
            owasp_rank_color = colored(owasp_rank, 'magenta')
            name_color = colored(name, 'green', attrs=['bold'])
            risk_level_color = colored(risk_level, 'red', attrs=['bold'])
            description = "\n".join(descriptions)
            vuln_table.add_row([owasp_rank_color, name_color, description, risk_level_color])

        # Group suggestions based on vulnerability
        sug_dict = {}
        for suggestion in suggestions:
            vulnerability = suggestion['vulnerability']
            if vulnerability in sug_dict:
                sug_dict[vulnerability].append(suggestion['suggestion'])
            else:
                sug_dict[vulnerability] = [suggestion['suggestion']]

        use_color = not args.output
        suggestions_str = "Suggestions for resolving vulnerabilities:\n"
        for vulnerability, suggestions in sug_dict.items():
            suggestions_str += get_colored(f"{vulnerability}:\n", 'red', use_color)
            for suggestion in suggestions:
                suggestions_str += get_colored(f"  - {suggestion}\n", 'green', use_color)

        vulnerability_summary = generate_vulnerability_summary(vulnerabilities)
        #output_str = f"Vulnerabilities found:\n{vuln_table}\n\n{suggestions_str}"
        output_str = f"Vulnerabilities found:\n{vuln_table}\n\n{suggestions_str}\n{vulnerability_summary}"

    if args.output:
        output_file = Path(args.output)
        write_file(output_file, output_str)
        print(f"Results have been written to {output_file}")
    else:
        print(output_str)

if __name__ == "__main__":
    print("                                                 ");
    print("                                                 ");
    print("     ██ ███████ ███████  ██████ ██████  ██    ██ ");
    print("     ██ ██      ██      ██      ██   ██  ██  ██  ");
    print("     ██ ███████ █████   ██      ██████    ████   ");
    print("██   ██      ██ ██      ██      ██         ██    ");
    print(" █████  ███████ ███████  ██████ ██         ██    ");
    print("                                                 ");
    print("   -h for help                                   ");
    print("   -output to get result in a new file           ");
    print("                                                 ");
    main()

