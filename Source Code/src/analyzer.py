# analyzer.py

import re
from pathlib import Path
from typing import List, Dict

from utils.file_io import read_file
from src.vulnerability_detector import detect_vulnerabilities
from data.vulnerability_patterns import vulnerability_patterns

def analyze_java_file(java_code: str) -> List[Dict]:
    """
    Analyzes the given Java code for vulnerabilities based on OWASP Top 10.

    :param java_code: The Java code to analyze
    :return: A list of detected vulnerabilities
    """
    detected_vulnerabilities = []

    for vulnerability, pattern in vulnerability_patterns.items():
        compiled_pattern = re.compile(pattern, re.MULTILINE)

        for line_number, line in enumerate(java_code.splitlines(), start=1):
            match = compiled_pattern.search(line)
            if match:
                detected_vulnerabilities.append({
                    "name": vulnerability,
                    "description": match.group(0),
                    "line_number": line_number,
                    "line": line.strip(),
                })

    vulnerabilities = detect_vulnerabilities(detected_vulnerabilities)
    return vulnerabilities

