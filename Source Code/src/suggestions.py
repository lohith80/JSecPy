# suggestions.py

from typing import List, Dict

suggestion_templates = {
    "Broken Access Control": "Adopt fine-grained access controls, utilize role-based permissions, and perform regular authorization checks. Use access control libraries and frameworks to ensure robust implementation.",
    "Cryptographic Failures": "Employ robust encryption algorithms and key management schemes. Adhere to best practices for securing cryptographic storage and transmission.",
    "Injection": "Thoroughly validate and sanitize user input. Utilize prepared statements with parameterized queries to avoid injection attacks. Rely on secure libraries and frameworks to prevent injections.",
    "Insecure Design": "Incorporate secure design principles like least privilege, defense-in-depth, and secure by default. Validate and sanitize all inputs, and use secure libraries and frameworks.",
    "Security Misconfiguration": "Periodically review configurations, apply security-hardened defaults, and adhere to best practices. Maintain up-to-date systems and software with the latest security patches.",
    "Vulnerable and Outdated Components": "Continuously update libraries and components, and remove unused dependencies. Regularly assess known vulnerabilities in your dependencies.",
    "Identification & Authentication Failures": "Establish strong authentication mechanisms, apply multi-factor authentication, and adhere to best practices for secure password storage.",
    "Software and Data Integrity Failures": "Leverage checksums and digital signatures to ensure software and data integrity. Develop secure update mechanisms and tamper detection.",
    "Security Logging and Monitoring Failures": "Set up proper logging and monitoring, and establish alerts for suspicious activities. Regularly analyze logs and security events.",
    "Server-Side Request Forgery": "Examine and sanitize user inputs to prevent server-side request forgery attacks. Use allowlists to limit the domains and IPs that the server can access.",
}



def generate_suggestions(vulnerabilities: List[Dict]) -> List[Dict]:
    """
    Generates suggestions for resolving the detected vulnerabilities.

    :param vulnerabilities: The list of detected vulnerabilities
    :return: A list of suggestions for resolving the vulnerabilities
    """
    unique_suggestions = {}

    for vulnerability in vulnerabilities:
        vulnerability_name = vulnerability["name"]
        if vulnerability_name in suggestion_templates:
            unique_suggestions[vulnerability_name] = suggestion_templates[vulnerability_name]

    suggestions = [{"vulnerability": k, "suggestion": v} for k, v in unique_suggestions.items()]

    return suggestions