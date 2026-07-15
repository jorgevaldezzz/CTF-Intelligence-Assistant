export const CWE_ALIASES: Record<string,string[]> = {
  "CWE-918": [
    "Server Side Request Forgery",
    "SSRF",
    "server-side request forgery",
    "URL fetch vulnerability",
    "internal network access",
    "cloud metadata exposure",
    "169.254.169.254",
    "AWS IMDS",
    "Azure metadata endpoint",
    "GCP metadata endpoint",
  ],

  "CWE-79": [
    "Cross Site Scripting",
    "XSS",
    "script injection",
    "browser code execution",
  ],

  "CWE-89": [
    "SQL Injection",
    "SQLi",
    "database injection",
    "query manipulation",
  ],

  "CWE-22": [
    "Path Traversal",
    "Directory Traversal",
    "file inclusion",
    "../ attack",
  ],

  "CWE-78": [
    "OS Command Injection",
    "command injection",
    "remote command execution",
    "RCE",
  ],
};