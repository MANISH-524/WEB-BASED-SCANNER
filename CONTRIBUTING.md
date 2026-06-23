# Contributing to OBSIDIAN

Thank you for wanting to make this better. Every module you add or fix helps the security community.

---

## What You Can Contribute

### 1. New Detection Modules
The most valuable contribution. A good module follows the zero-FP pattern — multiple confirmation gates before flagging a finding.

**Template for a new module:**
```python
def module_your_vuln(target, session):
    """
    OWASPID/MITREAD: Short description of what this checks.
    Zero-FP via:
    1. Gate 1 description
    2. Gate 2 description
    """
    findings = []
    logger.log("YOUR-MODULE", "Brief description of check …")

    try:
        # Establish baseline
        bl = safe_get(session, target)
        if not bl: return findings

        # Your detection logic here
        # ...

        # Create finding
        findings.append(make_finding(
            "your_module_key",        # Must exist in OWASP_MITRE dict
            "Title of Finding",       # Human-readable title
            "High",                   # Critical / High / Medium / Low / Info
            "Description of what was found.",
            "How to fix it.",
            url=target,
            payload="payload used",
            cwe="CWE-XXX",
            confidence="High"         # High / Medium / Low
        ))

    except Exception:
        pass
    return findings
```

### 2. New Path Checks in `module_sensitive_files`
Add to the `CHECKS` list:
```python
("path/to/check", "indicator_string", "Title of Finding", "Severity", "CWE-XXX"),
```

### 3. New Tech Signatures in `TECH_SIGNATURES`
```python
"YourFramework": {"body": ["unique_string"], "hdrs": ["X-Header-Name"]},
```

### 4. New Default Credentials in `DEFAULT_CREDS_DB`
```python
("username", "password"),
```

### 5. New CVE Entries in `PORT_CVE_DB`
```python
8080: [("CVE-XXXX-XXXXX", "Brief description", cvss_score)],
```

### 6. False-Positive Reports
If a module fires on legitimate content, open an Issue with:
- The false-positive scenario (what the page returns)
- Which gate failed to catch it
- A proposed fix

### 7. Tool Integrations
Wrap a new external tool in `tool_yourname(target, workdir)` pattern:
```python
def tool_yourname(target, workdir):
    findings = []
    if not find_bin("toolname"): return findings
    logger.log("TOOLNAME", f"Running: {target}", "TOOL")
    out = run_cmd(["toolname", "--args", target], timeout=120)
    # Parse output and create findings
    return findings
```

---

## How to Contribute

```bash
# Fork and clone
git clone https://github.com/YOUR-USERNAME/WEB-BASED-SCANNER.git
cd WEB-BASED-SCANNER

# Create a branch
git checkout -b feat/your-module-name

# Make your changes in CODE.py
# Test against DVWA or OWASP Juice Shop:
#   docker run -d -p 3000:3000 bkimminich/juice-shop
#   python CODE.py  # target: http://localhost:3000

# Commit
git commit -m "feat: add module_your_vuln — XYZ detection"

# Push and open PR
git push origin feat/your-module-name
```

---

## Testing Environments

Safe local targets to test your module against:

| Target | Deploy | Covers |
|---|---|---|
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | `docker run -p 3000:3000 bkimminich/juice-shop` | XSS, SQLi, IDOR, JWT, SSRF |
| [DVWA](https://github.com/digininja/DVWA) | `docker run -p 80:80 vulnerables/web-dvwa` | Classic web vulns |
| [WebGoat](https://github.com/WebGoat/WebGoat) | `docker run -p 8080:8080 webgoat/webgoat` | OWASP coverage |
| [VulnHub VMs](https://www.vulnhub.com) | Download + VMware | Full pentest environments |

**Never test against real targets without written permission.**

---

## Code Style

- Keep modules self-contained with their own `findings = []` and `return findings`
- Always use `make_finding()` — never create `Finding()` directly
- Add your module key to `OWASP_MITRE` if it's a new category
- Log the module name, brief description, and severity via `logger.log()`
- Include a docstring with OWASP/MITRE reference and FP-reduction gates

---

## Questions?

Open a [GitHub Issue](https://github.com/MANISH-524/WEB-BASED-SCANNER/issues) — questions, ideas, and feedback all welcome.
