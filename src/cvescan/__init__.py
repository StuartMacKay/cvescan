import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from jinja2 import Environment, BaseLoader
except ImportError:
    print("Error: jinja2 is required. Install with: pip install jinja2", file=sys.stderr)
    sys.exit(1)


# =============================================================================
# EMBEDDED TEMPLATES
# =============================================================================

TEMPLATE_MARKDOWN = """\
# CVE Vulnerability Scan Report

**File scanned:** `{{ file_path }}`
**Ecosystem:** {{ ecosystem }}
**Scan time:** {{ scan_time }}
**Total packages:** {{ total_packages }}
**Packages with vulnerabilities:** {{ vulnerable_package_count }}

## Summary
{% if not vulnerabilities %}

No known vulnerabilities found in the scanned packages.
{% else %}

### Vulnerabilities Found

| Vulnerability | Package | Severity |
|---------------|---------|----------|
{% for item in vulnerabilities %}
| {{ item.vuln_id }} | {{ item.package }} | {{ item.severity }} |
{% endfor %}

### Recommended Actions
{% if upgrades %}

#### Packages to Upgrade

| Package | Current Version | Upgrade To | Highest Severity |
|---------|-----------------|------------|------------------|
{% for upgrade in upgrades %}
| {{ upgrade.package }} | {{ upgrade.current }} | {{ upgrade.fixed }} | {{ upgrade.severity }} |
{% endfor %}

{% if ecosystem == "PyPI" %}
#### Upgrade Commands (pip)

```bash
{% for upgrade in upgrades %}
pip install '{{ upgrade.package }}>={{ upgrade.fixed }}'
{% endfor %}
```
{% elif ecosystem == "npm" %}
#### Upgrade Commands (npm)

```bash
{% for upgrade in upgrades %}
npm install {{ upgrade.package }}@{{ upgrade.fixed }}
{% endfor %}
```
{% endif %}
{% else %}
No automatic upgrades available. See individual vulnerabilities for mitigation guidance.
{% endif %}
{% for severity in severities %}
{% if severity.vulns %}

## {{ severity.level }} Severity
{% for item in severity.vulns %}

### {{ item.vuln_id }}

**Package:** `{{ item.package }}` (version {{ item.version }})
{% if item.cve_aliases %}

**CVE:** {{ item.cve_aliases | join(", ") }}
{% endif %}

**Description:** {{ item.summary }}
{% if item.details and item.details != item.summary %}
```
{{ item.details | truncate(500) }}
```
{% endif %}

**Recommended Action:**
{% if item.fixed_version %}
Upgrade `{{ item.package }}` to version **{{ item.fixed_version }}** or later.
{% else %}
Check the vulnerability references below for mitigation guidance.
{% endif %}
{% if item.references %}

**References:**
{% for ref in item.references[:5] %}
- [{{ ref.type }}]({{ ref.url }})
{% endfor %}
{% endif %}

---
{% endfor %}
{% endif %}
{% endfor %}
{% endif %}

---

*Report generated using OSV (Open Source Vulnerabilities) database.*
*For more information, visit: https://osv.dev/*
"""

TEMPLATE_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CVE Vulnerability Scan Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
        }
        h1 { color: #1a1a1a; border-bottom: 2px solid #e1e1e1; padding-bottom: 10px; }
        h2 { color: #2c3e50; margin-top: 30px; }
        h3 { color: #34495e; }
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 15px 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 10px 12px;
            text-align: left;
        }
        th {
            background-color: #f5f5f5;
            font-weight: 600;
        }
        tr:nth-child(even) { background-color: #fafafa; }
        tr:hover { background-color: #f0f0f0; }
        .severity-critical { color: #fff; background-color: #7b1fa2; font-weight: bold; }
        .severity-high { color: #fff; background-color: #c62828; font-weight: bold; }
        .severity-medium, .severity-moderate { color: #fff; background-color: #ef6c00; font-weight: bold; }
        .severity-low { color: #fff; background-color: #2e7d32; font-weight: bold; }
        .severity-unknown { color: #fff; background-color: #757575; }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.85em;
        }
        code {
            background-color: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        }
        pre {
            background-color: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }
        pre code {
            background-color: transparent;
            padding: 0;
            color: inherit;
        }
        blockquote {
            border-left: 4px solid #ddd;
            margin: 10px 0;
            padding: 10px 20px;
            background-color: #f9f9f9;
            color: #666;
        }
        .meta { color: #666; margin-bottom: 20px; }
        .meta strong { color: #333; }
        .vulnerability-card {
            border: 1px solid #e1e1e1;
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
            background-color: #fff;
        }
        .vulnerability-card h3 {
            margin-top: 0;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
        }
        .references { margin-top: 15px; }
        .references ul { margin: 5px 0; padding-left: 20px; }
        .references a { color: #0066cc; }
        .summary-section {
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        hr { border: none; border-top: 1px solid #e1e1e1; margin: 30px 0; }
        .footer {
            text-align: center;
            color: #888;
            font-size: 0.9em;
            margin-top: 40px;
        }
        .no-vulns {
            background-color: #e8f5e9;
            color: #2e7d32;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            font-size: 1.1em;
        }
    </style>
</head>
<body>
    <h1>CVE Vulnerability Scan Report</h1>

    <div class="meta">
        <p><strong>File scanned:</strong> <code>{{ file_path }}</code></p>
        <p><strong>Ecosystem:</strong> {{ ecosystem }}</p>
        <p><strong>Scan time:</strong> {{ scan_time }}</p>
        <p><strong>Total packages:</strong> {{ total_packages }}</p>
        <p><strong>Packages with vulnerabilities:</strong> {{ vulnerable_package_count }}</p>
    </div>

    <h2>Summary</h2>
{% if not vulnerabilities %}
    <div class="no-vulns">
        No known vulnerabilities found in the scanned packages.
    </div>
{% else %}
    <div class="summary-section">
        <h3>Vulnerabilities Found</h3>
        <table>
            <thead>
                <tr>
                    <th>Vulnerability</th>
                    <th>Package</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
{% for item in vulnerabilities %}
                <tr>
                    <td>{{ item.vuln_id }}</td>
                    <td><code>{{ item.package }}</code></td>
                    <td><span class="badge severity-{{ item.severity | lower }}">{{ item.severity }}</span></td>
                </tr>
{% endfor %}
            </tbody>
        </table>

        <h3>Recommended Actions</h3>
{% if upgrades %}
        <h4>Packages to Upgrade</h4>
        <table>
            <thead>
                <tr>
                    <th>Package</th>
                    <th>Current Version</th>
                    <th>Upgrade To</th>
                    <th>Highest Severity</th>
                </tr>
            </thead>
            <tbody>
{% for upgrade in upgrades %}
                <tr>
                    <td><code>{{ upgrade.package }}</code></td>
                    <td>{{ upgrade.current }}</td>
                    <td><strong>{{ upgrade.fixed }}</strong></td>
                    <td><span class="badge severity-{{ upgrade.severity | lower }}">{{ upgrade.severity }}</span></td>
                </tr>
{% endfor %}
            </tbody>
        </table>

{% if ecosystem == "PyPI" %}
        <h4>Upgrade Commands (pip)</h4>
        <pre><code>{% for upgrade in upgrades %}pip install '{{ upgrade.package }}&gt;={{ upgrade.fixed }}'
{% endfor %}</code></pre>
{% elif ecosystem == "npm" %}
        <h4>Upgrade Commands (npm)</h4>
        <pre><code>{% for upgrade in upgrades %}npm install {{ upgrade.package }}@{{ upgrade.fixed }}
{% endfor %}</code></pre>
{% endif %}
{% else %}
        <p>No automatic upgrades available. See individual vulnerabilities for mitigation guidance.</p>
{% endif %}
    </div>

{% for severity in severities %}
{% if severity.vulns %}
    <h2>{{ severity.level }} Severity</h2>
{% for item in severity.vulns %}
    <div class="vulnerability-card">
        <h3>{{ item.vuln_id }}</h3>
        <p><strong>Package:</strong> <code>{{ item.package }}</code> (version {{ item.version }})</p>
{% if item.cve_aliases %}
        <p><strong>CVE:</strong> {{ item.cve_aliases | join(", ") }}</p>
{% endif %}
        <p><strong>Description:</strong> {{ item.summary }}</p>
{% if item.details and item.details != item.summary %}
        <blockquote>{{ item.details | truncate(500) }}</blockquote>
{% endif %}
        <p><strong>Recommended Action:</strong><br>
{% if item.fixed_version %}
        Upgrade <code>{{ item.package }}</code> to version <strong>{{ item.fixed_version }}</strong> or later.
{% else %}
        Check the vulnerability references below for mitigation guidance.
{% endif %}
        </p>
{% if item.references %}
        <div class="references">
            <strong>References:</strong>
            <ul>
{% for ref in item.references[:5] %}
                <li><a href="{{ ref.url }}" target="_blank">{{ ref.type }}</a></li>
{% endfor %}
            </ul>
        </div>
{% endif %}
    </div>
{% endfor %}
{% endif %}
{% endfor %}
{% endif %}

    <hr>
    <div class="footer">
        <p><em>Report generated using OSV (Open Source Vulnerabilities) database.</em></p>
        <p><em>For more information, visit: <a href="https://osv.dev/">https://osv.dev/</a></em></p>
    </div>
</body>
</html>
"""

# =============================================================================
# CONSTANTS
# =============================================================================

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "MODERATE": 3,
    "LOW": 2,
    "UNKNOWN": 1,
}

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW", "UNKNOWN"]


# =============================================================================
# TEMPLATE ENGINE SETUP
# =============================================================================

def create_jinja_env() -> Environment:
    """Create and configure the Jinja2 environment with embedded templates."""
    env = Environment(loader=BaseLoader())

    # Register templates from embedded strings
    env.globals["TEMPLATES"] = {
        "markdown": TEMPLATE_MARKDOWN,
        "html": TEMPLATE_HTML,
    }

    env.trim_blocks = True

    return env


def render_template(env: Environment, template_name: str, context: dict) -> str:
    """Render an embedded template with the given context."""
    template_source = env.globals["TEMPLATES"].get(template_name)
    if not template_source:
        raise ValueError(f"Unknown template: {template_name}")

    template = env.from_string(template_source)
    return template.render(**context)


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def log(message: str) -> None:
    """Print a message to stderr for progress/status updates."""
    print(message, file=sys.stderr)


def log_warning(message: str) -> None:
    """Print a warning message to stderr."""
    print(f"WARNING: {message}", file=sys.stderr)


# =============================================================================
# FILE PARSERS
# =============================================================================

def detect_format(file_path: Path) -> str | None:
    """Auto-detect file format based on filename."""
    name = file_path.name.lower()

    if name == "requirements.txt" or name.endswith(".txt"):
        content = file_path.read_text()
        if "==" in content or "-r " in content or "# via" in content:
            return "requirements"
    elif name == "pyproject.toml":
        return "pyproject"
    elif name == "uv.lock":
        return "uv-lock"
    elif name == "package-lock.json":
        return "package-lock"

    return None


def parse_requirements(file_path: Path) -> dict[str, str]:
    """Parse a pip requirements.txt file."""
    packages = {}
    content = file_path.read_text()
    pattern = re.compile(r"^([a-zA-Z][a-zA-Z0-9._-]*)==([^\s\\]+)", re.MULTILINE)

    for match in pattern.finditer(content):
        packages[match.group(1).lower()] = match.group(2)

    return packages


def parse_pyproject(file_path: Path) -> dict[str, str]:
    """Parse a pyproject.toml file for dependencies."""
    packages = {}
    content = file_path.read_text()

    try:
        import tomllib
        data = tomllib.loads(content)
        deps = []

        if "project" in data:
            deps.extend(data["project"].get("dependencies", []))
            for group_deps in data["project"].get("optional-dependencies", {}).values():
                deps.extend(group_deps)

        if "tool" in data and "poetry" in data["tool"]:
            poetry = data["tool"]["poetry"]
            for dep_name, dep_spec in poetry.get("dependencies", {}).items():
                if dep_name.lower() != "python":
                    if isinstance(dep_spec, str):
                        deps.append(f"{dep_name}{dep_spec}")
                    elif isinstance(dep_spec, dict) and "version" in dep_spec:
                        deps.append(f"{dep_name}{dep_spec['version']}")

        for dep in deps:
            match = re.match(r"([a-zA-Z][a-zA-Z0-9._-]*)\s*([=<>!~]+.+)?", dep)
            if match:
                name = match.group(1).lower()
                version_spec = match.group(2) or ""
                exact_match = re.search(r"==\s*([^\s,;]+)", version_spec)
                packages[name] = exact_match.group(1) if exact_match else (version_spec.strip() or "*")

    except ImportError:
        log_warning("tomllib not available, using basic regex parsing for pyproject.toml")
        dep_pattern = re.compile(r'"([a-zA-Z][a-zA-Z0-9._-]*)\s*([=<>!~][^"]*)"')
        for match in dep_pattern.finditer(content):
            name = match.group(1).lower()
            version_spec = match.group(2)
            exact_match = re.search(r"==\s*([^\s,;\"]+)", version_spec)
            packages[name] = exact_match.group(1) if exact_match else version_spec.strip()

    return packages


def parse_uv_lock(file_path: Path) -> dict[str, str]:
    """Parse a uv.lock file (uv package manager lockfile)."""
    packages = {}
    content = file_path.read_text()

    try:
        import tomllib
        data = tomllib.loads(content)

        for pkg in data.get("package", []):
            name = pkg.get("name", "").lower()
            version = pkg.get("version", "")
            source = pkg.get("source", {})

            if isinstance(source, dict) and source.get("editable"):
                continue

            if name and version:
                packages[name] = version

    except ImportError:
        log_warning("tomllib not available, using regex parsing for uv.lock")
        package_pattern = re.compile(
            r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"',
            re.MULTILINE,
        )

        for match in package_pattern.finditer(content):
            name = match.group(1).lower()
            version = match.group(2)
            block_start = match.end()
            next_block = content.find("[[package]]", block_start)
            block_content = content[block_start:next_block] if next_block != -1 else content[block_start:]

            if 'editable = "' not in block_content and "editable = '" not in block_content:
                packages[name] = version

    return packages


def parse_package_lock(file_path: Path) -> dict[str, str]:
    """Parse an npm package-lock.json file."""
    packages = {}
    data = json.loads(file_path.read_text())
    lock_version = data.get("lockfileVersion", 1)

    if lock_version >= 2:
        for pkg_path, pkg_info in data.get("packages", {}).items():
            if pkg_path == "":
                continue
            parts = pkg_path.split("node_modules/")
            if len(parts) > 1:
                name = parts[-1]
                version = pkg_info.get("version", "")
                if name and version:
                    packages[name] = version
    else:
        def extract_deps(deps: dict):
            for name, info in deps.items():
                if isinstance(info, dict):
                    if version := info.get("version", ""):
                        packages[name] = version
                    if "dependencies" in info:
                        extract_deps(info["dependencies"])
        extract_deps(data.get("dependencies", {}))

    return packages


# =============================================================================
# CVE SCANNING
# =============================================================================

def query_osv(name: str, version: str, ecosystem: str) -> list[dict]:
    """Query the OSV API for a specific package."""
    url = "https://api.osv.dev/v1/query"

    if not version or version == "*" or version.startswith(("<", ">", "~", "^")):
        payload = {"package": {"name": name, "ecosystem": ecosystem}}
    else:
        payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}

    try:
        request = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8")).get("vulns", [])
    except HTTPError as e:
        if e.code != 400:
            log_warning(f"HTTP error querying {name}: {e.code}")
        return []
    except URLError as e:
        log_warning(f"Network error querying {name}: {e}")
        return []
    except json.JSONDecodeError:
        return []


def scan_packages(packages: dict[str, str], ecosystem: str) -> dict[str, list[dict]]:
    """Query OSV API for vulnerabilities in packages."""
    vulnerabilities = {}
    total = len(packages)

    for idx, (name, version) in enumerate(packages.items(), 1):
        if idx % 20 == 0 or idx == total:
            log(f"  Scanning package {idx}/{total}...")

        if vulns := query_osv(name, version, ecosystem):
            vulnerabilities[name] = {"version": version, "vulns": vulns}

    return vulnerabilities


def get_severity(vuln: dict) -> str:
    """Extract severity from vulnerability data."""
    if severity := vuln.get("database_specific", {}).get("severity"):
        return severity.upper()

    for affected in vuln.get("affected", []):
        if severity := affected.get("ecosystem_specific", {}).get("severity"):
            return severity.upper()

    return "UNKNOWN"


def get_fixed_version(vuln: dict, package_name: str) -> str | None:
    """Extract the fixed version from vulnerability data."""
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() == package_name.lower():
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
    return None


# =============================================================================
# REPORT GENERATION
# =============================================================================

def build_template_context(
    file_path: Path,
    ecosystem: str,
    packages: dict[str, str],
    vulnerabilities: dict[str, list[dict]],
) -> dict:
    """Build the context dictionary for template rendering."""
    all_vulns = []
    for pkg_name, pkg_data in vulnerabilities.items():
        version = pkg_data["version"]
        for vuln in pkg_data["vulns"]:
            severity = get_severity(vuln)
            fixed_version = get_fixed_version(vuln, pkg_name)
            aliases = vuln.get("aliases", [])
            cve_aliases = [a for a in aliases if a.startswith("CVE-")]
            references = vuln.get("references", [])

            all_vulns.append({
                "package": pkg_name,
                "version": version,
                "vuln_id": vuln.get("id", "Unknown"),
                "severity": severity,
                "fixed_version": fixed_version,
                "summary": vuln.get("summary", "No description available"),
                "details": vuln.get("details", ""),
                "cve_aliases": cve_aliases,
                "references": [
                    {"type": ref.get("type", "WEB"), "url": ref.get("url", "")}
                    for ref in references if ref.get("url")
                ],
            })

    all_vulns.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 0), reverse=True)

    by_severity = {}
    for v in all_vulns:
        by_severity.setdefault(v["severity"], []).append(v)

    severities = [{"level": level, "vulns": by_severity.get(level, [])} for level in SEVERITY_LEVELS]

    upgrades_needed = {}
    for item in all_vulns:
        pkg = item["package"]
        if item["fixed_version"]:
            if pkg not in upgrades_needed:
                upgrades_needed[pkg] = {
                    "package": pkg,
                    "current": item["version"],
                    "fixed": item["fixed_version"],
                    "severity": item["severity"],
                }
            else:
                try:
                    from packaging.version import Version
                    if Version(item["fixed_version"]) > Version(upgrades_needed[pkg]["fixed"]):
                        upgrades_needed[pkg]["fixed"] = item["fixed_version"]
                except (ImportError, Exception):
                    pass

    sorted_upgrades = sorted(
        upgrades_needed.values(),
        key=lambda x: SEVERITY_ORDER.get(x["severity"], 0),
        reverse=True,
    )

    return {
        "file_path": str(file_path),
        "ecosystem": ecosystem,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_packages": len(packages),
        "vulnerable_package_count": len(vulnerabilities),
        "vulnerabilities": all_vulns,
        "severities": severities,
        "upgrades": sorted_upgrades,
    }


# =============================================================================
# MAIN
# =============================================================================

def main() -> int:
    """Main entry point for the CVE scanner."""
    parser = argparse.ArgumentParser(
        description="Scan package dependency files for known CVEs (Jinja2 prototype).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python cve_scan.py requirements.txt
    python cve_scan.py requirements.txt --report-format html
    python cve_scan.py requirements.txt -o report.html --report-format html
        """,
    )
    parser.add_argument("file_path", help="Path to the dependency file")
    parser.add_argument(
        "--format", "-f",
        choices=["requirements", "pyproject", "uv-lock", "package-lock"],
        help="Force a specific input file format",
    )
    parser.add_argument(
        "--report-format", "-r",
        choices=["markdown", "html"],
        default="markdown",
        help="Output report format (default: markdown)",
    )
    parser.add_argument("--output", "-o", help="Output file path (defaults to stdout)")

    args = parser.parse_args()
    file_path = Path(args.file_path)

    if not file_path.exists():
        log(f"Error: File not found: {file_path}")
        return 1

    file_format = args.format or detect_format(file_path)
    if not file_format:
        log(f"Error: Could not detect file format for: {file_path}")
        return 1

    log(f"Scanning {file_path} as {file_format} format...")

    # Parse packages
    parsers = {
        "requirements": parse_requirements,
        "pyproject": parse_pyproject,
        "uv-lock": parse_uv_lock,
        "package-lock": parse_package_lock,
    }
    packages = parsers[file_format](file_path)
    ecosystem = "npm" if file_format == "package-lock" else "PyPI"

    log(f"Found {len(packages)} packages to scan...")

    # Scan for vulnerabilities
    vulnerabilities = scan_packages(packages, ecosystem)

    # Build context and render report
    context = build_template_context(file_path, ecosystem, packages, vulnerabilities)
    env = create_jinja_env()
    report = render_template(env, args.report_format, context)

    # Output
    if args.output:
        Path(args.output).write_text(report)
        log(f"Report written to {args.output}")
    else:
        print(report)

    return 1 if vulnerabilities else 0


if __name__ == "__main__":
    sys.exit(main())
