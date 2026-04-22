#!/usr/bin/env python3
"""
wcf_meta_check.py — Check a list of base URLs for exposed WCF metadata
Usage: python wcf_meta_check.py urls.txt
"""

import sys
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common WCF endpoint names to try at the root
SVC_NAMES = [
    "Service.svc",
    "DataService.svc",
    "API.svc",
    "ApiService.svc",
    "AuthService.svc",
    "SecurityService.svc",
    "UserService.svc",
    "AccountService.svc",
    "ApplicationService.svc",
    "IntegrationService.svc",
    "WebService.svc",
    "RemoteService.svc",
    "CoreService.svc",
    "BusinessService.svc",
    "PortalService.svc",
]

# Metadata suffixes to try on each endpoint
META_SUFFIXES = [
    "?wsdl",
    "?singleWsdl",
    "?mex",
    "?WSDL",
    "/mex",
]

# Sub-paths to look for .svc files under
SVC_PATHS = [
    "",
    "services/",
    "api/",
    "wcf/",
    "svc/",
    "webservices/",
    "ws/",
]

METADATA_KEYWORDS = [
    "wsdl",
    "definitions",
    "porttype",
    "servicemetadata",
    "imetadataexchange",
    "<soap",
    "targetnamespace",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}


def build_targets(base_url):
    """Build full list of URLs to probe from a single base URL."""
    base_url = base_url.strip().rstrip("/")
    targets = []
    for path in SVC_PATHS:
        for svc in SVC_NAMES:
            endpoint = f"{base_url}/{path}{svc}"
            for suffix in META_SUFFIXES:
                targets.append(endpoint + suffix)
    return targets


def check_target(url):
    try:
        r = requests.get(
            url,
            headers=HEADERS,
            timeout=8,
            verify=False,
            allow_redirects=True
        )
        if r.status_code == 200:
            body = r.text.lower()
            if any(kw in body for kw in METADATA_KEYWORDS):
                return (url, r.status_code, "METADATA EXPOSED")
            else:
                return (url, r.status_code, "200 - no metadata keywords")
        elif r.status_code not in (404, 400, 403):
            return (url, r.status_code, "")
    except requests.exceptions.Timeout:
        return (url, "TIMEOUT", "")
    except requests.exceptions.ConnectionError:
        pass
    except Exception as e:
        return (url, "ERROR", str(e))
    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python wcf_meta_check.py urls.txt")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        base_urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    all_targets = []
    for base in base_urls:
        all_targets.extend(build_targets(base))

    print(f"Loaded {len(base_urls)} base URL(s) → {len(all_targets)} probes\n")

    exposed = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check_target, t): t for t in all_targets}
        for future in as_completed(futures):
            result = future.result()
            if result:
                url, status, note = result
                tag = " *** METADATA EXPOSED ***" if "METADATA" in note else ""
                print(f"[{status}] {url}{tag}")
                if tag:
                    exposed.append(url)

    print(f"\n=== Summary ===")
    print(f"Probes:          {len(all_targets)}")
    print(f"Metadata exposed: {len(exposed)}")
    if exposed:
        print("\nHits:")
        for h in exposed:
            print(f"  {h}")


if __name__ == "__main__":
    main()
