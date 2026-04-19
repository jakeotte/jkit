#!/usr/bin/env python3
"""
Subdomain Takeover Scanner
==========================
Checks a list of subdomains for potential subdomain takeover vulnerabilities.

Features:
- Full CNAME chain resolution
- NXDOMAIN detection (dangling DNS)
- NS takeover detection (unregistered nameservers)
- HTTP/HTTPS body + header fingerprinting (50+ services)
- Concurrent async scanning with rate limiting
- Rich terminal output with progress bar
- JSON and CSV export

Usage:
    python scanner.py subdomains.txt
    python scanner.py subdomains.txt -o results.json --csv results.csv
    python scanner.py subdomains.txt --concurrency 50 --timeout 10
"""

import argparse
import asyncio
import csv
import ipaddress
import json
import logging
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import aiohttp
import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich import box


# ──────────────────────────────────────────────────────────────────────────────
# Fingerprint database
# ──────────────────────────────────────────────────────────────────────────────

FINGERPRINTS = [
    # ─── Cloud Storage ────────────────────────────────────────────────────────
    {
        "service": "AWS S3 Bucket",
        "cname": [
            r"\.s3\.amazonaws\.com",
            r"\.s3-website[.-]",
            r"s3-accelerate\.amazonaws\.com",
            r"\.s3\.[a-z0-9-]+\.amazonaws\.com",
        ],
        "fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": False,
        "notes": "Create the S3 bucket with the same name in the same region.",
    },
    {
        "service": "AWS Elastic Beanstalk",
        "cname": [r"\.elasticbeanstalk\.com"],
        "fingerprints": [
            "404 Not Found",
            "No Application",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Register the Elastic Beanstalk application/environment with the same name.",
    },
    {
        "service": "AWS CloudFront",
        "cname": [r"\.cloudfront\.net"],
        "fingerprints": [
            "Bad request",
            "ERROR: The request could not be satisfied",
        ],
        "headers": {},
        "status_codes": [400],
        "nxdomain": False,
        "notes": "Distribution exists but domain not whitelisted; may indicate misconfiguration.",
    },
    {
        "service": "Azure App Service / Web Apps",
        "cname": [
            r"\.azurewebsites\.net",
            r"\.cloudapp\.azure\.com",
            r"\.trafficmanager\.net",
        ],
        "fingerprints": [
            "404 Web Site not found",
            "Hmm, we can&#39;t find this page",
            "is not found in the",
            "No web site was found at this address",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Register the Azure Web App with the same subdomain name.",
    },
    {
        "service": "Azure Front Door",
        "cname": [r"\.azurefd\.net"],
        "fingerprints": [
            "Hmm... can&#39;t reach this page",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Register an Azure Front Door profile with the same hostname.",
    },
    {
        "service": "Azure Storage (Blob)",
        "cname": [
            r"\.blob\.core\.windows\.net",
            r"\.table\.core\.windows\.net",
            r"\.queue\.core\.windows\.net",
            r"\.file\.core\.windows\.net",
        ],
        "fingerprints": [
            "The specified resource does not exist",
            "BlobNotFound",
            "ContainerNotFound",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create an Azure Storage account/container with the same name.",
    },
    {
        "service": "Google Cloud Storage",
        "cname": [
            r"\.storage\.googleapis\.com",
            r"c\.storage\.googleapis\.com",
        ],
        "fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": False,
        "notes": "Create a GCS bucket with the subdomain name.",
    },
    {
        "service": "Google Firebase",
        "cname": [r"\.firebaseapp\.com", r"\.web\.app"],
        "fingerprints": [
            "The requested URL was not found on this server",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Firebase project with the same app name.",
    },
    # ─── PaaS / Hosting ───────────────────────────────────────────────────────
    {
        "service": "Heroku",
        "cname": [r"\.herokudns\.com", r"\.herokussl\.com", r"\.herokuapp\.com"],
        "fingerprints": [
            "No such app",
            "there is no app configured at that hostname",
            "herokucdn.com/error-pages/no-such-app.html",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Heroku app with the matching name.",
    },
    {
        "service": "Netlify",
        "cname": [r"\.netlify\.app", r"\.netlify\.com"],
        "fingerprints": [
            "Not Found - Request ID",
            "netlify-404-page",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Netlify site and configure the custom domain.",
    },
    {
        "service": "Vercel",
        "cname": [r"\.vercel\.app", r"\.now\.sh", r"cname\.vercel-dns\.com"],
        "fingerprints": [
            "The deployment could not be found on Vercel",
            "This Serverless Function has crashed",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Deploy a Vercel project and configure the custom domain.",
    },
    {
        "service": "Render",
        "cname": [r"\.onrender\.com"],
        "fingerprints": [
            "Service Not Found",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Render service with the matching name.",
    },
    {
        "service": "Fly.io",
        "cname": [r"\.fly\.dev"],
        "fingerprints": [
            "404 Not Found",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Deploy a Fly.io app with the matching hostname.",
    },
    {
        "service": "Surge.sh",
        "cname": [r"\.surge\.sh"],
        "fingerprints": [
            "project not found",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Run `surge` and configure the domain.",
    },
    {
        "service": "GitHub Pages",
        "cname": [r"\.github\.io", r"\.github\.com"],
        "fingerprints": [
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": False,
        "notes": "Create a GitHub repo named <subdomain> under the organization and enable Pages.",
    },
    {
        "service": "GitLab Pages",
        "cname": [r"\.gitlab\.io"],
        "fingerprints": [
            "The page you're looking for could not be found",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a GitLab project and enable Pages with that custom domain.",
    },
    {
        "service": "Bitbucket",
        "cname": [r"\.bitbucket\.io"],
        "fingerprints": [
            "Repository not found",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Bitbucket repository with the matching name.",
    },
    # ─── CDN ──────────────────────────────────────────────────────────────────
    {
        "service": "Fastly",
        "cname": [r"\.fastly\.net", r"\.fastlylb\.net"],
        "fingerprints": [
            "Fastly error: unknown domain",
            "Please check that this domain has been added to a service",
        ],
        "headers": {},
        "status_codes": [500],
        "nxdomain": False,
        "notes": "Create a Fastly service with the custom domain.",
    },
    {
        "service": "Pantheon",
        "cname": [r"\.pantheonsite\.io", r"\.pantheon\.io"],
        "fingerprints": [
            "The gods are wise, but do not know of the site which you seek",
            "404 - Page Not Found",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Register a Pantheon site with the matching domain.",
    },
    {
        "service": "Cloudflare Pages",
        "cname": [r"\.pages\.dev"],
        "fingerprints": [
            "uh oh",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Cloudflare Pages project with that name.",
    },
    # ─── SaaS / CMS / Support ─────────────────────────────────────────────────
    {
        "service": "Shopify",
        "cname": [r"\.myshopify\.com"],
        "fingerprints": [
            "Sorry, this shop is currently unavailable.",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": False,
        "notes": "Create a Shopify store with the matching name.",
    },
    {
        "service": "Squarespace",
        "cname": [r"\.squarespace\.com"],
        "fingerprints": [
            "No Such Account",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": False,
        "notes": "Create a Squarespace site and map the custom domain.",
    },
    {
        "service": "WordPress.com",
        "cname": [r"\.wordpress\.com"],
        "fingerprints": [
            "Do you want to register",
            "doesn't exist",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": False,
        "notes": "Register a WordPress.com blog with that name.",
    },
    {
        "service": "Ghost (Pro)",
        "cname": [r"\.ghost\.io"],
        "fingerprints": [
            "The thing you were looking for is no longer here",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Ghost(Pro) site with the matching name.",
    },
    {
        "service": "Webflow",
        "cname": [r"\.webflow\.io"],
        "fingerprints": [
            "The page you are looking for doesn't exist or has been moved",
            "Page not found",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Webflow project and configure the custom domain.",
    },
    {
        "service": "Tumblr",
        "cname": [r"\.tumblr\.com"],
        "fingerprints": [
            "There's nothing here.",
            "Whatever you were looking for doesn't currently exist at this address",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": False,
        "notes": "Create a Tumblr blog and configure the custom domain.",
    },
    {
        "service": "Zendesk",
        "cname": [r"\.zendesk\.com"],
        "fingerprints": [
            "Help Center Closed",
            "this page is temporarily unavailable",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": False,
        "notes": "Create a Zendesk account and configure the help center.",
    },
    {
        "service": "HubSpot",
        "cname": [r"\.hubspot\.com", r"\.hs-sites\.com", r"\.hubspotpagebuilder\.com"],
        "fingerprints": [
            "Domain not found",
            "does not exist in our system",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a HubSpot portal and configure the domain.",
    },
    {
        "service": "Intercom",
        "cname": [r"\.intercom\.io", r"\.intercomcdn\.com"],
        "fingerprints": [
            "This page is reserved for artistic dogs.",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create an Intercom workspace and configure the Help Center.",
    },
    {
        "service": "UserVoice",
        "cname": [r"\.uservoice\.com"],
        "fingerprints": [
            "This UserVoice subdomain is currently available",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Register a UserVoice account with the matching subdomain.",
    },
    {
        "service": "Desk.com",
        "cname": [r"\.desk\.com"],
        "fingerprints": [
            "Please try again or try Desk.com free for",
            "Sorry, we couldn&#8217;t find that page",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Desk.com (Salesforce) service — register the matching subdomain.",
    },
    {
        "service": "Freshdesk",
        "cname": [r"\.freshdesk\.com"],
        "fingerprints": [
            "There is no helpdesk configured at this address",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Freshdesk portal with the matching domain.",
    },
    {
        "service": "Helpjuice",
        "cname": [r"\.helpjuice\.com"],
        "fingerprints": [
            "We could not find what you're looking for",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Helpjuice account with the matching subdomain.",
    },
    {
        "service": "Help Scout",
        "cname": [r"\.helpscoutdocs\.com"],
        "fingerprints": [
            "No settings were found for this company",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Help Scout docs site with the matching domain.",
    },
    {
        "service": "StatusPage (Atlassian)",
        "cname": [r"\.statuspage\.io"],
        "fingerprints": [
            "Better Status Communication",
            "is not a registered statuspage.io domain",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a StatusPage.io page with the matching domain.",
    },
    {
        "service": "Pingdom",
        "cname": [r"\.pingdom\.com"],
        "fingerprints": [
            "Sorry, couldn't find the status page",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Pingdom public status page with the matching domain.",
    },
    {
        "service": "Campaign Monitor",
        "cname": [r"\.createsend\.com", r"\.campaignmonitor\.com"],
        "fingerprints": [
            "Double check the URL or",
            "Trying to access your account?",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Campaign Monitor account with the matching domain.",
    },
    {
        "service": "Mailchimp / Mandrill",
        "cname": [r"\.list-manage\.com", r"\.mailchimpapp\.com"],
        "fingerprints": [
            "Looks like you've stumbled upon a page that doesn't exist",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Mailchimp list or campaign landing page.",
    },
    {
        "service": "Unbounce",
        "cname": [r"\.unbounce\.com"],
        "fingerprints": [
            "The requested URL was not found on this server",
        ],
        "headers": {},
        "status_codes": [404, 410],
        "nxdomain": True,
        "notes": "Create an Unbounce landing page with the matching domain.",
    },
    {
        "service": "ReadTheDocs",
        "cname": [r"\.readthedocs\.io", r"\.readthedocs\.org"],
        "fingerprints": [
            "unknown to Read the Docs",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a ReadTheDocs project with the matching slug.",
    },
    {
        "service": "Acquia",
        "cname": [r"\.acquia-sites\.com"],
        "fingerprints": [
            "If you are an Acquia Cloud customer and expect to see your site at this address",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Configure an Acquia site with the matching domain.",
    },
    {
        "service": "WP Engine",
        "cname": [r"\.wpengine\.com"],
        "fingerprints": [
            "The site you were looking for couldn&#8217;t be found",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a WP Engine site with the matching install name.",
    },
    {
        "service": "Kinsta",
        "cname": [r"\.kinsta\.cloud"],
        "fingerprints": [
            "No Site For Domain",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Kinsta site and configure the custom domain.",
    },
    {
        "service": "Strikingly",
        "cname": [r"\.strikingly\.com", r"s\.strikinglydns\.com"],
        "fingerprints": [
            "But if you're looking to build your own website",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Strikingly site and configure the domain.",
    },
    {
        "service": "Wix",
        "cname": [r"\.wixdns\.net", r"\.wix\.com"],
        "fingerprints": [
            "Looks like this domain isn&#39;t connected to a website yet",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": False,
        "notes": "Connect the domain to a Wix website.",
    },
    {
        "service": "Aftership",
        "cname": [r"\.aftership\.com"],
        "fingerprints": [
            "Oops.",
            "The page you&#8217;re looking for doesn&#8217;t exist",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create an Aftership tracking page with that domain.",
    },
    {
        "service": "Tilda",
        "cname": [r"\.tilda\.ws"],
        "fingerprints": [
            "Domain is not connected to any project",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Tilda project and connect the domain.",
    },
    {
        "service": "Cargo Collective",
        "cname": [r"\.cargocollective\.com"],
        "fingerprints": [
            "404 Not Found",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Cargo Collective site with the matching domain.",
    },
    {
        "service": "Kajabi",
        "cname": [r"\.kajabi\.com", r"\.kajabi-cdn\.com"],
        "fingerprints": [
            "404 - Page Not Found",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Kajabi site and configure the custom domain.",
    },
    {
        "service": "Thinkific",
        "cname": [r"\.thinkific\.com"],
        "fingerprints": [
            "You may have mistyped the address or the page may have moved",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Thinkific school with the matching subdomain.",
    },
    {
        "service": "Feedpress",
        "cname": [r"\.feedpress\.me"],
        "fingerprints": [
            "The feed has not been found.",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Feedpress feed with the matching domain.",
    },
    {
        "service": "Smartling",
        "cname": [r"\.smartling\.com"],
        "fingerprints": [
            "Domain is not configured",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Configure a Smartling project with the matching domain.",
    },
    {
        "service": "LaunchRock",
        "cname": [r"\.launchrock\.com"],
        "fingerprints": [
            "It looks like you may have taken a wrong turn somewhere",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a LaunchRock page with the matching domain.",
    },
    {
        "service": "Bigcartel",
        "cname": [r"\.bigcartel\.com"],
        "fingerprints": [
            "An ACTIVE store was not found at this address",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": False,
        "notes": "Create a Big Cartel store with the matching subdomain.",
    },
    {
        "service": "Teamwork",
        "cname": [r"\.teamwork\.com"],
        "fingerprints": [
            "Oops - We didn&#8217;t find your site.",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Teamwork account with the matching subdomain.",
    },
    {
        "service": "SmugMug",
        "cname": [r"\.smugmug\.com"],
        "fingerprints": [
            "Page Not Found",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a SmugMug gallery with the matching custom domain.",
    },
    {
        "service": "Wishpond",
        "cname": [r"\.wishpond\.com"],
        "fingerprints": [
            "This page is no longer published",
        ],
        "headers": {},
        "status_codes": [404],
        "nxdomain": True,
        "notes": "Create a Wishpond landing page with the matching domain.",
    },
    # ─── Domain Parking / Expired ─────────────────────────────────────────────
    {
        "service": "Domain Parking / Sedo",
        "cname": [r"\.sedoparking\.com", r"\.sedo\.com"],
        "fingerprints": [
            "domain parking",
            "This domain may be for sale",
        ],
        "headers": {},
        "status_codes": [200],
        "nxdomain": False,
        "notes": "Domain is parked — CNAME target may be purchasable.",
    },
    {
        "service": "Uniregistry / GoDaddy Parked",
        "cname": [r"\.uniregistry\.com", r"\.godaddysites\.com"],
        "fingerprints": [
            "This domain is parked",
        ],
        "headers": {},
        "status_codes": [200],
        "nxdomain": False,
        "notes": "Domain is parked at registrar.",
    },
]

NXDOMAIN_TAKEOVER_SERVICES = [fp for fp in FINGERPRINTS if fp.get("nxdomain", False)]


# ──────────────────────────────────────────────────────────────────────────────
# Data models
# ──────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"   # Strong takeover signal (NXDOMAIN + known service)
    HIGH = "HIGH"           # HTTP fingerprint match
    MEDIUM = "MEDIUM"       # NXDOMAIN but service unknown / unverified
    LOW = "LOW"             # Suspicious but not confirmed
    INFO = "INFO"           # No issue found
    ERROR = "ERROR"         # Could not be scanned


SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
    Severity.ERROR: "magenta",
}


@dataclass
class DnsResult:
    cname_chain: list[str] = field(default_factory=list)
    a_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    final_cname: Optional[str] = None
    nxdomain: bool = False
    servfail: bool = False
    error: Optional[str] = None


@dataclass
class HttpResult:
    url: str = ""
    status_code: Optional[int] = None
    body_snippet: str = ""
    headers: dict = field(default_factory=dict)
    error: Optional[str] = None
    redirect_url: Optional[str] = None


@dataclass
class Finding:
    subdomain: str
    severity: Severity
    service: Optional[str]
    reason: str
    dns: DnsResult
    http_http: Optional[HttpResult] = None
    http_https: Optional[HttpResult] = None
    notes: str = ""
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# ──────────────────────────────────────────────────────────────────────────────
# DNS helpers
# ──────────────────────────────────────────────────────────────────────────────

RESOLVER = dns.asyncresolver.Resolver()
RESOLVER.timeout = 5
RESOLVER.lifetime = 10
RESOLVER.nameservers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]

MAX_CNAME_DEPTH = 15


async def resolve_cname_chain(name: str) -> list[str]:
    chain = []
    current = name.rstrip(".")
    seen = set()
    for _ in range(MAX_CNAME_DEPTH):
        if current in seen:
            break
        seen.add(current)
        try:
            answers = await RESOLVER.resolve(current, "CNAME")
            target = str(answers[0].target).rstrip(".")
            chain.append(target)
            current = target
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            break
    return chain


async def resolve_dns(subdomain: str) -> DnsResult:
    result = DnsResult()

    try:
        result.cname_chain = await resolve_cname_chain(subdomain)
        if result.cname_chain:
            result.final_cname = result.cname_chain[-1]
    except Exception as exc:
        result.error = f"CNAME resolution error: {exc}"

    for qtype in ("A", "AAAA"):
        try:
            answers = await RESOLVER.resolve(subdomain, qtype)
            for rr in answers:
                result.a_records.append(str(rr))
        except dns.resolver.NXDOMAIN:
            result.nxdomain = True
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NoNameservers:
            result.servfail = True
        except dns.exception.DNSException:
            pass

    if result.final_cname and not result.a_records:
        try:
            await RESOLVER.resolve(result.final_cname, "A")
        except dns.resolver.NXDOMAIN:
            result.nxdomain = True
        except Exception:
            pass

    try:
        answers = await RESOLVER.resolve(subdomain, "NS")
        result.ns_records = [str(rr).rstrip(".") for rr in answers]
    except Exception:
        pass

    try:
        answers = await RESOLVER.resolve(subdomain, "MX")
        result.mx_records = [str(rr.exchange).rstrip(".") for rr in answers]
    except Exception:
        pass

    return result


async def check_ns_dangling(ns_records: list[str]) -> list[str]:
    dangling = []
    for ns in ns_records:
        parts = ns.rstrip(".").split(".")
        if len(parts) < 2:
            continue
        ns_domain = ".".join(parts[-2:])
        try:
            await RESOLVER.resolve(ns_domain, "A")
        except dns.resolver.NXDOMAIN:
            dangling.append(ns)
        except Exception:
            pass
    return dangling


# ──────────────────────────────────────────────────────────────────────────────
# HTTP helpers
# ──────────────────────────────────────────────────────────────────────────────

BODY_SNIPPET_CHARS = 4096
REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


async def fetch_http(
    session: aiohttp.ClientSession, url: str, timeout: int
) -> HttpResult:
    result = HttpResult(url=url)
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers=REQUEST_HEADERS,
            allow_redirects=True,
            ssl=False,
        ) as resp:
            result.status_code = resp.status
            result.headers = dict(resp.headers)
            result.redirect_url = str(resp.url) if str(resp.url) != url else None
            try:
                body = await asyncio.wait_for(resp.text(errors="replace"), timeout=timeout)
                result.body_snippet = body[:BODY_SNIPPET_CHARS]
            except (asyncio.TimeoutError, Exception):
                result.body_snippet = ""
    except aiohttp.ClientConnectorError as exc:
        result.error = f"Connection error: {exc}"
    except asyncio.TimeoutError:
        result.error = "Timeout"
    except Exception as exc:
        result.error = str(exc)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Fingerprint matching
# ──────────────────────────────────────────────────────────────────────────────

def _cname_matches(cname: str, patterns: list[str]) -> bool:
    cname_lower = cname.lower()
    return any(re.search(pat, cname_lower, re.IGNORECASE) for pat in patterns)


def _body_matches(body: str, fingerprints: list[str]) -> bool:
    body_lower = body.lower()
    return any(fp.lower() in body_lower for fp in fingerprints)


def _header_matches(headers: dict, header_patterns: dict) -> bool:
    for key, pat in header_patterns.items():
        val = headers.get(key, headers.get(key.lower(), ""))
        if re.search(pat, val, re.IGNORECASE):
            return True
    return False


def _status_matches(status: Optional[int], expected: list[int]) -> bool:
    return status is not None and status in expected


def match_fingerprints(
    cname_chain: list[str],
    http_result: Optional[HttpResult],
    https_result: Optional[HttpResult],
) -> Optional[dict]:
    best = None
    all_cnames = " ".join(cname_chain).lower()

    for fp in FINGERPRINTS:
        cname_hit = any(
            re.search(pat, all_cnames, re.IGNORECASE) for pat in fp["cname"]
        )
        if not cname_hit:
            continue

        for http_res in [https_result, http_result]:
            if http_res is None or http_res.error:
                continue
            body_hit = _body_matches(http_res.body_snippet, fp["fingerprints"])
            status_hit = _status_matches(http_res.status_code, fp["status_codes"])
            header_hit = _header_matches(http_res.headers, fp.get("headers", {}))

            if body_hit or (status_hit and not fp["fingerprints"]) or header_hit:
                return {**fp, "_http_confirmed": True}

        if best is None:
            best = {**fp, "_http_confirmed": False}

    return best


# ──────────────────────────────────────────────────────────────────────────────
# Core scan logic per subdomain
# ──────────────────────────────────────────────────────────────────────────────

async def scan_subdomain(
    subdomain: str,
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    http_timeout: int,
) -> Finding:
    subdomain = subdomain.strip().lower()

    async with semaphore:
        dns_result = await resolve_dns(subdomain)

        dangling_ns = []
        if dns_result.ns_records:
            dangling_ns = await check_ns_dangling(dns_result.ns_records)

        http_result: Optional[HttpResult] = None
        https_result: Optional[HttpResult] = None

        has_resolution = (
            dns_result.a_records
            or dns_result.cname_chain
            or not dns_result.nxdomain
        )

        if has_resolution or dns_result.cname_chain:
            http_task = fetch_http(session, f"http://{subdomain}", http_timeout)
            https_task = fetch_http(session, f"https://{subdomain}", http_timeout)
            http_result, https_result = await asyncio.gather(
                http_task, https_task, return_exceptions=False
            )

        if dangling_ns:
            return Finding(
                subdomain=subdomain,
                severity=Severity.CRITICAL,
                service="NS Takeover",
                reason=(
                    f"NS records point to unregistered/non-resolving nameservers: "
                    f"{', '.join(dangling_ns)}"
                ),
                dns=dns_result,
                http_http=http_result,
                http_https=https_result,
                notes=(
                    "Register the nameserver domain(s) to take over all DNS for "
                    f"{subdomain}."
                ),
            )

        if dns_result.nxdomain and dns_result.cname_chain:
            fp_match = match_fingerprints(
                dns_result.cname_chain, http_result, https_result
            )
            if fp_match:
                return Finding(
                    subdomain=subdomain,
                    severity=Severity.CRITICAL,
                    service=fp_match["service"],
                    reason=(
                        f"CNAME chain {' -> '.join(dns_result.cname_chain)} resolves "
                        f"to NXDOMAIN and matches {fp_match['service']} fingerprint."
                    ),
                    dns=dns_result,
                    http_http=http_result,
                    http_https=https_result,
                    notes=fp_match.get("notes", ""),
                )
            return Finding(
                subdomain=subdomain,
                severity=Severity.MEDIUM,
                service=None,
                reason=(
                    f"CNAME chain {' -> '.join(dns_result.cname_chain)} ends in "
                    "NXDOMAIN. Service could not be identified."
                ),
                dns=dns_result,
                http_http=http_result,
                http_https=https_result,
            )

        if dns_result.cname_chain:
            fp_match = match_fingerprints(
                dns_result.cname_chain, http_result, https_result
            )
            if fp_match and fp_match.get("_http_confirmed"):
                return Finding(
                    subdomain=subdomain,
                    severity=Severity.HIGH,
                    service=fp_match["service"],
                    reason=(
                        f"HTTP response matches unclaimed-service fingerprint for "
                        f"{fp_match['service']} (CNAME → "
                        f"{dns_result.final_cname})."
                    ),
                    dns=dns_result,
                    http_http=http_result,
                    http_https=https_result,
                    notes=fp_match.get("notes", ""),
                )
            if fp_match:
                return Finding(
                    subdomain=subdomain,
                    severity=Severity.LOW,
                    service=fp_match["service"],
                    reason=(
                        f"CNAME chain matches {fp_match['service']} pattern, but "
                        "HTTP response did not confirm unclaimed state. Manual "
                        "verification recommended."
                    ),
                    dns=dns_result,
                    http_http=http_result,
                    http_https=https_result,
                    notes=fp_match.get("notes", ""),
                )

        if dns_result.nxdomain and not dns_result.cname_chain:
            return Finding(
                subdomain=subdomain,
                severity=Severity.LOW,
                service=None,
                reason="Subdomain resolves to NXDOMAIN with no CNAME. May be orphaned.",
                dns=dns_result,
                http_http=http_result,
                http_https=https_result,
            )

        if dns_result.servfail:
            return Finding(
                subdomain=subdomain,
                severity=Severity.ERROR,
                service=None,
                reason="DNS SERVFAIL — nameserver unreachable or misconfigured.",
                dns=dns_result,
                http_http=http_result,
                http_https=https_result,
            )

        return Finding(
            subdomain=subdomain,
            severity=Severity.INFO,
            service=None,
            reason="No takeover indicators detected.",
            dns=dns_result,
            http_http=http_result,
            http_https=https_result,
        )


# ──────────────────────────────────────────────────────────────────────────────
# Output helpers
# ──────────────────────────────────────────────────────────────────────────────

console = Console(highlight=False)


def build_results_table(findings: list[Finding]) -> Table:
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
        expand=True,
        title="[bold]Subdomain Takeover Scan Results[/bold]",
        title_justify="left",
    )
    table.add_column("Subdomain", style="bold", no_wrap=True, min_width=30)
    table.add_column("Severity", justify="center", min_width=10)
    table.add_column("Service", min_width=20)
    table.add_column("Reason", min_width=40)
    table.add_column("CNAME Target", min_width=30, overflow="fold")

    severity_order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.ERROR,
        Severity.INFO,
    ]

    sorted_findings = sorted(
        findings, key=lambda f: severity_order.index(f.severity)
    )

    for f in sorted_findings:
        if f.severity == Severity.INFO:
            continue
        color = SEVERITY_COLORS[f.severity]
        table.add_row(
            f.subdomain,
            f"[{color}]{f.severity.value}[/{color}]",
            f.service or "—",
            f.reason,
            f.dns.final_cname or (", ".join(f.dns.a_records[:2]) or "—"),
        )
    return table


def print_summary(findings: list[Finding], elapsed: float) -> None:
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    console.print()
    console.rule("[bold]Scan Summary[/bold]")
    console.print(f"  Total subdomains scanned : [bold]{len(findings)}[/bold]")
    console.print(f"  Time elapsed             : [bold]{elapsed:.1f}s[/bold]")
    console.print()
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        n = counts[sev]
        if n:
            color = SEVERITY_COLORS[sev]
            console.print(f"  [{color}]{sev.value:<10}[/{color}] : {n}")
    console.print(f"  {'INFO':<10} : {counts[Severity.INFO]} (clean)")
    if counts[Severity.ERROR]:
        console.print(
            f"  [magenta]{'ERROR':<10}[/magenta] : {counts[Severity.ERROR]} (scan errors)"
        )
    console.print()


def save_json(findings: list[Finding], path: str) -> None:
    data = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "total": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    console.print(f"[green]JSON results saved to {path}[/green]")


def save_csv(findings: list[Finding], path: str) -> None:
    fieldnames = [
        "subdomain", "severity", "service", "reason", "cname_chain",
        "final_cname", "a_records", "nxdomain", "http_status", "https_status",
        "notes", "scanned_at",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            writer.writerow({
                "subdomain": f.subdomain,
                "severity": f.severity.value,
                "service": f.service or "",
                "reason": f.reason,
                "cname_chain": " -> ".join(f.dns.cname_chain),
                "final_cname": f.dns.final_cname or "",
                "a_records": ", ".join(f.dns.a_records),
                "nxdomain": f.dns.nxdomain,
                "http_status": f.http_http.status_code if f.http_http else "",
                "https_status": f.http_https.status_code if f.http_https else "",
                "notes": f.notes,
                "scanned_at": f.scanned_at,
            })
    console.print(f"[green]CSV results saved to {path}[/green]")


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def load_subdomains(path: str) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        lines = [
            line.strip()
            for line in fh
            if line.strip() and not line.startswith("#")
        ]
    valid = []
    for line in lines:
        if "://" in line:
            parsed = urlparse(line)
            line = parsed.netloc or parsed.path
        line = line.split("/")[0].strip().lower()
        if line and "." in line:
            valid.append(line)
    return valid


async def run_scan(
    subdomains: list[str],
    concurrency: int,
    http_timeout: int,
) -> list[Finding]:
    semaphore = asyncio.Semaphore(concurrency)

    connector = aiohttp.TCPConnector(
        limit=concurrency,
        ssl=False,
        force_close=True,
        enable_cleanup_closed=True,
    )

    findings: list[Finding] = []

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    )

    async with aiohttp.ClientSession(connector=connector) as session:
        with progress:
            task_id = progress.add_task(
                "[cyan]Scanning subdomains...", total=len(subdomains)
            )

            async def scan_and_track(sub: str) -> Finding:
                finding = await scan_subdomain(sub, session, semaphore, http_timeout)
                progress.advance(task_id)
                if finding.severity not in (Severity.INFO, Severity.ERROR):
                    color = SEVERITY_COLORS[finding.severity]
                    progress.console.print(
                        f"  [{color}][{finding.severity.value}][/{color}] "
                        f"[bold]{finding.subdomain}[/bold] — "
                        f"{finding.service or 'Unknown'}: {finding.reason}"
                    )
                return finding

            tasks = [scan_and_track(sub) for sub in subdomains]
            findings = await asyncio.gather(*tasks)

    return list(findings)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Subdomain Takeover Scanner — checks a list of subdomains for takeover vulnerabilities.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py subdomains.txt
  python scanner.py subdomains.txt -o results.json --csv results.csv
  python scanner.py subdomains.txt --concurrency 50 --timeout 10 --verbose
  python scanner.py subdomains.txt --only-vulnerable
""",
    )
    parser.add_argument("input", help="Path to file containing subdomains (one per line)")
    parser.add_argument("-o", "--output", metavar="FILE", help="Save results to JSON file")
    parser.add_argument("--csv", metavar="FILE", help="Save results to CSV file")
    parser.add_argument("--concurrency", type=int, default=30, metavar="N",
                        help="Number of concurrent scans (default: 30)")
    parser.add_argument("--timeout", type=int, default=10, metavar="SECS",
                        help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("--only-vulnerable", action="store_true",
                        help="Only show CRITICAL/HIGH/MEDIUM findings in output")
    parser.add_argument("--verbose", action="store_true",
                        help="Show all findings including INFO/ERROR")
    parser.add_argument("--no-table", action="store_true",
                        help="Skip printing the results table (useful for very large scans)")

    args = parser.parse_args()

    if not Path(args.input).exists():
        console.print(f"[red]Error:[/red] File not found: {args.input}")
        sys.exit(1)

    subdomains = load_subdomains(args.input)
    if not subdomains:
        console.print("[red]Error:[/red] No valid subdomains found in input file.")
        sys.exit(1)

    console.print(
        Panel(
            f"[bold cyan]Subdomain Takeover Scanner[/bold cyan]\n"
            f"Loaded [bold]{len(subdomains)}[/bold] subdomains · "
            f"concurrency=[bold]{args.concurrency}[/bold] · "
            f"timeout=[bold]{args.timeout}s[/bold]",
            expand=False,
        )
    )

    start = time.monotonic()
    findings = asyncio.run(run_scan(subdomains, args.concurrency, args.timeout))
    elapsed = time.monotonic() - start

    if not args.no_table:
        vuln_findings = [
            f for f in findings if f.severity not in (Severity.INFO, Severity.ERROR)
        ]
        if vuln_findings:
            console.print()
            console.print(build_results_table(findings))
        else:
            console.print("\n[green]No takeover vulnerabilities detected.[/green]\n")

    if args.verbose:
        for f in findings:
            if f.severity in (Severity.ERROR,):
                console.print(
                    f"  [magenta][ERROR][/magenta] {f.subdomain} — {f.reason}"
                )

    print_summary(findings, elapsed)

    if args.output:
        save_json(findings, args.output)
    if args.csv:
        save_csv(findings, args.csv)


if __name__ == "__main__":
    main()
