#!/usr/bin/env python3
"""
cloud_enum2 — Comprehensive multi-cloud asset enumeration
Covers: AWS, Azure, GCP, Alibaba, DigitalOcean, Cloudflare, IBM, Oracle,
        GitHub/GitLab Pages, Vercel, Netlify, Heroku, Render, Fly.io,
        Supabase, Snowflake, JFrog, Atlassian, Zendesk, Shopify, and more.
        Also queries Certificate Transparency logs.

Usage: python3 cloud_enum2.py -k keyword [-k keyword2 ...] [options]
Deps:  pip install aiohttp dnspython
"""

import argparse
import asyncio
import csv as csvmod
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    import aiohttp
except ImportError:
    sys.exit("[!] Missing dep: pip install aiohttp")

try:
    import dns.resolver
    import dns.exception
except ImportError:
    sys.exit("[!] Missing dep: pip install dnspython")

# ── ANSI ──────────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def pub(t):  return f"{GREEN}{BOLD}[PUBLIC]   {t}{RESET}"
def prot(t): return f"{YELLOW}{BOLD}[AUTH]     {t}{RESET}"
def inf(t):  return f"{CYAN}[*] {t}{RESET}"

# ── MUTATIONS ─────────────────────────────────────────────────────────────────
_RAW_MUTATIONS = [
    # Numbers
    "0","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15",
    "01","02","03","04","05","06","07","08","09",
    "001","002","003","100","200","123","1234",
    "2015","2016","2017","2018","2019","2020","2021","2022","2023","2024","2025","2026",
    # Environments
    "dev","develop","development","developer","devops","devenv",
    "stage","staging","stg","stag",
    "prod","production","prd","live",
    "test","testing","tst","qa","uat","sit","sqa","qe",
    "demo","sandbox","sbx","lab","labs","poc","spike","prototype","proto",
    "alpha","beta","gamma","rc","release","nightly","preview","canary",
    "preprod","pre-prod","pre","hotfix","fix","patch",
    "local","int","integration","nonprod","lower",
    "v1","v2","v3","v4","v5","v6","v7","v8","v9","v10",
    "old","new","legacy","archive","temp","tmp","wip","draft",
    # Regions / geo
    "us","eu","uk","de","fr","jp","au","ca","br","in","sg","kr","cn","hk","tw",
    "east","west","north","south","central","global","worldwide",
    "us-east","us-west","eu-west","eu-central","ap-south","ap-southeast","ap-northeast",
    "us-east-1","us-east-2","us-west-1","us-west-2",
    "eu-west-1","eu-west-2","eu-west-3","eu-central-1","eu-north-1",
    "ap-southeast-1","ap-southeast-2","ap-northeast-1","ap-south-1",
    "sa-east-1","ca-central-1","me-south-1","af-south-1",
    "eastus","westus","westus2","centralus","northcentralus","southcentralus","eastus2",
    "westeurope","northeurope","uksouth","ukwest",
    "australiaeast","japaneast","southeastasia","eastasia","brazilsouth",
    "us-central1","us-east1","us-west1","us-west2","us-west3","us-west4",
    "europe-west1","europe-west2","europe-west3","europe-west4",
    "asia-east1","asia-northeast1","asia-southeast1","asia-south1",
    "southamerica-east1","australia-southeast1",
    # Infra / app tiers
    "api","app","web","www","mobile","m","wap","srv","svc","service","services",
    "cdn","edge","static","assets","media","images","img","icons","fonts",
    "files","uploads","downloads","attachments","content","resources","public",
    "backend","frontend","bff","gateway","proxy","lb","load","internal","private",
    "admin","portal","dashboard","console","panel","mgmt","management","control","ops",
    "auth","login","sso","oauth","identity","idp","iam","saml","okta",
    "support","help","docs","doc","documentation","wiki","kb","helpdesk",
    "mail","email","mx","smtp","ses","postfix",
    "ftp","sftp","ssh","vpn","bastion","jump","remote",
    # Data / storage
    "data","database","db","sql","mysql","postgres","postgresql","mssql","oracle","mongo",
    "redis","cache","elastic","elasticsearch","opensearch","solr","cassandra","dynamo",
    "etl","dw","dwh","warehouse","lake","datalake","lakehouse","delta","iceberg",
    "analytics","bi","reporting","tableau","powerbi","metabase","grafana","kibana","superset",
    "logs","logging","metrics","monitoring","tracing","observability","telemetry","apm",
    "backup","backups","cold","dr","disaster","recovery","snapshot","restore",
    "s3","gcs","blob","bucket","buckets","storage","object","objects","store","share","shares",
    "bigquery","bq","dataflow","datafactory","pipeline","kafka","kinesis","pubsub","sqs","sns",
    "dfs","adls","raw","bronze","silver","gold","curated","processed","ingest","ingestion",
    # Security
    "secret","secrets","password","passwords","passwd","creds","credentials","keys","key",
    "cert","certs","certificates","tls","ssl","pki","ca","vault","kv","hsm","keystore",
    "private","internal","confidential","sensitive","secure","security","protected",
    "scan","siem","soc","threat","ids","ips","waf","iam","rbac","policy","policies","audit",
    # DevOps / CI-CD
    "ci","cd","cicd","build","builds","deploy","deployment","release","releases","artifact","artifacts",
    "jenkins","gitlab","github","bitbucket","bamboo","teamcity","drone","circle","travis","actions",
    "terraform","tfstate","tf","ansible","puppet","chef","salt","saltstack","packer","crossplane",
    "vault","nomad","consul","helm","argo","argocd","flux","fluxcd","tekton","spinnaker",
    "docker","containers","container","registry","images","repo","repository","packages",
    "k8s","kubernetes","kube","eks","aks","gke","rancher","openshift","tanzu",
    "sonar","sonarqube","nexus","artifactory","jfrog","harbor","quay",
    # Cloud services
    "aws","azure","gcp","google","amazon","microsoft","ibm","oracle","alibaba","aliyun",
    "lambda","functions","serverless","faas","event","events","trigger","workflow","step",
    "ec2","vm","vms","compute","instance","instances","cluster","clusters","node","nodes",
    "ecs","fargate","batch","glue","emr","databricks","spark","flink","beam",
    "sagemaker","ml","mlops","ai","aiml","model","models","training","inference","llm","nlp","cv",
    "iot","edge","greengrass","iotcore","iotedge",
    # Teams / orgs / products
    "corp","co","inc","ltd","llc","group","org","foundation","labs","studio","ventures",
    "team","teams","dept","it","infra","infrastructure","platform","eng","engineering",
    "research","science","ds","ml","ai","finance","hr","legal","compliance","risk",
    "product","design","ux","ui","creative","marketing","sales","business","cx","success",
    "mobile","ios","android","web","desktop","embedded","firmware","hardware",
    # Single letters / combos
    "a","b","c","d","e","f","g","h","i","j","k","l","n","p","q","r","s","t","u","x","y","z",
    "aa","ab","ac","ad","ae","bb","cc","dd","ee","ff","gg","hh","ii","jj","kk","ll","mm","nn","pp","rr","ss","tt",
    # Misc
    "primary","secondary","tertiary","replica","master","slave","follower","leader","main",
    "test1","test2","test3","dev1","dev2","dev3","staging1","prod1","prod2","app1","app2",
    "io","net","cloud","online","digital","tech","software","platform","solution","solutions",
    "client","server","host","hosts","node","worker","agent","daemon","bot","job","task",
    "queue","topic","stream","feed","message","notification","alert","webhook","event",
    "config","configuration","settings","env","variables","params","schema","entity","record",
    "user","users","account","accounts","profile","member","customer","customers","tenant",
    "order","payment","billing","invoice","subscription","transaction","report","history",
    "search","query","index","catalog","inventory","product","products","item","items",
    "map","geo","location","spatial","video","audio","stream","media","cdn","delivery",
]

_seen: set = set()
MUTATIONS: List[str] = [
    x for x in _RAW_MUTATIONS if not (_seen.add(x) if x not in _seen else True)
]

# ── REGIONS ───────────────────────────────────────────────────────────────────
AWS_REGIONS = [
    "us-east-1","us-east-2","us-west-1","us-west-2",
    "ca-central-1","ca-west-1",
    "eu-west-1","eu-west-2","eu-west-3","eu-central-1","eu-central-2",
    "eu-north-1","eu-south-1","eu-south-2",
    "ap-southeast-1","ap-southeast-2","ap-southeast-3","ap-southeast-4",
    "ap-northeast-1","ap-northeast-2","ap-northeast-3",
    "ap-south-1","ap-south-2","ap-east-1",
    "sa-east-1","me-south-1","me-central-1","af-south-1","il-central-1",
]
AWS_KEY_REGIONS = ["us-east-1","us-west-2","eu-west-1","ap-southeast-1","eu-central-1"]

AZURE_REGIONS = [
    "eastus","eastus2","westus","westus2","westus3",
    "centralus","northcentralus","southcentralus","westcentralus",
    "northeurope","westeurope","uksouth","ukwest","francecentral","francesouth",
    "germanywestcentral","switzerlandnorth","norwayeast","swedencentral","polandcentral",
    "australiaeast","australiasoutheast","japaneast","japanwest",
    "koreacentral","eastasia","southeastasia","southafricanorth",
    "brazilsouth","canadacentral","canadaeast",
    "uaenorth","qatarcentral","centralindia","southindia",
]

GCP_REGIONS = [
    "us-central1","us-east1","us-east4","us-east5","us-south1",
    "us-west1","us-west2","us-west3","us-west4",
    "northamerica-northeast1","northamerica-northeast2",
    "southamerica-east1","southamerica-west1",
    "europe-central2","europe-north1","europe-southwest1",
    "europe-west1","europe-west2","europe-west3","europe-west4",
    "europe-west6","europe-west8","europe-west9",
    "asia-east1","asia-east2",
    "asia-northeast1","asia-northeast2","asia-northeast3",
    "asia-south1","asia-south2",
    "asia-southeast1","asia-southeast2",
    "australia-southeast1","australia-southeast2",
    "me-central1","me-west1","africa-south1",
]

DO_REGIONS = ["nyc3","nyc1","sfo3","sfo2","ams3","sgp1","lon1","fra1","tor1","blr1","syd1"]

ALIYUN_REGIONS = [
    "oss-cn-hangzhou","oss-cn-shanghai","oss-cn-beijing","oss-cn-shenzhen",
    "oss-cn-hongkong","oss-us-west-1","oss-us-east-1","oss-ap-southeast-1",
    "oss-ap-northeast-1","oss-eu-central-1","oss-me-east-1",
]

# ── RESULTS ───────────────────────────────────────────────────────────────────
RESULTS: List[Dict] = []
_log_fh = None
_log_fmt = "text"

def record(platform: str, service: str, target: str, access: str) -> None:
    entry = {"platform": platform, "service": service, "target": target, "access": access}
    RESULTS.append(entry)
    if access == "public":
        print(pub(f"{platform}/{service}: {target}"))
    else:
        print(prot(f"{platform}/{service}: {target}"))
    if _log_fh and _log_fmt == "text":
        _log_fh.write(f"{access.upper()} | {platform}/{service} | {target}\n")
        _log_fh.flush()
    elif _log_fh and _log_fmt == "json":
        _log_fh.write(json.dumps(entry) + "\n")
        _log_fh.flush()

# ── HTTP ──────────────────────────────────────────────────────────────────────
_TIMEOUT = aiohttp.ClientTimeout(total=10, connect=5)
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; cloud-enum/2.0; +github.com/initstring/cloud_enum)"}

async def hget(
    session: aiohttp.ClientSession,
    url: str,
    allow_redirects: bool = True,
) -> Optional[Tuple[int, dict, str]]:
    try:
        async with session.get(
            url, timeout=_TIMEOUT, headers=_HEADERS,
            allow_redirects=allow_redirects, ssl=False,
        ) as r:
            body = await r.text(errors="replace")
            return r.status, dict(r.headers), body
    except Exception:
        return None

async def hget_batch(
    session: aiohttp.ClientSession,
    items: List[Tuple[str, callable]],
    concurrency: int = 50,
) -> None:
    sem = asyncio.Semaphore(concurrency)
    async def _one(url, cb):
        async with sem:
            result = await hget(session, url)
            if result:
                cb(url, *result)
    await asyncio.gather(*[_one(u, cb) for u, cb in items], return_exceptions=True)

# ── DNS ───────────────────────────────────────────────────────────────────────
def _dns_resolves(args: Tuple) -> Optional[str]:
    hostname, resolver = args
    try:
        resolver.resolve(hostname, "A")
        return hostname
    except Exception:
        try:
            resolver.resolve(hostname, "CNAME")
            return hostname
        except Exception:
            return None

def dns_bulk(names: List[str], resolver, threads: int) -> List[str]:
    if not names:
        return []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        results = list(ex.map(_dns_resolves, [(n, resolver) for n in names]))
    return [r for r in results if r]

# ── NAME GENERATION ───────────────────────────────────────────────────────────
_CLEAN_RE = re.compile(r"[^a-z0-9\-]")
_CLEAN_DOT_RE = re.compile(r"[^a-z0-9\-\.]")

def build_names(keywords: List[str], allow_dots: bool = False) -> List[str]:
    pattern = _CLEAN_DOT_RE if allow_dots else _CLEAN_RE
    names: set = set()
    for kw in keywords:
        kw = kw.lower().strip()
        names.add(kw)
        for m in MUTATIONS:
            for combo in [
                f"{kw}{m}", f"{kw}-{m}",
                f"{m}{kw}", f"{m}-{kw}",
            ]:
                c = pattern.sub("", combo.lower())
                if 3 <= len(c) <= 63:
                    names.add(c)
    return sorted(names)

def nodot(names: List[str]) -> List[str]:
    return [n for n in names if "." not in n]

# ── PROGRESS ──────────────────────────────────────────────────────────────────
def banner(msg: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─'*64}{RESET}")
    print(f"{BOLD}{CYAN}  {msg}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*64}{RESET}")

def prog(cur: int, tot: int, label: str = "") -> None:
    pct = int(cur / max(tot, 1) * 40)
    bar = "█" * pct + "░" * (40 - pct)
    print(f"\r  {label}[{bar}] {cur}/{tot}  ", end="", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
#  AWS
# ══════════════════════════════════════════════════════════════════════════════
async def check_aws(session, names, resolver, threads):
    banner("Amazon Web Services")

    # ── S3 global ──
    print(inf(f"S3 (global) — {len(names):,} names"))
    total = len(names)
    for i in range(0, total, 60):
        prog(i, total, "S3  ")
        await asyncio.gather(*[_s3_check(session, n) for n in names[i:i+60]])
    prog(total, total, "S3  "); print()

    # ── S3 regional (key regions only) ──
    print(inf(f"S3 (regional, {len(AWS_KEY_REGIONS)} key regions) — {len(names):,} names"))
    for region in AWS_KEY_REGIONS:
        for i in range(0, total, 60):
            await asyncio.gather(*[_s3_regional_check(session, n, region) for n in names[i:i+60]])

    # ── Elastic Beanstalk ──
    print(inf(f"Elastic Beanstalk — {len(names):,} × {len(AWS_KEY_REGIONS)} regions"))
    eb = [f"{n}.{r}.elasticbeanstalk.com" for n in names for r in AWS_KEY_REGIONS]
    for h in dns_bulk(eb, resolver, threads):
        record("aws", "elastic-beanstalk", f"http://{h}", "public")

    # ── CloudFront ──
    print(inf(f"CloudFront — {len(names):,} names"))
    cf = [f"{n}.cloudfront.net" for n in names]
    for h in dns_bulk(cf, resolver, threads):
        record("aws", "cloudfront", f"https://{h}", "public")

    # ── Amplify ──
    print(inf(f"Amplify — {len(names):,} names"))
    amp = [f"{n}.amplifyapp.com" for n in names]
    for h in dns_bulk(amp, resolver, threads):
        record("aws", "amplify", f"https://{h}", "public")

    # ── awsapps (WorkMail, WorkDocs, Connect) ──
    print(inf(f"AWS Apps — {len(names):,} names"))
    awsapp = [f"{n}.awsapps.com" for n in names]
    for h in dns_bulk(awsapp, resolver, threads):
        record("aws", "awsapps", f"https://{h}", "public")

    # ── OpenSearch ──
    print(inf(f"OpenSearch/ES — {len(names):,} × {len(AWS_KEY_REGIONS)} regions"))
    es = [f"{n}.{r}.es.amazonaws.com" for n in names for r in AWS_KEY_REGIONS]
    for h in dns_bulk(es, resolver, threads):
        record("aws", "opensearch", f"https://{h}", "auth")

    # ── Cognito ──
    print(inf(f"Cognito — {len(names):,} × {len(AWS_KEY_REGIONS)} regions"))
    cog = [f"{n}.auth.{r}.amazoncognito.com" for n in names for r in AWS_KEY_REGIONS]
    for h in dns_bulk(cog, resolver, threads):
        record("aws", "cognito", f"https://{h}", "public")

    # ── Lightsail ──
    print(inf(f"Lightsail — {len(names):,} × key regions"))
    lsl = [f"{n}.{r}.cs.amazonlightsail.com" for n in names for r in AWS_KEY_REGIONS]
    for h in dns_bulk(lsl, resolver, threads):
        record("aws", "lightsail", f"https://{h}", "public")

    # ── SageMaker Studio ──
    print(inf(f"SageMaker Studio — {len(names):,} × key regions"))
    smk = [f"{n}.studio.{r}.sagemaker.aws" for n in names for r in AWS_KEY_REGIONS]
    for h in dns_bulk(smk, resolver, threads):
        record("aws", "sagemaker", f"https://{h}", "auth")

    # ── API Gateway (execute-api) ──
    print(inf(f"API Gateway execute-api — {len(names):,} names"))
    apigw = [f"{n}.execute-api.{r}.amazonaws.com" for n in names for r in AWS_KEY_REGIONS]
    for h in dns_bulk(apigw[:3000], resolver, threads):
        record("aws", "api-gateway", f"https://{h}", "public")


async def _s3_check(session, name):
    url = f"https://{name}.s3.amazonaws.com"
    r = await hget(session, url)
    if not r: return
    status, hdrs, body = r
    if status == 200:
        record("aws", "s3", url, "public")
    elif status == 403 and "NoSuchBucket" not in body:
        record("aws", "s3", url, "auth")
    elif status == 301:
        record("aws", "s3", url, "auth")


async def _s3_regional_check(session, name, region):
    url = f"https://{name}.s3.{region}.amazonaws.com"
    r = await hget(session, url)
    if not r: return
    status, hdrs, body = r
    if status == 200:
        record("aws", f"s3-{region}", url, "public")
    elif status == 403 and "NoSuchBucket" not in body:
        record("aws", f"s3-{region}", url, "auth")


# ══════════════════════════════════════════════════════════════════════════════
#  AZURE
# ══════════════════════════════════════════════════════════════════════════════
_AZ_ALPHA = re.compile(r"[^a-z0-9]")

def _azure_names(names):
    seen: set = set()
    out = []
    for n in names:
        c = _AZ_ALPHA.sub("", n)
        if 3 <= len(c) <= 24 and c not in seen:
            seen.add(c)
            out.append(c)
    return out


async def check_azure(session, names, resolver, threads):
    banner("Microsoft Azure")
    an = _azure_names(names)

    # ── Storage services (DNS filter + HTTP classify) ──
    for svc, suffix in [
        ("blob",  "blob.core.windows.net"),
        ("file",  "file.core.windows.net"),
        ("queue", "queue.core.windows.net"),
        ("table", "table.core.windows.net"),
        ("dfs",   "dfs.core.windows.net"),
    ]:
        print(inf(f"Azure {svc} storage — {len(an):,} names"))
        resolved = dns_bulk([f"{n}.{suffix}" for n in an], resolver, threads)
        for h in resolved:
            r = await hget(session, f"https://{h}")
            if r:
                _az_classify(f"https://{h}", svc, r)

    # ── App Service / Functions ──
    print(inf(f"App Service / Functions — {len(names):,} names"))
    for h in dns_bulk([f"{n}.azurewebsites.net" for n in names], resolver, threads):
        record("azure", "app-service", f"https://{h}", "public")

    # ── SCM / Kudu ──
    print(inf(f"Kudu/SCM — {len(names):,} names"))
    for h in dns_bulk([f"{n}.scm.azurewebsites.net" for n in names], resolver, threads):
        record("azure", "kudu-scm", f"https://{h}", "public")

    # ── Container Registry ──
    print(inf(f"Container Registry — {len(names):,} names"))
    acr_resolved = dns_bulk([f"{n}.azurecr.io" for n in names], resolver, threads)
    for h in acr_resolved:
        r = await hget(session, f"https://{h}/v2/")
        if r:
            acc = "public" if r[0] == 200 else "auth"
            record("azure", "container-registry", f"https://{h}", acc)

    # ── CDN / Front Door / Traffic Manager ──
    for svc, suffix in [
        ("cdn",             "azureedge.net"),
        ("front-door",      "azurefd.net"),
        ("traffic-manager", "trafficmanager.net"),
    ]:
        print(inf(f"Azure {svc} — {len(names):,} names"))
        for h in dns_bulk([f"{n}.{suffix}" for n in names], resolver, threads):
            record("azure", svc, f"https://{h}", "public")

    # ── Key Vault ──
    print(inf(f"Key Vault — {len(an):,} names"))
    for h in dns_bulk([f"{n}.vault.azure.net" for n in an], resolver, threads):
        record("azure", "key-vault", f"https://{h}", "auth")

    # ── SQL / Cosmos / Redis / Service Bus ──
    for svc, suffix in [
        ("sql-db",      "database.windows.net"),
        ("cosmos-db",   "documents.azure.com"),
        ("redis",       "redis.cache.windows.net"),
        ("service-bus", "servicebus.windows.net"),
        ("iot-hub",     "azure-devices.net"),
        ("ai-search",   "search.windows.net"),
        ("signalr",     "service.signalr.net"),
        ("api-mgmt",    "azure-api.net"),
        ("openai",      "openai.azure.com"),
        ("cognitive",   "cognitiveservices.azure.com"),
        ("spring-apps", "azuremicroservices.io"),
        ("purview",     "purview.azure.com"),
        ("dev-tunnels", "devtunnels.ms"),
        ("digital-twins","digitaltwins.azure.net"),
        ("event-grid",  "eventgrid.azure.net"),
    ]:
        print(inf(f"Azure {svc} — {len(names):,} names"))
        for h in dns_bulk([f"{n}.{suffix}" for n in names], resolver, threads):
            record("azure", svc, f"https://{h}", "auth" if svc in ("key-vault","sql-db","cosmos-db","redis","service-bus","iot-hub") else "public")

    # ── Container Apps (regional) — top 8 regions ──
    print(inf(f"Container Apps — {len(names):,} × 8 regions"))
    ca = [f"{n}.{r}.azurecontainerapps.io" for n in names for r in AZURE_REGIONS[:8]]
    for h in dns_bulk(ca, resolver, threads):
        record("azure", "container-apps", f"https://{h}", "public")

    # ── VMs (regional) — top 12 regions ──
    print(inf(f"VMs — {len(names):,} × 12 regions"))
    vms = [f"{n}.{r}.cloudapp.azure.com" for n in names for r in AZURE_REGIONS[:12]]
    for h in dns_bulk(vms, resolver, threads):
        record("azure", "vm", h, "public")

    # ── Static Web Apps (regional) ──
    print(inf(f"Static Web Apps — {len(names):,} × 10 regions"))
    swa = [f"{n}.{r}.azurestaticapps.net" for n in names for r in AZURE_REGIONS[:10]]
    for h in dns_bulk(swa, resolver, threads):
        record("azure", "static-web-app", f"https://{h}", "public")

    # ── Managed Grafana ──
    print(inf(f"Managed Grafana — {len(names):,} × 5 regions"))
    mgf = [f"{n}.{r}.grafana.azure.com" for n in names for r in AZURE_REGIONS[:5]]
    for h in dns_bulk(mgf, resolver, threads):
        record("azure", "managed-grafana", f"https://{h}", "public")


def _az_classify(url: str, svc: str, r: Tuple) -> None:
    status, hdrs, body = r
    err = hdrs.get("x-ms-error-code", "") + body[:300]
    if any(x in err for x in ("ResourceNotFound", "BlobServiceProperties")):
        return
    if any(x in err for x in ("AuthenticationFailed", "NoAuthenticationInformation",
                               "Server failed to authenticate", "PublicAccessNotPermitted")):
        record("azure", svc, url, "auth")
    elif status == 200:
        record("azure", svc, url, "public")
    elif status in (400, 403, 409):
        record("azure", svc, url, "auth")


# ══════════════════════════════════════════════════════════════════════════════
#  GCP
# ══════════════════════════════════════════════════════════════════════════════
async def check_gcp(session, names, resolver, threads):
    banner("Google Cloud Platform")
    nd = nodot(names)

    # ── GCS ──
    print(inf(f"GCS buckets — {len(names):,} names"))
    total = len(names)
    for i in range(0, total, 60):
        prog(i, total, "GCS ")
        await asyncio.gather(*[_gcs_check(session, n) for n in names[i:i+60]])
    prog(total, total, "GCS "); print()

    # ── Firebase RTDB ──
    print(inf(f"Firebase RTDB — {len(nd):,} names"))
    for i in range(0, len(nd), 40):
        await asyncio.gather(*[_firebase_rtdb(session, n) for n in nd[i:i+40]])

    # ── Firebase Hosting (.web.app) ──
    print(inf(f"Firebase Hosting .web.app — {len(nd):,} names"))
    for h in dns_bulk([f"{n}.web.app" for n in nd], resolver, threads):
        record("gcp", "firebase-hosting", f"https://{h}", "public")

    # ── Firebase Hosting (.firebaseapp.com) ──
    print(inf(f"Firebase Hosting .firebaseapp.com — {len(nd):,} names"))
    for h in dns_bulk([f"{n}.firebaseapp.com" for n in nd], resolver, threads):
        record("gcp", "firebase-hosting", f"https://{h}", "public")

    # ── App Engine ──
    print(inf(f"App Engine — {len(nd):,} names"))
    for i in range(0, len(nd), 40):
        await asyncio.gather(*[_appengine_check(session, n) for n in nd[i:i+40]])

    # ── Cloud Functions ──
    print(inf(f"Cloud Functions — {len(nd):,} × {len(GCP_REGIONS[:8])} regions"))
    await _cloud_functions(session, nd[:500])

    # ── Cloud Run ──
    print(inf(f"Cloud Run — DNS probe"))
    run_sfx = ["uc.a","ue.a","uw.a","ew.a","an.a","as.a","ue4.a","uw1.a"]
    cr = [f"{n}.{s}.run.app" for n in nd for s in run_sfx]
    for h in dns_bulk(cr[:4000], resolver, threads):
        record("gcp", "cloud-run", f"https://{h}", "public")

    # ── GCR / Artifact Registry ──
    print(inf(f"Container Registry — {len(names[:200]):,} names"))
    for reg in ["gcr.io","us.gcr.io","eu.gcr.io","asia.gcr.io"]:
        for name in names[:200]:
            r = await hget(session, f"https://{reg}/v2/{name}/tags/list")
            if r and r[0] in (200, 401):
                access = "public" if r[0] == 200 else "auth"
                record("gcp", "container-registry", f"https://{reg}/{name}", access)

    # ── Cloud Endpoints ──
    print(inf(f"Cloud Endpoints — {len(nd):,} names"))
    for h in dns_bulk([f"{n}.endpoints.{n}.cloud.goog" for n in nd], resolver, threads):
        record("gcp", "cloud-endpoints", f"https://{h}", "public")

    # ── Looker ──
    print(inf(f"Looker — {len(names):,} names"))
    for h in dns_bulk([f"{n}.looker.com" for n in names], resolver, threads):
        record("gcp", "looker", f"https://{h}", "auth")


async def _gcs_check(session, name):
    url = f"https://storage.googleapis.com/{name}"
    r = await hget(session, url)
    if not r: return
    status, hdrs, body = r
    if status == 200:
        record("gcp", "gcs", url, "public")
    elif status == 403 and "NoSuchBucket" not in body:
        record("gcp", "gcs", url, "auth")


async def _firebase_rtdb(session, name):
    url = f"https://{name}.firebaseio.com/.json"
    r = await hget(session, url)
    if not r: return
    status, _, body = r
    if status == 200:
        record("gcp", "firebase-rtdb", url, "public")
    elif status in (401, 403):
        record("gcp", "firebase-rtdb", f"https://{name}.firebaseio.com", "auth")


async def _appengine_check(session, name):
    url = f"https://{name}.appspot.com"
    r = await hget(session, url, allow_redirects=False)
    if not r: return
    status, hdrs, body = r
    loc = hdrs.get("location", "")
    if status in (500, 503):
        record("gcp", "app-engine", url, "public")
    elif status in (200, 302, 301):
        if "accounts.google.com" not in loc + body:
            record("gcp", "app-engine", url, "public")
        else:
            record("gcp", "app-engine", url, "auth")
    elif status == 403:
        record("gcp", "app-engine", url, "auth")


async def _cloud_functions(session, names):
    key_regions = GCP_REGIONS[:8]
    active: List[Tuple[str, str]] = []
    # Phase 1
    for region in key_regions:
        for name in names[:300]:
            url = f"https://{region}-{name}.cloudfunctions.net"
            r = await hget(session, url, allow_redirects=False)
            if r and r[0] == 302:
                active.append((region, name))
    # Phase 2 — brute function names
    fn_words = [
        "main","index","api","handler","process","run","execute","trigger","webhook",
        "function","fn","func","app","service","worker","auth","login","logout",
        "signup","register","profile","user","admin","data","fetch","get","post",
        "update","delete","create","list","search","health","status","ping","info",
    ]
    for region, project in active:
        record("gcp", "cloud-functions", f"https://{region}-{project}.cloudfunctions.net", "public")
        for fn in fn_words:
            url = f"https://{region}-{project}.cloudfunctions.net/{fn}"
            r = await hget(session, url)
            if r and r[0] in (200, 401, 403, 405):
                acc = "public" if r[0] in (200, 405) else "auth"
                record("gcp", f"cloud-function:{fn}", url, acc)


# ══════════════════════════════════════════════════════════════════════════════
#  ALIBABA
# ══════════════════════════════════════════════════════════════════════════════
async def check_alibaba(session, names, resolver, threads):
    banner("Alibaba Cloud")

    # OSS (top 5 regions)
    print(inf(f"OSS — {len(names):,} × 5 regions"))
    for region in ALIYUN_REGIONS[:5]:
        for i in range(0, len(names), 40):
            await asyncio.gather(*[_oss_check(session, n, region) for n in names[i:i+40]])

    # Function Compute
    print(inf(f"Function Compute — {len(names):,} names"))
    for suffix in ["cn-hangzhou.fc.aliyuncs.com", "cn-shanghai.fc.aliyuncs.com"]:
        for h in dns_bulk([f"{n}.{suffix}" for n in names], resolver, threads):
            record("alibaba", "function-compute", f"https://{h}", "public")


async def _oss_check(session, name, region):
    url = f"https://{name}.{region}.aliyuncs.com"
    r = await hget(session, url)
    if not r: return
    status, _, body = r
    if status == 200:
        record("alibaba", f"oss", url, "public")
    elif status == 403 and "NoSuchBucket" not in body:
        record("alibaba", f"oss", url, "auth")


# ══════════════════════════════════════════════════════════════════════════════
#  DIGITALOCEAN
# ══════════════════════════════════════════════════════════════════════════════
async def check_digitalocean(session, names, resolver, threads):
    banner("DigitalOcean")

    print(inf(f"Spaces — {len(names):,} × {len(DO_REGIONS[:5])} regions"))
    for region in DO_REGIONS[:5]:
        for i in range(0, len(names), 40):
            await asyncio.gather(*[_spaces_check(session, n, region) for n in names[i:i+40]])

    print(inf(f"App Platform — {len(names):,} names"))
    for h in dns_bulk([f"{n}.ondigitalocean.app" for n in names], resolver, threads):
        record("digitalocean", "app-platform", f"https://{h}", "public")


async def _spaces_check(session, name, region):
    url = f"https://{name}.{region}.digitaloceanspaces.com"
    r = await hget(session, url)
    if not r: return
    status, _, body = r
    if status == 200:
        record("digitalocean", "spaces", url, "public")
    elif status == 403 and "NoSuchBucket" not in body:
        record("digitalocean", "spaces", url, "auth")


# ══════════════════════════════════════════════════════════════════════════════
#  CLOUDFLARE
# ══════════════════════════════════════════════════════════════════════════════
async def check_cloudflare(session, names, resolver, threads):
    banner("Cloudflare")
    nd = nodot(names)
    for svc, suffix in [("pages", "pages.dev"), ("workers", "workers.dev")]:
        print(inf(f"Cloudflare {svc} — {len(nd):,} names"))
        for h in dns_bulk([f"{n}.{suffix}" for n in nd], resolver, threads):
            record("cloudflare", svc, f"https://{h}", "public")


# ══════════════════════════════════════════════════════════════════════════════
#  IBM CLOUD
# ══════════════════════════════════════════════════════════════════════════════
async def check_ibm(session, names, resolver, threads):
    banner("IBM Cloud")
    nd = nodot(names)
    ibm_svcs = [
        ("cloud-foundry",       "mybluemix.net"),
        ("cloud-foundry-eu",    "eu-gb.mybluemix.net"),
        ("cloud-foundry-au",    "au-syd.mybluemix.net"),
        ("cloud-functions",     "us-south.functions.appdomain.cloud"),
        ("code-engine",         "us-south.codeengine.appdomain.cloud"),
        ("object-storage",      "s3.us.cloud-object-storage.appdomain.cloud"),
        ("watson",              "watsonplatform.net"),
    ]
    for svc, suffix in ibm_svcs:
        print(inf(f"IBM {svc} — {len(nd):,} names"))
        for h in dns_bulk([f"{n}.{suffix}" for n in nd], resolver, threads):
            record("ibm", svc, f"https://{h}", "public")


# ══════════════════════════════════════════════════════════════════════════════
#  ORACLE CLOUD
# ══════════════════════════════════════════════════════════════════════════════
async def check_oracle(session, names, resolver, threads):
    banner("Oracle Cloud")
    nd = nodot(names)
    oci_svcs = [
        ("object-storage",  "objectstorage.us-phoenix-1.oci.customer-oci.com"),
        ("object-storage",  "objectstorage.us-ashburn-1.oci.customer-oci.com"),
        ("functions",       "us-phoenix-1.functions.oci.oraclecloud.com"),
        ("autonomous-db",   "adb.us-phoenix-1.oraclecloudapps.com"),
        ("autonomous-db",   "adb.us-ashburn-1.oraclecloudapps.com"),
        ("apex",            "apex.oracle.com"),
    ]
    for svc, suffix in oci_svcs:
        ns = nd if len(suffix.split(".")) > 3 else names
        print(inf(f"Oracle {svc} — {len(ns[:500]):,} names"))
        for h in dns_bulk([f"{n}.{suffix}" for n in ns[:500]], resolver, threads):
            record("oracle", svc, f"https://{h}", "public")


# ══════════════════════════════════════════════════════════════════════════════
#  GENERIC SAAS / PAAS PLATFORMS
# ══════════════════════════════════════════════════════════════════════════════
PLATFORMS = [
    # (platform, service, suffix, filter_dots)
    ("github",       "pages",          "github.io",                   False),
    ("gitlab",       "pages",          "gitlab.io",                   False),
    ("vercel",       "app",            "vercel.app",                  True),
    ("netlify",      "site",           "netlify.app",                 True),
    ("heroku",       "app",            "herokuapp.com",               True),
    ("render",       "service",        "onrender.com",                True),
    ("railway",      "app",            "railway.app",                 True),
    ("fly-io",       "app",            "fly.dev",                     True),
    ("supabase",     "project",        "supabase.co",                 True),
    ("supabase",     "project-alt",    "supabase.in",                 True),
    ("planetscale",  "db",             "psdb.cloud",                  True),
    ("snowflake",    "account",        "snowflakecomputing.com",      False),
    ("grafana",      "cloud",          "grafana.net",                 True),
    ("jfrog",        "artifactory",    "jfrog.io",                    True),
    ("atlassian",    "jira-cloud",     "atlassian.net",               False),
    ("zendesk",      "support",        "zendesk.com",                 False),
    ("shopify",      "store",          "myshopify.com",               False),
    ("wordpress",    "hosted",         "wordpress.com",               False),
    ("pantheon",     "site",           "pantheonsite.io",             True),
    ("wpengine",     "site",           "wpengine.com",                True),
    ("kinsta",       "app",            "kinsta.cloud",                True),
    ("fastly",       "cdn",            "global.ssl.fastly.net",       False),
    ("firebase",     "web",            "firebaseapp.com",             True),
    ("hugging-face", "spaces",         "hf.space",                    True),
    ("streamlit",    "app",            "streamlit.app",               True),
    ("replit",       "app",            "repl.co",                     True),
    ("glitch",       "app",            "glitch.me",                   True),
    ("surge",        "site",           "surge.sh",                    False),
    ("github-pages", "io",             "github.io",                   False),
    ("azuredevops",  "org",            "visualstudio.com",            False),
    ("bitbucket",    "pages",          "bitbucket.io",                False),
    ("hashicorp",    "terraform-cloud","app.terraform.io",            False),
    ("elastic",      "cloud",          "elastic-cloud.com",           True),
    ("mongodb",      "atlas",          "mongodb.net",                 True),
    ("neon",         "postgres",       "neon.tech",                   True),
    ("cockroach",    "cloud",          "cockroachlabs.cloud",         True),
    ("upstash",      "redis",          "upstash.io",                  True),
    ("deno",         "deploy",         "deno.dev",                    True),
    ("workers-cf",   "workers-dev",    "workers.dev",                 True),
    ("pages-cf",     "pages-dev",      "pages.dev",                   True),
    ("azurestatic",  "web",            "azurestaticapps.net",         True),
    ("clever-cloud", "app",            "cleverapps.io",               True),
    ("scalingo",     "app",            "osc-fr1.scalingo.io",         True),
]


async def check_platforms(session, names, resolver, threads):
    banner("SaaS / PaaS Platforms")
    nd = nodot(names)
    for platform, svc, suffix, filter_dots in PLATFORMS:
        ns = nd if filter_dots else names
        if not ns: continue
        print(inf(f"{platform}/{svc} — {len(ns):,} names"))
        found = dns_bulk([f"{n}.{suffix}" for n in ns], resolver, threads)
        for h in found:
            record(platform, svc, f"https://{h}", "public")


# ══════════════════════════════════════════════════════════════════════════════
#  CERTIFICATE TRANSPARENCY
# ══════════════════════════════════════════════════════════════════════════════
async def check_ct(session, keywords):
    banner("Certificate Transparency (crt.sh)")
    found: set = set()
    for kw in keywords:
        print(inf(f"crt.sh: {kw}"))
        url = f"https://crt.sh/?q=%25{kw}%25&output=json"
        r = await hget(session, url)
        if not r or r[0] != 200:
            print(f"  {RED}[!] crt.sh request failed{RESET}")
            continue
        try:
            data = json.loads(r[2])
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and kw.lower() in name.lower():
                        found.add(name)
        except Exception:
            pass
    if found:
        print(f"\n{CYAN}  CT found {len(found)} domains:{RESET}")
        for d in sorted(found)[:200]:
            print(f"    {d}")
    return found


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
LOGO = f"""{BOLD}{CYAN}
   ██████╗██╗      ██████╗ ██╗   ██╗██████╗      ███████╗███╗   ██╗██╗   ██╗███╗   ███╗██████╗
  ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗     ██╔════╝████╗  ██║██║   ██║████╗ ████║╚════██╗
  ██║     ██║     ██║   ██║██║   ██║██║  ██║     █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║ █████╔╝
  ██║     ██║     ██║   ██║██║   ██║██║  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║██╔═══╝
  ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝     ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║███████╗
   ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝      ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝
{RESET}  Multi-cloud enumeration | 20+ providers | 55+ service types | CT logs
  github.com/initstring/cloud_enum — enhanced rewrite
"""


def parse_args():
    p = argparse.ArgumentParser(
        description="cloud_enum2 — Comprehensive multi-cloud asset enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cloud_enum2.py -k acme
  python3 cloud_enum2.py -k acme -k acmecorp -t 40
  python3 cloud_enum2.py -k acme --only aws gcp
  python3 cloud_enum2.py -k acme --skip alibaba ibm oracle
  python3 cloud_enum2.py -k acme -o results.json --format json
  python3 cloud_enum2.py -k acme --quickscan
        """,
    )
    p.add_argument("-k", "--keyword", action="append", dest="keywords",
                   required=True, metavar="KEYWORD",
                   help="Keyword to enumerate (repeatable, e.g. -k acme -k acmecorp)")
    p.add_argument("-t", "--threads", type=int, default=25,
                   metavar="N", help="DNS thread count (default: 25)")
    p.add_argument("-ns", "--nameserver", default="1.1.1.1",
                   metavar="IP", help="DNS resolver IP (default: 1.1.1.1)")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Write results to file")
    p.add_argument("--format", choices=["text", "json", "csv"], default="text",
                   help="Output file format (default: text)")
    p.add_argument("--only", nargs="+",
                   choices=["ct","aws","azure","gcp","alibaba","digitalocean",
                            "cloudflare","ibm","oracle","platforms"],
                   metavar="PROVIDER",
                   help="Only run specified providers")
    p.add_argument("--skip", nargs="+",
                   choices=["ct","aws","azure","gcp","alibaba","digitalocean",
                            "cloudflare","ibm","oracle","platforms"],
                   metavar="PROVIDER",
                   help="Skip specified providers")
    p.add_argument("--quickscan", action="store_true",
                   help="Use keywords as-is, skip mutations (fast mode)")
    return p.parse_args()


def setup_resolver(nameserver: str) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.nameservers = [nameserver]
    r.timeout = 3
    r.lifetime = 6
    return r


async def run(args):
    global _log_fh, _log_fmt

    print(LOGO)

    keywords = [k.lower().strip() for k in args.keywords]

    if args.quickscan:
        names = keywords
        print(inf(f"Quickscan mode — {len(names)} keywords, no mutations"))
    else:
        names = build_names(keywords)
        print(inf(f"Generated {len(names):,} candidate names from {len(keywords)} keyword(s)"))

    resolver = setup_resolver(args.nameserver)
    print(inf(f"DNS: {args.nameserver} | Threads: {args.threads}"))

    all_providers = ["ct","aws","azure","gcp","alibaba","digitalocean","cloudflare","ibm","oracle","platforms"]
    if args.only:
        providers = [p for p in all_providers if p in args.only]
    elif args.skip:
        providers = [p for p in all_providers if p not in args.skip]
    else:
        providers = all_providers

    print(inf(f"Providers: {', '.join(providers)}"))
    print(inf(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))

    _log_fmt = args.format
    if args.output:
        _log_fh = open(args.output, "w", encoding="utf-8")

    connector = aiohttp.TCPConnector(limit=150, ssl=False, ttl_dns_cache=300,
                                     force_close=False, enable_cleanup_closed=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        if "ct"          in providers: await check_ct(session, keywords)
        if "aws"         in providers: await check_aws(session, names, resolver, args.threads)
        if "azure"       in providers: await check_azure(session, names, resolver, args.threads)
        if "gcp"         in providers: await check_gcp(session, names, resolver, args.threads)
        if "alibaba"     in providers: await check_alibaba(session, names, resolver, args.threads)
        if "digitalocean"in providers: await check_digitalocean(session, names, resolver, args.threads)
        if "cloudflare"  in providers: await check_cloudflare(session, names, resolver, args.threads)
        if "ibm"         in providers: await check_ibm(session, names, resolver, args.threads)
        if "oracle"      in providers: await check_oracle(session, names, resolver, args.threads)
        if "platforms"   in providers: await check_platforms(session, names, resolver, args.threads)

    # ── Summary ──
    print(f"\n{BOLD}{CYAN}{'═'*64}{RESET}")
    print(f"{BOLD}  RESULTS{RESET}")
    print(f"{BOLD}{CYAN}{'═'*64}{RESET}")
    public = [r for r in RESULTS if r["access"] == "public"]
    auth   = [r for r in RESULTS if r["access"] == "auth"]
    print(f"  {GREEN}Public/Open  : {len(public)}{RESET}")
    print(f"  {YELLOW}Auth-Required: {len(auth)}{RESET}")
    print(f"  Total found  : {len(RESULTS)}")

    if public:
        print(f"\n{GREEN}{BOLD}  PUBLIC ASSETS:{RESET}")
        for r in public:
            print(f"    [{r['platform']}/{r['service']}] {r['target']}")
    if auth:
        print(f"\n{YELLOW}{BOLD}  AUTH-PROTECTED ASSETS:{RESET}")
        for r in auth:
            print(f"    [{r['platform']}/{r['service']}] {r['target']}")

    # ── Write output file ──
    if _log_fh:
        if args.format == "csv":
            writer = csvmod.DictWriter(_log_fh,
                                       fieldnames=["platform","service","target","access"])
            writer.writeheader()
            writer.writerows(RESULTS)
        elif args.format == "json":
            json.dump(RESULTS, _log_fh, indent=2)
        _log_fh.close()
        print(f"\n  {CYAN}Results written: {args.output}{RESET}")

    print(inf(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))


def main():
    args = parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Interrupted — partial results above{RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()
