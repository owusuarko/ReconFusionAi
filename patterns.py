#!/usr/bin/env python3
"""
ReconFusionAI - Regex Patterns Module
All regex patterns for secret detection and vulnerability discovery
"""

import re

# ============================================================
# IGNORE PATTERNS
# ============================================================
IGNORE_SIGNATURES = [
    "lorem ipsum",
    "example.com",
    "test@test.com"
]

# ============================================================
# CRITICAL PATTERNS (Send to AI for Analysis)
# ============================================================
CRITICAL_PATTERNS = {
    # --- Cloud Providers ---
    'AWS_ACCESS_KEY': re.compile(r'((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})'),
    'AWS_SECRET_KEY': re.compile(r'["\']([0-9a-zA-Z\/+]{40})["\']'),
    'GOOGLE_API_KEY': re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    'GOOGLE_OAUTH': re.compile(r'ya29\.[0-9A-Za-z\-_]+'),
    'FIREBASE': re.compile(r'[a-z0-9.-]+\.firebaseio\.com'),
    'AZURE_ACCESS_KEY': re.compile(r'[a-zA-Z0-9]{88}'),
    'HEROKU_API_KEY': re.compile(r'[h|H]eroku\s*[=:]\s*["\']([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["\']'),
    'DIGITALOCEAN_TOKEN': re.compile(r'dop_v1_[a-f0-9]{64}'),
    'MAILGUN': re.compile(r'key-[0-9a-zA-Z]{32}'),
    
    # --- CI/CD & Dev Tools ---
    'GITHUB_TOKEN': re.compile(r'((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255})'),
    'GITHUB_OAUTH': re.compile(r'[a-f0-9]{40}'),
    'GITLAB_TOKEN': re.compile(r'glpat-[0-9a-zA-Z\-_]{20}'),
    'NPM_ACCESS_TOKEN': re.compile(r'npm_[a-z0-9]{36}'),
    'DOCKER_AUTH': re.compile(r'{"auths":{[^}]+}}'),
    
    # --- Messaging & Social ---
    'SLACK_TOKEN': re.compile(r'xox[baprs]-([0-9a-zA-Z]{10,48})'),
    'SLACK_WEBHOOK': re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'),
    'DISCORD_WEBHOOK': re.compile(r'https://discordapp\.com/api/webhooks/[0-9]+/[A-Za-z0-9-]+'),
    'TWILIO_SID': re.compile(r'AC[a-zA-Z0-9_\-]{32}'),
    'TELEGRAM_BOT': re.compile(r'[0-9]+:AA[0-9A-Za-z\-_]{33}'),
    
    # --- Payment & Security ---
    'STRIPE_KEY': re.compile(r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}'),
    'PAYPAL_TOKEN': re.compile(r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'),
    'SQUARE_ACCESS_TOKEN': re.compile(r'sq0atp-[0-9A-Za-z\-_]{22}'),
    'PRIVATE_KEY': re.compile(r'-----BEGIN (?:RSA|DSA|EC|PGP) PRIVATE KEY'),
    'RSA_PRIVATE': re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
    'JWT_TOKEN': re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    
    # --- Generic High-Entropy Secrets ---
    'GENERIC_API_KEY': re.compile(r'(?i)(?:api_key|apikey|access_token|auth_token|api_secret|client_secret)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|"]|[\s|\']|[\s|`])([0-9a-z]{32,})', re.IGNORECASE),
    'PASSWORD_ASSIGNMENT': re.compile(r'(?i)(?:password|passwd|pwd|secret)(?:[0-9a-z\-_\t .]{0,20})(?:=|:)(?:[\s|"]|[\s|\']|[\s|`])([0-9a-zA-Z@#$%]{8,})', re.IGNORECASE),
    
    # --- Authorization & Authentication ---
    'AUTH_BEARER': re.compile(r'Authorization[:\s]*Bearer\s+([A-Za-z0-9\-\._~\+\/]+=*)', re.IGNORECASE),
    'BASIC_AUTH': re.compile(r'Authorization[:\s]*Basic\s+([A-Za-z0-9+/=]{16,})', re.IGNORECASE),
    'AWS_SESSION_TOKEN': re.compile(r'(ASIA[0-9A-Z]{16,})'),
    'REFRESH_TOKEN': re.compile(r'refresh_token["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_\.]{20,})["\']', re.IGNORECASE),
    
    # --- Private Keys (Extended) ---
    'OPENSSH_PRIVATE_KEY': re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
    'PGP_PRIVATE_KEY': re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    'GSA_PRIVATE_KEY_JSON': re.compile(r'"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----', re.IGNORECASE),
    
    # --- Azure & Cloud Tokens ---
    'AZURE_SAS_SIG': re.compile(r'sig=[A-Za-z0-9%\-_.]{16,}', re.IGNORECASE),
    
    # --- Database Credentials ---
    'DATABASE_URL': re.compile(r'(postgres|mysql|mssql|sqlserver)://[^\s\'\"]{5,}', re.IGNORECASE),
    
    # --- Exposed Files & Configs ---
    'GIT_REPO_EXPOSED': re.compile(r'/(?:\.git/(?:HEAD|config|index|objects|refs)|\.gitignore\b)', re.IGNORECASE),
    'DOTENV_EXPOSED': re.compile(r'\.env\b|(?:DB_PASSWORD|DATABASE_URL|APP_KEY)=', re.IGNORECASE),
    
    # --- Debug & Development ---
    'PHPINFO_OR_DEBUG': re.compile(r'phpinfo\(|display_errors\s*=\s*on|dump\(|var_dump\(', re.IGNORECASE),
    'LONG_BASE64': re.compile(r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']'),
    'COMMENT_CREDENTIAL_HINTS': re.compile(r'<!--[^>]{0,200}(password|passwd|pwd|secret|api[_\s-]?key|token)[^>]{0,200}-->', re.IGNORECASE),
    
    # --- WordPress Critical (Database & Auth) ---
    'WP_DB_PASSWORD': re.compile(r'define\s*\(\s*[\'"]DB_PASSWORD["\']\s*,\s*[\'"]([^\'\"]+)["\']\s*\);'),
    'WP_DB_USER': re.compile(r'define\s*\(\s*[\'"]DB_USER["\']\s*,\s*[\'"]([^\'\"]+)["\']\s*\);'),
    'WP_AUTH_KEY': re.compile(r'define\s*\(\s*[\'"](?:AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY)["\']\s*,\s*[\'"]([^\'\"]+)["\']\s*\);'),
    'WP_SQL_DUMP_HEADER': re.compile(r'--\s+Host:\s+.*Database:\s+'),
    'WP_SQL_INSERT_USERS': re.compile(r'INSERT\s+INTO\s+[`"\']?wp_users[`"\']?'),
    'WP_FATAL_ERROR': re.compile(r'Fatal error:\s+Uncaught Error:'),
    'WP_DEBUG_STACKTRACE': re.compile(r'#\d+\s+.*wp-content/plugins/'),
}

# ============================================================
# DISCOVERY PATTERNS (Save to file directly - No AI)
# ============================================================
DISCOVERY_PATTERNS = {
    # --- Storage Buckets (Potential Takeover/Data Leak) ---
    'S3_BUCKET': re.compile(r'[a-z0-9.-]+\.s3\.amazonaws\.com'),
    'S3_BUCKET_ALT': re.compile(r'[a-z0-9.-]+\.s3-[a-z0-9-]+\.amazonaws\.com'),
    'GOOGLE_STORAGE': re.compile(r'[a-z0-9.-]+\.storage\.googleapis\.com'),
    'AZURE_BLOB': re.compile(r'[a-z0-9.-]+\.blob\.core\.windows\.net'),
    'DIGITALOCEAN_SPACE': re.compile(r'[a-z0-9.-]+\.digitaloceanspaces\.com'),
    
    # --- Databases & Services ---
    'FIREBASE_DB': re.compile(r'[a-z0-9.-]+\.firebaseio\.com'),
    'MONGODB_URI': re.compile(r'mongodb://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@'),
    'REDIS_URI': re.compile(r'redis://:[a-zA-Z0-9_]+@'),
    'POSTGRES_URI': re.compile(r'postgres://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@'),
    
    # --- Interesting Parameters (XSS/SSRF/LFI/IDOR) ---
    'DANGEROUS_PARAMS': re.compile(r'[\?\&](?:redirect|url|path|file|dest|target|source|callback|return|id|user|account|debug|admin|token|auth|key)=', re.IGNORECASE),
    
    # --- Network & Internal ---
    'INTERNAL_IP': re.compile(r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b|\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b'),
    'INTERNAL_DOMAIN': re.compile(r'[a-z0-9.-]+\.(?:internal|staging|dev|local|test|corp|intranet)\.[a-z]{2,}', re.IGNORECASE),
    
    # --- Sensitive PII/Info ---
    'EMAIL_ADDRESS': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    'DEV_COMMENT': re.compile(r'(?i)(?:TODO|FIXME|HACK|BUG|XXX|NOTE)[:\s](.{10,100})'),
    
    # --- Client-Side Vulnerabilities ---
    'INNERHTML_USAGE': re.compile(r'\.innerHTML\s*=', re.IGNORECASE),
    'EVAL_USAGE': re.compile(r'\beval\s*\(', re.IGNORECASE),
    'POSTMESSAGE': re.compile(r'\.postMessage\s*\(', re.IGNORECASE),
    'LOCATION_HASH': re.compile(r'location\.hash', re.IGNORECASE),
    'LOCATION_SEARCH': re.compile(r'location\.search', re.IGNORECASE),
    'WINDOW_NAME': re.compile(r'window\.name', re.IGNORECASE),
    
    # --- Backup & Archive Files ---
    'BACKUP_FILES': re.compile(r'\.(?:bak|backup|old|zip|tar\.gz|sql|tar|tgz)$', re.IGNORECASE),
    'WELL_KNOWN': re.compile(r'/.well-known/|/server-status|/admin/|/manager/html', re.IGNORECASE),
    'PACKAGE_MANIFEST': re.compile(r'package\.json|composer\.json|requirements\.txt', re.IGNORECASE),
    
    # --- WordPress Discovery (Exposed Files & Vulnerabilities) ---
    'WP_DEBUG_LOG': re.compile(r'wp-content/debug\.log'),
    'WP_CONFIG_BACKUP': re.compile(r'wp-config\.php\.(?:bak|old|swp|txt|save|orig)'),
    'WP_INSTALL_FILE': re.compile(r'wp-admin/install\.php'),
    'WP_XMLRPC': re.compile(r'xmlrpc\.php'),
    'WP_JSON_USERS': re.compile(r'wp-json/wp/v2/users'),
    'WP_AUTHOR_ARCHIVE': re.compile(r'/author/([a-zA-Z0-9_\-]+)/?'),
    'WP_YOAST_SEO_USERS': re.compile(r'"@type":"Person","name":"([^"]+)"'),
    'WP_TIMTHUMB': re.compile(r'(?:timthumb|thumb)\.php\?src='),
    'WP_VERSION_META': re.compile(r'<meta name="generator" content="WordPress ([0-9.]+)"'),
    'WP_OBSOLETE_PLUGIN': re.compile(r'/wp-content/plugins/(revslider|duplicator|contact-form-7|elementor)/'),
    'WP_DIRECTORY_LISTING': re.compile(r'Index of /wp-content/uploads'),
    'WP_FULL_PATH_DISCLOSURE': re.compile(r'/(?:var|home|usr)/www/[a-zA-Z0-9_/\-]+/wp-content/'),
    'WP_PHP_IN_UPLOADS': re.compile(r'wp-content/uploads/.*\.(?:php|php5|phtml)'),
}

# ============================================================
# Load additional patterns from external file
# ============================================================
try:
    import sys
    sys.path.insert(0, '/home/george/Desktop/ai-hacker(george)')
    from external_patterns import EXTERNAL_PATTERNS
    # Merge external patterns into DISCOVERY_PATTERNS
    DISCOVERY_PATTERNS.update(EXTERNAL_PATTERNS)
    print(f"[INFO] Loaded {len(EXTERNAL_PATTERNS)} additional patterns from external_patterns.py")
except ImportError:
    print("[WARNING] Could not load external_patterns.py - using default patterns only")
except Exception as e:
    print(f"[WARNING] Error loading external patterns: {e}")
