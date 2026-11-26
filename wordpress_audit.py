#!/usr/bin/env python3
"""wordpress-audit - scan WordPress plugins for MALICIOUS code before you activate them.

Wordfence and WPScan are excellent at what they do, and they do something else: Wordfence is
a runtime firewall + malware scanner that runs *inside* a site that already has the plugin
installed, and WPScan / Patchstack are databases of *known vulnerabilities* in plugin
versions. Neither answers "does the zip I am about to upload contain a backdoor that nobody has
reported yet?". That is the gap this fills: a deterministic (no LLM) static read of the plugin
zip, before it is ever installed or activated, for the shapes real WordPress supply-chain
backdoors have taken: hidden administrator accounts, eval of decoded or remote code, webshell
drops into uploads / mu-plugins / wp-includes, credentials and wp-config secrets posted to a
third host, remote SEO-spam injection into wp_head / wp_footer, and plugins that hide
themselves from the plugin list.

The zip is downloaded into memory and read as text. Nothing is installed or executed.

Context model. A WordPress plugin's code runs at very different times. Code on the main
plugin file's top level and in callbacks on init / plugins_loaded / wp_loaded / wp_head /
wp_footer runs on EVERY request; register_activation_hook callbacks run on activation;
wp_cron events run unattended; wp_ajax_nopriv_* and REST routes with
permission_callback => '__return_true' are reachable by anonymous visitors. A HIGH finding
inside any of those is escalated to CRITICAL (MEDIUM to HIGH). Matches inside comments,
inside quoted strings (for code-sink patterns), or under tests/ docs/ examples/ are demoted.
Network calls to the plugin's own vendor domain (Plugin URI / Author URI / Update URI) or to
well-known services are licensing / update / analytics traffic and are demoted.

Usage:
  python wordpress_audit.py <slug>[@version] [...]   # fetch from downloads.wordpress.org and scan
  python wordpress_audit.py ./my-plugin/             # a local plugin directory
  python wordpress_audit.py my-plugin.zip            # a local zip
  python wordpress_audit.py --text "<?php ..."       # a string
  add --json for machine-readable output, --verbose to print INFO context

Exit code 2 if any target is HIGH or CRITICAL (CI-friendly).
No dependencies beyond the standard library. MIT licensed.
"""
import bisect
import io
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

__version__ = "0.1.0"

DOWNLOADS = "https://downloads.wordpress.org/plugin"
API = "https://api.wordpress.org/plugins/info/1.2/"
PHP_EXT = (".php", ".inc", ".phtml", ".php5", ".php7", ".phps", ".module")
JS_EXT = (".js", ".mjs", ".cjs")
IMG_EXT = (".ico", ".png", ".gif", ".jpg", ".jpeg", ".bmp", ".webp", ".woff", ".woff2", ".ttf")
MAX_FILE = 2000000      # bytes per file; larger files are skipped (reported as info)
MAX_TOTAL = 60000000    # bytes of text scanned per plugin
BLOB_RE = re.compile(r"[A-Za-z0-9+/=]{4096,}")   # long base64 blobs are stripped before scanning
DOC_PATH_RE = re.compile(r"(?:^|/)(?:tests?|__tests__|spec|examples?|docs?|demo|node_modules|"
                         r"\.github|bin|dev|tools?|build-tools|grunt|gulp)/", re.IGNORECASE)

# Endpoints that legitimate plugins essentially never hard-code but stealers love.
EXFIL_HOST = (
    r"(?<![\w-])(?:discord(?:app)?\.com/api/webhooks/\d|api\.telegram\.org/bot\d|hooks\.slack\.com/services/T|"
    r"webhook\.site|pipedream\.net|requestbin\.(?:com|net|io)|requestb\.in|requestcatcher\.com|beeceptor\.com|"
    r"pastebin\.com/(?:api|raw)|paste\.ee/|hastebin\.com|transfer\.sh|"
    r"ngrok(?:-free)?\.(?:io|app|dev)|\.trycloudflare\.com|serveo\.net|localtunnel\.me|"
    r"oastify\.com|oast\.(?:fun|me|pro|live|site|online)|interact\.sh|interactsh|"
    r"burpcollaborator\.net|canarytokens\.com|dnslog\.cn|ceye\.io|requestrepo\.com)(?![\w-])"
)
RAW_IP_URL = (r"https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|"
              r"255\.))\d{1,3}(?:\.\d{1,3}){3}")
REQ = r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER\s*\[\s*['\"]HTTP_\w+['\"]\s*\])"
NET_SINK = (r"\b(?:wp_remote_(?:get|post|request|head)|wp_safe_remote_(?:get|post|request)|curl_exec|"
            r"fsockopen|stream_socket_client|download_url|file_get_contents\s*\(\s*['\"]https?:|"
            r"fopen\s*\(\s*['\"]https?:|Requests::(?:get|post|request)|"
            r"(?:\$\w+->)?(?:http_)?(?:post|request)\s*\(\s*['\"]https?:)")
REMOTE_SRC = (r"(?:wp_remote_(?:get|post|request)|wp_safe_remote_(?:get|post|request)|wp_remote_retrieve_body|"
              r"curl_exec|file_get_contents\s*\(\s*(?:['\"]https?:|\$\w*(?:url|uri|link|endpoint|remote|host|src)\b)|"
              r"stream_get_contents|fgets\s*\(\s*\$(?:sock|fp|socket)|download_url)")
DECODE = r"(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|convert_uudecode|rawurldecode|urldecode|pack)"
EVAL_SINK = r"\b(?:eval|assert|create_function)\s*\("
# A WordPress secret worth stealing, as it appears in code that reads it.
SECRET_SRC = (r"(?<!['\"\w$>-])(?:DB_PASSWORD|DB_USER|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|"
              r"SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)(?![\w'\"])|file_get_contents\s*\([^;]{0,80}wp-config\.php|"
              r"->user_pass\b|\$_POST\s*\[\s*['\"](?:pwd|log|user_pass|password)['\"]|"
              r"(?i:SELECT)\s[^;]{0,120}\{?\$wpdb->(?:users|usermeta)\b|\$wpdb->get_results\s*\([^;]{0,120}(?:users|usermeta)")

PATTERNS = {
    "critical": [
        {"id": "eval_decoded", "name": "Eval of Decoded Payload", "code": True,
         "desc": "eval/assert/create_function of base64/gzinflate/str_rot13/... decoded data (the classic PHP backdoor)",
         "regexes": [
             EVAL_SINK + r"\s*(?:['\"]\?>['\"]\s*\.\s*)?(?:@?\s*" + DECODE + r"\s*\(\s*){1,}",
             r"\bpreg_replace\s*\(\s*['\"]([^\w\s\\])[^'\"]{0,200}\1[imsxuUAD]*e[imsxuUAD]*['\"]\s*,\s*[^;]{0,80}" + DECODE,
         ]},
        {"id": "request_exec", "name": "Request-Controlled Code Execution (Webshell)", "code": True,
         "desc": "Passes an HTTP request parameter straight into eval / system / exec / a variable function",
         "regexes": [
             r"\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|create_function|pcntl_exec)\s*\(\s*"
             r"(?:@?(?:stripslashes|trim|" + DECODE[3:-1] + r")\s*\(\s*)*@?" + REQ,
             r"(?<![\w>$])@?" + REQ + r"\s*\[\s*['\"][^'\"\]]{1,40}['\"]\s*\]\s*\(",
             r"`[^`\n]{0,80}\$_(?:GET|POST|REQUEST|COOKIE)\s*\[",
             r"\bpreg_replace\s*\(\s*['\"]([^\w\s\\])[^'\"]{0,200}\1[imsxuUAD]*e[imsxuUAD]*['\"]\s*,\s*[^;]{0,40}" + REQ,
         ]},
    ],
    "high": [
        {"id": "exfil_host", "name": "Exfiltration Endpoint",
         "desc": "Hard-codes a chat webhook / paste / tunnel / OAST collector",
         "regexes": [EXFIL_HOST]},
        {"id": "obfuscation", "name": "Obfuscated PHP", "code": True,
         "desc": "Hides the names of eval/base64_decode/system (escaped, reversed, rot13'd or assembled at runtime)",
         "regexes": [
             r"['\"](?:\\x65|\\145)(?:\\x76|\\166)(?:\\x61|\\141)(?:\\x6c|\\154)['\"]",
             r"['\"](?:\\x62|\\142)(?:\\x61|\\141)(?:\\x73|\\163)(?:\\x65|\\145)(?:\\x36|\\66)(?:\\x34|\\64)",
             r"\bstr_rot13\s*\(\s*['\"](?:riny|onfr64_qrpbqr|tmvasyngr|flfgrz|furyy_rkrp|nffreg)['\"]",
             r"\bstrrev\s*\(\s*['\"](?:lave|edoced_46esab|etalfnizg|metsys|cexe_llehs|tressa)['\"]",
             r"['\"]bas['\"]\s*\.\s*['\"]e64_|['\"]base['\"]\s*\.\s*['\"]64_de|['\"]ba['\"]\s*\.\s*['\"]se64|"
             r"['\"]gzin['\"]\s*\.\s*['\"]flate|['\"]ev['\"]\s*\.\s*['\"]al['\"]|['\"]as['\"]\s*\.\s*['\"]sert['\"]",
         ]},
    ],
    "medium": [
        {"id": "raw_ip_url", "name": "Raw-IP URL",
         "desc": "Hard-codes a public IP address as an HTTP endpoint",
         "regexes": [RAW_IP_URL]},
        {"id": "decode_chain", "name": "Nested Decode", "code": True,
         "desc": "gzinflate/gzuncompress/str_rot13 of base64_decode with no visible eval (packed payload)",
         "regexes": [r"\b(?:gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(\s*base64_decode\s*\(\s*['\"$]"]},
    ],
    "low": [],
    # Context only, never scored: capabilities that popular plugins use every day.
    "info": [
        {"id": "network", "name": "Network Access", "desc": "Makes outbound HTTP/socket calls",
         "regexes": [NET_SINK]},
        {"id": "eval_dynamic", "name": "Dynamic eval", "code": True,
         "desc": "eval() of a variable (page builders / snippet plugins evaluate user-authored code)",
         "regexes": [r"\beval\s*\(\s*['\"]?\??>?['\"]?\s*\.?\s*\$"]},
        {"id": "shell_exec", "name": "Shell Execution", "code": True, "desc": "exec/shell_exec/system/proc_open",
         "regexes": [r"\b(?:shell_exec|passthru|proc_open|popen|system|exec)\s*\(\s*['\"$]"]},
        {"id": "base64", "name": "base64_decode", "code": True, "desc": "Decodes base64 (very common)",
         "regexes": [r"\bbase64_decode\s*\("]},
        {"id": "user_create", "name": "Creates Users", "code": True, "desc": "wp_insert_user / wp_create_user",
         "regexes": [r"\b(?:wp_insert_user|wp_create_user)\s*\("]},
        {"id": "file_write", "name": "Writes Files", "code": True, "desc": "file_put_contents / fwrite / WP_Filesystem",
         "regexes": [r"\b(?:file_put_contents|fwrite|fputs)\s*\("]},
        {"id": "wp_config_ref", "name": "wp-config.php Reference", "desc": "Mentions wp-config.php (cache/security plugins edit it)",
         "regexes": [r"wp-config\.php"]},
        {"id": "secret_read", "name": "Reads WordPress Secrets", "case": True, "desc": "DB_PASSWORD / salts / user_pass / users table",
         "regexes": [SECRET_SRC]},
    ],
}

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
SEV_NAMES = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_COMPILED = [(sev, pg, re.compile(rx, 0 if pg.get("case") else re.IGNORECASE))
             for sev, groups in PATTERNS.items() for pg in groups for rx in pg["regexes"]]
NET_RE = re.compile(NET_SINK, re.IGNORECASE)
EXFIL_RE = re.compile(EXFIL_HOST, re.IGNORECASE)
RAWIP_RE = re.compile(RAW_IP_URL)
REMOTE_RE = re.compile(REMOTE_SRC, re.IGNORECASE)
SECRET_RE = re.compile(SECRET_SRC)   # constants are case-sensitive in PHP
URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)
EXFIL_NEEDLES = ("discord", "telegram", "hooks.slack", "webhook.site", "pipedream", "requestb", "requestcatcher",
                 "beeceptor", "pastebin", "paste.ee", "hastebin", "transfer.sh", "ngrok", "trycloudflare", "serveo",
                 "localtunnel", "oast", "interact", "burpcollaborator", "canarytokens", "dnslog", "ceye.io", "requestrepo")
# cheap substring prefilter per rule (on the lower-cased file): a rule's regexes only run if one is present
RULE_NEEDLES = {
    "eval_decoded": ("eval", "assert", "create_function", "preg_replace"),
    "request_exec": ("$_", "`"),
    "exfil_host": EXFIL_NEEDLES,
    "obfuscation": ("\\x", "\\1", "rot13", "strrev", "e64_", "64_de", "se64", "flate", "al'", 'al"', "sert'", 'sert"'),
    "raw_ip_url": ("://",),
    "decode_chain": ("base64_decode",),
    "network": ("remote_", "curl_exec", "fsockopen", "stream_socket", "download_url", "http", "requests::",
                "_contents", "fopen", "post", "request"),
    "eval_dynamic": ("eval",),
    "shell_exec": ("exec", "system", "passthru", "popen"),
    "base64": ("base64_decode",),
    "user_create": ("wp_insert_user", "wp_create_user"),
    "file_write": ("file_put_contents", "fwrite", "fputs"),
    "wp_config_ref": ("wp-config.php",),
    "secret_read": ("db_password", "db_user", "_key", "_salt", "wp-config.php", "user_pass", "pwd", "password", "users"),
}
NEEDLES = ("eval", "assert", "create_function", "base64", "rot13", "strrev", "gzinflate", "\\x", "\\1",
           "_get", "_post", "_request", "_cookie", "_server", "http", "preg_replace", "`")

# Well-known services that plugins legitimately talk to (APIs, CDNs, payment, analytics).
KNOWN_HOSTS = {
    "wordpress.org", "w.org", "wordpress.com", "wp.com", "gravatar.com", "wp.me", "jetpack.com",
    "google.com", "googleapis.com", "gstatic.com", "google-analytics.com", "googletagmanager.com",
    "googlesyndication.com", "doubleclick.net", "youtube.com", "recaptcha.net", "hcaptcha.com",
    "cloudflare.com", "facebook.com", "facebook.net", "fb.com", "twitter.com", "x.com", "linkedin.com",
    "instagram.com", "pinterest.com", "github.com", "githubusercontent.com", "gitlab.com",
    "amazonaws.com", "amazon.com", "paypal.com", "stripe.com", "freemius.com", "mailchimp.com",
    "microsoft.com", "live.com", "office.com", "dropbox.com", "dropboxapi.com", "box.com",
    "backblazeb2.com", "digitaloceanspaces.com", "wasabisys.com", "apple.com", "mozilla.org",
    "jsdelivr.net", "cdnjs.com", "unpkg.com", "bootstrapcdn.com", "fontawesome.com", "jquery.com",
    "schema.org", "w3.org", "php.net", "example.com", "example.org", "example.net", "localhost",
    "akismet.com", "automattic.com", "woocommerce.com", "woo.com", "openai.com", "anthropic.com",
    "hubspot.com", "sendgrid.net", "mailgun.net", "sparkpost.com", "zoho.com", "shopify.com",
    "vimeo.com", "spotify.com", "tiktok.com", "bing.com", "yandex.ru", "yandex.com", "baidu.com",
    "ipinfo.io", "ip-api.com", "maxmind.com", "geoplugin.net", "cloudflareinsights.com",
}

# hook names whose callbacks run on (practically) every request
LOAD_HOOKS = {"init", "plugins_loaded", "wp_loaded", "muplugins_loaded", "setup_theme", "after_setup_theme",
              "wp", "template_redirect", "wp_head", "wp_footer", "wp_body_open", "admin_init", "send_headers",
              "parse_request", "wp_print_footer_scripts", "get_footer", "shutdown", "the_content"}
OUTPUT_HOOKS = {"wp_head", "wp_footer", "wp_body_open", "the_content", "wp_print_footer_scripts", "get_footer",
                "the_excerpt", "wp_meta", "loop_start", "template_redirect", "init", "wp"}
HOOK_RE = re.compile(
    r"\badd_(?:action|filter)\s*\(\s*['\"]([\w\-]+)['\"]\s*,\s*"
    r"(?:(?:array\s*\(|\[)\s*(?:\$this|__CLASS__|self::class|static::class|['\"][\w\\]+['\"]|\$\w+|[\w\\]+::class)\s*,\s*['\"](\w+)['\"]"
    r"|['\"](?:[\w\\]+::)?(\w+)['\"]|(?:static\s+)?(function)\s*\(|(fn)\s*\()", re.IGNORECASE)
ACTIVATION_RE = re.compile(
    r"\bregister_activation_hook\s*\(\s*[^,]{1,120},\s*"
    r"(?:(?:array\s*\(|\[)\s*[^,]{1,60},\s*['\"](\w+)['\"]|['\"](?:[\w\\]+::)?(\w+)['\"]|(?:static\s+)?(function)\s*\()",
    re.IGNORECASE)
CRON_RE = re.compile(r"\bwp_schedule_(?:single_)?event\s*\([^;]{0,200}?['\"]([\w\-]+)['\"]\s*(?:,|\))", re.IGNORECASE)
REST_OPEN_RE = re.compile(r"['\"]permission_callback['\"]\s*=>\s*['\"]__return_true['\"]")
REST_CB_RE = re.compile(r"['\"]callback['\"]\s*=>\s*(?:(?:array\s*\(|\[)\s*[^,]{1,60},\s*['\"](\w+)['\"]|['\"](?:[\w\\]+::)?(\w+)['\"]|(?:static\s+)?(function)\s*\()")
FUNC_DEF_RE = re.compile(r"\bfunction\s+&?\s*(\w+)\s*\(")
CLASS_RE = re.compile(r"^\s*(?:abstract\s+|final\s+|readonly\s+)*(?:class|trait|interface|enum)\s+\w+[^{;]*\{", re.M | re.IGNORECASE)
INCLUDE_RE = re.compile(r"\b(?:require|include)(?:_once)?\s*\(?\s*[^;]{0,160}?['\"]([\w./\\-]+\.php)['\"]", re.IGNORECASE)
INCLUDE_NONPHP_RE = re.compile(r"(?<![\w$>:])(?:require|include)(?:_once)?\b\s*\(?\s*(?!array\s*\(|\[)[^;\n]{0,160}?['\"][^'\"\n]*\.(?:ico|png|gif|jpe?g|bmp|woff2?|ttf|log|dat)['\"]\s*\)?\s*;", re.IGNORECASE)
HEADER_RE = re.compile(r"^[ \t/*#@]*(Plugin Name|Plugin URI|Author URI|Update URI|Author)\s*:\s*(.+)$", re.M | re.IGNORECASE)

ADMIN_ROLE_RE = re.compile(r"['\"]role['\"]\s*=>\s*['\"]administrator['\"]|set_role\s*\(\s*['\"]administrator['\"]|"
                           r"add_cap\s*\(\s*['\"]administrator['\"]|['\"]administrator['\"]", re.IGNORECASE)
USER_CREATE_RE = re.compile(r"\b(?:wp_insert_user|wp_create_user)\s*\(", re.IGNORECASE)
HARDCODED_CREDS_RE = re.compile(
    r"\bwp_create_user\s*\(\s*['\"][^'\"$]{2,}['\"]\s*,\s*['\"][^'\"$]{4,}['\"]|"
    r"['\"]user_pass['\"]\s*=>\s*['\"][^'\"$]{4,}['\"]|\$\w*pass\w*\s*=\s*['\"][^'\"$\s]{6,}['\"]\s*;", re.IGNORECASE)
USER_HIDE_RE = re.compile(r"\badd_(?:action|filter)\s*\(\s*['\"](?:pre_user_query|views_users|pre_get_users|users_list_table_query_args)['\"]",
                          re.IGNORECASE)
USER_HIDE_BODY_RE = re.compile(r"user_login\s*(?:!=|<>|\s+NOT\s+IN)\s*\(?\s*\\?['\"][\w.@-]{3,}|"
                               r"['\"]login__not_in['\"]\s*\]?\s*=>?\s*(?:array\s*\(|\[)\s*['\"][\w.@-]{3,}", re.IGNORECASE)
SELF_HIDE_RE = re.compile(r"\badd_filter\s*\(\s*['\"]all_plugins['\"]", re.IGNORECASE)
SELF_HIDE_BODY_RE = re.compile(r"\bunset\s*\(\s*\$\w+\s*\[\s*(?:plugin_basename\s*\(\s*__FILE__|\$\w+|['\"][\w.\-]+/[\w.\-]+\.php['\"])",
                               re.IGNORECASE)
AUTH_SET_RE = re.compile(r"\b(?:wp_set_auth_cookie|wp_set_current_user)\s*\(", re.IGNORECASE)
REQ_LITERAL_CMP_RE = re.compile(
    r"(?:" + REQ + r"\s*\[\s*['\"][^'\"]{1,40}['\"]\s*\]\s*(?:===?|!==?)\s*['\"][^'\"$]{6,}['\"]|"
    r"['\"][^'\"$]{6,}['\"]\s*(?:===?|!==?)\s*" + REQ + r"\s*\[|"
    r"(?:md5|sha1|hash\s*\(\s*['\"]\w+['\"]\s*,)\s*\(?\s*" + REQ + r"[^)]{0,60}\)\s*(?:===?)\s*['\"][0-9a-f]{32,}['\"])",
    re.IGNORECASE)
FIXED_USER_RE = re.compile(
    r"\b(?:wp_set_auth_cookie|wp_set_current_user)\s*\(\s*1\s*[,)]|"
    r"get_user_by\s*\(\s*['\"](?:login|email|slug)['\"]\s*,\s*['\"][^'\"$]{3,}['\"]|"
    r"['\"]role['\"]\s*=>\s*['\"]administrator['\"]|get_super_admins\s*\(|new\s+WP_User\s*\(\s*1\s*\)", re.IGNORECASE)
WRITE_SINK_RE = re.compile(r"\b(?:file_put_contents|fwrite|fputs|copy|move_uploaded_file|rename)\s*\(|->put_contents\s*\(", re.IGNORECASE)
WRITE_DEST_PHP_RE = re.compile(r"\.(?:php\d?|phtml|phar)['\"]", re.IGNORECASE)
WRITE_DEST_DIR_RE = re.compile(r"wp_upload_dir|['\"/]uploads/|WP_CONTENT_DIR|ABSPATH|WPMU_PLUGIN_DIR|mu-plugins|wp-includes|"
                               r"WPINC|get_template_directory|get_stylesheet_directory|get_theme_root|WP_PLUGIN_DIR|"
                               r"\$_SERVER\s*\[\s*['\"]DOCUMENT_ROOT", re.IGNORECASE)
CORE_DIR_RE = re.compile(r"wp-includes|WPINC|wp-admin/", re.IGNORECASE)
PHP_PAYLOAD_LIT_RE = re.compile(r"<\?php[^'\"]{0,400}?(?:eval\s*\(|assert\s*\(|\$_(?:GET|POST|REQUEST|COOKIE)|base64_decode|system\s*\(|shell_exec)",
                                re.IGNORECASE)
ECHO_RE = re.compile(r"\b(?:echo|print|printf|die|exit)\b|\breturn\s+\$", re.IGNORECASE)
CLOAK_RE = re.compile(r"(?:googlebot|bingbot|yandex|baiduspider|slurp|crawler|spider)[^\n]{0,80}HTTP_USER_AGENT|"
                      r"HTTP_USER_AGENT[^\n]{0,120}(?:googlebot|bingbot|yandex|baiduspider|bot\b)|!\s*is_user_logged_in\s*\(\s*\)",
                      re.IGNORECASE)
# what a backdoor reports home: which site it is on, and the keys to it (SMS / API gateways on
# raw IPs send message payloads, not these)
SITE_ID_RE = re.compile(r"\b(?:site_url|home_url|get_site_url|get_home_url|network_site_url|admin_url)\s*\(|"
                        r"get_bloginfo\s*\(\s*['\"](?:url|wpurl)|get_option\s*\(\s*['\"](?:siteurl|home|admin_email)|"
                        r"\$_SERVER\s*\[\s*['\"](?:HTTP_HOST|SERVER_NAME|SERVER_ADDR)|user_pass|user_login|DB_PASSWORD|"
                        r"wp-config\.php", re.IGNORECASE)
MAIL_RE = re.compile(r"\b(?:wp_)?mail\s*\(\s*['\"][\w.+-]+@[\w-]+\.[\w.]+['\"]", re.IGNORECASE)
LOGIN_HOOK_RE = re.compile(r"^(?:wp_login|wp_authenticate|authenticate|wp_authenticate_user|check_password|login_init)$")


def windows(low, needles, before=300, after=700, cap=4000):
    """Merged [a, b) windows around every occurrence of any needle in the lower-cased text.
    Regexes then run only inside these windows: Python's `re` has no literal-prefix speedup for
    IGNORECASE alternations, and plugins ship megabytes of PHP."""
    pts = []
    for n in needles:
        i = low.find(n)
        while i >= 0 and len(pts) < cap:
            pts.append(i)
            i = low.find(n, i + 1)
    if len(pts) >= cap:
        return [(0, len(low))]
    pts.sort()
    out = []
    for p in pts:
        a, b = max(0, p - before), min(len(low), p + after)
        if out and a <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def wfind(rx, text, low, needles, before=300, after=700):
    """finditer restricted to the needle windows (matches deduplicated by start)."""
    last = -1
    for a, b in windows(low, needles, before, after):
        for m in rx.finditer(text, a, b):
            if m.start() > last:
                last = m.start()
                yield m


def _sev(level):
    return SEV_NAMES[max(0, min(4, level))]


# ---------------------------------------------------------------------------
# PHP structure: comments / strings / inline HTML, function spans, hook contexts
# ---------------------------------------------------------------------------
_LEX_RE = re.compile(
    r"(?P<c>//[^\n]*?(?=\?>|\n|$)|#(?!\[)[^\n]*?(?=\?>|\n|$)|/\*.*?(?:\*/|\Z))"
    r"|(?P<h><<<[ \t]*(['\"]?)(\w+)\3[ \t]*\n.*?\n[ \t]*\4\b)"
    r"|(?P<s>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")"
    r"|(?P<x>\?>.*?(?:<\?php|<\?=|\Z))",
    re.S)


class PhpFile:
    """A PHP source with enough structure to answer: is this offset code, a comment or a
    string, which function body is it in, and is that function hooked somewhere?"""

    def __init__(self, path, text):
        self.path, self.text = path, text
        self.nl = [m.start() for m in re.finditer("\n", text)]
        self.low = text.lower()
        self.comments, self.strings = [], []      # sorted (start, end)
        start = 0
        first = re.search(r"<\?(?:php|=)?", text)
        if first is None:
            self.strings.append((0, len(text)))   # no PHP open tag: the whole file is inline HTML
            start = len(text)
        elif first.start() > 0:
            self.strings.append((0, first.start()))
            start = first.end()
        for m in _LEX_RE.finditer(text, start):
            if m.group("c") is not None:
                self.comments.append((m.start(), m.end()))
            elif m.group("h") is not None or m.group("s") is not None or m.group("x") is not None:
                self.strings.append((m.start(), m.end()))
        self.cstart = [a for a, _ in self.comments]
        self.sstart = [a for a, _ in self.strings]
        self.code = self._mask()
        self.funcs = self._functions()      # list of (name, start, end)

    def _mask(self):
        """Text with comments blanked and string contents replaced by spaces (positions kept)."""
        out, last = [], 0
        spans = sorted([(a, b, "c") for a, b in self.comments] + [(a, b, "s") for a, b in self.strings])
        for a, b, _k in spans:
            if a < last:
                continue
            out.append(self.text[last:a])
            seg = self.text[a:b]
            out.append("\n".join(" " * len(x) for x in seg.split("\n")))
            last = b
        out.append(self.text[last:])
        return "".join(out)

    def has_net(self):
        if not hasattr(self, "_net"):
            self._net = any(True for _ in wfind(NET_RE, self.code, self.low, RULE_NEEDLES["network"]))
        return self._net

    def hooks(self):
        if not hasattr(self, "_hooks"):
            self._hooks = list(HOOK_RE.finditer(self.text)) if ("add_action" in self.low or "add_filter" in self.low) else []
        return self._hooks

    def call_args(self, paren):
        """Top-level argument texts of the call whose '(' is at `paren` (strings/comments masked)."""
        code, depth, out, start = self.code, 0, [], paren + 1
        for i in range(paren, min(len(code), paren + 3000)):
            ch = code[i]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
                if depth == 0:
                    out.append(self.text[start:i])
                    return out
            elif ch == "," and depth == 1:
                out.append(self.text[start:i])
                start = i + 1
        return out

    def line(self, pos):
        return bisect.bisect_right(self.nl, pos - 1) + 1 if pos > 0 else 1

    def _in(self, starts, spans, pos):
        i = bisect.bisect_right(starts, pos) - 1
        return i >= 0 and spans[i][0] <= pos < spans[i][1]

    def in_comment(self, pos):
        return self._in(self.cstart, self.comments, pos)

    def in_string(self, pos):
        return self._in(self.sstart, self.strings, pos)

    def _match_brace(self, open_pos):
        depth, code = 0, self.code
        i = open_pos
        n = len(code)
        while i < n:
            j = code.find("{", i)
            k = code.find("}", i)
            if k < 0:
                return n
            if 0 <= j < k:
                depth += 1
                i = j + 1
            else:
                depth -= 1
                i = k + 1
                if depth == 0:
                    return k + 1
        return n

    def _functions(self):
        out = []
        for m in FUNC_DEF_RE.finditer(self.code):
            # find the opening brace of the body (skip abstract / interface declarations ending in ;)
            k = self.code.find("{", m.end())
            semi = self.code.find(";", m.end())
            if k < 0 or (0 <= semi < k):
                continue
            out.append((m.group(1), m.start(), self._match_brace(k)))
        return out

    def closure_span(self, pos):
        """Span of the closure / arrow function whose `function (` keyword starts at/after pos."""
        k = self.code.find("{", pos)
        semi = self.code.find(";", pos)
        if 0 <= semi < k or k < 0:     # `fn() => expr;`
            return (pos, semi if semi >= 0 else len(self.code))
        return (pos, self._match_brace(k))

    def enclosing(self, pos):
        """Innermost function span containing pos, or None (top level)."""
        best = None
        for name, a, b in self.funcs:
            if a <= pos < b and (best is None or a > best[1]):
                best = (name, a, b)
        return best

    def top_level(self):
        """Spans of the file that are outside every function and class body."""
        blocked = [(a, b) for _, a, b in self.funcs]
        for m in CLASS_RE.finditer(self.code):
            k = self.code.find("{", m.start())
            blocked.append((m.start(), self._match_brace(k)))
        blocked.sort()
        spans, last = [], 0
        for a, b in blocked:
            if a > last:
                spans.append((last, a))
            last = max(last, b)
        spans.append((last, len(self.text)))
        return spans


def _host(h):
    h = h.lower().rstrip(".")
    parts = h.split(".")
    if re.match(r"^\d+(?:\.\d+){3}$", h):
        return h
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov", "edu") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _external_hosts(text, vendor):
    """Registrable hosts of the URLs in text that are neither the vendor's nor well known."""
    out = []
    for m in URL_RE.finditer(text):
        h = _host(m.group(1))
        if h in vendor or h in KNOWN_HOSTS:
            continue
        out.append(h)
    return out


def _item(sev, pid, name, desc, pf, pos, matched, ctx=None):
    if pf is not None:
        ls = pf.text.rfind("\n", 0, pos) + 1
        le = pf.text.find("\n", pos)
        le = len(pf.text) if le < 0 else le
        context = pf.text[max(ls, pos - 80):min(le, pos + 140)].strip()[:200]
        return {"severity": sev, "id": pid, "name": name, "description": desc, "file": pf.path,
                "line": pf.line(pos), "matched": matched[:120], "context": ctx or context, "_pos": pos}
    return {"severity": sev, "id": pid, "name": name, "description": desc, "file": "", "line": 0,
            "matched": matched[:120], "context": ctx or "", "_pos": 0}


# ---------------------------------------------------------------------------
# Plugin scan
# ---------------------------------------------------------------------------
def _plugin_header(files):
    """(main file path, {header: value}) of the file that declares `Plugin Name:`."""
    cands = []
    for path, text in files.items():
        if not path.lower().endswith(".php") or path.count("/") > 1:
            continue
        hdr = {}
        for m in HEADER_RE.finditer(text[:8192]):
            hdr.setdefault(m.group(1).lower(), re.sub(r"\s*\*+/.*$", "", m.group(2)).strip())
        if "plugin name" in hdr:
            cands.append((path.count("/"), len(path), path, hdr))
    if not cands:
        return None, {}
    cands.sort()
    return cands[0][2], cands[0][3]


def _vendor_hosts(hdr, slug=""):
    out = set()
    for k in ("plugin uri", "author uri", "update uri"):
        v = hdr.get(k, "")
        for m in URL_RE.finditer(v):
            out.add(_host(m.group(1)))
        if v and "://" not in v and "." in v:
            out.add(_host(v.split("/")[0]))
    out.discard("wordpress.org")
    out.discard("github.com")
    return out


def _hook_contexts(pfs, cron_hooks):
    """{(path, func-name or None, start, end): ctx}. Resolves hooked callbacks by name across the
    whole plugin (methods hooked via array($this,'m') resolve to every function named m)."""
    named = {}            # func name -> set(ctx)
    spans = []            # (path, start, end, ctx, hook)
    for pf in pfs:
        code = pf.code
        for m in pf.hooks():
            if pf.in_comment(m.start()) or pf.in_string(m.start()):
                continue
            hook = m.group(1).lower()
            if hook in LOAD_HOOKS:
                ctx = "load"
            elif hook.startswith("wp_ajax_nopriv_"):
                ctx = "unauth"
            elif hook in cron_hooks:
                ctx = "cron"
            elif LOGIN_HOOK_RE.match(hook):
                ctx = "login"
            else:
                continue
            name = m.group(2) or m.group(3)
            if name:
                named.setdefault(name.lower(), set()).add((ctx, hook))
            else:
                a, b = pf.closure_span(m.start(4) if m.group(4) else m.start(5))
                spans.append((pf.path, a, b, ctx, hook))
        for m in (ACTIVATION_RE.finditer(pf.text) if "register_activation_hook" in pf.low else ()):
            if pf.in_comment(m.start()):
                continue
            name = m.group(1) or m.group(2)
            if name:
                named.setdefault(name.lower(), set()).add(("activation", "activate"))
            else:
                a, b = pf.closure_span(m.start(3))
                spans.append((pf.path, a, b, "activation", "activate"))
        if REST_OPEN_RE.search(pf.text):
            for m in re.finditer(r"\bregister_rest_route\s*\(", code):
                seg_end = min(len(code), m.start() + 1500)
                seg = pf.text[m.start():seg_end]
                if not REST_OPEN_RE.search(seg):
                    continue
                cm = REST_CB_RE.search(seg)
                if not cm:
                    continue
                name = cm.group(1) or cm.group(2)
                if name:
                    named.setdefault(name.lower(), set()).add(("unauth", "rest"))
                else:
                    a, b = pf.closure_span(m.start() + cm.start(3))
                    spans.append((pf.path, a, b, "unauth", "rest"))
    for pf in pfs:
        for name, a, b in pf.funcs:
            for ctx, hook in named.get(name.lower(), ()):
                spans.append((pf.path, a, b, ctx, hook))
    return spans


def scan_plugin(files, label="", slug=""):
    findings, info, skipped = [], [], []
    main, hdr = _plugin_header(files)
    vendor = _vendor_hosts(hdr, slug)
    pfs = []
    total = 0
    for path in sorted(files):
        text = files[path]
        low = path.lower()
        if len(text) > MAX_FILE:
            skipped.append(path)
            continue
        if low.endswith(PHP_EXT) or low.endswith(JS_EXT) or os.path.basename(low) in (".htaccess", ".user.ini"):
            total += len(text)
            if total > MAX_TOTAL:
                skipped.append(path)
                continue
        if low.endswith(PHP_EXT):
            text = BLOB_RE.sub(lambda m: "B" * 16, text)
            pfs.append(PhpFile(path, text))
        elif low.endswith(IMG_EXT):
            _nonphp_file(path, text, findings)
        elif low.endswith(JS_EXT):
            _js_file(path, text, findings, info)
    cron_hooks = set()
    for pf in pfs:
        for m in (CRON_RE.finditer(pf.text) if "wp_schedule" in pf.low else ()):
            cron_hooks.add(m.group(1).lower())
    ctx_spans = _hook_contexts(pfs, cron_hooks)
    # files included directly from the main plugin file run their top level on every request
    load_files = set()
    if main:
        load_files.add(main)
        mtext = files.get(main, "")
        base = os.path.dirname(main)
        for m in INCLUDE_RE.finditer(mtext):
            p = os.path.normpath(os.path.join(base, m.group(1).lstrip("/\\"))).replace("\\", "/")
            load_files.add(p)
    plugin_flags = {"admin_create_files": [], "user_hide": [], "self_hide": []}
    for pf in pfs:
        _scan_php(pf, findings, info, vendor, plugin_flags)
    _plugin_combos(pfs, findings, plugin_flags, vendor)
    _apply_context(pfs, findings, ctx_spans, load_files)
    naive = _naive(files)
    return _summarise(findings, info, label or slug, hdr, main, skipped, naive, vendor)


def _nonphp_file(path, text, findings):
    """PHP code hidden in an image / text / font file (included later by a loader)."""
    i = text.find("<?php")
    if i < 0:
        return
    tail = text[i:i + 200000]
    if re.search(EVAL_SINK + r"|\b" + DECODE + r"\s*\(|" + REQ, tail, re.IGNORECASE):
        findings.append({"severity": "HIGH", "id": "php_in_nonphp", "name": "PHP Hidden in Non-PHP File",
                         "description": "A %s file contains PHP code with eval/decode/request handling" % os.path.splitext(path)[1],
                         "file": path, "line": text.count("\n", 0, i) + 1, "matched": tail[:80],
                         "context": tail[:160].replace("\n", " "), "_pos": i})


def _js_file(path, text, findings, info):
    """Bundled JS: only the few shapes that matter (front-end injected skimmers / collectors)."""
    if DOC_PATH_RE.search("/" + path):
        return
    low = text[:3000000].lower()
    for m in (EXFIL_RE.finditer(text[:3000000]) if any(n in low for n in EXFIL_NEEDLES) else ()):
        if not re.search(r"(?:https?|wss?):(?:\\?/){2}[\w.-]*$", text[max(0, m.start() - 80):m.start()]):
            continue   # a domain in a list (public-suffix tables, block lists), not an endpoint
        findings.append({"severity": "HIGH", "id": "exfil_host", "name": "Exfiltration Endpoint",
                         "description": "JS hard-codes a chat webhook / paste / tunnel / OAST collector",
                         "file": path, "line": text.count("\n", 0, m.start()) + 1, "matched": m.group(0),
                         "context": text[max(0, m.start() - 60):m.end() + 60].replace("\n", " ")[:200], "_pos": m.start()})
        break
    m = "eval" in low and re.search(r"\beval\s*\(\s*(?:atob|unescape)\s*\(\s*['\"][A-Za-z0-9+/=%]{200,}", text[:3000000])
    if m:
        findings.append({"severity": "HIGH", "id": "js_eval_blob", "name": "JS eval of Encoded Blob",
                         "description": "eval(atob('<long base64>')) in shipped JavaScript",
                         "file": path, "line": text.count("\n", 0, m.start()) + 1, "matched": m.group(0)[:80],
                         "context": m.group(0)[:160], "_pos": m.start()})


def _scan_php(pf, findings, info, vendor, flags):
    text, path = pf.text, pf.path
    low = text.lower()
    seen = set()
    local = []
    rules = _COMPILED if any(n in low for n in NEEDLES) else ()
    for sev, pg, rx in rules:
        if sev == "info" and pg["id"] in {k[0] for k in seen}:
            continue
        nd = RULE_NEEDLES.get(pg["id"])
        if nd and not any(n in low for n in nd):
            continue
        for m in (wfind(rx, text, low, nd) if nd else rx.finditer(text)):
            pos = m.start()
            if pf.in_comment(pos):
                continue
            if pg.get("code") and pf.in_string(pos):
                continue
            key = (pg["id"], pf.line(pos))
            if key in seen:
                continue
            seen.add(key)
            it = _item(sev.upper(), pg["id"], pg["name"], pg["desc"], pf, pos, m.group(0))
            (info if sev == "info" else local).append(it)
            if sev == "info" or len([k for k in seen if k[0] == pg["id"]]) >= 5:
                break
    for f in local:
        # an exfil host / raw IP in a file that never sends anything is a URL in a list or UI string
        if f["id"] in ("exfil_host", "raw_ip_url"):
            fn = pf.enclosing(f["_pos"])
            seg = pf.code[fn[1]:fn[2]] if fn else pf.code
            if not (NET_RE.search(seg) or REMOTE_RE.search(pf.text[fn[1]:fn[2]] if fn else pf.text)):
                f["severity"] = "INFO"
            elif f["id"] == "raw_ip_url" and fn and SITE_ID_RE.search(pf.text[fn[1]:fn[2]]):
                f["severity"] = "HIGH"
                f["description"] += " [the same function sends site identity / credentials to it]"
        if f["id"] == "exfil_host" and f["severity"] != "INFO":
            # chat APIs called with the site owner's own token are integrations, not collectors
            if re.match(r"(?:api\.telegram|discord|hooks\.slack)", f["matched"], re.I) and \
                    not re.search(r"api\.telegram\.org/bot\d{6,}:[\w-]{20,}|webhooks/\d{6,}/[\w-]{20,}|services/T\w{6,}/B\w{6,}/\w{10,}",
                                  text[f["_pos"]:f["_pos"] + 160]):
                f["severity"] = "INFO"
    for f in local:
        (info if f["severity"] == "INFO" else findings).append(f)
    _php_combos(pf, findings, info, vendor, flags)


def _span_text(pf, fn):
    return (pf.text[fn[1]:fn[2]], pf.code[fn[1]:fn[2]]) if fn else (pf.text, pf.code)


def _tainted_vars(code_seg, text_seg):
    """Variables assigned (directly or one hop) from a remote fetch."""
    tainted = set()
    for m in re.finditer(r"\$(\w+)\s*=\s*([^;]{0,300});", text_seg):
        if REMOTE_RE.search(m.group(2)):
            tainted.add(m.group(1))
    for _ in range(2):
        for m in re.finditer(r"\$(\w+)\s*=\s*([^;]{0,300});", text_seg):
            if m.group(1) not in tainted and any(re.search(r"\$%s\b" % re.escape(v), m.group(2)) for v in tainted):
                tainted.add(m.group(1))
    tainted.discard("this")
    return tainted


def _php_combos(pf, findings, info, vendor, flags):
    text, code = pf.text, pf.code
    # 1. remote code execution: eval/include of something fetched over the network
    for m in (re.finditer(EVAL_SINK, code, re.IGNORECASE) if ("eval" in pf.low or "assert" in pf.low or "create_function" in pf.low) else ()):
        fn = pf.enclosing(m.start())
        tseg, cseg = _span_text(pf, fn)
        arg = text[m.end():m.end() + 200]
        direct = REMOTE_RE.match(arg.lstrip("@ ")) or re.match(r"\s*(?:['\"]\?>['\"]\s*\.\s*)?@?(?:" + DECODE + r"\s*\(\s*)*" + REMOTE_SRC, arg, re.I)
        tv = _tainted_vars(cseg, tseg) if REMOTE_RE.search(tseg) else set()
        hit = direct or any(re.match(r"\s*(?:['\"]\?>['\"]\s*\.\s*)?@?(?:" + DECODE + r"\s*\(\s*)*\$%s\b" % re.escape(v), arg, re.I) for v in tv)
        if hit:
            ext = _external_hosts(tseg, vendor)
            sev = "CRITICAL" if (ext or not URL_RE.search(tseg)) else "MEDIUM"
            findings.append(_item(sev, "remote_code_exec", "Remote Code Execution",
                                  "eval() of content fetched over the network" +
                                  ("" if sev == "CRITICAL" else " [from the plugin's own vendor domain]"),
                                  pf, m.start(), text[m.start():m.start() + 100]))
            break
    # 2. PHP file drops: write a .php file into uploads / mu-plugins / wp-includes / a theme with
    #    content that is remote, decoded, request-supplied or a literal webshell
    low = pf.low
    for m in (WRITE_SINK_RE.finditer(code) if any(n in low for n in ("file_put_contents", "fwrite", "fputs", "copy", "rename", "put_contents", "move_uploaded_file")) else ()):
        if ".php" not in low and "phtml" not in low:
            break
        fn = pf.enclosing(m.start())
        tseg, cseg = _span_text(pf, fn)
        args = pf.call_args(m.end() - 1)
        if len(args) < 2:
            continue
        name = m.group(0).lower()
        if "fwrite" in name or "fputs" in name:
            h = re.match(r"\s*\$(\w+)", args[0])
            om = h and re.search(r"\$%s\s*=\s*@?fopen\s*\(([^;]{0,300})" % re.escape(h.group(1)), tseg)
            if not om:
                continue
            dest, payload_arg = om.group(1).split(",")[0], args[1]
        elif re.match(r"(?:copy|rename|move_uploaded_file)", name):
            dest, payload_arg = args[1], args[0]
        else:
            dest, payload_arg = args[0], args[1]
        dest_ctx = dest
        for v in re.findall(r"\$(\w+)", dest):
            for am in re.finditer(r"\$%s\s*\.?=\s*([^;]{0,300});" % re.escape(v), tseg):
                dest_ctx += " " + am.group(1)
        if not WRITE_DEST_PHP_RE.search(dest_ctx) or not WRITE_DEST_DIR_RE.search(dest_ctx + " " + tseg):
            continue
        tv = _tainted_vars(cseg, tseg) if REMOTE_RE.search(tseg) else set()
        pay_ctx = payload_arg
        for v in re.findall(r"\$(\w+)", payload_arg):
            for am in re.finditer(r"\$%s\s*\.?=\s*([^;]{0,400});" % re.escape(v), tseg):
                pay_ctx += " " + am.group(1)
        payload = (REMOTE_RE.search(pay_ctx) or re.search(r"\b" + DECODE + r"\s*\(", pay_ctx, re.I) or re.search(REQ, pay_ctx)
                   or any(re.search(r"\$%s\b" % re.escape(v), payload_arg) for v in tv)
                   or PHP_PAYLOAD_LIT_RE.search(pay_ctx) or re.match(r"\s*['\"]https?://", payload_arg))
        if not payload:
            continue
        core = CORE_DIR_RE.search(dest_ctx)
        mu = re.search(r"WPMU_PLUGIN_DIR|mu-plugins", dest_ctx, re.I)
        where = "wp-includes" if core else ("mu-plugins" if mu else "the site's content / uploads dir")
        own = vendor and URL_RE.search(tseg) and not _external_hosts(tseg, vendor)
        findings.append(_item("HIGH" if (own and not core and not mu) else "CRITICAL",
                              "php_drop", "PHP File Drop (Webshell / Persistence)",
                              "Writes a .php file into %s with remote, decoded or request-supplied content" % where,
                              pf, m.start(), pf.text[m.start():m.start() + 100]))
        break
    # 3. secrets / credentials sent off-site from the same function
    for m in (wfind(SECRET_RE, text, pf.low, RULE_NEEDLES["secret_read"]) if pf.has_net() or "mail" in pf.low else ()):
        if pf.in_comment(m.start()):
            continue
        fn = pf.enclosing(m.start())
        tseg, cseg = _span_text(pf, fn)
        if not fn or not (NET_RE.search(cseg) or MAIL_RE.search(tseg) or re.search(r"curl_init|file_get_contents\s*\(\s*['\"]?https?", tseg)):
            continue
        # an unknown host only counts when the send and the host sit next to the secret read
        near = text[max(fn[1], m.start() - 1500):min(fn[2], m.end() + 1500)]
        ext = _external_hosts(near, vendor) if NET_RE.search(near) else []
        bad = RAWIP_RE.search(tseg) or EXFIL_RE.search(tseg) or MAIL_RE.search(tseg)
        if bad or ext:
            findings.append(_item("CRITICAL" if bad else "HIGH", "credential_exfil", "Credential / Secret Exfiltration",
                                  "Reads %s and sends it off-site (%s) from the same function" %
                                  (m.group(0)[:40], (bad.group(0)[:60] if bad else ", ".join(sorted(set(ext))[:3]))),
                                  pf, m.start(), m.group(0)))
            break
    # 5. user creation with the administrator role
    for m in (USER_CREATE_RE.finditer(code) if ("wp_insert_user" in pf.low or "wp_create_user" in pf.low) else ()):
        fn = pf.enclosing(m.start())
        tseg, cseg = _span_text(pf, fn)
        if not ADMIN_ROLE_RE.search(tseg):
            continue
        flags["admin_create_files"].append(pf.path)
        hard = HARDCODED_CREDS_RE.search(tseg)
        net = NET_RE.search(cseg) or MAIL_RE.search(tseg) or re.search(r"curl_init", tseg)
        literal = hard and not hard.group(0).startswith("$")
        if hard and (net or literal or not re.search(r"\$_(?:POST|GET|REQUEST)|get_option|wp_generate_password|sanitize_|\$args|\$data|\$input", tseg)):
            findings.append(_item("CRITICAL", "hardcoded_admin", "Hard-Coded Administrator Account",
                                  "Creates an administrator with a username/password baked into the code" +
                                  (" and sends it off-site" if net else ""),
                                  pf, m.start(), text[m.start():m.start() + 100]))
        elif net and (_external_hosts(tseg, vendor) or RAWIP_RE.search(tseg)) and re.search(r"pass", tseg, re.I):
            findings.append(_item("CRITICAL", "admin_cred_exfil", "Administrator Credentials Sent Off-Site",
                                  "Creates an administrator and posts its credentials to a third-party host",
                                  pf, m.start(), text[m.start():m.start() + 100]))
        break
    # 6. hiding users from the Users screen
    for m in (USER_HIDE_RE.finditer(text) if any(n in pf.low for n in ("pre_user_query", "views_users", "pre_get_users", "users_list_table")) else ()):
        if pf.in_comment(m.start()):
            continue
        seg = text[m.start():m.start() + 200]
        cb = re.search(r",\s*(?:(?:array\s*\(|\[)\s*[^,]{1,60},\s*)?['\"](\w+)['\"]", seg)
        body = None
        if cb:
            for name, a, b in pf.funcs:
                if name.lower() == cb.group(1).lower():
                    body = text[a:b]
                    break
        elif re.search(r",\s*(?:static\s+)?function\s*\(", seg):
            a, b = pf.closure_span(m.start() + seg.find("function"))
            body = text[a:b]
        if body and USER_HIDE_BODY_RE.search(body):
            flags["user_hide"].append(pf.path)
            findings.append(_item("HIGH", "user_hiding", "Hides Users From Admin",
                                  "Filters the Users screen query to exclude specific accounts",
                                  pf, m.start(), seg[:100]))
            break
    # 7. self-hiding from the plugin list
    for m in (SELF_HIDE_RE.finditer(text) if "all_plugins" in pf.low else ()):
        if pf.in_comment(m.start()):
            continue
        seg = text[m.start():m.start() + 200]
        cb = re.search(r",\s*(?:(?:array\s*\(|\[)\s*[^,]{1,60},\s*)?['\"](\w+)['\"]", seg)
        body = None
        if cb:
            for name, a, b in pf.funcs:
                if name.lower() == cb.group(1).lower():
                    body = text[a:b]
                    break
        elif re.search(r",\s*(?:static\s+)?function\s*\(", seg):
            a, b = pf.closure_span(m.start() + seg.find("function"))
            body = text[a:b]
        if body and SELF_HIDE_BODY_RE.search(body) and re.search(r"__FILE__|plugin_basename|" + re.escape(os.path.basename(pf.path)), body + seg):
            conditional = re.search(r"get_option|get_site_option|white_?label|hide_plugin|setting", body, re.I)
            flags["self_hide"].append(pf.path)
            findings.append(_item("MEDIUM" if conditional else "HIGH", "self_hiding", "Hides Itself From the Plugin List",
                                  "all_plugins filter that unsets this plugin's own entry" +
                                  (" [behind a white-label setting]" if conditional else ""),
                                  pf, m.start(), seg[:100]))
            break
    # 8. auth backdoor: log a visitor in when a request parameter equals a hard-coded secret
    for m in (AUTH_SET_RE.finditer(code) if ("wp_set_auth_cookie" in pf.low or "wp_set_current_user" in pf.low) else ()):
        fn = pf.enclosing(m.start())
        tseg, _ = _span_text(pf, fn)
        lit = REQ_LITERAL_CMP_RE.search(tseg)
        # the backdoor logs in a FIXED privileged account; login / registration forms log in the
        # user the form just authenticated or created
        fixed = FIXED_USER_RE.search(tseg)
        if lit and fixed and not re.search(r"wp_verify_nonce|check_admin_referer|hash_equals\s*\(\s*\$|get_user_meta|get_transient|get_option",
                                 tseg):
            findings.append(_item("CRITICAL", "auth_backdoor", "Authentication Backdoor",
                                  "Logs the visitor in (wp_set_auth_cookie / wp_set_current_user) when a request "
                                  "parameter matches a hard-coded value",
                                  pf, m.start(), lit.group(0)))
            break
    # 9. remote content injected into the page (SEO spam / malicious JS) from output hooks
    _remote_inject(pf, findings, vendor)
    # 10. login credential harvester
    for m in pf.hooks():
        hook = m.group(1).lower()
        if not LOGIN_HOOK_RE.match(hook) or pf.in_comment(m.start()):
            continue
        body = _callback_body(pf, m)
        if body and re.search(r"\$_POST\s*\[\s*['\"](?:pwd|password)['\"]|\$password\b|\$pass\b|->user_pass", body) and \
                (NET_RE.search(body) or MAIL_RE.search(body) or re.search(r"curl_init|file_put_contents", body)) and \
                (_external_hosts(body, vendor) or RAWIP_RE.search(body) or EXFIL_RE.search(body) or MAIL_RE.search(body)
                 or re.search(r"file_put_contents", body)):
            findings.append(_item("CRITICAL", "login_harvest", "Login Credential Harvester",
                                  "A %s callback captures the submitted password and sends or stores it" % hook,
                                  pf, m.start(), text[m.start():m.start() + 100]))
            break
    # 11. PHP payload loaded from a non-PHP file
    for m in (INCLUDE_NONPHP_RE.finditer(text) if re.search(r"\.(?:ico|png|gif|jpe?g|bmp|woff2?|ttf|log|dat)['\"]\s*\)?\s*;", text) else ()):
        if pf.in_comment(m.start()) or pf.in_string(m.start()):
            continue
        findings.append(_item("HIGH", "include_nonphp", "Includes a Non-PHP File as Code",
                              "include/require of an image / text / font file (a classic loader for hidden PHP)",
                              pf, m.start(), m.group(0)))
        break


def _callback_body(pf, m):
    name = m.group(2) or m.group(3)
    if name:
        for n, a, b in pf.funcs:
            if n.lower() == name.lower():
                return pf.text[a:b]
        return None
    pos = m.start(4) if m.group(4) else (m.start(5) if m.group(5) else None)
    if pos is None:
        return None
    a, b = pf.closure_span(pos)
    return pf.text[a:b]


def _callback_span(pf, m):
    name = m.group(2) or m.group(3)
    if name:
        for n, a, b in pf.funcs:
            if n.lower() == name.lower():
                return (a, b)
        return None
    pos = m.start(4) if m.group(4) else (m.start(5) if m.group(5) else None)
    return None if pos is None else pf.closure_span(pos)


def _remote_inject(pf, findings, vendor):
    """Output-hook callback that prints what it fetched from a third-party host (the Display
    Widgets / 2024 injected-footer shape). The fetch, the hard-coded host and the echo must all
    sit in the same innermost function."""
    for m in pf.hooks():
        hook = m.group(1).lower()
        if hook not in OUTPUT_HOOKS or pf.in_comment(m.start()) or pf.in_string(m.start()):
            continue
        span = _callback_span(pf, m)
        if not span or not REMOTE_RE.search(pf.text, span[0], span[1]):
            continue
        for rm in REMOTE_RE.finditer(pf.text, span[0], span[1]):
            inner = pf.enclosing(rm.start())
            a, b = (inner[1], inner[2]) if inner and span[0] <= inner[1] < span[1] else span
            body = pf.text[a:b]
            tv = _tainted_vars(body, body)
            ret = r"|\breturn\s+[^;]{0,40}\$%s\b" if hook in ("the_content", "the_excerpt") else ""
            out = None
            for v in tv:
                out = re.search((r"\b(?:echo|print)\b[^;]{0,120}\$%s\b" + ret) % ((re.escape(v),) * (2 if ret else 1)), body)
                if out:
                    break
            if not out:
                out = re.search(r"\b(?:echo|print)\s+[^;]{0,40}" + REMOTE_SRC, body, re.I)
            if not out:
                continue
            ext = _external_hosts(body, vendor) or RAWIP_RE.findall(body)
            if not ext:
                continue    # own vendor / a known service / a URL built from settings
            cloak = CLOAK_RE.search(body)
            findings.append(_item("CRITICAL" if cloak else "HIGH", "remote_inject", "Remote Content Injection",
                                  "A %s callback fetches content from %s and prints it into the page%s" %
                                  (hook, ", ".join(sorted(set(ext))[:2]),
                                   " (hidden from logged-in users / shown to crawlers: SEO-spam cloaking)" if cloak else ""),
                                  pf, m.start(), pf.text[m.start():m.start() + 100]))
            return


def _plugin_combos(pfs, findings, flags, vendor):
    """Plugin-wide: an administrator created AND users hidden / the plugin hidden = the backdoor shape."""
    if flags["admin_create_files"] and (flags["user_hide"] or flags["self_hide"]):
        findings.append({"severity": "CRITICAL", "id": "hidden_admin", "name": "Hidden Administrator Backdoor",
                         "description": "Creates an administrator account and hides users and/or itself from wp-admin",
                         "file": flags["admin_create_files"][0], "line": 0, "matched": "",
                         "context": "plugin-level combination", "_pos": -1})
    if flags["user_hide"] and flags["self_hide"]:
        findings.append({"severity": "CRITICAL", "id": "stealth_combo", "name": "Stealth: Hides Users and Itself",
                         "description": "Hides specific users from the Users screen and itself from the plugin list",
                         "file": flags["self_hide"][0], "line": 0, "matched": "",
                         "context": "plugin-level combination", "_pos": -1})


# findings located at a hook registration (not at the code that runs): their timing is already known
NO_ESCALATE = {"self_hiding", "user_hiding"}


def _apply_context(pfs, findings, ctx_spans, load_files):
    """Escalate by when code runs; demote matches in tests/docs/examples."""
    by_path = {pf.path: pf for pf in pfs}
    tops = {}
    for f in findings:
        pf = by_path.get(f["file"])
        pos = f.get("_pos", -1)
        lvl = SEV_ORDER[f["severity"]]
        if DOC_PATH_RE.search("/" + f["file"]):
            if lvl > 2:
                f["severity"] = "MEDIUM"
                f["description"] += " [in a tests/docs/examples path]"
            continue
        if pf is None or pos < 0 or f["id"] in NO_ESCALATE:
            continue
        ctx = None
        for path, a, b, c, hook in ctx_spans:
            if path == f["file"] and a <= pos < b:
                ctx = (c, hook)
                break
        if ctx is None and f["file"] in load_files:
            if f["file"] not in tops:
                tops[f["file"]] = pf.top_level()
            if any(a <= pos < b for a, b in tops[f["file"]]):
                ctx = ("load", "top level of a file loaded by the main plugin file")
        if ctx is None:
            continue
        f["exec_context"] = ctx[0]
        if lvl >= 2:
            f["severity"] = _sev(min(4, lvl + 1)) if lvl == 2 else "CRITICAL"
            if lvl < SEV_ORDER[f["severity"]]:
                label = {"load": "runs on every request", "activation": "runs on activation",
                         "cron": "runs from wp-cron", "unauth": "reachable by anonymous visitors",
                         "login": "runs on every login"}[ctx[0]]
                f["description"] += " [%s: %s]" % (label, ctx[1])


# Naive, context-free rules (to measure what calibration buys)
NAIVE_SUBSTR = ("eval(", "base64_decode(", "gzinflate(", "wp_insert_user(", "wp_create_user(", "'all_plugins'",
                "'pre_user_query'", "shell_exec(", "passthru(", "system(", "exec(", "wp_set_auth_cookie(", "db_password")


def _naive(files):
    """Context-free rule set (any occurrence anywhere) - only used to measure what calibration buys."""
    hits = set()
    for path, text in files.items():
        if path.lower().endswith(PHP_EXT) and len(text) <= MAX_FILE:
            low = text.lower()
            for n in NAIVE_SUBSTR:
                if n in low:
                    hits.add(n.strip("('"))
            if "://" in low and RAWIP_RE.search(text):
                hits.add("raw_ip_url")
            if any(n in low for n in EXFIL_NEEDLES) and EXFIL_RE.search(text):
                hits.add("exfil_host")
    return sorted(hits)


def _summarise(findings, info, label, hdr, main, skipped, naive, vendor):
    for f in findings + info:
        f.pop("_pos", None)
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["file"], f["line"]))
    score = sum(SEVERITY_SCORE[f["severity"].lower()] for f in findings)
    level = "SAFE"
    for f in findings:
        if SEV_ORDER[f["severity"]] > SEV_ORDER[level]:
            level = f["severity"]
    return {"target": label, "plugin_name": hdr.get("plugin name", ""), "main_file": main,
            "vendor_hosts": sorted(vendor), "risk_level": level, "risk_score": min(100, score),
            "findings": findings, "info": info, "skipped_large_files": skipped, "naive_flags": naive,
            "scanner": "wordpress-audit %s" % __version__}


def scan(content, label="<text>"):
    """Scan a single string of PHP as if it were the main plugin file."""
    if "Plugin Name:" not in content[:8192]:
        content = content.replace("<?php", "<?php\n/* Plugin Name: text */", 1) if "<?php" in content else content
    return scan_plugin({"plugin.php": content}, label)


# ---------------------------------------------------------------------------
# Input: local dir / zip, or the WordPress.org plugin directory
# ---------------------------------------------------------------------------
def _decode(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _want(name):
    low = name.lower()
    return low.endswith(PHP_EXT + JS_EXT + IMG_EXT) or os.path.basename(low) in (".htaccess", ".user.ini")


def files_from_zip(data):
    files = {}
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = [i for i in z.infolist() if not i.is_dir()]
        tops = {i.filename.split("/", 1)[0] for i in names}
        strip = len(tops) == 1 and all("/" in i.filename for i in names)
        for i in names:
            if i.file_size > MAX_FILE * 2 or not _want(i.filename):
                continue
            low = i.filename.lower()
            if low.endswith(IMG_EXT) and i.file_size > 400000:
                continue
            rel = i.filename.split("/", 1)[1] if strip else i.filename
            raw = z.read(i)
            if low.endswith(IMG_EXT) and b"<?php" not in raw:
                continue
            files[rel] = _decode(raw)
    return files


def files_from_dir(root):
    files = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".git", "node_modules", ".svn")]
        for fn in fns:
            if not _want(fn):
                continue
            full = os.path.join(dp, fn)
            try:
                if os.path.getsize(full) > MAX_FILE * 2:
                    continue
                with open(full, "rb") as fh:
                    raw = fh.read()
            except OSError:
                continue
            if fn.lower().endswith(IMG_EXT) and b"<?php" not in raw:
                continue
            files[os.path.relpath(full, root).replace(os.sep, "/")] = _decode(raw)
    return files


_orig_gai = socket.getaddrinfo


def _ipv4_first(*a, **k):
    res = _orig_gai(*a, **k)
    return sorted(res, key=lambda r: 0 if r[0] == socket.AF_INET else 1)


socket.getaddrinfo = _ipv4_first


def _get(url, timeout=90, tries=4):
    err = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "wordpress-audit/%s" % __version__})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise
            err = e
        except Exception as e:  # noqa: BLE001 - flaky network: retry
            err = e
        time.sleep(2 * (i + 1))
    raise err


def split_spec(spec):
    if "@" in spec:
        s, v = spec.split("@", 1)
        return s, v or None
    return spec, None


def audit_slug(spec):
    slug, ver = split_spec(spec)
    if not re.match(r"^[a-z0-9][a-z0-9\-_]*$", slug):
        raise ValueError("not a plugin slug: %r" % slug)
    url = "%s/%s.%s.zip" % (DOWNLOADS, slug, ver or "latest-stable")
    files = files_from_zip(_get(url))
    return scan_plugin(files, spec, slug)


def popular(page, per_page=250):
    q = urllib.parse.urlencode({"action": "query_plugins", "request[browse]": "popular",
                                "request[per_page]": per_page, "request[page]": page,
                                "request[fields][description]": 0, "request[fields][sections]": 0})
    return json.loads(_get(API + "?" + q))


def _print(r, verbose):
    icon = {"CRITICAL": "!!", "HIGH": "! ", "MEDIUM": "~ ", "LOW": ". ", "SAFE": "ok"}[r["risk_level"]]
    print("%s %s  [%s]  score=%d  (%d findings, %d info)%s" % (
        icon, r["target"], r["risk_level"], r["risk_score"], len(r["findings"]), len(r["info"]),
        ("  " + r["plugin_name"]) if r.get("plugin_name") else ""))
    for f in r["findings"] + (r["info"] if verbose else []):
        print("    %-8s %s  %s:%s" % (f["severity"], f["name"], f["file"], f["line"]))
        if f.get("context"):
            print("             %s" % f["context"][:160])
        if verbose:
            print("             %s" % f["description"])


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if args[0] == "--version":
        print(__version__)
        return 0
    as_json = "--json" in args
    verbose = "--verbose" in args or "-v" in args
    args = [a for a in args if a not in ("--json", "--verbose", "-v")]
    results = []
    if args and args[0] == "--text":
        results.append(scan(" ".join(args[1:])))
    else:
        for a in args:
            try:
                if os.path.isdir(a):
                    results.append(scan_plugin(files_from_dir(a), a))
                elif os.path.isfile(a) and a.lower().endswith(".zip"):
                    with open(a, "rb") as fh:
                        results.append(scan_plugin(files_from_zip(fh.read()), a))
                elif os.path.isfile(a):
                    with open(a, "rb") as fh:
                        results.append(scan_plugin({os.path.basename(a): _decode(fh.read())}, a))
                else:
                    results.append(audit_slug(a))
            except Exception as e:  # noqa: BLE001
                results.append({"target": a, "risk_level": "SAFE", "risk_score": 0, "findings": [], "info": [],
                                "error": "%s: %s" % (type(e).__name__, e)})
    if as_json:
        print(json.dumps(results if len(results) != 1 else results[0], indent=2))
    else:
        for r in results:
            if r.get("error"):
                print("?? %s  error: %s" % (r["target"], r["error"]))
            else:
                _print(r, verbose)
    return 2 if any(SEV_ORDER[r["risk_level"]] >= 3 for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
