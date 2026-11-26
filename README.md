# wordpress-audit

**Scan a WordPress plugin for *malicious* code before you install or activate it.**
One file, Python 3.9+, standard library only, MIT.

```bash
python3 wordpress_audit.py some-plugin            # fetch the zip from downloads.wordpress.org and scan it
python3 wordpress_audit.py some-plugin@1.2.3      # a specific version
python3 wordpress_audit.py ./premium-plugin.zip   # a zip you were sent / bought / downloaded
python3 wordpress_audit.py ./wp-content/plugins/some-plugin/
# !! social-share-canary  [CRITICAL]  score=100  (4 findings, 2 info)  Social Share Canary
#     CRITICAL Hard-Coded Administrator Account  social-warfare.php:14
#              $user_id = wp_insert_user( array(
#     CRITICAL Remote Content Injection  social-warfare.php:28
#              add_action( 'wp_footer', 'sw_canary_footer' );
```

**The plugin is never installed and none of its code runs.** The zip is downloaded into memory
and read as text. Exit code `2` if anything is HIGH/CRITICAL, so it drops into CI or a deploy
script.

## How this differs from Wordfence / WPScan / Patchstack

| | Wordfence | WPScan / Patchstack | **wordpress-audit** |
| --- | --- | --- | --- |
| Runs | inside a live site, after the plugin is installed | against a database of disclosed vulnerabilities | on the zip, **before** upload / activation |
| Answers | "does this site contain known malware signatures / is this request an attack?" | "does this plugin version have a known CVE?" | "does this zip contain backdoor *behaviour* nobody has reported yet?" |
| Needs | PHP, WordPress, the plugin activated | the plugin slug + version | nothing but the file |

These are complementary. WPScan cannot flag a version that was backdoored an hour ago (there is
no advisory yet), and a runtime scanner only sees the plugin after its activation hook has already
run. `wordpress-audit` is the pre-install gate: the place to look at a nulled / "premium" zip, a
plugin a client sent you, or a new version of a plugin you already trust, before WordPress loads it.
It looks for **malicious shapes**, not vulnerabilities (an unescaped `$_GET` is a bug for WPScan,
not a backdoor).

## What it flags

| Pattern | Severity |
| --- | --- |
| `eval` / `assert` / `create_function` of `base64_decode` / `gzinflate` / `str_rot13` / ... | CRITICAL |
| Request-controlled execution (`eval($_POST[..])`, `$_GET['f']($_GET['a'])`, `system($_REQUEST..)`) | CRITICAL |
| Remote code execution (`eval()` of something fetched with `wp_remote_get` / `file_get_contents(url)` / curl) | CRITICAL |
| `.php` file dropped into uploads / mu-plugins / wp-includes / a theme with remote, decoded or request content | CRITICAL |
| Administrator created with a hard-coded username/password, or whose credentials are sent off-site | CRITICAL |
| Administrator created **and** users hidden (`pre_user_query`) or the plugin hidden (`all_plugins`) | CRITICAL |
| Authentication backdoor (`wp_set_auth_cookie` when a request parameter equals a hard-coded secret) | CRITICAL |
| `wp-config.php` / `DB_PASSWORD` / salts / `user_pass` / users table sent to a third-party host | CRITICAL / HIGH |
| Login hook that captures the submitted password and sends or stores it | CRITICAL |
| `wp_head` / `wp_footer` / `the_content` callback that prints content fetched from a third-party host (SEO spam); CRITICAL with crawler / logged-out cloaking | HIGH / CRITICAL |
| Hides users from the Users screen; hides itself from the plugin list | HIGH |
| Chat-webhook / paste / tunnel / OAST collector hard-coded next to a send | HIGH |
| Obfuscated function names (`"\x65\x76\x61\x6c"`, `strrev('edoced_46esab')`, `'ba'.'se64'`) | HIGH |
| PHP hidden in an image / font file; `include` of an image file | HIGH |
| Raw public-IP endpoint (HIGH when the same function sends to it) | MEDIUM / HIGH |
| `gzinflate(base64_decode(...))` without a visible eval | MEDIUM |

Capabilities that popular plugins use every day (`wp_remote_post`, `eval` of a user's snippet,
`exec`, `base64_decode`, `wp_insert_user`, writing `advanced-cache.php`, reading `DB_PASSWORD` for
a backup) are reported in an INFO tier (`--verbose`) that never touches the score.

## Context model: when does this code run?

A WordPress plugin's code runs at very different moments, and the same line means very different
things depending on which:

| Context | How it is detected | Effect |
| --- | --- | --- |
| **Every request** | top level of the main plugin file and of files it `require`s; callbacks on `init`, `plugins_loaded`, `wp_loaded`, `wp`, `template_redirect`, `wp_head`, `wp_footer`, `the_content`, `admin_init`, ... | HIGH -> CRITICAL, MEDIUM -> HIGH |
| **Activation** | `register_activation_hook` callbacks (named, method or closure) | same |
| **wp-cron** | callbacks on hooks scheduled with `wp_schedule_event` / `wp_schedule_single_event` | same |
| **Anonymous visitors** | `wp_ajax_nopriv_*` callbacks; REST routes with `'permission_callback' => '__return_true'` | same |
| **Every login** | `wp_login`, `wp_authenticate`, `authenticate` callbacks | same |

Callbacks are resolved by name across the whole plugin (`'fn'`, `array($this, 'm')`, `[__CLASS__, 'm']`,
`'Class::m'`, closures and arrow functions) and their bodies found by brace matching on a copy of
the source with comments, strings, heredocs and inline HTML blanked out.

Demotions:

- a match inside a **comment**, or a code-sink pattern inside a **string** (security plugins ship
  malware signatures like `'eval(base64_decode('` as data) is dropped;
- **inline HTML** (`?> ... <?php`) is treated as a string, so a template mentioning `eval(` is inert;
- anything under `tests/`, `docs/`, `examples/`, `node_modules/`, `bin/`, ... is capped at MEDIUM;
- network destinations on the plugin's **own vendor domain** (from `Plugin URI` / `Author URI` /
  `Update URI`) or a **well-known service** (wordpress.org, Google, Stripe, Dropbox, Freemius, ...)
  are licensing / update / analytics traffic: remote-eval from the vendor is MEDIUM, remote
  content printed from the vendor is not flagged;
- chat APIs called with a token from the settings (`api.telegram.org/bot' . $token`) are
  integrations; only a hard-coded token / webhook id makes them a collector.

## Calibrated, not noisy

Measured on **2,000 WordPress.org plugins** (the top 2,000 by active installs, 10M+ down to 10k):

| | Flagged HIGH/CRITICAL |
| --- | --- |
| Naive rules (any `eval(` / `base64_decode(` / `system(` / `wp_insert_user(` / `all_plugins` / `pre_user_query` / `wp_set_auth_cookie(` / `DB_PASSWORD` / raw IP / collector host) | 704 / 1,200 (58.7%) |
| Calibrated engine, calibration set (top 1,200) | 17 during tuning -> **0 / 1,200** |
| Calibrated engine, **held-out** set (next 800, rules frozen first, scanned once) | **2 / 800 (0.25%)**, both false positives |

Both held-out false positives were the `.php`-file-drop rule on admin code / CSS editors (a
reused file handle, and a "create plugin" form behind `current_user_can`). They were fixed after
the held-out run (demotions only) and have a regression fixture; the 0.25% is the honest blind
number. No plugin in the corpus was found to contain malicious code.

**Full results: [FINDINGS.md](FINDINGS.md)** (method, noise taxonomy, what surfaced).

## Usage

```bash
python3 wordpress_audit.py <slug>[@version] [...]   # WordPress.org plugin directory
python3 wordpress_audit.py ./plugin.zip              # local zip (one top-level folder is stripped)
python3 wordpress_audit.py ./plugin-dir/             # local directory
python3 wordpress_audit.py file.php                  # one file
python3 wordpress_audit.py --text "<?php ..."        # a string
python3 wordpress_audit.py <target> --json           # machine-readable
python3 wordpress_audit.py <target> --verbose        # also print INFO context
```

As a library:

```python
import wordpress_audit as wa
r = wa.audit_slug("akismet")                  # or wa.scan_plugin(wa.files_from_zip(data), "label")
r["risk_level"], r["findings"], r["main_file"], r["vendor_hosts"]
```

Reproduce the corpus run: `python3 scripts/bulk_scan.py list list.json`, then
`python3 scripts/bulk_scan.py scan list.json 0 1200 calib.jsonl` (each plugin is scanned in its
own subprocess with a timeout; nothing is written to disk unless you use `fetch` + `--zipdir`).

## Tests

```bash
python3 -m unittest
```

Eleven inert malicious canaries must each fire their rule at the expected severity, including
one for each real incident shape:

- **June 2024 WordPress.org supply-chain compromise** (Social Warfare and four others): injected
  code that created an administrator with a hard-coded password, posted the credentials to a
  raw-IP server, and printed remote SEO spam into the footer -> `hardcoded_admin`, `remote_inject`,
  `raw_ip_url`, all CRITICAL;
- **2021 AccessPress backdoor**: an `initial.php` dropper included from the main file that reported
  the site to `wp-theme-connect` and planted a webshell in `wp-includes/vars.php` -> `php_drop` CRITICAL;
- **2017 Display Widgets**: `geolocation.php` that posted visitor IP / UA to a remote server and
  appended the returned spam to `the_content` for logged-out visitors -> `remote_inject` CRITICAL;
- **2023 fake security plugin**: hides itself from the plugin list, hides its admin from the Users
  screen, creates that admin with a fixed password, and logs in anyone with a magic `?key=` ->
  `hidden_admin`, `stealth_combo`, `auth_backdoor`, CRITICAL;
- **`eval(gzinflate(base64_decode(...)))`** -> `eval_decoded` CRITICAL;

plus a request webshell, remote `eval` from a wp-cron event, `wp-config.php` exfiltration on
activation, a login-password harvester, PHP hidden in a `.ico`, and an mu-plugin dropped from an
open REST route. Thirteen benign controls (license checker, an admin code/CSS editor, temporary-login plugin, cache drop-in
writer, snippets plugin, white-label hide, Telegram integration, backup to Dropbox, a malware
scanner's signature list, a vendor news footer, HTML templates, an anti-spam API, asset includes)
must stay SAFE (the white-label one MEDIUM). Fixture hosts are `.invalid` / TEST-NET, passwords are
`CANARY_...` strings, encoded payloads decode to `echo 'CANARY_inert_payload';`, and nothing in
`tests/` is ever executed.

## Limits

Static and pattern-based. A determined attacker can split a payload across files and variables,
fetch stage 2 at runtime from a host built at runtime, or ship an ionCube-encoded file (reported
as nothing: this tool does not decode loaders). The callback resolver matches methods by name, so
two classes with a same-named method share a context. Files over 2 MB are skipped (listed in
`skipped_large_files`). Treat SAFE as "no known-bad shape", and findings as leads for human review,
not verdicts.

Family: [mcp-audit](https://github.com/eltociear/mcp-audit) (MCP servers & agent skills),
[npm-audit](https://github.com/eltociear/npm-audit), [crate-audit](https://github.com/eltociear/crate-audit)
and the other `eltociear/*-audit` scanners.

MIT licensed.
