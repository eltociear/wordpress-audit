# What we found scanning 2,000 popular WordPress plugins

The research behind `wordpress-audit`: a real scan of the most-installed part of the
WordPress.org plugin directory with this exact engine, calibrated so that "clean" means clean
before any number is reported, then checked once on a held-out set it was never tuned on.

## Method

1. Listed the WordPress.org directory's `popular` browse (10 pages of 250 via
   `api.wordpress.org/plugins/info/1.2/`) and ranked by `active_installs`.
2. **Calibration set (1,200):** the top 1,200 by active installs (10M+ down to 20k installs).
   Rules were tuned against this set until HIGH+ false positives were 0.
3. **Rules frozen** in a git commit (`f05c237`), then the **held-out set (800)** - the next 800 by
   active installs (20k down to 10k) - was scanned **once**.
4. For each plugin: the version-pinned zip from `downloads.wordpress.org`, every PHP file up to
   2 MB, bundled JS (collector endpoints / `eval(atob(blob))` only) and image/font files that
   contain `<?php`. Each plugin scanned in its own subprocess with a timeout. Nothing installed,
   nothing executed.

Scan date: 2026-11-26. Latest stable versions at that time. 0 fetch errors, 0 timeouts.

## Headline

| | Calibration (1,200) | Held-out (800) |
| --- | --- | --- |
| Naive rule set flags (any `eval(`, `base64_decode(`, `system(`, `wp_insert_user(`, `all_plugins`, `pre_user_query`, `wp_set_auth_cookie(`, `DB_PASSWORD`, raw IP, collector host, ...) | 704 (58.7%) | 387 (48.4%) |
| Calibrated engine, HIGH / CRITICAL | 17 during tuning -> **0** | **2 (0.25%)**, both false positives |
| MEDIUM (review-worthy, not alerting) | 7 | 3 |
| SAFE | 1,193 | 795 |

**Held-out false positives (reported as measured, before any fix).** Both were the `php_drop`
rule (`.php` file written into uploads / plugins dir with request-supplied content):

- a plugin's custom-CSS editor that reuses one `$f` file handle: it first `fopen()`s an empty
  `index.php` guard file, then re-opens `$f` on a `.css` file and writes the admin's CSS. The rule
  resolved the handle to the *first* `fopen()` in the function instead of the most recent one.
- a plugin/theme code editor whose "create new plugin" action writes `<?php /* Plugin Name: ... */`
  from the admin's form into `WP_PLUGIN_DIR`, behind `current_user_can('edit_plugins')`.

Fixed after the held-out run: the handle now resolves to the latest `fopen()` before the write,
and request-only content behind a capability / nonce check is INFO ("Admin File Editor"). Both
fixes only demote, so the post-fix engine is 0/800 on the held-out set - but that is no longer a
blind number, and **0.25% is the honest held-out figure**. A regression fixture
(`ok-admin-editor`) covers both shapes.

**No plugin in either set was found to contain malicious code.** That is the expected result
for the most-installed plugins and it is what makes the tool usable: a CRITICAL on a zip from a
"nulled plugins" site or an unfamiliar author means something.

## The noise: what looks like a backdoor in WordPress but isn't

Per-plugin prevalence in the calibration set (INFO tier: reported with `--verbose`, never scored):

| Signal | Plugins | Why it's noise |
| --- | --- | --- |
| Outbound HTTP (`wp_remote_*`, curl) | 68% | License checks, update checkers, API integrations, analytics, feeds |
| Writes files | 52% | Caches, logs, exports, `index.php` "silence is golden" guards, `advanced-cache.php` drop-ins |
| `base64_decode(` | 34% | Images, settings blobs, JWTs, import/export, API payloads |
| Reads WordPress secrets (`DB_PASSWORD`, salts, `->user_pass`, users table) | 29% | Backups, migrations, security plugins, user tooling |
| `system(`/`exec(` etc. (naive) | 40% | Mostly method names (`->system(`, `->exec(` on PDO / WP-CLI), plus mysqldump / ImageMagick |
| `all_plugins` filter (naive) | 10% | Plugin managers, white-label, multisite UI - almost never self-hiding |
| `wp_insert_user` / `wp_create_user` | 10% | Registration, checkout account creation, membership, imports |
| `wp_set_auth_cookie(` (naive) | 9% | Login forms, social login, magic links, registration auto-login |
| `wp-config.php` reference | 16% | Cache plugins add `WP_CACHE`, security plugins harden it |
| `eval()` of a variable | 6% | Snippet / conditional-logic plugins evaluating admin-authored code |
| Collector host string | 5% | Public-suffix tables, Discord/Telegram/Slack integrations with the user's token |
| `pre_user_query` (naive) | 2% | Users-screen filtering by role / meta, not account hiding |

What the 17 calibration hits taught (each now has a benign fixture or a stricter rule):

| Noise class | Plugins | Fix |
| --- | --- | --- |
| `oast.pro` matching inside `toast.promise` / `yoast.propTypes`; `ngrok.app` in a public-suffix list | 3 | hosts anchored on word boundaries; JS hits must be inside a `scheme://` URL |
| `pre_user_query` / `pre_get_users` with an `'exclude'` arg | 2 | must exclude a *literal* login (`user_login != 'x'`, `login__not_in => ['x']`) |
| `include 'style.css'` in e-mail templates; `includes_url(` read as `include` | 3 | only image/font/log includes count; keyword needs a word boundary |
| `.txt` docs containing `<?php` examples | 2 | hidden-PHP check limited to image / font files |
| `auth_key` request field matched the `AUTH_KEY` constant; `['user_pass']` array key in a 600-line dispatcher | 2 | constants matched case-sensitively; unknown hosts must sit within ~1.5 KB of the secret |
| Remote fetch + echo inside a class nested in a hooked function; a vendor reverse proxy | 2 | fetch, literal third-party host and echo must share the innermost function |
| A remote-authenticated file writer with a variable filename | 1 | the write destination itself must be a literal `.php` path |
| SMS gateways on raw IPs | 1 | raw-IP HIGH needs site identity / credentials in the same function |
| Login form comparing `$_POST['action'] === 'register'` before `wp_set_auth_cookie` | 1 | backdoor must log in a *fixed* privileged account |

Two things carry most of the precision:

1. **Combination inside one function, not one file.** WordPress plugins are huge (UpdraftPlus
   ships 11 MB of PHP); file-level co-occurrence of "reads a secret" and "makes a request" is
   near-universal. Function spans from brace matching on comment/string-masked source made the
   difference.
2. **Strings and inline HTML are data.** Security plugins ship malware signatures
   (`'eval(base64_decode('`) as strings, and templates mention code in HTML. Masking them before
   matching code-sink patterns removed a whole class without losing the real shapes.

## MEDIUM (worth a look, not alerting)

- `gzinflate/gzdecode(base64_decode(...))` with no visible eval (8 plugins across both sets):
  packed import/export payloads, embedded assets, compressed settings.
- Raw public-IP endpoints in send code (2): SMS / payment gateways that publish IP endpoints.

## Takeaways

1. **A vulnerability scanner passing says nothing about a backdoor.** WPScan / Patchstack track
   disclosed CVEs; every incident canary here (2024 wordpress.org account takeovers, 2021
   AccessPress, 2017 Display Widgets, 2023 fake security plugin) shipped as a fresh version that
   no advisory covered yet. Scan new versions for behaviour.
2. **Scan before activation, not after.** Activation hooks, the main file's top level and
   `init` callbacks run before any runtime scanner can look; that is why findings there escalate.
3. **Score combinations, not capabilities.** 59% of the most-installed plugins trip a naive
   "dangerous function" list.
4. **Your own premium / nulled / client-supplied zips are the real target.** The directory is
   reviewed and clean; the zip from a forum is not.

---

*Findings are pattern matches warranting human review, not verdicts. No plugin in the scanned
corpus is accused of anything; the held-out false positives are described by shape only.
Suspected malicious plugins should be reported to the WordPress.org plugin team
(plugins@wordpress.org) and the author, not published as unverified accusations.*
