\# jsrecon



Automated JavaScript recon pipeline: collects JS files from a target, downloads them in parallel with rate limiting, and analyzes them for exposed API endpoints and leaked secrets (API keys, tokens, credentials).



Instead of reinventing JS parsing or secret-detection logic, `jsrecon` chains together proven, actively maintained security tools into one clean workflow with a single command.



\## How it works



| Stage | Tool |

|---|---|

| Collect JS URLs | \[katana](https://github.com/projectdiscovery/katana) (+ optional \[gau](https://github.com/lc/gau) for historical/Wayback JS) |

| Download | \[httpx](https://github.com/projectdiscovery/httpx) — parallel requests, built-in rate limiting |

| Endpoint extraction | Python regex engine (LinkFinder-style patterns) |

| Secret detection | \[gitleaks](https://github.com/gitleaks/gitleaks) — default rule set always on; custom regex is additive only |

| Report merging | Python + jq |



The script checks for all required tools on startup and offers to install anything missing.



\## Usage



```bash

chmod +x jsrecon.sh

./jsrecon.sh -u https://target.com -t 20 -r 50

```



Or against a list of targets, with historical JS included:



```bash

./jsrecon.sh -l urls.txt --scope target.com --wayback --regex-file my\_rules.txt -o results/

```



\## Flags

Target:
-u, --url URL Single target URL
-l, --list FILE File of URLs, one per line
--scope DOMAIN Restrict discovered JS to this domain
--wayback Also pull historical JS via gau

Performance:
-t, --threads N Parallel requests (default 10)
-r, --rate-limit N Requests/sec (default 50)
--delay MS Fixed delay between requests
--timeout SEC Per-request timeout (default 10)
--retries N Retries per request (default 2)

Secrets:
--regex-file FILE Extra custom rules, ADDITIVE to gitleaks defaults.
Format: RULE_NAME|REGEX, one per line

Network:
--proxy URL
-H HEADER Repeatable, e.g. -H “Cookie: session=abc”

Output:
-o, --output DIR
--format json|csv|both (default: both)


## Output

jsrecon_output_<timestamp>/
├── js/ downloaded JS files
├── raw/ intermediate output per stage
├── report.json merged findings grouped by source file
└── report.csv flat endpoint/secret rows


## Requirements

`katana`, `httpx` (on Kali/Debian: `httpx-toolkit`), `gitleaks`, `jq`, `python3`, and `gau` if using `--wayback`. The script auto-detects missing tools and offers to install them.

## Legal

Only run this against targets you own or are explicitly authorized to test.
