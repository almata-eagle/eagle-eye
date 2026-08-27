# Eagle Eye — Client Self-Service Security Portal

The client-facing counterpart to Eagle Talon. Where Talon is an operator's
console for managing many domains across many client workspaces, Eye is the
individual client's own portal — usually 1-3 domains, framed as a personal
security checkup rather than a monitoring console. Same passive-OSINT scan
engine underneath, different audience and tone entirely.

## Two modes, both real

- **Independent**: a client signs up directly, adds their own domain(s),
  runs their own checks. No dependency on Eagle Talon at all.
- **Tied to Eagle Talon**: if an operator (e.g. an insurer or a supply-chain
  manager) has already scanned this client's domain in Talon, the client can
  link their Eagle Eye account to that Talon client ID and see the *same*
  result Talon already has — no redundant re-scan, and the two stay in sync
  automatically since Eye reads Talon's database directly (read-only).

## Bilingual

Full English/Japanese throughout, including all plain-language remediation
content — reused directly from Eagle Talon's "what a hacker could do with
this" / "how to fix it" copy, just presented in a warmer, less console-like
shell.

## Deploying alongside Eagle Talon on core

Eagle Eye needs Talon's Docker volume (`eagle-talon-data`) to exist for the
linking feature to work, so **deploy Talon at least once first** if you
haven't already.

```bash
# on core
git clone https://github.com/almata-eagle/eagle-eye.git   # or wherever this repo ends up
cd eagle-eye/deploy
cp .env.example .env
nano .env    # adjust EAGLE_EYE_WEB_PORT if 8089 is taken — check with:
             #   docker ps --format '{{.Names}}\t{{.Ports}}'
docker compose up -d --build
```

This runs two new containers (`eagle-eye-api`, `eagle-eye-web`) alongside
Talon's existing ones, on different ports, using the same host-networking
approach Talon needed on this box (see Talon's own deploy notes for why —
short version: Tailscale's netfilter management excludes Docker's usual
bridge-NAT rule on this specific host).

Once up: `http://core:8089` (or whatever port you set) from any device on
your tailnet.

## Local dev / testing without Docker

```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8001

# separate terminal
cd frontend
python3 -m http.server 5501
```

Then `http://localhost:5501`.

## What's intentionally minimal here (prototype-grade, flagged honestly)

- **Auth**: PBKDF2-HMAC-SHA256 password hashing (stdlib only, no bcrypt
  dependency), bearer tokens with no expiry, no email verification, no
  password reset flow. Fine for a demo; needs hardening before real
  customer accounts.
- **No rate limiting** on login/signup — same caveat as Talon's API generally.
- **HTTPS**: not configured here — same as Talon, this assumes it's sitting
  behind Tailscale/a private network, not exposed directly to the public
  internet as-is.
