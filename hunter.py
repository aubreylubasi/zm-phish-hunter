"""ZM Phish Hunter - finds new websites that pretend to be Zambian banks,
mobile money services and public bodies.

Every new HTTPS website needs a certificate, and every certificate is written
to public logs. This bot searches those logs (through crt.sh) for new domain
names that look like a Zambian brand, scores how suspicious each one is, and
writes a report. It is passive: it never visits or scans the websites.

    python hunter.py                 # normal run: search, score, write the report
    python hunter.py --dry-run       # same, but save nothing and send no alerts
    python hunter.py --check         # test that each search works
    python hunter.py --score zanaco-login.top mtn.zm   # score names by hand

Settings and the list of brands are in config.toml.
"""
import argparse
import json
import os
import re
import socket
import sys
import time
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATE_FILE = ROOT / "state" / "seen.json"
REPORT_FILE = ROOT / "findings" / "latest.md"
HISTORY_FILE = ROOT / "findings" / "all.json"
USER_AGENT = "zm-phish-hunter (student research; github.com/aubreylubasi)"

# Second-level endings where the registered name is one label further left.
TWO_PART_ENDINGS = {
    "co.zm", "com.zm", "org.zm", "ac.zm", "gov.zm", "net.zm", "edu.zm", "info.zm", "biz.zm", "sch.zm",
    "co.za", "org.za", "co.uk", "org.uk", "co.ke", "co.tz", "co.zw", "com.ng", "co.in", "com.au",
}
# Places where anyone can get a free sub-domain: the brand name shows up left of these.
FREE_HOSTS = {
    "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "vercel.app", "netlify.app", "github.io",
    "weebly.com", "wixsite.com", "blogspot.com", "glitch.me", "r2.dev", "onrender.com", "herokuapp.com",
    "godaddysites.com", "square.site", "webflow.io", "framer.app", "replit.app", "surge.sh",
}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"})


def log(msg):
    print(msg, flush=True)


# ───────────────────────────── domain helpers ─────────────────────────────

def clean_domain(name):
    """'*.Login.Example.com.' -> 'login.example.com'. Returns '' for things that aren't domains."""
    name = name.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", name):
        return ""
    return name


def registered_domain(domain):
    """The part someone actually registered: 'login.zanaco.co.zm' -> 'zanaco.co.zm'.
    On free hosts the sub-domain is the 'registered' part: 'zanaco.web.app' stays whole."""
    labels = domain.split(".")
    for host in FREE_HOSTS:
        if domain.endswith("." + host):
            return ".".join(labels[-(host.count(".") + 2):])
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_PART_ENDINGS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def free_host_of(domain):
    return next((h for h in FREE_HOSTS if domain.endswith("." + h)), None)


def name_part(domain):
    """Everything left of the public ending - the part a scammer chooses."""
    ending = free_host_of(domain)
    if ending is None:
        labels = domain.split(".")
        ending = ".".join(labels[-2:]) if ".".join(labels[-2:]) in TWO_PART_ENDINGS else labels[-1]
    return domain[: -(len(ending) + 1)]


def tokens_of(text):
    """'secure-zanaco2.login' -> ['secure', 'zanaco', 'login'] (digits split words unless they look like letters)."""
    return [t for t in re.split(r"[^a-z]+", text) if t]


def edit_distance_1(a, b):
    """True if a and b differ by exactly one insert, delete, swap or changed letter."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    for i in range(len(long_)):
        if long_[:i] + long_[i + 1:] == short:
            return True
    return False


# ───────────────────────────── scoring ─────────────────────────────

def match_brand(domain, brand, context_words):
    """Returns (kind, alias) where kind is 'exact', 'inside' or 'lookalike', or None if no match."""
    chosen = name_part(domain)
    plain_tokens = tokens_of(chosen)
    leet_tokens = tokens_of(chosen.translate(LEET))

    def joined(tokens):
        """Tokens plus neighbouring tokens glued together: ['zana', 'co'] also gives 'zanaco'."""
        return set(tokens) | {"".join(tokens[i:i + n]) for n in (2, 3) for i in range(len(tokens) - n + 1)}

    plain, leet = joined(plain_tokens), joined(leet_tokens)
    found = None
    for alias in brand["names"]:
        if alias in plain:
            found = ("exact", alias)
        elif len(alias) >= 5 and any(alias in t for t in plain_tokens):
            found = ("inside", alias)
        elif alias in leet or (len(alias) >= 5 and any(alias in t for t in leet_tokens)):
            found = ("lookalike", alias)                # digits standing in for letters: zanac0
        elif len(alias) >= 6 and any(edit_distance_1(t, alias) for t in leet):
            found = ("lookalike", alias)                # one letter off: zannaco, zanaoc
        if found:
            break
    if not found:
        return None
    if brand.get("needs_zambia_context"):
        # Names like MTN or Absa are used in many countries: only count them with a Zambia hint.
        alias = found[1]
        has_context = (domain.endswith(".zm")
                       or any(w in plain_tokens for w in context_words)
                       or any(len(w) >= 5 and w in t for w in context_words for t in plain_tokens)
                       or any(t in (alias + "zm", "zm" + alias) for t in leet_tokens))
        if not has_context:
            return None
    return found


def score_domain(domain, cfg):
    """Returns None if the domain is official or matches no brand, otherwise a finding dict."""
    official = {d for b in cfg["brands"] for d in b["official_domains"]} | set(cfg.get("ignore_domains", []))
    reg = registered_domain(domain)
    if reg in official or domain in official:
        return None
    best = None
    for brand in cfg["brands"]:
        m = match_brand(domain, brand, cfg["zambia_words"])
        if m and (best is None or (m[0] == "lookalike" and best[1][0] != "lookalike")):
            best = (brand, m)
    if not best:
        return None
    brand, (kind, alias) = best
    chosen = name_part(domain)
    toks = tokens_of(chosen)
    score, reasons = 50, [f"uses the name \"{alias}\" ({brand['label']})"]
    if kind == "lookalike":
        score += 20
        reasons.append("the name is misspelt or uses digits for letters")
    lures = sorted({w for w in cfg["lure_words"] if w in toks or (len(w) >= 5 and w in chosen)})
    if lures:
        score += 15
        reasons.append("lure words: " + ", ".join(lures))
    tld = domain.rsplit(".", 1)[-1]
    if tld in cfg["risky_endings"]:
        score += 10
        reasons.append(f"cheap ending .{tld}")
    host = free_host_of(domain)
    if host:
        score += 10
        reasons.append(f"free hosting ({host})")
    if chosen.count("-") >= 2 or len(chosen) >= 30:
        score += 10
        reasons.append("long name with several hyphens")
    if "xn--" in domain:
        score += 10
        reasons.append("uses special characters that can look like normal letters")
    if not domain.endswith(".zm") and brand.get("official_domains") and all(d.endswith(".zm") for d in brand["official_domains"]):
        score += 5
        reasons.append("not a .zm address, unlike the real one")
    score = min(score, 100)
    level = "high" if score >= cfg["high_score"] else "medium" if score >= cfg["medium_score"] else "low"
    return {"domain": domain, "brand": brand["label"], "score": score, "level": level, "reasons": reasons}


# ───────────────────────────── certificate search ─────────────────────────────

def search_crtsh(term, cfg):
    """All unexpired certificates whose names contain `term`. Returns a list of crt.sh rows."""
    import requests
    url = "https://crt.sh/"
    params = {"q": f"%{term}%", "output": "json", "exclude": "expired", "deduplicate": "Y"}
    last = None
    for attempt in range(1, cfg["search_retries"] + 1):
        try:
            r = requests.get(url, params=params, timeout=cfg["search_timeout"], headers={"User-Agent": USER_AGENT})
            if r.status_code == 200:
                return r.json() if r.text.strip() else []
            last = f"HTTP {r.status_code}"
        except Exception as e:  # noqa: BLE001 - crt.sh is often slow; try again
            last = type(e).__name__
        time.sleep(5 * attempt)
    raise RuntimeError(f"crt.sh did not answer for '{term}' ({last})")


def parse_time(text):
    try:
        t = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


def domains_from_rows(rows, since):
    """{domain: {first_logged, issuer}} for certificates logged after `since`."""
    out = {}
    for row in rows:
        logged = parse_time(row.get("entry_timestamp") or row.get("not_before") or "")
        if since and logged and logged < since:
            continue
        names = f"{row.get('common_name') or ''}\n{row.get('name_value') or ''}".split("\n")
        issuer = re.search(r"O=([^,]+)", row.get("issuer_name") or "")
        for raw in names:
            d = clean_domain(raw)
            if d and (d not in out or (logged and out[d]["logged"] and logged < parse_time(out[d]["logged"]))):
                out[d] = {"logged": logged.isoformat() if logged else None,
                          "issuer": issuer.group(1).strip('"') if issuer else ""}
    return out


def resolves(domain):
    try:
        socket.setdefaulttimeout(5)
        socket.getaddrinfo(domain, 443)
        return True
    except OSError:
        return False


# ───────────────────────────── state, report, alerts ─────────────────────────────

def load_config(path=ROOT / "config.toml"):
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    s = cfg["settings"]
    out = {**s, "brands": cfg["brands"]}
    for b in out["brands"]:
        b["names"] = [n.lower() for n in b["names"]]
        b["official_domains"] = [d.lower() for d in b["official_domains"]]
    out["zambia_words"] = [w.lower() for w in s["zambia_words"]]
    return out


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def defang(domain):
    """zanaco-login.top -> zanaco-login[.]top, so nobody clicks it by accident."""
    return domain.replace(".", "[.]")


def write_report(new, history, failed, now):
    lines = ["# ZM Phish Hunter - latest findings", "",
             f"*Last run: {now:%d %B %Y, %H:%M} UTC*", "",
             "Domains are written with `[.]` so they can't be clicked by accident. "
             "A finding is a **lead to check**, not proof of a scam.", ""]
    if failed:
        lines += [f"> Searches that failed this run and will be tried again: {', '.join(failed)}", ""]
    lines += [f"## New this run ({len(new)})", ""]
    if not new:
        lines += ["Nothing new.", ""]
    for f in new:
        live = "online" if f.get("online") else "not online yet" if f.get("online") is False else "not checked"
        lines += [f"### {defang(f['domain'])}",
                  f"- **May imitate:** {f['brand']}",
                  f"- **Score:** {f['score']}/100 ({f['level']})",
                  f"- **Why:** {'; '.join(f['reasons'])}",
                  f"- **Certificate logged:** {(f.get('logged') or 'unknown')[:16].replace('T', ' ')} UTC"
                  + (f", issued by {f['issuer']}" if f.get("issuer") else ""),
                  f"- **Status:** {live}", ""]
    recent = sorted(history.values(), key=lambda f: f.get("found") or "", reverse=True)[:50]
    lines += ["## Last 50 findings", "", "| Found | Domain | May imitate | Score |", "|---|---|---|---|"]
    lines += [f"| {(f.get('found') or '')[:10]} | {defang(f['domain'])} | {f['brand']} | {f['score']} ({f['level']}) |"
              for f in recent]
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def send_telegram(findings):
    token, chat = os.environ.get("TG_BOT_TOKEN"), os.environ.get("TG_CHAT_ID")
    if not (token and chat and findings):
        return
    import requests
    text = "🚨 ZM Phish Hunter: new suspicious domains\n\n" + "\n\n".join(
        f"{defang(f['domain'])}\nMay imitate: {f['brand']} | score {f['score']}\n{'; '.join(f['reasons'])}"
        for f in findings[:10])
    try:
        requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                      json={"chat_id": chat, "text": text[:4000], "disable_web_page_preview": True}, timeout=20)
    except Exception as e:  # noqa: BLE001 - an alert problem must not lose the findings
        log(f"   Telegram alert failed ({type(e).__name__})")


# ───────────────────────────── main ─────────────────────────────

def hunt(cfg, dry_run=False, rows_file=None):
    now = datetime.now(timezone.utc)
    state = load_json(STATE_FILE, {"first_run_done": False, "seen": {}})
    history = load_json(HISTORY_FILE, {})
    days = cfg["lookback_days"] if state["first_run_done"] else cfg["first_run_lookback_days"]
    since = now - timedelta(days=days)
    log(f"Looking for certificates logged in the last {days} day(s)")

    found, failed = {}, []
    if rows_file:
        found = domains_from_rows(json.loads(Path(rows_file).read_text(encoding="utf-8")), since)
    else:
        terms = sorted({t.lower() for b in cfg["brands"] for t in b.get("search", [])} | set(cfg["extra_searches"]))
        for i, term in enumerate(terms):
            if i:
                time.sleep(cfg["seconds_between_searches"])  # be polite to crt.sh
            try:
                rows = search_crtsh(term, cfg)
            except RuntimeError as e:
                log(f"❌ {e}")
                failed.append(term)
                continue
            got = domains_from_rows(rows, since)
            log(f"✅ '{term}': {len(rows)} certificates, {len(got)} recent names")
            for d, info in got.items():
                found.setdefault(d, info)

    new = []
    for domain, info in sorted(found.items()):
        if domain in state["seen"]:
            continue
        state["seen"][domain] = now.isoformat()
        f = score_domain(domain, cfg)
        if not f or f["level"] == "low":
            continue
        f.update(info, found=now.isoformat())
        new.append(f)
    # One entry per registered name: keep the highest score (www.x and x are the same site).
    by_reg = {}
    for f in new:
        key = registered_domain(f["domain"])
        if key not in by_reg or f["score"] > by_reg[key]["score"]:
            by_reg[key] = f
    new = sorted(by_reg.values(), key=lambda f: -f["score"])
    for f in new[: cfg["max_online_checks"]]:
        f["online"] = resolves(f["domain"])

    log(f"\n{len(found)} names checked, {len(new)} new finding(s)")
    for f in new:
        log(f"  {f['score']:3d} {f['level']:6} {defang(f['domain'])}  -> {f['brand']}: {'; '.join(f['reasons'])}")
    if dry_run:
        return new
    for f in new:
        history[f["domain"]] = f
    state["first_run_done"] = state["first_run_done"] or not failed or bool(found)
    write_report(new, history, failed, now)
    save_json(STATE_FILE, state)
    save_json(HISTORY_FILE, history)
    send_telegram([f for f in new if f["level"] == "high"])
    return new


def main():
    ap = argparse.ArgumentParser(description="Find new websites that imitate Zambian brands.")
    ap.add_argument("--dry-run", action="store_true", help="search and score, but save nothing")
    ap.add_argument("--check", action="store_true", help="test each certificate search")
    ap.add_argument("--score", nargs="+", metavar="DOMAIN", help="score these names and exit")
    ap.add_argument("--probe", metavar="TERM", help="show the raw crt.sh answers for one term (for debugging)")
    ap.add_argument("--rows", help="read crt.sh rows from a JSON file instead of the internet (for testing)")
    args = ap.parse_args()
    cfg = load_config()

    if args.score:
        for raw in args.score:
            d = clean_domain(raw)
            f = score_domain(d, cfg) if d else None
            if not d:
                print(f"{raw}: not a domain name")
            elif not f:
                print(f"{d}: nothing suspicious (official, or no brand name in it)")
            else:
                print(f"{d}: {f['score']}/100 ({f['level']}) - may imitate {f['brand']}: {'; '.join(f['reasons'])}")
        return
    if args.probe:
        import requests
        for q, extra in [(f"%{args.probe}%", {"exclude": "expired", "deduplicate": "Y"}), (f"%{args.probe}%", {}),
                         (f"%.{args.probe}.co.zm", {}), (f"{args.probe}.co.zm", {})]:
            try:
                r = requests.get("https://crt.sh/", params={"q": q, "output": "json", **extra}, timeout=120,
                                 headers={"User-Agent": USER_AGENT})
                body = r.text.strip()
                n = len(r.json()) if body.startswith("[") else "not JSON"
                print(f"q={q} {extra}: HTTP {r.status_code}, {len(r.content)} bytes, rows={n}, starts {body[:80]!r}")
            except Exception as e:  # noqa: BLE001
                print(f"q={q} {extra}: {type(e).__name__}: {e}")
            time.sleep(6)
        return
    if args.check:
        ok = True
        for term in sorted({t for b in cfg["brands"] for t in b.get("search", [])} | set(cfg["extra_searches"])):
            try:
                print(f"✅ {term}: {len(search_crtsh(term, cfg))} certificates")
            except RuntimeError as e:
                ok = False
                print(f"❌ {e}")
            time.sleep(cfg["seconds_between_searches"])
        sys.exit(0 if ok else 1)
    hunt(cfg, dry_run=args.dry_run, rows_file=args.rows)


if __name__ == "__main__":
    main()
