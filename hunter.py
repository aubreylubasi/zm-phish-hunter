"""ZM Phish Hunter - finds websites that pretend to be Zambian banks,
mobile money services and public bodies.

How it works:
  1. For every brand in config.toml it builds the names a scammer would likely
     register: misspellings (zannaco, zanac0), added lure words (zanaco-login)
     and cheap endings (.top, .xyz).
  2. It asks DNS which of those names exist.
  3. For new ones it looks up the certificate in the public Certificate
     Transparency logs (crt.sh) to see when the site was set up.
  4. It scores each name and writes a report.
It is passive: it never visits or scans the websites.

    python hunter.py                 # normal run: generate, check, score, write the report
    python hunter.py --dry-run       # same, but save nothing and send no alerts
    python hunter.py --check         # test DNS and the certificate lookup
    python hunter.py --score zanaco-login.top mtn.zm   # score names by hand
    python hunter.py --candidates zanaco               # show the names it would try for a brand

Settings and the list of brands are in config.toml.
"""
import argparse
import itertools
import json
import os
import re
import socket
import sys
import time
import tomllib
import uuid
from concurrent.futures import ThreadPoolExecutor
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
    lures = sorted({w for w in cfg["lure_words"] if w in toks or (len(w) >= 5 and w in chosen)})
    if kind == "lookalike":
        # One letter off could also be an unrelated company, so on its own it only counts a little.
        score += 20 if lures else 10
        reasons.append("the name is one letter off, or uses digits for letters")
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


# ───────────────────────────── candidate names ─────────────────────────────

SWAPS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}


def misspellings(name):
    """Common ways to fake a name: drop, double or swap a letter, or use a digit that looks like one."""
    out = set()
    for i in range(len(name)):
        if len(name) >= 8:
            out.add(name[:i] + name[i + 1:])                  # dropping a letter of a short name gives
                                                              # ordinary words (zanco, amtel), so long names only
        out.add(name[:i] + name[i] * 2 + name[i + 1:])        # zannaco
        if name[i] in SWAPS:
            out.add(name[:i] + SWAPS[name[i]] + name[i + 1:])  # zanac0
        if i + 1 < len(name) and name[i] != name[i + 1]:
            out.add(name[:i] + name[i + 1] + name[i] + name[i + 2:])  # zanaoc
    out.discard(name)
    return {n for n in out if len(n) >= 4 and n[0].isalpha()}


def candidates_for(brand, cfg):
    """Every name the bot will try for one brand (without checking if it exists)."""
    endings, lures = cfg["try_endings"], cfg["try_lure_words"]
    main = brand["names"][0]          # lure words and misspellings are only tried on the main name
    bases, lure_bases = set(), set()
    for name in brand["names"]:
        if brand.get("needs_zambia_context"):
            # MTN, Absa…: only the Zambian forms, e.g. mtnzambia, mtn-zm, zambia-mtn
            for z in ("zambia", "zm"):
                bases |= {name + z, f"{name}-{z}", z + name, f"{z}-{name}"}
            if name == main:
                lure_bases |= {name + "zambia", f"{name}-zambia"}
        elif len(name) >= 4 or name == main:
            bases.add(name)
            if name == main:
                lure_bases.add(name)
    stems = set(bases)
    for base in lure_bases:
        if len(base) >= 5 and not brand.get("needs_zambia_context"):
            stems |= misspellings(base)
        for lure, sep in itertools.product(lures, ("", "-")):
            stems |= {f"{base}{sep}{lure}", f"{lure}{sep}{base}"}
    official = set(brand["official_domains"]) | set(cfg.get("ignore_domains", []))
    return {f"{stem}.{end}" for stem in stems for end in endings} - official


def lookup(domain):
    """True if the name, or www. in front of it, has an address in DNS."""
    for name in (domain, "www." + domain):
        try:
            socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)
            return True
        except OSError:
            continue
    return False


resolves = lookup  # kept under both names so tests can swap either


def wildcard_endings(endings):
    """Endings where every name 'exists' (the registry answers for anything). These are skipped."""
    bad = set()
    for end in endings:
        if lookup(f"zmph-{uuid.uuid4().hex[:16]}.{end}"):
            bad.add(end)
    return bad


def find_existing(names, workers):
    socket.setdefaulttimeout(6)
    names = sorted(names)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return {n for n, ok in zip(names, pool.map(lookup, names)) if ok}


# ───────────────────────────── certificate lookup ─────────────────────────────

def parse_time(text):
    try:
        t = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


def certificate_info(domain, cfg):
    """When the first certificate for this exact name was logged, and by whom. {} if unknown.
    (An exact-name lookup on crt.sh is reliable; its 'contains' search is not.)"""
    import requests
    for attempt in range(1, cfg["search_retries"] + 1):
        try:
            r = requests.get("https://crt.sh/", params={"q": domain, "output": "json"},
                             timeout=cfg["search_timeout"], headers={"User-Agent": USER_AGENT})
            if r.status_code == 200 and r.text.strip().startswith("["):
                rows = r.json()
                times = [(parse_time(x.get("entry_timestamp") or ""), x) for x in rows]
                times = [(t, x) for t, x in times if t]
                if not times:
                    raise ValueError("empty answer")  # crt.sh sometimes answers [] when busy: try again
                first, row = min(times, key=lambda p: p[0])
                issuer = re.search(r"O=([^,]+)", row.get("issuer_name") or "")
                return {"logged": first.isoformat(), "certificates": len(rows),
                        "issuer": issuer.group(1).strip('"') if issuer else ""}
        except Exception:  # noqa: BLE001 - crt.sh is often slow; try again
            pass
        time.sleep(5 * attempt)
    return {}


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
        live = "exists in DNS"
        lines += [f"### {defang(f['domain'])}",
                  f"- **May imitate:** {f['brand']}",
                  f"- **Score:** {f['score']}/100 ({f['level']})",
                  f"- **Why:** {'; '.join(f['reasons'])}",
                  "- **First certificate:** " + (f"{f['logged'][:10]}" + (f", issued by {f['issuer']}" if f.get("issuer") else "")
                                                 if f.get("logged") else "none found / not looked up"),
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

def hunt(cfg, dry_run=False):
    now = datetime.now(timezone.utc)
    state = load_json(STATE_FILE, {"seen": {}})
    history = load_json(HISTORY_FILE, {})

    names = set()
    for brand in cfg["brands"]:
        got = candidates_for(brand, cfg)
        log(f"{brand['label']}: {len(got)} names to try")
        names |= got
    bad = wildcard_endings(cfg["try_endings"])
    if bad:
        log(f"Skipping endings that answer for every name: {', '.join(sorted(bad))}")
        names = {n for n in names if n.rsplit(".", 1)[-1] not in bad and not any(n.endswith("." + b) for b in bad)}
    log(f"Checking which of {len(names)} names exist…")
    existing = find_existing(names, cfg["dns_workers"])
    log(f"{len(existing)} exist")

    new = []
    for domain in sorted(existing):
        if domain in state["seen"]:
            continue
        state["seen"][domain] = now.isoformat()
        f = score_domain(domain, cfg)
        if not f or f["level"] == "low":
            continue
        f.update(found=now.isoformat(), online=True)
        new.append(f)
    new.sort(key=lambda f: -f["score"])
    crt_down_first = False
    for i, f in enumerate(new[: cfg["max_certificate_lookups"]]):
        if i:
            time.sleep(cfg["seconds_between_searches"])  # be polite to crt.sh
        info = certificate_info(f["domain"], cfg)
        if not info and i < 2:
            crt_down = i == 1 or crt_down_first
            crt_down_first = True
            if crt_down:
                log("crt.sh isn't answering right now - skipping certificate dates this run")
                break
        f.update(info)
        if f.get("logged") and now - parse_time(f["logged"]) <= timedelta(days=cfg["fresh_days"]):
            f["score"] = min(f["score"] + 10, 100)
            f["reasons"].append(f"set up in the last {cfg['fresh_days']} days")
            f["level"] = "high" if f["score"] >= cfg["high_score"] else f["level"]
    new.sort(key=lambda f: -f["score"])

    log(f"\n{len(new)} new finding(s)")
    for f in new:
        log(f"  {f['score']:3d} {f['level']:6} {defang(f['domain'])}  -> {f['brand']}: {'; '.join(f['reasons'])}")
    if dry_run:
        return new
    for f in new:
        history[f["domain"]] = f
    write_report(new, history, [], now)
    save_json(STATE_FILE, state)
    save_json(HISTORY_FILE, history)
    send_telegram([f for f in new if f["level"] == "high"])
    return new


def main():
    ap = argparse.ArgumentParser(description="Find new websites that imitate Zambian brands.")
    ap.add_argument("--dry-run", action="store_true", help="search and score, but save nothing")
    ap.add_argument("--check", action="store_true", help="test DNS and the certificate lookup")
    ap.add_argument("--score", nargs="+", metavar="DOMAIN", help="score these names and exit")
    ap.add_argument("--candidates", metavar="BRAND", help="list the names it would try for a brand and exit")
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
    if args.candidates:
        for brand in cfg["brands"]:
            if args.candidates.lower() in brand["label"].lower():
                names = sorted(candidates_for(brand, cfg))
                print(f"{brand['label']}: {len(names)} names")
                print("\n".join(names))
        return
    if args.check:
        ok = True
        bad = wildcard_endings(cfg["try_endings"])
        print(f"Endings that answer for every name (skipped): {', '.join(sorted(bad)) or 'none'}")
        for d in ["zanaco.co.zm", "zesco.co.zm", "github.com"]:
            good = lookup(d)
            ok &= good
            print(f"{'✅' if good else '❌'} DNS finds the real site {d}")
        info = certificate_info("zesco.co.zm", cfg)
        print(f"{'✅' if info else '⚠️'} certificate lookup: "
              f"{info or 'no answer from crt.sh right now (the hunt still works; dates will be blank)'}")
        sys.exit(0 if ok else 1)
    hunt(cfg, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
