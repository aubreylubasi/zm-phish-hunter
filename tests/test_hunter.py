"""Offline tests: no internet needed.    python tests/test_hunter.py"""
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import hunter  # noqa: E402

cfg = hunter.load_config()
level = lambda d: (hunter.score_domain(d, cfg) or {}).get("level")  # noqa: E731

SHOULD_FLAG = {  # domain -> lowest level expected
    "zanaco-login.top": "high", "zanac0.com": "medium", "zannaco-online.com": "high",
    "secure-zanaco.co.zm.verify-account.xyz": "high", "zesco-prepaid-bonus.shop": "high",
    "mtn-zm-momo-reward.online": "high", "airtelmoney-zambia.claim-bonus.live": "high",
    "zra-refund.info": "high", "zanaco.web.app": "medium", "zamtelkwacha.com": "medium",
    "napsa-portal.com": "medium", "absa-zambia.com": "medium", "zana-co.net": "medium",
}
SHOULD_IGNORE = [
    "zanaco.co.zm", "www.zanaco.co.zm", "online.zanaco.co.zm", "mtn.zm", "airtel.co.zm", "zra.org.zm",
    "mtn.ng", "mtn-login.com", "absa.co.za", "airtel.in", "fnb-online.com",          # other countries
    "google.com", "pizza-nacos.com", "extra.co.zm", "zambia-tourism.com", "ezra.com", "mtnview.com",
]
ORDER = {None: 0, "low": 1, "medium": 2, "high": 3}
ok = True
for d, want in SHOULD_FLAG.items():
    got = level(d)
    good = ORDER[got] >= ORDER[want]
    ok &= good
    print(f"{'ok  ' if good else 'FAIL'} flag   {d}: {got} (wanted at least {want})")
for d in SHOULD_IGNORE:
    got = level(d)
    good = got in (None, "low")
    ok &= good
    print(f"{'ok  ' if good else 'FAIL'} ignore {d}: {got}")

# Candidate names: the fakes we expect to try are generated, the real site is not.
names = set().union(*(hunter.candidates_for(b, cfg) for b in cfg["brands"]))
for d in ["zanaco-login.top", "zanac0.com", "zannaco.com", "zesco-bonus.shop", "mtnzambia.com", "airtel-zambia-promo.online"]:
    good = d in names
    ok &= good
    print(f"{'ok  ' if good else 'FAIL'} would try {d}")
for d in ["zanaco.co.zm", "mtn.zm", "mtn-login.com", "zanco.com", "amtel.shop"]:
    good = d not in names
    ok &= good
    print(f"{'ok  ' if good else 'FAIL'} would not try {d}")

# Full run with pretend DNS and certificate answers, in a temporary folder.
now = datetime.now(timezone.utc)
PRETEND_EXISTS = {"zanaco-login.top", "zannaco.com", "zesco.com"}
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    hunter.STATE_FILE, hunter.REPORT_FILE, hunter.HISTORY_FILE = tmp / "seen.json", tmp / "latest.md", tmp / "all.json"
    hunter.lookup = lambda d: d in PRETEND_EXISTS
    hunter.certificate_info = lambda d, c: ({"logged": (now - timedelta(days=2)).isoformat(), "issuer": "Let's Encrypt",
                                             "certificates": 1} if d == "zanaco-login.top" else {})
    cfg["seconds_between_searches"] = 0
    first = hunter.hunt(cfg)
    second = hunter.hunt(cfg)
    report = hunter.REPORT_FILE.read_text()
    top = first[0] if first else {}
    checks = {
        "finds the three pretend sites": {f["domain"] for f in first} == PRETEND_EXISTS,
        "the newly set up site scores highest": top.get("domain") == "zanaco-login.top" and "set up in the last" in " ".join(top.get("reasons", [])),
        "second run reports nothing new": second == [],
        "report hides clickable links": "zanaco-login[.]top" in report and "zanaco-login.top" not in report,
    }
    for name, good in checks.items():
        ok &= good
        print(f"{'ok  ' if good else 'FAIL'} {name}")
print("\nAll good." if ok else "\nSomething failed - see FAIL above.")
sys.exit(0 if ok else 1)
