"""Offline tests: no internet needed.    python tests/test_hunter.py"""
import json
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
    "zanaco-login.top": "high", "zanac0.com": "high", "zannaco-online.com": "high",
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

# Full run from a saved crt.sh-style file, in a temporary folder.
now = datetime.now(timezone.utc)
rows = [
    {"common_name": "zanaco-login.top", "name_value": "zanaco-login.top\nwww.zanaco-login.top",
     "entry_timestamp": (now - timedelta(hours=5)).isoformat(), "issuer_name": "C=US, O=Let's Encrypt, CN=R11"},
    {"common_name": "*.zanaco.co.zm", "name_value": "*.zanaco.co.zm\nzanaco.co.zm",
     "entry_timestamp": (now - timedelta(hours=2)).isoformat(), "issuer_name": "C=US, O=DigiCert Inc"},
    {"common_name": "old-zesco-bonus.xyz", "name_value": "old-zesco-bonus.xyz",
     "entry_timestamp": (now - timedelta(days=200)).isoformat(), "issuer_name": ""},
]
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    hunter.STATE_FILE, hunter.REPORT_FILE, hunter.HISTORY_FILE = tmp / "seen.json", tmp / "latest.md", tmp / "all.json"
    (tmp / "rows.json").write_text(json.dumps(rows))
    hunter.resolves = lambda d: False
    first = hunter.hunt(cfg, rows_file=tmp / "rows.json")
    second = hunter.hunt(cfg, rows_file=tmp / "rows.json")
    report = hunter.REPORT_FILE.read_text()
    checks = {
        "one finding (www and bare name merged, official and old skipped)": [f["domain"] for f in first] in (["zanaco-login.top"], ["www.zanaco-login.top"]),
        "second run reports nothing new": second == [],
        "report hides clickable links": "zanaco-login[.]top" in report and "zanaco-login.top" not in report,
    }
    for name, good in checks.items():
        ok &= good
        print(f"{'ok  ' if good else 'FAIL'} {name}")
print("\nAll good." if ok else "\nSomething failed - see FAIL above.")
sys.exit(0 if ok else 1)
