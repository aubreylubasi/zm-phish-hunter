# 🇿🇲 ZM Phish Hunter

Finds new websites that imitate Zambian banks, mobile money services and public bodies,
often before the scam link starts spreading.

## Why I built it
Fake "Airtel Money", "MTN MoMo", "Zanaco" and "ZRA" links reach people by SMS and WhatsApp every
day. Global tools are not tuned for Zambian brands, and by the time a link is reported, people have
already lost money. I wanted an early warning that watches for the fake site being **set up**.

## How it works
1. For every brand in `config.toml`, the bot builds the names a scammer would likely register:
   misspellings (`zannaco`, `zanac0`), added lure words (`zanaco-login`, `secure-zesco`) and cheap
   endings (`.top`, `.xyz`, `.shop`). That is about 25,000 names.
2. It asks DNS which of those names exist, and skips the real sites (`official_domains`).
   For new ones it looks up the first certificate in the public **Certificate Transparency logs**
   (through [crt.sh](https://crt.sh)) to see when the site was set up.
3. It scores what is left out of 100:

| Sign | Points |
|---|---|
| Uses a protected brand name on a site the brand doesn't own | 50 |
| One letter off or digits for letters (`zanac0`, `zannaco`) | +10, or +20 with a lure word |
| Lure words (`login`, `verify`, `bonus`, `reversal`…) | +15 |
| Cheap ending (`.top`, `.xyz`, `.shop`…) | +10 |
| Free hosting (`web.app`, `pages.dev`…) | +10 |
| Long name with several hyphens | +10 |
| Look-alike special characters | +10 |
| Not a `.zm` address when the real one is | +5 |
| First certificate in the last 30 days | +10 |

4. **70 or more is "high"** (sent to Telegram if you set that up). **50 or more is "medium"**
   (report only). Findings are saved in [`findings/latest.md`](findings/latest.md).

Names used in many countries (MTN, Airtel, Absa, FNB, Stanbic) only count when the domain also
points at Zambia (`zambia`, `zm`, `lusaka`, `kwacha`, or a `.zm` ending).

## It is passive
The bot only does DNS lookups and reads public certificate logs. It never
visits, scans or attacks any website. Domains in the report are written like `example[.]com` so
nobody clicks one by accident.

**A finding is a lead, not proof.** Check it before telling anyone a site is a scam. Some results
will be genuine third parties; add those to `ignore_domains` in `config.toml`.

## Run it on your computer
```bash
pip install -r requirements.txt
python tests/test_hunter.py                       # offline tests, should end "All good."
python hunter.py --score zanaco-login.top mtn.zm  # score any name by hand
python hunter.py --candidates zanaco              # the names it would try for a brand
python hunter.py --check                          # test DNS and the certificate lookup
python hunter.py --dry-run                        # a real run that saves nothing
```
Needs Python 3.11 or newer.

## Run it free on GitHub
1. Put these files in a **public** repository.
2. Open **Actions**, enable workflows, then **ZM Phish Hunter → Run workflow → check**.
3. Run it again with **hunt**. After that it runs by itself every 6 hours and saves the report.

**Telegram alerts (optional):** create a bot with @BotFather, then add two repository secrets under
**Settings → Secrets and variables → Actions**: `TG_BOT_TOKEN` and `TG_CHAT_ID`.

## Add a brand
Copy a `[[brands]]` block in `config.toml` and fill in the label, the spellings to look for (main one first)
and the real websites. **Check `official_domains` carefully**: a wrong entry means
the real site gets reported.

## Known limits
- **It only finds names it thought to try.** A fake site with an unusual name is missed. (Searching
  the certificate logs for any name *containing* a brand would catch more, but crt.sh's "contains"
  search turned out to cover only a small part of its data: it returned 2 certificates for
  "zanaco" where an exact lookup of the real site returned 474.)
- A name that is registered but has no website address in DNS yet is not seen until it has one.
- It judges the **name** only. It does not look at the page, so it cannot yet say "this page copies
  Zanaco's login screen". Screenshots and page comparison are the next step.
- The first run lists everything that already exists, including old and harmless sites. After that
  only new names are reported.
- crt.sh is a free service and is sometimes slow or down; then the certificate date is left blank.

## What to do with a finding
Report it to the brand's fraud team and to ZICTA, and to the registrar or host shown by a WHOIS
lookup. Do not enter any details on the site.
