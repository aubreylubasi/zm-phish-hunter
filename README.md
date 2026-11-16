# 🇿🇲 ZM Phish Hunter

Finds new websites that imitate Zambian banks, mobile money services and public bodies,
often before the scam link starts spreading.

## Why I built it
Fake "Airtel Money", "MTN MoMo", "Zanaco" and "ZRA" links reach people by SMS and WhatsApp every
day. Global tools are not tuned for Zambian brands, and by the time a link is reported, people have
already lost money. I wanted an early warning that watches for the fake site being **set up**.

## How it works
1. Every HTTPS website needs a certificate, and every certificate is written to public
   **Certificate Transparency logs** within minutes. The bot searches those logs through
   [crt.sh](https://crt.sh) for new names containing a Zambian brand.
2. It throws away the real sites (`official_domains` in `config.toml`).
3. It scores what is left out of 100:

| Sign | Points |
|---|---|
| Uses a protected brand name on a site the brand doesn't own | 50 |
| Misspelt name or digits for letters (`zanac0`, `zannaco`) | +20 |
| Lure words (`login`, `verify`, `bonus`, `reversal`…) | +15 |
| Cheap ending (`.top`, `.xyz`, `.shop`…) | +10 |
| Free hosting (`web.app`, `pages.dev`…) | +10 |
| Long name with several hyphens | +10 |
| Look-alike special characters | +10 |
| Not a `.zm` address when the real one is | +5 |

4. **70 or more is "high"** (sent to Telegram if you set that up). **50 or more is "medium"**
   (report only). Findings are saved in [`findings/latest.md`](findings/latest.md).

Names used in many countries (MTN, Airtel, Absa, FNB, Stanbic) only count when the domain also
points at Zambia (`zambia`, `zm`, `lusaka`, `kwacha`, or a `.zm` ending).

## It is passive
The bot only reads public logs and does one DNS lookup to see if a name is online. It never
visits, scans or attacks any website. Domains in the report are written like `example[.]com` so
nobody clicks one by accident.

**A finding is a lead, not proof.** Check it before telling anyone a site is a scam. Some results
will be genuine third parties; add those to `ignore_domains` in `config.toml`.

## Run it on your computer
```bash
pip install -r requirements.txt
python tests/test_hunter.py                       # offline tests, should end "All good."
python hunter.py --score zanaco-login.top mtn.zm  # score any name by hand
python hunter.py --check                          # test the certificate searches
python hunter.py --dry-run                        # a real search that saves nothing
```
Needs Python 3.11 or newer.

## Run it free on GitHub
1. Put these files in a **public** repository.
2. Open **Actions**, enable workflows, then **ZM Phish Hunter → Run workflow → check**.
3. Run it again with **hunt**. After that it runs by itself every 3 hours and saves the report.

**Telegram alerts (optional):** create a bot with @BotFather, then add two repository secrets under
**Settings → Secrets and variables → Actions**: `TG_BOT_TOKEN` and `TG_CHAT_ID`.

## Add a brand
Copy a `[[brands]]` block in `config.toml` and fill in the label, the spellings to look for, the
real websites and what to search for. **Check `official_domains` carefully**: a wrong entry means
the real site gets reported.

## Known limits
- crt.sh is a free service and is sometimes slow or down. A failed search is retried next run.
- It only sees sites that get their own certificate. A fake page hidden in a folder of a hacked
  site, or on a shared wildcard certificate, will not appear.
- It judges the **name** only. It does not look at the page, so it cannot yet say "this page copies
  Zanaco's login screen". Screenshots and page comparison are the next step.
- Short names (`zra`, `boz`, `mtn`) must appear as a whole word, so some tricky spellings are missed.

## What to do with a finding
Report it to the brand's fraud team and to ZICTA, and to the registrar or host shown by a WHOIS
lookup. Do not enter any details on the site.
