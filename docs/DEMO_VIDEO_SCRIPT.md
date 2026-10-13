# ThreatDesk: Demo Video Script (about 5 minutes)

The order follows the judging rubric, so every scored point is visibly on screen:
Brand Profile (15) → Social Media Monitoring (30) → App Store Monitoring (30) → Look-alike bonus → UX (15),
with the whole video counting toward Presentation (10).

---

## 0. Prepare before you press record (about 20 minutes)

The seeded demo data (`scripts.seed_demo`, brand **Acme Bank**) mostly contains *website* findings. Social and app
monitoring are 60% of the score, so you also need a brand with **real** social and app-store results:

1. **Log in** to https://threatdesk-ten.vercel.app with the demo account in a clean browser window (no extensions,
   zoom 100–110%, window about 1440×900).
2. **Create a live brand** whose impersonators really exist on Google Play and Bluesky, for example:
   * Name: `PhonePe` · Keywords: `phonepe`, `phone pe`
   * Website: `phonepe.com` · Official app: Google Play `com.phonepe.app` · Publisher: `PhonePe`
   * Official social: `https://www.youtube.com/@PhonePe`, `https://www.instagram.com/phonepe`
   * Upload the logo (Brand settings → Logo).
3. Press **Scan now** on that brand and **let it finish before recording**. You will show a scan starting on camera,
   but the results need to be ready.
4. Open the findings and pick, in advance:
   * one **suspicious app** (different developer, similar title/icon),
   * one **social profile** finding (look-alike handle or scam bio),
   * one finding that shows a source as **not possible / not configured** (for the UX section).
5. Keep these ready to paste into Investigate (in a notepad, not on screen):
   * an **official** link: `https://www.instagram.com/acmebank` (on the Acme Bank brand, proves "never flagged")
   * a **look-alike handle**, for example `https://www.instagram.com/acmebank.support` or `https://t.me/acmebnak`
6. Close other tabs and silence notifications. Use OBS or the Windows Game Bar (Win+Alt+R) at 1080p, with a mic.

> If a live source is blocked during recording, keep going. Showing **"not possible: reason"** is exactly the
> "graceful handling of unavailable sources" the judges score under UX.

---

## 1. Intro: start recording here (0:00–0:25)
**Screen:** the ThreatDesk welcome / sign-in page.

**Say:** "Hi, we're team WILD CARD. This is ThreatDesk, a Digital Risk Protection platform for social and app
monitoring. Brands get impersonated by fake profiles, scam support accounts and copycat apps. ThreatDesk lets a
company register what is genuinely theirs and then finds and explains everything that pretends to be them."

**Do:** sign in. You land on the **Dashboard**.

## 2. Dashboard overview (0:25–0:45)
**Show:** the High / Medium / Low risk tiles, *Prioritized Findings*, and *Recent Activity & Audit Trail*.

**Say:** "The dashboard shows open risk by severity, the findings that need attention first, and an audit trail of
every analyst action."

## 3. Brand Profile, 15 points (0:45–1:40)
**Do:** sidebar → **Assets & Brands** → open **PhonePe** (or Acme Bank).

1. **Overview tab:** point to the **setup checklist** and the **Official assets** cards.
   "Setup is guided: add your website, social accounts, apps and logo, then run a scan."
2. **Social accounts tab:** show the official handles, then expand **How to verify**.
   "Assets are *verified*, not just typed in: a DNS TXT record, a meta tag, a code in the bio, or assetlinks.json for
   apps. A bio that just links to our site is not proof, because impostors do that too."
3. **Mobile apps tab:** show the official app and its verified status.
4. **Brand settings:** briefly show the keywords, **official publishers**, **logo**, and **look-alike sensitivity**.
   "Every scan reads this profile. Official assets and the allow list are excluded from detection."
5. **Allow list tab:** "Partners or resellers we trust go here and are never flagged."

## 4. Live scan and unavailable sources (1:40–2:05)
**Do:** on the brand page press **Scan now**. Show the **Latest scan** progress and expand **Source details**.

**Say:** "Monitoring runs on a schedule, and we can also scan on demand. Each source (Google Play, App Store,
Bluesky, YouTube, Telegram, web search) reports whether it *ran*, was *not possible* with the reason, or is *not
configured* because a key is missing. Nothing is ever silently marked safe."

(You don't need to wait. Move on to the results from your earlier scan.)

## 5. Social Media Monitoring, 30 points (2:05–3:00)
**Do:** **Findings** → filter by the brand → open your chosen **social profile** finding.

Walk down the report:
1. **What did we find?** The impersonating account and its verdict.
2. **How serious is it?** Score and severity.
3. **Evidence:** read out the signals, e.g. *"Handle is a look-alike of the official @phonepe"*, *"Bio asks users to DM
   for KYC / customer support"*, *"Bio links to a non-official site"*, *"New account, small audience, no verified
   badge"*.

**Say:** "Every flag is explained in plain language, so an analyst can trust it and act on it."

**Then prove official accounts are not flagged:** **Investigate** → paste `https://www.instagram.com/acmebank` →
**Investigate**. The result is **Official/whitelisted asset, score 0**.
"Our own official account scores zero, because official assets are matched before any detection rule runs."

## 6. App Store Monitoring, 30 points (3:00–3:50)
**Do:** open your chosen **suspicious app** finding.

Point at each signal:
* **Similar app name** to the official app
* **Icon vs. official logo** similarity (perceptual hash)
* **Different developer:** "the publisher is not on our official publisher list"
* **Description resembling** the real app, plus package id and permissions

**Say:** "On Google Play the developer *account* must match one of our official apps before a publisher counts as
official, so a fake can't just copy our company name."

**Then** open the **official app** (or Investigate its Play URL) to show it is **not flagged**.

## 7. Look-alike name detection, bonus (3:50–4:15)
**Do:** **Investigate** → paste a look-alike, e.g. `https://t.me/acmebnak` or `https://www.instagram.com/acmebank.support`.

**Say:** "Our look-alike engine catches character swaps like *acmebnak*, added words like *acmebank-support*,
spacing and hyphen changes like *acme-bank*, and homoglyphs like *acmeb4nk*, with guards so normal names that just
contain a common word aren't over-flagged."

Expand **7. Technical Details** to show the matched rule (e.g. *Adjacent letter swap*).

## 8. Respond: triage, takedown, campaigns (4:15–4:45)
**Do:** on a finding, go to **Case actions** → **Move to → Confirmed** (add a reason) → **Assign** → **Add comment**.
Click **Takedown packet**: show the pre-filled request, **Send to → Report form**, and **Download as text**.
Briefly open **Cases** (campaigns): "Fakes sharing the same phone number, UPI ID, developer or IP are grouped into
one campaign."
Mention **Alerts**: "Medium and High findings also go to email or Slack/Discord webhooks."

## 9. Close (4:45–5:00)
**Screen:** back to the Dashboard (or the architecture diagram, `docs/architecture/threatdesk-architecture.html`).

**Say:** "ThreatDesk: define what's yours, find what pretends to be you, explain every detection, never flag your
own assets, and act on it. Thank you."

**Stop recording.**

---

## Upload and submit
* Trim the start and end, then export MP4 at 1080p.
* Upload to YouTube (**Unlisted**) or Google Drive (**Anyone with the link can view**). Open the link in a private
  window to confirm it plays without signing in.
* Paste it into **Demo video URL** on the submission form, then click **Finalize submission**.

## Tips
* Rehearse once with a timer. Aim for 4–6 minutes.
* Zoom the browser (Ctrl +) when reading evidence text so it's legible in the video.
* Talk about **what the judge scores**: "official accounts are not flagged", "different publisher", "explained
  evidence", "graceful when a source is unavailable".
* If something fails live, say what the screen shows and move on. Honest status messages are a feature.
