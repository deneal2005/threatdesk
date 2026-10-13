# ThreatDesk: Platform Guide

**Live app:** https://threatdesk-ten.vercel.app · **Challenge:** HacXLerate 2026, Challenge 3: Digital Risk Protection
(Social & App Monitoring)

## What ThreatDesk is

ThreatDesk is a Digital Risk Protection platform. An organization first tells it what is **genuinely theirs**: the
brand name, logo, official websites, official social-media accounts, official Android/iOS apps and the app publishers
they trust. ThreatDesk then looks across social networks and app stores for anything that **pretends to be** that
brand. This includes impersonating profiles, fake company pages, scam support accounts and copycat apps. Each match
becomes an explained, evidence-backed finding that an analyst can triage, confirm and send for takedown.

```
Brand profile → Discover → Investigate with evidence → Score & classify → Triage → Takedown → Keep monitoring
```

Three principles run through the whole product:

1. **Official assets are never flagged.** Verified official accounts, apps, sites and allow-listed items are matched
   first. They get score 0 and the verdict *Official/whitelisted asset* before any detection rule runs.
2. **Every verdict is explained.** Each finding lists the exact signals behind it in plain language, for example
   *"Adjacent letter swap: 'amcebank' vs 'acmebank'"* or *"Developer is not on your official publisher list"*.
3. **ThreatDesk is honest about what it could not check.** It never labels anything "safe". Each source reports *ran*,
   *not possible* (with the reason) or *not configured* (API key missing). Nothing is invented when a source is
   down.

## How detection works (in short)

| Area | What it checks |
|---|---|
| **Social media** (Bluesky, YouTube, Telegram; Instagram/Facebook/X via web search when keys are set) | Handle and display-name look-alikes, logo similarity, bio links to non-official sites, scam wording in bios ("DM for KYC", "customer care helpline"), account age, audience size, verified badge |
| **App stores** (Google Play, Apple App Store) | Title look-alikes, icon compared to the official logo (perceptual hash), developer/publisher not on the official list, package/bundle id, description resembling the real app, permissions, developer website |
| **Look-alike names** (bonus) | Character swaps (`amcebank`), added words (`acmebank-support`), spacing/hyphen changes (`acme bank`, `acme-bank`), homoglyphs/leet (`acmeb4nk`), insertions and deletions. Guards stop ordinary names that merely contain a common word from being over-flagged |
| **Scoring** | About 60 explainable rules add points by category. An identity gate caps accounts and apps that only look similar but have no supporting evidence, so a name match alone never produces a High finding |

---

## Screen-by-screen: what every button does

### Welcome / Sign in (`/login`)
| Control | What it does |
|---|---|
| **Email address / Password → Sign in** | Logs you into your organization's workspace |
| **Create a new organization** | Opens sign-up to create a new organization and its first admin account |

### Sign up (`/signup`)
| Control | What it does |
|---|---|
| **Organisation / Work email / Password → Create** | Creates an isolated organization (tenant). Its data is never visible to other organizations |
| **Log in** | Back to sign in |

### Sidebar (on every page)
| Item | Goes to |
|---|---|
| **ThreatDesk** logo | Dashboard |
| **Dashboard** | Overall risk overview |
| **Findings** (badge = new findings) | Triage queue of everything detected |
| **Investigate** | Check a single suspicious link or profile on demand |
| **Discovery Auto** | Findings that came from automated scans only |
| **Assets & Brands** | The brands you protect and their official assets |
| **Cases** | Campaigns: groups of findings run by the same actor |
| **Reports** | Brand summaries, CSV export, customer reports |
| **Actions** | Findings waiting on a takedown request |
| **Team** | Teammates (Settings → Team) |
| **Alerts** (badge = unread) | Notification inbox |
| **Settings** | Organization settings, API keys, alert channels |
| **Log out** | Ends the session |

**Top bar:** **Search findings** (⌘K / Ctrl+K) searches the findings queue. The **bell** opens the alert menu
(**Mark all as read**, a tick to mark one alert read, **View all alerts**, **Email & webhook alerts**). **Investigate**
is a shortcut, and the **avatar** opens Settings.

### Dashboard (`/`)
| Control | What it does |
|---|---|
| **Scan all N brands** | Queues a discovery scan for every brand right now, without waiting for the schedule |
| **All brands** | Brand list |
| **Review urgent threats →** | Findings filtered to High severity |
| **Open triage queue →** | Findings not looked at yet (*New*) |
| **Manage brand assets →** | Brand list |
| **View all findings →** | Every finding, any status |
| **Detection & Defense Lifecycle** (expand) | One-screen explanation of how ThreatDesk works |
| **High / Medium / Low Risk** tiles | Open findings at that severity |
| **See all open findings** | Open findings queue |
| **Prioritized Findings → Review →** | Opens that finding's case page |
| **Recent Activity & Audit Trail** links | Opens the case each event belongs to |
| **Add brand** (first run) | Starts brand setup |

### Assets & Brands (`/brands`)
| Control | What it does |
|---|---|
| **Add a brand** | Opens the brand profile form |
| Brand name / **Open overview** | Brand page |
| **Findings** | Findings for that brand only |
| **Brand settings** | Edit the brand profile |
| **Delete brand…** | Confirmation page (you must type the brand name). Download the summary and CSV first |

### Add a brand / Brand settings (`/brands/new`, `/brands/{id}/edit`)
This is the **Brand Profile**, the source of truth every scan reads.

| Field | Purpose |
|---|---|
| **Name** | The brand name people know |
| **Keywords** | Extra terms and product names to search for and to match look-alikes against |
| **Websites** | Official domains (excluded from detection, used to verify other assets) |
| **Social profiles** | Official accounts (excluded from detection) |
| **Apps** | Official Play/App Store listings (excluded from detection) |
| **Publishers** | Official app developer names. Apps from anyone else using the brand are suspicious |
| **Logo** | Used for icon/avatar similarity matching |
| **Look-alike sensitivity** | Stricter or looser name matching (fewer misses vs fewer false alarms) |
| **Scan interval (hours)** | How often the scheduler re-scans this brand (default 24) |
| **Save** | Saves. Findings that the new profile now covers as official are closed automatically |
| **Delete brand…** | Permanent delete, with confirmation |

### Brand page (`/brands/{id}`)
Header: **Findings** (this brand's findings), **Summary** (printable brand report), **Brand settings**, and the
**Scan now / Stop scan** button.

**Tabs:** **Overview · Websites · Social accounts · Mobile apps · Allow list**

**Overview tab**
| Control | What it does |
|---|---|
| **Set up checklist** (add/verify website, add social accounts, add apps, upload logo, run first scan) | Each step has a button that does it. **Not applicable** skips a step that does not apply, and **Undo** brings it back |
| **Official assets** cards | Jump to the Websites / Social / Apps tabs with counts of verified items |
| **Latest scan** panel | Live progress per source (Play, App Store, Bluesky, YouTube, …). **Source details** shows exactly which sources ran, were not possible or not configured. **Review findings →** opens what this scan found, and **Try again** reruns a failed scan |
| **Customer report link → Open the form** | Public link you can give customers to report scams using your name |
| **Add a logo / Change settings** | Brand settings |

**Websites / Social accounts / Mobile apps tabs**
| Control | What it does |
|---|---|
| **+ Add website / social account / app** | Registers an official asset |
| **Check** / **Check again** | Re-verifies that the brand really controls this asset |
| **Check all unverified** | Verifies up to 50 pending assets in one go |
| **How to verify** (expand) | Exact proof accepted: a DNS TXT record or `<meta name="threatdesk-verification">` on the site, a code in the account bio, a link from your verified website, or `assetlinks.json` / `apple-app-site-association` for apps. A bio or store listing that only links to your site is **not** proof, because impostors do that too |
| **Make primary** | Marks the main website/account shown in the header |
| **Edit** | Change the asset |
| **Remove… → Yes, remove / Keep it** | Deletes the asset (with confirmation) |
| **Search / Platform filter / page numbers** | Find an asset in long lists |

**Allow list tab**
| Control | What it does |
|---|---|
| **Add to the allow list** (type + value) | Things that are legitimate but not owned, such as partners and resellers. Never flagged |
| **Remove** | Takes the item off the allow list |

### Investigate (`/investigate`)
| Control | What it does |
|---|---|
| **Suspicious link → Investigate** | Paste any profile, app listing or website URL. ThreatDesk runs every relevant check and produces a report in seconds (live progress shown) |
| **Your recent investigations** → link | Reopens a past report |
| **Delete** | Removes that investigation from the list |

**The investigation report** reads top to bottom as seven plain-language questions:
1. What did we find? · 2. How serious is it? · 3. Why should I care? · 4. What evidence supports this? ·
5. What should I do next? · 6. How confident is the finding? · 7. **Technical Details & Raw Signals** (expand: rule
IDs, points, **Raw JSON**). **Save as finding** puts the result into the triage queue.

### Findings: Triage Queue (`/findings`)
| Control | What it does |
|---|---|
| **Open / New / All** tabs | Unresolved findings / not yet looked at / everything |
| **Search** | Search by name, handle, domain or app |
| **Filter Options** | Brand, severity (High/Medium/Low), status, classification, source (any automated scan, or a specific one), sort (highest score, newest, oldest). **Clear filters** resets |
| **Export CSV** | Downloads the current findings as a spreadsheet |
| Row checkbox + **Mark false positive** | Bulk-closes the selected findings with a reason. Tick **Add to brand allowlist** so future scans ignore them |
| Finding name | Opens the case page |
| **Run First Brand Discovery Scan** (empty state) | Starts the first scan |

### Finding / Case page (`/findings/{id}`)
| Control | What it does |
|---|---|
| **← Findings** | Back to the queue |
| **Case actions ↓** | Jumps to the action panel |
| Report sections 1–7 | Same plain-language explanation as Investigate, with evidence captures and redirect chain |
| **Profile details** (expand) | Add what you can see on a profile that could not be fetched automatically (display name, join date, bio, followers). This is marked as user-supplied and unverified |
| **Move to …** | Change status: *New → Investigating → Confirmed → Takedown requested → Taken down*, or *False positive* / *Monitoring*. Only valid moves are offered, and each one is logged |
| **Assignee** | Assign the case to a teammate |
| **Takedown packet** | Opens the ready-to-send takedown request |
| **Comment → Add comment** | Adds a note to the case history (audit trail) |
| **Customer reports** | Customer submissions linked to this finding |

### Takedown packet (`/findings/{id}/takedown`)
| Control | What it does |
|---|---|
| **Download as text** | The complete request (who is impersonated, why, evidence, redirect chain) as a text file |
| **Send to → Report form** | Opens the right platform's, registrar's or host's abuse/impersonation form |
| **Log a request you sent** (recipient + note) | Records in the case history who the request went to and when. Use **Move to → Takedown requested** on the case to change its status |

### Cases: Campaigns (`/campaigns`)
| Control | What it does |
|---|---|
| **Rebuild campaigns** | Re-groups findings that share infrastructure or identifiers (same phone, UPI id, email, developer, handle, IP, ASN or domain; shared CDN/cloud addresses are skipped), so you can see one actor behind many fakes |
| Finding links | Open each member case |

### Reports (`/reports`)
| Control | What it does |
|---|---|
| **Export all findings** | CSV of every finding |
| Brand name / **CSV** | Printable brand summary / that brand's CSV |
| **Customer reports → Case NNNN** | Opens the case created from a customer report |

### Alerts (`/notifications`)
| Control | What it does |
|---|---|
| Alert text | Opens the related finding or scan |
| **Mark read / Mark all as read** | Clears unread alerts |

### Settings (`/settings`)
| Control | What it does |
|---|---|
| **Team → Add a teammate** (email + temporary password) | Gives a colleague access to this organization. **Remove** revokes it |
| **API keys → Create API key / Revoke** | Keys for the REST API (`/api/v1`) used for integrations and automation |
| **Alerts → Change alert channels** | Email recipients and up to 5 webhook URLs (Slack, Discord, Teams…) for new Medium/High findings (every new finding also appears in the in-app Alerts inbox). **Send test alert** checks the setup |
| **Connected Services & Adapters** | Shows which data sources are configured and which need an API key |

### Public customer report form (`/report/{token}`)
This page needs no login. A customer pastes the suspicious link or message and submits. A receipt confirms it, and
the report lands in **Reports → Customer reports** and on the matching finding.

---

## Graceful handling of unavailable sources

* Each scan shows per-source status: **ran**, **not possible** (e.g. the store blocked the request, with the reason)
  or **not configured** (API key missing). A missing source never makes a result look safe.
* The lowest verdicts are **No strong signals** and **Insufficient data**, never "safe".
* Failed scans offer **Try again**. A running scan can be stopped with **Stop scan**.
* Monitoring is scheduled (every brand re-scanned on its interval), not real-time.

## Where to read more
* [ARCHITECTURE.md](../ARCHITECTURE.md): diagram, data sources, detection logic, storage, official-asset exclusion
* [architecture/threatdesk-architecture.html](architecture/threatdesk-architecture.html): interactive architecture diagram (download and open in a browser)
* [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md): 3-minute demo script
* [REQUIREMENTS_TRACEABILITY.md](REQUIREMENTS_TRACEABILITY.md): each challenge requirement mapped to code and tests
