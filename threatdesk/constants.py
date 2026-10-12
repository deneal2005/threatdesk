"""Editable phrase lists and constants used by content, app and social checks.

All matching is case-insensitive substring/regex matching on visible text. Add phrases here, not in code.
Hindi entries are common transliterations seen in Indian scam messages.
"""

SCAM_PHRASES = [
    # account / KYC
    "kyc update", "update your kyc", "kyc pending", "kyc expired", "complete your kyc", "account blocked",
    "account suspended", "account will be blocked", "pan card update", "aadhaar update", "verify your account",
    "verify now", "re-activate your account", "reactivate your account",
    # refunds / rewards / lottery
    "upi refund", "refund processing", "claim refund", "claim reward", "claim your reward", "reward points expire",
    "free gift", "lottery", "lucky draw", "you have won", "kbc lottery", "prize money", "cashback offer",
    # fees
    "registration fee", "processing fee", "activation fee", "delivery charge", "clearance fee", "advance fee",
    # loans / jobs / investment
    "instant loan", "loan instant approval", "no cibil", "without documents", "pre-approved loan",
    "task job", "part time job", "work from home", "earn daily", "earn per day", "like and earn",
    "guaranteed returns", "investment guaranteed", "double your money", "100% profit", "daily profit",
    "trading tips", "vip signals", "crypto investment",
    # action bait
    "click link", "click the link", "click here to verify", "send otp", "share otp", "tell otp",
    # transliterated Hindi
    "aapka account band", "account band ho jayega", "kyc update karein", "kyc karwaye", "turant", "jaldi karein",
    "inaam", "lottery jeeti", "paise double", "ghar baithe kamaye", "ghar baithe paise", "loan turant",
    "otp batayein", "otp bhejein", "refund milega", "naukri", "registration shulk",
]

URGENCY_WORDS = [
    "urgent", "urgently", "immediately", "act now", "hurry", "last chance", "today only", "expires today",
    "within 24 hours", "within 2 hours", "limited time", "final notice", "asap", "right now", "abhi", "turant",
]

OFFICIAL_CLAIMS = ["official", "customer care", "customer support", "support team", "helpline", "help desk",
                   "verified account", "authorised", "authorized", "toll free", "grievance"]

EARN_LOAN_CLAIMS = ["guaranteed returns", "guaranteed profit", "earn from home", "work from home", "earn daily",
                    "instant loan", "loan approval", "loan in 5 minutes", "no cibil", "task job", "part time job",
                    "investment plan", "double your money", "daily income", "high returns", "fixed returns"]

# Crypto terms need payment context: a bare "bitcoin" mention is not a payment demand.
PAYMENT_ONLY = ["upi only", "pay via upi", "only upi", "scan qr to pay", "pay using qr", "crypto only",
                "pay in bitcoin", "pay with bitcoin", "pay via bitcoin", "send bitcoin", "bitcoin only", "btc only",
                "pay in usdt", "pay with usdt", "pay via usdt", "send usdt", "deposit usdt", "usdt only", "trc20 address",
                "gift card", "google play gift card", "amazon gift card", "itunes card", "steam card",
                "cash on delivery not available", "no cod"]

CREDENTIAL_WORDS = ["password", "passcode", "otp", "one time password", "mpin", "upi pin", "atm pin", "cvv", "cvc",
                    "card number", "expiry date", "net banking", "netbanking", "login id", "user id", "aadhaar number"]

POLICY_PAGE_HINTS = {
    "contact": ["contact", "contact-us", "contact us", "support", "help"],
    "privacy": ["privacy"],
    "refund": ["refund", "return", "cancellation", "shipping"],
}

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "ow.ly", "tiny.cc",
              "rebrand.ly", "s.id", "shorte.st", "bitly.com", "v.gd", "t.ly"]

FREE_EMAIL_PROVIDERS = ["gmail.com", "googlemail.com", "yahoo.com", "yahoo.in", "yahoo.co.in", "outlook.com",
                        "hotmail.com", "live.com", "rediffmail.com", "protonmail.com", "proton.me", "aol.com",
                        "icloud.com", "mail.com", "yandex.com", "gmx.com", "zoho.com", "tutanota.com"]

DANGEROUS_PERMISSIONS = {
    "READ_SMS": "read your text messages", "RECEIVE_SMS": "receive text messages",
    "READ_CALL_LOG": "read call log", "READ_CONTACTS": "read your contacts",
    "SYSTEM_ALERT_WINDOW": "draw over other apps", "BIND_ACCESSIBILITY_SERVICE": "accessibility service",
    "REQUEST_INSTALL_PACKAGES": "request install packages", "BIND_DEVICE_ADMIN": "device admin",
}
# Play shows human-readable permission text; map those phrases to the Android constants above.
PERMISSION_TEXT_HINTS = {
    "read your text messages": "READ_SMS", "read sms": "READ_SMS", "receive text messages": "RECEIVE_SMS",
    "receive sms": "RECEIVE_SMS", "read call log": "READ_CALL_LOG", "read your contacts": "READ_CONTACTS",
    "draw over other apps": "SYSTEM_ALERT_WINDOW", "display over other apps": "SYSTEM_ALERT_WINDOW",
    "accessibility": "BIND_ACCESSIBILITY_SERVICE", "request install packages": "REQUEST_INSTALL_PACKAGES",
    "install unknown apps": "REQUEST_INSTALL_PACKAGES", "device admin": "BIND_DEVICE_ADMIN",
    "device administrator": "BIND_DEVICE_ADMIN",
}

CLOSED_SOCIAL_HOSTS = {
    "instagram.com": "instagram", "www.instagram.com": "instagram", "m.instagram.com": "instagram",
    "x.com": "x", "www.x.com": "x", "twitter.com": "x", "www.twitter.com": "x", "mobile.twitter.com": "x",
    "facebook.com": "facebook", "www.facebook.com": "facebook", "m.facebook.com": "facebook",
    "fb.com": "facebook", "web.facebook.com": "facebook",
    "tiktok.com": "tiktok", "www.tiktok.com": "tiktok", "m.tiktok.com": "tiktok", "vm.tiktok.com": "tiktok",
}

# ------------------------------------------------------------------ brand-independent rules (checks/generic.py)
# Commonly impersonated brands: (name, official domains, tokens, loose). Tokens match whole hostname pieces and
# page-title words. loose=True also accepts near-misses in hostnames (substring / typo: "ledgrl", "exods"); only
# for names that are not ordinary words.
KNOWN_BRANDS = [
    ("PayPal", ["paypal.com", "paypal.me", "paypalobjects.com"], ["paypal"], True),
    ("Apple", ["apple.com", "icloud.com", "apple.news", "cdn-apple.com"], ["apple", "icloud", "itunes"], False),
    ("Microsoft", ["microsoft.com", "live.com", "office.com", "office365.com", "microsoftonline.com", "outlook.com",
                   "sharepoint.com", "onedrive.com", "msn.com", "bing.com", "azure.com", "windows.net",
                   "microsoft365.com", "skype.com", "xbox.com", "linkedin.com", "github.com"],
     ["microsoft", "office365", "office 365", "microsoft 365", "onedrive", "sharepoint", "outlook web app"], True),
    ("Google", ["google.com", "gmail.com", "youtube.com", "googleusercontent.com", "googleapis.com", "gstatic.com",
                "goo.gl", "google.co.in", "google.co.uk", "blogger.com", "withgoogle.com", "googleblog.com"],
     ["google", "gmail"], False),
    ("Amazon", ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es",
                "amazon.ca", "amazon.com.br", "amazon.co.jp", "amazon.com.au", "amazon.ae", "amazonaws.com",
                "amazon.dev", "media-amazon.com", "primevideo.com"], ["amazon"], False),
    ("Netflix", ["netflix.com", "netflix.net", "nflxext.com"], ["netflix"], True),
    ("Facebook", ["facebook.com", "fb.com", "facebook.net", "fbcdn.net", "meta.com"], ["facebook"], True),
    ("Instagram", ["instagram.com", "cdninstagram.com"], ["instagram"], True),
    ("WhatsApp", ["whatsapp.com", "whatsapp.net", "wa.me"], ["whatsapp"], True),
    ("Telegram", ["telegram.org", "t.me", "telegram.me"], ["telegram"], False),
    ("LinkedIn", ["linkedin.com", "licdn.com"], ["linkedin"], True),
    ("DocuSign", ["docusign.com", "docusign.net"], ["docusign"], True),
    ("Dropbox", ["dropbox.com", "dropboxusercontent.com"], ["dropbox"], True),
    ("Adobe", ["adobe.com", "adobelogin.com", "acrobat.com"], ["adobe"], True),
    ("Steam", ["steampowered.com", "steamcommunity.com", "steamstatic.com"], ["steamcommunity", "steampowered"], True),
    ("Roblox", ["roblox.com", "rbxcdn.com"], ["roblox"], True),
    ("Binance", ["binance.com", "binance.us", "bnbstatic.com"], ["binance"], True),
    ("Coinbase", ["coinbase.com"], ["coinbase"], True),
    ("MetaMask", ["metamask.io"], ["metamask"], True),
    ("Trust Wallet", ["trustwallet.com"], ["trustwallet", "trust wallet"], True),
    ("Ledger", ["ledger.com"], ["ledger"], True),
    ("Trezor", ["trezor.io"], ["trezor"], True),
    ("Exodus", ["exodus.com"], ["exodus wallet", "exodus"], True),
    ("Kraken", ["kraken.com"], ["kraken"], False),
    ("Phantom", ["phantom.app", "phantom.com"], ["phantom wallet"], False),
    ("Uphold", ["uphold.com"], ["uphold"], False),
    ("KuCoin", ["kucoin.com"], ["kucoin"], True),
    ("OpenSea", ["opensea.io"], ["opensea"], True),
    ("DHL", ["dhl.com", "dhl.de", "dhl.co.uk"], ["dhl"], False),
    ("FedEx", ["fedex.com"], ["fedex"], True),
    ("UPS", ["ups.com"], ["ups"], False),
    ("USPS", ["usps.com"], ["usps"], True),
    ("Royal Mail", ["royalmail.com"], ["royalmail", "royal mail"], True),
    ("SEUR", ["seur.com"], ["seur"], False),
    ("Correos", ["correos.es"], ["correos"], False),
    ("India Post", ["indiapost.gov.in"], ["indiapost", "india post"], True),
    ("Magalu", ["magazineluiza.com.br", "magalu.com", "magalu.com.br"], ["magalu", "magazineluiza", "magazine luiza"],
     True),
    ("Chase", ["chase.com", "jpmorganchase.com"], ["chase"], False),
    ("Wells Fargo", ["wellsfargo.com"], ["wellsfargo", "wells fargo"], True),
    ("Bank of America", ["bankofamerica.com", "bofa.com"], ["bankofamerica", "bank of america"], True),
    ("HSBC", ["hsbc.com", "hsbc.co.uk", "hsbc.co.in"], ["hsbc"], False),
    ("SBI", ["sbi.co.in", "sbi", "sbi.bank.in", "onlinesbi.com", "sbicard.com"], ["onlinesbi", "sbi"], False),
    ("HDFC Bank", ["hdfcbank.com", "hdfc.com", "hdfcbank.net", "hdfc.bank.in", "hdfcbank.bank.in"], ["hdfcbank", "hdfc"], True),
    ("ICICI Bank", ["icicibank.com", "icici.com", "icici.bank.in"], ["icicibank", "icici"], True),
    ("Paytm", ["paytm.com", "paytm.in", "paytmbank.com"], ["paytm"], True),
    ("PhonePe", ["phonepe.com"], ["phonepe"], True),
    ("Flipkart", ["flipkart.com"], ["flipkart"], True),
    ("IRCTC", ["irctc.co.in"], ["irctc"], True),
    ("Raiffeisen", ["raiffeisen.ch", "raiffeisen.at", "raiffeisen.ru", "rbinternational.com"], ["raiffeisen"], True),
    ("Robinhood", ["robinhood.com"], ["robinhood"], True),
    ("Shopee", ["shopee.com", "shopee.co.id", "shopee.com.br", "shopee.vn", "shopee.ph", "shopee.sg", "shopee.com.my",
                "shopee.co.th", "shopee.tw"], ["shopee"], True),
    ("Mercado Libre", ["mercadolibre.com", "mercadolivre.com.br", "mercadopago.com"], ["mercadolibre", "mercadolivre",
                                                                                     "mercadopago"], True),
    ("eBay", ["ebay.com", "ebay.co.uk", "ebay.de", "ebay.in"], ["ebay"], False),
    ("Walmart", ["walmart.com"], ["walmart"], True),
    ("Booking.com", ["booking.com"], ["booking.com"], False),
    ("Airbnb", ["airbnb.com", "airbnb.co.in", "airbnb.co.uk"], ["airbnb"], True),
    ("Spotify", ["spotify.com"], ["spotify"], True),
    ("Disney+", ["disneyplus.com", "disney.com"], ["disneyplus", "disney+"], True),
    ("Venmo", ["venmo.com"], ["venmo"], True),
    ("Cash App", ["cash.app", "cashapp.com"], ["cashapp"], True),
    ("Zelle", ["zellepay.com"], ["zelle"], False),
    ("Revolut", ["revolut.com"], ["revolut"], True),
    ("Santander", ["santander.com", "santander.co.uk", "santander.com.br", "santander.es"], ["santander"], True),
    ("BBVA", ["bbva.com", "bbva.es", "bbva.mx"], ["bbva"], False),
    ("Itau", ["itau.com.br"], ["itau"], False),
    ("Bradesco", ["bradesco.com.br"], ["bradesco"], True),
    ("Nubank", ["nubank.com.br", "nu.com.mx"], ["nubank"], True),
    ("Caixa", ["caixa.gov.br"], ["caixa"], False),
    ("La Poste", ["laposte.fr", "laposte.net"], ["laposte"], True),
    ("Poste Italiane", ["poste.it", "posteitaliane.it"], ["posteitaliane", "poste italiane"], True),
    ("PostNL", ["postnl.nl"], ["postnl"], True),
    ("Swiss Post", ["post.ch", "swisspost.ch"], ["swisspost"], True),
    ("Canada Post", ["canadapost-postescanada.ca", "canadapost.ca"], ["canadapost", "canada post"], True),
    ("Australia Post", ["auspost.com.au"], ["auspost", "australia post"], True),
    ("Evri", ["evri.com"], ["evri"], False),
    ("CommBank", ["commbank.com.au"], ["commbank"], True),
    ("Interac", ["interac.ca"], ["interac"], True),
    ("AT&T", ["att.com", "att.net"], ["att"], False),
    ("Verizon", ["verizon.com", "verizonwireless.com"], ["verizon"], True),
    ("Yahoo", ["yahoo.com", "yahoo.co.jp", "yahoo.co.in"], ["yahoo"], False),
    ("Discord", ["discord.com", "discord.gg", "discordapp.com"], ["discordapp", "discord nitro"], True),
    ("TikTok", ["tiktok.com"], ["tiktok"], True),
    ("Snapchat", ["snapchat.com"], ["snapchat"], True),
    ("Twitch", ["twitch.tv"], ["twitch"], False),
    ("Epic Games", ["epicgames.com"], ["epicgames", "epic games"], True),
    ("WeTransfer", ["wetransfer.com", "we.tl"], ["wetransfer"], True),
    ("Zoom", ["zoom.us", "zoom.com"], ["zoom meeting"], False),
    ("Okta", ["okta.com", "oktacdn.com"], ["okta"], False),
    ("Bybit", ["bybit.com"], ["bybit"], True),
    ("OKX", ["okx.com"], ["okx"], False),
    ("Bitget", ["bitget.com"], ["bitget"], True),
    ("Crypto.com", ["crypto.com"], ["crypto.com"], False),
    ("Uniswap", ["uniswap.org", "app.uniswap.org"], ["uniswap"], True),
    ("PancakeSwap", ["pancakeswap.finance"], ["pancakeswap"], True),
    ("Atomic Wallet", ["atomicwallet.io"], ["atomicwallet", "atomic wallet"], True),
    ("Rabby", ["rabby.io"], ["rabby wallet"], False),
]

# Registries that only admit verified holders (RBI-regulated banks, governments...): a name there is not a lookalike.
RESTRICTED_SUFFIXES = ["bank.in", "fin.in", "gov.in", "nic.in", "mil.in", "bank", "gov", "mil", "edu"]

# Free website builders, app hosts, tunnels and dynamic DNS: anyone can create a subdomain in seconds.
FREE_HOSTING_SUFFIXES = [
    "vercel.app", "pages.dev", "workers.dev", "netlify.app", "github.io", "gitlab.io", "web.app", "firebaseapp.com",
    "glitch.me", "wasmer.app", "onrender.com", "herokuapp.com", "fly.dev", "railway.app", "repl.co", "replit.app",
    "replit.dev", "deno.dev", "csb.app", "stackblitz.io", "glide.page", "glideapp.io", "typedream.app", "craftum.io",
    "b12sites.com", "weebly.com", "weeblysite.com", "wixsite.com", "wixstudio.io", "webflow.io", "framer.app",
    "framer.website", "framer.ai", "carrd.co", "godaddysites.com", "square.site", "mystrikingly.com",
    "strikingly.com", "site123.me", "jimdofree.com", "jimdosite.com", "000webhostapp.com", "ngrok-free.app",
    "ngrok.io", "ngrok.app", "trycloudflare.com", "loca.lt", "serveo.net", "duckdns.org", "webhop.me", "ddns.net",
    "hopto.org", "zapto.org", "sytes.net", "no-ip.org", "myftp.org", "servehttp.com", "r2.dev", "dweb.link",
    "fleek.co", "surge.sh", "tiiny.site", "notion.site", "gitbook.io", "blogspot.com", "wordpress.com",
    "azurewebsites.net", "appspot.com", "ondigitalocean.app", "cloudwaysapps.com", "webwave.me", "wuaze.com",
    "rf.gd", "epizy.com", "infinityfreeapp.com", "lovable.app", "pythonanywhere.com", "w3spaces.com", "tilda.ws",
    "ucraft.site", "yolasite.com", "mobirisesite.com", "softr.app", "bubbleapps.io", "simdif.com", "ukit.me",
    "bolt.host", "edgeone.app", "canva.site", "my.canva.site", "gamma.site",
]
# Here the subdomain is the account/org name, so "<brand>.github.io" is the brand's own org, not a lookalike.
ORG_NAMESPACE_HOSTS = ["github.io", "gitlab.io"]

# A hosting provider's default server name: a site nobody bothered to give a domain.
SERVER_HOST_PATTERNS = [
    r"^vmi\d+\.contaboserver\.net$", r"\.vps\.ovh\.(net|ca|us)$", r"^ec2-[\d-]+\.[\w.-]*compute\.amazonaws\.com$",
    r"\.your-server\.de$", r"\.linodeusercontent\.com$", r"\.vultrusercontent\.com$",
    r"\.bc\.googleusercontent\.com$", r"\.hostwindsdns\.com$", r"\.(sslip|nip)\.io$",
    r"^\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3}\.", r"\.global\.ssl\.fastly\.net$", r"\.cloudfront\.net$",
    r"\.azureedge\.net$",
]

# Whole hostname pieces that phishing kits put in attacker-chosen names (login-verify-account...).
HOST_PHISH_WORDS = ["login", "signin", "logon", "verify", "verification", "secure", "account", "accounts", "update",
                    "wallet", "recover", "recovery", "unlock", "suspended", "auth", "authenticate", "kyc", "billing",
                    "confirm", "webscr", "appeal", "claim", "reward", "rewards", "airdrop", "bonus", "refund",
                    "support", "helpdesk", "validate", "restore", "dapp", "payment", "invoice"]
# Distinctive enough to count when glued to other words too ("verifynow", "signinpage").
HOST_PHISH_STEMS = ["verif", "signin", "login", "logon", "webscr", "airdrop", "kyc"]

# Page titles that are classic lures: anywhere in the title, or as the whole title.
LURE_TITLE_ANYWHERE = [r"\bvoice ?mail\b", r"\bpdf (viewer|online|document)\b", r"\bwallet ?connect\b",
                       r"\bconnect (your )?wallet\b", r"\bclaim (your )?(airdrop|reward)", r"\bairdrop claim\b",
                       r"\bsecure (document|file|message)\b", r"\bshared (a )?(document|file) with you\b",
                       r"\bdocument (viewer|portal|shared)\b"]
LURE_TITLE_EXACT = [r"verification", r"verify", r"verify (your )?(account|identity|email)",
                    r"account (verification|suspended|locked)", r"email verification", r"webmail( login)?",
                    r"mailbox (full|update|login)", r"airdrop", r"document"]

# What a hosting provider shows after taking a site down for abuse.
ABUSE_BLOCK_PATTERNS = [
    r"suspected (phishing|malware)", r"reported for (potential |possible )?(phishing|malware)",
    r"reported for potentially distributing malware", r"disabled by the [\w .&-]{0,40}trust (&|and) safety",
    r"\bdeployment_disabled\b", r"phishing (site|page) (detected|warning|blocked)",
    r"(site|app|page|website) has been (disabled|suspended|removed|taken down) (for|due to) (a )?"
    r"(violation|violating|abuse|phishing|malicious|fraud)",
]

# ------------------------------------------------------------------ public scam/phishing lists (scamlists.py)
# (name, url, terms). Downloaded at runtime and never stored in the repo. Check each source's terms before use;
# drop one with SCAM_LIST_EXCLUDE=<name>. Every line is a domain, an adblock rule (||domain^) or a URL.
SCAM_LIST_SOURCES = [
    ("openphish", "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
     "OpenPhish Community Feed: non-commercial use only (openphish.com/terms.html)"),
    ("phishing-database", "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/"
                          "phishing-domains-ACTIVE.txt", "MIT"),
    ("discord-antiscam", "https://raw.githubusercontent.com/Discord-AntiScam/scam-links/main/list.txt",
     "no license stated"),
    ("devspen", "https://raw.githubusercontent.com/DevSpen/scam-links/master/src/links.txt", "Unlicense"),
    ("jarelllama", "https://raw.githubusercontent.com/jarelllama/Scam-Blocklist/main/lists/wildcard_domains/scams.txt",
     "GPL-3.0"),
    ("nikolaischunk", "https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/txt/domain-list.txt",
     "MIT"),
]
# List entries that are popular sites are list mistakes (bit.ly, surveymonkey.com, rei.com were all listed).
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_SANITISE_TOP = 100_000
