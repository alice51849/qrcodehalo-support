#!/usr/bin/env python3
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HTML_FILES = ("index.html", "support.html", "privacy.html", "terms.html")
EXPECTED_LOCALES = {
    "ar-SA", "bn-BD", "ca", "cs", "da", "de-DE", "el", "en-AU", "en-CA", "en-GB",
    "en-US", "es-ES", "es-MX", "fi", "fr-CA", "fr-FR", "gu-IN", "he", "hi", "hr",
    "hu", "id", "it", "ja", "kn-IN", "ko", "ml-IN", "mr-IN", "ms", "nl-NL", "no",
    "or-IN", "pa-IN", "pl", "pt-BR", "pt-PT", "ro", "ru", "sk", "sl-SI", "sv",
    "ta-IN", "te-IN", "th", "tr", "uk", "ur-PK", "vi", "zh-Hans", "zh-Hant",
}
PAYLOAD_RE = re.compile(r"<script>window\.QH_I18N=(\{.*?\});</script>", re.S)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
DATE_RE = re.compile(r"\b20\d{2}-\d{2}-\d{2}\b")
LOCALE_KEYS = {
    "langName", "langLabel", "navHome", "navSupport", "navPrivacy", "navTerms", "foot",
    "updated", "secContact", "contact", "contactHint", "secStart", "start", "secTrouble",
    "trouble", "secPrivacy", "priv", "secAppStore", "appStorePurchase", "secTerms",
    "terms", "secSecurity", "securityTiles", "secAccess", "freeTitle", "freeItems",
    "proTitle", "proSummary", "proNote", "proFeatureCount", "secBoundaries", "boundaries",
    "pages",
}
PAGE_KEYS = {"title", "meta", "badge", "h1", "lead"}
FORBIDDEN_SNIPPETS = {
    "ls-family",
    "More apps from the same developer",
    "apps.apple.com",
    "is1-ssl.mzstatic.com",
    "WiFi Aid Lite",
    "Snapport Lite",
    "Mask My File",
    "ScanTo Pro",
    "ios-app-guide",
    "alice51849@hotmail.com",
    "2026-08-30",
    "adds six things",
    "six things:",
    "unlimited scanning of every supported format",
    "Wi-Fi will not join from a code",
    "When you choose to open a link, join a Wi-Fi network or add a contact",
}


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def require(condition, message):
    if not condition:
        fail(message)


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)


def require_tokens(text, tokens, label):
    folded = text.casefold().replace("‑", "-")
    missing = [token for token in tokens if token.casefold().replace("‑", "-") not in folded]
    require(not missing, f"{label} missing: {', '.join(missing)}")


documents = {}
payload_texts = {}
payloads = {}
for name in HTML_FILES:
    path = ROOT / name
    require(path.is_file(), f"missing {name}")
    text = path.read_text()
    documents[name] = text
    match = PAYLOAD_RE.search(text)
    require(match is not None, f"{name} has no QH_I18N payload")
    payload_texts[name] = match.group(1)
    try:
        payloads[name] = json.loads(match.group(1))
    except json.JSONDecodeError as error:
        fail(f"{name} payload is not valid JSON: {error}")

reference = payloads["index.html"]
require(set(reference) == EXPECTED_LOCALES, "locale set is not Apple exact 50")
for name in HTML_FILES[1:]:
    require(payloads[name] == reference, f"{name} payload differs from index.html")

for locale, data in reference.items():
    require(set(data) == LOCALE_KEYS, f"{locale} has an unexpected payload schema")
    require(data["proFeatureCount"] == 7, f"{locale} does not declare seven Pro unlocks")
    require(len(data["securityTiles"]) == 2, f"{locale} needs two security workflows")
    require(len(data["freeItems"]) == 5, f"{locale} free contract is incomplete")
    require(len(data["boundaries"]) == 3, f"{locale} capability boundaries are incomplete")
    require(len(data["start"]) == 3, f"{locale} getting-started content is incomplete")
    require(len(data["trouble"]) == 3, f"{locale} troubleshooting content is incomplete")
    require(len(data["priv"]) == 6, f"{locale} privacy content is incomplete")
    require(len(data["appStorePurchase"]) == 3, f"{locale} purchase privacy content is incomplete")
    require(len(data["terms"]) == 4, f"{locale} terms content is incomplete")
    require(set(data["pages"]) == {"index", "support", "privacy", "terms"}, f"{locale} page set differs")
    for page, page_data in data["pages"].items():
        require(set(page_data) == PAGE_KEYS, f"{locale}/{page} page schema differs")
    require(all(value.strip() for value in strings(data)), f"{locale} contains a blank translation")
    require(
        data["securityTiles"][0].startswith(data["secSecurity"] + " · Local Payload Security Inspector|"),
        f"{locale} does not expose Local Payload Security Inspector",
    )
    require(
        " · Batch Risk & Difference Audit|" in data["securityTiles"][1],
        f"{locale} does not expose Batch Risk & Difference Audit",
    )

english = reference["en-US"]
for locale, data in reference.items():
    if locale.startswith("en-"):
        continue
    comparisons = (
        (data["securityTiles"], english["securityTiles"], "securityTiles"),
        (data["freeItems"][0], english["freeItems"][0], "scan quota"),
        (data["freeItems"][-1], english["freeItems"][-1], "free batch details"),
        (data["proSummary"], english["proSummary"], "Pro summary"),
        (data["boundaries"], english["boundaries"], "capability boundaries"),
        (data["pages"]["index"]["lead"], english["pages"]["index"]["lead"], "home lead"),
    )
    for value, english_value, label in comparisons:
        require(value != english_value, f"{locale} uses an English fallback for {label}")

inspector = english["securityTiles"][0]
require_tokens(
    inspector,
    ("scheme", "host", "path", "query", "Safe", "Caution", "Blocked", "deterministic",
     "device", "network reputation"),
    "English security inspector",
)
audit = english["securityTiles"][1]
require_tokens(
    audit,
    ("exact duplicates", "matching hosts", "lookalike-host", "bounded", "every item", "risk", "device"),
    "English batch audit",
)
free_contract = " ".join(english["freeItems"])
require_tokens(
    free_contract,
    ("three successful scans", "camera", "Photos", "failed scans", "cancellations",
     "permission denials", "text", "link", "Wi-Fi", "contact", "email", "phone", "SMS",
     "location", "calendar event", "unlimited history", "favorites", "search", "filters",
     "category", "multi-select deletion", "history export as CSV", "batch collection",
     "complete per-item reading"),
    "English free contract",
)
require_tokens(
    english["proSummary"],
    ("seven items", "Unlimited scanning", "saving a scanned batch to history",
     "opening a batch result's action", "batch creation and batch CSV",
     "committing a backup or a restore", "high resolution PNG, PDF and SVG export",
     "custom Aurora styles"),
    "English Pro contract",
)
boundaries = " ".join(english["boundaries"])
require_tokens(
    boundaries,
    ("read, copied and shared", "safe actionURL", "explicitly confirm",
     "does not claim to join Wi-Fi or add contacts or events directly",
     "Share Extension", "URL or plain text", "PDF export contains QR artwork only",
     "not a document scanner", "OCR tool", "PDF library"),
    "English capability boundaries",
)

for name, text in documents.items():
    for snippet in FORBIDDEN_SNIPPETS:
        require(snippet.casefold() not in text.casefold(), f"{name} contains forbidden claim: {snippet}")
    require(set(EMAIL_RE.findall(text)) == {"hourstag.app@gmail.com"}, f"{name} has an unexpected email")
    require(set(DATE_RE.findall(text)) == {"2026-09-10"}, f"{name} has an unexpected update date")
    expected_page = name.removesuffix(".html")
    require(f'<body data-page="{expected_page}">' in text, f"{name} has the wrong page identity")

index = documents["index.html"]
lead = english["pages"]["index"]["lead"]
require(f'<meta name="description" content="{lead}">' in index, "static home description is stale")
require(f'<meta property="og:description" content="{lead}">' in index, "static Open Graph description is stale")
require(f'<p class="lead" id="lead">{lead}</p>' in index, "static home lead is stale")

sitemap = (ROOT / "sitemap.xml").read_text()
require(sitemap.count("<lastmod>2026-09-10</lastmod>") == 4, "sitemap lastmod is stale")
require("2026-09-03" not in sitemap, "sitemap contains the previous lastmod")

digest = hashlib.sha256(payload_texts["index.html"].encode()).hexdigest()[:12]
print(f"PASS: 4 pages · exact 50 locales · identical payload {digest} · contract/date/email checks")
