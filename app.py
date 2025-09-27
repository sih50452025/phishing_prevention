# app.py
from flask import Flask, render_template, request
import pickle
import numpy as np
import re
from urllib.parse import urlparse
import os
import pickle
import subprocess

MODEL_PATH="phishing.pkl"
if not os.path.exists(MODEL_PATH):
  subprocess.run(["python","model.py"],check=True)
with open(MODEL_PATH,"rb") as f:
  model=pickle.load(f)
# ---------------- Trusted Domains ----------------
TRUSTED_DOMAINS = [
    "google.com", "github.com","instagram.com" ,"microsoft.com", "apple.com",
    "facebook.com", "amazon.com", "wikipedia.org", "yahoo.com","https://sincet.ac.in","https://www.khanacademy.org",
  "https://www.coursera.org",
  "https://www.edx.org",
  "https://ocw.mit.edu",
  "https://www.duolingo.com",
  "https://www.codecademy.com",
  "https://www.udemy.com",
  "https://www.brilliant.org",
  "https://academicearth.org",
  "https://www.ted.com",
  "https://github.com",
  "https://stackoverflow.com",
  "https://developer.mozilla.org",
  "https://www.w3schools.com",
  "https://www.geeksforgeeks.org",
  "https://www.freecodecamp.org",
  "https://www.hackerrank.com",
  "https://leetcode.com",
  "https://dev.to",
  "https://www.smashingmagazine.com",
  "https://www.bbc.com",
  "https://www.reuters.com",
  "https://www.theguardian.com",
  "https://www.aljazeera.com",
  "https://www.npr.org",
  "https://apnews.com",
  "https://www.bloomberg.com",
  "https://www.thehindu.com",
  "https://indianexpress.com",
  "https://thewire.in",
  "https://scholar.google.com",
  "https://www.wolframalpha.com",
  "https://pubmed.ncbi.nlm.nih.gov",
  "https://www.jstor.org",
  "https://www.gutenberg.org",
  "https://archive.org",
  "https://www.britannica.com",
  "https://www.sciencedirect.com",
  "https://www.springer.com",
  "https://arxiv.org",
  "https://www.grammarly.com",
  "https://www.zotero.org",
  "https://www.notion.so",
  "https://www.evernote.com",
  "https://keep.google.com",
  "https://trello.com",
  "https://www.canva.com",
  "https://www.overleaf.com",
  "https://www.mendeley.com",
  "https://mathworld.wolfram.com",
  "https://www.ign.com",
  "https://www.polygon.com",
  "https://kotaku.com",
  "https://store.steampowered.com",
  "https://www.epicgames.com",
  "https://www.gamespot.com",
  "https://www.twitch.tv",
  "https://itch.io",
  "https://www.playstation.com",
  "https://www.xbox.com",
  "https://workspace.google.com",
  "https://www.microsoft.com/en-us/microsoft-365",
  "https://www.dropbox.com",
  "https://www.box.com",
  "https://slack.com",
  "https://zoom.us",
  "https://calendly.com",
  "https://todoist.com",
  "https://www.clickup.com",
  "https://asana.com",
  "https://www.figma.com",
  "https://www.adobe.com",
  "https://www.behance.net",
  "https://dribbble.com",
  "https://elements.envato.com",
  "https://unsplash.com",
  "https://www.pexels.com",
  "https://pixabay.com",
  "https://coolors.co",
  "https://www.fontsquirrel.com",
  "https://haveibeenpwned.com",
  "https://proton.me",
  "https://duckduckgo.com",
  "https://signal.org",
  "https://www.torproject.org",
  "https://bitwarden.com",
  "https://www.mozilla.org",
  "https://www.eff.org",
  "https://www.privacytools.io",
  "https://www.cisa.gov",
  "https://www.speedtest.net",
  "https://downdetector.com",
  "https://ifttt.com",
  "https://zapier.com",
  "https://tinyurl.com",
  "https://www.namecheap.com",
  "https://gitlab.com",
  "https://bitbucket.org",
  "https://www.cloudflare.com",
  "https://www.netlify.com",
   "twitter.com",
  "linkedin.com",
  "reddit.com",
  "netflix.com",
  "microsoft.com",
  "apple.com",
  "whatsapp.com",
  "github.com",
  "stackoverflow.com",
  "bing.com",
  "yahoo.com",
  "zoom.us",
  "dropbox.com",
  "canva.com",
  "notion.so",
  "slack.com",
  "medium.com",
  "quora.com",
  "twitch.tv",
  "paypal.com",
  "adobe.com",
  "cloudflare.com",
  "wordpress.com",
  "tumblr.com",
  "pinterest.com",
  "roblox.com",
  "steamcommunity.com",
  "epicgames.com",
  "playstation.com",
  "xbox.com",
  "deezer.com",
  "spotify.com",
  "soundcloud.com",
  "coursera.org",
  "edx.org",
  "khanacademy.org",
  "udemy.com",
  "brilliant.org",
  "duolingo.com",
  "archive.org",
  "gutenberg.org",
  "arxiv.org",
  "jstor.org",
  "springer.com",
  "sciencedirect.com",
  "pubmed.ncbi.nlm.nih.gov",
  "npr.org",
  "bbc.com",
  "reuters.com",
  "theguardian.com",
  "aljazeera.com",
  "thehindu.com",
  "indianexpress.com",
  "thewire.in",
  "mozilla.org",
  "eff.org",
  "proton.me",
  "duckduckgo.com",
  "signal.org",
  "torproject.org",
  "bitwarden.com",
  "privacytools.io",
  "cisa.gov",
  "speedtest.net",
  "downdetector.com",
  "ifttt.com",
  "zapier.com",
  "tinyurl.com",
  "namecheap.com",
  "gitlab.com",
  "bitbucket.org",
  "netlify.com",
  "figma.com",
  "dribbble.com",
  "behance.net",
  "unsplash.com",
  "pexels.com",
  "pixabay.com",
  "coolors.co",
  "fontsquirrel.com",
  "store.steampowered.com",
  "itch.io",
  "dev.to",
  "freecodecamp.org",
  "geeksforgeeks.org",
  "w3schools.com",
  "developer.mozilla.org",
  "mathworld.wolfram.com",
  "wolframalpha.com",
  "scholar.google.com",
  "calendar.google.com",
  "keep.google.com",
  "workspace.google.com",
  "microsoft365.com"

]

# ---------------- Suspicious Keywords ----------------
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account", "banking",
    "confirm", "paypal", "signin", "password", "credential"
]

# ---------------- Features ----------------
FEATURE_COLS = [
    'length_url','qty_dot_url','qty_hyphen_url','qty_slash_url','qty_questionmark_url','qty_equal_url',
    'qty_at_url','qty_and_url','qty_exclamation_url','qty_hashtag_url','qty_dollar_url','qty_percent_url',
    'qty_tld_url','qty_dot_domain','domain_length','subdomain_count','subdomain_length','query_count',
    'has_ip','https_presence'
]

def extract_features_from_url(url):
    u = url.strip()
    if not (u.startswith('http://') or u.startswith('https://')):
        u = 'http://' + u
    parsed = urlparse(u)
    path = parsed.path or ""
    query = parsed.query or ""
    host = parsed.netloc or ""
    host = host.split(":")[0]

    length_url = len(u)
    qty_dot_url = u.count(".")
    qty_hyphen_url = u.count("-")
    qty_slash_url = u.count("/")
    qty_questionmark_url = u.count("?")
    qty_equal_url = u.count("=")
    qty_at_url = u.count("@")
    qty_and_url = u.count("&")
    qty_exclamation_url = u.count("!")
    qty_hashtag_url = u.count("#")
    qty_dollar_url = u.count("$")
    qty_percent_url = u.count("%")

    common_tlds = ['.com', '.net', '.org', '.info', '.io', '.gov', '.edu', '.co', '.uk', '.ru', '.cn']
    qty_tld_url = sum(u.count(tld) for tld in common_tlds)
    qty_dot_domain = host.count(".")
    domain_parts = host.split(".")
    domain_length = len(domain_parts[0]) if domain_parts and domain_parts[0] else 0
    subdomain_count = max(0, len(domain_parts) - 2) if len(domain_parts) >= 2 else 0
    subdomain_length = sum(len(p) for p in domain_parts[:-2]) if subdomain_count > 0 else 0
    query_count = len([part for part in query.split("&") if part]) if query else 0
    has_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) else 0
    https_presence = 1 if parsed.scheme == "https" else 0

    feats = {
        'length_url': length_url,
        'qty_dot_url': qty_dot_url,
        'qty_hyphen_url': qty_hyphen_url,
        'qty_slash_url': qty_slash_url,
        'qty_questionmark_url': qty_questionmark_url,
        'qty_equal_url': qty_equal_url,
        'qty_at_url': qty_at_url,
        'qty_and_url': qty_and_url,
        'qty_exclamation_url': qty_exclamation_url,
        'qty_hashtag_url': qty_hashtag_url,
        'qty_dollar_url': qty_dollar_url,
        'qty_percent_url': qty_percent_url,
        'qty_tld_url': qty_tld_url,
        'qty_dot_domain': qty_dot_domain,
        'domain_length': domain_length,
        'subdomain_count': subdomain_count,
        'subdomain_length': subdomain_length,
        'query_count': query_count,
        'has_ip': has_ip,
        'https_presence': https_presence
    }
    return [feats[c] for c in FEATURE_COLS], host, path, query

# ---------------- Load Model ----------------
with open("phishing.pkl", "rb") as f:
    model_obj = pickle.load(f)
model = model_obj['model']

# ---------------- Flask App ----------------
app = Flask(__name__)

@app.route("/", methods=["GET","POST"])
def index():
    result = None
    score = None
    url = ""
    if request.method == "POST":
        url = request.form.get("url", "")
        if url:
            feats, host, path, query = extract_features_from_url(url)

            # ---- Rule 1: Trusted domain override ----
            for trusted in TRUSTED_DOMAINS:
                if host.endswith(trusted):
                    result = f"safe ✅ (trusted domain: {trusted})"
                    score = 0.0
                    return render_template("index.html", result=result, score=score, url=url)

            # ---- Rule 2: Suspicious keyword boost ----
            for word in SUSPICIOUS_KEYWORDS:
                if word in url.lower():
                    result = f"Phishing 🚨 (suspicious keyword: {word})"
                    score = 1.0
                    return render_template("index.html", result=result, score=score, url=url)

            # ---- Otherwise, use ML model ----
            feats[0] = np.log1p(feats[0])  # log transform length_url
            X = np.array(feats).reshape(1, -1)
            pred = model.predict(X)[0]
            try:
                prob = model.predict_proba(X)[0][1]
                score = float(round(prob, 4))
            except Exception:
                score = None
            result = "Phishing 🚨" if int(pred) == 1 else "Legitimate ✅"

    return render_template("index.html", result=result, score=score, url=url)

if __name__ == "__main__":
    app.run(debug=True)
    app.run(host="0.0.0.0", port=5000, debug=False)

