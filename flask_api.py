# app.py
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import requests
from bs4 import BeautifulSoup
import sqlite3
import os
import re
import time
import json
from datetime import datetime
import tldextract
from dateutil import tz
from urllib.parse import urljoin, urlparse
import threading
import logging
import socket

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
DB_NAME = "crawler.db"

# heuristics / keywords
SUSPICIOUS_KEYWORDS = [
    "malware", "phish", "phishing", "trojan", "ransom", "credential", "steal",
    "login", "bank", "password", "confirm", "verify", "account", "credit card"
]

_alert_queue = []               # SSE alert queue
_currently_crawling = set()     # in-memory tracking (single-process)
_crawl_lock = threading.Lock()  # protects _currently_crawling

# Optional API keys
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GOOGLE_SAFE_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

# --------------------
# Tor auto-detection
# --------------------
def detect_tor_proxy():
    """Detect whether Tor SOCKS proxy is running on 9050 or 9150. Returns proxies dict or None."""
    for port in (9050, 9150):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.5):
                logging.info("Using Tor proxy at 127.0.0.1:%d", port)
                return {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}
        except OSError:
            continue
    logging.warning("No Tor proxy detected on 9050 or 9150.")
    return None

TOR_PROXIES = detect_tor_proxy()

# --------------------
# Database Setup + migration helper
# --------------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS crawled_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            link TEXT,
            content TEXT,
            risk_level TEXT,
            classification TEXT,
            entities TEXT,
            last_analyzed TEXT
        )
    """)
    conn.commit()
    # apply safe ALTERs for new columns if missing
    cursor.execute("PRAGMA table_info(crawled_data)")
    cols = [c[1] for c in cursor.fetchall()]
    if "is_onion" not in cols:
        try:
            cursor.execute("ALTER TABLE crawled_data ADD COLUMN is_onion INTEGER DEFAULT 0")
        except Exception as e:
            logging.debug("Could not add is_onion column: %s", e)
    if "title" not in cols:
        try:
            cursor.execute("ALTER TABLE crawled_data ADD COLUMN title TEXT")
        except Exception as e:
            logging.debug("Could not add title column: %s", e)
    conn.commit()
    conn.close()

# --------------------
# Helpers: entity extraction & heuristics
# --------------------
EMAIL_RE = re.compile(r'[a-zA-Z0-9\.\-_+%]+@[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}')
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_RE = re.compile(r'(?:https?://)?(?:www\.)?([A-Za-z0-9.-]+\.[A-Za-z]{2,})')

def extract_entities(text):
    emails = list(set(EMAIL_RE.findall(text or "")))
    ips = list(set(IP_RE.findall(text or "")))
    domains = list(set(m for m in DOMAIN_RE.findall(text or "") if m))
    return {"emails": emails, "ips": ips, "domains": domains}

def detect_obfuscated_js(soup):
    scripts = soup.find_all('script')
    score = 0
    for s in scripts:
        src = s.get('src')
        if not src:
            txt = (s.string or '')[:10000]
            if len(txt) > 1000:
                score += 1
            if re.search(r'\beval\(|\bFunction\(|atob\(|unescape\(|\\x[0-9A-Fa-f]{2}', txt):
                score += 2
    return score

def detect_suspicious_forms(soup):
    forms = soup.find_all('form')
    score = 0
    host_url = ""
    try:
        host_url = request.host_url
    except RuntimeError:
        host_url = ""
    for f in forms:
        inputs = f.find_all('input')
        names = " ".join([ (i.get('name') or '') + " " + (i.get('type') or '') for i in inputs ])
        if re.search(r'password|passwd|credit|card|cvv|ssn|account', names, re.I):
            score += 3
        action = (f.get('action') or '')
        if action and not action.strip().startswith('#'):
            # external action: basic heuristic
            if not action.startswith('/') and (not host_url or not action.startswith(host_url)):
                score += 1
    return score

def heuristics_analysis(text, soup, url):
    text_lower = (text or "").lower()
    keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in text_lower)
    obf_score = detect_obfuscated_js(soup)
    form_score = detect_suspicious_forms(soup)
    entities = extract_entities(text)
    parsed = tldextract.extract(url)
    domain_score = 0
    # some basic weird-domain heuristics
    if parsed.suffix and parsed.suffix.isdigit():
        domain_score += 1
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed.domain or ""):
        domain_score += 2

    raw_score = keyword_hits * 2 + obf_score * 3 + form_score * 3 + domain_score
    if raw_score >= 7:
        risk = "High"
    elif raw_score >= 3:
        risk = "Medium"
    else:
        risk = "Low"

    classification = "benign"
    if "phish" in text_lower or "verify your account" in text_lower or form_score >= 3:
        classification = "phishing"
    elif obf_score >= 2:
        classification = "malicious-js"
    elif "ransom" in text_lower or "encrypt" in text_lower:
        classification = "ransomware-host"
    elif raw_score >= 7:
        classification = "suspicious"

    return {"risk_level": risk, "classification": classification, "entities": entities, "score": raw_score}

# --------------------
# Threat intel helpers (unchanged)
# --------------------
def check_virustotal(url):
    if not VT_API_KEY:
        return None
    try:
        headers = {"x-apikey": VT_API_KEY}
        resp = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers, timeout=10)
        if resp.status_code in (200, 201):
            analysis_id = resp.json().get("data", {}).get("id")
            if analysis_id:
                get_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                result = requests.get(get_url, headers=headers, timeout=10)
                return result.json()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

def check_google_safe(url):
    if not GOOGLE_SAFE_KEY:
        return None
    try:
        r = requests.get("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                         params={"key": GOOGLE_SAFE_KEY},
                         json={
                             "client": {"clientId": "crawler", "clientVersion": "1.0"},
                             "threatInfo": {
                                 "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                                 "platformTypes": ["ANY_PLATFORM"],
                                 "threatEntryTypes": ["URL"],
                                 "threatEntries": [{"url": url}]
                             }
                         }, timeout=10)
        if r.status_code == 200 and r.json():
            return r.json()
        return None
    except Exception as e:
        return {"error": str(e)}

# --------------------
# Utility: normalize/validate URLs
# --------------------
URL_RE = re.compile(r'^(?:http|https)://', re.I)

def normalize_url(maybe_url):
    maybe_url = (maybe_url or "").strip()
    if not maybe_url:
        return None
    # if user provided domain without scheme:
    if not URL_RE.match(maybe_url):
        # prefer http for .onion, otherwise https
        if maybe_url.lower().endswith(".onion") or ".onion/" in maybe_url.lower():
            maybe_url = "http://" + maybe_url
        else:
            maybe_url = "https://" + maybe_url
    parsed = urlparse(maybe_url)
    if not parsed.netloc:
        return None
    return parsed.geturl()

def looks_like_url(text):
    if not text:
        return False
    text = text.strip()
    if URL_RE.match(text):
        return True
    if " " not in text and "." in text and len(text) < 200:
        return True
    return False

# --------------------
# Database CRUD helpers
# --------------------
def save_crawl_record(url, links, content, risk_level, classification, entities, is_onion=False, title=""):
    """Insert records for the seed url. Keeps only latest records for the seed (deletes old)."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    last_analyzed = datetime.utcnow().isoformat() + "Z"
    try:
        cursor.execute("DELETE FROM crawled_data WHERE url = ?", (url,))
        for link in links:
            cursor.execute("""
                INSERT INTO crawled_data (url, link, content, risk_level, classification, entities, last_analyzed, is_onion, title)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (url, link, content[:20000], risk_level, classification, json.dumps(entities), last_analyzed, 1 if is_onion else 0, title))
        conn.commit()
    except Exception as e:
        logging.exception("Error saving crawl record for %s: %s", url, e)
    finally:
        conn.close()

def _get_table_columns():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(crawled_data)")
    cols = [c[1] for c in cursor.fetchall()]
    conn.close()
    return cols

def fetch_results():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cols = _get_table_columns()
    has_is_onion = "is_onion" in cols
    has_title = "title" in cols
    query = "SELECT url, link, risk_level, classification, entities, last_analyzed"
    query += ", is_onion" if has_is_onion else ", 0"
    query += ", title" if has_title else ", ''"
    query += " FROM crawled_data"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()

    results = {}
    for url, link, risk, classification, entities_json, last, is_onion, title in rows:
        if url not in results:
            results[url] = {
                "risk_level": risk,
                "classification": classification,
                "entities": json.loads(entities_json) if entities_json else {},
                "last_analyzed": last,
                "is_onion": bool(is_onion),
                "title": title or "",
                "links": []
            }
        results[url]["links"].append(link)
    return results

def search_results_db(query):
    """Search links by substring. Works with older/newer schemas."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cols = _get_table_columns()
    has_is_onion = "is_onion" in cols
    has_title = "title" in cols

    base = "SELECT url, link, risk_level, classification, entities, last_analyzed"
    base += ", is_onion" if has_is_onion else ", 0"
    base += ", title" if has_title else ", ''"
    base += " FROM crawled_data WHERE link LIKE ?"
    cursor.execute(base, ('%' + query + '%',))
    rows = cursor.fetchall()
    conn.close()

    results = {}
    for url, link, risk, classification, entities_json, last, is_onion, title in rows:
        if url not in results:
            results[url] = {
                "risk_level": risk,
                "classification": classification,
                "entities": json.loads(entities_json) if entities_json else {},
                "last_analyzed": last,
                "is_onion": bool(is_onion),
                "title": title or "",
                "links": []
            }
        results[url]["links"].append(link)
    return results

def url_already_crawled(url):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(1) FROM crawled_data WHERE url = ?", (url,))
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0

# --------------------
# Core analyze function
# --------------------
def analyze_and_save(url):
    with _crawl_lock:
        if url in _currently_crawling:
            return {"status": "already_crawling", "url": url}
        _currently_crawling.add(url)

    parsed_netloc = urlparse(url).netloc or ""
    is_onion = parsed_netloc.lower().endswith(".onion")

    # decide proxies: use TOR_PROXIES for onion if available
    proxies = TOR_PROXIES if is_onion and TOR_PROXIES else None
    if is_onion and not TOR_PROXIES:
        logging.warning("Attempting to crawl .onion but no Tor proxy detected")

    try:
        # single request, longer timeout for .onion
        resp = requests.get(
            url,
            timeout=60 if is_onion else 15,
            headers={"User-Agent": "Mozilla/5.0 (crawler)"},
            proxies=proxies,
            allow_redirects=True,
            verify=False if is_onion else True
        )
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        links = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.startswith('//'):
                href = 'http:' + href
            elif href.startswith('/'):
                href = urljoin(url, href)
            links.append(href)
        text = soup.get_text(separator=' ', strip=True)
        heur = heuristics_analysis(text, soup, url)

        # optional threat intel
        vt_res = check_virustotal(url)
        gs_res = check_google_safe(url)
        if vt_res and isinstance(vt_res, dict) and vt_res.get("error") is None:
            try:
                stats = vt_res.get("data", {}).get("attributes", {}).get("stats") or {}
                malicious_votes = sum([v for k, v in stats.items() if k.lower() in ("malicious", "suspicious")])
                if malicious_votes > 0:
                    heur["risk_level"] = "High"
                    heur["classification"] = "malware"
            except Exception:
                logging.debug("VT parsing error", exc_info=True)
        if gs_res:
            heur["risk_level"] = "High"
            heur["classification"] = "blacklisted"

        # save to DB (includes is_onion/title)
        save_crawl_record(url, links, text, heur["risk_level"], heur["classification"], heur["entities"], is_onion=is_onion, title=title)

        # push alerts for medium/high
        if heur["risk_level"] in ("High", "Medium"):
            alert = {
                "url": url,
                "risk": heur["risk_level"],
                "classification": heur["classification"],
                "time": datetime.utcnow().isoformat() + "Z",
                "is_onion": is_onion
            }
            _alert_queue.append(alert)

        return {
            "status": "ok",
            "url": url,
            "links_count": len(links),
            "risk_level": heur["risk_level"],
            "classification": heur["classification"],
            "entities": heur["entities"],
            "vt": bool(vt_res),
            "google_safe": bool(gs_res),
            "is_onion": is_onion,
            "title": title
        }
    except Exception as e:
        logging.exception("Error crawling %s", url)
        return {"status": "error", "url": url, "error": str(e)}
    finally:
        with _crawl_lock:
            _currently_crawling.discard(url)

# --------------------
# Tor health endpoint
# --------------------
@app.route("/check_tor", methods=["GET"])
def check_tor():
    return {"tor_proxy": TOR_PROXIES, "status": "connected" if TOR_PROXIES else "not running"}, 200

# --------------------
# Endpoints: crawl single (form/json), batch, and lists
# --------------------
@app.route('/crawl', methods=['POST'])
def crawl():
    data = {}
    if request.is_json:
        data = request.get_json()
        url_raw = data.get('url')
    else:
        url_raw = request.form.get('url') or request.values.get('url')

    if not url_raw:
        return jsonify({"error": "No URL provided"}), 400

    url = normalize_url(url_raw)
    if not url:
        return jsonify({"error": "Invalid URL"}), 400

    if url_already_crawled(url):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT risk_level, classification, entities, last_analyzed FROM crawled_data WHERE url = ? LIMIT 1", (url,))
        row = cursor.fetchone()
        conn.close()
        if row:
            risk, classification, entities_json, last = row
            return jsonify({"status": "cached", "url": url, "risk_level": risk,
                            "classification": classification,
                            "entities": json.loads(entities_json) if entities_json else {},
                            "last_analyzed": last})

    result = analyze_and_save(url)
    if result.get("status") == "error":
        return jsonify(result), 500
    return jsonify(result)

@app.route('/crawl_batch', methods=['POST'])
def crawl_batch():
    if not request.is_json:
        return jsonify({"error": "send JSON with 'urls' list"}), 400
    data = request.get_json()
    urls = data.get('urls') or []
    if not isinstance(urls, list) or not urls:
        return jsonify({"error": "send 'urls' as a non-empty list"}), 400

    results = {}
    for u in urls:
        norm = normalize_url(u)
        if not norm:
            results[u] = {"status": "error", "error": "invalid url"}
            continue
        if norm in results:
            continue
        if url_already_crawled(norm):
            results[norm] = {"status": "cached"}
            continue
        results[norm] = analyze_and_save(norm)
    return jsonify(results)

@app.route('/crawled_urls', methods=['GET'])
def crawled_urls():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT url, COUNT(link) AS links_count, MAX(last_analyzed) AS last_analyzed
        FROM crawled_data
        GROUP BY url
        ORDER BY last_analyzed DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    data = []
    for url, links_count, last in rows:
        data.append({"url": url, "links_count": links_count, "last_analyzed": last})
    return jsonify({"crawled_urls": data})

@app.route('/currently_crawling')
def currently_crawling():
    with _crawl_lock:
        return jsonify({"currently_crawling": list(_currently_crawling)})

# --------------------
# SSE / Events for real-time alerts
# --------------------
@app.route('/events')
def events():
    def event_stream():
        last_index = 0
        while True:
            if len(_alert_queue) > last_index:
                for alert in _alert_queue[last_index:]:
                    yield f"data: {json.dumps(alert)}\n\n"
                last_index = len(_alert_queue)
            time.sleep(1)
    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")

# --------------------
# Results & Search UI endpoints
# --------------------
@app.route('/')
def dashboard():
    results = fetch_results()
    # render_template expected to exist in templates/dashboard.html
    return render_template('dashboard.html', results=results)

@app.route('/results_json')
def results_json():
    results = fetch_results()
    return jsonify(results)

@app.route('/search', methods=['GET'])
def search():
    q = request.args.get('q', '').strip()
    if not q:
        results = fetch_results()
        return render_template('dashboard.html', results=results)

    if looks_like_url(q):
        norm = normalize_url(q)
        if not norm:
            return jsonify({"error": "invalid URL in query"}), 400
        if not url_already_crawled(norm):
            res = analyze_and_save(norm)
            if res.get("status") == "error":
                return jsonify(res), 500
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        # include optional columns safely
        cols = _get_table_columns()
        select = "SELECT url, link, risk_level, classification, entities, last_analyzed"
        select += ", is_onion" if "is_onion" in cols else ", 0"
        select += ", title" if "title" in cols else ", ''"
        select += " FROM crawled_data WHERE url = ?"
        cursor.execute(select, (norm,))
        rows = cursor.fetchall()
        conn.close()
        results = {}
        for url, link, risk, classification, entities_json, last, is_onion, title in rows:
            if url not in results:
                results[url] = {"risk_level": risk, "classification": classification,
                                "entities": json.loads(entities_json) if entities_json else {},
                                "last_analyzed": last, "is_onion": bool(is_onion), "title": title or "", "links": []}
            results[url]["links"].append(link)
        return render_template('dashboard.html', results=results)

    # otherwise normal substring search in links
    results = search_results_db(q.lower())
    return render_template('dashboard.html', results=results)

# --------------------
# Graph endpoint
# --------------------
@app.route('/graph')
def graph():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT url, link FROM crawled_data")
    rows = cursor.fetchall()
    conn.close()
    nodes = {}
    edges = []
    for url, link in rows:
        nodes[url] = nodes.get(url, {"id": url})
        nodes[link] = nodes.get(link, {"id": link})
        edges.append({"source": url, "target": link})
    return jsonify({"nodes": list(nodes.values()), "edges": edges})

# --------------------
# Run
# --------------------
if __name__ == '__main__':
    # ensure db + columns exist
    if not os.path.exists(DB_NAME):
        init_db()
    else:
        # attempt to add missing columns if needed
        try:
            init_db()
        except Exception as e:
            logging.exception("DB init/migration error: %s", e)
    app.run(debug=True, threaded=True)
