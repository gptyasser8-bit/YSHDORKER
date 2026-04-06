from flask import Flask, request, jsonify, render_template, Response, send_file
import requests, threading, time, os, re, json
from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

# ===== TOKENS =====
# ضع عدة توكنات مفصولة بفاصلة داخل Environment Variable:
# GITHUB_TOKEN=tok1,tok2,tok3
TOKENS = [t.strip() for t in (os.getenv("GITHUB_TOKEN") or "").split(",") if t.strip()]
token_index = 0

def get_token():
    global token_index
    if not TOKENS:
        return None
    t = TOKENS[token_index]
    token_index = (token_index + 1) % len(TOKENS)
    return t

# ===== SESSION (HIGH PERFORMANCE) =====
session = requests.Session()
adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100)
session.mount("https://", adapter)
session.mount("http://", adapter)

# Threads
executor = ThreadPoolExecutor(max_workers=25)

task = {
    "running": False,
    "logs": [],
    "results": [],
    "file_txt": None,
    "file_json": None,
    "display_name": "results",
    "found": 0,
    "start_time": None
}

EXTENSIONS = [
"env","json","yaml","yml","ini","conf","txt","log",
"sql","xml","config","properties","pem","key","crt","p12","py"
]

IGNORE_WORDS = [
"example","sample","dummy","test","demo","replace","changeme",
"placeholder","fake","tutorial","template","null","none",
"docs","documentation","mock","sandbox"
]

SECRET_PATTERNS = [
    r'AKIA[0-9A-Z]{16}',
    r'aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{20,}',
    r'AIza[0-9A-Za-z-_]{35}',
    r'AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}',
    r'dop_v1_[a-z0-9]{64}',
    r'cloudinary://[0-9]{15}:[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+',
    r'stripe_[a-zA-Z0-9]{24,}',
    r'sk_live_[0-9a-zA-Z]{24}',
    r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    r'ghp_[a-zA-Z0-9]{36}',
    r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}',
    r'[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}',
    r'key-[0-9a-zA-Z]{32}',
    r'AC[a-z0-9]{32}',
    r'mongodb(?:\+srv)?:\/\/[^\s]+',
    r'mysql://[^\s]+',
    r'postgres(?:ql)?:\/\/[^\s]+',
    r'ftp:\/\/[^\s]+',
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}[:|][^\s]+',
    r'(?i)api[-]?key\s*[:=]\s*["\']?[A-Za-z0-9-]{16,}',
    r'(?i)token\s*[:=]\s*["\']?[A-Za-z0-9-_]{16,}',
    r'(?i)secret\s*[:=]\s*["\']?[A-Za-z0-9-_]{16,}',
    r'(?i)password\s*[:=]\s*["\']?[A-Za-z0-9-_!@#$%^&*]{4,}',
    r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    r'0x[a-fA-F0-9]{40}'
]

# ===== UTILS =====
def log(msg):
    task["logs"].append(msg)
    if len(task["logs"]) > 800:
        task["logs"].pop(0)

def scan(text):
    out = []
    for p in SECRET_PATTERNS:
        out += re.findall(p, text, re.I)
    return list(set(out))

def process_item(it, keyword):
    if not task["running"]:
        return

    url = it["html_url"]
    if any(x in url.lower() for x in IGNORE_WORDS):
        return

    raw = url.replace("github.com","raw.githubusercontent.com").replace("/blob","")

    try:
        txt = session.get(raw, timeout=6).text
        secrets = scan(txt)

        if secrets:
            task["found"] += 1

            result = {
                "keyword": keyword,
                "url": url,
                "raw": raw,
                "secrets": secrets
            }

            task["results"].append(result)

            # TXT
            with open(task["file_txt"], "a", encoding="utf-8") as f:
                f.write(f"KEYWORD: {keyword}\nFILE: {url}\nRAW: {raw}\n")
                for s in secrets:
                    f.write(f"SECRET: {s}\n")
                f.write("\n----------------------\n\n")

            log(f"🔥 FOUND {url}")

    except:
        pass

def scan_query(keyword, ext):
    seen = set()
    page = 1

    while task["running"]:
        try:
            token = get_token()
            headers = {"Authorization": f"token {token}"} if token else {}

            r = session.get(
                "https://api.github.com/search/code",
                headers=headers,
                params={
                    "q": f"{keyword} extension:{ext}",
                    "sort": "indexed",
                    "order": "desc",
                    "page": page,
                    "per_page": 100
                },
                timeout=15
            )

            if r.status_code == 403:
                log("⚠️ RATE LIMIT - rotating token...")
                time.sleep(2)
                continue

            if r.status_code != 200:
                log(f"API ERROR {r.status_code}")
                break

            items = r.json().get("items", [])
            if not items:
                break

            new_items = [i for i in items if i["html_url"] not in seen]
            for i in new_items:
                seen.add(i["html_url"])

            list(executor.map(lambda it: process_item(it, keyword), new_items))

            page += 1
            time.sleep(0.3)

        except:
            break

def grab(keywords, exts):
    threads = []

    for k in keywords:
        for ext in exts:
            t = threading.Thread(target=scan_query, args=(k, ext))
            t.start()
            threads.append(t)

    for t in threads:
        t.join()

    # save JSON
    with open(task["file_json"], "w", encoding="utf-8") as f:
        json.dump(task["results"], f, indent=2)

    task["running"] = False
    log("✅ DONE")

# ===== ROUTES =====
@app.route("/")
def index():
    return render_template("index.html", exts=EXTENSIONS)

@app.route("/start", methods=["POST"])
def start():
    d = request.json

    task["running"] = True
    task["logs"] = []
    task["results"] = []
    task["found"] = 0
    task["start_time"] = time.time()

    name = d["keyword"].replace(";","_").replace(" ","_")
    task["display_name"] = name

    task["file_txt"] = f"{name}.txt"
    task["file_json"] = f"{name}.json"

    open(task["file_txt"], "w").close()

    keywords = [k.strip() for k in d["keyword"].split(";") if k.strip()]
    exts = d["ext"]

    t = threading.Thread(target=grab, args=(keywords, exts))
    t.start()

    return jsonify({"ok":1})

@app.route("/stop", methods=["POST"])
def stop():
    task["running"] = False
    return jsonify({"ok":1})

@app.route("/logs")
def logs():
    def stream():
        i = 0
        while True:
            if len(task["logs"]) > i:
                yield f"data: {task['logs'][i]}\n\n"
                i += 1
            time.sleep(0.1)
    return Response(stream(), mimetype="text/event-stream")

@app.route("/results")
def results():
    elapsed = max(time.time() - (task["start_time"] or time.time()), 1)
    speed = round(task["found"] / elapsed, 2)
    return jsonify({
        "results": task["results"],
        "found": task["found"],
        "speed": speed
    })

@app.route("/download")
def download():
    t = request.args.get("type","txt")
    if t == "json":
        return send_file(task["file_json"], as_attachment=True)
    return send_file(task["file_txt"], as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
