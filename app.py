from flask import Flask, request, jsonify, render_template, Response, send_file
import requests, threading, time, os, re, json
from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

session = requests.Session()
adapter = HTTPAdapter(pool_connections=50, pool_maxsize=50)
session.mount("https://", adapter)

executor = ThreadPoolExecutor(max_workers=5)

task = {
    "running": False,
    "logs": [],
    "results": [],
    "file_txt": None,
    "file_json": None,
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

def log(msg):
    task["logs"].append(msg)
    if len(task["logs"]) > 500:
        task["logs"].pop(0)

def scan_secrets(text):
    results=[]
    for p in SECRET_PATTERNS:
        results.extend(re.findall(p,text,re.IGNORECASE))
    return list(set(results))

def process_item(it, keyword):
    if not task["running"]:
        return

    url = it["html_url"]

    if any(x in url.lower() for x in IGNORE_WORDS):
        return

    raw = url.replace("github.com","raw.githubusercontent.com").replace("/blob","")

    try:
        log(f"Checking {url}")

        txt = session.get(raw, timeout=6).text
        secrets = scan_secrets(txt)

        if secrets:
            task["found"] += 1

            result = {
                "url": url,
                "secrets": secrets
            }

            task["results"].append(result)

            with open(task["file_txt"], "a", encoding="utf-8") as f:
                f.write(f"{url}\n")
                for s in secrets:
                    f.write(f"{s}\n")
                f.write("\n")

            with open(task["file_json"], "w", encoding="utf-8") as f:
                json.dump(task["results"], f, indent=2)

            log(f"SECRET FOUND {url}")

    except:
        pass

def grab(keyword, exts):
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}"
    }

    seen = set()

    keywords = [k.strip() for k in keyword.split(";") if k.strip()]

    for k in keywords:
        for ext in exts:
            query = f"{k} extension:{ext}"
            log(f"Search {query}")

            page = 1

            while task["running"]:
                try:
                    r = session.get(
                        "https://api.github.com/search/code",
                        headers=headers,
                        params={
                            "q": query,
                            "sort": "indexed",
                            "order": "desc",
                            "page": page,
                            "per_page": 100
                        },
                        timeout=15
                    )

                    if r.status_code == 403:
                        log("Rate limit... waiting")
                        time.sleep(10)
                        continue

                    if r.status_code != 200:
                        log(f"API ERROR {r.status_code}")
                        break

                    items = r.json().get("items", [])
                    if not items:
                        break

                    def scan_item(it):
                        url = it["html_url"]
                        if url in seen:
                            return
                        seen.add(url)
                        process_item(it, k)

                    executor.map(scan_item, items)

                    page += 1
                    time.sleep(2)

                except:
                    break

    task["running"] = False
    log("Finished ✅")

@app.route("/")
def index():
    return render_template("index.html", exts=EXTENSIONS)

@app.route("/start", methods=["POST"])
def start():
    data = request.json

    task["running"] = True
    task["logs"] = []
    task["results"] = []
    task["found"] = 0

    keyword = data["keyword"]
    exts = data["ext"] if data["ext"] else ["env"]

    name = keyword.replace(";","_")
    task["file_txt"] = f"{name}.txt"
    task["file_json"] = f"{name}.json"

    open(task["file_txt"], "w").close()

    t = threading.Thread(target=grab, args=(keyword, exts))
    t.start()

    return jsonify({"ok":1})

@app.route("/stop", methods=["POST"])
def stop():
    task["running"] = False
    return jsonify({"ok":1})

@app.route("/logs")
def logs():
    def stream():
        i=0
        while True:
            if len(task["logs"])>i:
                yield f"data: {task['logs'][i]}\n\n"
                i+=1
            time.sleep(0.2)
    return Response(stream(), mimetype="text/event-stream")

@app.route("/download")
def download():
    t = request.args.get("type","txt")
    if t=="json":
        return send_file(task["file_json"], as_attachment=True)
    return send_file(task["file_txt"], as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
