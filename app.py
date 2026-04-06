from flask import Flask, request, jsonify, render_template, Response
import requests, threading, time, os, re

app = Flask(__name__)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

task = {"running": False, "logs": [], "results": []}

IGNORE_WORDS = ["example","test","demo","sample"]

SECRET_PATTERNS = [
    r'AKIA[0-9A-Z]{16}',
    r'AIza[0-9A-Za-z-_]{35}',
    r'sk_live_[0-9a-zA-Z]{24}',
    r'ghp_[a-zA-Z0-9]{36}',
    r'(?i)api[-]?key\s*[:=]\s*["\']?[A-Za-z0-9-]{16,}',
]

def log(msg):
    task["logs"].append(msg)
    if len(task["logs"]) > 200:
        task["logs"].pop(0)

def scan_secrets(text):
    found = []
    for p in SECRET_PATTERNS:
        found += re.findall(p, text)
    return found

def grab(keyword, ext):
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    page = 1

    while task["running"]:
        url = f"https://api.github.com/search/code?q={keyword}+extension:{ext}&page={page}&per_page=50"
        r = requests.get(url, headers=headers)

        if r.status_code != 200:
            log("API ERROR")
            break

        items = r.json().get("items", [])
        if not items:
            break

        for it in items:
            if not task["running"]:
                break

            url_html = it["html_url"]
            if any(x in url_html for x in IGNORE_WORDS):
                continue

            raw = url_html.replace("github.com","raw.githubusercontent.com").replace("/blob","")

            try:
                txt = requests.get(raw).text
                secrets = scan_secrets(txt)

                if secrets:
                    task["results"].append({
                        "url": url_html,
                        "secrets": secrets
                    })
                    log(f"🔥 FOUND: {url_html}")

            except:
                pass

        page += 1
        time.sleep(2)

    task["running"] = False
    log("DONE ✅")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/start", methods=["POST"])
def start():
    data = request.json
    task["running"] = True
    task["logs"] = []
    task["results"] = []

    t = threading.Thread(target=grab, args=(data["keyword"], data["ext"]))
    t.start()

    return jsonify({"ok": True})

@app.route("/stop", methods=["POST"])
def stop():
    task["running"] = False
    return jsonify({"ok": True})

@app.route("/logs")
def logs():
    def stream():
        last = 0
        while True:
            if len(task["logs"]) > last:
                yield f"data: {task['logs'][last]}\n\n"
                last += 1
            time.sleep(0.5)
    return Response(stream(), mimetype="text/event-stream")

@app.route("/results")
def results():
    return jsonify(task["results"])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
