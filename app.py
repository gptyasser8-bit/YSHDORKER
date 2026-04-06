from flask import Flask, request, jsonify, render_template, Response, send_file
import requests, threading, time, os, re
from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

session = requests.Session()
adapter = HTTPAdapter(pool_connections=20, pool_maxsize=20)
session.mount("https://", adapter)
session.mount("http://", adapter)

executor = ThreadPoolExecutor(max_workers=5)

SERVER_FILE_PATH = "results.txt"

task = {
    "running": False,
    "logs": [],
    "results": [],
    "file": None,
    "display_name": "results.txt",
    "found": 0
}

EXTENSIONS = [
"env","json","yaml","yml",
"ini","conf","txt","log",
"sql","xml","config","properties",
"pem","key","crt","p12","py"
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
    if len(task["logs"]) > 400:
        task["logs"].pop(0)

def scan_secrets(text):
    findings=[]
    for p in SECRET_PATTERNS:
        findings.extend(re.findall(p,text,re.IGNORECASE))
    return findings

def process_item(it, keyword):
    if not task["running"]: return

    url=it["html_url"]
    if any(x in url.lower() for x in IGNORE_WORDS): return

    raw=url.replace("github.com","raw.githubusercontent.com").replace("/blob","")

    try:
        log(f"Checking {url}")
        txt=session.get(raw,timeout=6).text
        secrets=scan_secrets(txt)

        if secrets:
            task["found"] += 1

            task["results"].append({
                "url": url,
                "secrets": secrets
            })

            with open(task["file"],"a",encoding="utf-8") as f:
                f.write(f"KEYWORD: {keyword}\n")
                f.write(f"FILE: {url}\n")
                f.write(f"RAW: {raw}\n")
                for s in secrets:
                    f.write(f"SECRET: {s}\n")
                f.write("\n----------------------\n\n")

            log(f"🔥 FOUND {url}")

    except:
        pass

def grab(keyword,year,exts):
    headers={"Authorization":f"token {GITHUB_TOKEN}"}
    keywords=[k.strip() for k in keyword.split(';')]
    seen=set()

    for k in keywords:
        for ext in exts:
            page=1
            log(f"Search {k} .{ext}")

            while task["running"]:
                try:
                    r=session.get(
                        "https://api.github.com/search/code",
                        headers=headers,
                        params={
                            "q":f"{k} extension:{ext}",
                            "sort":"indexed",
                            "order":"desc",
                            "page":page,
                            "per_page":100
                        },
                        timeout=15
                    )

                    if r.status_code==403:
                        log("Rate limit... waiting")
                        time.sleep(10)
                        continue

                    if r.status_code!=200:
                        log(f"API ERROR {r.status_code}")
                        break

                    items=r.json().get("items",[])
                    if not items: break

                    executor.map(lambda it: process_item(it,k), items)

                    page+=1
                    time.sleep(2)

                except:
                    break

    task["running"]=False
    log("Finished ✅")

@app.route("/")
def index():
    return render_template("index.html", exts=EXTENSIONS)

@app.route("/start", methods=["POST"])
def start():
    data=request.json

    task["running"]=True
    task["logs"]=[]
    task["results"]=[]
    task["found"]=0

    if os.path.exists(SERVER_FILE_PATH):
        os.remove(SERVER_FILE_PATH)

    task["file"]=SERVER_FILE_PATH
    task["display_name"]=data["keyword"].split()[0]+".txt"

    with open(SERVER_FILE_PATH,"w",encoding="utf-8") as f:
        f.write(f"--- Scan started {time.ctime()} ---\n\n")

    t=threading.Thread(target=grab,args=(data["keyword"],data["year"],data["ext"]))
    t.start()

    return jsonify({"ok":1})

@app.route("/stop", methods=["POST"])
def stop():
    task["running"]=False
    return jsonify({"ok":1})

@app.route("/logs")
def logs():
    def stream():
        last=0
        while True:
            if len(task["logs"])>last:
                yield f"data: {task['logs'][last]}\n\n"
                last+=1
            time.sleep(0.3)
    return Response(stream,mimetype="text/event-stream")

@app.route("/results")
def results():
    return jsonify(task)

@app.route("/download")
def download():
    if not os.path.exists(SERVER_FILE_PATH):
        return "No file"

    return send_file(SERVER_FILE_PATH,as_attachment=True,download_name=task["display_name"])

if __name__=="__main__":
    app.run(host="0.0.0.0",port=10000)
