from flask import request, jsonify, render_template_string, send_file, Response
import requests
import threading
import time
import os
import re
from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor

TOOL_NAME = "GitHub Dorker"
TOOL_ICON = "fa-brands fa-github"

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

session = requests.Session()

# تم تقليل الرقم قليلاً لضمان استقرار السبيس وعدم التعليق
adapter = HTTPAdapter(pool_connections=20, pool_maxsize=20)
session.mount("https://", adapter)
session.mount("http://", adapter)

executor = ThreadPoolExecutor(max_workers=5)

# --- التعديل: مسار ثابت للملف لمنع ضياعه أثناء البحث ---
SERVER_FILE_PATH = os.path.join(os.getcwd(), "github_scan_results.txt")

task = {
    "running": False,
    "logs": [],
    "file": None,
    "display_name": "results.txt" # لحفظ الاسم الذي يريده المستخدم
}

EXTENSIONS = [
"env","json","yaml","yml",
"ini","conf","txt","log",
"sql","xml","config","properties",
"pem","key","crt","p12","py","csv"
]

IGNORE_WORDS = [
    "example", "sample", "dummy", "test", "demo", "replace", "changeme",
    "placeholder", "fake", "tutorial", "template", "null", "none",
    "docs", "documentation", "test-case", "mock", "sandbox"
]

SECRET_PATTERNS = [
    # --- Cloud & Infra (الأصلية + الجديدة) ---
    r'AKIA[0-9A-Z]{16}', # AWS Access Key
    r'aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{20,}', # AWS Secret
    r'AIza[0-9A-Za-z-_]{35}', # Google API Key
    r'AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}', # Firebase (FCM)
    r'dop_v1_[a-z0-9]{64}', # DigitalOcean Token
    r'cloudinary://[0-9]{15}:[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+', # Cloudinary
    
    # --- Payment & Social (الأصلية + الجديدة) ---
    r'stripe_[a-zA-Z0-9]{24,}', # Stripe Generic
    r'sk_live_[0-9a-zA-Z]{24}', # Stripe Secret Key
    r'xox[baprs]-[0-9a-zA-Z]{10,48}', # Slack Token
    r'ghp_[a-zA-Z0-9]{36}', # GitHub PAT
    r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', # GitHub PAT (New)
    r'[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}', # Discord Bot Token
    r'key-[0-9a-zA-Z]{32}', # Mailgun API Key
    r'AC[a-z0-9]{32}', # Twilio SID
    
    # --- Databases & Connections ---
    r'mongodb(?:\+srv)?:\/\/[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', # MongoDB
    r'mysql://[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9.-]+', # MySQL
    r'postgres(?:ql)?:\/\/[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+', # Postgres
    r'ftp:\/\/[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+', # FTP Credentials
    
    # --- Accounts & Emails (صيد الحسابات والباسوردات) ---
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}[:|][a-zA-Z0-9._!@#$%^&*?-]{4,}', # email:password format
    r'(?i)(?:user(?:name)?|login|email|admin)\s*[:=]\s*["\']?[A-Za-z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}["\']?', # Admin/User Email assignment
    
    # --- Generic & Sensitive (تطوير للأصلية) ---
    r'(?i)api[-]?key\s*[:=]\s*["\']?[A-Za-z0-9-]{16,}["\']?', 
    r'(?i)token\s*[:=]\s*["\']?[A-Za-z0-9-_]{16,}["\']?',
    r'(?i)secret\s*[:=]\s*["\']?[A-Za-z0-9-_]{16,}["\']?',
    r'(?i)(?:pass(?:word)?|pwd|secret)\s*[:=]\s*["\']?[A-Za-z0-9-_!@#$%^&*]{4,}["\']?', # Password/Key assignment
    r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', # Private Keys
    r'0x[a-fA-F0-9]{40}' # Crypto Wallet
]

HTML = """
<!DOCTYPE html>
<html dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{background:#0a0f1c;color:white;font-family:Arial;padding:20px;}
.card{background:#1e293b;padding:20px;border-radius:10px;margin-bottom:15px;}
input{width:100%;padding:10px;margin-bottom:10px;background:#0f172a;border:1px solid #334155;border-radius:6px;color:#38bdf8;}
button{padding:10px 20px;border:none;border-radius:6px;margin:5px;cursor:pointer;font-weight:bold;}
.start{background:#10b981;color:white;}
.stop{background:#ef4444;color:white;}
.down{background:#38bdf8;color:black;}
#console{background:black;height:420px;overflow:auto;padding:10px;font-family:monospace;font-size:13px;border-radius:10px;}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin-bottom:10px;}
.ext{background:#0f172a;padding:6px;border-radius:6px;text-align:center;}
</style>
</head>
<body>

<div class="card">

<label>Keywords</label>
<input id="keyword" value="aws_access_key stripe_secret">

<label>Since</label>
<input id="year" value="2024">

<label>Extensions</label>

<div class="grid">
""" + "".join([f"""
<label class="ext">
<input type="checkbox" value="{e}" class="extbox"> {e}
</label>
""" for e in EXTENSIONS]) + """
</div>

<button onclick="selectAll()">Select All</button>
<button onclick="clearAll()">Clear</button>

<br><br>

<button class="start" onclick="start()">START</button>
<button class="stop" onclick="stop()">STOP</button>
<button class="down" onclick="download()">Download</button>

</div>

<div id="console"></div>

<script>

let source=null

function log(t){
let c=document.getElementById("console")
c.innerHTML+=t+"<br>"
c.scrollTop=c.scrollHeight
}

function selectAll(){
document.querySelectorAll(".extbox").forEach(e=>e.checked=true)
}

function clearAll(){
document.querySelectorAll(".extbox").forEach(e=>e.checked=false)
}

function getExt(){
let ex=[]
document.querySelectorAll(".extbox:checked").forEach(e=>{
ex.push(e.value)
})
return ex
}

async function start(){

document.getElementById("console").innerHTML=""

let k=document.getElementById("keyword").value
let y=document.getElementById("year").value
let ex=getExt()

await fetch("?api=1",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({
action:"start",
keyword:k,
year:y,
ext:ex
})
})

if(source){source.close()}
source = new EventSource("?logs=1")

source.onmessage=function(event){
log(event.data)
}

}

async function stop(){

await fetch("?api=1",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({
action:"stop"
})
})

if(source){source.close()}
}

function download(){
window.location="?download=1"
}

</script>
</body>
</html>
"""

def run():
    if request.args.get("download"):
        return download()
    if request.args.get("logs"):
        return stream_logs()
    if request.method == "POST":
        return api()
    if request.args.get("api"):
        return jsonify(task)
    return render_template_string(HTML)

def stream_logs():
    def event_stream():
        last = 0
        while True:
            if len(task["logs"]) > last:
                msg = task["logs"][last]
                yield f"data: {msg}\n\n"
                last += 1
            time.sleep(0.3)
    return Response(event_stream(), mimetype="text/event-stream")

def api():
    data=request.json
    action=data.get("action")

    if action=="start":
        keyword=data["keyword"]
        year=data["year"]
        ext=data["ext"]

        if not ext:
            ext=["env"]

        task["logs"]=[]
        task["running"]=True

        # --- تعديل: تنظيف الملف القديم عند البداية فقط لضمان وجود الملف دائماً ---
        if os.path.exists(SERVER_FILE_PATH):
            os.remove(SERVER_FILE_PATH)

        # حفظ الاسم الذي سيظهر للمستخدم عند التحميل
        task["display_name"] = keyword.split()[0].replace(" ","_") + ".txt"
        task["file"] = SERVER_FILE_PATH

        # إنشاء الملف فوراً
        with open(SERVER_FILE_PATH, "w", encoding="utf-8") as f:
            f.write(f"--- Scan started at {time.ctime()} ---\n\n")

        t=threading.Thread(target=grab,args=(keyword,year,ext))
        t.daemon=True
        t.start()
        return jsonify({"ok":1})

    if action=="stop":
        task["running"]=False
        return jsonify({"stopped":1})

def log(m):
    task["logs"].append(m)
    if len(task["logs"])>400:
        task["logs"].pop(0)

def scan_secrets(text):
    findings=[]
    for pattern in SECRET_PATTERNS:
        matches=re.findall(pattern,text,re.IGNORECASE)
        findings.extend(matches)
    return findings

def grab(keyword,year,exts):
    keywords = [k.strip() for k in keyword.split(';')]
    fname = SERVER_FILE_PATH

    headers={
        "Authorization":f"token {GITHUB_TOKEN}",
        "Accept":"application/vnd.github.v3+json"
    }
    seen=set()

    for k in keywords:
        for ext in exts:
            query=f"{k} extension:{ext}"
            log("Search "+query)
            page=1
            while task["running"]:
                try:
                    # هذا هو الجزء الذي طلبته (تم تحديثه ليجلب الأحدث دائماً)
                    r=session.get(
                        "https://api.github.com/search/code",
                        headers=headers,
                        params={
                            "q":query,
                            "sort":"indexed", # ترتيب حسب الفهرسة
                            "order":"desc",   # من الأحدث للأقدم
                            "page":page,
                            "per_page":100
                        },
                        timeout=15
                    )
                    
                    if r.status_code==403:
                        log("Rate limit reached... waiting 10s")
                        time.sleep(10)
                        continue
                    if r.status_code!=200:
                        log("API error "+str(r.status_code))
                        break
                    
                    items=r.json().get("items",[])
                    if not items:
                        break

                    def scan_item(it):
                        url=it["html_url"]
                        if url in seen: return
                        if any(x in url.lower() for x in IGNORE_WORDS): return
                        raw=url.replace("github.com","raw.githubusercontent.com").replace("/blob","")
                        try:
                            log("Checking "+url)
                            raw_data=session.get(raw,timeout=5).text
                            secrets=scan_secrets(raw_data)
                            if secrets:
                                with open(fname,"a",encoding="utf-8") as f:
                                    f.write(f"KEYWORD: {k}\n")
                                    f.write(f"FILE: {url}\n")
                                    f.write(f"RAW: {raw}\n")
                                    for s in secrets:
                                        f.write(f"SECRET: {s}\n")
                                    f.write("\n--------------------------------\n\n")
                                log("SECRET FOUND "+url)
                        except: pass
                        seen.add(url)

                    executor.map(scan_item, items)
                    page+=1
                    time.sleep(3)
                except: break
    task["running"]=False
    log("Finished ✅")

def download():
    # --- التعديل الأهم: إرسال الملف باسم مخصص دون حذفه من السيرفر ---
    if not os.path.exists(SERVER_FILE_PATH):
        return "File not found - Please start a scan first."

    return send_file(
        SERVER_FILE_PATH, 
        as_attachment=True, 
        download_name=task.get("display_name", "results.txt")
    )
if __name__ == "__main__":
    from flask import Flask
    app = Flask(__name__)

    @app.route("/", methods=["GET","POST"])
    def home():
        return run()

    app.run(host="0.0.0.0", port=10000)
