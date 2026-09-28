"""SecureDMS - minimal prototype backend (FastAPI + SQLite + local file storage)."""
import hashlib, json, os, re, secrets, sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE = Path(__file__).parent
UPLOADS = BASE / "uploads"; UPLOADS.mkdir(exist_ok=True)
DB = BASE / "dms.db"
SECRET = os.getenv("SECRET_KEY", "dev-secret-change-me")   # env var in real deployments
ALLOWED_EXT = {".pdf", ".txt", ".md", ".docx", ".png", ".jpg"}
MAX_BYTES = 10 * 1024 * 1024

# ---- RBAC: role -> permissions + document types it may upload (None = any) ----
ROLES = {
    "case_officer":     {"perms": {"view", "upload", "manage", "verify", "audit"}, "types": None},
    "investigator":     {"perms": {"view", "upload"}, "types": None},
    "forensic_officer": {"perms": {"view", "upload", "verify"}, "types": ["Forensic Report", "Evidence Report"]},
    "legal_officer":    {"perms": {"view", "upload"}, "types": ["Legal Notice", "Court Filing"]},
    "auditor":          {"perms": {"view", "audit", "verify"}, "types": []},
    "admin":            {"perms": {"view", "upload", "manage", "verify", "audit"}, "types": None},  # global oversight
}

# ---------------------------------------------------------------- database
def q(sql, args=(), one=False):
    con = sqlite3.connect(DB); con.row_factory = sqlite3.Row
    cur = con.execute(sql, args); rows = [dict(r) for r in cur.fetchall()]
    con.commit(); lid = cur.lastrowid; con.close()
    if sql.lstrip().upper().startswith("INSERT"): return lid
    return (rows[0] if rows else None) if one else rows

def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex()

def check_pw(pw, stored):
    return secrets.compare_digest(hash_pw(pw, stored.split("$")[0]), stored)

def init_db():
    for stmt in [
        "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name, email UNIQUE, pw, role, department)",
        "CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, case_number UNIQUE, title, description, status DEFAULT 'OPEN', created_by, created_at)",
        "CREATE TABLE IF NOT EXISTS case_depts(case_id, department)",
        "CREATE TABLE IF NOT EXISTS documents(id INTEGER PRIMARY KEY, case_id, name, doc_type, version, sha256, path, uploader_id, department, created_at)",
        "CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id, action, case_id, doc_id, detail, ts, prev_hash, hash)",
    ]: q(stmt)
    if not q("SELECT 1 FROM users LIMIT 1"):
        for n, e, r, d in [("Insp. Sharma", "officer@police.gov", "case_officer", "Police"),
                           ("Dr. Rao", "forensic@lab.gov", "forensic_officer", "Forensics"),
                           ("Adv. Mehta", "legal@legal.gov", "legal_officer", "Legal"),
                           ("Auditor Iyer", "auditor@audit.gov", "auditor", "Audit"),
                           ("Sysadmin", "admin@it.gov", "admin", "IT")]:
            q("INSERT INTO users(name,email,pw,role,department) VALUES(?,?,?,?,?)", (n, e, hash_pw("demo123"), r, d))
init_db()

# ---------------------------------------------------------------- audit (hash-chained)
def _chain_hash(prev, uid, action, cid, did, detail, ts):
    return hashlib.sha256(json.dumps([prev, uid, action, cid, did, detail, ts]).encode()).hexdigest()

def audit(user, action, case_id=None, doc_id=None, detail=""):
    last = q("SELECT hash FROM audit ORDER BY id DESC LIMIT 1", one=True)
    prev = last["hash"] if last else "GENESIS"
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    uid = user["id"] if user else None
    q("INSERT INTO audit(user_id,action,case_id,doc_id,detail,ts,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?)",
      (uid, action, case_id, doc_id, detail, ts, prev, _chain_hash(prev, uid, action, case_id, doc_id, detail, ts)))

def chain_valid():
    prev = "GENESIS"
    for r in q("SELECT * FROM audit ORDER BY id"):
        if r["prev_hash"] != prev or r["hash"] != _chain_hash(prev, r["user_id"], r["action"], r["case_id"], r["doc_id"], r["detail"], r["ts"]):
            return False
        prev = r["hash"]
    return True

# ---------------------------------------------------------------- auth + access control
bearer = HTTPBearer()
def current_user(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        uid = int(jwt.decode(cred.credentials, SECRET, algorithms=["HS256"])["sub"])
    except Exception:
        raise HTTPException(401, "Invalid or expired token")
    u = q("SELECT * FROM users WHERE id=?", (uid,), one=True)
    if not u: raise HTTPException(401, "Unknown user")
    return u

def get_case(user, cid, perm):
    """Role check AND case-level check (department must be assigned to the case)."""
    c = q("SELECT * FROM cases WHERE id=?", (cid,), one=True)
    if not c: raise HTTPException(404, "Case not found")
    c["departments"] = [r["department"] for r in q("SELECT department FROM case_depts WHERE case_id=?", (cid,))]
    if user["role"] != "admin" and user["department"] not in c["departments"]:
        raise HTTPException(403, "Your department is not assigned to this case")
    if perm not in ROLES[user["role"]]["perms"]:
        raise HTTPException(403, f"Role '{user['role']}' does not have '{perm}' permission")
    return c

def get_doc(user, did, perm):
    d = q("SELECT * FROM documents WHERE id=?", (did,), one=True)
    if not d: raise HTTPException(404, "Document not found")
    get_case(user, d["case_id"], perm)
    return d

def public(d):
    return {k: v for k, v in d.items() if k != "path"}

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
    return h.hexdigest()

def latest_docs(cid):
    out = {}
    for d in q("SELECT d.*, u.name AS uploader FROM documents d JOIN users u ON u.id=d.uploader_id WHERE case_id=? ORDER BY version", (cid,)):
        out[d["name"]] = d
    return list(out.values())

def text_of(d):
    if d["name"].lower().endswith((".txt", ".md")):
        return Path(d["path"]).read_text("utf-8", errors="ignore")[:200_000]
    return ""

# ---------------------------------------------------------------- app
app = FastAPI(title="SecureDMS Prototype")

class Login(BaseModel):
    email: str
    password: str

class CaseIn(BaseModel):
    case_number: str
    title: str
    description: str = ""
    departments: list[str]

def user_payload(u):
    r = ROLES[u["role"]]
    return {"id": u["id"], "name": u["name"], "role": u["role"], "department": u["department"],
            "perms": sorted(r["perms"]), "types": r["types"]}

@app.get("/api/v1/me")
def me(user=Depends(current_user)):
    return user_payload(user)

@app.post("/api/v1/auth/login")
def login(body: Login):
    u = q("SELECT * FROM users WHERE email=?", (body.email,), one=True)
    if not u or not check_pw(body.password, u["pw"]):
        raise HTTPException(401, "Invalid email or password")
    token = jwt.encode({"sub": str(u["id"]), "exp": datetime.now(timezone.utc) + timedelta(hours=8)}, SECRET, "HS256")
    audit(u, "LOGIN")
    return {"token": token, "user": user_payload(u)}

@app.post("/api/v1/cases")
def create_case(body: CaseIn, user=Depends(current_user)):
    if "manage" not in ROLES[user["role"]]["perms"]:
        raise HTTPException(403, "Only a Case Officer can create cases")
    if q("SELECT 1 FROM cases WHERE case_number=?", (body.case_number,)):
        raise HTTPException(409, "Case number already exists")
    cid = q("INSERT INTO cases(case_number,title,description,created_by,created_at) VALUES(?,?,?,?,?)",
            (body.case_number, body.title, body.description, user["id"], datetime.now(timezone.utc).isoformat(timespec="seconds")))
    for d in set(body.departments) | {user["department"]}:
        q("INSERT INTO case_depts VALUES(?,?)", (cid, d))
    audit(user, "CREATE_CASE", cid, detail=f"{body.case_number}: {', '.join(sorted(set(body.departments)))}")
    return {"id": cid}

@app.get("/api/v1/cases")
def list_cases(user=Depends(current_user)):
    if user["role"] == "admin":
        rows = q("SELECT * FROM cases ORDER BY id DESC")
    else:
        rows = q("SELECT c.* FROM cases c JOIN case_depts d ON d.case_id=c.id WHERE d.department=? ORDER BY c.id DESC", (user["department"],))
    for c in rows:
        c["departments"] = [r["department"] for r in q("SELECT department FROM case_depts WHERE case_id=?", (c["id"],))]
    return rows

async def save_version(user, cid, name, doc_type, file):
    if Path(file.filename).suffix.lower() not in ALLOWED_EXT:
        raise HTTPException(400, f"File type not allowed. Allowed: {', '.join(sorted(ALLOWED_EXT))}")
    data = await file.read()
    if not data or len(data) > MAX_BYTES:
        raise HTTPException(400, "File is empty or larger than 10 MB")
    path = UPLOADS / secrets.token_hex(12)          # storage path is never exposed to clients
    path.write_bytes(data)
    version = (q("SELECT MAX(version) m FROM documents WHERE case_id=? AND name=?", (cid, name), one=True)["m"] or 0) + 1
    did = q("INSERT INTO documents(case_id,name,doc_type,version,sha256,path,uploader_id,department,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (cid, name, doc_type, version, hashlib.sha256(data).hexdigest(), str(path), user["id"], user["department"],
             datetime.now(timezone.utc).isoformat(timespec="seconds")))
    audit(user, "UPLOAD_DOCUMENT" if version == 1 else "CREATE_DOCUMENT_VERSION", cid, did, f"{name} v{version}")
    return {"id": did, "version": version}

def check_type(user, doc_type):
    allowed = ROLES[user["role"]]["types"]
    if allowed is not None and doc_type not in allowed:
        raise HTTPException(403, f"Your role may only upload: {', '.join(allowed) or 'nothing'}")

@app.post("/api/v1/cases/{cid}/documents")
async def upload(cid: int, doc_type: str = Form(...), file: UploadFile = File(...), user=Depends(current_user)):
    get_case(user, cid, "upload")
    check_type(user, doc_type)
    return await save_version(user, cid, Path(file.filename).name, doc_type, file)

@app.post("/api/v1/documents/{did}/versions")
async def update_document(did: int, file: UploadFile = File(...), user=Depends(current_user)):
    """Update an existing document: stores a NEW version under the same name; old versions are kept."""
    d = get_doc(user, did, "upload")
    check_type(user, d["doc_type"])
    if Path(file.filename).suffix.lower() != Path(d["name"]).suffix.lower():
        raise HTTPException(400, f"Updated file must be a {Path(d['name']).suffix} file")
    return await save_version(user, d["case_id"], d["name"], d["doc_type"], file)

@app.get("/api/v1/cases/{cid}/documents")
def list_docs(cid: int, user=Depends(current_user)):
    get_case(user, cid, "view")
    docs = latest_docs(cid)
    return [{**public(d), "versions": d["version"]} for d in reversed(docs)]

@app.get("/api/v1/documents/{did}/versions")
def versions(did: int, user=Depends(current_user)):
    d = get_doc(user, did, "view")
    return [public(x) for x in q("SELECT d.*, u.name AS uploader FROM documents d JOIN users u ON u.id=d.uploader_id WHERE case_id=? AND d.name=? ORDER BY version DESC", (d["case_id"], d["name"]))]

@app.get("/api/v1/documents/{did}/download")
def download(did: int, user=Depends(current_user)):
    d = get_doc(user, did, "view")
    audit(user, "DOWNLOAD_DOCUMENT", d["case_id"], did, f"{d['name']} v{d['version']}")
    return FileResponse(d["path"], filename=d["name"])

@app.post("/api/v1/documents/{did}/verify")
def verify(did: int, user=Depends(current_user)):
    d = get_doc(user, did, "verify")
    current = sha256_file(d["path"])
    ok = current == d["sha256"]
    audit(user, "VERIFY_DOCUMENT", d["case_id"], did, f"{d['name']} v{d['version']}: {'VALID' if ok else 'INTEGRITY FAILURE'}")
    return {"status": "VALID" if ok else "INTEGRITY FAILURE", "recorded_hash": d["sha256"], "current_hash": current}

@app.post("/api/v1/documents/{did}/tamper")
def demo_tamper(did: int, user=Depends(current_user)):
    """DEMO ONLY: silently alters the stored file so verification can be shown to fail."""
    d = get_doc(user, did, "manage")
    with open(d["path"], "ab") as f: f.write(b"\n[tampered]")
    audit(user, "DEMO_TAMPER", d["case_id"], did, "Stored file modified out-of-band (demo)")
    return {"ok": True}

@app.get("/api/v1/cases/{cid}/audit")
def case_audit(cid: int, user=Depends(current_user)):
    get_case(user, cid, "audit")
    rows = q("SELECT a.*, u.name AS user_name, u.role FROM audit a LEFT JOIN users u ON u.id=a.user_id WHERE a.case_id=? ORDER BY a.id DESC", (cid,))
    return {"chain_valid": chain_valid(), "events": rows}

@app.get("/api/v1/search")
def search(q_: str = "", user=Depends(current_user)):
    terms = [t for t in re.findall(r"\w+", q_.lower()) if len(t) > 2]
    if not terms: return []
    hits = []
    for c in list_cases(user):
        if "view" not in ROLES[user["role"]]["perms"]: break
        for d in latest_docs(c["id"]):
            body = text_of(d).lower()
            score = sum(body.count(t) + 3 * (t in d["name"].lower() or t in d["doc_type"].lower()) for t in terms)
            if score:
                i = min((body.find(t) for t in terms if t in body), default=-1)
                snippet = ("…" + text_of(d)[max(0, i - 60): i + 120].replace("\n", " ") + "…") if i >= 0 else ""
                hits.append({"case_number": c["case_number"], "case_id": c["id"], "doc_id": d["id"], "name": d["name"],
                             "doc_type": d["doc_type"], "score": score, "snippet": snippet})
    audit(user, "SEARCH", detail=q_)
    return sorted(hits, key=lambda h: -h["score"])[:10]

@app.post("/api/v1/cases/{cid}/summary")
def summary(cid: int, user=Depends(current_user)):
    """Extractive stand-in for the LLM step. Swap in a real model call here later."""
    get_case(user, cid, "view")
    parts, sources = [], []
    for d in latest_docs(cid):
        t = " ".join(text_of(d).split())
        if not t: continue
        parts.append(f"[{d['doc_type']}] " + " ".join(re.split(r"(?<=[.!?])\s+", t)[:2])[:320])
        sources.append(f"{d['name']} (v{d['version']})")
    audit(user, "GENERATE_AI_SUMMARY", cid, detail=f"{len(sources)} sources")
    return {"label": "AI-generated summary (prototype: extractive). Verify against source documents.",
            "summary": parts or ["No readable text documents in this case yet."], "sources": sources}

app.mount("/", StaticFiles(directory=BASE.parent / "frontend", html=True), name="frontend")
