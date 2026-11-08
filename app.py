"""
Dental Clinic backend — REAL shared server for the web dashboard and the
Android app. One SQLite database, one REST API, no demo/seed data.

Run:  ./run.sh            (uvicorn on http://0.0.0.0:8000)
Web:  http://localhost:8000/        (doctor dashboard)
API:  http://localhost:8000/api/...  (docs at /docs)
DB:   dental_clinic.db (created EMPTY on first start)

Auth: opaque bearer tokens. Staff log in with username+password.
Patients log in with phone+PIN (PIN is set by the clinic when the
patient is created). First account is created via POST /api/setup,
which only works while the users table is empty.
"""
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from datetime import date, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.environ.get("DENTAL_DB", str(BASE_DIR / "dental_clinic.db"))
SECRET = os.environ.get("DENTAL_SECRET", "change-this-secret-before-vps-deploy")
TOKEN_TTL_SECONDS = 30 * 24 * 3600  # 30 days

app = FastAPI(title="Dental Clinic API", version="2.0.0")

# ---------------------------------------------------------------- database
def connect():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    return c

def init_db():
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL, username TEXT UNIQUE, phone TEXT,
          role TEXT NOT NULL CHECK(role IN ('doctor','owner','reception','patient')),
          password_hash TEXT NOT NULL, patient_id INTEGER,
          created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS tokens(
          token TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
          expires_at INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')),
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS patients(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL, age INTEGER NOT NULL DEFAULT 0,
          phone TEXT NOT NULL UNIQUE, whatsapp TEXT,
          allergy TEXT NOT NULL DEFAULT 'None',
          last_checkup TEXT NOT NULL DEFAULT '',
          notes TEXT NOT NULL DEFAULT '',
          created_by INTEGER, created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS appointments(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
          date TEXT NOT NULL, time TEXT NOT NULL,
          treatment_type TEXT NOT NULL DEFAULT 'Checkup',
          status TEXT NOT NULL DEFAULT 'Booked'
            CHECK(status IN ('Booked','Arrived','Done','Cancelled','Walk-in')),
          created_by INTEGER, created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS treatments(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
          type TEXT NOT NULL, tooth_no TEXT NOT NULL DEFAULT '-',
          total_sittings INTEGER NOT NULL DEFAULT 1,
          done_sittings INTEGER NOT NULL DEFAULT 0,
          total_fee INTEGER NOT NULL DEFAULT 0,
          next_sitting TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'In Progress'
            CHECK(status IN ('In Progress','Complete','Planned')),
          created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS payments(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          treatment_id INTEGER NOT NULL REFERENCES treatments(id) ON DELETE CASCADE,
          amount INTEGER NOT NULL, mode TEXT NOT NULL DEFAULT 'Cash',
          date TEXT NOT NULL, note TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS xrays(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
          tooth_no TEXT NOT NULL DEFAULT '-', label TEXT NOT NULL,
          date TEXT NOT NULL, note TEXT NOT NULL DEFAULT '',
          file_name TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS tooth_status(
          patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
          tooth_no TEXT NOT NULL, status TEXT NOT NULL,
          PRIMARY KEY(patient_id, tooth_no)
        );
        """)

@app.on_event("startup")
def _startup():
    init_db()

# ---------------------------------------------------------------- helpers
def hash_pw(pw: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()
    return f"{salt}${h}"

def check_pw(pw: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$", 1)
        return hmac.compare_digest(
            h, hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex())
    except Exception:
        return False

def row(d: sqlite3.Row):
    return dict(d)

def paid_for(c, treatment_id: int) -> int:
    r = c.execute("SELECT COALESCE(SUM(amount),0) s FROM payments WHERE treatment_id=?",
                  (treatment_id,)).fetchone()
    return int(r["s"])

def treatment_view(c, t: sqlite3.Row):
    d = row(t)
    d["paid"] = paid_for(c, d["id"])
    d["remaining"] = max(0, d["total_fee"] - d["paid"])
    return d

def new_token(c, user_id: int) -> str:
    tok = secrets.token_hex(24)
    exp = int(time.time()) + TOKEN_TTL_SECONDS
    c.execute("INSERT INTO tokens(token,user_id,expires_at) VALUES(?,?,?)", (tok, user_id, exp))
    return tok

def auth_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token — please log in again.")
    tok = authorization[7:]
    with connect() as c:
        r = c.execute(
            "SELECT u.* FROM tokens t JOIN users u ON u.id=t.user_id "
            "WHERE t.token=? AND t.expires_at>?",
            (tok, int(time.time()))).fetchone()
        if not r:
            raise HTTPException(401, "Invalid or expired token — please log in again.")
        return row(r)

def require_staff(*roles):
    def dep(u=Depends(auth_user)):
        if u["role"] == "patient":
            raise HTTPException(403, "Patients cannot do this.")
        if roles and u["role"] not in roles:
            raise HTTPException(403, "Your role cannot do this.")
        return u
    return dep

def scope_patient(u, patient_id: int):
    """Patients may only touch their own record."""
    if u["role"] == "patient" and u.get("patient_id") != patient_id:
        raise HTTPException(403, "You can only see your own record.")

# ---------------------------------------------------------------- models
class SetupIn(BaseModel):
    name: str = Field(min_length=2)
    username: str = Field(min_length=3)
    password: str = Field(min_length=4)

class LoginIn(BaseModel):
    mode: str  # "staff" or "patient"
    username: str = ""
    password: str = ""
    phone: str = ""
    pin: str = ""

class UserIn(BaseModel):
    name: str = Field(min_length=2)
    username: str = Field(min_length=3)
    password: str = Field(min_length=4)
    role: str  # doctor | owner | reception

class PatientIn(BaseModel):
    name: str = Field(min_length=2)
    age: int = 0
    phone: str = Field(min_length=7)
    whatsapp: str = ""
    allergy: str = "None"
    last_checkup: str = ""
    notes: str = ""
    pin: str = ""  # optional: sets the patient's app login PIN

class AppointmentIn(BaseModel):
    patient_id: int
    date: str
    time: str
    treatment_type: str = "Checkup"
    status: str = "Booked"

class TreatmentIn(BaseModel):
    patient_id: int
    type: str
    tooth_no: str = "-"
    total_sittings: int = 1
    total_fee: int = 0
    next_sitting: str = ""

class PaymentIn(BaseModel):
    treatment_id: int
    amount: int = Field(gt=0)
    mode: str = "Cash"
    date: str = ""
    note: str = ""

class XrayIn(BaseModel):
    patient_id: int
    tooth_no: str = "-"
    label: str = Field(min_length=2)
    note: str = ""
    file_name: str = ""

class ToothIn(BaseModel):
    status: str

class StatusIn(BaseModel):
    status: str

class NextSittingIn(BaseModel):
    next_sitting: str

class CheckupIn(BaseModel):
    last_checkup: str

# ---------------------------------------------------------------- health / setup
@app.get("/health")
def health():
    return {"status": "ok", "service": "dental-clinic", "version": "2.0.0"}

@app.get("/api/setup/status")
def setup_status():
    with connect() as c:
        n = c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
    return {"setup_needed": n == 0}

@app.post("/api/setup")
def setup(body: SetupIn):
    with connect() as c:
        n = c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
        if n > 0:
            raise HTTPException(400, "Setup already done — log in with the doctor account.")
        cur = c.execute(
            "INSERT INTO users(name,username,role,password_hash) VALUES(?,?,?,?)",
            (body.name, body.username, "doctor", hash_pw(body.password)))
        uid = cur.lastrowid
        tok = new_token(c, uid)
    return {"token": tok, "user": {"id": uid, "name": body.name, "role": "doctor",
                                   "username": body.username, "patient_id": None}}

# ---------------------------------------------------------------- auth
@app.post("/api/auth/login")
def login(body: LoginIn):
    with connect() as c:
        if body.mode == "patient":
            phone = body.phone.strip()
            u = c.execute("SELECT * FROM users WHERE role='patient' AND phone=?",
                          (phone,)).fetchone()
            if not u or not check_pw(body.pin, u["password_hash"]):
                raise HTTPException(401, "Wrong phone or PIN.")
            u = row(u)
        else:
            u = c.execute("SELECT * FROM users WHERE username=? AND role!='patient'",
                          (body.username.strip(),)).fetchone()
            if not u or not check_pw(body.password, u["password_hash"]):
                raise HTTPException(401, "Wrong username or password.")
            u = row(u)
        tok = new_token(c, u["id"])
    return {"token": tok, "user": {"id": u["id"], "name": u["name"], "role": u["role"],
                                   "username": u.get("username"), "patient_id": u.get("patient_id")}}

@app.get("/api/auth/me")
def me(u=Depends(auth_user)):
    return {"id": u["id"], "name": u["name"], "role": u["role"],
            "username": u.get("username"), "patient_id": u.get("patient_id")}

@app.post("/api/auth/logout")
def logout(authorization: str = Header(None), u=Depends(auth_user)):
    tok = authorization[7:]
    with connect() as c:
        c.execute("DELETE FROM tokens WHERE token=?", (tok,))
    return {"ok": True}

# ---------------------------------------------------------------- staff users
@app.post("/api/users")
def create_user(body: UserIn, u=Depends(require_staff("doctor", "owner"))):
    if body.role not in ("doctor", "owner", "reception"):
        raise HTTPException(400, "Role must be doctor, owner or reception.")
    with connect() as c:
        try:
            cur = c.execute(
                "INSERT INTO users(name,username,role,password_hash) VALUES(?,?,?,?)",
                (body.name, body.username, body.role, hash_pw(body.password)))
        except sqlite3.IntegrityError:
            raise HTTPException(400, "Username already taken.")
        return {"id": cur.lastrowid, "name": body.name, "username": body.username, "role": body.role}

@app.get("/api/users")
def list_users(u=Depends(require_staff("doctor", "owner"))):
    with connect() as c:
        rows = c.execute(
            "SELECT id,name,username,role,patient_id FROM users ORDER BY role,name").fetchall()
    return [row(r) for r in rows]

# ---------------------------------------------------------------- patients
@app.post("/api/patients")
def create_patient(body: PatientIn, u=Depends(require_staff())):
    with connect() as c:
        try:
            cur = c.execute(
                "INSERT INTO patients(name,age,phone,whatsapp,allergy,last_checkup,notes,created_by) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (body.name, body.age, body.phone.strip(), body.whatsapp.strip() or body.phone.strip(),
                 body.allergy, body.last_checkup, body.notes, u["id"]))
        except sqlite3.IntegrityError:
            raise HTTPException(400, "A patient with this phone number already exists.")
        pid = cur.lastrowid
        if body.pin:
            c.execute(
                "INSERT INTO users(name,phone,role,password_hash,patient_id) VALUES(?,?,?, ?,?)",
                (body.name, body.phone.strip(), "patient", hash_pw(body.pin), pid))
        return row(c.execute("SELECT * FROM patients WHERE id=?", (pid,)).fetchone())

@app.get("/api/patients")
def list_patients(search: str = "", u=Depends(auth_user)):
    with connect() as c:
        if u["role"] == "patient":
            r = c.execute("SELECT * FROM patients WHERE id=?", (u["patient_id"],)).fetchone()
            return [row(r)] if r else []
        if search:
            q = f"%{search}%"
            rows = c.execute(
                "SELECT * FROM patients WHERE name LIKE ? OR phone LIKE ? ORDER BY name",
                (q, q)).fetchall()
        else:
            rows = c.execute("SELECT * FROM patients ORDER BY name").fetchall()
    return [row(r) for r in rows]

@app.get("/api/patients/{pid}")
def get_patient(pid: int, u=Depends(auth_user)):
    scope_patient(u, pid)
    with connect() as c:
        r = c.execute("SELECT * FROM patients WHERE id=?", (pid,)).fetchone()
    if not r:
        raise HTTPException(404, "Patient not found.")
    return row(r)

@app.put("/api/patients/{pid}")
def update_patient(pid: int, body: PatientIn, u=Depends(require_staff())):
    with connect() as c:
        if not c.execute("SELECT 1 FROM patients WHERE id=?", (pid,)).fetchone():
            raise HTTPException(404, "Patient not found.")
        try:
            c.execute(
                "UPDATE patients SET name=?,age=?,phone=?,whatsapp=?,allergy=?,last_checkup=?,notes=? WHERE id=?",
                (body.name, body.age, body.phone.strip(), body.whatsapp.strip() or body.phone.strip(),
                 body.allergy, body.last_checkup, body.notes, pid))
        except sqlite3.IntegrityError:
            raise HTTPException(400, "Another patient already uses this phone number.")
        return row(c.execute("SELECT * FROM patients WHERE id=?", (pid,)).fetchone())

@app.delete("/api/patients/{pid}")
def delete_patient(pid: int, u=Depends(require_staff("doctor", "owner"))):
    with connect() as c:
        cur = c.execute("DELETE FROM patients WHERE id=?", (pid,))
        if cur.rowcount == 0:
            raise HTTPException(404, "Patient not found.")
        c.execute("DELETE FROM users WHERE patient_id=?", (pid,))
    return {"ok": True}

@app.post("/api/patients/{pid}/checkup")
def mark_checkup(pid: int, body: CheckupIn, u=Depends(require_staff())):
    with connect() as c:
        cur = c.execute("UPDATE patients SET last_checkup=? WHERE id=?",
                        (body.last_checkup, pid))
        if cur.rowcount == 0:
            raise HTTPException(404, "Patient not found.")
        return row(c.execute("SELECT * FROM patients WHERE id=?", (pid,)).fetchone())

@app.post("/api/patients/{pid}/set-pin")
def set_patient_pin(pid: int, body: dict, u=Depends(require_staff())):
    pin = str(body.get("pin", "")).strip()
    if len(pin) < 4:
        raise HTTPException(400, "PIN must be at least 4 digits.")
    with connect() as c:
        p = c.execute("SELECT * FROM patients WHERE id=?", (pid,)).fetchone()
        if not p:
            raise HTTPException(404, "Patient not found.")
        if c.execute("SELECT 1 FROM users WHERE patient_id=?", (pid,)).fetchone():
            c.execute("UPDATE users SET password_hash=? WHERE patient_id=?",
                      (hash_pw(pin), pid))
        else:
            c.execute(
                "INSERT INTO users(name,phone,role,password_hash,patient_id) VALUES(?,?,?, ?,?)",
                (p["name"], p["phone"], "patient", hash_pw(pin), pid))
    return {"ok": True}

# ---------------------------------------------------------------- appointments
@app.get("/api/appointments")
def list_appointments(date: str = "", patient_id: int = 0, u=Depends(auth_user)):
    if u["role"] == "patient":
        patient_id = u["patient_id"]
    with connect() as c:
        sql, args = "SELECT * FROM appointments WHERE 1=1", []
        if date:
            sql += " AND date=?"; args.append(date)
        if patient_id:
            sql += " AND patient_id=?"; args.append(patient_id)
        sql += " ORDER BY date, time"
        rows = c.execute(sql, args).fetchall()
    return [row(r) for r in rows]

@app.post("/api/appointments")
def create_appointment(body: AppointmentIn, u=Depends(auth_user)):
    scope_patient(u, body.patient_id)
    if body.status not in ("Booked", "Arrived", "Done", "Cancelled", "Walk-in"):
        raise HTTPException(400, "Bad status.")
    with connect() as c:
        if not c.execute("SELECT 1 FROM patients WHERE id=?", (body.patient_id,)).fetchone():
            raise HTTPException(404, "Patient not found.")
        cur = c.execute(
            "INSERT INTO appointments(patient_id,date,time,treatment_type,status,created_by) "
            "VALUES(?,?,?,?,?,?)",
            (body.patient_id, body.date, body.time, body.treatment_type, body.status, u["id"]))
        return row(c.execute("SELECT * FROM appointments WHERE id=?", (cur.lastrowid,)).fetchone())

@app.put("/api/appointments/{aid}")
def update_appointment(aid: int, body: StatusIn, u=Depends(require_staff())):
    if body.status not in ("Booked", "Arrived", "Done", "Cancelled", "Walk-in"):
        raise HTTPException(400, "Bad status.")
    with connect() as c:
        cur = c.execute("UPDATE appointments SET status=? WHERE id=?", (body.status, aid))
        if cur.rowcount == 0:
            raise HTTPException(404, "Appointment not found.")
        return row(c.execute("SELECT * FROM appointments WHERE id=?", (aid,)).fetchone())

@app.delete("/api/appointments/{aid}")
def delete_appointment(aid: int, u=Depends(require_staff())):
    with connect() as c:
        cur = c.execute("DELETE FROM appointments WHERE id=?", (aid,))
        if cur.rowcount == 0:
            raise HTTPException(404, "Appointment not found.")
    return {"ok": True}

# ---------------------------------------------------------------- treatments
@app.get("/api/treatments")
def list_treatments(patient_id: int = 0, status: str = "", u=Depends(auth_user)):
    if u["role"] == "patient":
        patient_id = u["patient_id"]
    with connect() as c:
        sql, args = "SELECT * FROM treatments WHERE 1=1", []
        if patient_id:
            sql += " AND patient_id=?"; args.append(patient_id)
        if status:
            sql += " AND status=?"; args.append(status)
        sql += " ORDER BY id"
        return [treatment_view(c, r) for r in c.execute(sql, args).fetchall()]

@app.post("/api/treatments")
def create_treatment(body: TreatmentIn, u=Depends(require_staff("doctor", "owner"))):
    with connect() as c:
        if not c.execute("SELECT 1 FROM patients WHERE id=?", (body.patient_id,)).fetchone():
            raise HTTPException(404, "Patient not found.")
        cur = c.execute(
            "INSERT INTO treatments(patient_id,type,tooth_no,total_sittings,total_fee,next_sitting) "
            "VALUES(?,?,?,?,?,?)",
            (body.patient_id, body.type, body.tooth_no, max(1, body.total_sittings),
             body.total_fee, body.next_sitting))
        return treatment_view(c, c.execute("SELECT * FROM treatments WHERE id=?",
                                           (cur.lastrowid,)).fetchone())

@app.post("/api/treatments/{tid}/complete-sitting")
def complete_sitting(tid: int, u=Depends(require_staff("doctor", "owner", "reception"))):
    with connect() as c:
        t = c.execute("SELECT * FROM treatments WHERE id=?", (tid,)).fetchone()
        if not t:
            raise HTTPException(404, "Treatment not found.")
        done = min(t["done_sittings"] + 1, t["total_sittings"])
        status = "Complete" if done >= t["total_sittings"] else "In Progress"
        nxt = "" if status == "Complete" else t["next_sitting"]
        c.execute("UPDATE treatments SET done_sittings=?, status=?, next_sitting=? WHERE id=?",
                  (done, status, nxt, tid))
        return treatment_view(c, c.execute("SELECT * FROM treatments WHERE id=?", (tid,)).fetchone())

@app.put("/api/treatments/{tid}/next-sitting")
def set_next_sitting(tid: int, body: NextSittingIn, u=Depends(require_staff())):
    with connect() as c:
        cur = c.execute("UPDATE treatments SET next_sitting=? WHERE id=?",
                        (body.next_sitting, tid))
        if cur.rowcount == 0:
            raise HTTPException(404, "Treatment not found.")
        return treatment_view(c, c.execute("SELECT * FROM treatments WHERE id=?", (tid,)).fetchone())

# ---------------------------------------------------------------- payments
@app.get("/api/payments")
def list_payments(treatment_id: int = 0, date: str = "", u=Depends(auth_user)):
    with connect() as c:
        sql, args = ("SELECT p.* FROM payments p JOIN treatments t ON t.id=p.treatment_id "
                     "WHERE 1=1"), []
        if u["role"] == "patient":
            sql += " AND t.patient_id=?"; args.append(u["patient_id"])
        if treatment_id:
            sql += " AND p.treatment_id=?"; args.append(treatment_id)
        if date:
            sql += " AND p.date=?"; args.append(date)
        sql += " ORDER BY p.date DESC, p.id DESC"
        return [row(r) for r in c.execute(sql, args).fetchall()]

@app.post("/api/payments")
def create_payment(body: PaymentIn, u=Depends(require_staff())):
    if not body.date:
        body.date = date.today().isoformat()
    with connect() as c:
        t = c.execute("SELECT * FROM treatments WHERE id=?", (body.treatment_id,)).fetchone()
        if not t:
            raise HTTPException(404, "Treatment not found.")
        cur = c.execute(
            "INSERT INTO payments(treatment_id,amount,mode,date,note) VALUES(?,?,?,?,?)",
            (body.treatment_id, body.amount, body.mode, body.date, body.note))
        return row(c.execute("SELECT * FROM payments WHERE id=?", (cur.lastrowid,)).fetchone())

# ---------------------------------------------------------------- xrays / teeth
@app.get("/api/xrays")
def list_xrays(patient_id: int = 0, u=Depends(auth_user)):
    if u["role"] == "patient":
        patient_id = u["patient_id"]
    with connect() as c:
        sql, args = "SELECT * FROM xrays WHERE 1=1", []
        if patient_id:
            sql += " AND patient_id=?"; args.append(patient_id)
        sql += " ORDER BY date DESC, id DESC"
        return [row(r) for r in c.execute(sql, args).fetchall()]

@app.post("/api/xrays")
def create_xray(body: XrayIn, u=Depends(require_staff())):
    with connect() as c:
        if not c.execute("SELECT 1 FROM patients WHERE id=?", (body.patient_id,)).fetchone():
            raise HTTPException(404, "Patient not found.")
        cur = c.execute(
            "INSERT INTO xrays(patient_id,tooth_no,label,date,note,file_name) VALUES(?,?,?,?,?,?)",
            (body.patient_id, body.tooth_no, body.label, date.today().isoformat(),
             body.note, body.file_name))
        return row(c.execute("SELECT * FROM xrays WHERE id=?", (cur.lastrowid,)).fetchone())

@app.get("/api/patients/{pid}/teeth")
def get_teeth(pid: int, u=Depends(auth_user)):
    scope_patient(u, pid)
    with connect() as c:
        rows = c.execute("SELECT tooth_no, status FROM tooth_status WHERE patient_id=?",
                         (pid,)).fetchall()
    return {r["tooth_no"]: r["status"] for r in rows}

@app.put("/api/patients/{pid}/teeth/{tooth}")
def set_tooth(pid: int, tooth: str, body: ToothIn, u=Depends(require_staff("doctor", "owner"))):
    with connect() as c:
        c.execute(
            "INSERT INTO tooth_status(patient_id,tooth_no,status) VALUES(?,?,?) "
            "ON CONFLICT(patient_id,tooth_no) DO UPDATE SET status=excluded.status",
            (pid, tooth, body.status))
    return {"patient_id": pid, "tooth_no": tooth, "status": body.status}

# ---------------------------------------------------------------- patient self-view
@app.get("/api/me/overview")
def my_overview(u=Depends(auth_user)):
    if u["role"] != "patient":
        raise HTTPException(400, "Only patients use this view.")
    pid = u["patient_id"]
    with connect() as c:
        p = c.execute("SELECT * FROM patients WHERE id=?", (pid,)).fetchone()
        ts = [treatment_view(c, r) for r in c.execute(
            "SELECT * FROM treatments WHERE patient_id=? ORDER BY id", (pid,)).fetchall()]
        appts = [row(r) for r in c.execute(
            "SELECT * FROM appointments WHERE patient_id=? ORDER BY date,time", (pid,)).fetchall()]
        xs = [row(r) for r in c.execute(
            "SELECT * FROM xrays WHERE patient_id=? ORDER BY date DESC", (pid,)).fetchall()]
    return {"patient": row(p) if p else None, "treatments": ts,
            "appointments": appts, "xrays": xs}

# ---------------------------------------------------------------- reports
@app.get("/api/reports/dashboard")
def dashboard(u=Depends(require_staff())):
    today = date.today().isoformat()
    cutoff = (date.today() - timedelta(days=180)).isoformat()
    with connect() as c:
        d = {
            "today_appointments": c.execute(
                "SELECT COUNT(*) n FROM appointments WHERE date=?", (today,)).fetchone()["n"],
            "incomplete_treatments": c.execute(
                "SELECT COUNT(*) n FROM treatments WHERE status='In Progress'").fetchone()["n"],
            "checkup_due": c.execute(
                "SELECT COUNT(*) n FROM patients WHERE last_checkup<>'' AND last_checkup<=?",
                (cutoff,)).fetchone()["n"],
            "total_patients": c.execute("SELECT COUNT(*) n FROM patients").fetchone()["n"],
            "today_income": c.execute(
                "SELECT COALESCE(SUM(amount),0) s FROM payments WHERE date=?", (today,)).fetchone()["s"],
            "pending_total": 0,
        }
        pending = 0
        for t in c.execute("SELECT id,total_fee FROM treatments").fetchall():
            pending += max(0, t["total_fee"] - paid_for(c, t["id"]))
        d["pending_total"] = pending
    return d

@app.get("/api/reports/income")
def income_report(date_: str = "", days: int = 7, u=Depends(require_staff())):
    d = date_ or date.today().isoformat()
    with connect() as c:
        total = c.execute("SELECT COALESCE(SUM(amount),0) s FROM payments WHERE date=?",
                          (d,)).fetchone()["s"]
        by_mode = {r["mode"]: r["s"] for r in c.execute(
            "SELECT mode, COALESCE(SUM(amount),0) s FROM payments WHERE date=? GROUP BY mode",
            (d,)).fetchall()}
        week = []
        for i in range(days - 1, -1, -1):
            dd = (date.today() - timedelta(days=i)).isoformat()
            week.append({"date": dd, "amount": c.execute(
                "SELECT COALESCE(SUM(amount),0) s FROM payments WHERE date=?", (dd,)).fetchone()["s"]})
        pending = 0
        for t in c.execute("SELECT id,total_fee FROM treatments").fetchall():
            pending += max(0, t["total_fee"] - paid_for(c, t["id"]))
    return {"date": d, "total": total, "by_mode": by_mode, "last_days": week,
            "pending_total": pending}

@app.get("/api/reports/incomplete")
def incomplete_report(u=Depends(auth_user)):
    with connect() as c:
        sql = ("SELECT t.*, p.name AS patient_name, p.phone AS patient_phone FROM treatments t "
               "JOIN patients p ON p.id=t.patient_id WHERE t.status='In Progress' ORDER BY t.next_sitting")
        args = []
        if u["role"] == "patient":
            sql = sql.replace("WHERE t.status", "WHERE t.patient_id=? AND t.status")
            args = [u["patient_id"]]
        return [treatment_view(c, r) | {"patient_name": r["patient_name"],
                                        "patient_phone": r["patient_phone"]}
                for r in c.execute(sql, args).fetchall()]

@app.get("/api/reports/checkup-due")
def checkup_due_report(u=Depends(require_staff())):
    cutoff = (date.today() - timedelta(days=180)).isoformat()
    with connect() as c:
        rows = c.execute(
            "SELECT * FROM patients WHERE last_checkup<>'' AND last_checkup<=? ORDER BY last_checkup",
            (cutoff,)).fetchall()
    out = []
    for r in rows:
        d = row(r)
        d["days_since"] = (date.today() - date.fromisoformat(r["last_checkup"])).days
        out.append(d)
    return out

@app.get("/api/reports/pending-payments")
def pending_report(u=Depends(require_staff())):
    with connect() as c:
        out = []
        for t in c.execute(
                "SELECT t.*, p.name AS patient_name, p.phone AS patient_phone FROM treatments t "
                "JOIN patients p ON p.id=t.patient_id ORDER BY t.id").fetchall():
            tv = treatment_view(c, t)
            if tv["remaining"] > 0:
                tv["patient_name"] = t["patient_name"]
                tv["patient_phone"] = t["patient_phone"]
                out.append(tv)
        out.sort(key=lambda x: -x["remaining"])
    return out

# ---------------------------------------------------------------- web dashboard (static, served last)
WEB_DIR = BASE_DIR / "web"
if WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
else:
    @app.get("/")
    def root():
        return {"service": "dental-clinic", "web": "web/ folder not found"}
