#!/usr/bin/env python3
"""Smart Household Financial Management System. Python 3.8+ only, no installs.
Run: python app.py   then open http://localhost:8000
Data lives in household.db (SQLite) next to this file."""
import sqlite3, json, os, secrets, hashlib, csv, io, re, sys
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from datetime import date

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "household.db")
PORT = int(os.environ.get("PORT", 8000))
HOST = os.environ.get("HOST", "127.0.0.1")  # set HOST=0.0.0.0 to share on your network

SCHEMA = """
CREATE TABLE IF NOT EXISTS households(id INTEGER PRIMARY KEY, name TEXT NOT NULL, code TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, household_id INTEGER NOT NULL REFERENCES households(id),
  name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, pw TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id));
CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY, household_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
  type TEXT NOT NULL CHECK(type IN('income','expense')), amount REAL NOT NULL CHECK(amount>0),
  category TEXT NOT NULL, note TEXT DEFAULT '', date TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS tx_idx ON transactions(household_id, date);
CREATE TABLE IF NOT EXISTS budgets(id INTEGER PRIMARY KEY, household_id INTEGER NOT NULL, category TEXT NOT NULL,
  month TEXT NOT NULL, limit_amt REAL NOT NULL CHECK(limit_amt>0), UNIQUE(household_id, category, month));
CREATE TABLE IF NOT EXISTS goals(id INTEGER PRIMARY KEY, household_id INTEGER NOT NULL, name TEXT NOT NULL,
  target REAL NOT NULL CHECK(target>0), saved REAL NOT NULL DEFAULT 0, deadline TEXT DEFAULT '');
"""

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()

class Err(Exception):
    def __init__(self, msg, code=400): self.msg, self.code = msg, code

def num(v, name):
    try: v = float(v)
    except (TypeError, ValueError): raise Err(f"{name} must be a number")
    if v <= 0: raise Err(f"{name} must be greater than zero")
    return round(v, 2)

def valid_date(s):
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", s or ""): raise Err("Date must look like 2026-01-31")
    return s

def valid_month(s):
    if not re.fullmatch(r"\d{4}-\d{2}", s or ""): raise Err("Month must look like 2026-01")
    return s

def rows(c, sql, *a): return [dict(r) for r in c.execute(sql, a).fetchall()]

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def user(self, c):
        m = re.search(r"sid=([\w-]+)", self.headers.get("Cookie", ""))
        if not m: return None
        return c.execute("SELECT u.*, h.name hname, h.code hcode FROM sessions s JOIN users u ON u.id=s.user_id "
                         "JOIN households h ON h.id=u.household_id WHERE s.token=?", (m.group(1),)).fetchone()

    def send(self, code, body, ctype="application/json", headers=()):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers: self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def handle_any(self, method):
        path, _, qs = self.path.partition("?")
        q = dict(p.split("=", 1) for p in qs.split("&") if "=" in p)
        if method == "GET" and not path.startswith("/api/"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                return self.send(200, f.read(), "text/html; charset=utf-8")
        body = {}
        if method == "POST":
            n = int(self.headers.get("Content-Length", 0))
            try: body = json.loads(self.rfile.read(n) or b"{}")
            except ValueError: return self.send(400, {"error": "Invalid request"})
        c = db()
        try:
            res = self.route(c, method, path, q, body)
            c.commit()
            if isinstance(res, tuple): return self.send(*res)
            self.send(200, res)
        except Err as e:
            self.send(e.code, {"error": e.msg})
        except sqlite3.IntegrityError:
            self.send(400, {"error": "That entry already exists or is invalid"})
        except Exception as e:
            print("Error:", e, file=sys.stderr)
            self.send(500, {"error": "Something went wrong on the server"})
        finally:
            c.close()

    def do_GET(self): self.handle_any("GET")
    def do_POST(self): self.handle_any("POST")

    def route(self, c, method, path, q, b):
        if path == "/api/register" and method == "POST":
            name, email, pw = (b.get(k, "").strip() for k in ("name", "email", "password"))
            if not name or "@" not in email or len(pw) < 6:
                raise Err("Enter your name, a valid email and a password of at least 6 characters")
            code = b.get("join_code", "").strip().upper()
            if code:
                h = c.execute("SELECT id FROM households WHERE code=?", (code,)).fetchone()
                if not h: raise Err("No household found with that join code")
                hid = h["id"]
            else:
                hn = b.get("household_name", "").strip() or f"{name}'s household"
                hid = c.execute("INSERT INTO households(name,code) VALUES(?,?)",
                                (hn, secrets.token_hex(3).upper())).lastrowid
            salt = secrets.token_hex(8)
            try:
                uid = c.execute("INSERT INTO users(household_id,name,email,salt,pw) VALUES(?,?,?,?,?)",
                                (hid, name, email.lower(), salt, hash_pw(pw, salt))).lastrowid
            except sqlite3.IntegrityError:
                raise Err("An account with that email already exists")
            return self.login_cookie(c, uid)
        if path == "/api/login" and method == "POST":
            u = c.execute("SELECT * FROM users WHERE email=?", (b.get("email", "").strip().lower(),)).fetchone()
            if not u or not secrets.compare_digest(u["pw"], hash_pw(b.get("password", ""), u["salt"])):
                raise Err("Email or password is incorrect", 401)
            return self.login_cookie(c, u["id"])
        u = self.user(c)
        if path == "/api/me": 
            if not u: raise Err("Not signed in", 401)
            return {"name": u["name"], "household": u["hname"], "join_code": u["hcode"]}
        if not u: raise Err("Please sign in", 401)
        hid = u["household_id"]
        if path == "/api/logout":
            c.execute("DELETE FROM sessions WHERE user_id=?", (u["id"],))
            return (200, {"ok": True}, "application/json", [("Set-Cookie", "sid=; Max-Age=0; Path=/")])

        if path == "/api/transactions" and method == "GET":
            sql, a = ("SELECT t.*, u.name member FROM transactions t JOIN users u ON u.id=t.user_id "
                      "WHERE t.household_id=?"), [hid]
            if q.get("month"): sql += " AND substr(t.date,1,7)=?"; a.append(valid_month(q["month"]))
            return rows(c, sql + " ORDER BY t.date DESC, t.id DESC LIMIT 500", *a)
        if path == "/api/transactions" and method == "POST":
            t = b.get("type")
            if t not in ("income", "expense"): raise Err("Choose income or expense")
            cat = b.get("category", "").strip()
            if not cat: raise Err("Choose or type a category")
            c.execute("INSERT INTO transactions(household_id,user_id,type,amount,category,note,date) VALUES(?,?,?,?,?,?,?)",
                      (hid, u["id"], t, num(b.get("amount"), "Amount"), cat, b.get("note", "").strip()[:200],
                       valid_date(b.get("date"))))
            return {"ok": True}
        m = re.fullmatch(r"/api/(transactions|budgets|goals)/(\d+)/delete", path)
        if m and method == "POST":
            c.execute(f"DELETE FROM {m.group(1)} WHERE id=? AND household_id=?", (m.group(2), hid))
            return {"ok": True}

        if path == "/api/summary":
            mo = valid_month(q.get("month") or date.today().strftime("%Y-%m"))
            s = rows(c, "SELECT type, COALESCE(SUM(amount),0) total FROM transactions WHERE household_id=? "
                        "AND substr(date,1,7)=? GROUP BY type", hid, mo)
            tot = {r["type"]: r["total"] for r in s}
            cats = rows(c, "SELECT category, SUM(amount) total FROM transactions WHERE household_id=? AND type='expense' "
                           "AND substr(date,1,7)=? GROUP BY category ORDER BY total DESC", hid, mo)
            spent = {r["category"].lower(): r["total"] for r in cats}
            bud = rows(c, "SELECT * FROM budgets WHERE household_id=? AND month=? ORDER BY category", hid, mo)
            for r in bud: r["spent"] = spent.get(r["category"].lower(), 0)
            trend = rows(c, "SELECT substr(date,1,7) month, "
                            "SUM(CASE WHEN type='income' THEN amount ELSE 0 END) income, "
                            "SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) expense "
                            "FROM transactions WHERE household_id=? GROUP BY 1 ORDER BY 1 DESC LIMIT 6", hid)[::-1]
            return {"month": mo, "income": tot.get("income", 0), "expense": tot.get("expense", 0),
                    "categories": cats, "budgets": bud, "trend": trend}

        if path == "/api/budgets" and method == "POST":
            cat = (b.get("category") or "").strip()
            if not cat: raise Err("Enter a category")
            c.execute("INSERT INTO budgets(household_id,category,month,limit_amt) VALUES(?,?,?,?) "
                      "ON CONFLICT(household_id,category,month) DO UPDATE SET limit_amt=excluded.limit_amt",
                      (hid, cat, valid_month(b.get("month")), num(b.get("limit"), "Budget limit")))
            return {"ok": True}

        if path == "/api/goals" and method == "GET":
            return rows(c, "SELECT * FROM goals WHERE household_id=? ORDER BY id DESC", hid)
        if path == "/api/goals" and method == "POST":
            if not (b.get("name") or "").strip(): raise Err("Give the goal a name")
            c.execute("INSERT INTO goals(household_id,name,target,deadline) VALUES(?,?,?,?)",
                      (hid, b["name"].strip(), num(b.get("target"), "Target"), b.get("deadline", "")))
            return {"ok": True}
        m = re.fullmatch(r"/api/goals/(\d+)/add", path)
        if m and method == "POST":
            c.execute("UPDATE goals SET saved=saved+? WHERE id=? AND household_id=?",
                      (num(b.get("amount"), "Amount"), m.group(1), hid))
            return {"ok": True}

        if path == "/api/export.csv":
            out = io.StringIO(); w = csv.writer(out)
            w.writerow(["date", "type", "category", "amount", "note", "member"])
            for r in rows(c, "SELECT t.*, u.name member FROM transactions t JOIN users u ON u.id=t.user_id "
                             "WHERE t.household_id=? ORDER BY date", hid):
                w.writerow([r["date"], r["type"], r["category"], r["amount"], r["note"], r["member"]])
            return (200, out.getvalue().encode(), "text/csv",
                    [("Content-Disposition", "attachment; filename=transactions.csv")])
        raise Err("Not found", 404)

    def login_cookie(self, c, uid):
        tok = secrets.token_urlsafe(32)
        c.execute("INSERT INTO sessions VALUES(?,?)", (tok, uid))
        return (200, {"ok": True}, "application/json",
                [("Set-Cookie", f"sid={tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000")])

if __name__ == "__main__":
    with db() as c: c.executescript(SCHEMA)
    print(f"Household finance running at http://{'localhost' if HOST == '127.0.0.1' else HOST}:{PORT}  (Ctrl+C to stop)")
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
