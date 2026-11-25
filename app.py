import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, session, redirect, flash, g, abort, jsonify, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(16)),
    DB=os.environ.get("DB_PATH", "events.db"),
)
LEADS = {10: "10 minutes", 30: "30 minutes", 60: "1 hour", 1440: "1 day"}
SCHEMA = """
CREATE TABLE IF NOT EXISTS user(user_id INTEGER PRIMARY KEY, name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
  is_admin INTEGER DEFAULT 0, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS event(event_id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES user(user_id), title TEXT NOT NULL,
  description TEXT, event_date TEXT NOT NULL, event_time TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reminder(reminder_id INTEGER PRIMARY KEY,
  event_id INTEGER NOT NULL REFERENCES event(event_id) ON DELETE CASCADE,
  lead INTEGER NOT NULL, reminder_time TEXT NOT NULL,
  notification_status TEXT NOT NULL DEFAULT 'Pending');
"""

def db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DB"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.executescript(SCHEMA)
    return g.db

@app.teardown_appcontext
def close_db(_):
    if "db" in g:
        g.pop("db").close()

PAGE = """<!doctype html><title>Event Reminder</title>
<style>
body{font-family:Arial,sans-serif;margin:0;background:#f3f6fb;color:#1c2733}
nav{background:#1f3a8a;padding:14px 28px;color:#fff}nav a{color:#fff;margin-left:18px}
main{max-width:760px;margin:22px auto;background:#fff;padding:22px 28px;border-radius:8px}
input,select,textarea{display:block;width:100%;box-sizing:border-box;padding:8px;margin:4px 0 12px}
button{background:#1f3a8a;color:#fff;border:0;padding:8px 16px;border-radius:4px;cursor:pointer}
table{width:100%;border-collapse:collapse;margin-bottom:16px}
td,th{border-bottom:1px solid #dde3ee;padding:7px;text-align:left}
td form{display:inline}.msg{background:#fff4d6;padding:10px;border-radius:4px}
.cards{display:flex;gap:12px}.cards div{flex:1;background:#e8eefc;padding:12px;border-radius:6px}
</style>
<nav><b>Event Reminder</b>{% if session.uid %}<a href="/">Dashboard</a><a href="/events">Add Event</a>
{% if session.admin %}<a href="/admin">Admin</a>{% endif %}<a href="/logout">Logout</a>{% endif %}</nav>
<main><div id="alerts"></div>{% for m in get_flashed_messages() %}<p class="msg">{{m}}</p>{% endfor %}
BODY</main>
{% if session.uid %}<script>
async function check(){
  const r = await fetch('/api/check', {method:'POST', headers:{'X-CSRF':'{{session.csrf}}'}});
  for (const m of (await r.json()).alerts){
    const p = document.createElement('p'); p.className='msg';
    p.textContent = '\\u23f0 Reminder: ' + m; document.getElementById('alerts').appendChild(p);
  }
}
check(); setInterval(check, 30000);
</script>{% endif %}"""

def page(body, **kw):
    return render_template_string(PAGE.replace("BODY", body), **kw)

@app.before_request
def csrf_protect():
    session.setdefault("csrf", secrets.token_hex(16))
    if request.method == "POST":
        token = request.form.get("csrf") or request.headers.get("X-CSRF")
        if token != session["csrf"]:
            abort(400)

CSRF = '<input type="hidden" name="csrf" value="{{session.csrf}}">'

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = db().execute("SELECT * FROM user WHERE user_id=? AND active=1",
                            (session.get("uid"),)).fetchone()
        if not user:
            session.clear()
            return redirect("/login")
        g.user = user
        resp = app.make_response(view(*args, **kwargs))
        resp.headers["Cache-Control"] = "no-store"
        return resp
    return wrapped

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        pw = request.form["password"]
        if not name or "@" not in email or len(pw) < 6:
            flash("Enter a name, a valid email and a password of 6+ characters.")
        else:
            try:
                db().execute("INSERT INTO user(name,email,password) VALUES(?,?,?)",
                             (name, email, generate_password_hash(pw)))
                db().commit()
                flash("Account created. Please log in.")
                return redirect("/login")
            except sqlite3.IntegrityError:
                flash("This email is already registered.")
    return page('<h2>Register</h2><form method="post">' + CSRF +
      'Full name<input name="name">Email<input name="email">'
      'Password<input name="password" type="password"><button>Create account</button></form>'
      '<p><a href="/login">Already registered? Log in</a></p>')

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = db().execute("SELECT * FROM user WHERE email=? AND active=1",
                         (request.form["email"].strip().lower(),)).fetchone()
        if u and check_password_hash(u["password"], request.form["password"]):
            session.clear()
            session.update(uid=u["user_id"], admin=u["is_admin"], csrf=secrets.token_hex(16))
            return redirect("/")
        flash("Invalid email or password.")
    return page('<h2>Login</h2><form method="post">' + CSRF +
      'Email<input name="email">Password<input name="password" type="password">'
      '<button>Log in</button></form><p><a href="/register">New user? Register</a></p>')

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

def load_events(uid):
    rows = db().execute("SELECT * FROM event WHERE user_id=? ORDER BY event_date, event_time", (uid,))
    events = [dict(r) for r in rows]                # list: like Java ArrayList
    by_id = {e["event_id"]: e for e in events}      # dict: like Java HashMap
    return events, by_id

@app.route("/")
@login_required
def dashboard():
    events, _ = load_events(g.user["user_id"])
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    upcoming = [e for e in events if f'{e["event_date"]} {e["event_time"]}' > now]
    done = [e for e in events if e not in upcoming]
    q = request.args.get("q", "").strip().lower()
    match = lambda e: q in e["title"].lower() or q == e["event_date"]
    return page("""<h2>Welcome, {{g.user.name}}</h2>
<div class="cards"><div>Total: <b>{{total}}</b></div><div>Upcoming: <b>{{nu}}</b></div>
<div>Completed: <b>{{nd}}</b></div></div>
<form><input name="q" value="{{q}}" placeholder="Search by title or date (YYYY-MM-DD)"><button>Search</button></form>
{% for heading, items in groups %}<h3>{{heading}}</h3><table><tr><th>Title<th>Date<th>Time<th>Actions</tr>
{% for e in items %}<tr><td>{{e.title}}<td>{{e.event_date}}<td>{{e.event_time}}<td>
<a href="/events/{{e.event_id}}">Edit</a> <form method="post" action="/events/{{e.event_id}}/delete"
 onsubmit="return confirm('Delete this event?')">""" + CSRF + """<button>Delete</button></form></tr>
{% else %}<tr><td colspan="4">No events</tr>{% endfor %}</table>{% endfor %}""",
      total=len(events), nu=len(upcoming), nd=len(done), q=q,
      groups=[("Upcoming Events", list(filter(match, upcoming))),
              ("Completed Events", list(filter(match, done)))])

def owned_event(eid):
    _, by_id = load_events(g.user["user_id"])
    if eid not in by_id:
        abort(403)
    return by_id[eid]

@app.route("/events", methods=["GET", "POST"])
@app.route("/events/<int:eid>", methods=["GET", "POST"])
@login_required
def event_form(eid=None):
    event, lead = {}, 30
    if eid:
        event = owned_event(eid)
        lead = db().execute("SELECT lead FROM reminder WHERE event_id=?", (eid,)).fetchone()["lead"]
    if request.method == "POST":
        event = {k: request.form.get(k, "").strip()
                 for k in ("title", "description", "event_date", "event_time")}
        try:
            lead = int(request.form["lead"])
            start = datetime.strptime(f'{event["event_date"]} {event["event_time"]}', "%Y-%m-%d %H:%M")
            if lead not in LEADS:
                raise ValueError
        except ValueError:
            flash("Enter a valid date, time and reminder option.")
        else:
            if not event["title"]:
                flash("Title is required.")
            else:
                values = (event["title"], event["description"], event["event_date"], event["event_time"])
                target = eid
                if eid:
                    db().execute("UPDATE event SET title=?,description=?,event_date=?,event_time=? "
                                 "WHERE event_id=?", values + (eid,))
                    db().execute("DELETE FROM reminder WHERE event_id=?", (eid,))
                else:
                    target = db().execute("INSERT INTO event(title,description,event_date,event_time,user_id) "
                                          "VALUES(?,?,?,?,?)", values + (g.user["user_id"],)).lastrowid
                when = (start - timedelta(minutes=lead)).strftime("%Y-%m-%d %H:%M")
                db().execute("INSERT INTO reminder(event_id,lead,reminder_time) VALUES(?,?,?)",
                             (target, lead, when))
                db().commit()
                flash("Event saved.")
                return redirect("/")
    return page('<h2>{{"Edit" if eid else "Add"}} Event</h2><form method="post">' + CSRF + """
Title<input name="title" value="{{e.title}}">Description<textarea name="description">{{e.description}}</textarea>
Date<input type="date" name="event_date" value="{{e.event_date}}">
Time<input type="time" name="event_time" value="{{e.event_time}}">
Remind me before<select name="lead">{% for k,v in leads.items() %}
<option value="{{k}}" {{'selected' if k==lead}}>{{v}}</option>{% endfor %}</select>
<button>Save</button></form>""", e=event, eid=eid, lead=lead, leads=LEADS)

@app.post("/events/<int:eid>/delete")
@login_required
def delete_event(eid):
    owned_event(eid)
    db().execute("DELETE FROM event WHERE event_id=?", (eid,))
    db().commit()
    flash("Event deleted.")
    return redirect("/")

@app.post("/api/check")
@login_required
def check_reminders():
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    due = db().execute("""SELECT r.reminder_id, e.title, e.event_date, e.event_time
        FROM reminder r JOIN event e USING(event_id)
        WHERE e.user_id=? AND r.notification_status='Pending' AND r.reminder_time<=?""",
        (g.user["user_id"], now)).fetchall()
    for r in due:
        db().execute("UPDATE reminder SET notification_status='Sent' WHERE reminder_id=?", (r["reminder_id"],))
    db().commit()
    return jsonify(alerts=[f'{r["title"]} at {r["event_date"]} {r["event_time"]}' for r in due])

@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    if not g.user["is_admin"]:
        abort(403)
    if request.method == "POST":
        db().execute("UPDATE user SET active=1-active WHERE user_id=? AND is_admin=0",
                     (request.form["user_id"],))
        db().commit()
        return redirect("/admin")
    users = db().execute("SELECT * FROM user").fetchall()
    count = lambda sql: db().execute(sql).fetchone()[0]
    return page("""<h2>Administrator Console</h2><div class="cards">
<div>Users: <b>{{users|length}}</b></div><div>Events: <b>{{ev}}</b></div>
<div>Reminders sent: <b>{{sent}}</b></div><div>Pending: <b>{{pend}}</b></div></div>
<table><tr><th>Name<th>Email<th>Status<th>Action</tr>{% for u in users %}<tr><td>{{u.name}}<td>{{u.email}}
<td>{{'Active' if u.active else 'Inactive'}}<td>{% if not u.is_admin %}<form method="post">""" + CSRF + """
<input type="hidden" name="user_id" value="{{u.user_id}}">
<button>{{'Deactivate' if u.active else 'Activate'}}</button></form>{% endif %}</tr>{% endfor %}</table>""",
      users=users, ev=count("SELECT COUNT(*) FROM event"),
      sent=count("SELECT COUNT(*) FROM reminder WHERE notification_status='Sent'"),
      pend=count("SELECT COUNT(*) FROM reminder WHERE notification_status='Pending'"))

@app.cli.command("make-admin")
def make_admin():
    """Promote a registered account: flask make-admin"""
    db().execute("UPDATE user SET is_admin=1 WHERE email=?", (input("Email: ").strip().lower(),))
    db().commit()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
