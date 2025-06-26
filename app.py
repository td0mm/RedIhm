from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
import os
import xml.etree.ElementTree as ET
import sqlite3
from collections import defaultdict, Counter
from datetime import datetime

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATABASE'] = 'redteam.db'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ---------- DB SETUP ----------
def init_db():
    with sqlite3.connect(app.config['DATABASE']) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                ip TEXT PRIMARY KEY,
                tags TEXT,
                checklist TEXT,
                notes TEXT,
                priority TEXT
            )
        ''')
        # ports : clé primaire composite => (ip, port, protocol)
        c.execute('''
            CREATE TABLE IF NOT EXISTS ports (
                ip TEXT,
                port INTEGER,
                protocol TEXT,
                PRIMARY KEY (ip, port, protocol)
            )
        ''')
        # si la table existait déjà sans PK, crée un index unique
        c.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS idx_ip_port_proto
            ON ports(ip, port, protocol)
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                timestamp TEXT,
                action TEXT
            )
        ''')
        conn.commit()

init_db()

# ---------- HELPERS ----------
def parse_masscan(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    data = defaultdict(list)

    for host in root.findall('host'):
        ip = host.find('address').attrib['addr']
        for port in host.find('ports').findall('port'):
            port_id = int(port.attrib['portid'])
            protocol = port.attrib['protocol']
            data[ip].append((port_id, protocol))
    return data

def insert_scan_results(data):
    with sqlite3.connect(app.config['DATABASE']) as conn:
        c = conn.cursor()
        for ip, ports in data.items():
            c.execute(
                "INSERT OR IGNORE INTO hosts (ip, tags, checklist, notes, priority) "
                "VALUES (?, '', '', '', '')",
                (ip,)
            )
            for port, proto in ports:
                # empêche le doublon grâce au PRIMARY KEY + INSERT OR IGNORE
                c.execute(
                    "INSERT OR IGNORE INTO ports (ip, port, protocol) VALUES (?, ?, ?)",
                    (ip, port, proto)
                )
        conn.commit()

# ---------- ROUTES ----------
@app.route('/', methods=['GET', 'POST'])
def main():
    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename:
                filename = secure_filename(file.filename)
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(path)
                insert_scan_results(parse_masscan(path))
                return redirect(url_for('main'))

        elif 'ip' in request.form:
            ip = request.form['ip']
            tags = request.form.get('tags', '')
            checklist = request.form.get('checklist', '')
            notes = request.form.get('notes', '')
            priority = request.form.get('priority', '')
            action = request.form.get('action', '').strip()

            with sqlite3.connect(app.config['DATABASE']) as conn:
                c = conn.cursor()
                c.execute(
                    "UPDATE hosts SET tags=?, checklist=?, notes=?, priority=? WHERE ip=?",
                    (tags, checklist, notes, priority, ip)
                )
                if action:
                    c.execute(
                        "INSERT INTO actions (ip, timestamp, action) VALUES (?, ?, ?)",
                        (ip, datetime.now().isoformat(timespec='seconds'), action)
                    )
                conn.commit()
            return redirect(url_for('main'))

    # ---- filtres ----
    search   = request.args.get('search', '')
    tag_f    = request.args.get('tag', '')
    prio_f   = request.args.get('priority', '')

    with sqlite3.connect(app.config['DATABASE']) as conn:
        c = conn.cursor()

        q = "SELECT * FROM hosts"
        cond, p = [], []

        if search:
            cond.append("(ip LIKE ? OR notes LIKE ?)")
            p.extend([f'%{search}%', f'%{search}%'])
        if tag_f:
            cond.append("tags LIKE ?")
            p.append(f'%{tag_f}%')
        if prio_f:
            cond.append("priority = ?")
            p.append(prio_f)
        if cond:
            q += " WHERE " + " AND ".join(cond)

        c.execute(q, p)
        hosts = c.fetchall()

        # ports et actions
        ports_data = defaultdict(list)
        for ip, port, proto in c.execute("SELECT ip, port, protocol FROM ports"):
            ports_data[ip].append((port, proto))

        actions_data = defaultdict(list)
        for ip, ts, act in c.execute("SELECT ip, timestamp, action FROM actions ORDER BY timestamp DESC"):
            actions_data[ip].append((ts, act))

    # stats
    tags_sum, prio_cnt, port_cnt = defaultdict(int), defaultdict(int), Counter()
    for ip, tags, *_ , prio in hosts:
        for t in tags.split(',') if tags else []:
            tags_sum[t.strip()] += 1
        if prio:
            prio_cnt[prio] += 1
        for port, _ in ports_data[ip]:
            port_cnt[port] += 1

    return render_template(
        'main.html',
        hosts=hosts,
        ports_data=ports_data,
        actions_data=actions_data,
        tags_summary=tags_sum,
        priority_counts=prio_cnt,
        port_stats=dict(port_cnt.most_common(10)),
        search=search,
        tag_filter=tag_f,
        priority_filter=prio_f
    )

# ---------- STATIC ----------
@app.context_processor
def inject_bootstrap():
    return dict(bootstrap_css='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css')

# ---------- RUN ----------
if __name__ == '__main__':
    app.run(debug=True)
