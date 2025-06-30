from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
import os, sqlite3, xml.etree.ElementTree as ET
from collections import defaultdict, Counter
from datetime import datetime

app = Flask(__name__)
app.config.update(
    UPLOAD_FOLDER='uploads',
    DATABASE='redteam.db',
    LOGFILE='timeline.log'
)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ---------- DB SETUP ----------
def init_db():
    with sqlite3.connect(app.config['DATABASE']) as c:
        cur = c.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS hosts (
            ip TEXT PRIMARY KEY,
            tags TEXT, checklist TEXT, notes TEXT, priority TEXT)''')

        cur.execute('''CREATE TABLE IF NOT EXISTS ports (
            ip TEXT, port INTEGER, protocol TEXT,
            PRIMARY KEY (ip,port,protocol))''')

        cur.execute('''CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT, timestamp TEXT, action TEXT,
            type TEXT DEFAULT 'info',
            status TEXT DEFAULT '')''')
        c.commit()
init_db()

# ---------- HELPERS ----------
def parse_masscan(xml_path):
    tree = ET.parse(xml_path)
    data = defaultdict(list)
    for host in tree.iterfind('host'):
        ip = host.find('address').attrib['addr']
        for p in host.find('ports').findall('port'):
            data[ip].append((int(p.attrib['portid']), p.attrib['protocol']))
    return data

def insert_scan_results(results):
    with sqlite3.connect(app.config['DATABASE']) as c:
        cur = c.cursor()
        for ip, ports in results.items():
            cur.execute("INSERT OR IGNORE INTO hosts (ip,tags,checklist,notes,priority) VALUES(?, '', '', '', '')", (ip,))
            for port, proto in ports:
                cur.execute("INSERT OR IGNORE INTO ports(ip,port,protocol) VALUES(?,?,?)", (ip, port, proto))
        c.commit()

def log_action(ip, text, a_type='info', status='', conn=None, skip_db=False):
    ts = datetime.now().isoformat(timespec='seconds')
    if not skip_db:
        if conn:
            conn.execute("INSERT INTO actions(ip,timestamp,action,type,status) VALUES(?,?,?,?,?)", (ip, ts, text, a_type, status))
        else:
            with sqlite3.connect(app.config['DATABASE']) as c:
                c.execute("INSERT INTO actions(ip,timestamp,action,type,status) VALUES(?,?,?,?,?)", (ip, ts, text, a_type, status))
                c.commit()
    with open(app.config['LOGFILE'], 'a') as f:
        f.write(f"[{ts}] {ip}|{a_type}|{status}|{text}\n")

# ---------- ROUTES ----------
@app.route('/', methods=['GET', 'POST'])
def main():
    if request.method == 'POST':
        if 'file' in request.files:
            f = request.files['file']
            if f and f.filename:
                path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f.filename))
                f.save(path)
                insert_scan_results(parse_masscan(path))
                log_action('SYSTEM', f'Fichier Masscan importé : {f.filename}', 'info')
                return redirect(url_for('main'))

        ip = request.form.get('ip')
        if ip:
            tags = request.form.get('tags','')
            checklist = request.form.get('checklist','')
            notes = request.form.get('notes','')
            prio = request.form.get('priority','')
            a_text = request.form.get('action','').strip()
            a_type = request.form.get('action_type','info')
            a_status = request.form.get('action_status','')
            with sqlite3.connect(app.config['DATABASE']) as conn:
                conn.execute("UPDATE hosts SET tags=?, checklist=?, notes=?, priority=? WHERE ip=?", (tags, checklist, notes, prio, ip))
                if a_text:
                    log_action(ip, a_text, a_type, a_status, conn)
                conn.commit()
            return redirect(url_for('main'))

    search = request.args.get('search','')
    tag_f = request.args.get('tag','')
    prio_f = request.args.get('priority','')

    with sqlite3.connect(app.config['DATABASE']) as c:
        cur = c.cursor()
        q, params, cond = "SELECT * FROM hosts", [], []
        if search:
            cond.append("(ip LIKE ? OR notes LIKE ?)"); params += [f'%{search}%']*2
        if tag_f:
            cond.append("tags LIKE ?"); params.append(f'%{tag_f}%')
        if prio_f:
            cond.append("priority = ?"); params.append(prio_f)
        if cond:
            q += " WHERE " + " AND ".join(cond)
        cur.execute(q, params)
        hosts = cur.fetchall()

        ports_data = defaultdict(list)
        for ip, port, proto in cur.execute("SELECT ip,port,protocol FROM ports"):
            ports_data[ip].append((port,proto))

        actions_data = defaultdict(list)
        for ip, ts, txt, typ, stat in cur.execute("SELECT ip,timestamp,action,type,status FROM actions ORDER BY timestamp ASC"):
            actions_data[ip].append((ts, txt, typ, stat))

        global_port_stats = {port:cnt for port,cnt in cur.execute("SELECT port, COUNT(DISTINCT ip) FROM ports GROUP BY port ORDER BY COUNT(DISTINCT ip) DESC LIMIT 10")}
        global_total_ports = cur.execute("SELECT COUNT(*) FROM ports").fetchone()[0]
        global_priority_counts = {prio:cnt for prio,cnt in cur.execute("SELECT priority, COUNT(*) FROM hosts WHERE priority != '' GROUP BY priority")}
        global_tag_summary = defaultdict(int)
        for (tag_str,) in cur.execute("SELECT tags FROM hosts WHERE tags != ''"):
            for t in tag_str.split(','):
                global_tag_summary[t.strip()] += 1

    return render_template('main.html',
        hosts=hosts,
        ports_data=ports_data,
        actions_data=actions_data,
        port_stats=global_port_stats,
        total_ports=global_total_ports,
        priority_counts=global_priority_counts,
        tags_summary=global_tag_summary,
        search=search, tag_filter=tag_f, priority_filter=prio_f)

@app.route('/timeline', methods=['GET', 'POST'])
def timeline():
    if request.method == 'POST':
        ip = request.form.get('ip')
        txt = request.form.get('action')
        typ = request.form.get('type')
        stat = request.form.get('status')
        if ip and txt:
            log_action(ip, txt, typ, stat)
        return redirect(url_for('timeline'))

    with sqlite3.connect(app.config['DATABASE']) as c:
        rows = c.execute("SELECT id, timestamp, ip, type, status, action FROM actions WHERE type != 'info' ORDER BY timestamp ASC").fetchall()
    return render_template('timeline.html', rows=rows)

@app.route('/action/<int:action_id>', methods=['POST'])
def edit_action(action_id):
    text = request.form.get('action')
    stat = request.form.get('status')
    timestamp = request.form.get('timestamp')

    with sqlite3.connect(app.config['DATABASE']) as c:
        if timestamp:
            c.execute("UPDATE actions SET action=?, status=?, timestamp=? WHERE id=?", (text, stat, timestamp, action_id))
        else:
            c.execute("UPDATE actions SET action=?, status=? WHERE id=?", (text, stat, action_id))
        c.commit()
    return redirect(url_for('timeline'))

@app.context_processor
def inject_bootstrap():
    return dict(bootstrap_css='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css')

if __name__ == '__main__':
    app.run(debug=True)
