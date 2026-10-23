import os,sqlite3,csv,io,secrets,datetime,functools,re
from flask import Flask,request,session,redirect,url_for,render_template,flash,Response,abort
from werkzeug.security import generate_password_hash,check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

BASE=os.path.dirname(__file__)
app=Flask(__name__)
app.secret_key=os.environ.get('SECRET_KEY',secrets.token_hex(32))
app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',SESSION_COOKIE_SECURE=os.environ.get('HTTPS_ONLY')=='1',MAX_CONTENT_LENGTH=1024*1024)
DB=os.environ.get('DATABASE_PATH',os.path.join(BASE,'portal.db'))
ROLES=('admin','district','assembly','mandal','booth','viewer')
STATUSES=('Submitted','Under Review','Verified','Rejected','Needs Correction')

def conn():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON');return c

def init():
 with conn() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL,district TEXT DEFAULT '',assembly TEXT DEFAULT '',mandal TEXT DEFAULT '',booth TEXT DEFAULT '',active INTEGER DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
 CREATE TABLE IF NOT EXISTS applications(id INTEGER PRIMARY KEY,reference TEXT UNIQUE NOT NULL,full_name TEXT NOT NULL,phone TEXT NOT NULL,district TEXT NOT NULL,assembly TEXT NOT NULL,mandal TEXT NOT NULL,booth TEXT DEFAULT '',qualification TEXT DEFAULT '',status TEXT DEFAULT 'Submitted',notes TEXT DEFAULT '',consent INTEGER NOT NULL DEFAULT 0,created_by INTEGER NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(created_by) REFERENCES users(id));
 CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,user_id INTEGER,action TEXT,entity TEXT,entity_id TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
 CREATE INDEX IF NOT EXISTS idx_geo ON applications(district,assembly,mandal,booth);
 CREATE INDEX IF NOT EXISTS idx_status ON applications(status);''')
  if not c.execute('SELECT 1 FROM users LIMIT 1').fetchone():
   username=os.environ.get('ADMIN_USERNAME');pwd=os.environ.get('ADMIN_PASSWORD')
   if not username or not pwd or len(pwd)<12: raise RuntimeError('Set ADMIN_USERNAME and ADMIN_PASSWORD (12+ chars) before first launch')
   c.execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)',(username,generate_password_hash(pwd),'admin'))

def csrf():
 if 'csrf' not in session:session['csrf']=secrets.token_urlsafe(32)
 return session['csrf']
app.jinja_env.globals['csrf_token']=csrf
@app.before_request
def protect():
 if request.method=='POST' and not secrets.compare_digest(request.form.get('_csrf',''),session.get('csrf','')):abort(400,'Invalid CSRF token')

@app.context_processor
def context():return dict(me=current_user(),statuses=STATUSES)

def current_user():
 uid=session.get('uid')
 if not uid:return None
 with conn() as c:return c.execute('SELECT * FROM users WHERE id=? AND active=1',(uid,)).fetchone()

def login_required(fn):
 @functools.wraps(fn)
 def wrapper(*args,**kwargs):
  if not current_user():return redirect(url_for('login'))
  return fn(*args,**kwargs)
 return wrapper

def admin_required(fn):
 @functools.wraps(fn)
 @login_required
 def wrapper(*args,**kwargs):
  if current_user()['role']!='admin':abort(403)
  return fn(*args,**kwargs)
 return wrapper

def scope(user,alias='a'):
 clauses=[];args=[]
 for field in ('district','assembly','mandal','booth'):
  if user[field]:clauses.append(f'{alias}.{field}=?');args.append(user[field])
 return (' AND '.join(clauses) or '1=1'),args

def audit(c,action,entity,eid):c.execute('INSERT INTO audit(user_id,action,entity,entity_id) VALUES(?,?,?,?)',(session.get('uid'),action,entity,str(eid)))

@app.route('/login',methods=['GET','POST'])
def login():
 if request.method=='POST':
  username=request.form.get('username','').strip();password=request.form.get('password','')
  with conn() as c:u=c.execute('SELECT * FROM users WHERE username=? AND active=1',(username,)).fetchone()
  if u and check_password_hash(u['password_hash'],password):
   session.clear();session['uid']=u['id'];csrf();return redirect(url_for('dashboard'))
  flash('Invalid credentials','error')
 return render_template('login.html')
@app.post('/logout')
def logout():session.clear();return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
 u=current_user();where,args=scope(u)
 with conn() as c:
  summary=c.execute(f'SELECT COUNT(*) total, SUM(CASE WHEN status="Verified" THEN 1 ELSE 0 END) verified,SUM(CASE WHEN status="Submitted" THEN 1 ELSE 0 END) submitted,SUM(CASE WHEN status="Under Review" THEN 1 ELSE 0 END) review,SUM(CASE WHEN status="Rejected" THEN 1 ELSE 0 END) rejected FROM applications a WHERE {where}',args).fetchone()
  by_status=c.execute(f'SELECT status,COUNT(*) n FROM applications a WHERE {where} GROUP BY status',args).fetchall()
  by_district=c.execute(f'SELECT district,COUNT(*) n FROM applications a WHERE {where} GROUP BY district ORDER BY n DESC',args).fetchall()
  recent=c.execute(f'SELECT a.* FROM applications a WHERE {where} ORDER BY a.id DESC LIMIT 8',args).fetchall()
 return render_template('dashboard.html',summary=summary,by_status=by_status,by_district=by_district,recent=recent)

@app.route('/applications')
@login_required
def applications():
 u=current_user();where,args=scope(u);filters=[]
 for f in ('district','assembly','mandal','booth','status'):
  v=request.args.get(f,'').strip()
  if v:filters.append(f'a.{f}=?');args.append(v)
 if filters:where+=' AND '+' AND '.join(filters)
 with conn() as c:
  rows=c.execute(f'SELECT a.* FROM applications a WHERE {where} ORDER BY a.id DESC LIMIT 500',args).fetchall()
 return render_template('applications.html',rows=rows)

@app.route('/applications/new',methods=['GET','POST'])
@login_required
def new_application():
 u=current_user()
 if u['role']=='viewer':abort(403)
 if request.method=='POST':
  d={k:request.form.get(k,'').strip() for k in ('full_name','phone','district','assembly','mandal','booth','qualification','notes')}
  if not all(d[k] for k in ('full_name','phone','district','assembly','mandal')) or not re.fullmatch(r'[0-9+\- ]{8,16}',d['phone']):flash('Complete the required fields and provide a valid phone number.','error')
  elif request.form.get('consent')!='yes':flash('Explicit consent is required.','error')
  elif any(u[k] and d[k]!=u[k] for k in ('district','assembly','mandal','booth')):abort(403)
  else:
   ref='GSR-'+datetime.datetime.now(datetime.timezone.utc).strftime('%y%m%d')+'-'+secrets.token_hex(4).upper()
   with conn() as c:
    cur=c.execute('INSERT INTO applications(reference,full_name,phone,district,assembly,mandal,booth,qualification,notes,consent,created_by) VALUES(?,?,?,?,?,?,?,?,?,1,?)',(ref,*[d[k] for k in ('full_name','phone','district','assembly','mandal','booth','qualification','notes')],u['id']))
    audit(c,'create','application',cur.lastrowid)
   flash('Assistance record created. This does NOT submit Form 18 to the Election Commission.','success');return redirect(url_for('applications'))
 return render_template('new_application.html')

@app.post('/applications/<int:aid>/status')
@login_required
def update_status(aid):
 u=current_user()
 if u['role'] in ('viewer','booth'):abort(403)
 status=request.form.get('status','')
 if status not in STATUSES:abort(400)
 where,args=scope(u)
 with conn() as c:
  item=c.execute(f'SELECT a.id FROM applications a WHERE a.id=? AND {where}',[aid]+args).fetchone()
  if not item:abort(404)
  c.execute('UPDATE applications SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(status,aid));audit(c,'status:'+status,'application',aid)
 flash('Status updated','success');return redirect(url_for('applications'))

@app.route('/reports')
@login_required
def reports():
 u=current_user();where,args=scope(u)
 with conn() as c:
  rows=c.execute(f'SELECT district,assembly,mandal,booth,status,COUNT(*) n FROM applications a WHERE {where} GROUP BY district,assembly,mandal,booth,status ORDER BY district,assembly,mandal,booth',args).fetchall()
 return render_template('reports.html',rows=rows)

@app.route('/reports/export.csv')
@login_required
def export():
 u=current_user();where,args=scope(u)
 with conn() as c:rows=c.execute(f'SELECT reference,district,assembly,mandal,booth,status,created_at FROM applications a WHERE {where} ORDER BY id DESC',args).fetchall()
 out=io.StringIO();w=csv.writer(out);w.writerow(['Reference','District','Assembly','Mandal','Booth','Status','Created UTC']);w.writerows([list(r) for r in rows])
 return Response(out.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment; filename=gsr_aggregate_report.csv','Cache-Control':'no-store'})

@app.route('/users',methods=['GET','POST'])
@admin_required
def users():
 if request.method=='POST':
  vals={k:request.form.get(k,'').strip() for k in ('username','password','role','district','assembly','mandal','booth')}
  if vals['role'] not in ROLES or len(vals['password'])<12 or not vals['username']:flash('Username, role and a password of 12+ characters are required','error')
  else:
   try:
    with conn() as c:
     cur=c.execute('INSERT INTO users(username,password_hash,role,district,assembly,mandal,booth) VALUES(?,?,?,?,?,?,?)',(vals['username'],generate_password_hash(vals['password']),*[vals[k] for k in ('role','district','assembly','mandal','booth')]))
     audit(c,'create','user',cur.lastrowid)
    flash('Coordinator created','success')
   except sqlite3.IntegrityError:flash('Username already exists','error')
 with conn() as c:rows=c.execute('SELECT id,username,role,district,assembly,mandal,booth,active FROM users ORDER BY id').fetchall()
 return render_template('users.html',rows=rows,roles=ROLES)

@app.post('/users/<int:uid>/toggle')
@admin_required
def toggle_user(uid):
 if uid==session['uid']:abort(400)
 with conn() as c:
  c.execute('UPDATE users SET active=1-active WHERE id=?',(uid,));audit(c,'toggle','user',uid)
 return redirect(url_for('users'))

@app.after_request
def headers(resp):
 resp.headers['X-Content-Type-Options']='nosniff';resp.headers['X-Frame-Options']='DENY';resp.headers['Referrer-Policy']='strict-origin-when-cross-origin';resp.headers['Cache-Control']='no-store';resp.headers['Content-Security-Policy']="default-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
 return resp

if __name__=='__main__':
 init()
 from waitress import serve
 serve(app,host='127.0.0.1',port=int(os.environ.get('PORT','8000')))
