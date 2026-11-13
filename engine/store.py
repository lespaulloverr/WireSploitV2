import sqlite3, uuid, json, hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
import os
ROOT=Path(__file__).resolve().parents[1]
default_db = ROOT/'data'/'wiresploit.sqlite3'
DB = Path(os.environ.get('WIRESPOOL_DB', default_db))

def now(): return datetime.now(timezone.utc).isoformat()
def connect():
    c=sqlite3.connect(DB, timeout=20); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c

def init():
    DB.parent.mkdir(parents=True,exist_ok=True)
    # Create evidence directory
    (ROOT/'data'/'evidence').mkdir(parents=True, exist_ok=True)
    with connect() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS investigations(id TEXT PRIMARY KEY,name TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,srm_authorized INTEGER NOT NULL DEFAULT 0, permanent INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS inputs(id TEXT PRIMARY KEY,investigation_id TEXT NOT NULL,kind TEXT NOT NULL,value TEXT NOT NULL,normalized TEXT NOT NULL,source TEXT NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,investigation_id TEXT NOT NULL,status TEXT NOT NULL,stage INTEGER NOT NULL DEFAULT 0,total_stages INTEGER NOT NULL DEFAULT 0,current TEXT,started_at TEXT NOT NULL,finished_at TEXT,error TEXT,FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,run_id TEXT NOT NULL,category TEXT NOT NULL,target TEXT NOT NULL,provider TEXT NOT NULL,status TEXT NOT NULL,message TEXT,started_at TEXT,finished_at TEXT,FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,run_id TEXT NOT NULL,category TEXT NOT NULL,provider TEXT NOT NULL,entity_key TEXT NOT NULL,value TEXT,url TEXT,confidence REAL NOT NULL DEFAULT .5,exact_match INTEGER NOT NULL DEFAULT 1,evidence_json TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(run_id,entity_key,provider),FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS identifiers(id TEXT PRIMARY KEY,investigation_id TEXT NOT NULL,kind TEXT NOT NULL,value TEXT NOT NULL,normalized TEXT NOT NULL,status TEXT NOT NULL,stage INTEGER NOT NULL,UNIQUE(investigation_id,kind,normalized),FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,run_id TEXT NOT NULL,level TEXT NOT NULL,message TEXT NOT NULL,meta_json TEXT,created_at TEXT NOT NULL,FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY,investigation_id TEXT NOT NULL,kind TEXT NOT NULL,title TEXT NOT NULL,source TEXT,url TEXT,description TEXT,sha256 TEXT,created_at TEXT NOT NULL,FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS investigation_notes(id TEXT PRIMARY KEY,investigation_id TEXT NOT NULL,note TEXT NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS search_history(id TEXT PRIMARY KEY,query TEXT NOT NULL,kind TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_search_history_created ON search_history(created_at);
        CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id); CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id);
        ''')
        migrate_database()

def row(q,args=()):
    with connect() as c: return c.execute(q,args).fetchone()
def rows(q,args=()):
    with connect() as c: return c.execute(q,args).fetchall()
def create_investigation(name,srm=False):
    i=str(uuid.uuid4()); t=now();
    with connect() as c:c.execute('INSERT INTO investigations VALUES(?,?,?,?,?,?,?)',(i,name.strip() or 'Untitled investigation','ready',t,t,int(srm),0))
    return get_investigation(i)
def get_investigation(i):
    r=row('SELECT * FROM investigations WHERE id=?',(i,));
    if not r:return None
    d=dict(r); d['srm_authorized']=bool(d['srm_authorized']); d['permanent']=bool(d['permanent']); d['inputs']=[dict(x) for x in rows('SELECT * FROM inputs WHERE investigation_id=? ORDER BY created_at',(i,))]; return d
def list_investigations():
    return [dict(r) for r in rows('SELECT * FROM investigations ORDER BY updated_at DESC')]
def add_input(i,kind,value):
    n=' '.join(value.strip().lower().split()); iid=str(uuid.uuid4())
    with connect() as c:c.execute('INSERT OR IGNORE INTO inputs VALUES(?,?,?,?,?,?,?)',(iid,i,kind,value.strip(),n,'user',now()))
    return iid
def set_status(i,status):
    with connect() as c:c.execute('UPDATE investigations SET status=?,updated_at=? WHERE id=?',(status,now(),i))
def create_run(i,total):
    rid=str(uuid.uuid4());
    with connect() as c:c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?,?)',(rid,i,'queued',0,total,'',now(),None,None))
    return rid
def update_run(rid,**kw):
    if not kw:return
    fields=[];vals=[]
    for k,v in kw.items():fields.append(k+'=?');vals.append(v)
    vals.append(rid)
    with connect() as c:c.execute('UPDATE runs SET '+','.join(fields)+' WHERE id=?',vals)
def get_run(rid):
    r=row('SELECT * FROM runs WHERE id=?',(rid,));
    if not r:return None
    d=dict(r); d['jobs']=[dict(x) for x in rows('SELECT * FROM jobs WHERE run_id=? ORDER BY started_at IS NULL, started_at',(rid,))]; d['findings_count']=row('SELECT COUNT(*) n FROM findings WHERE run_id=?',(rid,))['n']; d['events']=[dict(x) for x in rows('SELECT * FROM events WHERE run_id=? ORDER BY id',(rid,))]; return d
def add_job(rid,cat,target,provider):
    jid=str(uuid.uuid4());
    with connect() as c:c.execute('INSERT INTO jobs(id,run_id,category,target,provider,status) VALUES(?,?,?,?,?,?)',(jid,rid,cat,target,provider,'queued'))
    return jid
def job_update(jid,**kw):
    fields=[];vals=[]
    for k,v in kw.items():fields.append(k+'=?');vals.append(v)
    vals.append(jid)
    with connect() as c: c.execute('UPDATE jobs SET ' + ','.join(fields) + ' WHERE id=?', vals)
def event(rid,level,msg,meta=None):
    with connect() as c:c.execute('INSERT INTO events(run_id,level,message,meta_json,created_at) VALUES(?,?,?,?,?)',(rid,level,msg,json.dumps(meta or {}),now()))
def add_identifier(i,kind,value,stage):
    n=' '.join(value.strip().lower().split());
    with connect() as c:
        before=c.total_changes;c.execute('INSERT OR IGNORE INTO identifiers VALUES(?,?,?,?,?,?,?)',(str(uuid.uuid4()),i,kind,value.strip(),n,'queued',stage)); return c.total_changes>before
def requeue_identifier(i,kind,value,stage=0):
    n=' '.join(value.strip().lower().split())
    with connect() as c:
        row=c.execute('SELECT id FROM identifiers WHERE investigation_id=? AND kind=? AND normalized=?',(i,kind,n)).fetchone()
        if row:
            c.execute("UPDATE identifiers SET status='queued',stage=? WHERE id=?",(stage,row['id']))
            return row['id']
        ident=str(uuid.uuid4())
        c.execute('INSERT INTO identifiers VALUES(?,?,?,?,?,?,?)',(ident,i,kind,value.strip(),n,'queued',stage))
        return ident
def queued_identifiers(i,stage):
    return [dict(r) for r in rows('SELECT * FROM identifiers WHERE investigation_id=? AND status="queued" AND stage<=? ORDER BY stage,id',(i,stage))]
def mark_identifier(iid,status):
    with connect() as c:c.execute('UPDATE identifiers SET status=? WHERE id=?',(status,iid))
def add_evidence(i, kind, title, source, description, content_bytes=None, filename=None):
    eid = str(uuid.uuid4())
    t = now()
    sha256_hash = None
    stored_filename = None
    url = None
    mime_type = None
    file_path_str = None

    if content_bytes is not None:
        # Compute SHA-256
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()

        # Determine storage filename: preserve extension if possible
        ext = ''
        if filename and '.' in filename:
            ext = '.' + filename.split('.')[-1]
        elif content_bytes is not None and not filename:
            ext = '.bin'

        # Create a safe filename: use evidence id and extension
        stored_filename = f"{eid}{ext}"
        url = stored_filename

        # Determine MIME type from extension
        if ext:
            ext_lower = ext[1:].lower()  # remove leading dot
            mime_map = {
                'txt': 'text/plain',
                'png': 'image/png',
                'jpg': 'image/jpeg',
                'jpeg': 'image/jpeg',
                'pdf': 'application/pdf',
                'json': 'application/json',
                'csv': 'text/csv',
                'html': 'text/html',
                'bin': 'application/octet-stream',
            }
            mime_type = mime_map.get(ext_lower, 'application/octet-stream')
        else:
            mime_type = 'application/octet-stream'

        # Ensure evidence directory exists
        evidence_dir = ROOT / 'data' / 'evidence'
        evidence_dir.mkdir(parents=True, exist_ok=True)
        file_path = evidence_dir / stored_filename
        file_path_str = str(file_path)

        # If title not provided, use filename
        if not title:
            title = filename if filename else "binary_evidence"
        # If source not provided, use filename
        if not source:
            source = filename if filename else "binary_evidence"

        # ATOMIC WRITE: Insert DB record FIRST, then write file
        # If file write fails, we delete the DB record
        with connect() as c:
            c.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                     (eid, i, kind, title, source, url, description, sha256_hash, t, filename, mime_type, file_path_str))

        try:
            # Write file after DB insert
            with open(file_path, 'wb') as f:
                f.write(content_bytes)
        except Exception:
            # If file write fails, clean up DB record
            with connect() as c:
                c.execute('DELETE FROM evidence WHERE id=?', (eid,))
            raise
    else:
        # Metadata-only evidence (no file upload) - URL provided by user
        # URL validation is done at API level
        url = ''
        with connect() as c:
            c.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                     (eid, i, kind, title, source, url, description, None, t, None, None, None))

    return eid


def verify_evidence_hash(eid):
    """Verify that the stored file's SHA-256 matches the database record.
    Returns (verified: bool, expected_hash: str, actual_hash: str or None)."""
    with connect() as c:
        row = c.execute('SELECT file_path, url, sha256 FROM evidence WHERE id=?', (eid,)).fetchone()
    if not row or not row[2]:
        return (False, None, None)  # No file or no hash to verify

    expected_hash = row[2]
    file_path_str = row[0] if row[0] else row[1]

    if not file_path_str:
        return (False, expected_hash, None)  # No file path

    # Get file path - use file_path column if available, fallback to url
    evidence_dir = (ROOT / 'data' / 'evidence').resolve()
    try:
        file_path = Path(file_path_str).resolve()
        file_path.relative_to(evidence_dir)
    except (ValueError, OSError):
        return (False, expected_hash, None)  # Path traversal or invalid

    if not file_path.is_file():
        return (False, expected_hash, None)  # File not found

    # Compute actual hash
    actual_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
    return (actual_hash == expected_hash, expected_hash, actual_hash)
def add_finding(rid, category, provider, finding):
    """Add a finding to the database for a specific run.
    finding dict should contain: entity_key, value, url, platform, source_tools, evidence, confidence, exact_match"""
    fid = str(uuid.uuid4())
    t = now()
    # Extract fields from finding dict with defaults
    entity_key = finding.get('entity_key') or finding.get('platform', 'unknown') + ':' + str(finding.get('value', ''))
    value = finding.get('value') or finding.get('platform', '')
    url = finding.get('url')
    confidence = finding.get('confidence', 0.5)
    exact_match = int(finding.get('evidence', {}).get('exact_match', finding.get('exact_match', True)))
    # Convert evidence dict to JSON string
    evidence_json = json.dumps(finding.get('evidence', {}))
    with connect() as c:
        c.execute('''
            INSERT OR IGNORE INTO findings(id, run_id, category, provider, entity_key, value, url, confidence, exact_match, evidence_json, created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
        ''', (fid, rid, category, provider, entity_key, value, url, confidence, exact_match, evidence_json, t))
    return fid

def findings_for(i):
    return [dict(r) for r in rows('SELECT f.* FROM findings f JOIN runs r ON r.id=f.run_id WHERE r.investigation_id=? ORDER BY f.created_at',(i,))]
def evidence_for(i):return [dict(r) for r in rows('SELECT * FROM evidence WHERE investigation_id=? ORDER BY created_at DESC',(i,))]
def get_evidence_filepath(eid):
    """Return the absolute path to the stored file for the given evidence id, if it exists.
    Validates that the path is within the evidence directory to prevent path traversal."""
    with connect() as c:
        row = c.execute('SELECT file_path, url FROM evidence WHERE id=?', (eid,)).fetchone()
    if row:
        # Prefer file_path column if available (new schema), fallback to url
        file_path_str = row[0] if row[0] else row[1]
        if file_path_str:
            # Validate path traversal: ensure the resolved path is within the evidence directory
            evidence_dir = (ROOT / 'data' / 'evidence').resolve()
            try:
                file_path = Path(file_path_str).resolve()
                # Check that the resolved path is within the evidence directory
                file_path.relative_to(evidence_dir)
                return file_path
            except (ValueError, OSError):
                # Path traversal attempt or invalid path
                return None
    return None

def delete_old_investigations(days=3):
    'Delete investigations older than the specified number of days (default 3). Also deletes associated evidence files from disk.'
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    cutoff_str = cutoff.isoformat()

    # First, get evidence files that will be deleted (before CASCADE)
    evidence_files = []
    with connect() as c:
        rows = c.execute('''
            SELECT e.url FROM evidence e
            JOIN investigations i ON i.id = e.investigation_id
            WHERE i.updated_at < ? AND i.permanent = 0
        ''', (cutoff_str,)).fetchall()
        evidence_files = [row[0] for row in rows if row[0]]

    # Delete investigations (CASCADE will remove evidence records)
    with connect() as c:
        cursor = c.execute('DELETE FROM investigations WHERE updated_at < ? AND permanent=0', (cutoff_str,))
        deleted_count = cursor.rowcount

    # Delete evidence files from disk
    evidence_dir = ROOT / 'data' / 'evidence'
    for url in evidence_files:
        if url:
            try:
                file_path = evidence_dir / url
                if file_path.is_file():
                    file_path.unlink()
            except Exception:
                pass  # Ignore errors deleting individual files

    return deleted_count


def cleanup_orphaned_evidence_files():
    """Scan evidence directory for files not referenced in database and delete them.
    Returns count of deleted orphaned files."""
    evidence_dir = ROOT / 'data' / 'evidence'
    if not evidence_dir.exists():
        return 0

    # Get all evidence URLs from database
    with connect() as c:
        rows = c.execute('SELECT url FROM evidence WHERE url IS NOT NULL AND url != ""').fetchall()
        db_files = {row[0] for row in rows}

    deleted = 0
    for file_path in evidence_dir.iterdir():
        if file_path.is_file() and file_path.name not in db_files:
            try:
                file_path.unlink()
                deleted += 1
            except Exception:
                pass
    return deleted

def add_search_history(query, kind):
    """Add a search history entry."""
    hid = str(uuid.uuid4())
    t = now()
    with connect() as c:
        c.execute('INSERT INTO search_history VALUES(?,?,?,?)', (hid, query, kind, t))
    return hid

def get_search_history(limit=50):
    """Get recent search history entries."""
    return [dict(r) for r in rows('SELECT * FROM search_history ORDER BY created_at DESC LIMIT ?', (limit,))]

def delete_search_history(hid):
    """Delete a specific search history entry."""
    with connect() as c:
        cursor = c.execute('DELETE FROM search_history WHERE id=?', (hid,))
    return cursor.rowcount > 0

def clear_search_history():
    """Clear all search history."""
    with connect() as c:
        cursor = c.execute('DELETE FROM search_history')
    return cursor.rowcount

def cleanup_search_history(days=3):
    """Delete search history entries older than the specified number of days (default 3)."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    cutoff_str = cutoff.isoformat()
    with connect() as c:
        cursor = c.execute('DELETE FROM search_history WHERE created_at < ?', (cutoff_str,))
    return cursor.rowcount

def add_investigation_note(iid, note):
    """Add a note to an investigation."""
    nid = str(uuid.uuid4())
    t = now()
    with connect() as c:
        c.execute('INSERT INTO investigation_notes VALUES (?,?,?,?)', (nid, iid, note, t))
    return nid

def get_investigation_notes(iid):
    """Get all notes for an investigation."""
    return [dict(r) for r in rows('SELECT * FROM investigation_notes WHERE investigation_id=? ORDER BY created_at', (iid,))]

def update_investigation_note(nid, note):
    """Update a note."""
    with connect() as c:
        cursor = c.execute('UPDATE investigation_notes SET note=? WHERE id=?', (note, nid))
        return cursor.rowcount > 0

def delete_investigation_note(nid):
    """Delete a note."""
    with connect() as c:
        cursor = c.execute('DELETE FROM investigation_notes WHERE id=?', (nid,))
        return cursor.rowcount > 0


def migrate_database():
    '''Migrate the database schema for versions that lack the permanent column or have incorrect foreign keys.'''
    with connect() as c:
        # Check if the permanent column exists in investigations
        col_info = c.execute("PRAGMA table_info(investigations)").fetchall()
        col_names = [col[1] for col in col_info]
        if 'permanent' not in col_names:
            c.execute('ALTER TABLE investigations ADD COLUMN permanent INTEGER NOT NULL DEFAULT 0')

        # Check if evidence table has the new columns (filename, mime_type, file_path)
        col_info = c.execute("PRAGMA table_info(evidence)").fetchall()
        col_names = [col[1] for col in col_info]
        if 'filename' not in col_names:
            c.execute('ALTER TABLE evidence ADD COLUMN filename TEXT')
        if 'mime_type' not in col_names:
            c.execute('ALTER TABLE evidence ADD COLUMN mime_type TEXT')
        if 'file_path' not in col_names:
            c.execute('ALTER TABLE evidence ADD COLUMN file_path TEXT')

        # Backfill existing records: infer filename from url, mime_type from extension
        rows = c.execute('SELECT id, url FROM evidence WHERE filename IS NULL OR mime_type IS NULL').fetchall()
        for row in rows:
            eid, url = row['id'], row['url']
            if url:
                # url is the stored filename (eid + ext)
                filename = url
                # Guess mime_type from extension
                ext = ''
                if '.' in url:
                    ext = url.split('.')[-1].lower()
                mime_map = {
                    'txt': 'text/plain',
                    'png': 'image/png',
                    'jpg': 'image/jpeg',
                    'jpeg': 'image/jpeg',
                    'pdf': 'application/pdf',
                    'json': 'application/json',
                    'csv': 'text/csv',
                    'html': 'text/html',
                    'bin': 'application/octet-stream',
                }
                mime_type = mime_map.get(ext, 'application/octet-stream')
                c.execute('UPDATE evidence SET filename=?, mime_type=? WHERE id=?', (filename, mime_type, eid))