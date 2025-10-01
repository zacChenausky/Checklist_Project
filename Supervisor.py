__version__ = "0010"
# Supervisor.py — PyQt5 UI for hierarchical monitor of Tech clients
# Blink policy:
#   - Yellow: SHIFT, NOT_POSSIBLE, and CHAT (from Tech) — stops when the row is clicked
#   - Red: OVERDUE and D1_MISSING — stops when that exact row is clicked
#   - No blinking for regular UPDATE / APPROVED
# Right pane:
#   - UPDATEs grouped by “X hours before KO” using the incoming section text
#   - Each bucket header shows: done/totalExpected — time left to the nearest due
#   - MD-1 header shows: received / required_min (D1_MIN_ITEMS)
import math
import os
import re
import csv
from concurrent.futures import ThreadPoolExecutor
import time
import socket
import queue
import threading
from datetime import datetime, date, timedelta
import json  # NEW
import hashlib
from configparser import ConfigParser
from PyQt5.QtGui import QIcon, QFont, QBrush, QColor
from PyQt5.QtCore import Qt, QTimer, QEvent, QUrl  
from PyQt5.QtWidgets import (
    QApplication, QWidget, QMainWindow, QLabel, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QMessageBox, QSplitter,
    QMenu, QAction, QAbstractItemView, QInputDialog, QProgressBar, QFrame, QScrollArea,
    QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, QSizePolicy, QCheckBox, QPlainTextEdit, QSplitter, QListWidget,
    QFileDialog, QGridLayout  
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtMultimedia import QSoundEffect
from PyQt5.QtPrintSupport import QPrinter
from PyQt5.QtGui import QIcon, QFont, QBrush, QColor, QTextDocument
import sqlite3

try:
    import winsound  # Windows fallback
except Exception:
    winsound = None  
# ---------- Small helpers ----------
def _parse_ip_list(value: str) -> list:
    import re as _re
    parts = [p.strip() for p in _re.split(r"[,\s]+", value or "") if p.strip()]
    seen, out = set(), []
    for p in parts:
        if p not in seen:
            out.append(p); seen.add(p)
    return out

# ---------- Paths / config loading ----------
def _default_support_dir():
    hard = r"C:\Matchday\VAR\Checklist\SupportingFiles"
    if os.path.isdir(hard):
        return hard
    here = os.path.abspath(os.path.dirname(__file__))
    guess = os.path.join(here, "SupportingFiles")
    return guess if os.path.isdir(guess) else here


SUPPORT_DIR = _default_support_dir()
PATH_SUPERVISOR = os.path.join(SUPPORT_DIR, "supervisor.ini")
LOG_PATH = os.path.join(SUPPORT_DIR, "supervisor_log.csv")
STATE_PATH = os.path.join(SUPPORT_DIR, "supervisor_state.json")  # NEW
def read_supervisor_ini(path=PATH_SUPERVISOR):
    cfg = {
        "bind_ip": "0.0.0.0",
        "port": 5000,
        "ack_port": 5010,
        "stale_ttl_seconds": 180,
        "title": "Supervisor – Live Tech Status-v0010",
        "theme": "clam",
        # === D1
        "d1_min_items": 8,
        "d1_eval_delay_sec": 60,
        "enable_csv_log": 1,
        # === Persistence (allow override from INI)
        "state_save_mode": "minimal",        # can be "full"
        "state_keep_chat": 20,
        "state_save_interval_ms": 5000,
    }
    if not os.path.exists(path):
        raise FileNotFoundError(f"Required supervisor.ini not found at {path}")

    parser = ConfigParser(inline_comment_prefixes=(";", "#"))
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        if "[Supervisor]" not in raw and "[supervisor]" not in raw:
            parser.read_string("[Supervisor]\n" + raw)
        else:
            parser.read(path, encoding="utf-8")

        sec = "Supervisor"

        def _get(*keys, default=""):
            for k in keys:
                if parser.has_option(sec, k):
                    return parser.get(sec, k, fallback=default)
            return default

        def _strip(s: str) -> str:
            return re.split(r"[;#]", s, maxsplit=1)[0].strip()

        def _get_int(*keys, default: int):
            rawv = _strip(_get(*keys, default=str(default)))
            try:
                return int(rawv)
            except Exception:
                return default

        host  = _strip(_get("bind_ip", "host", "ip", default=cfg["bind_ip"]) or cfg["bind_ip"])
        title = _strip(_get("title", default=cfg["title"]) or cfg["title"])
        theme = _strip(_get("theme", default=cfg["theme"]) or cfg["theme"])
        port     = _get_int("port", default=cfg["port"])
        ack_port = _get_int("ack_port", default=cfg["ack_port"])
        ttl      = _get_int("stale_ttl_seconds", "ttl", default=cfg["stale_ttl_seconds"])
        d1_min   = _get_int("d1_min_items", default=cfg["d1_min_items"])
        d1_wait  = _get_int("d1_eval_delay_sec", default=cfg["d1_eval_delay_sec"])
        enable = _get_int("enable_csv_log", default=cfg["enable_csv_log"])
        savemode   = _strip(_get("state_save_mode", default=cfg["state_save_mode"]) or cfg["state_save_mode"])
        keep_chat  = _get_int("state_keep_chat", default=cfg["state_keep_chat"])
        save_every = _get_int("state_save_interval_ms", default=cfg["state_save_interval_ms"])
        cfg.update({
            "bind_ip": host,
            "port": port,
            "ack_port": ack_port,
            "stale_ttl_seconds": ttl,
            "title": title,
            "theme": theme,
            "d1_min_items": d1_min,
            "d1_eval_delay_sec": d1_wait,
            "enable_csv_log": enable,
            "state_save_mode": savemode,
            "state_keep_chat": keep_chat,
            "state_save_interval_ms": save_every,
        })
        notes_db_raw = _strip(_get("notes_db", default=""))
        cfg.update({"notes_db": notes_db_raw})
        sup_name = _strip(_get("name", default="Supervisor"))
        cfg.update({"name": sup_name})
        # Tech stations list (optional)
        tech_ips = []
        tech_ack_port = None
        if parser.has_section("TechStations"):
            raw_ips = parser.get("TechStations", "ips", fallback="")
            tech_ips = _parse_ip_list(raw_ips)
            if parser.has_option("TechStations", "ack_port"):
                try:
                    tech_ack_port = int(parser.get("TechStations", "ack_port").strip())
                except Exception:
                    tech_ack_port = None

        cfg.update({
            "tech_ips": tech_ips,
            "tech_ack_port": tech_ack_port or cfg["ack_port"],
        })
        return cfg


    except Exception:
        # even on parse error, return defaults
        return cfg


CONF = read_supervisor_ini()
# Resolve DB path from [Supervisor] notes_db (folder or file)
_raw_notes_db = (CONF.get("notes_db") or "").strip()

def _resolve_db_path(raw: str) -> str:
    import os
    if not raw:
        # default to SupportingFiles\supervisor_notes.db
        return os.path.join(SUPPORT_DIR, "supervisor_notes.db")

    # expand ~ and %VARS%
    raw = os.path.expanduser(os.path.expandvars(raw))

    # If user gave a directory, drop the DB inside it
    if os.path.isdir(raw) or raw.endswith(os.sep) or raw.endswith("/"):
        return os.path.join(raw.rstrip("\\/"), "supervisor_notes.db")

    # Otherwise treat as a file path; add .db if missing
    return raw if raw.lower().endswith(".db") else (raw + ".db")

PATH_NOTES_DB = _resolve_db_path(_raw_notes_db)

# Ensure parent directory exists
try:
    os.makedirs(os.path.dirname(PATH_NOTES_DB), exist_ok=True)
except Exception:
    pass

ENABLE_LOG = bool(CONF.get("enable_csv_log", 1))
HOST = CONF["bind_ip"]
PORT = CONF["port"]
ACK_PORT = CONF["ack_port"]
STALE_TTL_SECONDS = CONF["stale_ttl_seconds"]
WINDOW_TITLE = CONF["title"]
ENABLE_STATE = True  # always persist unless you want to disable
STATE_SAVE_MODE = (CONF.get("state_save_mode", "minimal") or "minimal").lower()
STATE_KEEP_CHAT = int(CONF.get("state_keep_chat", 20))          # last N chats to keep
STATE_SAVE_INTERVAL_MS = int(CONF.get("state_save_interval_ms", 5000))  # debounce interval

# === D1: tunables
D1_MIN_ITEMS = CONF["d1_min_items"]
D1_EVAL_DELAY_SEC = CONF["d1_eval_delay_sec"]
# --- NEW: Tech stations pulled from supervisor.ini ---
TECH_IPS = CONF.get("tech_ips", [])
TECH_ACK_PORT = CONF.get("tech_ack_port", ACK_PORT)

# ---- Column indexes for the left QTree
COL_TECH     = 0
COL_TEAMS    = 1
COL_DAY      = 2
COL_KO       = 3
COL_KOHRS    = 4
COL_MD1      = 5
COL_PROGRESS = 6
COL_REQS     = 7
COL_IP       = 8

# ---------- Parsing ----------
SETUP_RE = re.compile(r"^SETUP:\s*(.*)$", re.IGNORECASE)
LEGACY_PROGRESS_RE = re.compile(r"^PROGRESS:\s*(.+?):\s*([0-9]{1,3})%", re.IGNORECASE)
GEN_UPDATE_RE = re.compile(r"^(UPDATE|D1|APPROVED|OVERDUE):\s*(.*)$", re.IGNORECASE)
REQUEST_RE = re.compile(r"^REQUEST:\s*(.*)$", re.IGNORECASE)
D1_EXPECT_RE = re.compile(r"^D1_EXPECT:\s*(.*)$", re.IGNORECASE)
KV_ANY = re.compile(r"(\w+)\s*=\s*(?:'([^']*)'|\"([^\"]*)\"|([^ \|]+))")
MATCH_TAG_SPLIT_RE = re.compile(r"\b(Match1|Match2):", re.IGNORECASE)
# add near your other regex extracts inside the block for this match:
def parse_kv_blob(blob: str) -> dict:
    out = {}
    for m in KV_ANY.finditer(blob):
        k = m.group(1).strip().lower()
        v = m.group(2) or m.group(3) or m.group(4) or ""
        out[k] = v.strip()
    return out
# === Progress normalizer (global) ===
def _norm_progress(raw):
    """Return int 0..100, or None if not parseable."""
    try:
        if raw is None:
            return None
        if isinstance(raw, (int, float)):
            return max(0, min(100, int(round(float(raw)))))
        s = str(raw).strip().rstrip("%")
        if s == "":
            return None
        return max(0, min(100, int(round(float(s)))))
    except Exception:
        return None

def parse_setup(msg: str) -> dict:
    m = SETUP_RE.match(msg)
    if not m:
        return {}
    body = m.group(1)

    # station/operator can live outside match blocks; grab them first
    header_kv = parse_kv_blob(body)
    station  = header_kv.get("station", "")
    operator = header_kv.get("operator", "")

    matches = {1: {}, 2: {}}

    # Split into [tag, block, tag, block, ...]
    parts = MATCH_TAG_SPLIT_RE.split(body)[1:]  # drop any leading non-match text
    # Iterate in pairs
    for tag, block in zip(parts[0::2], parts[1::2]):
        idx = 1 if tag.lower() == "match1" else 2

        # Stop this block at the start of the next "MatchX:" (if present)
        nxt = MATCH_TAG_SPLIT_RE.search(block)
        if nxt:
            block = block[:nxt.start()]

        mkv = parse_kv_blob(block)



        # Prefer Label over Teams; strip any wrapping quotes
        def _clean(v):
            v = (v or "").strip()
            if (len(v) >= 2) and ((v[0] == v[-1]) and v[0] in ("'", '"')):
                v = v[1:-1]
            return v

        teams_val = _clean(mkv.get("label") or mkv.get("teams"))
        matches[idx] = {
            "day":      (mkv.get("day") or "").strip(),
            "teams":    teams_val,
            "ko":       (mkv.get("ko") or "").strip(),
            "ko_date":  (mkv.get("ko_date") or "").strip(),
            "remi":     (mkv.get("remi") or "").strip(),
            "stadium":  (mkv.get("stadium") or "").strip(),
            "ws":       (mkv.get("ws") or "").strip(), 
        }

    return {"station": station, "operator": operator, "matches": matches}

def parse_legacy_progress(msg: str):
    m = LEGACY_PROGRESS_RE.match(msg)
    if not m:
        return None
    who = m.group(1).strip()
    try:
        pct = max(0, min(100, int(m.group(2))))
    except ValueError:
        pct = 0
    return who, pct

def parse_gen_update(msg: str) -> dict | None:
    m = GEN_UPDATE_RE.match(msg)
    if not m:
        return None
    tag = m.group(1).upper()
    kv = parse_kv_blob(m.group(2))

    day = kv.get("day") or kv.get("matchday") or kv.get("md") or ""
    ko = kv.get("ko") or kv.get("time") or kv.get("kickoff") or kv.get("kickoff_time") or ""
    teams = (
        kv.get("label")
        or kv.get("teams")
        or (f"{kv.get('hometeam','')} vs {kv.get('awayteam','')}".strip()
            if kv.get("hometeam") or kv.get("awayteam") else "")
        or (f"{kv.get('home','')} vs {kv.get('away','')}".strip()
            if kv.get("home") or kv.get("away") else "")
    )

    out = {
        "tag": tag,
        "station": kv.get("station", ""),
        "operator": kv.get("operator", ""),
        "match": int(kv.get("match", "1")) if kv.get("match") else 1,
        "item": kv.get("item", ""),
        "section": kv.get("section", ""),
        "state": (kv.get("state", "")).upper(),
        "progress": kv.get("progress", "").rstrip("%"),
        "teams": teams,
        "day": day,
        "ko": ko,
        "catchup": 1 if (kv.get("catchup","") or "0").strip().lower() in ("1","true","yes") else 0,
    }    # numbers
    try:
        out["progress"] = max(0, min(100, int(out["progress"])))
    except Exception:
        out["progress"] = None
    try:
        # parse either 'duets' (DueTS lowercased) or 'due_ts'
        out["due_ts"] = int(kv.get("duets") or kv.get("due_ts"))
    except Exception:
        out["due_ts"] = None
    try:
        out["total"] = int(kv.get("total")) if kv.get("total") else None
    except Exception:
        out["total"] = None

    return out

def parse_request(msg: str) -> dict | None:
    m = REQUEST_RE.match(msg)
    if not m:
        return None
    body = m.group(1).strip()
    parts = body.split(None, 1)
    if not parts:
        return None
    req_type = parts[0].upper()
    rest = parts[1] if len(parts) > 1 else ""
    kv = parse_kv_blob(rest)
    out = {
        "type": req_type,
        "match": int(kv.get("match", "1")) if kv.get("match") else 1,
        "item": kv.get("item", ""),
        "section": kv.get("section", ""),
        "from": kv.get("from", ""),
        "to": kv.get("to", ""),
        "text": kv.get("text", ""),
    }
    return out
def _norm_progress(raw):
    """Return an int 0..100 if we can parse it, else None."""
    if isinstance(raw, int):
        return max(0, min(100, raw))
    if isinstance(raw, str):
        s = raw.strip().rstrip("%")
        if s.isdigit():
            return max(0, min(100, int(s)))
    return None

# ---------- Networking server (threads) ----------
class ServerThread(threading.Thread):
    def __init__(self, host, port, ui_queue):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.ui_queue = ui_queue
        self._stop = threading.Event()
        self.sock = None

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(64)
            self.sock.settimeout(0.5)
            self.ui_queue.put(("info", f"Listening on {self.host}:{self.port}  (ack → {ACK_PORT})"))
        except OSError as e:
            self.ui_queue.put(("info", f"⚠️ Cannot bind {self.host}:{self.port} — {e}"))
            return

        while not self._stop.is_set():
            try:
                conn, addr = self.sock.accept()
                conn.settimeout(2.0)

                def _worker(c=conn, a=addr):
                    self._process_conn(c, a)

                threading.Thread(target=_worker, daemon=True).start()

            except socket.timeout:
                continue
            except OSError:
                break

        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

    def stop(self):
        self._stop.set()
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
    # ---- request fingerprint (for debug + dedupe) ----
    def _req_fp(d: dict):
        return (
            (d.get("ip","") or "").strip(),
            int(d.get("match",1) or 1),
            (d.get("type","") or "").upper(),
            (d.get("text","") or "").strip(),
        )
    # --------------------------------------------------

    def _process_conn(self, conn, addr):
        ip = addr[0]
        try:
            with conn:
                data = conn.recv(8192)
                if not data:
                    return
                line = data.decode(errors="ignore").strip()
                if line.upper().startswith("PING"):
                    return
                if line.upper().startswith("SETUP:"):
                    payload = parse_setup(line)
                    if payload:
                        # DEBUG: show what we parsed out (including WS)
                        try:
                            m1_ws = payload.get("matches", {}).get(1, {}).get("ws", "")
                            m2_ws = payload.get("matches", {}).get(2, {}).get("ws", "")
                        except Exception:
                            pass
                        payload["ip"] = ip
                        self.ui_queue.put(("setup", payload))

                elif GEN_UPDATE_RE.match(line):
                    upd = parse_gen_update(line)
                    if upd:
                        upd["ip"] = ip
                        self.ui_queue.put(("update", upd))
                elif D1_EXPECT_RE.match(line):
                    kv = parse_kv_blob(line.split(":", 1)[1])
                    try:
                        cnt = int(re.sub(r"\D", "", kv.get("count", "0") or "0"))
                    except Exception:
                        cnt = 0
                    evt = {
                        "station":  kv.get("station", ""),
                        "operator": kv.get("operator", ""),
                        "match":    int(kv.get("match", "1") or 1),
                        "teams":    kv.get("teams", ""),
                        "count":    cnt,
                        "ip":       ip,
                    }
                    self.ui_queue.put(("d1_expect", evt))

                elif line.upper().startswith("REQUEST:"):
                    req = parse_request(line)
                    if req:
                        req["ip"] = ip
                        
                        self.ui_queue.put(("request", req))
                elif line.upper().startswith("REPLY:"):
                    kv = parse_kv_blob(line.split(":", 1)[1])
                    req = {
                        "type": "CHAT",
                        "match": int(kv.get("match", "1")) if kv.get("match") else 1,
                        "from": f"{kv.get('station', '')} — {kv.get('operator', '')}".strip(" —"),
                        "text": kv.get("text", ""),
                        "ip": ip
                    }
                    self.ui_queue.put(("request", req))
                elif line.upper().startswith("PROGRESS:"):
                    p = parse_legacy_progress(line)
                    if p:
                        who, pct = p
                        self.ui_queue.put(("legacy_progress", {"who": who, "pct": pct, "ip": ip}))
                elif line.upper().startswith("MESSAGE:"):
                    kv = parse_kv_blob(line.split(":", 1)[1])
                    if (kv.get("kind","").strip().upper() == "REPORT"):
                        req = {
                            "type":  "REPORT",
                            "match": int(kv.get("match","1") or 1),
                            "from":  kv.get("from","Tech"),
                            "text":  kv.get("text",""),
                            "ip":    ip,
                        }
                        self.ui_queue.put(("request", req))
                    else:
                        req = {
                            "type":  "CHAT",
                            "match": int(kv.get("match","1") or 1),
                            "from":  kv.get("from","Tech"),
                            "text":  kv.get("text",""),
                            "ip":    ip,
                        }
                        self.ui_queue.put(("request", req))
                else:
                    self.ui_queue.put(("unknown", {"ip": ip, "text": line}))


        except Exception:
            pass
class SupervisorNotesDialog(QDialog):
    # At top of class:
    DEFAULT_CHECK_LABELS = [chr(c) for c in range(ord("A"), ord("J")+1)]  # A..J
    CHECK_KEYS = [chr(c) for c in range(ord("a"), ord("j")+1)]            # a..j (persist keys)

    def _load_check_labels(self):
        """
        Read display labels from supervisor.ini [notes_headers] h1..h10.
        Fallback to A..J when missing.
        """
        from configparser import ConfigParser
        import os
        labels = list(self.DEFAULT_CHECK_LABELS)

        # ask the parent for the path to supervisor.ini
        sup = self.parent()
        ini_path = sup._supervisor_ini_path() if sup else None
        if ini_path and os.path.exists(ini_path):
            cfg = ConfigParser()
            cfg.read(ini_path, encoding="utf-8")
            if cfg.has_section("notes_headers"):
                out = []
                for i in range(1, 11):
                    val = cfg.get("notes_headers", f"h{i}", fallback="").strip()
                    out.append(val if val else self.DEFAULT_CHECK_LABELS[i-1])
                labels = out
        return labels

    COLS = ["WS", "Name", "Home Team"] + [chr(c) for c in range(ord("A"), ord("J")+1)]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Supervisor notes")
        self.setWindowFlags(self.windowFlags() | Qt.WindowMinMaxButtonsHint | Qt.WindowStaysOnTopHint)
        self.resize(1200, 600)

        self._rows_key_index = {}  # key -> row index
        self._expanded_rows = {}   # base_row -> detail_row
        self._report_popups = {}   # base_row -> QDialog (modeless)
        self._loading = False      # guard re-entrancy while populating

        lay = QVBoxLayout(self)

        # Top bar with a Reset button (for notes only)
        top = QHBoxLayout()
        top.addStretch()
        self.btn_reset_notes = QPushButton("Reset Notes")
        self.btn_reset_notes.setToolTip("Clear only Supervisor notes (keeps main app state).")
        self.btn_reset_notes.clicked.connect(self._reset_notes)
        top.addWidget(self.btn_reset_notes)
        # NEW: Export report (PDF)
        self.btn_export_pdf = QPushButton("Export report")
        self.btn_export_pdf.setToolTip("Export general notes + match reporting to a PDF")
        self.btn_export_pdf.clicked.connect(self._export_report_pdf)
        top.addWidget(self.btn_export_pdf)
        self.btn_refresh = QPushButton("Refresh")
        self.btn_refresh.setToolTip("Reload from database")
        self.btn_refresh.clicked.connect(self._reload_from_db)
        top.addWidget(self.btn_refresh)

        lay.addLayout(top)
        # Build final header list (left 3 are fixed, last 10 come from supervisor.ini)
        self.check_labels = self._load_check_labels()                       # NEW
        self.COLS = ["WS", "Name", "Home Team", "Report"] + self.check_labels      
        # Table
        self.table = QTableWidget(0, len(self.COLS), self)
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.setColumnWidth(3, 60)
        self.table.setAlternatingRowColors(True)
        self.table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        # Selection + context menu
        self.table.setSelectionBehavior(self.table.SelectRows)
        self.table.setSelectionMode(self.table.ExtendedSelection)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_table_context_menu)
        self.table.installEventFilter(self)  # for Delete key support

        # --- NEW: right-side general notes pad -------------------------
        self.note_edit = QPlainTextEdit(self)
        self.note_edit.setPlaceholderText("Supervisor general notes…")
        self.note_edit.setMinimumWidth(280)
        self.note_edit.setStyleSheet("""
            font-size: 14pt;
            font-weight: 400;
            line-height: 1.4em;
        """)

        # Debounced autosave for notes
        from PyQt5.QtCore import QTimer
        self._notes_save_timer = QTimer(self)
        self._notes_save_timer.setSingleShot(True)
        self._notes_save_timer.timeout.connect(self._save_notes_to_db)
        self.note_edit.textChanged.connect(lambda: self._notes_save_timer.start(400))

        # Put table + notes into a splitter
        splitter = QSplitter(Qt.Horizontal, self)
        splitter.addWidget(self.table)
        splitter.addWidget(self.note_edit)
        splitter.setStretchFactor(0, 1)  # table grows
        splitter.setStretchFactor(1, 0)  # notes keeps min width
        lay.addWidget(splitter)


        # Bold horizontal headers with thicker borders
        hheader = self.table.horizontalHeader()
        font = hheader.font(); font.setBold(True); hheader.setFont(font)
        hheader.setStyleSheet("""
            QHeaderView::section {
                border: 2px solid black;
                background-color: #f0f0f0;
                padding: 4px;
                font: bold 7pt "Segoe UI";
            }
        """)
        # NEW: create/open DB and schema (Step 1 only)
        self._db = None
        self._db_init()
        from PyQt5.QtCore import QTimer
        self._wal_timer = QTimer(self)
        self._wal_timer.setInterval(60_000)  # every 60s
        self._wal_timer.timeout.connect(self._maybe_checkpoint_wal)
        self._wal_timer.start()

        # Load existing notes from DB on creation
        self._load_from_db()

    # --- SQLite helpers (Step 1: schema only) ---
    def _db_path(self) -> str:
        # single DB file next to supervisor.ini (SupportingFiles/supervisor_notes.db)
        return PATH_NOTES_DB
    def _wal_paths(self):
        db_path = self._db_path()
        return db_path, (db_path + "-wal")
    def _reload_from_db(self):
        # Safely persist anything local first, then reload from DB
        try:
            for r in range(self.table.rowCount()):
                self._save_row_to_db(r)
            self._save_notes_to_db()
        except Exception:
            pass
        self._load_from_db()

    def _maybe_checkpoint_wal(self, threshold_mb: int = 10):
        import os
        _, wal_path = self._wal_paths()
        try:
            if os.path.exists(wal_path) and os.path.getsize(wal_path) >= threshold_mb * 1024 * 1024:
                self._checkpoint(truncate=True, vacuum=False)
        except Exception:
            pass

    def _db_connect(self):
        if getattr(self, "_db", None) is None:
            self._db = sqlite3.connect(self._db_path(), check_same_thread=False)
            self._db.row_factory = sqlite3.Row
            # safer concurrent writes
            try:
                self._db.execute("PRAGMA journal_mode=WAL;")
                self._db.execute("PRAGMA synchronous=NORMAL;")
                self._db.execute("PRAGMA wal_autocheckpoint=200")  # checkpoint roughly every ~200 pages

            except Exception:
                pass
        return self._db
    def _checkpoint(self, *, truncate: bool = True, vacuum: bool = False):
        """Flush WAL back into the main DB; optionally VACUUM to reclaim space."""
        try:
            con = self._db_connect()
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)" if truncate else "PRAGMA wal_checkpoint(FULL)")
            if vacuum:
                con.execute("VACUUM")  # compact main .db (use sparingly)
            con.commit()
        except Exception:
            pass

    def _db_init(self):
        con = self._db_connect()
        con.executescript("""
        CREATE TABLE IF NOT EXISTS meta(
            schema_version INTEGER DEFAULT 1,
            migrated_from_ini INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS general_notes(
            id INTEGER PRIMARY KEY CHECK(id=1),
            text TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS notes_rows(
            key TEXT PRIMARY KEY,
            station  TEXT,
            operator TEXT,
            match    INTEGER,
            ws       TEXT,
            home     TEXT,
            -- A..J checkboxes:
            a INTEGER DEFAULT 0, b INTEGER DEFAULT 0, c INTEGER DEFAULT 0, d INTEGER DEFAULT 0, e INTEGER DEFAULT 0,
            f INTEGER DEFAULT 0, g INTEGER DEFAULT 0, h INTEGER DEFAULT 0, i INTEGER DEFAULT 0, j INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS reporting(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key   TEXT,
            match INTEGER,
            line  TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(key, match, line)
        );

        CREATE TABLE IF NOT EXISTS deleted_rows(
            key TEXT PRIMARY KEY,
            deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        con.commit()


    def reload_headers_from_supervisor_ini(self):
        self.check_labels = self._load_check_labels()
        self.COLS = ["WS", "Name", "Home Team", "Report"] + self.check_labels
        # update header text only (column count stays the same)
        self.table.setHorizontalHeaderLabels(self.COLS)

    def _export_report_pdf(self):
        """Create a PDF with: general notes, then per-match notes (WS/Name/Home + Reporting).
        Prompts for Matchday and Day; names file SupervisorReport_<MD>_<DAY>_<date>.pdf.
        Saves to [Supervisor].export folder from supervisor.ini when it exists; else asks user.
        """
        import os, html
        from datetime import datetime
        from PyQt5.QtWidgets import QInputDialog

        # ---------- 1) Ask Matchday and Day ----------
        md_ok = day_ok = False
        md_text, md_ok = QInputDialog.getText(self, "Matchday", "Enter Matchday (e.g., MD-1):")
        if not md_ok:
            return
        day_text, day_ok = QInputDialog.getText(self, "Day", "Enter Day (e.g., Saturday):")
        if not day_ok:
            return

        def _clean_for_filename(s: str) -> str:
            s = (s or "").strip()
            # strip any characters illegal in Windows filenames
            return "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in s)

        md_safe  = _clean_for_filename(md_text)
        day_safe = _clean_for_filename(day_text)

        today_str = datetime.now().strftime("%Y-%m-%d")
        file_name = f"SupervisorReport_{md_safe}_{day_safe}_{today_str}.pdf"

        # ---------- 2) Resolve export directory from supervisor.ini ----------
        export_dir = ""
        try:
            from configparser import ConfigParser
            parser = ConfigParser(inline_comment_prefixes=(";", "#"))
            # read supervisor.ini; handle files without explicit [Supervisor] section
            with open(self._supervisor_ini_path(), "r", encoding="utf-8") as f:
                raw = f.read()
            if "[Supervisor]" not in raw and "[supervisor]" not in raw:
                parser.read_string("[Supervisor]\n" + raw)
            else:
                parser.read(self._supervisor_ini_path(), encoding="utf-8")

            # basic strip to remove inline comments/trailing spaces
            val = parser.get("Supervisor", "export", fallback="").strip()
            export_dir = val.split(";")[0].split("#")[0].strip()
        except Exception:
            export_dir = ""

        # ---------- 3) Choose output path ----------
        path = ""
        if export_dir and os.path.isdir(export_dir):
            path = os.path.join(export_dir, file_name)
        else:
            # folder missing or not set → ask the user
            default_path = os.path.join(os.path.expanduser("~"), file_name)
            path, _ = QFileDialog.getSaveFileName(self, "Export report as PDF",
                                                default_path, "PDF Files (*.pdf)")
            if not path:
                return
            if not path.lower().endswith(".pdf"):
                path += ".pdf"

        # ---------- 4) Build HTML ----------
        def esc(s: str) -> str:
            return html.escape((s or "").strip())

        parts = []

        # Header image (first page)
        try:
            base_dir = os.path.dirname(self._supervisor_ini_path())  # ...\SupportingFiles
            img_path = os.path.join(base_dir, "Sportec.jpg")
        except Exception:
            img_path = r"C:\Matchday\VAR\Checklist\SupportingFiles\Sportec.jpg"

        header_html = ""
        if os.path.exists(img_path):
            img_url = "file:///" + img_path.replace("\\", "/")
            # use width attr so Qt honors the size
            header_html = f"""
            <div style="text-align:center; margin:0 0 6px 0;">
            <img src="{img_url}" width="500">
            </div>
            """

        # Small sub-header: Matchday — Day — Date
        parts.append(header_html)
        parts.append(f'<div style="text-align:center; font-weight:600; margin:2px 0 10px 0;">'
                    f'{esc(md_text)} — {esc(day_text)} — {esc(today_str)}</div>')
        parts.append("<hr>")

        # General notes
        parts.append("<h1>Supervisor general notes</h1>")
        gen = esc(self.note_edit.toPlainText())
        parts.append(f"<pre>{gen if gen else '(none)'}</pre>")
        parts.append("<hr>")
        parts.append("<h1>Match notes</h1>")
        # Per row (match)
        for row in range(self.table.rowCount()):
            ws   = self._safe_item_text(row, 0)
            name = self._safe_item_text(row, 1)
            home = self._safe_item_text(row, 2)
            parts.append(f"<h2>WS {esc(ws)} — {esc(name)} — {esc(home)}</h2>")

            # NEW: persist what’s currently in the Reporting pane so DB is up to date
            try:
                self._save_row_to_db(row)   # harmless no-op if nothing changed
            except Exception:
                pass

            # Now read the merged history (DB + live, de-duped, ordered)
            lines = self._collect_reporting_lines_for_row(row) or []
            if lines:
                parts.append("<ul>")
                for ln in lines:
                    parts.append(f"<li>{esc(ln)}</li>")
                parts.append("</ul>")
            else:
                parts.append("<p><i>(no reporting for this match)</i></p>")

        html_doc = """<html><head><meta charset="utf-8">
        <style>
        body{font-family:'Segoe UI', Arial, sans-serif; font-size:10pt;}
        h1{font-size:14pt;margin:0 0 8px;}
        h2{font-size:12pt;margin:14px 0 4px;}
        pre{white-space:pre-wrap;background:#f7f7f7;border:1px solid #ddd;border-radius:6px;padding:8px;}
        ul{margin:6px 0 10px 18px;} li{margin:3px 0;}
        hr{margin:14px 0;border:none;border-top:1px solid #ccc;}
        </style></head><body>
        """ + "\n".join(parts) + "</body></html>"

        # ---------- 5) Render to PDF ----------
        doc = QTextDocument()
        doc.setHtml(html_doc)

        printer = QPrinter(QPrinter.HighResolution)
        printer.setOutputFormat(QPrinter.PdfFormat)
        printer.setOutputFileName(path)

        try:
            doc.print_(printer)
            QMessageBox.information(self, "Export complete", f"Saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export failed", f"Could not write the PDF.\n\n{e}")

    def _hash_key(self, key: str) -> str:
        return hashlib.md5(key.encode("utf-8")).hexdigest()

    def _remember_deleted_key(self, key: str):
        if not key:
            return
        con = self._db_connect()
        con.execute(
            "INSERT OR REPLACE INTO deleted_rows(key, deleted_at) VALUES(?, CURRENT_TIMESTAMP)",
            (key,)
        )
        con.commit()
        # keep in-memory set in sync (used by populate_rows)
        if not hasattr(self, "_deleted_keys"):
            self._deleted_keys = set()
        self._deleted_keys.add(key)


    def hideEvent(self, ev):
        try:
            self._save_notes_to_db()
        except Exception:
            pass
        self._checkpoint(truncate=True, vacuum=False)   # <— add this line
        super().hideEvent(ev)
    # ---------- persistence helpers ----------
    def _ini_path(self) -> str:
        # parent is SupervisorWindow
        return self.parent()._notes_ini_path()
    def closeEvent(self, ev):
        # Save all rows on close
        try:
            for r in range(self.table.rowCount()):
                self._save_row_to_db(r)
            self._save_notes_to_db()
        except Exception:
            pass
        super().closeEvent(ev)
    def _on_table_context_menu(self, pos):
        if self.table.rowCount() == 0:
            return
        menu = QMenu(self)
        act_del = QAction("Delete selected row(s)", self)
        act_del.triggered.connect(self._delete_selected_rows)
        menu.addAction(act_del)
        menu.exec_(self.table.viewport().mapToGlobal(pos))

    def _delete_selected_rows(self):
        # Collect rows (unique, sorted descending so index doesn’t shift)
        sel = sorted({i.row() for i in self.table.selectionModel().selectedRows()}, reverse=True)
        if not sel:
            return

        # Optional confirmation
        try:
            from PyQt5.QtWidgets import QMessageBox
            if QMessageBox.question(self, "Delete rows",
                                    f"Delete {len(sel)} selected row(s) from the notes?",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
                return
        except Exception:
            pass

        # Remove from INI + table
        for row in sel:
            key = self._row_key_from_row(row)
            if key:
                self._delete_row_from_db(key)
                self._remember_deleted_key(key) 
            self.table.removeRow(row)

        # Rebuild in-memory index after deletions
        self._rebuild_row_index()

    def _row_key_from_row(self, row: int) -> str:
        """Read the unique row key we stored in the WS cell's UserRole."""
        it = self.table.item(row, 0)
        return (it.data(Qt.UserRole) if it else None) or ""
    def _find_tech_key_for_row(self, row: int) -> str:
        """Map a notes row (Station+WS) back to the tech_state key in the parent window.
        Accept a match if station matches and WS matches either the global st['ws'] or
        any per-match ws (m1/m2). If WS is blank, station match is enough.
        """
        sup = self.parent()
        if not sup or not hasattr(sup, "tech_state"):
            return ""

        # Station is not visible in a column; pull it (and ws) from our hidden row key
        key = self._row_key_from_row(row)
        try:
            station_from_key, _operator, _match_tag, ws = (key or "").split("|", 3)
        except Exception:
            station_from_key, ws = "", ""

        station = (station_from_key or "").strip()
        ws = (ws or "").strip()

        for k, st in (sup.tech_state or {}).items():
            st_station = (st.get("station") or "").strip()
            if st_station != station:
                continue

            # Collect every known WS for this tech: global + per-match
            ws_candidates = set()
            gws = (st.get("ws") or "").strip()
            if gws:
                ws_candidates.add(gws)
            try:
                matches = st.get("matches") or {}
                for mi in (1, 2):
                    mw = (matches.get(mi, {}) or {}).get("ws", "")
                    mw = (mw or "").strip()
                    if mw:
                        ws_candidates.add(mw)
            except Exception:
                pass

            # If row has no ws, station match is enough; else require it be in candidates
            if not ws or (not ws_candidates) or (ws in ws_candidates):
                return k

        return ""


        # Prefer the station embedded in our row key
        station = station_from_key or station
        for k, st in (sup.tech_state or {}).items():
            st_station = (st.get("station") or "").strip()
            st_ws      = (st.get("ws") or "").strip()
            if st_station == station and (not ws or ws == st_ws):
                return k
        return ""
    def _collect_reporting_lines_for_row(self, row: int):
        """Return the full reporting history for this row by merging DB + live."""
        # Parse key + match
        key_str = self._row_key_from_row(row)
        try:
            _station, _operator, match_tag, _ws = (key_str or "").split("|", 3)
            match_idx = int((match_tag or "M1").replace("M", "") or 1)
        except Exception:
            match_idx = 1

        # Read live (what’s currently in the right pane)
        live = self._collect_live_reporting_for_row(row)  # list[str]

        # Read DB snapshot (everything we’ve persisted so far)
        db_lines = []
        try:
            con = self._db_connect()
            cur = con.cursor()
            for r in cur.execute(
                "SELECT line FROM reporting WHERE key=? AND match=? ORDER BY id",
                (key_str, match_idx)
            ):
                ln = (r["line"] or "").strip()
                if ln:
                    db_lines.append(ln)
        except Exception:
            pass

        # Order-preserving union: all DB lines first, then any new live lines
        out, seen = [], set()
        for ln in (db_lines or []):
            s = (ln or "").strip()
            if s and s not in seen:
                out.append(s); seen.add(s)
        for ln in (live or []):
            s = (ln or "").strip()
            if s and s not in seen:
                out.append(s); seen.add(s)
        return out



    def _collect_live_reporting_for_row(self, row: int):
        """Collect only LIVE items from right-pane report_tree (no INI/DB fallback)."""
        sup = self.parent()
        if not sup or not hasattr(sup, "report_tree"):
            return []
        # Parse key + match
        key_str = self._row_key_from_row(row)
        try:
            _station, _operator, match_tag, _ws = (key_str or "").split("|", 3)
            match_idx = int((match_tag or "M1").replace("M", "") or 1)
        except Exception:
            match_idx = 1

        tech_key = self._find_tech_key_for_row(row)
        out = []
        if not tech_key:
            return out
        try:
            tree = sup.report_tree
            for i in range(tree.topLevelItemCount()):
                it = tree.topLevelItem(i)
                ud = it.data(0, Qt.UserRole) or {}
                if ud.get("key") == tech_key and int(ud.get("match", 0)) == match_idx:
                    out.append(it.text(0))
        except Exception:
            pass
        return out


    def _rebuild_row_index(self):
        """Rebuild self._rows_key_index after structural changes."""
        self._rows_key_index.clear()
        for r in range(self.table.rowCount()):
            key = self._row_key_from_row(r)
            if key:
                self._rows_key_index[key] = r

    def eventFilter(self, obj, ev):
        # Allow Delete key to remove selected rows
        try:
            from PyQt5.QtCore import QEvent
            from PyQt5.QtGui import QKeyEvent
            if obj is self.table and ev.type() == QEvent.KeyPress:
                if hasattr(ev, "key") and ev.key() in (Qt.Key_Delete, Qt.Key_Backspace):
                    self._delete_selected_rows()
                    return True
        except Exception:
            pass
        return super().eventFilter(obj, ev)

    def _row_key(self, station: str, operator: str, match: str, ws: str) -> str:
        # unique per (station, operator, match, ws)
        return f"{station}|{operator}|M{match}|{ws}".strip()
    def _supervisor_ini_path(self):
        # use the module-level path that already points at SupportingFiles\supervisor.ini
        return PATH_SUPERVISOR

    def _section_for_key(self, key: str) -> str:
        return f"row::{key}"

    # ---------- UI building helpers ----------
    def _append_empty_row(self, key: str) -> int:
        """Create a new row, store its unique key in WS cell's UserRole, and add unchecked checkboxes in A..J."""
        row = self.table.rowCount()
        self.table.insertRow(row)

        # Ensure items exist for first three columns so we can store the key
        for c in (0, 1, 2):
            if not self.table.item(row, c):
                self.table.setItem(row, c, QTableWidgetItem(""))

        # Store unique key inside WS cell
        ws_item = self.table.item(row, 0)
        ws_item.setData(Qt.UserRole, key)
        # Add the Report (+) button cell
        self._make_report_cell(row)

        # Add A..J as checkboxes
        for col in range(4, len(self.COLS)):
            self._make_checkbox(row, col)


        self._rows_key_index[key] = row
        return row
    def _merge_reporting_from_ini(self, key: str, match_idx: int, lines: list[str]):
        """Ensure the right-pane report_tree has these lines for (key, match_idx).
        Avoid dupes by checking existing texts."""
        sup = self.parent()
        if not sup or not hasattr(sup, "report_tree"):
            return
        tree = sup.report_tree

        # Build a set of existing texts for this (key, match)
        existing = set()
        for i in range(tree.topLevelItemCount()):
            it = tree.topLevelItem(i)
            ud = it.data(0, Qt.UserRole) or {}
            if ud.get("key") == key and int(ud.get("match", 0)) == match_idx:
                existing.add(it.text(0))

        from PyQt5.QtWidgets import QTreeWidgetItem
        for line in lines:
            line = (line or "").strip()
            if not line or line in existing:
                continue
            tli = QTreeWidgetItem([line])
            tli.setData(0, Qt.UserRole, {"key": key, "match": match_idx})
            tree.addTopLevelItem(tli)

    def _make_checkbox(self, row: int, col: int):
        from PyQt5.QtWidgets import QWidget, QCheckBox, QHBoxLayout
        wrapper = QWidget(self.table)
        chk = QCheckBox(wrapper)
        lay = QHBoxLayout(wrapper)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addStretch(); lay.addWidget(chk); lay.addStretch()
        self.table.setCellWidget(row, col, wrapper)
        # Save whenever a box changes
        chk.stateChanged.connect(lambda _s, r=row: (not self._loading) and self._save_row_to_db(r))
        return chk

    def _make_report_cell(self, row: int):
        from PyQt5.QtWidgets import QWidget, QPushButton, QHBoxLayout
        wrapper = QWidget(self.table)
        btn = QPushButton("+", wrapper)
        btn.setFixedWidth(28)
        lay = QHBoxLayout(wrapper)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addStretch(); lay.addWidget(btn); lay.addStretch()
        self.table.setCellWidget(row, 3, wrapper)

        # Store dialog on the button object so we can toggle it
        btn._report_dialog = None

        def _read_db_lines_for_row(_row: int):
            """Read saved reporting lines for this row from SQLite."""
            key_str = self._row_key_from_row(_row)
            try:
                _station, _operator, match_tag, _ws = (key_str or "").split("|", 3)
                match_idx = int((match_tag or "M1").replace("M", "") or 1)
            except Exception:
                match_idx = 1

            out = []
            try:
                con = self._db_connect()
                cur = con.cursor()
                for r in cur.execute(
                    "SELECT line FROM reporting WHERE key=? AND match=? ORDER BY id",
                    (key_str, match_idx)
                ):
                    ln = (r["line"] or "").strip()
                    if ln:
                        out.append(ln)
            except Exception:
                pass
            return out


        def _merge_lines(a, b):
            """Order-preserving union: keep all 'a', then add non-duplicates from 'b'."""
            out, seen = [], set()
            for ln in (a or []):
                s = (ln or "").strip()
                if s and s not in seen:
                    out.append(s); seen.add(s)
            for ln in (b or []):
                s = (ln or "").strip()
                if s and s not in seen:
                    out.append(s); seen.add(s)
            return out

        def open_or_close():
            # If dialog exists and visible => close
            if btn._report_dialog and btn._report_dialog.isVisible():
                try:
                    btn._report_dialog.close()
                finally:
                    btn.setText("+")
                return

            live_now = self._collect_reporting_lines_for_row(row)
            db_now   = _read_db_lines_for_row(row)
            merged   = _merge_lines(db_now, live_now)


            title = f"Reporting — {self._safe_item_text(row, 2) or 'Match'}"
            dlg = _ReportPopup(self, title=title)
            dlg.set_lines(merged if merged else [])
            btn.setText("–")
            btn._report_dialog = dlg

            # Save a snapshot immediately when the popup opens (append-only merge handled in _save_row_to_ini)
            try:
                self._save_row_to_db(row)
            except Exception:
                pass

            # Hook into the Reporting tree (right pane) to live-refresh & save
            rep_tree = getattr(self.parent(), "report_tree", None)
            model = rep_tree.model() if rep_tree else None

            if model:
                # capture strong refs to avoid late-binding issues
                def _refresh_and_save(*_args, _row=row, _dlg=dlg):
                    if not _dlg.isVisible():
                        return
                    try:
                        # 1) persist (append-only) current live lines to INI
                        self._save_row_to_db(_row)
                        live_latest = self._collect_reporting_lines_for_row(_row)
                        db_latest   = _read_db_lines_for_row(_row)
                        merged_now  = _merge_lines(db_latest, live_latest)
                        _dlg.set_lines(merged_now if merged_now else [])

                    except Exception:
                        pass
                try:
                    model.rowsInserted.connect(_refresh_and_save)
                    model.rowsRemoved.connect(_refresh_and_save)
                    model.dataChanged.connect(_refresh_and_save)
                except Exception:
                    pass

            def on_finished(_code):
                btn.setText("+")
                if model:
                    try: model.rowsInserted.disconnect(_refresh_and_save)
                    except Exception: pass
                    try: model.rowsRemoved.disconnect(_refresh_and_save)
                    except Exception: pass
                    try: model.dataChanged.disconnect(_refresh_and_save)
                    except Exception: pass
                # final persist on close
                try:
                    self._save_row_to_db(row)
                except Exception:
                    pass

            dlg.finished.connect(on_finished)
            dlg.show()
            dlg.raise_()

        # 🔗 connect the button
        btn.clicked.connect(open_or_close)
    # =========================
    # DB LOAD / SAVE HELPERS
    # =========================

    def _load_from_db(self):
        """Recreate UI from SQLite (general notes, tombstones, rows with checkboxes)."""
        self._loading = True
        self.table.setRowCount(0)
        self._rows_key_index.clear()

        con = self._db_connect()
        cur = con.cursor()

        # 1) general notes
        try:
            row = cur.execute("SELECT text FROM general_notes WHERE id=1").fetchone()
            txt = row["text"] if row else ""
        except Exception:
            txt = ""
        was_loading = self._loading
        self._loading = True
        self.note_edit.setPlainText(txt or "")
        self._loading = was_loading

        # 2) deleted/tombstones (store in-memory set)
        self._deleted_keys = set()
        try:
            for r in cur.execute("SELECT key FROM deleted_rows"):
                k = (r["key"] or "").strip()
                if k:
                    self._deleted_keys.add(k)
        except Exception:
            pass

        # 3) rows (skip tombstoned keys)
        try:
            rows = cur.execute("""
                SELECT key, station, operator, match, ws, home,
                    a,b,c,d,e,f,g,h,i,j
                FROM notes_rows
                ORDER BY operator, ws, match
            """).fetchall()
        except Exception:
            rows = []

        for r in rows:
            key = r["key"]
            if key in self._deleted_keys:
                continue

            row_idx = self._append_empty_row(key)
            self.table.item(row_idx, 0).setText(r["ws"] or "")
            self.table.item(row_idx, 1).setText(r["operator"] or "")
            self.table.item(row_idx, 2).setText(r["home"] or "")

            # restore a..j (columns start at 4 because col 3 is "Report")
            checks = [r["a"], r["b"], r["c"], r["d"], r["e"], r["f"], r["g"], r["h"], r["i"], r["j"]]
            for idx, val in enumerate(checks, start=4):
                chk = self._make_checkbox(row_idx, idx)
                chk.setChecked(bool(val))

        self._loading = False


    def _save_notes_to_db(self):
        """Persist right-side general notes."""
        con = self._db_connect()
        cur = con.cursor()
        txt = self.note_edit.toPlainText()
        cur.execute("INSERT INTO general_notes(id, text) VALUES(1, ?) "
                    "ON CONFLICT(id) DO UPDATE SET text=excluded.text, updated_at=CURRENT_TIMESTAMP",
                    (txt,))
        con.commit()


    def _save_row_to_db(self, row: int):
        """Upsert a single UI row into notes_rows + append reporting lines into reporting table."""
        if row < 0:
            return
        con = self._db_connect()
        cur = con.cursor()

        key = self.table.item(row, 0).data(Qt.UserRole)
        if not key:
            return

        # parse key back out (station|operator|M{match}|ws)
        try:
            station, operator, match_tag, ws = key.split("|", 3)
            match = int((match_tag or "M1").replace("M", "") or 1)
        except Exception:
            station = operator = ws = ""
            match = 1

        name = self._safe_item_text(row, 1) or operator
        home = self._safe_item_text(row, 2) or ""

        # collect checkbox states
        vals = []
        for offset in range(4, 14):  # 10 checkboxes
            w = self.table.cellWidget(row, offset)
            from PyQt5.QtWidgets import QCheckBox
            chk = w.findChild(QCheckBox) if w else None
            vals.append(1 if (chk and chk.isChecked()) else 0)

        cur.execute("""
            INSERT INTO notes_rows (key, station, operator, match, ws, home,
                                    a,b,c,d,e,f,g,h,i,j, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET
                station=excluded.station, operator=excluded.operator, match=excluded.match,
                ws=excluded.ws, home=excluded.home,
                a=excluded.a, b=excluded.b, c=excluded.c, d=excluded.d, e=excluded.e,
                f=excluded.f, g=excluded.g, h=excluded.h, i=excluded.i, j=excluded.j,
                updated_at=CURRENT_TIMESTAMP
        """, (key, station, name, match, ws, home, *vals))

        # append (de-dup) reporting lines for this row/match
        try:
            lines = [ln.strip() for ln in (self._collect_live_reporting_for_row(row) or []) if ln.strip()]
            for ln in lines:
                cur.execute("INSERT OR IGNORE INTO reporting (key, match, line) VALUES (?,?,?)",
                            (key, match, ln))
        except Exception:
            pass

        con.commit()


    def _delete_row_from_db(self, key: str):
        """Delete a row and tombstone it."""
        if not key:
            return
        con = self._db_connect()
        cur = con.cursor()
        cur.execute("DELETE FROM notes_rows WHERE key=?", (key,))
        cur.execute("INSERT OR REPLACE INTO deleted_rows(key, deleted_at) VALUES(?, CURRENT_TIMESTAMP)", (key,))
        con.commit()


    def _reset_notes(self):
        """
        Clear ONLY the notes data (rows + general notes + tombstones) in the DB.
        Then refresh from live tech_state.
        """
        con = self._db_connect()
        cur = con.cursor()
        # wipe tables (keep schema)
        cur.execute("DELETE FROM notes_rows")
        cur.execute("DELETE FROM general_notes")
        cur.execute("DELETE FROM deleted_rows")
        # keep reporting? If you want it cleared too, uncomment next line:
        cur.execute("DELETE FROM reporting")
        con.commit()
        self._checkpoint(truncate=True, vacuum=True)  # <— add here

        # 2) Clear UI state
        self._loading = True
        self.table.setRowCount(0)
        self._rows_key_index.clear()
        self.note_edit.clear()
        try:
            self._deleted_keys = set()
        except Exception:
            pass
        self._loading = False

        # 3) Re-populate from the parent’s live state
        parent = self.parent()
        if parent and hasattr(parent, "_gather_notes_columns"):
            try:
                self.populate_rows(parent._gather_notes_columns())
            except Exception:
                pass


    def _toggle_report_popup(self, row: int):
        """Open/close a modeless Reporting popup for this row."""
        # If already open → close it and flip button back to "+"
        dlg = self._report_popups.get(row)
        if dlg is not None:
            try:
                dlg.close()
            except Exception:
                pass
            self._report_popups.pop(row, None)
            self._set_report_button(row, "+")
            return

        # Create and show a new popup
        dlg = self._build_report_popup_for_row(row)
        if dlg is None:
            return
        self._report_popups[row] = dlg
        self._set_report_button(row, "–")
        dlg.show()
        dlg.raise_()

    def _set_report_button(self, row: int, text: str):
        """Utility: set '+' / '–' on the Report button in this row."""
        try:
            w = self.table.cellWidget(row, 3)  # column 3 = Report
            if not w:
                return
            from PyQt5.QtWidgets import QPushButton
            b = w.findChild(QPushButton)
            if b:
                b.setText(text)
        except Exception:
            pass

    def _build_report_popup_for_row(self, row: int):
        """
        Build a small modeless dialog that shows Reporting for this match.
        Step 1 = placeholder list; we'll wire real data next.
        """
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QListWidget, QPushButton
        from PyQt5.QtCore import Qt

        # Read visible fields for title context
        ws   = self._safe_item_text(row, 0)
        oper = self._safe_item_text(row, 1)
        home = self._safe_item_text(row, 2)

        dlg = QDialog(self)
        dlg.setWindowTitle(f"Reporting — WS {ws} — {oper} — {home}")
        dlg.setWindowFlags(dlg.windowFlags() | Qt.WindowStaysOnTopHint)
        dlg.resize(480, 360)

        lay = QVBoxLayout(dlg)
        title = QLabel(f"Reporting for WS {ws} — {home}")
        f = title.font(); f.setBold(True); title.setFont(f)
        lay.addWidget(title)

        lst = QListWidget(dlg)
        lst.addItem("This will show the match's Reporting entries here. (Wiring in next step.)")
        lay.addWidget(lst, 1)

        buttons = QHBoxLayout()
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(dlg.close)
        buttons.addStretch(1)
        buttons.addWidget(btn_close)
        lay.addLayout(buttons)

        # When user closes window (via X or Close), flip button back to '+'
        def _on_closed(*_):
            try:
                # find which row this dialog belonged to and clear it
                for r, d in list(self._report_popups.items()):
                    if d is dlg:
                        self._report_popups.pop(r, None)
                        self._set_report_button(r, "+")
                        break
            except Exception:
                pass

        dlg.finished.connect(_on_closed)
        return dlg


    def _safe_item_text(self, row: int, col: int) -> str:
        it = self.table.item(row, col)
        return it.text().strip() if it else ""

    # ---------- external API (called from SupervisorWindow) ----------
    def populate_rows(self, rows_from_parent: list):
        """
        rows_from_parent = [{station, operator, match, ws, home}, ...]
        Upsert:
          - if same (station, operator, match, ws) exists -> keep existing checkboxes
          - else append a new row and save it once
        """
        self._loading = True
        for r in rows_from_parent:
            station = r.get("station", "")
            operator = r.get("operator", "")
            match    = r.get("match", "")
            ws       = r.get("ws", "")
            home     = r.get("home", "")
            key = self._row_key(station, operator, match, ws)

            # NEW: don’t recreate rows the user deleted
            if hasattr(self, "_deleted_keys") and key in self._deleted_keys:
                continue
            if key in self._rows_key_index:
                row = self._rows_key_index[key]
                # update visible fields (do not touch checkboxes)
                self.table.item(row, 0).setText(ws)
                self.table.item(row, 1).setText(operator)
                self.table.item(row, 2).setText(home)
            else:
                row = self._append_empty_row(key)
                self.table.item(row, 0).setText(ws)
                self.table.item(row, 1).setText(operator)
                self.table.item(row, 2).setText(home)
                # Save the freshly added row (all boxes off)
                self._save_row_to_db(row)

        self._loading = False

class _ReportPopup(QDialog):
    def __init__(self, parent=None, title="Reporting"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(520, 420)
        lay = QVBoxLayout(self)
        self.list = QListWidget(self)
        lay.addWidget(self.list)

    def set_lines(self, lines):
        self.list.clear()
        if not lines:
            self.list.addItem("(no reporting for this match yet)")
            return
        for line in lines:
            self.list.addItem(line)

# ---------- Main Window ----------
class SupervisorWindow(QMainWindow):
    notes_update = pyqtSignal(list) 
    def __init__(self):
        super().__init__()
        self.setWindowTitle(WINDOW_TITLE)
        self.resize(1180, 640)
        self.setWindowIcon(QIcon("app_icon.ico"))
        # Queues/threads
        self.ui_queue = queue.Queue()
        self.server = ServerThread(HOST, PORT, self.ui_queue)
        self.server.start()

        self.timer_ping = QTimer(self)
        self.timer_ping.timeout.connect(self._schedule_probes)  # async, non-blocking
        self.timer_ping.start(15000)   # was 5000ms

        # --- UDP discovery: announce the Supervisor TCP port less often ---
        self._disco_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._disco_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        self._disco_timer = QTimer(self)
        self._disco_timer.timeout.connect(self._broadcast_discover)
        self._disco_timer.start(5000)  # send name beacon every 5s (not 30s)
        self._broadcast_discover()     # 👈 send one immediately on startup

        # --- async probe pool + per-IP backoff ---
        self._pool = ThreadPoolExecutor(max_workers=6)
        # backoff state: ip -> {"next": epoch_seconds, "backoff": seconds}
        self._ip_state = {ip: {"next": 0, "backoff": 0} for ip in TECH_IPS}
        # Track IPs from which we have seen inbound data (for keepalive)
        self._connected_ips = set()

        # State
        self.tech_state = {}     # key -> dict
        self._items_by_id = {}   # item_id (int) -> QTreeWidgetItem
        self._blink_on = False

        # persistent blink sets
        self._blink_tree_items = set()           # item_id(int) of rows that should blink (tech node + match node)
        self._blink_list_entries = set()         # tuples (key, match_idx, req_index) that should blink
        self._blink_colors = {}                  # tree item_id -> Qt.GlobalColor
        self._blink_entry_colors = {}            # (key,match,idx) -> Qt.GlobalColor (for chat rows)
        # Per-match mute state: (key, match_idx) -> bool
        self._muted_matches = {}
        
        self._current_selection = None  # (key, match_idx)
        self._req_item_index = {}       # (key, match_idx, req_idx) -> QTreeWidgetItem
        self._req_group_index = {} 
        self._blink_group_headers = set()          # set of (key, match, group_title)
        self._blink_group_colors = {}    
        self._report_groups = set()

        # Map (key, match_idx, group_title) -> {"item": str, "section": str}
        self._last_overdue = {}

                # Cards: widgets that should blink (actual way ahead of expected)
        self._blink_cards = set()

        # UI
        self._build_ui()
        self._rebuild_match_cards()   # first-time build of bottom cards
        self._save_timer = None  # NEW
        self._load_state()       # NEW

        # --- notify sound setup ---
        # --- notify sound setup ---
        # --- notify sound setup (silent; no status_lbl messages) ---
        self._last_sound_ts = 0
        self._sound = None
        self._notify_path = os.path.join(SUPPORT_DIR, "notify.wav")

        try:
            if os.path.exists(self._notify_path):
                self._sound = QSoundEffect(self)
                self._sound.setSource(QUrl.fromLocalFile(self._notify_path))
                self._sound.setLoopCount(1)
                self._sound.setMuted(False)
                self._sound.setVolume(0.9)

                # On status change, just ensure fallback on error; don't touch status label
                def _on_se_status():
                    try:
                        st = self._sound.status()
                    except Exception:
                        return
                    # PyQt5 uses Ready; if any error, disable so _play_notify() falls back
                    try:
                        loaded = bool(self._sound.isLoaded())
                    except Exception:
                        loaded = (st == QSoundEffect.Ready)
                    if st == QSoundEffect.Error:
                        self._sound = None  # fall back silently

                self._sound.statusChanged.connect(_on_se_status)
            else:
                self._sound = None
        except Exception:
            self._sound = None

                # timers
        # timers
        self.timer_drain = QTimer(self); self.timer_drain.timeout.connect(self._drain); self.timer_drain.start(200)   # was 80ms
        self.timer_prune = QTimer(self); self.timer_prune.timeout.connect(self._prune_stale); self.timer_prune.start(3000)
        self.timer_blink = QTimer(self); self.timer_blink.timeout.connect(self._blink_tick); self.timer_blink.start(900)   # was 600ms

                # Debounce heavy card rebuilds (prevents UI pauses)
        self._cards_rebuild_timer = QTimer(self)
        self._cards_rebuild_timer.setSingleShot(True)
        self._cards_rebuild_timer.timeout.connect(self._rebuild_match_cards)


        # with this
        if ENABLE_LOG:
            self._ensure_log_header()
        self._set_info("Starting…")
        self.setStyleSheet("""
            QWidget { font-size: 13px; }
            QTreeWidget::item:selected {
                background: #e0f2fe;
                color: black;
            }
            QTreeWidget::item { padding:4px; }
        """)
        self._schedule_save_state()
    def _supervisor_ini_path(self):
        # Points to SupportingFiles\supervisor.ini (module-level constant)
        return PATH_SUPERVISOR

    def _play_notify(self, *, force: bool = False):
        """Play a short notification when a new blink starts (rate-limited)."""
        now = time.time()
        if not force and (now - getattr(self, "_last_sound_ts", 0) < 1.0):
            return
        self._last_sound_ts = now

        try:
            if (self._sound is not None and self._sound.source().isValid()):
                try:
                    if self._sound.isLoaded():          # PyQt6 API (present in some builds)
                        self._sound.play()
                        return
                except Exception:
                    if self._sound.status() == QSoundEffect.Ready:   # PyQt5
                        self._sound.play()
                        return
        except Exception:
            pass

        # Fallbacks
        try:
            # If we have a wav and we're on Windows, try winsound
            if winsound and os.path.exists(getattr(self, "_notify_path", "")):
                winsound.PlaySound(self._notify_path, winsound.SND_FILENAME | winsound.SND_ASYNC)
                return
        except Exception:
            pass

        try:
            QApplication.beep()
        except Exception:
            pass
    def _with_sup_stamp(self, line: str) -> str:
        """Append supervisor identity so Tech can show who sent it."""
        try:
            sup_name = CONF.get("name", "Supervisor")
            if "FromSupName=" not in line:
                line = f"{line} FromSupName='{sup_name}'"
        except Exception:
            pass
        return line

    def _maybe_play_notify(self, key: str, match_idx: int, *, force: bool = False):
        """Play notify sound only if this match is not muted."""
        if not self._muted_matches.get((key, match_idx), False):
            self._play_notify(force=force)

    # ---------- UI ----------
    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root); layout.setContentsMargins(8,8,8,8); layout.setSpacing(8)

        # --- Top bar with title and Reset
        top = QHBoxLayout()
        banner = QLabel(WINDOW_TITLE)
        f = QFont(); f.setPointSize(14); f.setBold(True); banner.setFont(f)
        banner.setStyleSheet("QLabel{background:#dc2626;color:#fff;padding:10px;border-radius:8px;}")
        top.addWidget(banner, 1)
        self.btn_notes = QPushButton("Supervisor notes")
        self.btn_notes.setToolTip("Open Supervisor notes (A–J rows; stations in columns)")
        self.btn_notes.clicked.connect(self.open_supervisor_notes)
        top.addWidget(self.btn_notes)
        self.btn_reset_all = QPushButton("Reset")
        self.btn_reset_all.setToolTip("Clear saved state and current view")
        self.btn_reset_all.clicked.connect(self._reset_everything)
        top.addWidget(self.btn_reset_all)
        self.btn_refresh = QPushButton("Refresh")
        self.btn_refresh.setToolTip("Recompute & redraw from current state (F5)")
        self.btn_refresh.clicked.connect(self._refresh_view)
        top.addWidget(self.btn_refresh)
        self.btn_send_all = QPushButton("Send to all")
        self.btn_send_all.setToolTip("Send a message to all connected techs")
        self.btn_send_all.clicked.connect(self._send_broadcast_message)
        top.addWidget(self.btn_send_all)

        try:
            from PyQt5.QtWidgets import QShortcut
            from PyQt5.QtGui import QKeySequence
            QShortcut(QKeySequence("F5"), self, activated=self._refresh_view)
        except Exception:
            pass
        layout.addLayout(top)

        split = QSplitter(Qt.Horizontal)
        layout.addWidget(split, 1)

        # --- Bottom horizontal cards strip (scrollable) ---
        self.cards_area = QScrollArea()
        self.cards_area.setWidgetResizable(True)
        self.cards_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.cards_area.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.cards_area.setFixedHeight(160)

        self.cards_inner = QWidget()
        self.cards_row = QHBoxLayout(self.cards_inner)
        self.cards_row.setContentsMargins(6, 6, 6, 6)
        self.cards_row.setSpacing(8)
        self.cards_area.setWidget(self.cards_inner)
        layout.addWidget(self.cards_area, 0)

        # --- Left tree ---
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Tech / Match", "Teams", "KO", "Hours to KO", "MD-1", "Request"])
        self.COL_TECH, self.COL_TEAM, self.COL_KO, self.COL_KOHRS, self.COL_MD1, self.COL_REQ = range(6)
        self.tree.setColumnWidth(self.COL_TECH, 260)
        self.tree.setColumnWidth(self.COL_TEAM, 240)
        self.tree.setColumnWidth(self.COL_KO, 70)
        self.tree.setColumnWidth(self.COL_KOHRS, 110)
        self.tree.setColumnWidth(self.COL_MD1, 80)
        self.tree.setColumnWidth(self.COL_REQ, 80)
        self.tree.setAlternatingRowColors(True)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._on_tree_context_menu)
        split.addWidget(self.tree)

        # --- Right container ---
        right = QWidget()
        rv = QVBoxLayout(right); rv.setContentsMargins(0,0,0,0)

        # ---- Right pane: grid layout ----
        grid = QGridLayout()
        rv.addLayout(grid, 1)

        # ========== Top-left: CHECKS & CHECKLIST ==========
        checks_panel = QWidget()
        checksv = QVBoxLayout(checks_panel); checksv.setSpacing(6)
        checksv.addWidget(QLabel("Checks & Checklist"))
        self.checks_tree = QTreeWidget()
        self.checks_tree.setHeaderHidden(True)
        self.checks_tree.setRootIsDecorated(True)
        self.checks_tree.setColumnCount(1)
        self.checks_tree.setColumnWidth(0, 1000)
        checksv.addWidget(self.checks_tree, 1)

        # ========== Top-right: Requests & Messages ==========
        req_panel = QWidget()
        reqv = QVBoxLayout(req_panel); reqv.setSpacing(6)
        reqv.addWidget(QLabel("Requests & Messages"))
        self.req_tree = QTreeWidget()
        self.req_tree.setHeaderHidden(True)
        self.req_tree.setRootIsDecorated(True)
        self.req_tree.setColumnCount(1)
        self.req_tree.setColumnWidth(0, 1000)
        self.req_tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.req_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.req_tree.customContextMenuRequested.connect(self._on_req_context_menu)
        self.req_tree.installEventFilter(self)
        reqv.addWidget(self.req_tree, 1)

        # Approve/Deny row
        row = QHBoxLayout()
        self.btn_approve = QPushButton("Approve selected"); self.btn_approve.setEnabled(False)
        self.btn_approve.clicked.connect(self._approve_selected); row.addWidget(self.btn_approve)
        self.btn_deny = QPushButton("Deny"); self.btn_deny.setEnabled(False)
        self.btn_deny.clicked.connect(self._deny_selected); row.addWidget(self.btn_deny)
        self.btn_approve.hide(); self.btn_deny.hide()
        row.addStretch(1)
        reqv.addLayout(row)

        # Notes & messages
        noterow = QHBoxLayout()
        noterow.addWidget(QLabel("Add note:"))
        self.note_entry = QLineEdit(); noterow.addWidget(self.note_entry, 1)
        self.btn_add_note = QPushButton("Add"); self.btn_add_note.clicked.connect(self._add_note)
        noterow.addWidget(self.btn_add_note)
        reqv.addLayout(noterow)
        self.note_entry.returnPressed.connect(self._add_note)

        msgrow = QHBoxLayout()
        msgrow.addWidget(QLabel("Send message:"))
        self.msg_entry = QLineEdit(); msgrow.addWidget(self.msg_entry, 1)
        self.btn_send = QPushButton("Send"); self.btn_send.setEnabled(False)
        self.btn_send.clicked.connect(self._send_message); msgrow.addWidget(self.btn_send)
        reqv.addLayout(msgrow)
        self.msg_entry.returnPressed.connect(self._send_message)

        self.status_lbl = QLabel(""); self.status_lbl.setStyleSheet("color:#0f766e;")
        reqv.addWidget(self.status_lbl)

        # Place top cells
        grid.addWidget(checks_panel, 0, 0)
        grid.addWidget(req_panel, 0, 1)

        # ========== Bottom: Reporting ==========
        rep_panel = QWidget()
        repv = QVBoxLayout(rep_panel); repv.setSpacing(6)
        repv.addWidget(QLabel("Reporting"))
        self.report_tree = QTreeWidget()
        self.report_tree.setHeaderHidden(True)
        self.report_tree.setRootIsDecorated(True)
        self.report_tree.setColumnCount(1)
        self.report_tree.setColumnWidth(0, 1000)
        repv.addWidget(self.report_tree, 1)

        rep_note_row = QHBoxLayout()
        rep_note_row.addWidget(QLabel("Add note:"))
        self.report_note_entry = QLineEdit(); rep_note_row.addWidget(self.report_note_entry, 1)
        self.report_btn_add_note = QPushButton("Add")
        self.report_btn_add_note.clicked.connect(self._add_report_note)
        rep_note_row.addWidget(self.report_btn_add_note)
        repv.addLayout(rep_note_row)
        self.report_note_entry.returnPressed.connect(self._add_report_note)

        rep_msg_row = QHBoxLayout()
        rep_msg_row.addWidget(QLabel("Send message:"))
        self.report_msg_entry = QLineEdit(); rep_msg_row.addWidget(self.report_msg_entry, 1)
        self.report_btn_send = QPushButton("Send"); self.report_btn_send.setEnabled(False)
        self.report_btn_send.clicked.connect(self._send_report_message)
        self.report_btn_send.clicked.connect(self._send_report_to_tech)
        rep_msg_row.addWidget(self.report_btn_send)
        repv.addLayout(rep_msg_row)
        self.report_msg_entry.returnPressed.connect(self._send_report_to_tech)

        self.report_status_lbl = QLabel("")
        repv.addWidget(self.report_status_lbl)

        grid.addWidget(rep_panel, 1, 0, 1, 2)

        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.setRowStretch(0, 3)
        grid.setRowStretch(1, 2)

        # add right side to splitter
        split.addWidget(right)
        split.setSizes([700, 440])

        # Signals
        self.tree.currentItemChanged.connect(self._on_tree_select)
        self.req_tree.itemClicked.connect(self._on_request_clicked)
        self.req_tree.itemChanged.connect(self._on_req_item_changed)
    def _match_title_for(self, key: str, match_idx: int) -> str:
        """Human label for a reporting group (per match)."""
        st = self.tech_state.get(key, {}) or {}
        station  = (st.get("station") or "").strip()
        operator = (st.get("operator") or "").strip()
        m        = (st.get("matches") or {}).get(match_idx, {}) or {}
        teams    = (m.get("teams") or "").strip()
        ws       = (m.get("ws") or st.get("ws") or "").strip()
        ko       = (m.get("ko") or "").strip()
        return f"{station} — {operator} — Match {match_idx} — WS {ws} — {teams} — KO {ko}"

    def _ensure_report_group(self, key: str, match_idx: int):
        """
        We no longer create visible group headers. We just track which (key, match)
        pairs have reporting items. Keep this as a set; if it's ever a dict from
        older code, migrate it on the fly.
        """
        rg = getattr(self, "_report_groups", None)
        if rg is None:
            self._report_groups = set()
        elif isinstance(rg, dict):
            # Migrate old dict {(key,match): ...} -> set of (key,match)
            try:
                self._report_groups = set(rg.keys())
            except Exception:
                self._report_groups = set()
        elif not isinstance(rg, set):
            self._report_groups = set()

        self._report_groups.add((key, match_idx))
        return None  # no visible header anymore

    def _send_report_to_tech(self):
        """
        Send a reporting message from Supervisor → Tech for the currently selected match.
        Sends: MESSAGE: Match=<n> kind=REPORT Text='<text>' FromSupName='<name>'
        """
        try:
            cur = self.tree.currentItem()
            if not cur:
                self.report_status_lbl.setText("Select a match first.")
                return

            key = cur.data(0, Qt.UserRole)
            st  = self.tech_state.get(key)
            if not st:
                self.report_status_lbl.setText("Unknown tech selected.")
                return

            # are we on a match node?
            mi = None
            for idx in (1, 2):
                if st["items"].get(f"m{idx}") is cur:
                    mi = idx
                    break
            if mi is None:
                self.report_status_lbl.setText("Select Match 1 or Match 2 to send.")
                return

            ip = (st.get("ip", "") or "").strip()
            if not ip:
                self.report_status_lbl.setText("No IP for this tech; cannot send.")
                return

            # ✅ read the correct widget
            txt = (self.report_msg_entry.text() or "").strip()
            if not txt:
                self.report_status_lbl.setText("Type a message to send.")
                return

            # include supervisor name
            msg = f"MESSAGE: Match={mi} kind=REPORT Text='{txt}'"
            msg = self._with_sup_stamp(msg)

            ok, err = self._send_to_tech(ip, msg)
            if ok:
                self.report_status_lbl.setText("Message queued in Reporting.")
                # mirror it locally
                ts = datetime.now().strftime("%H:%M:%S")
                line = f"[{ts}] MSG — {txt}"
                tli = QTreeWidgetItem([line])
                tli.setData(0, Qt.UserRole, {"key": key, "match": mi})
                self.report_tree.addTopLevelItem(tli)
                self.report_tree.scrollToItem(tli)
                self.report_msg_entry.clear()
            else:
                self.report_status_lbl.setText(f"Failed to send report message: {err}")
        except Exception as e:
            self.report_status_lbl.setText(f"Error sending report: {e}")

    def _schedule_cards_rebuild(self, delay_ms: int = 150):
        """Coalesce multiple updates and rebuild cards once."""
        try:
            self._cards_rebuild_timer.start(delay_ms)
        except Exception:
            # If timer not yet created, fall back to immediate rebuild
            self._rebuild_match_cards()
    def _add_report_note(self):
        txt = (self.report_note_entry.text() or "").strip()
        if not txt or not self._current_selection:
            return
        key, match_idx = self._current_selection
        self._ensure_report_group(key, match_idx)
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        item = QTreeWidgetItem([f"[{ts}] NOTE — {txt}"])
        item.setData(0, Qt.UserRole, {"key": key, "match": match_idx})
        self.report_tree.addTopLevelItem(item)
        self.report_tree.scrollToItem(item)

        self.report_note_entry.clear()
        self.report_status_lbl.setText("Note added to Reporting.")

    def _send_report_message(self):
        txt = (self.report_msg_entry.text() or "").strip()
        if not txt or not self._current_selection:
            return
        key, match_idx = self._current_selection
        self._ensure_report_group(key, match_idx)
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        item = QTreeWidgetItem([f"[{ts}] MSG — {txt}"])
        item.setData(0, Qt.UserRole, {"key": key, "match": match_idx})
        self.report_tree.addTopLevelItem(item)
        self.report_tree.scrollToItem(item)
        self.report_msg_entry.clear()
        self.report_status_lbl.setText("Message queued in Reporting.")


    def _broadcast_discover(self):
        """Broadcast our TCP listen port + supervisor name so Tech clients can push their state back."""
        try:
            sup_name = CONF.get("name", "Supervisor")
            msg = f"DISCOVER_SUP port={PORT} name={sup_name}".encode("utf-8")
            # Techs are listening on their ACK UDP port (same numeric value as TCP ACK)
            self._disco_sock.sendto(msg, ("255.255.255.255", ACK_PORT))
        except Exception:
            pass
    def open_supervisor_notes(self):
        if not hasattr(self, "notes_dialog"):
            self.notes_dialog = SupervisorNotesDialog(self)
            self.notes_update.connect(self.notes_dialog.populate_rows)
        self.notes_dialog.reload_headers_from_supervisor_ini()   # NEW
        # initial fill (also merges with what was loaded from INI)
        self.notes_dialog.populate_rows(self._gather_notes_columns())
        self.notes_dialog.show()
        self.notes_dialog.raise_()


    def _notes_ini_path(self) -> str:
        """Get the path for supervisor_notes.ini from supervisor.ini:
        [Supervisor]
        notes_ini = <path>   # or 'notes_path'
        - expands ~ and %ENV%
        - if relative, resolves relative to the folder that contains supervisor.ini
        - auto-creates the parent directory
        """
        import os
        from configparser import ConfigParser

        # default fallback
        fallback = os.path.join(SUPPORT_DIR, "supervisor_notes.ini")

        try:
            parser = ConfigParser(inline_comment_prefixes=(";", "#"))
            parser.read(PATH_SUPERVISOR, encoding="utf-8")
            sec = "Supervisor"
            raw = ""
            if parser.has_section(sec):
                if parser.has_option(sec, "notes_ini"):
                    raw = parser.get(sec, "notes_ini", fallback="").strip()
                elif parser.has_option(sec, "notes_path"):
                    raw = parser.get(sec, "notes_path", fallback="").strip()

            if not raw:
                return fallback

            # expand env and ~
            p = os.path.expandvars(os.path.expanduser(raw))
            # resolve relative to supervisor.ini directory
            if not os.path.isabs(p):
                base = os.path.dirname(PATH_SUPERVISOR)
                p = os.path.normpath(os.path.join(base, p))
            # ensure parent dir exists
            os.makedirs(os.path.dirname(p), exist_ok=True)
            return p
        except Exception:
            return fallback




    def _gather_notes_columns(self):
        """
        Build rows for the Supervisor notes grid.
        Returns list of dicts with: station, operator, match, ws, home
        (one row per (station, match) that has teams)
        """
        rows = []
        for key, st in (self.tech_state or {}).items():
            station  = (st.get("station") or "").strip()
            operator = (st.get("operator") or "").strip()
            matches  = (st.get("matches")  or {})  # {1:{...}, 2:{...}}

            for mi in (1, 2):
                m = matches.get(mi) or {}
                teams = (m.get("teams") or "").strip()
                if not teams:
                    continue
                home = teams.split(" vs ")[0].strip() if " vs " in teams else teams
                ws   = (m.get("ws") or st.get("ws") or "").strip()
                rows.append({
                    "station":  station,
                    "operator": operator,
                    "match":    str(mi),
                    "ws":       ws,
                    "home":     home,
                })

        return rows


    def _on_card_clicked(self, key: str, mi: int):
        """When a match card is clicked: select that match’s checklist."""
        try:
            self._ensure_nodes(key)
            st = self.tech_state.get(key, {})
            it = (st.get("items") or {}).get(f"m{mi}")
            if it:
                self.tree.setCurrentItem(it)
                self.tree.scrollToItem(it)
        except Exception:
            pass

        # ---------- Logging ----------
    def _ensure_log_header(self):
        if not ENABLE_LOG:
            return
        if not os.path.exists(LOG_PATH):
            try:
                with open(LOG_PATH, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow([
                        "ts_iso","ts_hms","station","operator","ip","match",
                        "direction","type","text","item","section","sender",
                        "approved","approved_ts_iso"
                    ])
            except Exception:
                pass


    def _parse_ko_dt(self, ko_str: str, ko_date: str):
        """Return a datetime for KO using HH:MM and YYYY-MM-DD; None if bad."""
        try:
            hh, mm = map(int, (ko_str or "").split(":", 1))
            d = datetime.strptime((ko_date or "").strip(), "%Y-%m-%d").date() if ko_date else date.today()
            return datetime.combine(d, datetime.min.time().replace(hour=hh, minute=mm))
        except Exception:
            return None

    def _fmt_hours_to_ko(self, ko_dt):
        """Return strings like 'in 5h 23m', 'in 40m', or '1h 12m past KO'."""
        if not ko_dt:
            return ""
        diff = ko_dt - datetime.now()
        total = int(diff.total_seconds())
        past = total < 0
        total = abs(total)

        h, rem = divmod(total, 3600)
        m, _ = divmod(rem, 60)

        if not past:
            if h == 0 and m == 0:
                return "now"
            if h == 0:
                return f"in {m}m"
            return f"in {h}h {m}m" if m else f"in {h}h"
        else:
            if h == 0 and m == 0:
                return "now"
            if h == 0:
                return f"{m}m past KO"
            return f"{h}h {m}m past KO" if m else f"{h}h past KO"
    def _expected_pct_for_match(self, key: str, mi: int):
        """
        Returns (expected_pct:int, label:str) based on hour-bucket cutoffs.
        Rules:
          - Before KO-6h: expected = 0%, label = "KO-6h"
          - Between KO-6h and KO-5h: expected = MD-1 + 6h bucket
          - Between KO-5h and KO-4h: expected = MD-1 + 6h + 5h
          - ...
          - Between KO-2h and KO-1h: expected = MD-1 + 6h + 5h + 4h + 3h + 2h
        Only items whose section maps to MD-1 or an 'N hours before KO' bucket (N=1..6)
        participate in expected%. Others are ignored for the expected calculation.
        """
        st = self.tech_state.get(key, {})
        m  = (st.get("matches") or {}).get(mi, {}) or {}
        ko_dt = self._parse_ko_dt(m.get("ko", ""), m.get("ko_date", ""))
        if not ko_dt:
            return (None, "—")

        now = datetime.now()
        # Determine which bucket "end" we are in front of
        # Choose cutoff hour H in {6,5,4,3,2,1}; and label "KO-Hh".
        # Use the *current hour bucket* (ceil) so 4h51m -> KO-5h
        hours_to_ko = (ko_dt - now).total_seconds() / 3600.0
        if hours_to_ko > 6:
            cutoff_h = 6                 # before the 6h window -> show KO-6h
        elif hours_to_ko <= 0:
            cutoff_h = 0                 # at/after KO -> everything due
        else:
            cutoff_h = int(math.ceil(hours_to_ko))
            cutoff_h = max(1, min(6, cutoff_h))  # clamp to [1..6]

        label = "KO" if cutoff_h == 0 else f"KO-{cutoff_h}h"


        # Map each item to a bucket: 24 (MD-1) or 1..6
        def _bucket_for_section(sec: str) -> int | None:
            s = (sec or "").lower().strip()

            # MD-1
            if any(x in s for x in ("matchday -1", "matchday-1", "md-1", "md1", "day -1", "day-1")):
                return 24

            # NEW: during KO / post match buckets
            if "during ko" in s or "during kickoff" in s:
                return 0          # treat as “KO window”
            if "post match" in s or "post-match" in s or "post ko" in s:
                return -1         # treat as after KO

            # Hourly buckets (1..6 hours before KO)
            mhr = re.search(r"(\d+)\s*hour", s)
            if mhr:
                try:
                    h = int(mhr.group(1))
                    if 1 <= h <= 6:
                        return h
                except Exception:
                    pass
            return None


        # Collect items with recognized buckets
        items = []
        for rec in (m.get("requests") or []):
            t = (rec.get("type") or rec.get("tag") or "").upper()
            if t not in ("UPDATE","DAY1","D1","OVERDUE","NOT_POSSIBLE","EARLY_MARK"):
                continue
            name = (rec.get("item") or "").strip().lower()
            if not name:
                continue
            b = _bucket_for_section(rec.get("section",""))
            if b is None:
                continue
            items.append((name, b))

        if not items:
            return (0, label)

        # Unique by item name, keep the *earliest* (strictest) bucket if duplicates
        item_bucket = {}
        for name, b in items:
            prev = item_bucket.get(name)
            if prev is None:
                item_bucket[name] = b
            else:
                # MD-1(24) is earlier than any hour bucket; lower hour means *later*,
                # so choose min() across numeric hours except treat 24 as "earliest".
                if b == 24 or (prev != 24 and b < prev):
                    item_bucket[name] = b

        # Compute expected set at current cutoff:
        # include MD-1 (24) always; include all hour buckets >= cutoff_h and <= 6
        total = len(item_bucket)
        if total == 0:
            return (0, label)

        expected_names = set()
        for nm, b in item_bucket.items():
            if b == 24:
                # MD-1 counts only at/after KO-6h cutoff
                if cutoff_h <= 6:
                    expected_names.add(nm)
            elif cutoff_h == 0:
                # past last hourly boundary -> everything (1..6) counts
                expected_names.add(nm)
            else:
                # bucket hours run 6..1; include any bucket with hour >= cutoff_h
                if 1 <= b <= 6 and b >= cutoff_h:
                    expected_names.add(nm)

        # Special case: before KO-6h -> expected 0%
        if now < ko_dt - timedelta(hours=6):
            return (0, "KO-6h")

        # return how many items should be done by the current cutoff,
        # we'll scale it to the card's total later so denominators match
        due_count = len(expected_names)
        return (due_count, label)



    def _actual_done_total_for_match(self, key: str, mi: int):
        """Return (done, total) across unique UPDATE/D1 items for the cards."""
        st = self.tech_state.get(key, {})
        m  = (st.get("matches") or {}).get(mi, {}) or {}
        seen = {}
        for r in (m.get("requests") or []):
            rtype = (r.get("type") or r.get("tag") or "").upper()
            if rtype not in ("UPDATE","DAY1","D1","OVERDUE"):
                continue
            name = (r.get("item") or "").strip().lower()
            if not name:
                continue
            row_done = False
            state = (r.get("state") or "").upper()
            if state in ("ON","DONE","OK","COMPLETED","APPROVED"):
                row_done = True
            try:
                rp = r.get("progress")
                if rp is not None:
                    rp = int(str(rp).rstrip("%"))
                    if rp >= 100:
                        row_done = True
            except Exception:
                pass
            prev = seen.get(name, False)
            seen[name] = prev or row_done
        total = len(seen)
        done = sum(1 for v in seen.values() if v)
        return done, total

    def _stop_card_blink(self, card: QFrame):
        """Stop red blinking for this match card and restore base style."""
        if not card:
            return
        # Remove from the blinking set
        if hasattr(self, "_blink_cards"):
            self._blink_cards.discard(card)

        # Restore the base (non-blinking) style for cards
        base = """
            QFrame#matchCard {
                background: #f8fafc;
                border: 1px solid #e5e7eb;
                border-radius: 10px;
            }
            QLabel[role="title"] { font-weight: 700; }
            QLabel[role="sub"] { color: #000000; }
        """
        # keep the red border if it was flagged (optional — delete this if you want border to reset too)
        if card.property("flagged") in (True, "true"):
            base = base.replace("1px solid #e5e7eb", "2px solid #ef4444")

        try:
            card.setStyleSheet(base)
        except RuntimeError:
            pass

    def _build_one_card(self, key: str, mi: int, ws: str, title: str, progress: int, done: int, total: int,
                    ko_str: str, hrs_to_ko: str,
                    expected_pct: int | None, expected_label: str,
                    flagged: bool, *, is_remi: bool = False) -> QWidget:

        card = QFrame()
        card.setObjectName("matchCard")

        # NEW: set dynamic property before stylesheet so the rule applies immediately
        if is_remi:
            card.setProperty("remi", True)

        card.setStyleSheet("""
            QFrame#matchCard {
                background: #f8fafc;
                border: 1px solid #111827;        /* was #e5e7eb */
                border-radius: 10px;
            }
            /* REMI tint (light orange) */
            QFrame#matchCard[remi="true"] {
                background: #faca8e;
                border: 1px solid #111827;        /* was #f59e0b */
            }
            QLabel[role="title"] { font-weight: 700; }
            QLabel[role="sub"]   { color: #000000; }
            /* Keep flagged red border strongest */
            QFrame#matchCard[flagged="true"] {
                border: 2px solid #ef4444;
            }
        """)


        card.setFixedWidth(230)
        v = QVBoxLayout(card); v.setContentsMargins(10,10,10,10); v.setSpacing(6)

        # --- Title row with WS pill (white bg, black text) -----------------
        title_row = QHBoxLayout()

        lbl_title = QLabel(title)
        lbl_title.setProperty("role", "title")
        lbl_title.setWordWrap(True)
        title_row.addWidget(lbl_title, 1)

        ws_text = (ws or "").strip() or "—"
        ws_pill = QLabel(f"WS {ws_text}")
        ws_pill.setAlignment(Qt.AlignCenter)
        ws_pill.setStyleSheet(
            "QLabel{background:#ffffff;color:#000000;"
            "border:1px solid #111827;border-radius:11px;"
            "padding:2px 10px;font-weight:700;}"
        )
        ws_pill.setFixedHeight(22)
        title_row.addSpacing(8)
        title_row.addWidget(ws_pill, 0, Qt.AlignRight)

        v.addLayout(title_row)

        # --- Progress -------------------------------------------------------
        bar = QProgressBar()
        try:
            bar.setTextVisible(False)
        except Exception:
            pass
        bar.setRange(0, 100)
        bar.setValue(0 if progress is None else max(0, min(100, int(progress))))
        v.addWidget(bar)

        lbl_mid = QLabel(f"{0 if progress is None else progress}%    {done} / {total} done")
        lbl_mid.setProperty("role", "sub")
        lbl_mid.setWordWrap(True)
        v.addWidget(lbl_mid)

        elab = expected_label or "now"
        lbl_exp = QLabel(f"exp {expected_pct}% by {elab}" if expected_pct is not None else f"exp --% by {elab}")
        lbl_exp.setProperty("role", "sub")
        lbl_exp.setWordWrap(True)
        v.addWidget(lbl_exp)

        # --- Bottom meta (no WS here anymore) ------------------------------
        lbl_bottom = QLabel(f"KO {ko_str or '--:--'}   |   {hrs_to_ko or ''}")
        lbl_bottom.setProperty("role", "sub")
        lbl_bottom.setWordWrap(True)
        v.addWidget(lbl_bottom)

        if flagged:
            card.setProperty("flagged", True)
            # Re-apply stylesheet so flagged rule takes effect if property set post-style
            card.setStyleSheet(card.styleSheet())

        # Click: stop card blink and open the match
        card.setCursor(Qt.PointingHandCursor)
        def _click(ev, c=card, k=key, m=mi):
            try:
                self._stop_card_blink(c)
            except Exception:
                pass
            self._on_card_clicked(k, m)
        card.mousePressEvent = _click

        return card


    def _clear_cards(self):
        if not hasattr(self, "cards_row"):
            return
        while self.cards_row.count():
            item = self.cards_row.takeAt(0)
            w = item.widget()
            if w:
                self._blink_cards.discard(w)   # <- add this line
                w.deleteLater()


    def _rebuild_match_cards(self):
        if not hasattr(self, "cards_row"):
            return
        self._clear_cards()

        for key, st in self.tech_state.items():
            tech_name = (st.get("operator") or st.get("station") or "Tech").strip()
            for mi in (1, 2):
                m = st["matches"].get(mi, {})
                has_match = bool(m.get("teams") or m.get("day") or m.get("ko") or m.get("ko_date"))
                if not has_match:
                    continue

                progress = m.get("progress")
                try: progress = int(progress) if progress is not None else None
                except Exception: progress = None
                done, total = self._actual_done_total_for_match(key, mi)
                ko_str = m.get("ko","")
                ko_dt  = self._parse_ko_dt(ko_str, m.get("ko_date",""))
                hrs    = self._fmt_hours_to_ko(ko_dt)

                # expected: count of due items (MD-1 ∪ hourly up to cutoff), scaled to same total
                due_count, expected_label = self._expected_pct_for_match(key, mi)
                if total and due_count is not None:
                    expected_pct = int(round(due_count * 100.0 / total))
                else:
                    expected_pct = None

                flagged = False
                if progress is not None and expected_pct is not None:
                    flagged = (progress > expected_pct + 15)

                title = f"{tech_name} — Match {mi}"
                ws = (m.get("ws") or "").strip()
                is_remi = (m.get("remi", "").strip().lower() in ("yes", "true", "1"))  # ← add

                card = self._build_one_card(
                    key, mi, ws,
                    title, progress, done, total, ko_str, hrs,
                    expected_pct, expected_label, flagged,
                    is_remi=is_remi,  # ← pass the flag
                )



                self.cards_row.addWidget(card)

                if flagged:
                    self._blink_cards.add(card)

        self.cards_row.addStretch(1)
        # keep only live widgets
        self._blink_cards = {c for c in self._blink_cards if c and c.parent() is self.cards_inner}


    def _log(self, *, st=None, ip="", match="", direction="", typ="", text="", item="", section="", sender="", ts=None, approved=False, approved_ts=None):
        if not ENABLE_LOG:
            return
        try:
            if ts is None: ts = time.time()
            ts_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))
            ts_hms = time.strftime("%H:%M:%S", time.localtime(ts))
            appr_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(approved_ts)) if approved_ts else ""
            row = [
                ts_iso, ts_hms,
                (st or {}).get("station",""), (st or {}).get("operator",""),
                ip, match, direction, typ, text, item, section, sender,
                1 if approved else 0, appr_iso
            ]
            with open(LOG_PATH, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(row)
        except Exception:
            pass


    # ---------- Helpers ----------
    def _set_info(self, text: str):
        self.statusBar().showMessage(text)

    @staticmethod
    def _key(station: str, operator: str, ip: str) -> str:
        if station: return f"ST::{station}"
        if operator: return f"OP::{operator}"
        return f"IP::{ip}"

    def _title_for(self, st: dict) -> str:
        a = st.get("station","") or "(Unknown Station)"
        b = st.get("operator","") or "(Unknown Operator)"
        return f"{a} — {b}"
    def _ensure_nodes(self, key: str):
        st = self.tech_state.setdefault(key, {
            "station":"", "operator":"", "ip":"",
            "matches": {
                1: {"teams":"", "day":"", "ko":"", "ko_date":"", "ws":"", "remi":"", "progress":None, "requests":[],
                    "d1_seen": set(), "d1_missing": False, "d1_eval_timer": None, "d1_reminder_sent": False},
                2: {"teams":"", "day":"", "ko":"", "ko_date":"", "ws":"","remi":"",  "progress":None, "requests":[],
                    "d1_seen": set(), "d1_missing": False, "d1_eval_timer": None, "d1_reminder_sent": False},
            },

            "items": {}, "last_ts": time.time()
        })
        items = st["items"]

        if "root" not in items:
            root = QTreeWidgetItem([""] * self.tree.columnCount())
            root.setText(self.COL_TECH, self._title_for(st))
            # (no IP column anymore)
            root.setData(0, Qt.UserRole, key)
            self.tree.addTopLevelItem(root)
            items["root"] = root
            self._items_by_id[id(root)] = root

        for mi in (1, 2):
            tag = f"m{mi}"
            if tag not in items:
                child = QTreeWidgetItem([""] * self.tree.columnCount())
                child.setText(self.COL_TECH, f"Match {mi}")
                child.setText(self.COL_REQ,  "0")
                child.setData(0, Qt.UserRole, key)
                items["root"].addChild(child)
                items[tag] = child
                self._items_by_id[id(child)] = child
                self._muted_matches.setdefault((key, mi), False)


    def _rename_key(self, old_key: str, new_key: str):
        """Move state + UI nodes from old_key to new_key."""
        if not old_key or old_key == new_key:
            return
        st = self.tech_state.pop(old_key, None)
        if not st:
            return
        # install under new key
        self.tech_state[new_key] = st

        # update the UserRole key on existing tree items
        for tag in ("root", "m1", "m2"):
            it = st.get("items", {}).get(tag if tag != "root" else "root")
            if it:
                it.setData(0, Qt.UserRole, new_key)

        # also retarget any blinking list entries that referenced old_key
        self._blink_list_entries = {
            (new_key if k == old_key else k, m, idx)
            for (k, m, idx) in self._blink_list_entries
        }
        self._blink_entry_colors = {
            ((new_key if k == old_key else k), m, idx): col
            for (k, m, idx), col in self._blink_entry_colors.items()
        }
    def _norm_text(self, s: str) -> str:
        return (s or "").strip().lower()

    def _merge_keys(self, primary_key: str, other_key: str):
        """Merge state & UI for other_key into primary_key, then remove other_key."""
        if not other_key or primary_key == other_key:
            return
        dst = self.tech_state.get(primary_key)
        src = self.tech_state.pop(other_key, None)
        if not dst or not src:
            return

        # --- merge identity
        if not dst.get("ip"):       dst["ip"] = src.get("ip", "")
        if not dst.get("station"):  dst["station"] = src.get("station", "")
        if not dst.get("operator"): dst["operator"] = src.get("operator", "")

        # --- merge per-match state
        for mi in (1, 2):
            dm = dst["matches"][mi]; sm = src["matches"][mi]

            # prefer non-empty metadata
            for k in ("teams", "day", "ko", "ko_date"):
                if not dm.get(k) and sm.get(k):
                    dm[k] = sm[k]

            # keep the higher progress, if any
            if sm.get("progress") is not None:
                if dm.get("progress") is None or sm["progress"] > dm["progress"]:
                    dm["progress"] = sm["progress"]

            # D1 accumulation
            dm["d1_seen"] = set(dm.get("d1_seen") or set()) | set(sm.get("d1_seen") or set())
            dm["d1_missing"] = bool(dm.get("d1_missing")) or bool(sm.get("d1_missing"))

            # Requests: dedupe using a simple signature
            seen = {(r.get("type",""), r.get("item",""), r.get("section",""), r.get("text",""))
                    for r in dm.get("requests", [])}
            for r in sm.get("requests", []):
                sig = (r.get("type",""), r.get("item",""), r.get("section",""), r.get("text",""))
                if sig not in seen:
                    dm["requests"].append(r)
                    seen.add(sig)

        # --- remove UI nodes for other_key
        items = src.get("items", {})
        for tag in ("m1", "m2", "root"):
            it = items.get(tag)
            if not it:
                continue
            parent = it.parent()
            if parent:
                parent.removeChild(it)
            else:
                idx = self.tree.indexOfTopLevelItem(it)
                if idx >= 0:
                    self.tree.takeTopLevelItem(idx)
            self._items_by_id.pop(id(it), None)
            self._blink_tree_items.discard(id(it))
            self._blink_colors.pop(id(it), None)

        # --- clear any blinking list entries for other_key
        self._blink_list_entries = {t for t in self._blink_list_entries if t[0] != other_key}
        if hasattr(self, "_blink_entry_colors"):
            self._blink_entry_colors = {t: c for t, c in getattr(self, "_blink_entry_colors", {}).items() if t[0] != other_key}

    def _update_rows(self, key: str):
        st = self.tech_state[key]
        st["last_ts"] = time.time()
        self.tree.setUpdatesEnabled(False)

        items = st["items"]
        self._ensure_nodes(key)

        # Root line
        items["root"].setText(self.COL_TECH, self._title_for(st))
        # (no IP column anymore)

        for mi in (1, 2):
            m  = st["matches"][mi]
            it = items[f"m{mi}"]

            it.setText(self.COL_TEAM, m.get("teams",""))
            it.setText(self.COL_KO,   m.get("ko",""))
            it.setText(self.COL_REQ,  str(len(m.get("requests", []))))

            base_label = f"Match {mi}"
            it.setText(self.COL_TECH, base_label + "  🔇" if self._muted_matches.get((key, mi), False) else base_label)

            has_match = bool(m.get("teams") or m.get("day") or m.get("ko") or m.get("ko_date"))
            ko_dt = self._parse_ko_dt(m.get("ko",""), m.get("ko_date",""))
            it.setText(self.COL_KOHRS, self._fmt_hours_to_ko(ko_dt) if has_match else "")

            # MD-1 cell (unchanged)
            if has_match:
                total_seen = len(m.get("d1_seen") or [])
                expected_total = self._expected_d1_total(key, mi)
                if total_seen >= expected_total:
                    it.setText(self.COL_MD1, "SENT");    it.setBackground(self.COL_MD1, Qt.green)
                else:
                    it.setText(self.COL_MD1, "WAITING"); it.setBackground(self.COL_MD1, Qt.red)
                it.setToolTip(self.COL_MD1, f"{total_seen}/{expected_total} items")
            else:
                it.setText(self.COL_MD1, ""); it.setBackground(self.COL_MD1, Qt.white); it.setToolTip(self.COL_MD1, "")

        self._schedule_cards_rebuild(150)
        self.tree.setUpdatesEnabled(True)
        # NEW:
        self.notes_update.emit(self._gather_notes_columns())


    def _send_to_tech(self, ip: str, text: str, timeout: float = 3.5):
        """Send a single line to Tech, stamping supervisor identity so Tech can display who sent it."""
        try:
            # Append supervisor display name unless already present
            try:
                sup_name = CONF.get("name", "Supervisor")
            except Exception:
                sup_name = "Supervisor"
            line = text
            if "FromSupName=" not in line:
                line = f"{line} FromSupName='{sup_name}'"

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, TECH_ACK_PORT))
                s.sendall((line + "\n").encode("utf-8", errors="ignore"))
            return True, ""
        except Exception as e:
            return False, str(e)


    def _suppress_prior_overdue(self, key: str, mi: int, item_name: str):
        """
        If there are older unseen OVERDUE rows for this item, mark them seen and
        stop their blinking. Call this right after you append a new UPDATE/APPROVED.
        """
        st = self.tech_state.get(key)
        if not st or not item_name:
            return
        m = st["matches"][mi]
        nm = (item_name or "").strip().lower()
        cleared = False

        # scan all but the most recently appended record
        for idx, r in enumerate(m.get("requests", [])[:-1]):
            if (r.get("type", "").upper() == "OVERDUE"
                and not r.get("seen", False)
                and (r.get("item", "") or "").strip().lower() == nm):
                r["seen"] = True
                tup = (key, mi, idx)
                self._blink_list_entries.discard(tup)
                if hasattr(self, "_blink_entry_colors"):
                    self._blink_entry_colors.pop(tup, None)
                cleared = True

        if cleared:
            self._recompute_blink_for_match(key, mi)
            self._refresh_group_blinks(key, mi) 

    # ---------- Blink bookkeeping ----------
    def _mark_unseen(self, key: str, match_idx: int, req_index: int, *, color=Qt.yellow):
        """Start blinking for this match (tree rows) and remember the unseen entry."""
        st = self.tech_state.get(key)
        if not st: return
        root = st["items"].get("root")
        child = st["items"].get(f"m{match_idx}")
        if root:
            self._blink_tree_items.add(id(root))
            self._blink_colors[id(root)] = color
        if child:
            self._blink_tree_items.add(id(child))
            self._blink_colors[id(child)] = color
        tup = (key, match_idx, req_index)
        self._blink_list_entries.add(tup)
        self._blink_entry_colors[tup] = color
        self._maybe_play_notify(key, match_idx)

    def _reset_tree_item_bg(self, item: QTreeWidgetItem):
        if not item:
            return
        cols = self.tree.columnCount()
        for c in range(cols):
            if c == self.COL_MD1:   # preserve MD-1 red/green
                continue
            item.setBackground(c, Qt.white)

    def _has_unseen_for_match(self, key: str, match_idx: int) -> bool:
        return any((k == key and m == match_idx) for (k, m, _i) in self._blink_list_entries)

    def _has_unseen_for_any(self, key: str) -> bool:
        return any((k == key) for (k, _m, _i) in self._blink_list_entries)

    def _recompute_blink_for_match(self, key: str, match_idx: int):
        """Stop/start blink on the match row; and adjust tech row based on unseen across both matches."""
        st = self.tech_state.get(key)
        if not st: return
        root = st["items"].get("root")
        child = st["items"].get(f"m{match_idx}")

        if not self._has_unseen_for_match(key, match_idx):
            if child:
                self._blink_tree_items.discard(id(child))
                self._blink_colors.pop(id(child), None)
                self._reset_tree_item_bg(child)
        else:
            if child:
                self._blink_tree_items.add(id(child))

        if not self._has_unseen_for_any(key):
            if root:
                self._blink_tree_items.discard(id(root))
                self._blink_colors.pop(id(root), None)
                self._reset_tree_item_bg(root)
        else:
            if root:
                self._blink_tree_items.add(id(root))
    def _refresh_group_blinks(self, key: str, match_idx: int):
        """
        Ensure group headers blink only if they contain at least one unseen row.
        Stops header blink automatically once the last unseen child is marked seen.
        """
        # 1) Gather unseen rows for this (key, match) grouped by their parent header title
        unseen_groups = {}
        for (k, m, idx) in list(self._blink_list_entries):
            if k != key or m != match_idx:
                continue
            it = self._req_item_index.get((k, m, idx))
            if not it:
                continue
            parent = it.parent()
            if not parent:
                continue
            gtitle = parent.text(0)
            # pick the strongest color among that group's unseen rows (red wins over yellow)
            col = self._blink_entry_colors.get((k, m, idx), Qt.yellow)
            prev = unseen_groups.get(gtitle)
            if prev is None or prev == Qt.yellow:
                unseen_groups[gtitle] = col

        # 2) Turn blink ON for headers that still have unseen rows, OFF otherwise
        for (gk, hdr_item) in list(self._req_group_index.items()):
            k, m, gtitle = gk
            if k != key or m != match_idx:
                continue
            if gtitle in unseen_groups:
                self._blink_group_headers.add(gk)
                self._blink_group_colors[gk] = unseen_groups[gtitle]
            else:
                self._blink_group_headers.discard(gk)
                self._blink_group_colors.pop(gk, None)
                try:
                    hdr_item.setBackground(0, Qt.white)
                except Exception:
                    pass

    # === D1 helpers
    @staticmethod
    def _is_today_str(dstr: str) -> bool:
        try:
            return datetime.strptime((dstr or "").strip(), "%Y-%m-%d").date() == date.today()
        except Exception:
            return False
    def _resolve_path_from_ini(self, p: str, default_name: str) -> str:
        """
        Expand env vars and ~; if relative, resolve relative to the folder
        containing supervisor.ini; ensure the folder exists.
        """
        import os
        if not p:
            # default to SupportingFiles/<default_name>
            p = os.path.join(SUPPORT_DIR, default_name)
        p = os.path.expandvars(os.path.expanduser(p))
        if not os.path.isabs(p):
            # resolve relative to supervisor.ini directory
            base = os.path.dirname(PATH_SUPERVISOR)
            p = os.path.normpath(os.path.join(base, p))
        # make sure the directory exists
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    def _eval_d1_missing(self, key: str, mi: int):
        """Do NOT surface MD-1 as a blink or a right-side row anymore.
        We still compute MD-1 status elsewhere for the MD-1 column."""
        st = self.tech_state.get(key)
        if not st:
            return
        mm = st["matches"].get(mi)
        if not mm:
            return

        # MD-1 status is still tracked by d1_seen/expected elsewhere.
        # Explicitly clear any previous MD-1 'missing' state.
        mm["d1_missing"] = False

        # Purge any existing MD-1 reminder rows we may have added earlier.
        reqs = mm.get("requests", [])
        rm_idxs = [i for i, r in enumerate(reqs)
                if (r.get("type", "").upper() == "D1_MISSING" and r.get("match", mi) == mi)]
        if rm_idxs:
            # Stop any blinking tied to those right-side rows
            for tup in list(self._blink_list_entries):
                k, mmi, idx = tup
                if k == key and mmi == mi and idx in rm_idxs:
                    self._blink_list_entries.discard(tup)
                    self._blink_entry_colors.pop(tup, None)

            # Remove the rows
            mm["requests"] = [r for i, r in enumerate(reqs) if i not in rm_idxs]

        # Also ensure no leftover left-tree blink from previous MD-1 logic.
        items = st.get("items", {})
        for tag in (f"m{mi}", "root"):
            node = items.get(tag)
            if node is not None:
                self._blink_tree_items.discard(id(node))
                self._blink_colors.pop(id(node), None)
                self._reset_tree_item_bg(node)

        # Refresh UI; MD-1 column label remains handled elsewhere.
        self._update_rows(key)

    def _drain(self):
        try:
            processed = 0
            BATCH = 50  # cap per tick to keep UI responsive

            while processed < BATCH:
                try:
                    typ, payload = self.ui_queue.get_nowait()
                    # Reset backoff & mark connected when we see activity from an IP
                    ip = (payload.get("ip", "") or "").strip() if isinstance(payload, dict) else ""
                    if ip:
                        self._connected_ips.add(ip)
                        st_back = self._ip_state.get(ip)
                        if st_back:
                            st_back["backoff"] = 0
                            st_back["next"] = 0
                except queue.Empty:
                    break

                processed += 1

                if typ == "info":
                    # Keep title fixed; don't show the noisy "Listening on ..." anywhere.
                    self.setWindowTitle(WINDOW_TITLE)
                    msg = str(payload).strip().lower()
                    if msg.startswith("listening on"):
                        self.statusBar().clearMessage()
                    else:
                        self._set_info(payload)
                    continue

                elif typ == "setup":
                    station  = (payload.get("station","") or "").strip()
                    operator = (payload.get("operator","") or "").strip()
                    ip       = (payload.get("ip","") or "").strip()

                    # Compute the primary stable key (station > operator > ip)
                    primary_key = self._key(station, operator, ip)

                    # Find any existing keys that represent the same person/box
                    dupes = []
                    for k, st0 in list(self.tech_state.items()):
                        if k == primary_key:
                            continue
                        same_station  = bool(station)  and self._norm_text(st0.get("station"))  == self._norm_text(station)
                        same_operator = bool(operator) and self._norm_text(st0.get("operator")) == self._norm_text(operator)
                        same_ip       = bool(ip)       and (st0.get("ip","") == ip)
                        if same_station or same_operator or same_ip:
                            dupes.append(k)

                    # If primary doesn't exist but a dupe does, rename the first dupe to primary.
                    if primary_key not in self.tech_state and dupes:
                        self._rename_key(dupes[0], primary_key)
                        dupes = dupes[1:]

                    # Ensure the primary node exists
                    st = self.tech_state.setdefault(primary_key, {
                        "station": station, "operator": operator, "ip": ip,
                        "matches": {
                            1: {"teams":"", "day":"", "ko":"", "ko_date":"", "progress":None, "requests":[],
                                "d1_seen": set(), "d1_missing": False, "d1_eval_timer": None, "d1_reminder_sent": False},
                            2: {"teams":"", "day":"", "ko":"", "ko_date":"", "progress":None, "requests":[],
                                "d1_seen": set(), "d1_missing": False, "d1_eval_timer": None, "d1_reminder_sent": False},
                        },
                        "items": {}, "last_ts": time.time()
                    })

                    # Merge any duplicates we found into primary
                    for k in dupes:
                        self._merge_keys(primary_key, k)

                    # Update identity (fill in missing bits)
                    st["station"]  = station  or st["station"]
                    st["operator"] = operator or st["operator"]
                    st["ip"]       = ip       or st["ip"]

                    self._ensure_nodes(primary_key)

                    # Fill match metadata from SETUP payload
                    for mi in (1, 2):
                        m = payload.get("matches", {}).get(mi, {})
                        if m:
                            st["matches"][mi]["teams"]   = m.get("teams","") or st["matches"][mi]["teams"]
                            st["matches"][mi]["day"]     = m.get("day","")   or st["matches"][mi]["day"]
                            st["matches"][mi]["ko"]      = m.get("ko","")    or st["matches"][mi]["ko"]
                            st["matches"][mi]["ko_date"] = (m.get("ko_date","") or "").strip() or st["matches"][mi]["ko_date"]
                            # persist WS and REMI if provided
                            val_ws = (m.get("ws","") or "").strip()
                            if val_ws:
                                st["matches"][mi]["ws"] = val_ws
                            val_remi = (m.get("remi","") or "").strip()
                            if val_remi:
                                st["matches"][mi]["remi"] = val_remi

                    # D1 reset / reminder
                    for mi in (1, 2):
                        mm = st["matches"][mi]
                        before_sig = mm.get("_sig")
                        now_sig = (mm.get("teams",""), mm.get("day",""), mm.get("ko",""), mm.get("ko_date",""))
                        mm["_sig"] = now_sig

                        if before_sig != now_sig:
                            mm["d1_seen"] = set()
                            mm["d1_missing"] = False
                            t = mm.get("d1_eval_timer")
                            if t:
                                try: t.stop()
                                except Exception: pass
                            mm["d1_eval_timer"] = None
                            mm["d1_reminder_sent"] = False

                        if self._is_today_str(mm.get("ko_date","")) and st.get("ip"):
                            if not mm.get("d1_reminder_sent"):
                                msg = f"MESSAGE: Match={mi} Text='Please send Day-1 checklist now (press “Send Day-1 now”).'"
                                ok, err = self._send_to_tech(st["ip"], msg)
                                if ok:
                                    self.status_lbl.setText(f"Reminded {st['station']} to send Day-1 for Match {mi}.")
                                    ts_now = time.time()
                                    rec = {"type":"CHAT","match":mi,"from":"SUPERVISOR","text":"Reminder: send Day-1 now.",
                                        "ip":st["ip"],"ts":ts_now,"seen":True}
                                    mm["requests"].append(rec)
                                    self._log(st=st, ip=st["ip"], match=mi, direction="out", typ="CHAT",
                                            text="Reminder: send Day-1 now.", item="", section="", sender="SUPERVISOR", ts=ts_now)
                                else:
                                    self.status_lbl.setText(f"Failed to send Day-1 reminder: {err}")
                                mm["d1_reminder_sent"] = True

                            if not mm.get("d1_eval_timer"):
                                t = QTimer(self)
                                t.setSingleShot(True)
                                t.timeout.connect(lambda k=primary_key, _mi=mi: self._eval_d1_missing(k, _mi))
                                t.start(D1_EVAL_DELAY_SEC * 1000)
                                mm["d1_eval_timer"] = t

                    self._update_rows(primary_key)
                    self._schedule_save_state()

                elif typ == "update":
                    station = payload.get("station","").strip()
                    operator = payload.get("operator","").strip()
                    ip = payload.get("ip","").strip()
                    tag = (payload.get("tag","UPDATE") or "UPDATE").upper()

                    # find the key
                    key = None
                    for k, st in self.tech_state.items():
                        if station and st.get("station","") == station:
                            key = k; break
                    if not key:
                        for k, st in self.tech_state.items():
                            if operator and st.get("operator","") == operator:
                                key = k; break
                    if not key:
                        key = self._key(station, operator, ip)
                        self._ensure_nodes(key)
                        self.tech_state[key]["station"] = station
                        self.tech_state[key]["operator"] = operator
                        self.tech_state[key]["ip"] = ip

                    mi = payload.get("match", 1)
                    m = self.tech_state[key]["matches"][mi]

                    # refresh metadata if carried on the update
                    if payload.get("teams"): m["teams"] = payload["teams"]
                    if payload.get("day"):   m["day"]   = payload["day"]
                    if payload.get("ko"):    m["ko"]    = payload["ko"]
                    if payload.get("progress") is not None:
                        m["progress"] = payload["progress"]

                    if tag == "UPDATE":
                        rec = {
                            "type": "UPDATE",
                            "match": mi,
                            "item": payload.get("item",""),
                            "section": payload.get("section",""),
                            "from": station or operator or "TECH",
                            "text": payload.get("text",""),
                            "state": payload.get("state",""),
                            "progress": payload.get("progress", None),
                            "due_ts": payload.get("due_ts", None),
                            "total": payload.get("total", None),
                            "ts": time.time(),
                            "seen": True,  # UPDATEs don’t blink
                            "catchup": payload.get("catchup", 0),
                        }
                        # If this UPDATE belongs to MD-1 and carries a 'total', remember it
                        sec_txt = rec.get("section", "")
                        tot_val = rec.get("total", None)
                        if self._is_md1_section_text(sec_txt) and isinstance(tot_val, int) and tot_val > 0:
                            m["d1_expected"] = max(int(m.get("d1_expected", 0) or 0), tot_val)

                        idx = self._upsert_update(key, mi, rec)
                        self._record_md1_done(key, mi, rec)
                        self._suppress_prior_overdue(key, mi, rec.get("item",""))
                        self._update_rows(key)
                        self._log(st=self.tech_state[key], ip=ip, match=mi, direction="in",
                                typ="UPDATE", text=rec.get("text",""), item=rec.get("item",""),
                                section=rec.get("section",""), sender=rec.get("from",""), ts=rec["ts"])
                        self._schedule_save_state()
                        continue

                    if tag in ("D1", "APPROVED", "OVERDUE"):
                        rec_type = "DAY1" if tag == "D1" else ("APPROVED" if tag == "APPROVED" else "OVERDUE")
                        rec = {
                            "type": rec_type,
                            "match": mi,
                            "item": payload.get("item",""),
                            "from": station or operator or "TECH",
                            "text": payload.get("text",""),
                            "section": payload.get("section",""),
                            "ts": time.time(),
                            "seen": (rec_type != "OVERDUE"),
                        }
                        if rec_type == "APPROVED":
                            rec["approved"] = True
                            rec["approved_ts"] = time.time()

                        m["requests"].append(rec)

                        # approvals clear older unseen warnings for this item
                        if rec_type == "APPROVED":
                            nm = (rec.get("item") or "").strip().lower()
                            # reflect approval on prior EARLY/NOT_POSSIBLE
                            for j, older in enumerate(m["requests"][:-1]):
                                if (older.get("type","").upper() in ("EARLY_MARK", "NOT_POSSIBLE")
                                    and (older.get("item","") or "").strip().lower() == nm):
                                    older["approved"] = True
                                    older["approved_ts"] = rec.get("ts", time.time())
                                    older["seen"] = True
                                    tup = (key, mi, j)
                                    self._blink_list_entries.discard(tup)
                                    if hasattr(self, "_blink_entry_colors"):
                                        self._blink_entry_colors.pop(tup, None)
                            # also clear any older unseen OVERDUE for this item
                            self._suppress_prior_overdue(key, mi, rec.get("item",""))
                            # do not render the APPROVED row itself
                            rec["archived"] = True

                        st_obj = self.tech_state[key]
                        items = st_obj["items"]

                        if rec_type == "OVERDUE":
                            # blink red until clicked
                            if items.get(f"m{mi}"):
                                self._blink_tree_items.add(id(items[f"m{mi}"]))
                                self._blink_colors[id(items[f"m{mi}"])] = Qt.red
                            if items.get("root"):
                                self._blink_tree_items.add(id(items["root"]))
                                self._blink_colors[id(items["root"])] = Qt.red
                            tup = (key, mi, len(m["requests"]) - 1)
                            self._blink_list_entries.add(tup)
                            self._blink_entry_colors[tup] = Qt.red
                            self._maybe_play_notify(key, mi)

                        # D1 accumulation & immediate evaluation
                        if tag == "D1":
                            itxt = (payload.get("item") or "").strip().lower()
                            if itxt:
                                seen = m.get("d1_seen")
                                if not isinstance(seen, set):
                                    seen = set(seen or [])
                                    m["d1_seen"] = seen
                                seen.add(itxt)
                            self._eval_d1_missing(key, mi)

                        self._log(st=self.tech_state[key], ip=ip, match=mi,
                                direction="in", typ=rec_type, text=rec.get("text",""),
                                item=rec.get("item",""), section=rec.get("section",""),
                                sender=rec.get("from",""), ts=rec["ts"])

                    self._update_rows(key)
                    self._schedule_save_state()

                elif typ == "d1_expect":
                    station = payload.get("station","").strip()
                    operator = payload.get("operator","").strip()
                    ip = payload.get("ip","").strip()

                    # find/create key
                    key = None
                    for k, st0 in self.tech_state.items():
                        if station and st0.get("station","") == station:
                            key = k; break
                    if not key:
                        for k, st0 in self.tech_state.items():
                            if operator and st0.get("operator","") == operator:
                                key = k; break
                    if not key:
                        key = self._key(station, operator, ip)
                        self._ensure_nodes(key)
                        self.tech_state[key]["station"]  = station or self.tech_state[key]["station"]
                        self.tech_state[key]["operator"] = operator or self.tech_state[key]["operator"]
                        self.tech_state[key]["ip"]       = ip or self.tech_state[key]["ip"]

                    mi = payload.get("match", 1)
                    st = self.tech_state[key]
                    m  = st["matches"][mi]

                    if payload.get("teams"):
                        m["teams"] = payload["teams"]

                    # Treat 'count' as the expected Day-1 total if provided (>0)
                    try:
                        cnt = int(payload.get("count", 0) or 0)
                    except Exception:
                        cnt = 0
                    if cnt > 0:
                        m["d1_expected"] = cnt

                    count_seen = len(m.get("d1_seen") or set())
                    expected_total = self._expected_d1_total(key, mi)

                    if count_seen < expected_total and not m.get("d1_missing"):
                        items = st["items"]
                        if items.get(f"m{mi}"):
                            self._blink_tree_items.add(id(items[f"m{mi}"]))
                            self._blink_colors[id(items[f"m{mi}"])] = Qt.red
                        if items.get("root"):
                            self._blink_tree_items.add(id(items["root"]))
                            self._blink_colors[id(items["root"])] = Qt.red

                        msg = f"received {count_seen}, expected ≥{expected_total}"
                        rec = {"type":"D1_MISSING","match":mi,"item":msg,"from":"SYSTEM","text":"",
                            "section":"", "ts": time.time(), "seen": False}
                        m["requests"].append(rec)
                        tup = (key, mi, len(m["requests"])-1)
                        self._blink_list_entries.add(tup)
                        self._blink_entry_colors[tup] = Qt.red
                        m["d1_missing"] = True
                        self._log(st=st, ip=st.get("ip",""), match=mi, direction="in",
                                typ="D1_MISSING", text="", item=msg, section="", sender="SYSTEM", ts=rec["ts"])
                    elif count_seen >= expected_total and m.get("d1_missing"):
                        m["d1_missing"] = False
                        items = st["items"]
                        for tag in (f"m{mi}", "root"):
                            node = items.get(tag)
                            if node:
                                self._blink_tree_items.discard(id(node))
                                self._blink_colors.pop(id(node), None)
                                self._reset_tree_item_bg(node)

                        # Purge lingering D1_MISSING rows
                        rm_idxs = [i for i, r in enumerate(m.get("requests", []))
                                if (r.get("type", "").upper() == "D1_MISSING" and r.get("match", mi) == mi)]
                        if rm_idxs:
                            for tup in list(self._blink_list_entries):
                                k, mmi, idx = tup
                                if k == key and mmi == mi and idx in rm_idxs:
                                    self._blink_list_entries.discard(tup)
                                    self._blink_entry_colors.pop(tup, None)
                            m["requests"] = [r for i, r in enumerate(m["requests"]) if i not in rm_idxs]

                    self._update_rows(key)
                    self._schedule_save_state()

                elif typ == "request":
                    # ========== UPDATED REQUEST HANDLER ==========
                    ip = (payload.get("ip","") or "").strip()
                    from_str = (payload.get("from","") or "").strip()

                    # Parse "03 — Heysen" or "03 - Heysen"
                    station = operator = ""
                    if from_str:
                        parts = [p.strip() for p in re.split(r"[—-]+", from_str, maxsplit=1)]
                        if parts:
                            station = parts[0]
                            if len(parts) > 1:
                                operator = parts[1]

                    # 1) Prefer existing entry by station/operator
                    key = None
                    if station:
                        for k, st0 in self.tech_state.items():
                            if (st0.get("station","") or "").strip() == station:
                                key = k; break
                    if not key and operator:
                        for k, st0 in self.tech_state.items():
                            if (st0.get("operator","") or "").strip() == operator:
                                key = k; break

                    # 2) Else try by IP (remember this to possibly upgrade)
                    ip_key = None
                    if ip:
                        for k, st0 in self.tech_state.items():
                            if (st0.get("ip","") or "").strip() == ip:
                                ip_key = k
                                if not key:
                                    key = k
                                break

                    # 3) If nothing, create fresh node with whatever we know
                    if not key:
                        key = self._key(station, operator, ip)
                        self._ensure_nodes(key)
                        st_new = self.tech_state[key]
                        st_new["station"]  = station or st_new.get("station","")
                        st_new["operator"] = operator or st_new.get("operator","")
                        st_new["ip"]       = ip or st_new.get("ip","")

                    st = self.tech_state[key]

                    # 4) If this is the IP-only “unknown” row but we now know station/operator, upgrade/re-key
                    needs_rekey = False
                    if ip_key and ip_key == key:
                        if station and not (st.get("station") or "").strip():
                            st["station"] = station; needs_rekey = True
                        if operator and not (st.get("operator") or "").strip():
                            st["operator"] = operator; needs_rekey = True

                    if needs_rekey:
                        new_key = self._key(st.get("station",""), st.get("operator",""), st.get("ip",""))
                        if new_key != key:
                            # move state and fix tree item user-data
                            self.tech_state[new_key] = st
                            try:
                                for tag, itm in (st.get("items") or {}).items():
                                    if itm:
                                        itm.setData(0, Qt.UserRole, new_key)
                            except Exception:
                                pass
                            self.tech_state.pop(key, None)
                            key = new_key
                            st = self.tech_state[key]

                    # Continue with normal append + blink logic
                    mi = payload.get("match", 1)
                    payload.setdefault("ts", time.time())
                    payload["seen"] = False
                    fp = (
                        payload.get("ip","").strip(),
                        int(payload.get("match",1) or 1),
                        (payload.get("type","") or "").upper(),
                        (payload.get("text","") or "").strip()
                    )
                    if not hasattr(self, "_recent_seen"):
                        from collections import deque
                        self._recent_seen = set()
                        self._recent_fifo = deque(maxlen=400)
                    if fp in self._recent_seen:
                        continue
                    self._recent_seen.add(fp)
                    self._recent_fifo.append(fp)
                    st["matches"][mi]["requests"].append(payload)
                    idx = len(st["matches"][mi]["requests"]) - 1

                    req_type = (payload.get("type","") or "").upper()

                    if req_type == "OVERDUE":
                        items = st["items"]
                        if items.get(f"m{mi}"):
                            self._blink_tree_items.add(id(items[f"m{mi}"]))
                            self._blink_colors[id(items[f"m{mi}"])] = Qt.red
                        if items.get("root"):
                            self._blink_tree_items.add(id(items["root"]))
                            self._blink_colors[id(items["root"])] = Qt.red
                        tup = (key, mi, idx)
                        self._blink_list_entries.add(tup)
                        self._blink_entry_colors[tup] = Qt.red
                        self._maybe_play_notify(key, mi)

                    elif req_type in ("SHIFT", "NOT_POSSIBLE", "CHAT", "EARLY_MARK"):
                        self._mark_unseen(key, mi, idx, color=Qt.yellow)

                    elif req_type == "REPORT":
                        # mark unseen in requests (yellow)
                        self._mark_unseen(key, mi, idx, color=Qt.yellow)

                        # build multi-line view for Reporting tree
                        from datetime import datetime as _dt
                        ts      = _dt.now().strftime("%H:%M:%S")
                        fromwho = (payload.get("from", "") or "").strip()
                        text    = (payload.get("text", "") or "")  # keep original; don't strip mid-lines
                        print("[DEBUG][SUP][REPORT] from=", repr(fromwho), "len(text)=", len(text), "repr(text)=", repr(text))

                        # normalize newlines and split to visible lines
                        norm  = text.replace("\r", "\n")
                        lines = [ln.strip() for ln in norm.split("\n") if ln.strip()] or [""]

                        print("[DEBUG][SUP][REPORT] split lines:", lines)
                        last_itm = None
                        for ln in lines:
                            disp = f"[{ts}] REPORT — {fromwho}: {ln}"
                            itm = QTreeWidgetItem([disp])
                            itm.setData(0, Qt.UserRole, {"key": key, "match": mi})
                            itm.setBackground(0, QBrush(QColor("#facc15")))
                            itm.setToolTip(0, text)  # hover shows the full multi-line report
                            self.report_tree.addTopLevelItem(itm)
                            last_itm = itm

                        if last_itm is not None:
                            self.report_tree.scrollToItem(last_itm)


                        # hide it from left Requests
                        st["matches"][mi]["requests"][idx]["seen"] = True
                        st["matches"][mi]["requests"][idx]["archived"] = True

                        # re-apply right-pane filter
                        cur = self.tree.currentItem()
                        if cur is not None:
                            self._on_tree_select(cur, cur)

                    else:
                        st["matches"][mi]["requests"][idx]["seen"] = True

                    self._update_rows(key)
                    self._schedule_save_state()

                    self._log(
                        st=st, ip=ip, match=mi, direction="in", typ=payload.get("type",""),
                        text=payload.get("text",""), item=payload.get("item",""),
                        section=payload.get("section",""), sender=payload.get("from",""),
                        ts=payload["ts"]
                    )
                    continue   # <— add this line
                    # ========== END UPDATED REQUEST HANDLER ==========

                elif typ == "legacy_progress":
                    who = payload.get("who",""); pct = payload.get("pct", 0); ip = payload.get("ip","")
                    key = None
                    for k, st in self.tech_state.items():
                        if st.get("station","") == who or st.get("operator","") == who:
                            key = k; break
                    if not key:
                        key = self._key(who, "", ip)
                        self._ensure_nodes(key)
                        self.tech_state[key]["station"] = who
                        self.tech_state[key]["ip"] = ip
                    self.tech_state[key]["matches"][1]["progress"] = pct
                    self._update_rows(key)
                    self._schedule_save_state()

                elif typ == "unknown":
                    ip = payload.get("ip",""); txt = payload.get("text","")
                    self.status_lbl.setText(f"Unknown from {ip}: {txt}")

        except queue.Empty:
            pass
    def _on_tree_context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if not item:
            return

        # Only allow mute on match rows ("Match 1" / "Match 2" or with icon)
        label = item.text(self.COL_TECH)
        if not label.startswith("Match"):
            return

        mi = 1 if "1" in label else 2
        key = item.data(0, Qt.UserRole)
        if not key:
            return

        mute_key = (key, mi)
        is_muted = self._muted_matches.get(mute_key, False)

        menu = QMenu(self)
        act = menu.addAction("Unmute" if is_muted else "Mute")

        def _toggle():
            new_state = not is_muted
            self._muted_matches[mute_key] = new_state
            # optional: show a small icon next to muted matches
            base = f"Match {mi}"
            item.setText(self.COL_TECH, base + ("  🔇" if new_state else ""))

        act.triggered.connect(_toggle)
        menu.exec_(self.tree.viewport().mapToGlobal(pos))

    # ---------- Blink & prune ----------
    def _blink_tick(self):
        self._blink_on = not self._blink_on

        # Blink tree rows that are in the blink set
        for item_id in list(self._blink_tree_items):
            item = self._items_by_id.get(item_id)
            if not item:
                self._blink_tree_items.discard(item_id)
                self._blink_colors.pop(item_id, None)
                continue
            color_on = self._blink_colors.get(item_id, Qt.yellow)
            color_off = Qt.white
            for c in range(self.tree.columnCount()):
                item.setBackground(c, color_on if self._blink_on else color_off)

        # Blink specific request rows (when visible)
        for t in list(self._blink_list_entries):
            item = self._req_item_index.get(t)
            if item is None:
                continue
            color_on = self._blink_entry_colors.get(t, Qt.yellow)
            item.setBackground(0, color_on if self._blink_on else Qt.white)

        # Blink category headers (MD-1 / Hourly) that have unseen OVERDUE
        for gkey in list(self._blink_group_headers):
            gitem = self._req_group_index.get(gkey)
            # If header no longer exists or was removed from the tree, clean it up
            if gitem is None or gitem.treeWidget() is None:  # <-- was gitem.tree()
                self._req_group_index.pop(gkey, None)
                self._blink_group_headers.discard(gkey)
                self._blink_group_colors.pop(gkey, None)
                continue
            color_on = self._blink_group_colors.get(gkey, Qt.red)
            gitem.setBackground(0, color_on if self._blink_on else Qt.white)
        # Blink match cards that are flagged (actual >> expected by >10pp)
        # Blink match cards that are flagged (actual >> expected by >10pp)
        for card in list(getattr(self, "_blink_cards", [])):
            # Widget might already be deleted; any access can raise RuntimeError
            try:
                parent = card.parent()
            except RuntimeError:
                self._blink_cards.discard(card)
                continue

            if parent is None:
                self._blink_cards.discard(card)
                continue

            if self._blink_on:
                card.setStyleSheet(card.styleSheet() + " QFrame#matchCard { background: #ffe4e6; }")
            else:
                base = """
                    QFrame#matchCard {
                        background: #f8fafc;
                        border: 1px solid #e5e7eb;
                        border-radius: 10px;
                    }
                    QLabel[role="title"] { font-weight: 700; }
                    QLabel[role="sub"] { color: #475569; }
                """
                if card.property("flagged") in (True, "true"):
                    base = base.replace("1px solid #e5e7eb", "2px solid #ef4444")
                card.setStyleSheet(base)




    def _prune_stale(self):
        now = time.time()
        to_del = []
        for key, st in list(self.tech_state.items()):
            if (now - st.get("last_ts", now)) > STALE_TTL_SECONDS:
                to_del.append(key)

        for k in to_del:
            st = self.tech_state.pop(k, None)
            if not st:
                continue

            root = st.get("items", {}).get("root")
            if root:
                idx = self.tree.indexOfTopLevelItem(root)
                if idx >= 0:
                    self.tree.takeTopLevelItem(idx)
                self._blink_tree_items.discard(id(root))
                self._blink_colors.pop(id(root), None)
                self._items_by_id.pop(id(root), None)

            for tag in ("m1", "m2"):
                child = st.get("items", {}).get(tag)
                if child:
                    self._blink_tree_items.discard(id(child))
                    self._blink_colors.pop(id(child), None)
                    self._items_by_id.pop(id(child), None)

            # Drop any per-entry blink flags for this tech
            self._blink_list_entries = {t for t in self._blink_list_entries if t[0] != k}
            if hasattr(self, "_blink_entry_colors"):
                self._blink_entry_colors = {t: col for t, col in self._blink_entry_colors.items() if t[0] != k}

        # Persist after pruning
        try:
            self._schedule_save_state()
        except Exception:
            pass
    def _is_md1_section_text(self, section: str) -> bool:
        s = (section or "").lower()
        return any(x in s for x in ("matchday -1", "matchday-1", "md-1", "md1", "day -1", "day-1"))

    def _expected_d1_total(self, key: str, mi: int) -> int:
        """Dynamic MD-1 total: state → latest MD-1 'total' seen → fallback to D1_MIN_ITEMS."""
        mm = self.tech_state.get(key, {}).get("matches", {}).get(mi, {}) or {}
        exp = int(mm.get("d1_expected", 0) or 0)
        if exp <= 0:
            # Try to learn it from any MD-1 UPDATE/OVERDUE that carried 'total'
            for r in reversed(mm.get("requests", [])):
                if (r.get("type","").upper() in ("UPDATE","OVERDUE")) and self._is_md1_section_text(r.get("section","")):
                    tot = r.get("total")
                    if isinstance(tot, int) and tot > 0:
                        exp = tot
                        break
        return exp if exp > 0 else D1_MIN_ITEMS

    # --------- Grouping helper for right pane (MD-1 + Hourly collapsible; headers show done/total only) ---------
    def _group_requests_for_match(self, key: str, mi: int):
        """
        Return a dict:
        {
            "groups": [
            {"title":"MD-1 checks","kind":"__MD1__","rows":[(idx,rec),...],"header":"..."},
            {"title":"At KO","kind":"__HOUR__","rows":[...],"header":"..."},
            {"title":"X hours before KO","kind":"__HOUR__","rows":[...],"header":"..."},
            {"title":"Post Match","kind":"__POST__","rows":[...],"header":"..."},
            ],
            "flat": [ (idx, rec), ... ]
        }
        """
        def _fmt_left(secs):
            if secs is None: return None
            sign = "-" if secs < 0 else ""
            secs = abs(int(secs))
            h, r = divmod(secs, 3600)
            m, _ = divmod(r, 60)
            if h > 0: return (f"Overdue by {h}h {m}m" if sign == "-" else f"{h}h {m}m left")
            if m > 0: return (f"Overdue by {m}m" if sign == "-" else f"{m}m left")
            return "now"

        def _norm_progress(raw):
            if isinstance(raw, int): return max(0, min(100, raw))
            if isinstance(raw, str):
                s = raw.strip().rstrip("%")
                if s.isdigit(): return max(0, min(100, int(s)))
            return None

        def _parse_hours_from_section(section: str):
            s = (section or "").lower()
            m = re.search(r"(\d+)\s*hour", s)
            if m:
                try: return int(m.group(1))
                except Exception: return None
            # KO window aliases
            if ("at ko" in s) or (s.strip() == "ko") or ("during game" in s) or ("during ko" in s) or ("during kickoff" in s):
                return 0
            return None


        def _is_md1_section_text(section: str) -> bool:
            s = (section or "").lower()
            return any(x in s for x in ("matchday -1", "md-1", "md1", "day-1", "day 1"))

        st = self.tech_state.get(key)
        if not st:
            return {"groups": [], "flat": []}

        reqs = st["matches"][mi]["requests"]
        flat_rows = []

        # MD-1 bucket with quality-first dedupe (prefer UPDATE with progress/state over plain DAY1)
        md1 = {
            "rows": [],
            "best_by": {},          # key_name -> (quality, idx, rec) where quality: 2=has progress/state, 1=plain
            "unique_items": set(),
            "done_items": set(),
            "has_unseen_overdue": False,
        }

        hourly = {}  # hours_before(int) -> bucket
        post   = {"rows": [], "last_by": {}, "unique_items": set(), "done_items": set(), "has_unseen_overdue": False}

        ko_dt = self._parse_ko_dt(st["matches"][mi].get("ko",""), st["matches"][mi].get("ko_date",""))

        for i, r in enumerate(reqs):
            typ = (r.get("type","") or r.get("tag","") or "").upper()

            # ---------- MD-1 intake ----------
            if typ in ("DAY1", "D1") or (typ in ("UPDATE", "OVERDUE") and _is_md1_section_text(r.get("section",""))):
                name_display = (r.get("item","") or f"M#{i}").strip()
                key_name = name_display.lower() or f"m#{i}"
                md1["unique_items"].add(key_name)

                prog  = _norm_progress(r.get("progress"))
                state = (r.get("state","") or "").upper()
                has_signal = (prog is not None) or bool(state)
                quality = 2 if has_signal else 1

                prev = md1["best_by"].get(key_name)
                # prefer higher quality; tie-breaker = later arrival
                if (prev is None) or (quality > prev[0]) or (quality == prev[0] and i > prev[1]):
                    md1["best_by"][key_name] = (quality, i, r)

                if typ == "OVERDUE" and not r.get("seen", False):
                    md1["has_unseen_overdue"] = True
                continue

            # ---------- Time-bucketed (before/at KO) ----------
            if typ in ("UPDATE", "OVERDUE"):
                section = r.get("section","")
                # Post-match?
                due_ts = r.get("due_ts")
                is_after_ko = isinstance(due_ts, (int, float)) and (ko_dt is not None) and (due_ts > ko_dt.timestamp())
                s = (section or "").lower()
                is_post_section = any(x in s for x in ("post match", "post-match", "postmatch", "post game", "post-game"))
                if is_post_section or is_after_ko:
                    name_display = (r.get("item","") or f"P#{i}").strip()
                    key_name = name_display.lower() or f"p#{i}"
                    post["last_by"][key_name] = (i, r)
                    post["unique_items"].add(key_name)
                    prog  = _norm_progress(r.get("progress"))
                    state = (r.get("state","") or "").upper()
                    if (prog is not None and prog >= 100) or state in ("ON","DONE","OK","COMPLETED"):
                        post["done_items"].add(key_name)
                    if typ == "OVERDUE" and not r.get("seen", False):
                        post["has_unseen_overdue"] = True
                    continue

                hours_before = _parse_hours_from_section(section)
                if hours_before is None:
                    flat_rows.append((i, r))
                    continue

                b = hourly.setdefault(hours_before, {
                    "rows": [],
                    "last_by": {},
                    "unique_items": set(),
                    "done_items": set(),
                    "nearest_due": None,
                    "total_expected": 0,
                    "has_unseen_overdue": False,
                })
                name_display = (r.get("item","") or f"H#{i}").strip()
                key_name = name_display.lower() or f"h#{i}"
                b["last_by"][key_name] = (i, r)
                b["unique_items"].add(key_name)

                if typ == "OVERDUE" and not r.get("seen", False):
                    b["has_unseen_overdue"] = True

                prog  = _norm_progress(r.get("progress"))
                state = (r.get("state","") or "").upper()
                if (prog is not None and prog >= 100) or state in ("ON","DONE","OK","COMPLETED"):
                    b["done_items"].add(key_name)

                due_ts = r.get("due_ts")
                if isinstance(due_ts, (int, float)):
                    if b["nearest_due"] is None or due_ts < b["nearest_due"]:
                        b["nearest_due"] = due_ts
                tot = r.get("total")
                if isinstance(tot, int) and tot > b["total_expected"]:
                    b["total_expected"] = tot
                continue

            # everything else
            flat_rows.append((i, r))

        # ---- finalize MD-1 using best_by (quality-first) + retire items moved out of MD-1
        # Build the latest-known section per item, considering SHIFT "to" and UPDATE/APPROVED/OVERDUE sections
        last_section_by_item = {}
        for i2, r2 in enumerate(reqs):
            nm2 = (r2.get("item","") or f"M#{i2}").strip().lower()
            if not nm2:
                continue
            typ2 = (r2.get("type") or r2.get("tag") or "").upper()
            sec_txt = ""
            if typ2 == "SHIFT":
                sec_txt = (r2.get("to") or "")
            else:
                sec_txt = (r2.get("section") or "")
            if sec_txt:
                prev = last_section_by_item.get(nm2)
                if prev is None or i2 > prev[0]:
                    last_section_by_item[nm2] = (i2, sec_txt)

        # Any item whose latest section is NOT MD-1 should be removed from the MD-1 bucket
        moved_out = set()
        for nm2, (_idx2, sec_txt) in last_section_by_item.items():
            if not _is_md1_section_text(sec_txt):
                moved_out.add(nm2)

        md1_rows = []
        md1["done_items"] = set()
        for key_name, (_q, idx, rec) in md1["best_by"].items():
            if key_name in moved_out:
                continue  # retire from MD-1 if shifted to a later category
            md1_rows.append((idx, rec))
            prog = _norm_progress(rec.get("progress"))
            state = (rec.get("state","") or "").upper()
            if (prog is not None and prog >= 100) or state in ("ON","DONE","OK","COMPLETED"):
                md1["done_items"].add(key_name)

        md1_rows.sort(key=lambda t: t[0])
        md1["rows"] = md1_rows
        # Also shrink the MD-1 expected total by removing moved-out items
        md1["unique_items"] = {nm for nm in md1["unique_items"] if nm not in moved_out}

        # ---- finalize hour buckets (latest per item per bucket)
        latest_for_item = {}
        for h, b in hourly.items():
            for nm, (idx, rec) in b["last_by"].items():
                prev = latest_for_item.get(nm)
                if prev is None or idx > prev[0]:
                    latest_for_item[nm] = (idx, h)

        for h, b in hourly.items():
            rows = []
            for nm, (idx, rec) in b["last_by"].items():
                last_idx, last_h = latest_for_item.get(nm, (idx, h))
                if last_h == h and last_idx == idx:
                    rows.append((idx, rec))
            rows.sort(key=lambda t: t[0])
            b["rows"] = rows
            b["unique_items"] = {(rec.get("item","") or f"H#{idx}").strip().lower() for idx, rec in rows}
            b["done_items"] = set()
            # ---- NEW: If we're past KO and the KO bucket has incomplete items, mark it as virtually overdue
            try:
                from datetime import datetime
                if ko_dt is not None and datetime.now() > ko_dt and 0 in hourly:
                    b0 = hourly[0]
                    total0 = len(b0.get("unique_items", set()))
                    done0  = len(b0.get("done_items", set()))
                    # Only synthesize “virtual overdue” if there are no real unseen OVERDUE rows
                    if total0 > 0 and done0 < total0 and not b0.get("has_unseen_overdue", False):
                        b0["virtual_overdue"] = True
                        b0["has_unseen_overdue"] = True
                        b0["virtual_pending_counts"] = (done0, total0)

            except Exception:
                pass

            for idx, rec in rows:
                prog = _norm_progress(rec.get("progress"))
                state = (rec.get("state","") or "").upper()
                if (prog is not None and prog >= 100) or state in ("ON","DONE","OK","COMPLETED"):
                    nm = (rec.get("item","") or f"H#{idx}").strip().lower()
                    b["done_items"].add(nm)

        # ---- finalize Post-Match
        post_rows = [(idx, rec) for _nm, (idx, rec) in post["last_by"].items()]
        post_rows.sort(key=lambda t: t[0])
        post["rows"] = post_rows
        post["unique_items"] = {(rec.get("item","") or f"P#{idx}").strip().lower() for idx, rec in post_rows}
        post["done_items"] = set()
        for idx, rec in post_rows:
            prog = _norm_progress(rec.get("progress"))
            state = (rec.get("state","") or "").upper()
            if (prog is not None and prog >= 100) or state in ("ON","DONE","OK","COMPLETED"):
                nm = (rec.get("item","") or f"P#{idx}").strip().lower()
                post["done_items"].add(nm)

        # ---- NEW: virtual overdue for Post after KO (if not all done), but suppress if user already ACKed this exact state
        try:
            from datetime import datetime
            now_dt = datetime.now()
            total_post = len(post.get("unique_items", set()))
            done_post  = len(post.get("done_items",  set()))
            ko_ok      = (ko_dt is not None)

            # read last ACKed signature from match state
            mstate = (self.tech_state.get(key, {}).get("matches", {}) or {}).get(mi, {})
            ack_sig = mstate.get("_post_ack_sig")  # tuple like (done, total)

            needs_virtual = (
                ko_ok and (now_dt > ko_dt) and
                (total_post > 0) and (done_post < total_post) and
                (ack_sig != (done_post, total_post))  # suppress if unchanged since ACK
            )

            if needs_virtual and not post.get("has_unseen_overdue", False):
                post["has_unseen_overdue"] = True
                post["virtual_overdue"] = True
                post["virtual_pending_counts"] = (done_post, total_post)
                print(f"[SUP][POST] Virtual overdue set: done={done_post}/{total_post} ko={ko_dt} now={now_dt}")
        except Exception as e:
            print(f"[SUP][POST] virtual overdue compute error: {e}")


        # ---- build groups
        groups = []

        # MD-1 header: done / expected (expected from union of items we saw)
        if md1["rows"]:
            expected_total = len(md1["unique_items"]) or D1_MIN_ITEMS
            done = min(len(md1["done_items"]), expected_total)
            md1_header = f"MD-1 checks — {done}/{expected_total}"
            groups.append({
                "title": "MD-1 checks",
                "kind": "__MD1__",
                "rows": md1["rows"],
                "header": md1_header,
                "has_unseen_overdue": md1.get("has_unseen_overdue", False)
            })

        def _hour_title(h): return "At KO" if h == 0 else f"{h} hours before KO"

        # Desired order for hourly groups: 6 → 5 → 4 → 3 → 2 → 1 → (At KO/0)
        preferred = [6, 5, 4, 3, 2, 1, 0]
        # If any unusual hours exist (e.g., 7, 8) append them descending after preferred
        remaining = sorted([x for x in hourly.keys() if x not in preferred], reverse=True)
        ordered_hours = [h for h in preferred if h in hourly] + remaining

        now = time.time()
        for h in ordered_hours:
            b = hourly[h]
            left_str = _fmt_left(b.get("nearest_due") - now) if b.get("nearest_due") is not None else None
            header = f"{_hour_title(h)} — {len(b['done_items'])}/{len(b['unique_items'])}"
            if left_str:
                header += f" — {left_str}"
            groups.append({
                "title": _hour_title(h),
                "kind": "__HOUR__",
                "rows": b["rows"],
                "header": header,
                "has_unseen_overdue": b.get("has_unseen_overdue", False),
                "virtual_overdue": b.get("virtual_overdue", False),                 # ← add
                "virtual_pending_counts": b.get("virtual_pending_counts", None),    # ← add
            })
                    # Always add Post group (even if there are no rows), so the UI can insert a virtual row when needed
        header = f"Post Match — {len(post['done_items'])}/{len(post['unique_items'])}"
        groups.append({
            "title": "Post Match",
            "kind": "__POST__",
            "rows": post["rows"],  # may be empty
            "header": header,
            "has_unseen_overdue": post.get("has_unseen_overdue", False),
            "virtual_overdue": post.get("virtual_overdue", False),
            "virtual_pending_counts": post.get("virtual_pending_counts", None),
        })

        return {"groups": groups, "flat": flat_rows}

    def _populate_checks_tree(self, key: str, mi: int):
        """Fill the top-left Checks tree with only MD-1, hourly, and Post groups."""
        try:
            self.checks_tree.clear()
            buckets = self._group_requests_for_match(key, mi)
            for g in buckets["groups"]:
                if g.get("kind") not in ("__MD1__", "__HOUR__", "__POST__"):
                    continue  # only checklist groups
                header = g.get("header") or g.get("title") or ""
                parent = QTreeWidgetItem([header])
                parent.setFirstColumnSpanned(True)
                self.checks_tree.addTopLevelItem(parent)
                parent.setExpanded(False)

                # Optionally list only task-like rows (skip chat/shift/report)
                for idx, rec in g.get("rows", []):
                    t = (rec.get("type","") or rec.get("tag","") or "").upper()
                    if t in ("CHAT", "SHIFT", "REQUEST", "REPLY", "REPORT", "NOT_POSSIBLE", "EARLY_MARK"):
                        continue
                    txt = (rec.get("item") or rec.get("text") or "").strip()
                    if not txt:
                        continue
                    # prepend progress if available
                    prog = rec.get("progress")
                    if isinstance(prog, (int, float)):
                        txt = f"{txt} — {int(prog)}%"
                    leaf = QTreeWidgetItem([txt])
                    parent.addChild(leaf)
        except Exception as e:
            print("checks_tree build error:", e)

    def _on_tree_select(self, cur: QTreeWidgetItem, prev: QTreeWidgetItem):
        # Clear indices first so the blink timer can’t touch dead items
        self._req_item_index.clear()
        self._req_group_index.clear()
        # Also clear header-blink bookkeeping from the previous selection
        self._blink_group_headers.clear()
        self._blink_group_colors.clear()

        # Helper: hide all reporting items (top-level entries)
        def _hide_all_reporting_items():
            try:
                for i in range(self.report_tree.topLevelItemCount()):
                    self.report_tree.topLevelItem(i).setHidden(True)
            except Exception:
                pass

        if not cur:
            self._clear_side()
            if hasattr(self, "report_btn_send"):
                self.report_btn_send.setEnabled(False)   # NEW
            _hide_all_reporting_items()
            return

        key = cur.data(0, Qt.UserRole)
        st = self.tech_state.get(key)
        if not st:
            self._clear_side()
            if hasattr(self, "report_btn_send"):
                self.report_btn_send.setEnabled(False)   # NEW
            _hide_all_reporting_items()
            return

        # Are we sitting on a match node?
        mi = None
        for idx in (1, 2):
            if st["items"].get(f"m{idx}") is cur:
                mi = idx
                break

        if mi is None:
            self.sel_lbl.setText(self._title_for(st))
            self.req_tree.clear()
            self._building_req_tree = True
            self.btn_approve.setEnabled(False)
            self.btn_send.setEnabled(False)
            self.btn_deny.setEnabled(False)
            self._current_selection = None
            self._building_req_tree = False
            if hasattr(self, "report_btn_send"):
                self.report_btn_send.setEnabled(False)   # NEW
            _hide_all_reporting_items()
            return

        # --- Reporting panel: show only entries tagged with the selected (key, match) ---
        try:
            for i in range(self.report_tree.topLevelItemCount()):
                tli = self.report_tree.topLevelItem(i)
                meta = tli.data(0, Qt.UserRole) or {}
                show = (meta.get("key") == key and meta.get("match") == mi)
                tli.setHidden(not show)
        except Exception:
            pass

        if hasattr(self, "report_btn_send"):
            self.report_btn_send.setEnabled(True)        # NEW

        # ----- Build Requests list for this match -----
        m = st["matches"][mi]
        self.sel_lbl.setText(f"{self._title_for(st)}  —  Match {mi}  |  {m.get('teams','')}  |  KO {m.get('ko','')}")
        self._populate_checks_tree(key, mi)
        self.req_tree.clear()
        
        self._building_req_tree = True

        buckets = self._group_requests_for_match(key, mi)

        # helper: is a group complete?
        def _group_complete(gdict):
            try:
                total = int(gdict.get("total", 0))
                done = int(gdict.get("done", 0))
                if total > 0:
                    return done >= total
            except Exception:
                pass
            import re
            header_text = (gdict.get("header") or gdict.get("title") or "")
            m_ = re.search(r'(\d+)\s*/\s*(\d+)', header_text)
            if m_:
                done = int(m_.group(1)); total = int(m_.group(2))
                return total > 0 and done >= total
            return False

        # 2a) Collapsible groups
        for g in buckets["groups"]:
            header = g.get("header") or g["title"]
            parent = QTreeWidgetItem([header])
            parent.setFirstColumnSpanned(True)
            parent.setData(0, Qt.UserRole, {"is_group": True, "key": key, "match": mi, "kind": g["kind"], "gtitle": g["title"]})
            self._req_group_index[(key, mi, g["title"])] = parent

            has_unseen_overdue = bool(g.get("has_unseen_overdue") or g.get("virtual_overdue"))
            self.req_tree.addTopLevelItem(parent)
            parent.setExpanded(False)

            if g.get("virtual_overdue", False) and (g.get("kind") in ("__POST__", "__HOUR__")):
                for idx, rec in g.get("rows", []):
                    prog  = _norm_progress(rec.get("progress"))
                    state = (rec.get("state", "") or "").upper()
                    done  = (prog is not None and prog >= 100) or state in ("ON","DONE","OK","COMPLETED")
                    if not done and not rec.get("seen", False):
                        self._mark_unseen(key, mi, idx, color=Qt.red)
                        has_unseen_overdue = True

            for idx, rec in g["rows"]:
                if rec.get("archived"):
                    continue
                prefix = time.strftime("[%H:%M:%S] ", time.localtime(rec.get("ts", time.time())))
                t = (rec.get("type","") or rec.get("tag","") or "").upper()
                txt = (rec.get("text","") or "").strip()

                if t in ("D1_MISSING", "D1_EXPECT"):
                    continue
                if t == "CHAT" and "reminder" in txt.lower() and "day-1" in txt.lower():
                    continue
                if t == "REPORT":
                    # REPORT messages live in the right Reporting panel only
                    continue  # NEW: do not render a duplicate/blank line in Requests

                if t in ("NOT_POSSIBLE", "EARLY_MARK"):
                    label = "NOT POSSIBLE" if t == "NOT_POSSIBLE" else "EARLY"
                    txt = f"{prefix}{label} — {rec.get('item','')}"
                    if rec.get('section'):
                        txt += f" (sec: {rec.get('section','')})"
                    leaf = QTreeWidgetItem([txt])
                    meta = {"is_group": False, "key": key, "match": mi, "idx": idx, "approvable": True}
                    leaf.setData(0, Qt.UserRole, meta)
                    leaf.setFlags(leaf.flags() | Qt.ItemIsUserCheckable | Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                    leaf.setCheckState(0, Qt.Checked if bool(rec.get("approved")) else Qt.Unchecked)
                    if rec.get("approved"):
                        leaf.setBackground(0, QBrush(QColor(220, 255, 220)))
                    parent.addChild(leaf)
                    self._req_item_index[(key, mi, idx)] = leaf
                    tup = (key, mi, idx)
                    if tup in self._blink_list_entries and not rec.get("approved"):
                        leaf.setBackground(0, self._blink_entry_colors.get(tup, Qt.yellow))
                    continue

                if t == "UPDATE":
                    prog  = _norm_progress(rec.get("progress"))
                    state = (rec.get("state", "") or "").upper()
                    done  = (prog is not None and prog >= 100) or state in ("ON","DONE","OK","COMPLETED")
                    box = "☑" if done else "☐"
                    txt = f"{box} {rec.get('item','')}"
                    if (prog is not None) and not done:
                        txt += f" — {prog}%"
                    if rec.get('section'):
                        txt += f"  ({rec.get('section','')})"

                    child = QTreeWidgetItem([txt])
                    child.setData(0, Qt.UserRole, {"is_group": False, "key": key, "match": mi, "idx": idx})
                    if done:
                        child.setForeground(0, QBrush(Qt.darkGreen))
                    else:
                        child.setForeground(0, QBrush(Qt.red))
                    parent.addChild(child)
                    self._req_item_index[(key, mi, idx)] = child
                    tup = (key, mi, idx)
                    if tup in self._blink_list_entries:
                        child.setBackground(0, self._blink_entry_colors.get(tup, Qt.yellow))
                    continue

                elif t in ("DAY1","D1"):
                    txt = f"{prefix}{rec.get('item','')}"
                    rawp = rec.get("progress", None)
                    showp = None
                    if isinstance(rawp, int):
                        showp = max(0, min(100, rawp))
                    elif isinstance(rawp, str):
                        s = rawp.strip().rstrip("%")
                        if s.isdigit():
                            showp = max(0, min(100, int(s)))
                    if showp is not None:
                        txt += f" — {showp}%"
                elif t == "SHIFT":
                    txt = f"{prefix}SHIFT — {rec.get('item','')}  {rec.get('from','')} → {rec.get('to','')}"
                elif t == "CHAT":
                    txt = f"{prefix}CHAT — {rec.get('from','')}: {rec.get('text','') or rec.get('item','')}"
                elif t == "APPROVED":
                    continue
                elif t == "OVERDUE":
                    extra = (f" — {rec.get('text','')}" if rec.get('text') else "")
                    txt = f"{prefix}OVERDUE — {rec.get('section','')}: {rec.get('item','')}{extra}"
                elif t == "D1_MISSING":
                    txt = f"{prefix}D1 MISSING — {rec.get('item','')}"
                else:
                    txt = f"{prefix}{t} — {rec.get('item','')}"

                child = QTreeWidgetItem([txt])
                child.setData(0, Qt.UserRole, {"is_group": False, "key": key, "match": mi, "idx": idx})
                parent.addChild(child)
                self._req_item_index[(key, mi, idx)] = child

                if (t == "OVERDUE") and not rec.get("seen", False):
                    has_unseen_overdue = True
                tup = (key, mi, idx)
                if tup in self._blink_list_entries:
                    child.setBackground(0, self._blink_entry_colors.get(tup, Qt.yellow))

            gkey = (key, mi, g["title"])
            if has_unseen_overdue:
                self._blink_group_headers.add(gkey)
                self._blink_group_colors[gkey] = Qt.red
                parent.setBackground(0, Qt.red if self._blink_on else Qt.white)
            else:
                self._blink_group_headers.discard(gkey)
                self._blink_group_colors.pop(gkey, None)
                parent.setBackground(0, Qt.white)
            if not has_unseen_overdue and _group_complete(g):
                parent.setBackground(0, QBrush(QColor(220, 255, 220)))

        # 2b) Flat items
        for idx, rec in buckets["flat"]:
            prefix = time.strftime("[%H:%M:%S] ", time.localtime(rec.get("ts", time.time())))
            t = (rec.get("type","") or rec.get("tag","") or "").upper()
            txt = (rec.get("text","") or "").strip()

            if t in ("D1_MISSING", "D1_EXPECT"):
                continue
            if t == "CHAT" and "reminder" in txt.lower() and "day-1" in txt.lower():
                continue
            if t in ("OVERDUE", "D1_MISSING", "D1_EXPECT"):
                continue

            if t in ("NOT_POSSIBLE", "EARLY_MARK"):
                label = "NOT POSSIBLE" if t == "NOT_POSSIBLE" else "EARLY"
                txt = f"{prefix}{label} — {rec.get('item','')}"
                if rec.get('section'):
                    txt += f" (sec: {rec.get('section','')})"
                leaf = QTreeWidgetItem([txt])
                meta = {"is_group": False, "key": key, "match": mi, "idx": idx, "approvable": True}
                leaf.setData(0, Qt.UserRole, meta)
                leaf.setFlags(leaf.flags() | Qt.ItemIsUserCheckable | Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                leaf.setCheckState(0, Qt.Checked if bool(rec.get("approved")) else Qt.Unchecked)
                if rec.get("approved"):
                    leaf.setBackground(0, QBrush(QColor(220, 255, 220)))
                self.req_tree.addTopLevelItem(leaf)
                self._req_item_index[(key, mi, idx)] = leaf
                tup = (key, mi, idx)
                if tup in self._blink_list_entries and not rec.get("approved"):
                    leaf.setBackground(0, self._blink_entry_colors.get(tup, Qt.yellow))
                continue

            if t == "SHIFT":
                txt = f"{prefix}SHIFT — {rec.get('item','')}  {rec.get('from','')} → {rec.get('to','')}"
            elif t == "CHAT":
                txt = f"{prefix}CHAT — {rec.get('from','')}: {rec.get('text','') or rec.get('item','')}"
            elif t == "NOTE":
                txt = f"{prefix}NOTE — {rec.get('text','') or rec.get('item','')}"
            elif t == "APPROVED":
                continue
            elif t == "OVERDUE":
                extra = (f" — {rec.get('text','')}" if rec.get('text') else "")
                txt = f"{prefix}OVERDUE — {rec.get('section','')}: {rec.get('item','')}{extra}"
            elif t == "D1_MISSING":
                txt = f"{prefix}D1 MISSING — {rec.get('item','')}"
            else:
                txt = f"{prefix}{t} — {rec.get('item','')}"

            leaf = QTreeWidgetItem([txt])
            leaf.setData(0, Qt.UserRole, {"is_group": False, "key": key, "match": mi, "idx": idx})
            if t == "NOTE":
                leaf.setBackground(0, QBrush(QColor(255, 253, 208)))
            self.req_tree.addTopLevelItem(leaf)
            self._req_item_index[(key, mi, idx)] = leaf
            tup = (key, mi, idx)
            if tup in self._blink_list_entries:
                leaf.setBackground(0, self._blink_entry_colors.get(tup, Qt.yellow))

        self.btn_approve.setEnabled(self.req_tree.topLevelItemCount() > 0)
        self.btn_send.setEnabled(True)
        self._building_req_tree = False
        self.btn_deny.setEnabled(self.req_tree.topLevelItemCount() > 0)

        # Remember currently selected match
        self._current_selection = (key, mi)

        # ---- Show ONLY this match's Reporting items (no header rows) ----
        try:
            # Items on the Reporting side are top-level and tagged with {"key":..., "match":...}
            for i in range(self.report_tree.topLevelItemCount()):
                tli = self.report_tree.topLevelItem(i)
                meta = tli.data(0, Qt.UserRole) or {}
                tkey, tmi = meta.get("key"), meta.get("match")
                tli.setHidden(not (tkey == key and tmi == mi))
            if hasattr(self, "report_btn_send"):
                self.report_btn_send.setEnabled(True)
        except Exception:
            if hasattr(self, "report_btn_send"):
                self.report_btn_send.setEnabled(False)

    def _on_request_clicked(self, item):
        if not self._current_selection:
            return

        meta = item.data(0, Qt.UserRole) or {}

        # ===== A) Group header click: toggle + allow ACK of header blink (incl. virtual Post) =====
        if meta.get("is_group"):
            item.setExpanded(not item.isExpanded())  # toggle expand/collapse
            k = meta.get("key"); m = meta.get("match")
            gtitle = meta.get("gtitle") or meta.get("kind") or item.text(0)
            gkey = (k, m, gtitle)
            if gkey in self._blink_group_headers:
                # If this is Post and there is a virtual child, persist its pending_counts as ACK sig
                try:
                    if (meta.get("gtitle") == "Post Match") and item.childCount() > 0:
                        for j in range(item.childCount()):
                            ch_meta = (item.child(j).data(0, Qt.UserRole) or {})
                            if ch_meta.get("virtual_group_ack"):
                                st = self.tech_state.get(k)
                                if st:
                                    st["matches"][m]["_post_ack_sig"] = tuple(ch_meta.get("pending_counts") or (0, 0))
                                    print(f"[SUP][CLICK] Saved Post ACK sig via header: {st['matches'][m].get('_post_ack_sig')}")
                                break
                except Exception:
                    pass

                # Clear the header blink + any synthetic unseen tuple we might have added (-1)
                self._blink_group_headers.discard(gkey)
                self._blink_group_colors.pop(gkey, None)
                self._blink_list_entries.discard((k, m, -1))
                self._blink_entry_colors.pop((k, m, -1), None)
                try:
                    item.setBackground(0, Qt.white)
                except Exception:
                    pass
                print(f"[SUP][CLICK] Header ACK: {k} M{m} {gtitle}")
                self._recompute_blink_for_match(k, m)
                self._refresh_group_blinks(k, m)
                self.tree.viewport().update()
                self.req_tree.viewport().update()
            return

        # ===== B) Synthetic Post virtual row click (idx == -1) =====
        if meta.get("virtual_group_ack"):
            key = meta.get("key"); mi = meta.get("match")
            gtitle = meta.get("virtual_group_ack")
            # persist the acked signature for this match (done,total)
            try:
                st = self.tech_state.get(key)
                if st:
                    st["matches"][mi]["_post_ack_sig"] = tuple(meta.get("pending_counts") or (0, 0))
                    print(f"[SUP][CLICK] Saved Post ACK sig: {st['matches'][mi].get('_post_ack_sig')}")
            except Exception:
                pass
            gkey = (key, mi, gtitle)            
            # Clear synthetic list blink + header blink
            self._blink_list_entries.discard((key, mi, -1))
            self._blink_entry_colors.pop((key, mi, -1), None)
            self._blink_group_headers.discard(gkey)
            self._blink_group_colors.pop(gkey, None)
            try:
                item.setBackground(0, Qt.white)
                parent = item.parent()
                if parent: parent.setBackground(0, Qt.white)
            except Exception:
                pass
            print(f"[SUP][CLICK] ACK virtual Post overdue: {key} M{mi} {gtitle}")
            self._recompute_blink_for_match(key, mi)
            self._refresh_group_blinks(key, mi)
            self.tree.viewport().update()
            self.req_tree.viewport().update()
            return

        # ===== C) Normal child row click (existing logic) =====
        key = meta.get("key"); mi = meta.get("match"); idx = meta.get("idx")
        st = self.tech_state.get(key)
        if not st or idx is None:
            return

        # mark seen in the underlying record (best-effort)
        try:
            st["matches"][mi]["requests"][idx]["seen"] = True
        except Exception:
            pass

        tup = (key, mi, idx)
        self._blink_list_entries.discard(tup)
        self._blink_entry_colors.pop(tup, None)
        it = self._req_item_index.get(tup)
        if it:
            it.setBackground(0, Qt.white)

        # Stop the header blink if this was the last unseen OVERDUE in its group
        if it:
            parent = it.parent()
            if parent:
                pmeta = parent.data(0, Qt.UserRole) or {}
                if pmeta.get("is_group"):
                    gtitle = pmeta.get("gtitle") or pmeta.get("kind") or parent.text(0)
                    # scan siblings for any other unseen OVERDUE rows
                    still_unseen = False
                    for j in range(parent.childCount()):
                        ch  = parent.child(j)
                        mta = (ch.data(0, Qt.UserRole) or {})
                        jdx = mta.get("idx")
                        # ignore the synthetic row in this scan; it doesn't live in requests[]
                        if jdx is None or jdx == -1:
                            continue
                        recj = st["matches"][mi]["requests"][jdx]
                        if (recj.get("type","").upper() == "OVERDUE") and not recj.get("seen", False):
                            still_unseen = True
                            break

                    gkey = (key, mi, gtitle)
                    if still_unseen:
                        self._blink_group_headers.add(gkey)
                        self._blink_group_colors[gkey] = Qt.red
                    else:
                        self._blink_group_headers.discard(gkey)
                        self._blink_group_colors.pop(gkey, None)
                        parent.setBackground(0, Qt.white)

        # recompute blinking for this match/tech
        self._recompute_blink_for_match(key, mi)
        self._refresh_group_blinks(key, mi)
        self.tree.viewport().update()
        self.req_tree.viewport().update()

    def _on_req_item_changed(self, item, column):
        # Ignore changes while we’re building the tree
        if getattr(self, "_building_req_tree", False):
            return
        if item is None:
            return
        meta = item.data(0, Qt.UserRole) or {}
        if meta.get("is_group"):
            return

        key = meta.get("key"); mi = meta.get("match"); idx = meta.get("idx")
        st = self.tech_state.get(key) if key else None
        if not st or idx is None:
            return

        rec = st["matches"][mi]["requests"][idx]
        t = (rec.get("type","") or "").upper()

        # We only act on approvable rows
        if t not in ("NOT_POSSIBLE", "EARLY_MARK"):
            return

        # Tick = approve (one-way)
        if item.checkState(0) == Qt.Checked:
            if rec.get("approved"):
                return  # already approved
            item_name = rec.get("item","")
            ok, err = self._send_to_tech(st["ip"], f"APPROVE: Match={mi} Item='{item_name}'")
            if ok:
                now_ts = time.time()
                rec["approved"] = True
                rec["approved_ts"] = now_ts
                rec["seen"] = True

                # Greener row + stop blinking for this entry
                item.setBackground(0, QBrush(QColor(220, 255, 220)))
                tup = (key, mi, idx)
                self._blink_list_entries.discard(tup)
                if hasattr(self, "_blink_entry_colors"):
                    self._blink_entry_colors.pop(tup, None)
                self._recompute_blink_for_match(key, mi)
                self._refresh_group_blinks(key, mi)  
                # Log + persist
                self.status_lbl.setText(f"Sent approval for: {item_name}")
                self._log(
                    st=st, ip=st["ip"], match=mi, direction="out", typ="APPROVE",
                    text="", item=item_name, section=rec.get("section",""), sender="SUPERVISOR",
                    ts=now_ts, approved=True, approved_ts=now_ts
                )
                self._schedule_save_state()
            else:
                # revert tick if send failed
                try:
                    self.req_tree.blockSignals(True)
                    item.setCheckState(0, Qt.Unchecked)
                finally:
                    self.req_tree.blockSignals(False)
                self.status_lbl.setText(f"Approve failed: {err}")
        else:
            # Prevent un-approving from UI – revert to checked if it was approved
            if rec.get("approved"):
                try:
                    self.req_tree.blockSignals(True)
                    item.setCheckState(0, Qt.Checked)
                finally:
                    self.req_tree.blockSignals(False)

    def _clear_side(self):
        self.sel_lbl.setText("(none)")
        # Clear indices first so the blink timer can’t touch dead items
        self._req_item_index.clear()
        self._req_group_index.clear()
        self.req_tree.clear()
        self.btn_approve.setEnabled(False)
        self.btn_send.setEnabled(False)
        self.btn_deny.setEnabled(False)
    def _deny_selected(self):
        item = self.tree.currentItem()
        if not item:
            return
        key = item.data(0, Qt.UserRole)
        st = self.tech_state.get(key)
        if not st:
            return

        sel = self.req_tree.currentItem()
        if not sel:
            QMessageBox.information(self, "Deny", "Expand a group and select a specific request.")
            return
        meta = sel.data(0, Qt.UserRole) or {}
        if meta.get("is_group"):
            QMessageBox.information(self, "Deny", "Expand a group and select a specific request.")
            return

        mi  = meta.get("match", 1)
        idx = meta.get("idx", -1)
        if idx < 0 or idx >= len(st["matches"][mi]["requests"]):
            return

        req = st["matches"][mi]["requests"][idx]

        # mark as seen, log denial; do NOT notify Tech on deny
        req["seen"] = True
        self.status_lbl.setText(f"Denied: {req.get('item','')}")
        self._log(
            st=st, ip=st["ip"], match=mi, direction="local", typ="DENIED",
            text="", item=req.get("item",""), section=req.get("section",""),
            sender="SUPERVISOR", ts=time.time(), approved=False
        )

        # stop blinking for this entry
        tup = (key, mi, idx)
        self._blink_list_entries.discard(tup)
        self._blink_entry_colors.pop(tup, None)

        # If its group header was blinking (all unseen), recompute/clear
        self._recompute_blink_for_match(key, mi)
        self._update_rows(key)
        self.req_tree.viewport().update()
    @staticmethod
    def _is_md1_section(s: str) -> bool:
        s = (s or "").lower()
        # adjust or extend aliases if your naming differs
        return any(t in s for t in ("md-1", "md1", "matchday -1", "matchday-1", "day -1", "day-1"))

    def _record_md1_done(self, key: str, mi: int, upd: dict) -> None:
        """
        Track MD-1 item completion so the left 'MD-1' cell can flip to SENT automatically.
        """
        # must be an MD-1 row
        if not self._is_md1_section(upd.get("section", "")):
            return

        # must identify the item
        item_name = (upd.get("item") or "").strip().lower()
        if not item_name:
            return

        # must be completed
        state = str(upd.get("state") or "").upper()
        prog  = upd.get("progress")
        is_done = (state in ("ON", "DONE", "OK", "COMPLETED", "APPROVED")) or (isinstance(prog, int) and prog >= 100)
        if not is_done:
            return

        # get/set the accumulator set
        st = self.tech_state.setdefault(key, {})
        matches = st.setdefault("matches", {}).setdefault(mi, {})
        seen = matches.get("d1_seen")
        if not isinstance(seen, set):
            seen = set(seen or [])
            matches["d1_seen"] = seen

        # add and refresh left row only if this is newly seen
        if item_name not in seen:
            seen.add(item_name)
            # this will recompute: total_seen vs expected and paint 'SENT' in green automatically
            self._update_rows(key)


    def _approve_selected(self):
        item = self.tree.currentItem()
        if not item:
            return
        key = item.data(0, Qt.UserRole)
        st = self.tech_state.get(key)
        if not st:
            return

        sel = self.req_tree.currentItem()
        if not sel:
            QMessageBox.information(self, "Approve", "Expand a group and select a specific request.")
            return
        meta = sel.data(0, Qt.UserRole) or {}
        if meta.get("is_group"):
            QMessageBox.information(self, "Approve", "Expand a group and select a specific request.")
            return

        mi  = meta.get("match", 1)
        idx = meta.get("idx", -1)
        if idx < 0 or idx >= len(st["matches"][mi]["requests"]):
            return

        req = st["matches"][mi]["requests"][idx]
        typ = (req.get("type", "")).upper()
        if typ not in ("NOT_POSSIBLE", "EARLY_MARK"):
            QMessageBox.information(self, "Approve", "Select a 'Not possible' or 'Early' request to approve.")
            return


        item_name = req.get("item", "")
        ok, err = self._send_to_tech(st["ip"], f"APPROVE: Match={mi} Item='{item_name}'")
        if ok:
            now_ts = time.time()
            req["approved"] = True
            req["approved_ts"] = now_ts
            req["seen"] = True
            req["archived"] = True
            self.status_lbl.setText(f"Sent approval for: {item_name}")
            self._log(
                st=st, ip=st["ip"], match=mi, direction="out", typ="APPROVE",
                text="", item=item_name, section=req.get("section", ""), sender="SUPERVISOR",
                ts=now_ts, approved=True, approved_ts=now_ts
            )

            # Stop blinking for this specific entry and recompute for the match row(s)
            tup = (key, mi, idx)
            self._blink_list_entries.discard(tup)
            if hasattr(self, "_blink_entry_colors"):
                self._blink_entry_colors.pop(tup, None)
            self._recompute_blink_for_match(key, mi)

            # Refresh UI
            self.tree.viewport().update()
            self.req_tree.viewport().update()
            self._on_tree_select(item, None)
            self._update_rows(key)

            # Persist
            try:
                self._schedule_save_state()
            except Exception:
                pass
        else:
            self.status_lbl.setText(f"Failed to send message: {err}")
    def _on_req_context_menu(self, pos):
        """Right-click menu on the Requests tree (right pane)."""
        item = self.req_tree.itemAt(pos)
        if not item:
            return

        # Ensure clicked row becomes current for leaf ops
        if item and item not in self.req_tree.selectedItems():
            self.req_tree.setCurrentItem(item)

        meta = item.data(0, Qt.UserRole) or {}

        # Leaf (actual entry)?
        is_group = bool(isinstance(meta, dict) and meta.get("is_group"))
        menu = QMenu(self)

        act_mark = act_shift = None
        if not is_group:
            # Resolve the underlying record
            key = meta.get("key")
            try:
                mi = int(meta.get("match") or 1)
            except Exception:
                mi = 1
            idx = meta.get("idx")
            st = self.tech_state.get(key, {})
            rec = None
            try:
                rec = st.get("matches", {}).get(mi, {}).get("requests", [])[idx] if idx is not None else None
            except Exception:
                rec = None

            t = (rec.get("type","") or rec.get("tag","") or "").upper() if rec else ""
            if rec and t == "OVERDUE":
                act_mark  = menu.addAction("Mark task done for Tech")
                act_shift = menu.addAction("Shift task to next category on Tech")
                menu.addSeparator()

        # Existing delete action (works on selected leafs)
        leafs = [it for it in self.req_tree.selectedItems()
                if not ((it.data(0, Qt.UserRole) or {}).get("is_group"))]
        act_del = menu.addAction(f"Delete selected ({len(leafs)})")
        act_del.setEnabled(bool(leafs))
        act_del.triggered.connect(self._delete_selected_requests)
        # NEW actions
        act_copy = QAction("Copy to Reporting", self)
        act_copy.triggered.connect(self._req_copy_to_reporting)
        menu.addAction(act_copy)

        act_move = QAction("Move to Reporting", self)
        act_move.triggered.connect(self._req_move_to_reporting)
        menu.addAction(act_move)

        menu.exec_(self.req_tree.viewport().mapToGlobal(pos))
        chosen = menu.exec_(self.req_tree.viewport().mapToGlobal(pos))
        if not chosen:
            return

        # Handle our new actions
        if act_mark and chosen == act_mark or act_shift and chosen == act_shift:
            # need ip + fields for SUP_ACTION line
            ip = (st.get("ip","") or "").strip()
            if not ip:
                self.status_lbl.setText("No IP for this Tech.")
                return
            item_name = rec.get("item","")
            section   = rec.get("section","")
            if chosen == act_mark:
                line = f"SUP_ACTION type=MARK_DONE match={mi} item='{item_name}' section='{section}'"
            else:
                line = f"SUP_ACTION type=SHIFT_NEXT match={mi} item='{item_name}' section='{section}'"
            ok, err = self._send_to_tech(ip, line)
            self.status_lbl.setText("Sent action to Tech" if ok else f"Send failed: {err}")

    def _req_move_to_reporting(self):
        self._req_transfer_to_reporting(delete_after=True)

    def _req_copy_to_reporting(self):
        self._req_transfer_to_reporting(delete_after=False)

    def _req_transfer_to_reporting(self, delete_after: bool):
        """Copy/move selected Request rows into the per-match Reporting tree."""
        items = self.req_tree.selectedItems()
        if not items:
            return

        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")

        # Map a QTreeWidgetItem back to our request tuple (key, match_idx, req_idx)
        def _lookup_tuple_for_item(it):
            for tup, ref in self._req_item_index.items():
                if ref is it:
                    return tup
            return None

        moved = 0
        last_key = None
        last_mi = None

        for it in items:
            tup = _lookup_tuple_for_item(it)
            if not tup:
                continue  # skip headers/buckets
            key, match_idx, _req_idx = tup
            self._ensure_report_group(key, match_idx)  # register, no UI header now

            text = it.text(0).strip()
            new = QTreeWidgetItem([f"[{ts}] {text}"])
            # tag the reporting item with (key, match) so we can filter later
            new.setData(0, Qt.UserRole, {"key": key, "match": match_idx})
            self.report_tree.addTopLevelItem(new)

            moved += 1
            last_key, last_mi = key, match_idx

        if moved:
            self.report_status_lbl.setText(
                f"{'Moved' if delete_after else 'Copied'} {moved} item(s) to Reporting."
            )
            # Keep only the active match visible
            try:
                if getattr(self, "_current_selection", None):
                    ckey, cmi = self._current_selection
                    for i in range(self.report_tree.topLevelItemCount()):
                        tli = self.report_tree.topLevelItem(i)
                        meta = tli.data(0, Qt.UserRole) or {}
                        tkey, tmi = meta.get("key"), meta.get("match")
                        tli.setHidden(not (tkey == ckey and tmi == cmi))
            except Exception:
                pass

            # NEW: keep only the active match's group visible
            try:
                # Prefer current selection; fall back to the last moved item's match
                if getattr(self, "_current_selection", None):
                    ckey, cmi = self._current_selection
                else:
                    ckey, cmi = last_key, last_mi
                if ckey is not None and cmi is not None:
                    self._ensure_report_group(ckey, cmi)
                    for (k, m_), grp in list(self._report_groups.items()):
                        grp.setHidden(not (k == ckey and m_ == cmi))
            except Exception:
                pass

        # If moving, remove originals from Requests (bottom-up; no set() on Qt items)
        if delete_after and moved:
            def _remove_item(item):
                parent = item.parent()
                if parent is not None:
                    parent.removeChild(item)
                else:
                    idx = self.req_tree.indexOfTopLevelItem(item)
                    if idx >= 0:
                        self.req_tree.takeTopLevelItem(idx)

            for it in reversed(items):
                tup = _lookup_tuple_for_item(it)
                if tup:
                    _remove_item(it)

    def _delete_selected_requests(self):
        """Delete currently selected request/chat entries from the right pane."""
        # Left tree tells us which Tech key we’re on
        left_item = self.tree.currentItem()
        if not left_item:
            return
        key = left_item.data(0, Qt.UserRole)
        st = self.tech_state.get(key)
        if not st:
            return

        # Collect indices to delete by match
        selected = [
            it for it in self.req_tree.selectedItems()
            if not ((it.data(0, Qt.UserRole) or {}).get("is_group"))
        ]
        if not selected:
            return

        by_match = {}
        for it in selected:
            meta = it.data(0, Qt.UserRole) or {}
            mi = int(meta.get("match", 1))
            idx = int(meta.get("idx", -1))
            if idx >= 0:
                by_match.setdefault(mi, []).append(idx)

        # Remove from highest index downward to keep indices valid
        for mi, idxs in by_match.items():
            for idx in sorted(set(idxs), reverse=True):
                if 0 <= idx < len(st["matches"][mi]["requests"]):
                    # Stop blinking for this entry
                    tup = (key, mi, idx)
                    self._blink_list_entries.discard(tup)
                    if hasattr(self, "_blink_entry_colors"):
                        self._blink_entry_colors.pop(tup, None)
                    # Remove the record
                    try:
                        st["matches"][mi]["requests"].pop(idx)
                    except Exception:
                        pass
            # Recompute blink state for this match row
            try:
                self._recompute_blink_for_match(key, mi)
            except Exception:
                pass

        # Refresh UI and persist
        try:
            self._update_rows(key)
            self._on_tree_select(left_item, None)
            self.req_tree.clearSelection()
        except Exception:
            pass
        try:
            self._schedule_save_state()
        except Exception:
            pass
        self.status_lbl.setText("Deleted selected message(s).")


    def eventFilter(self, obj, event):
        """Let the Delete/Backspace key delete selected right-pane messages."""
        if obj is self.req_tree and event.type() == QEvent.KeyPress:
            if event.key() in (Qt.Key_Delete, Qt.Key_Backspace):
                self._delete_selected_requests()
                return True
        return super().eventFilter(obj, event)
    def _add_note(self):
        """Store a local supervisor note in the right pane (light yellow), not sent to Tech."""
        item = self.tree.currentItem()
        if not item:
            QMessageBox.information(self, "Note", "Select a Match row to attach this note to.")
            return

        key = item.data(0, Qt.UserRole)
        st = self.tech_state.get(key)
        if not st:
            return

        note = self.note_entry.text().strip()
        if not note:
            return

        # Work out which match (m1 or m2) this left-pane row corresponds to
        mi = None
        if st["items"].get("m1") is item:
            mi = 1
        elif st["items"].get("m2") is item:
            mi = 2

        if not mi:
            QMessageBox.information(self, "Note", "Select Match 1 or Match 2 to add a note.")
            return

        ts_now = time.time()
        rec = {
            "type": "NOTE", "match": mi, "from": "SUPERVISOR",
            "text": note, "ip": st.get("ip",""), "ts": ts_now,
            "seen": True  # notes aren't actionable; don't blink
        }
        st["matches"][mi]["requests"].append(rec)

        self.note_entry.clear()
        self._update_rows(key)
        self._schedule_save_state()
        self.status_lbl.setText("Note added.")

    def _send_message(self):
        item = self.tree.currentItem()
        if not item:
            return
        key = item.data(0, Qt.UserRole)
        st = self.tech_state.get(key)
        if not st:
            return

        msg = self.msg_entry.text().strip()
        if not msg:
            return

        # determine match index
        mi = None
        if st["items"].get("m1") is item:
            mi = 1
        elif st["items"].get("m2") is item:
            mi = 2

        if not mi:
            QMessageBox.information(self, "Send", "Select a Match row to send.")
            return

        # sanitize quotes for the wire line
        safe_msg = (msg or "").replace("'", "’")

        # send a NORMAL chat message (no Kind=REPORT here)
        ok, err = self._send_to_tech(st["ip"], f"MESSAGE: Match={mi} Text='{safe_msg}'")
        if ok:
            ts_now = time.time()
            # record outbound supervisor chat (marked seen: no blink)
            rec = {
                "type": "CHAT", "match": mi, "from": "SUPERVISOR", "text": msg,
                "ip": st["ip"], "ts": ts_now, "seen": True
            }
            st["matches"][mi]["requests"].append(rec)

            self._update_rows(key)
            self._log(
                st=st, ip=st["ip"], match=mi, direction="out", typ="CHAT",
                text=msg, item="", section="", sender="SUPERVISOR", ts=ts_now
            )
            self._on_tree_select(item, None)
            self.msg_entry.clear()
            self.status_lbl.setText("Message sent.")

            # persist
            try:
                self._schedule_save_state()
            except Exception:
                pass
        else:
            self.status_lbl.setText(f"Failed to send message: {err}")


    def _send_broadcast_message(self):
        """
        Prompt for a message and send it to all connected techs (all matches present).
        Also records a local CHAT entry for each match so it appears in the UI.
        """
        # Ask for the message
        text, ok = QInputDialog.getText(self, "Broadcast message", "Message to all techs:")
        if not ok:
            return
        msg = (text or "").strip()
        if not msg:
            return

        # Gentle apostrophe sanitization to match the single-quoted wire format
        safe_msg = msg.replace("'", "’")

        total_targets, sent, failed = 0, 0, 0
        ts_now = time.time()

        # Loop over all known techs
        for key, st in list(self.tech_state.items()):
            ip = (st or {}).get("ip", "")
            if not ip:
                continue
            matches = list((st.get("matches") or {}).keys())
            if not matches:
                continue

            for mi in matches:
                total_targets += 1
                ok2, err = self._send_to_tech(ip, f"MESSAGE: Match={mi} Text='{safe_msg}'")
                if ok2:
                    sent += 1
                    # Record locally (no blink)
                    rec = {
                        "type": "CHAT", "match": mi, "from": "SUPERVISOR", "text": msg,
                        "ip": ip, "ts": ts_now, "seen": True
                    }
                    try:
                        st["matches"][mi]["requests"].append(rec)
                    except Exception:
                        pass

                    # Log for CSV / audit
                    try:
                        self._log(
                            st=st, ip=ip, match=mi, direction="out", typ="CHAT",
                            text=msg, item="", section="", sender="SUPERVISOR", ts=ts_now
                        )
                    except Exception:
                        pass
                else:
                    failed += 1

            # Refresh the left row for this tech after updates
            try:
                self._update_rows(key)
            except Exception:
                pass

        # If we have a current selection, rebuild the right pane
        try:
            cur = self.tree.currentItem()
            if cur:
                self._on_tree_select(cur, None)
        except Exception:
            pass

        # Persist state
        try:
            self._schedule_save_state()
        except Exception:
            pass

        # Status line
        if total_targets == 0:
            self.status_lbl.setText("No connected techs to send to.")
        else:
            self.status_lbl.setText(f"Broadcast sent: {sent}/{total_targets} delivered; {failed} failed.")

    # ---------- Close ----------
    def closeEvent(self, ev):
        try:
            self.server.stop()
        except Exception:
            pass
        try:
            self._save_state()   # NEW (flush to disk on exit)
        except Exception:
            pass
        ev.accept()


    def _ingest_wire_line(self, ip: str, line: str):
        line = (line or "").strip()
        if not line:
            return

        # SETUP snapshot
        if line.upper().startswith("SETUP:"):
            payload = parse_setup(line)
            if payload:
                payload["ip"] = ip
                self.ui_queue.put(("setup", payload))
            return

        # General UPDATE
        if GEN_UPDATE_RE.match(line):
            upd = parse_gen_update(line)
            if upd:
                upd["ip"] = ip
                self.ui_queue.put(("update", upd))
            return

        # Day-1 EXPECT
        if D1_EXPECT_RE.match(line):
            kv = parse_kv_blob(line.split(":", 1)[1])
            try:
                cnt = int(re.sub(r"\D", "", kv.get("count", "0") or "0"))
            except Exception:
                cnt = 0
            evt = {
                "station":  kv.get("station",""),
                "operator": kv.get("operator",""),
                "match":    int(kv.get("match","1") or 1),
                "teams":    kv.get("teams",""),
                "count":    cnt,
                "ip":       ip
            }
            self.ui_queue.put(("d1_expect", evt))
            return

        # REQUEST (includes REPORT)
        if line.upper().startswith("REQUEST:"):
            req = parse_request(line)  # your existing helper -> dict
            if req:
                req["ip"] = ip
                # NEW: route REPORT to Reporting pane (separate UI event)
                kind = (req.get("type") or req.get("request") or "").upper()
                is_report = (kind == "REPORT") or (str(req.get("report","")).strip() == "1")
                if is_report:
                    # normalize payload for UI thread
                    try:
                        match_idx = int(req.get("match","1") or 1)
                    except Exception:
                        match_idx = 1
                    from_who  = req.get("from", "Tech")
                    text      = req.get("text", "")
                    self.ui_queue.put((
                        "report",  # <-- handle this in the UI thread: add yellow item to Reporting for (key, match)
                        {"match": match_idx, "from": from_who, "text": text, "ip": ip}
                    ))
                    return
                # non-REPORT requests flow as before
                self.ui_queue.put(("request", req))
            return

        # REPLY (legacy CHAT reply from tech)
        if line.upper().startswith("REPLY:"):
            kv = parse_kv_blob(line.split(":",1)[1])
            req = {
                "type": "CHAT",
                "match": int(kv.get("match","1") or 1),
                "from":  f"{kv.get('station','')} — {kv.get('operator','')}".strip(" —"),
                "text":  kv.get("text",""),
                "ip":    ip
            }
            self.ui_queue.put(("request", req))
            return

        # PROGRESS (legacy)
        if line.upper().startswith("PROGRESS:"):
            p = parse_legacy_progress(line)
            if p:
                who, pct = p
                self.ui_queue.put(("legacy_progress", {"who": who, "pct": pct, "ip": ip}))
            return

        # Unknown -> pass through (for logs/debug)
        self.ui_queue.put(("unknown", {"ip": ip, "text": line}))

    def _schedule_save_state(self):
        """Debounced save to disk."""
        if not hasattr(self, "_save_timer") or self._save_timer is None:
            self._save_timer = QTimer(self)
            self._save_timer.setSingleShot(True)
            self._save_timer.timeout.connect(self._save_state)
        self._save_timer.start(STATE_SAVE_INTERVAL_MS)

    def _upsert_update(self, key: str, mi: int, rec: dict) -> int:
        """
        Keep only the latest UPDATE per (section,item) within a match.
        Returns the index where the record lives.
        """
        m = self.tech_state[key]["matches"][mi]
        # normalize e.g. strip trailing " [PENDING]" that might have leaked from Tech UI
        sec_norm  = (rec.get("section","") or "").strip().lower()
        name_norm = re.sub(r"\s*\[pending\]\s*$", "", (rec.get("item","") or ""), flags=re.I).strip().lower()
        item_key  = (sec_norm, name_norm)

        for i in range(len(m["requests"]) - 1, -1, -1):
            r = m["requests"][i]
            if (r.get("type","").upper() == "UPDATE" and
                ((r.get("section","") or "").strip().lower(),
                (r.get("item","") or "").strip().lower()) == item_key):
                m["requests"][i] = rec
                return i
        m["requests"].append(rec)
        return len(m["requests"]) - 1
    def _filter_requests_for_save(self, reqs: list) -> list:
        if STATE_SAVE_MODE == "full":
            return reqs

        kept = []
        latest_update = {}     # (section,item) -> record
        chats = []

        for r in reqs:
            typ = (r.get("type","") or "").upper()
            if not r.get("seen", False):
                kept.append(r)                  # preserve unseen so blinking restores
                continue
            if typ == "UPDATE":
                sec_norm  = (r.get("section","") or "").strip().lower()
                name_norm = re.sub(r"\s*\[pending\]\s*$", "", (r.get("item","") or ""), flags=re.I).strip().lower()
                key = (sec_norm, name_norm)
                latest_update[key] = r
         # keep only the latest UPDATE per item
            elif typ in ("CHAT", "NOTE"):
                chats.append(r)                 # trim later
               # trim later
            # seen SHIFT / NOT_POSSIBLE / OVERDUE / D1_MISSING can be dropped for persistence

        kept.extend(latest_update.values())
        if STATE_KEEP_CHAT > 0 and chats:
            kept.extend(chats[-STATE_KEEP_CHAT:])
        return kept

    def _serialize_state_entry(self, key: str, st: dict) -> dict:
        out = {
            "key": key,
            "station": st.get("station",""),
            "operator": st.get("operator",""),
            "ip": st.get("ip",""),
            "matches": {}
        }
        for mi in (1,2):
            mm = st["matches"][mi]
            to_save = self._filter_requests_for_save(mm.get("requests", []))
            out["matches"][str(mi)] = {
                "teams": mm.get("teams",""),
                "day": mm.get("day",""),
                "ko": mm.get("ko",""),
                "ko_date": mm.get("ko_date",""),
                "progress": mm.get("progress", None),
                "d1_seen": list(mm.get("d1_seen") or []),
                "d1_missing": bool(mm.get("d1_missing", False)),
                "d1_reminder_sent": bool(mm.get("d1_reminder_sent", False)),
                "requests": []
            }
            for r in to_save:
                out["matches"][str(mi)]["requests"].append({
                    "type": r.get("type",""),
                    "item": r.get("item",""),
                    "section": r.get("section",""),
                    "from": r.get("from",""),
                    "text": r.get("text",""),
                    "ts": float(r.get("ts", 0) or 0),
                    "seen": bool(r.get("seen", False)),
                    "approved": bool(r.get("approved", False)),
                    "approved_ts": float(r.get("approved_ts", 0) or 0),
                    "progress": r.get("progress", None),
                    "due_ts": r.get("due_ts", None),
                    "total": r.get("total", None),
                    "catchup": int(r.get("catchup", 0) or 0),
                })
        return out

    def _save_state(self):
        try:
            blob = {"techs": []}
            for key, st in self.tech_state.items():
                blob["techs"].append(self._serialize_state_entry(key, st))
            os.makedirs(SUPPORT_DIR, exist_ok=True)
            with open(STATE_PATH, "w", encoding="utf-8") as f:
                json.dump(blob, f, ensure_ascii=False, indent=2)
            # cosmetic
            if hasattr(self, "status_lbl"):
                self.status_lbl.setText("State saved.")
        except Exception as e:
            if hasattr(self, "status_lbl"):
                self.status_lbl.setText(f"Save failed: {e}")

    def _load_state(self):
        if not os.path.exists(STATE_PATH):
            return
        try:
            with open(STATE_PATH, "r", encoding="utf-8") as f:
                blob = json.load(f)
        except Exception as e:
            if hasattr(self, "status_lbl"):
                self.status_lbl.setText(f"Restore failed: {e}")
            return

        for ent in blob.get("techs", []):
            key = ent.get("key") or self._key(ent.get("station",""), ent.get("operator",""), ent.get("ip",""))
            st = self.tech_state.setdefault(key, {
                "station": ent.get("station",""),
                "operator": ent.get("operator",""),
                "ip": ent.get("ip",""),
                "matches": {
                    1: {"teams":"", "day":"", "ko":"", "ko_date":"", "progress":None, "requests":[],
                        "d1_seen": set(), "d1_missing": False, "d1_eval_timer": None, "d1_reminder_sent": False},
                    2: {"teams":"", "day":"", "ko":"", "ko_date":"", "progress":None, "requests":[],
                        "d1_seen": set(), "d1_missing": False, "d1_eval_timer": None, "d1_reminder_sent": False},
                },
                "items": {}, "last_ts": time.time()
            })
            st["station"] = ent.get("station","") or st["station"]
            st["operator"] = ent.get("operator","") or st["operator"]
            st["ip"] = ent.get("ip","") or st["ip"]

            # ensure tree nodes exist
            self._ensure_nodes(key)

            # matches
            for mi in (1,2):
                mm = ent.get("matches", {}).get(str(mi), {}) or {}
                dst = st["matches"][mi]
                dst["teams"] = mm.get("teams","")
                dst["day"] = mm.get("day","")
                dst["ko"] = mm.get("ko","")
                dst["ko_date"] = mm.get("ko_date","")
                dst["progress"] = mm.get("progress", None)
                dst["d1_seen"] = set(mm.get("d1_seen") or [])
                dst["d1_missing"] = bool(mm.get("d1_missing", False))
                dst["d1_reminder_sent"] = bool(mm.get("d1_reminder_sent", False))
                dst["requests"] = []

                # restore requests
                for r in mm.get("requests", []):
                    rec = {
                        "type": (r.get("type","") or "").upper(),
                        "match": mi,
                        "item": r.get("item",""),
                        "section": r.get("section",""),
                        "from": r.get("from",""),
                        "text": r.get("text",""),
                        "ts": float(r.get("ts", 0) or 0),
                        "seen": bool(r.get("seen", False)),
                        "approved": bool(r.get("approved", False)),
                        "approved_ts": float(r.get("approved_ts", 0) or 0),
                        "progress": r.get("progress", None),
                        "due_ts": r.get("due_ts", None),
                        "total": r.get("total", None),
                        "catchup": int(r.get("catchup", 0) or 0),
                    }
                    dst["requests"].append(rec)

                # rebuild blinking from unseen
                for idx, rec in enumerate(dst["requests"]):
                    if rec.get("seen"):
                        continue
                    t = rec.get("type","").upper()
                    if t in ("OVERDUE", "D1_MISSING"):
                        items = st["items"]
                        if items.get(f"m{mi}"):
                            self._blink_tree_items.add(id(items[f"m{mi}"]))
                            self._blink_colors[id(items[f"m{mi}"])] = Qt.red
                        if items.get("root"):
                            self._blink_tree_items.add(id(items["root"]))
                            self._blink_colors[id(items["root"])] = Qt.red
                        self._blink_list_entries.add((key, mi, idx))
                    elif t in ("CHAT", "SHIFT", "NOT_POSSIBLE"):
                        self._mark_unseen(key, mi, idx, color=Qt.yellow)

                # re-arm D1 evaluation timer if KO is today
                if self._is_today_str(dst.get("ko_date","")) and not dst.get("d1_eval_timer"):
                    tmr = QTimer(self)
                    tmr.setSingleShot(True)
                    tmr.timeout.connect(lambda k=key, _mi=mi: self._eval_d1_missing(k, _mi))
                    tmr.start(D1_EVAL_DELAY_SEC * 1000)
                    dst["d1_eval_timer"] = tmr

            self._update_rows(key)

        if hasattr(self, "status_lbl"):
            self.status_lbl.setText("State restored.")

    def _reset_everything(self):
        from PyQt5.QtWidgets import QMessageBox
        if QMessageBox.question(self, "Reset", "Clear saved state and current view?", QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return

        # stop any timers
        for st in self.tech_state.values():
            for mi in (1,2):
                t = st["matches"][mi].get("d1_eval_timer")
                if t:
                    try: t.stop()
                    except Exception: pass
                st["matches"][mi]["d1_eval_timer"] = None

        # clear memory/UI
        self.tech_state.clear()
        self._blink_tree_items.clear()
        self._blink_list_entries.clear()
        self._blink_colors.clear()
        self._items_by_id.clear()
        self.tree.clear()
        self.req_tree.clear()

        # remove file
        try:
            if os.path.exists(STATE_PATH):
                os.remove(STATE_PATH)
        except Exception:
            pass

        if hasattr(self, "status_lbl"):
            self.status_lbl.setText("All state cleared.")
    def _refresh_view(self):
        """
        Force a full refresh:
        - Ping/sync all techs (pull latest)
        - Recompute & update left tree rows
        - Rebuild right-hand request list for current selection
        """
        try:
            # 1) Ask for async probes (returns immediately; updates arrive via ui_queue)
            try:
                self._schedule_probes()
            except Exception:
                pass


            # 2) Remember what is currently selected (so we can restore details pane)
            cur_item = self.tree.currentItem() if hasattr(self, "tree") else None

            # 3) Rebuild / update rows for all known techs
            for key in list(self.tech_state.keys()):
                self._ensure_nodes(key)
                self._update_rows(key)   # updates Hours to KO, MD-1, progress, request counts, etc.

            # 4) Re-apply selection to rebuild the right side (requests/groups)
            if cur_item is not None:
                try:
                    self._on_tree_select(cur_item, None)
                except Exception:
                    pass

            # 5) Nudge the view to repaint
            try:
                self.tree.viewport().update()
                self.req_tree.viewport().update()
            except Exception:
                pass

            if hasattr(self, "status_lbl"):
                self.status_lbl.setText("Refreshed.")
        except Exception as e:
            if hasattr(self, "status_lbl"):
                self.status_lbl.setText(f"Refresh failed: {e}")
    def _schedule_probes(self):
        """Timer-driven: enqueue light probes for IPs whose backoff window has elapsed."""
        now = time.time()
        for ip in TECH_IPS:
            st = self._ip_state.get(ip)
            if not st or now < st["next"]:
                continue
            # Enqueue worker (returns immediately; UI thread stays free)
            self._pool.submit(self._probe_ip_worker, ip)

    def _probe_ip_worker(self, ip: str):
        """Run in worker thread. Quick connect -> if OK, do a sync; else backoff."""
        ok, _ = self._send_to_tech(ip, "PING_SUP", timeout=0.8)  # short connect timeout
        if ok:
            # reset backoff
            self._ip_state[ip]["backoff"] = 0
            self._ip_state[ip]["next"] = 0
            # do light sync (also in worker; it only enqueues to ui_queue)
            try:
                self._sync_from_tech(ip)
            except Exception:
                # treat as transient failure; apply a small backoff
                self._apply_backoff(ip)
        else:
            self._apply_backoff(ip)

    def _apply_backoff(self, ip: str):
        """Exponential backoff per IP: 30s -> 60s -> 120s -> ... cap 300s."""
        st = self._ip_state[ip]
        b = st["backoff"] or 30
        nb = min(300, b * 2) if st["backoff"] else 30
        st["backoff"] = nb
        st["next"] = time.time() + nb

    def _sync_from_tech(self, ip: str):
        """Ask a Tech for its current state (SYNC) and ingest all lines returned.
        Robust to long payloads: read in chunks until the peer closes or we time out.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3.5)
                s.connect((ip, TECH_ACK_PORT))
                s.sendall(b"SYNC\n")

                buf = bytearray()
                # read until peer closes or we time out after first data
                # (cap to avoid unbounded memory if a peer misbehaves)
                MAX_BYTES = 2 * 1024 * 1024  # 2 MB cap
                got_any = False
                while True:
                    try:
                        chunk = s.recv(8192)
                        if not chunk:
                            break
                        buf.extend(chunk)
                        got_any = True
                        if len(buf) >= MAX_BYTES:
                            break
                        # after first data, tighten timeout for snappier exit
                        s.settimeout(0.30)
                        # if Tech sends line-delimited frames, we can keep reading;
                        # syncing may return many lines, so don't stop at the first '\n'
                    except socket.timeout:
                        # no more data forthcoming
                        break

            # Normalize newlines and ingest line by line
            text = bytes(buf).decode("utf-8", errors="ignore").replace("\r", "\n")
            for ln in text.split("\n"):
                if ln.strip():
                    self._ingest_wire_line(ip, ln)
            return got_any
        except Exception:
            return False


    def _ping_all_techs(self):
        for ip in TECH_IPS:
            ok, _ = self._send_to_tech(ip, "PING_SUP")
            if ok:
                self._sync_from_tech(ip)
    def _apply_backoff(self, ip: str):
        """Exponential backoff per IP, capped & jittered: 30s -> 60s -> 120s (cap 180s)."""
        import random, time
        st = self._ip_state[ip]
        prev = st["backoff"] or 0
        nb = 30 if prev == 0 else min(180, prev * 2)  # cap at 3 minutes
        jitter = random.randint(-15, 15)  # spread retries to avoid bursts
        st["backoff"] = nb
        st["next"] = time.time() + nb + jitter


# ---------- Run ----------
if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    win = SupervisorWindow()
    win.show()
    sys.exit(app.exec_())
