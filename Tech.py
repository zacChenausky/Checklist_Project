
# ===============================
# SECTION: Imports & Debug Logger
# ===============================

# ── Standard library
import csv
import os
import re
import socket
import threading
import unicodedata
import json
from collections import defaultdict
from configparser import ConfigParser
from datetime import datetime, timedelta, time as dtime

# ── PyQt5
from PyQt5.QtCore import Qt, QTimer, QSize, QPoint, pyqtSignal, QUrl, QDate
from PyQt5.QtGui import QIcon, QFont, QPixmap, QDesktopServices, QColor
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QComboBox, QRadioButton,
    QHBoxLayout, QVBoxLayout, QGroupBox, QPushButton, QMessageBox,
    QSizePolicy, QScrollArea, QCheckBox, QMenu, QDateEdit, QToolButton,
    QDialog, QDialogButtonBox, QListWidget, QListWidgetItem, QAction, QWidgetAction
)

# Optional Pillow for broader image support
try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

# Toggleable debug logger; flip to False to silence debug prints.
DEBUG_LOG = False
def _log(msg: str):
    if DEBUG_LOG:
        try:
            print(msg)
        except Exception:
            pass

# ===============================
# SECTION: Table of Contents
# ===============================
#  1) Constants & Paths
#  2) Timers & Visual Constants
#  3) Helper Utilities
#  4) Data Loaders (stations/managers/matches/logos/manuals/issues)
#  5) Config Save/Load
#  6) Networking helpers (settings, send/recv)
#  7) Checklist selection & parsing
#  8) Time/Window helpers
#  9) UI Widgets / Screens
# 10) Application Entry (__main__)

__version__ = "0010"
# Tech.py — PyQt5 refactor (bright, classy UI) with robust Supervisor messaging + console tracing
# Requires: pip install PyQt5 pillow

import csv
import os
import re
import socket
import threading
import unicodedata
from configparser import ConfigParser
from datetime import datetime, timedelta, time as dtime
from PyQt5.QtWidgets import QMenu
import json
from collections import defaultdict
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtGui import QFont, QPixmap, QDesktopServices
from PyQt5.QtCore import Qt, QTimer, QSize, QPoint, pyqtSignal, QUrl, QDate
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QComboBox, QRadioButton,
    QHBoxLayout, QVBoxLayout, QGroupBox, QPushButton, QMessageBox,
    QSizePolicy, QScrollArea, QCheckBox, QMenu, QDateEdit
)
from PyQt5.QtWidgets import QToolButton, QListWidget, QListWidgetItem, QButtonGroup

# Optional Pillow for broader image support
try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

# ===============================
# SECTION: Constants & Paths
# ===============================
# ---------- Paths ----------
# ===============================
# SECTION: Constants & Paths
# ===============================
SUPPORT_DIR = r"C:\Matchday\VAR\Checklist\SupportingFiles"
if not os.path.isdir(SUPPORT_DIR):
    here = os.path.abspath(os.path.dirname(__file__))
    guess = os.path.join(here, "SupportingFiles")
    if os.path.isdir(guess):
        SUPPORT_DIR = guess

PATH_STATIONS   = os.path.join(SUPPORT_DIR, "TechStation.ini")
PATH_MANAGERS   = os.path.join(SUPPORT_DIR, "TechMangers.ini")
PATH_MATCHES    = os.path.join(SUPPORT_DIR, "MatchInformation.csv")
PATH_CONFIG     = os.path.join(SUPPORT_DIR, "config.ini")
PATH_TECHINI    = os.path.join(SUPPORT_DIR, "tech.ini")
PATH_LOGOMAP    = os.path.join(SUPPORT_DIR, "LogoMap.ini")
PATH_LOGOS_DIR  = os.path.join(SUPPORT_DIR, "logos")
PATH_CHECKLISTS = os.path.join(SUPPORT_DIR, "Checklists")
PATH_STAD_CL    = os.path.join(PATH_CHECKLISTS, "stadiums")
PATH_MANUALS_DIR  = os.path.join(SUPPORT_DIR, "Manuals")
PATH_MANUALS_FILE = os.path.join(PATH_MANUALS_DIR, "Manual.ini")
# Manuals files can live anywhere; Manual.ini stays in PATH_MANUALS_DIR
MANUALS_ROOT = PATH_MANUALS_DIR  # default
# --- Manual supervisor target (VPN fallback) ---
def _read_manual_sup_from_supervisor(path: str = PATH_TECHINI):
    parser = ConfigParser(inline_comment_prefixes=(";", "#"))
    try:
        parser.read(path, encoding="utf-8")
    except Exception:
        return None
    if not parser.has_section("Supervisor"):
        return None
    ip   = (parser.get("Supervisor", "ip",   fallback="") or "").strip()
    port = parser.getint("Supervisor", "port", fallback=5000)
    name = (parser.get("Supervisor", "name", fallback="Supervisor") or "").strip()
    if ip:
        print(f"[TECH][CONF] Manual Supervisor target = {ip}:{port} ({name})", flush=True)
        return (ip, port, name)
    return None

MANUAL_SUP = _read_manual_sup_from_supervisor()

# Optional override via SupportingFiles\tech.ini → [Manuals] root = <path>
try:
    _m_cfg = ConfigParser(inline_comment_prefixes=(";", "#"))
    if os.path.exists(PATH_TECHINI):
        _m_cfg.read(PATH_TECHINI, encoding="utf-8")
        if _m_cfg.has_section("Manuals"):
            _root = (_m_cfg.get("Manuals", "root", fallback="") or "").strip()
            if _root:
                # allow tokens + env vars
                _root = _root.replace("{SUPPORT_DIR}", SUPPORT_DIR).replace("{THIS}", PATH_MANUALS_DIR)
                MANUALS_ROOT = os.path.abspath(os.path.expandvars(_root))
except Exception as e:
    _log("[CONF][WARN] Manuals root override ignored: {e}")

# ---------- Timer / visual config ----------
# ===============================
# SECTION: Timers & Visual Constants
# ===============================
GAME_WINDOW_HOURS = 2
# ===============================
# SECTION: Timers & Visual Constants
# ===============================
TIMER_TICK_SECS   = 30
DUE_BLINK_THRESHOLD_MIN = 10
REMINDER_MINUTES = (10, 5, 1)  # reminder popups relative to section due time
# ---------- Reminder Dialog ----------
class ReminderDialog(QDialog):
    """
    Modal popup that lists pending (unchecked) tasks for a section and lets the
    tech mark them done or shift them to the next hour category.
    """
    def __init__(self, parent, section_title: str, tasks: list[str]):
        super().__init__(parent)

        # Make it behave like a real alert over everything
        self.setWindowFlags(self.windowFlags() | Qt.WindowStaysOnTopHint | Qt.Dialog)
        self.setWindowModality(Qt.ApplicationModal)   # block entire app
        self.setWindowTitle(f"Pending tasks — {section_title}")
        self.resize(520, 440)

        # Optional audible nudge
        try:
            QApplication.beep()
        except Exception:
            pass

        from PyQt5.QtWidgets import QVBoxLayout, QLabel, QWidget, QScrollArea, QCheckBox, QDialogButtonBox
        v = QVBoxLayout(self)

        header = QLabel("<b>Pending tasks</b> — mark completed or shift to next hour category.")
        v.addWidget(header)

        # Scrollable list of checkboxes
        area = QScrollArea(self); area.setWidgetResizable(True)
        inner = QWidget(); area.setWidget(inner)
        iv = QVBoxLayout(inner)
        self._checks = []
        for t in tasks:
            cb = QCheckBox(t, inner)
            self._checks.append(cb)
            iv.addWidget(cb)
        iv.addStretch(1)
        v.addWidget(area, 1)

        # Buttons
        btns = QDialogButtonBox(self)
        self.btn_done   = btns.addButton("Mark Done", QDialogButtonBox.AcceptRole)
        self.btn_shift  = btns.addButton("Shift to Next Hour", QDialogButtonBox.AcceptRole)
        self.btn_cancel = btns.addButton(QDialogButtonBox.Cancel)
        v.addWidget(btns)

        self._action = None
        def on_clicked(btn):
            if btn is self.btn_done:
                self._action = "MARK_DONE";  self.accept()
            elif btn is self.btn_shift:
                self._action = "SHIFT_NEXT"; self.accept()
            else:
                self._action = "CANCEL";     self.reject()
        btns.clicked.connect(on_clicked)

        # Center & raise
        try:
            self.show(); self.raise_(); self.activateWindow()
            geo = self.frameGeometry()
            center = QApplication.desktop().screenGeometry(self).center()
            geo.moveCenter(center); self.move(geo.topLeft())
        except Exception:
            pass

    def selected_tasks(self) -> list[str]:
        return [cb.text() for cb in self._checks if cb.isChecked()]

    def action(self) -> str:
        return self._action or "CANCEL"

# ---------- Helpers ----------
def _sanitize_filename(s: str) -> str:
    s = "".join(ch for ch in s if ch.isalnum() or ch in ("_", "-", " ")).strip()
    return s.replace(" ", "_")

def _sanitize_component(s: str) -> str:
    bad = '<>:"/\\|?*'
    return "".join(ch for ch in s if ch not in bad).strip()

def _normalize_key(s: str) -> str:
    if not s: return ""
    nk = unicodedata.normalize("NFKD", s)
    nk = "".join(ch for ch in nk if not unicodedata.combining(ch))
    return nk.lower().strip()

# ---------- Loaders ----------
# ===============================
# SECTION: Data Loaders
# ===============================
def load_stations():
    out = []
    try:
        with open(PATH_STATIONS, "r", encoding="utf-8") as f:
            for ln in f:
                s = ln.strip()
                if s and not s.startswith("#"):
                    out.append(s)
    except FileNotFoundError:
        pass
    _log("[LOAD] Stations: {len(out)}")
    return out

def load_managers():
    items = []
    try:
        with open(PATH_MANAGERS, "r", encoding="utf-8") as f:
            for ln in f:
                raw = ln.strip()
                if not raw or raw.startswith("#"): continue
                name, station = raw, ""
                if "-" in raw:
                    head, tail = raw.rsplit("-", 1)
                    if head and tail:
                        name, station = head.strip(), tail.strip()
                items.append({"name": name, "station": station})
    except FileNotFoundError:
        pass
    # de-dupe
    seen, uniq = set(), []
    for it in items:
        if it["name"] not in seen:
            seen.add(it["name"]); uniq.append(it)
    _log("[LOAD] Managers: {len(uniq)}")
    return uniq

def load_matches():
    if not os.path.exists(PATH_MATCHES):
        _log("[LOAD] MatchInformation.csv not found; continuing with empty list")
        return [], {}
    required = ["matchday","hometeam","awayteam","stadium","matchid","andlanguage"]
    rows = []
    with open(PATH_MATCHES, "r", encoding="utf-8-sig", newline="") as f:
        sample = f.read(2048); f.seek(0)
        delimiter = ";" if ";" in sample and "," not in sample else ","
        try:
            dialect = csv.Sniffer().sniff(sample)
            delimiter = dialect.delimiter
        except Exception:
            pass
        first = f.readline().strip(); f.seek(0)
        has_header = False
        if first:
            parts = [p.strip().lower() for p in first.split(delimiter)]
            if any(p in parts for p in required):
                has_header = True
        if has_header:
            rdr = csv.DictReader(f, delimiter=delimiter)
            for r in rdr:
                r = {(k or "").strip().lower(): (v or "").strip() for k, v in r.items()}
                rows.append({k: r.get(k,"") for k in required})
        else:
            rdr = csv.reader(f, delimiter=delimiter)
            for cols in rdr:
                cols = [(c or "").strip() for c in cols]
                if len(cols) < 6: continue
                rows.append(dict(zip(required, cols[:6])))
    by_day = {}
    for r in rows:
        day = r.get("matchday","")
        if not day: continue
        by_day.setdefault(day, []).append(r)
    # sort by numeric part of matchid when possible
    for d in by_day:
        try:
            by_day[d].sort(key=lambda x: int("".join(ch for ch in x.get("matchid","0") if ch.isdigit())))
        except Exception:
            pass
    days = sorted(by_day.keys())
    _log("[LOAD] Matchdays: {len(days)} | total rows: {len(rows)}")
    return days, by_day

# ---------- Logo maps ----------
def _load_logo_map_from_cfg(path: str) -> dict:
    mapping = {}
    cfg = ConfigParser(); cfg.optionxform = str
    try:
        cfg.read(path, encoding="utf-8")
        if cfg.has_section("logos"):
            for k, v in cfg.items("logos"):
                mapping[_normalize_key(k)] = v.strip()
    except Exception:
        pass
    return mapping

def _load_logo_map_from_plain(path: str) -> dict:
    mapping = {}
    try:
        with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
            for ln in f:
                s = ln.strip()
                if not s or s.startswith("#") or s.startswith(";"): continue
                if "=" not in s: continue
                left, right = s.split("=", 1)
                key = _normalize_key(left.strip())
                val = right.strip()
                if " #" in val: val = val.split(" #", 1)[0].strip()
                if " ;" in val: val = val.split(" ;", 1)[0].strip()
                mapping[key] = val
    except Exception:
        pass
    return mapping

def load_logo_map() -> dict:
    mapping = {}
    if os.path.exists(PATH_LOGOMAP):
        mapping.update(_load_logo_map_from_cfg(PATH_LOGOMAP))
        if not mapping:
            mapping.update(_load_logo_map_from_plain(PATH_LOGOMAP))
    try:
        for fname in os.listdir(SUPPORT_DIR):
            low = fname.lower()
            if not low.startswith("teamlogo"): continue
            if not (low.endswith(".ini") or low.endswith(".txt")): continue
            path = os.path.join(SUPPORT_DIR, fname)
            m = _load_logo_map_from_cfg(path) or _load_logo_map_from_plain(path)
            mapping.update(m)
    except Exception:
        pass
    _log("[LOAD] Logo map entries: {len(mapping)}")
    return mapping
def wipe_all_config_file():
    """
    Hard-reset: delete config.ini entirely (preferred).
    Falls back to writing an empty file if deletion fails
    (e.g., locked by AV or permissions).
    """
    try:
        if os.path.exists(PATH_CONFIG):
            os.remove(PATH_CONFIG)
            _log("[SAVE] Removed {PATH_CONFIG}")
            return True
    except Exception as e:
        _log("[SAVE][WARN] Could not remove {PATH_CONFIG}: {e}")

    # Fallback: create a truly empty config file
    try:
        cfg = ConfigParser()
        with open(PATH_CONFIG, "w", encoding="utf-8") as f:
            cfg.write(f)
        _log("[SAVE] Wrote empty config.ini")
        return True
    except Exception as e:
        _log("[SAVE][ERR] Could not write empty config.ini: {e}")
        return False

def load_manuals(path: str = PATH_MANUALS_FILE) -> dict:
    """
    Parse Manuals/Manual.ini

    Format:
      -CATEGORY-
      Title A - https://example.com
      Title B -
      -ANOTHER-
      Title C - http://...

    Returns: { "CATEGORY": [("Title A","url"), ("Title B",""), ...], ... }
    """
    manuals = {}
    if not os.path.exists(path):
        return manuals

    cur = None
    with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
        for raw in f:
            ln = raw.strip()
            if not ln:
                continue
            if ln.startswith("-") and ln.endswith("-") and len(ln) > 2:
                cur = ln.strip("-").strip()
                manuals.setdefault(cur, [])
                continue
            if cur is None:
                continue
            # split on the FIRST " - "
            if " - " in ln:
                title, url = ln.split(" - ", 1)
            else:
                title, url = ln, ""
            manuals[cur].append((title.strip(), url.strip()))
    return manuals
def _is_url(s: str) -> bool:
    s = (s or "").strip().lower()
    return s.startswith("http://") or s.startswith("https://")

def _find_manual_file(name: str) -> str | None:
    """
    Resolve a manual target to a local file path.
    - If 'name' is absolute and exists -> return it
    - Else look under MANUALS_ROOT (recursive), matching case-insensitively.
      If the given name has no extension, match by base name (ignoring spaces/underscores).
    """
    if not name:
        return None
    p = name.strip().strip('"').strip("'")

    # absolute path?
    if os.path.isabs(p) and os.path.exists(p):
        return p

    # relative to manuals root
    candidate = os.path.join(MANUALS_ROOT, p)
    if os.path.exists(candidate):
        return candidate

    # fuzzy search inside manuals root (and subfolders)
    base = os.path.splitext(os.path.basename(p))[0]

    def _norm(x: str) -> str:
        x = x.lower().strip()
        x = x.replace(" ", "").replace("_", "")
        return x

    want = _norm(base)
    best = None
    for root, _, files in os.walk(MANUALS_ROOT):
        for f in files:
            full = os.path.join(root, f)
            if os.path.exists(candidate) and os.path.samefile(full, candidate):
                return full
            name_noext = os.path.splitext(f)[0]
            if _norm(f) == _norm(os.path.basename(p)) or _norm(name_noext) == want:
                best = full
                # prefer exact filename match (including extension)
                if _norm(f) == _norm(os.path.basename(p)):
                    return full
    return best


def load_stadium_issues(path: str = os.path.join(PATH_STAD_CL, "Issues.ini")) -> dict:
    """
    Parses Issues.ini with format:
      -Saputo Stadium
      1- No a
      2- abcdefg

      -Inter&Co Stdium
      1- ...
    Returns { normalized_stadium_name: [issue1, issue2, ...], ... }
    """
    issues = {}
    if not os.path.exists(path):
        return issues

    def _norm(s: str) -> str:
        s = (s or "").replace("&", "and")
        s = _normalize_key(s)  # already trims/accents
        return re.sub(r"\s+", " ", s).strip()

    cur_key = None
    try:
        with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
            for raw in f:
                ln = raw.strip()
                if not ln:
                    continue
                if ln.startswith("-"):
                    stadium = ln.lstrip("-").strip()
                    cur_key = _norm(stadium)
                    issues.setdefault(cur_key, [])
                else:
                    m = re.match(r"^\s*\d+\s*[-.)]\s*(.+)\s*$", ln)
                    if m and cur_key:
                        issues[cur_key].append(m.group(1).strip())
    except Exception:
        pass
    return issues

# ---------- Config (last used) ----------
def load_config():
    cfg = ConfigParser()
    if os.path.exists(PATH_CONFIG):
        try:
            cfg.read(PATH_CONFIG, encoding="utf-8")
        except Exception:
            pass
    return cfg

SAVED_PREFIX = "SavedChecklist"

def save_config_payload(payload: dict):
    cfg = load_config()
    if not cfg.has_section("LastUsed"):
        cfg.add_section("LastUsed")
    cfg["LastUsed"] = {
        "operator": payload.get("operator",""),
        "station": payload.get("station",""),
        "match_count": str(payload.get("match_count",1)),

        "m1_day": payload.get("m1",{}).get("matchday",""),
        "m1_home": payload.get("m1",{}).get("hometeam",""),
        "m1_away": payload.get("m1",{}).get("awayteam",""),
        "m1_time": payload.get("m1",{}).get("time",""),
        "m1_date": payload.get("m1",{}).get("date",""),
        "m1_remi": "yes" if payload.get("m1",{}).get("is_remi",False) else "no",
        "m1_stadium": payload.get("m1",{}).get("stadium",""),
        "m1_ws": payload.get("m1",{}).get("ws",""),    

        "m2_day": payload.get("m2",{}).get("matchday",""),
        "m2_home": payload.get("m2",{}).get("hometeam",""),
        "m2_away": payload.get("m2",{}).get("awayteam",""),
        "m2_time": payload.get("m2",{}).get("time",""),
        "m2_date": payload.get("m2",{}).get("date",""),
        "m2_remi": "yes" if payload.get("m2",{}).get("is_remi",False) else "no",
        "m2_stadium": payload.get("m2",{}).get("stadium",""),
        "m2_ws": payload.get("m2",{}).get("ws",""),  
    }
    os.makedirs(os.path.dirname(PATH_CONFIG), exist_ok=True)
    with open(PATH_CONFIG, "w", encoding="utf-8") as f:
        cfg.write(f)
    _log("[SAVE] Wrote last-used config")

def _match_key(info: dict) -> str:
    # stable identifier per match; now includes explicit calendar date
    home = _normalize_key(info.get("hometeam",""))
    away = _normalize_key(info.get("awayteam",""))
    stad = _normalize_key(info.get("stadium",""))
    day  = str(info.get("matchday","")).strip()
    date = (info.get("date","") or "").strip()  # yyyy-mm-dd
    return f"date={date}|day={day}|home={home}|away={away}|stad={stad}"

def _saved_section_for_key(key: str) -> str:
    return f"{SAVED_PREFIX}|{key}"

def load_saved_states(key: str) -> tuple[dict, list]:
    """return (state_map, reloc_list)
       state_map: {(section_title_lower, item_text_lower): state}
       reloc_list: [{"title": "...", "text": "..."}]  (desired placements)
    """
    cfg = load_config()
    sec = _saved_section_for_key(key)
    if not cfg.has_section(sec):
        # legacy fallback (pre-date keys)
        legacy = "|".join(part for part in key.split("|") if not part.startswith("date="))
        sec_legacy = _saved_section_for_key(legacy)
        if not cfg.has_section(sec_legacy):
            return {}, []
        sec = sec_legacy

    raw_states = cfg.get(sec, "states", fallback="[]")
    raw_reloc  = cfg.get(sec, "relocations", fallback="[]")
    try:
        lst_states = json.loads(raw_states)
    except Exception:
        lst_states = []
    try:
        lst_reloc = json.loads(raw_reloc)
    except Exception:
        lst_reloc = []

    state_map = {}
    for row in lst_states:
        t = (row.get("title","").strip().lower(), row.get("text","").strip().lower())
        state_map[t] = row.get("state","open")

    _log("[LOAD] Saved states for {key}: {len(state_map)} items; reloc={len(lst_reloc)}")
    return state_map, lst_reloc

def save_current_states(key: str, model: dict):
    """persist every item state AND which section each item currently sits in"""
    rows = []
    reloc = []
    for sec in model.get("sections", []):
        title = sec.get("title","")
        for it in sec.get("items", []):
            rows.append({"title": title, "text": it.get("text",""), "state": it.get("state","open")})
            reloc.append({"title": title, "text": it.get("text","")})

    cfg = load_config()
    secname = _saved_section_for_key(key)
    if not cfg.has_section(secname):
        cfg.add_section(secname)

    cfg.set(secname, "states", json.dumps(rows, ensure_ascii=False))
    cfg.set(secname, "relocations", json.dumps(reloc, ensure_ascii=False))

    with open(PATH_CONFIG, "w", encoding="utf-8") as f:
        cfg.write(f)
    _log("[SAVE] Persisted {len(rows)} item states (+relocations) for {key}")


def clear_saved_states(keys: list):
    cfg = load_config()
    removed = 0
    for k in keys:
        sec = _saved_section_for_key(k)
        if cfg.has_section(sec):
            cfg.remove_section(sec)
            removed += 1
    with open(PATH_CONFIG, "w", encoding="utf-8") as f:
        cfg.write(f)
    _log("[SAVE] Cleared saved states for {removed} matches")

# ---------- Tech.ini (ack listener only) ----------
# ===============================
# SECTION: Networking Helpers (settings, send/recv)
# ===============================
def read_tech_settings(path: str = PATH_TECHINI):
    if not os.path.exists(path):
        _log("[ERR] Missing tech.ini at {path}")
        QMessageBox.critical(None, "Missing tech.ini", f"Required file not found:\n{path}")
        raise SystemExit(1)

    parser = ConfigParser(inline_comment_prefixes=(";", "#"))
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    if "[Supervisor]" not in raw and "[supervisor]" not in raw:
        parser.read_string("[Supervisor]\n" + raw)
    else:
        parser.read(path, encoding="utf-8")

    sec = "Supervisor"
    bind_ip = parser.get(sec, "bind_ip", fallback="0.0.0.0")
    ack_port = parser.getint(sec, "ack_port", fallback=None)

    if not ack_port:
        _log("[ERR] Missing ack_port in tech.ini [Supervisor]")
        QMessageBox.critical(None, "Bad config", f"Missing required ack_port in {path}")
        raise SystemExit(1)

    _log("[CONF] Tech ACK listener bind_ip={bind_ip} ack_port={ack_port}")
    return bind_ip, ack_port


# ---------- Networking ----------
# ===============================
# SECTION: Networking Helpers (settings, send/recv)
# ===============================
def send_line(ip: str, port: int, text: str, timeout: float = 3.5):
    # --- DEBUG start: classify & log every TX line once ---
    upper = (text or "").strip().upper()
    if upper.startswith("MESSAGE:"):
        kind = "REPORT" if "KIND=REPORT" in upper else "CHAT"
        print(f"[TECH][TX][{kind}] -> {ip}:{port} :: {text[:180]}")
    elif upper.startswith("REQUEST:"):
        req_type = upper.split(None, 1)[0].split(":",1)[1].strip()
        print(f"[TECH][TX][{req_type}] -> {ip}:{port} :: {text[:180]}")
    else:
        print(f"[TECH][TX] -> {ip}:{port} :: {text[:180]}")
    # --- DEBUG end ---

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall((text + "\n").encode("utf-8"))
        return True, ""
    except Exception as e:
        print(f"[TECH][TX][ERR] {ip}:{port} :: {e}")
        return False, str(e)



# ===============================
# SECTION: Checklist Selection & Parsing
# ===============================
def _choose_checklist_file(match: dict):
    """
    New rule (no 'stadiums' folder anymore):
      Defaults in PATH_CHECKLISTS:
        regular.ini, remi.ini
      Stadium overrides in the same folder:
        regular-<stadium>.ini, remi-<stadium>.ini
      Competition presets (Other):
        <Competition>_regular.ini, <Competition>_remi.ini
      Competition + Stadium overrides:
        <Competition>_regular-<stadium>.ini, <Competition>_remi-<stadium>.ini
    Matching is case-insensitive and accent/spacing tolerant.
    """
    def _slug(s: str) -> str:
        # normalize accents → lowercase → keep only [a-z0-9]
        s = _normalize_key(s or "")
        return "".join(ch for ch in s if ch.isalnum())

    stadium_raw = (match.get("stadium") or "").strip()
    competition_raw = (match.get("competition") or "").strip()
    is_remi = bool(match.get("is_remi"))

    mode = "remi" if is_remi else "regular"
    stad_slug = _slug(stadium_raw)
    comp_slug = _slug(competition_raw)

    # Helper: scan PATH_CHECKLISTS for a filename that matches after slugging
    def _find_candidate(cand_prefix: str, want_stad_slug: str = ""):
        """Examples:
           cand_prefix='USOpenCup_regular' want_stad_slug=''       -> USOpenCup_regular.ini
           cand_prefix='USOpenCup_regular' want_stad_slug='allianz'-> USOpenCup_regular-Allianz Field.ini
        """
        try:
            for fname in os.listdir(PATH_CHECKLISTS):
                if not fname.lower().endswith(".ini"):
                    continue
                low = fname.lower()
                if not low.startswith(cand_prefix.lower()):
                    continue
                if want_stad_slug:
                    # require a trailing '-<stadium>.ini' with matching slug
                    if "-" not in fname:
                        continue
                    stadium_part = fname.split("-", 1)[1][:-4]  # between '-' and '.ini'
                    if _slug(stadium_part) == want_stad_slug:
                        return os.path.join(PATH_CHECKLISTS, fname)
                else:
                    # require exact prefix + '.ini' (no stadium suffix)
                    # allow any case in the actual filename
                    base_no_ext = fname[:-4]
                    if base_no_ext.lower() == cand_prefix.lower():
                        return os.path.join(PATH_CHECKLISTS, fname)
        except Exception:
            pass
        return None

    # 1) If a competition is chosen, prefer its stadium override then its default
    if comp_slug:
        cand = _find_candidate(f"{competition_raw}_{mode}", stad_slug)  # competition + stadium
        if cand:
            return cand, f"{competition_raw} — {mode.upper()} ({stadium_raw})" if stadium_raw else f"{competition_raw} — {mode.upper()}"
        cand = _find_candidate(f"{competition_raw}_{mode}")              # competition default
        if cand:
            return cand, f"{competition_raw} — {mode.upper()}"

    # 2) No competition or not found: try mode + stadium override
    if stad_slug:
        cand = _find_candidate(mode, stad_slug)  # e.g., regular-Allianz Field.ini
        if cand:
            return cand, f"{mode.upper()} — {stadium_raw}"

    # 3) Fallback: global default for mode
    default_path = os.path.join(PATH_CHECKLISTS, f"{mode}.ini")
    return default_path, mode.capitalize()

# ===============================
# SECTION: Checklist Selection & Parsing
# ===============================
def _parse_checklist(path: str):
    sections = []
    cur = {"title": "Checklist", "items": []}
    try:
        with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
            for raw in f:
                s = raw.strip()
                if not s: continue
                if s.startswith("---") and s.endswith("---"):
                    title = s.strip("- ").strip()
                    if cur["items"] or cur.get("title") != "Checklist":
                        sections.append(cur)
                    cur = {"title": title, "items": []}
                    continue
                if "-" in s and s.split("-", 1)[0].strip().isdigit():
                    s = s.split("-", 1)[1].strip()
                cur["items"].append({"text": s, "state": "open"})
        if cur["items"] or cur.get("title") != "Checklist":
            sections.append(cur)
    except FileNotFoundError:
        pass
    _log("[LOAD] Checklist sections from {os.path.basename(path)}: {len(sections)}")
    return sections

def _inject_day1_if_missing(sections: list) -> list:
    """If the chosen checklist has no 'Matchday -1' section, pull it from regular.ini and prepend."""
    has_day1 = any("matchday -1" in (s.get("title","").lower()) for s in sections)
    if has_day1:
        return sections
    # try to pull Day-1 block from regular.ini
    base = os.path.join(PATH_CHECKLISTS, "regular.ini")
    try:
        base_secs = _parse_checklist(base)
        day1_secs = [s for s in base_secs if "matchday -1" in (s.get("title","").lower())]
        if day1_secs:
            return day1_secs + sections
    except Exception:
        pass
    return sections

# ---------- Timing helpers ----------
# ===============================
# SECTION: Time & Window Helpers
# ===============================
def _parse_ko_datetime(ko_str: str, date_str: str | None = None) -> datetime:
    ko_str = (ko_str or "").strip()
    try:
        hh, mm = map(int, ko_str.split(":", 1))
    except Exception:
        hh, mm = 23, 45
    if date_str:
        from datetime import datetime as _dt
        try:
            d = _dt.strptime(date_str, "%Y-%m-%d").date()
        except Exception:
            d = datetime.now().date()
        return datetime.combine(d, dtime(hour=hh, minute=mm))
    # fallback (old behavior)
    now = datetime.now()
    candidate = datetime.combine(now.date(), dtime(hour=hh, minute=mm))
    if candidate <= now:
        candidate += timedelta(days=1)
    return candidate

def _extract_hours_before(title: str):
    low = (title or "").lower()
    if "hour" in low and "before" in low:
        digits = "".join(ch for ch in low if ch.isdigit())
        try:
            return int(digits)
        except Exception:
            return None
    return None

def _augment_sections_with_windows(sections, ko_dt: datetime):
    for i, sec in enumerate(sections):
        title = sec.get("title","")
        hrs = _extract_hours_before(title)
        if hrs is not None:
            start = ko_dt - timedelta(hours=hrs)
            due = ko_dt
            for j in range(i+1, len(sections)):
                nxt = _extract_hours_before(sections[j].get("title",""))
                if nxt is not None:
                    due = ko_dt - timedelta(hours=nxt)
                    break
            sec["start"], sec["due"] = start, due
        else:
            tl = title.lower()
            if "during game" in tl:
                sec["start"], sec["due"] = ko_dt, ko_dt + timedelta(hours=GAME_WINDOW_HOURS)
            elif "post match" in tl or "post-match" in tl:
                sec["start"], sec["due"] = ko_dt + timedelta(hours=GAME_WINDOW_HOURS), None
            else:
                sec["start"], sec["due"] = None, None
    return sections

def _fmt_hhmm(dt: datetime) -> str:
    return dt.strftime("%H:%M")

def _human_delta(target: datetime, now: datetime) -> str:
    diff = target - now
    sign = "-" if diff.total_seconds() < 0 else ""
    diff = abs(diff)
    h = int(diff.total_seconds() // 3600)
    m = int((diff.total_seconds() % 3600) // 60)
    return f"{sign}{h}h {m:02d}m" if h else f"{sign}{m}m"

def _clear_layout(layout):
    """Remove all widgets/layouts from a layout without replacing it."""
    if layout is None:
        return
    while layout.count():
        item = layout.takeAt(0)
        w = item.widget()
        if w:
            w.setParent(None)
            w.deleteLater()
        elif item.layout():
            _clear_layout(item.layout())

# ---------- PyQt widgets ----------
def _bold_label(text, size=10):
    lbl = QLabel(text)
    f = QFont()
    f.setPointSize(size)
    f.setBold(True)
    lbl.setFont(f)
    return lbl

# ===============================
# SECTION: UI Class — MatchCard
# ===============================
class MatchCard(QGroupBox):
    def __init__(self, title: str):
        super().__init__(title)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setStyle(normal=True)

    def setStyle(self, normal=True):
        if normal:
            self.setStyleSheet("""
                QGroupBox {
                    background: #ffffff;
                    border: 2px solid #cbd5e1;   /* darker, visible */
                    border-radius: 12px;
                    font-weight: 600;
                    margin-top: 10px;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    subcontrol-position: top left;
                    padding: 4px 8px;
                }
            """)
        else:
            self.setStyleSheet("""
                QGroupBox {
                    background: #ffead5;        /* light orange fill */
                    border: 2px solid #f59e0b;  /* strong orange border */
                    border-radius: 12px;
                    font-weight: 700;
                    margin-top: 10px;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    subcontrol-position: top left;
                    padding: 4px 8px;
                }
            """)

# ===============================
# SECTION: UI Class — Section
# ===============================
class Section(QGroupBox):
    def __init__(self, title: str):
        super().__init__(title)
        self.setStyleSheet("""
            QGroupBox {
                background: #ffffff;
                border: 1px solid #e2e2e2;
                border-radius: 10px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 4px 8px;
                font-weight: 600;
            }
        """)

# ---------- Main window ----------
# ===============================
# SECTION: UI Class — MainWindow
# ===============================
class MainWindow(QMainWindow):
    rosterChanged = pyqtSignal()
    popupRequested = pyqtSignal(int, str)     # (match_idx, text)
    approveRequested = pyqtSignal(int, str)   # (match_idx, item_text)
    supPingDone = pyqtSignal(bool)
    supActionRequested = pyqtSignal(str, int, str, str)  # NEW
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Tech – Checklist v{__version__}")
        self.setWindowIcon(QIcon("app_icon.ico"))
        self.setMinimumSize(1100, 720)
        self.setStyleSheet("""
            QWidget { background: #f5f7fb; font-size: 14px; color:#111; }
            QComboBox, QLineEdit {
                background: #ffffff; border: 1px solid #d0d0d0; border-radius: 8px; padding: 6px 8px;
            }
            QRadioButton { font-weight: 600; }
            QPushButton { border-radius: 10px; padding: 8px 14px; font-weight: 700; }
            QPushButton#accent { background:#22c55e; color:#fff; }
            QPushButton#secondary { background:#e5e7eb; color:#111; }
            QLabel.formlbl { font-weight: 700; }
        """)

        # Data caches
        self.stations = load_stations()
        self.managers = load_managers()
        self.days, self.by_day = load_matches()
        self.logo_map = load_logo_map()
        self.stadium_issues = load_stadium_issues()
        self.manuals = load_manuals()
        self._day1_buttons = []               # keep references to all Day-1 buttons
        self.supPingDone.connect(self._apply_sup_status)
        _log("[LOAD] Stadium issues: {sum(len(v) for v in self.stadium_issues.values())} items across {len(self.stadium_issues)} stadiums")
        # --- queued outbound lines for Supervisor pull (SYNC) ---
        self._outbox = []  # list[str]
        # register Qt meta-type to silence queued-connection warning from background threads
        # when roster changes (from UDP listener/prune thread), rebuild combo on GUI thread
        self.rosterChanged.connect(self._refresh_sup_combo)
        # --- supervisors online roster (id-less for now; key by ip) ---
        self.supervisors_online = {}   # ip -> {"ip": ip, "name": str, "port": int, "last_seen": datetime}
        self._sup_ttl_secs = 90
        # Multi-select state
        self._multi_sel = {}     # {(match_idx, sec_i): set(item_indices)}
        self._sel_anchor = {}    # {(match_idx, sec_i): anchor_item_index}
        self._cb_index = {}      # {checkbox_widget: (match_idx, sec_i, item_i)}

        # prune timer
        self._sup_prune_timer = QTimer(self)
        self._sup_prune_timer.timeout.connect(self._prune_supervisors)
        self._sup_prune_timer.start(15000)  # every 15s

        # [CLEANUP] removed duplicate _chat_log dict init (defaultdict is used)   # [(ts, sender, text), ...]
        self._chat_log = defaultdict(list) 
        self.bind_ip, self.ack_port = read_tech_settings()
        def _queue_for_supervisor_impl(line: str):
            if not (line and isinstance(line, str)):
                return

            # --- Manual Supervisor override ---
            if MANUAL_SUP:
                ip, port, name = MANUAL_SUP
                ok, _ = send_line(ip, port, line, timeout=2.5)
                if ok:
                    _log(f"[WIRE][→{name}] {line}")
                    return
                # if manual fails, fall through to discovery roster

            # existing logic: use discovered supervisors
            for (ip, port, name) in self._sup_roster:
                ok, _ = send_line(ip, port, line, timeout=2.5)
                if ok:
                    _log(f"[WIRE][→{name}] {line}")
                    return

            # --- Build target list (either the selected one, or all known) ---
            targets = []  # list of tuples: (ip, port, name)

            # If a specific supervisor is selected in the combo, send only to that one.
            target_ip = None
            try:
                if hasattr(self, "sup_target_combo"):
                    sel = self.sup_target_combo.currentData()
                    # we store ip in item data; "ALL" is broadcast
                    if sel and sel != "ALL":
                        target_ip = sel
            except Exception:
                pass

            if target_ip:
                rec = self.supervisors_online.get(target_ip, {}) or {}
                ip, port = rec.get("ip"), rec.get("port")
                if ip and port:
                    targets.append((ip, port, rec.get("name", "?")))
            else:
                # Fallback/broadcast to all known supervisors.
                for ip, rec in list(self.supervisors_online.items()):
                    r_ip, r_port = rec.get("ip"), rec.get("port")
                    if r_ip and r_port:
                        targets.append((r_ip, r_port, rec.get("name", "?")))

            # --- De-dupe by (ip,port) to avoid double-sends from overlapping paths ---
            seen = set()
            uniq = []
            for ip, port, name in targets:
                key = (ip, port)
                if key in seen:
                    continue
                seen.add(key)
                uniq.append((ip, port, name))


            # --- Send ---
            sent_any = False
            for ip, port, name in uniq:
                ok, _ = send_line(ip, port, line, timeout=2.5)
                if ok:
                    sent_any = True
                    _log(f"[WIRE][→{name}] {line}")  # fixed f-string formatting

            # If nobody reachable now, queue it to outbox for later flush.
            if not sent_any:
                self._outbox.append(line)
                _log(f"[WIRE][QUEUE] {line}")  # fixed f-string formatting

        # expose as method
        self._queue_for_supervisor = _queue_for_supervisor_impl
        self._sent_overdue_keys = set()
        # Models/state
        self.models = {1: None, 2: None}  # per-match models with sections/timers
        self.task_widgets = {}            # (m, s_i, i_i) -> QCheckBox
        self._blink_phase = False
        self.payload = {}
        self._prefer_load_saved = True

        # timers
        self._timer_entries = {1: [], 2: []}
        self._timer = None
        # countdown labels per match: {1: {"label": QLabel, "ko": datetime}, 2: {...}}
        self._ko_labels = {}
        self._reminder_fired = {1: {}, 2: {}}  # per-section gates: {match_idx: {section_title: set(minute_marks)}}

        # Supervisor status
        self._sup_online = False
        self.sup_status_lbl = None
        self._sup_ping = None
        self._need_catchup = False
        # Offline auto-flip timer (optional)
        self._sup_offline_timer = QTimer(self)
        self._sup_offline_timer.setSingleShot(True)
        self._sup_offline_timer.timeout.connect(lambda: self.supPingDone.emit(False))

        # Build UI
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0,0,0,0)

        # Banner
        banner = QLabel("CHECKLIST")
        f = QFont(); f.setPointSize(22); f.setBold(True)
        banner.setFont(f)
        banner.setAlignment(Qt.AlignCenter)
        banner.setStyleSheet("QLabel{background:#e53935;color:#fff;padding:10px;}")
        banner.setFixedHeight(56)
        outer.addWidget(banner)

        # Pages
        self.pages = QWidget()
        pages_layout = QVBoxLayout(self.pages); pages_layout.setContentsMargins(16,16,16,16)
        outer.addWidget(self.pages)

        self.page_setup = QWidget(); self.page_check = QWidget()
        for p in (self.page_setup, self.page_check):
            p.setVisible(False)
            pages_layout.addWidget(p)

        self._build_setup_page()
        self._load_last_used()
        # Cross-thread UI updates (signals)
        self.popupRequested.connect(self._popup_message)
        self.approveRequested.connect(self._mark_item_supervisor_approved)
        self.supActionRequested.connect(
            lambda action, mi, section, text:
                self._handle_sup_action(action=action, match_idx=mi, section=section, item_text=text)
        )

        self._show(self.page_setup)

        # Start ack listener
        threading.Thread(target=self._ack_server, daemon=True).start()
        threading.Thread(target=self._ack_discovery_listener, daemon=True).start()
    def _check_and_show_deadline_reminders(self):
        """
        Runs on the same timer tick. For each match/section, if we're exactly
        10, 5, or 1 minute before the section 'due' time AND there are pending
        tasks, show a one-time popup that lets the tech mark or shift tasks.
        """
        now_dt = datetime.now()
        for match_idx in (1, 2):
            model = self.models.get(match_idx)
            if not model:
                continue

            for sec in model.get("sections", []):
                title = (sec.get("title") or "").strip()
                start = sec.get("start")
                due   = sec.get("due")
                if not (title and start and due):
                    continue

                # Only near the end of the window
                if not (start <= now_dt < due):
                    continue

                remaining = (due - now_dt).total_seconds()
                if remaining <= 0:
                    continue
                mins_left = int(remaining // 60)

                if mins_left not in REMINDER_MINUTES:
                    continue

                # Collect pending items (not done/approved)
                pending = [
                    (it.get("text") or "").strip()
                    for it in sec.get("items", [])
                    if (it.get("state") not in ("done", "approved")) and (it.get("text") or "").strip()
                ]
                if not pending:
                    continue

                fired = self._reminder_fired.setdefault(match_idx, {}).setdefault(title, set())
                if mins_left in fired:
                    continue  # already shown at this threshold

                # Show dialog
                try:
                    dlg = ReminderDialog(self, title, pending)
                    dlg.show()                # ensure it’s visible immediately
                    dlg.raise_()              # bring to front
                    dlg.activateWindow()      # give it focus
                    if dlg.exec_() == QDialog.Accepted:
                        chosen = dlg.selected_tasks()
                        act = dlg.action()

                        if chosen and act in ("MARK_DONE", "SHIFT_NEXT"):
                            for item_text in chosen:
                                try:
                                    # If your action handler is named differently, update this call.
                                    self._handle_sup_action(
                                        action=act,
                                        match_idx=match_idx,
                                        section=title,
                                        item_text=item_text
                                    )
                                except Exception as e:
                                    _log(f"[REMINDER][APPLY][ERR] {e}")
                except Exception as e:
                    _log(f"[REMINDER][DIALOG][ERR] {e}")

                fired.add(mins_left)

    # ----- Pages -----
    def _show(self, page):
        self.page_setup.setVisible(False)
        self.page_check.setVisible(False)
        page.setVisible(True)

    def _build_setup_page(self):
        lay = QVBoxLayout(self.page_setup)
        lay.setSpacing(12)

        hdr = Section("Operator / Station / Matches")
        lay.addWidget(hdr)
        row = QHBoxLayout(); row.setSpacing(16)
        hdr.setLayout(row)
        # Make the heading heavier and the box compact
        hdr.setStyleSheet("""
            QGroupBox {
                background: #ffffff;
                border: 1px solid #e2e2e2;
                border-radius: 10px;
                margin-top: 8px;
                padding-top: 8px;
                padding-bottom: 6px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 4px 8px;
                font-weight: 700;
            }
        """)
        hdr.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        hdr.setMaximumHeight(92)
        row.setContentsMargins(10, 6, 10, 6)

        op_lbl = _bold_label("Operator", size=13); op_lbl.setStyleSheet("font-weight:700;")
        row.addWidget(op_lbl)
        self.operator_cb = QComboBox()
        self.operator_cb.setEditable(True)
        self.operator_cb.addItems([m["name"] for m in self.managers])
        self.operator_cb.currentTextChanged.connect(self._on_operator_changed)
        row.addWidget(self.operator_cb)

        st_lbl = _bold_label("Station",  size=13); st_lbl.setStyleSheet("font-weight:700;")
        row.addWidget(st_lbl)
        self.station_cb = QComboBox()
        self.station_cb.setEditable(True)
        self.station_cb.addItems(self.stations)
        # Make sure the display isn’t clipped
        self.station_cb.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.station_cb.setMinimumContentsLength(4)   # widen the line-edit area
        self.station_cb.setMinimumWidth(90)           # safety width so “01 / 101 / 201” etc. don’t clip
        row.addWidget(self.station_cb)


        mc_lbl = _bold_label("Matches",  size=13); mc_lbl.setStyleSheet("font-weight:700;")
        row.addWidget(mc_lbl)
        self.rb1 = QRadioButton("1"); self.rb2 = QRadioButton("2"); self.rb1.setChecked(True)
        self.rb1.toggled.connect(self._toggle_match2)
        row.addWidget(self.rb1); row.addWidget(self.rb2); row.addStretch(1)

        # Match cards
        self.card1 = MatchCard("Match 1"); self._build_match_card(self.card1, 1); lay.addWidget(self.card1)
        self.card2 = MatchCard("Match 2"); self._build_match_card(self.card2, 2); lay.addWidget(self.card2)
        self.card2.setVisible(False)

        # Footer (retrieve/reset/next)
        footer = QHBoxLayout(); lay.addLayout(footer)
        self.load_saved_chk = QCheckBox("Retrieve saved (if any)")
        self.load_saved_chk.setChecked(True)
        footer.addWidget(self.load_saved_chk)

        btn_reset_saved = QPushButton("Reset saved")
        btn_reset_saved.setObjectName("secondary")
        btn_reset_saved.clicked.connect(self._reset_saved_for_current_selection)
        footer.addWidget(btn_reset_saved)

        footer.addStretch(1)
        btn_next = QPushButton("Next → Checklist"); btn_next.setObjectName("accent"); btn_next.clicked.connect(self._go_checklist)
        footer.addWidget(btn_next)
    def _send_catchup_snapshot(self):
        """
        Send a baseline UPDATE for every hourly checklist item (checked or not),
        so Supervisor can render the full list immediately.
        Also send a single OVERDUE line for items that are currently overdue & unchecked.
        """
        from datetime import datetime
        now = datetime.now()

        def _base_kv(m):
            st = (self.station_cb.currentText() or "").strip()
            op = (self.operator_cb.currentText() or "").strip()
            return f"station='{st}' operator='{op}' match={m}"

        for m in (1, 2):
            model = self.models.get(m)
            if not model:
                continue
            for sec in model.get("sections", []):
                title = sec.get("title", "")
                items = sec.get("items", [])
                total = len(items)
                due_dt = sec.get("due")  # may be None
                try:
                    due_ts = int(due_dt.timestamp()) if due_dt else None
                except Exception:
                    due_ts = None

                # derive "hours before KO" if the section has it (optional)
                try:
                    hours_before = _extract_hours_before(title)
                except Exception:
                    hours_before = None

                for it in items:
                    text = (it.get("text") or "").strip()
                    if not text:
                        continue
                    state = (it.get("state") or "open").lower()
                    checked = state in ("done", "approved", "ok")

                    # 1) Always send UPDATE for list rendering
                    line = (
                        "UPDATE: "
                        f"{_base_kv(m)} "
                        f"section='{title}' item='{text}' "
                        f"progress={'100' if checked else '0'} "
                        f"state={'ON' if checked else 'OFF'} "
                        f"total={total} "
                        f"{'' if due_ts is None else f'due_ts={due_ts}'}"
                    )
                    self._queue_for_supervisor(line)

                    # 2) If overdue & not checked → send ONE OVERDUE (latched)
                    key = (m, hours_before, text.lower())
                    if (not checked) and (due_ts is not None) and (due_dt and now > due_dt) and key not in self._sent_overdue_keys:
                        self._sent_overdue_keys.add(key)
                        self._queue_for_supervisor(
                            "OVERDUE: "
                            f"{_base_kv(m)} section='{title}' item='{text}' "
                            f"due_ts={due_ts}"
                        )

    def _build_match_card(self, card: MatchCard, idx: int):
        """Setup-page match card: left form beside a vertically-centered logo."""
        # Root layout for the card (wipe any old children if present)
        if card.layout():
            while card.layout().count():
                item = card.layout().takeAt(0)
                w = item.widget()
                if w:
                    w.setParent(None)
                    w.deleteLater()

        v = QVBoxLayout(card)
        v.setSpacing(6)
        v.setContentsMargins(10, 8, 10, 10)

        # Main row: left (form) | right (logo)
        main = QHBoxLayout()
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(12)
        v.addLayout(main)

        # -------- Left: form (grid so everything stays on one line)
        from PyQt5.QtWidgets import QGridLayout
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(8)
        grid.setContentsMargins(0, 0, 0, 0)
        main.addLayout(grid, 1)

        # Controls
        md_lbl   = _bold_label("Matchday")
        md_cb    = QComboBox()
        md_cb.addItem("— Select matchday —")   # placeholder (index 0)
        md_cb.addItems(self.days)
        md_cb.setCurrentIndex(0)


        match_lbl = _bold_label("Match")
        match_cb  = QComboBox()
        match_cb.addItem("— Select match —")   # placeholder stays until user chooses


        time_lbl = _bold_label("Time (24h)")
        time_cb  = QComboBox()
        time_cb.addItems([f"{h:02d}:{m:02d}" for h in range(11, 24) for m in (0, 15, 30, 45)])


        date_lbl = _bold_label("Date")
        date_de  = QDateEdit()
        date_de.setCalendarPopup(True)
        date_de.setDisplayFormat("yyyy-MM-dd")
        date_de.setDate(QDate.currentDate())

        # Auto-bump to tomorrow if the chosen KO time already passed today (until user manually changes date)
        _date_manual = {"v": False}
        def _on_date_changed(_):
            _date_manual["v"] = True
        date_de.dateChanged.connect(_on_date_changed)

        def _suggest_date_from_time(tstr: str) -> QDate:
            try:
                hh, mm = map(int, tstr.split(":",1))
            except Exception:
                hh, mm = 23, 45
            now = QDate.currentDate()
            from datetime import datetime as _dt, time as _time
            today_dt = _dt.combine(_dt.now().date(), _time(hh, mm))
            return now.addDays(1) if _dt.now() >= today_dt else now

        def _on_time_changed(tstr: str):
            if not _date_manual["v"]:
                date_de.setDate(_suggest_date_from_time(tstr))
        time_cb.currentTextChanged.connect(_on_time_changed)
        _on_time_changed(time_cb.currentText())

        remi_lbl = _bold_label("REMI Game")
        remi_no  = QRadioButton("No"); remi_yes = QRadioButton("Yes"); remi_no.setChecked(True)
        remi_row = QHBoxLayout(); remi_row.setContentsMargins(0,0,0,0); remi_row.setSpacing(8)
        remi_row.addWidget(remi_no); remi_row.addWidget(remi_yes); remi_row.addStretch(1)
        # --- Other (competition) picker
        comp_lbl = _bold_label("Other")
        comp_cb  = QComboBox()
        comp_cb.addItems(["— None —", "USOpenCup", "LeaguesCup", "OnsiteGame"])
        comp_cb.setCurrentIndex(0)
        setattr(self, f"m{idx}_comp_cb", comp_cb)

        ws_lbl = _bold_label("WS")
        ws_cb  = QComboBox()
        ws_cb.addItems(["Choose workstation"] + [str(n) for n in range(101, 116)])  # placeholder + 101..115
        ws_cb.setCurrentIndex(0)
        setattr(self, f"m{idx}_ws_cb", ws_cb)

        # When WS changes, store to payload and push a fresh SETUP to Supervisor
        def _on_ws_changed(txt, i=idx):
            self.payload.setdefault(f"m{i}", {})["ws"] = txt.strip()
            try:
                save_config_payload(self.payload)
            except Exception:
                pass
            # notify Supervisor so WS shows on its cards right away
            try:
                self._queue_for_supervisor(self._format_setup_message())
            except Exception:
                pass

        ws_cb.currentTextChanged.connect(_on_ws_changed)

        # Put into grid (controls must be created BEFORE they’re added)
        grid.addWidget(md_lbl,     0, 0)
        grid.addWidget(md_cb,      0, 1)
        grid.addWidget(match_lbl,  0, 2)
        grid.addWidget(match_cb,   0, 3)

        grid.addWidget(time_lbl,   1, 0)
        grid.addWidget(time_cb,    1, 1)
        grid.addWidget(date_lbl,   1, 2)
        grid.addWidget(date_de,    1, 3)

        grid.addWidget(remi_lbl,   2, 0)
        grid.addLayout(remi_row,   2, 1, 1, 3)

        grid.addWidget(comp_lbl,   3, 0)
        grid.addWidget(comp_cb,    3, 1)
        grid.addWidget(ws_lbl,     3, 2)
        grid.addWidget(ws_cb,      3, 3)

        # Make the last column stretch so the row stays single-line
        grid.setColumnStretch(0, 0)
        grid.setColumnStretch(1, 0)
        grid.setColumnStretch(2, 0)
        grid.setColumnStretch(3, 1)

        # -------- Right: logo (centered vertically, fixed box, no cropping)
        logo_box = QVBoxLayout()
        logo_box.setContentsMargins(4, 0, 4, 0)
        logo_box.addStretch(1)
        logo_lbl = QLabel()
        logo_lbl.setFixedSize(QSize(110, 110))
        logo_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        logo_lbl.setStyleSheet("QLabel{background:transparent;}")
        logo_box.addWidget(logo_lbl, 0, Qt.AlignRight | Qt.AlignVCenter)
        logo_box.addStretch(1)
        main.addLayout(logo_box, 0)

        # ---------- Populate matches for the selected day + logo behavior
        mapping = {}

        def on_day_change(val):
            mapping.clear()
            match_cb.clear()

            # If placeholder or nothing picked yet → keep Match blank too
            if not val or val.strip() == "— Select matchday —":
                match_cb.addItem("— Select match —")
                match_cb.setCurrentIndex(0)
                logo_lbl.clear()
                return

            # Populate matches for the selected day, but keep placeholder selected
            match_cb.addItem("— Select match —")
            for r in self.by_day.get(val, []):
                label = f"{r.get('hometeam','')} vs {r.get('awayteam','')}"
                mapping[label] = r
                match_cb.addItem(label)
            match_cb.setCurrentIndex(0)   # ← do NOT auto-pick a real match
            logo_lbl.clear()


        def on_match_change(val):
            row = mapping.get(val, {})
            home = row.get("hometeam","") or (val.split(" vs ")[0] if " vs " in val else "")
            path_logo, _ = self._find_logo_path(home)
            if path_logo:
                try:
                    pm = QPixmap(path_logo).scaled(110, 110, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    logo_lbl.setPixmap(pm)
                except Exception:
                    logo_lbl.clear()
            else:
                logo_lbl.clear()

        md_cb.currentTextChanged.connect(on_day_change)
        match_cb.currentTextChanged.connect(on_match_change)

        def on_remi_toggle():
            card.setStyle(normal=not remi_yes.isChecked())
        remi_yes.toggled.connect(on_remi_toggle)

        # initial fill
        on_day_change(md_cb.currentText())

        # ---------- keep references for collection later
        setattr(self, f"m{idx}_md_cb", md_cb)
        setattr(self, f"m{idx}_match_cb", match_cb)
        setattr(self, f"m{idx}_time_cb", time_cb)
        setattr(self, f"m{idx}_date_de", date_de)
        setattr(self, f"m{idx}_remi_yes", remi_yes)
        setattr(self, f"m{idx}_logo_lbl", logo_lbl)
        setattr(self, f"m{idx}_map", mapping)

    # ----- Setup interactions -----
    def _on_operator_changed(self, name: str):
        for m in self.managers:
            if m["name"] == name and m["station"]:
                idx = self.station_cb.findText(m["station"], Qt.MatchFixedString)
                if idx >= 0:
                    self.station_cb.setCurrentIndex(idx)
                else:
                    self.station_cb.setEditText(m["station"])
                _log("[UI] Auto-station for {name} -> {m['station']}")
                return

    def _toggle_match2(self):
        self.card2.setVisible(self.rb2.isChecked())
        _log("[UI] Match count -> {'2' if self.rb2.isChecked() else '1'}")

    def _go_checklist(self):
        if not self._validate_setup():
            return

        # Build payload (WS is already included by _collect(idx))
        self.payload = {
            "operator": self.operator_cb.currentText().strip(),
            "station":  self.station_cb.currentText().strip(),
            "match_count": 2 if self.rb2.isChecked() else 1,
            "m1": self._collect(1),
            "m2": self._collect(2) if self.rb2.isChecked() else {},
        }

        # Each match gets its own checklist model
        self.models = {1: None, 2: None}

        _log(f"[SETUP] Payload -> {self.payload}")
        self._prefer_load_saved = bool(getattr(self, "load_saved_chk", None)
                                    and self.load_saved_chk.isChecked())
        save_config_payload(self.payload)

        # ---- NEW: immediately push a SETUP snapshot so Supervisor sees WS
        try:
            # _format_setup_message() already includes "WS=…" for each match
            self._queue_for_supervisor(self._format_setup_message())
        except Exception:
            pass

        # Continue to checklist UI
        self._render_checklist_page()
        self._show(self.page_check)

    def _collect(self, idx: int):
        md = getattr(self, f"m{idx}_md_cb").currentText().strip()
        label = getattr(self, f"m{idx}_match_cb").currentText().strip()
        time_val = getattr(self, f"m{idx}_time_cb").currentText().strip()
        date_val = getattr(self, f"m{idx}_date_de").date().toString("yyyy-MM-dd")
        is_remi = getattr(self, f"m{idx}_remi_yes").isChecked()

        comp_cb = getattr(self, f"m{idx}_comp_cb", None)
        competition = ""
        if comp_cb is not None:
            cval = comp_cb.currentText().strip()
            competition = "" if cval.startswith("—") else cval

        # NEW: WS from the setup dropdown (101–115) with safe fallback
        ws_cb  = getattr(self, f"m{idx}_ws_cb", None)
        ws_val = ws_cb.currentText().strip() if ws_cb is not None else ""
        if not ws_val:
            ws_val = (self.payload.get(f"m{idx}", {}) or {}).get("ws", "").strip()

        mapping = getattr(self, f"m{idx}_map")
        row = mapping.get(label, {})
        data = {
            "matchday": md,
            "hometeam": row.get("hometeam","") or (label.split(" vs ")[0] if " vs " in label else ""),
            "awayteam": row.get("awayteam","") or (label.split(" vs ")[1] if " vs " in label else ""),
            "stadium": row.get("stadium",""),
            "time": time_val,
            "date": date_val,
            "is_remi": is_remi,
            "competition": competition,
            "ws": ws_val,                   # ← keep WS in payload
        }
        _log(f"[COLLECT] m{idx} -> {data}")
        return data

    def _extract_sup_sender(self, line: str) -> str:
        """Pull the supervisor display name from an inbound line, if present."""
        try:
            m = re.search(r"FromSupName\s*=\s*'([^']+)'", line)
            if m:
                return m.group(1).strip()
        except Exception:
            pass
        return None

    def _format_setup_message(self):
        st = self.payload.get("station","")
        op = self.payload.get("operator","")
        m1 = self.payload.get("m1",{})
        m2 = self.payload.get("m2",{})

        parts = [
            f"SETUP: Station={st} Operator={op} AckPort={self.ack_port or ''}",

            # Match 1 (note WS=...)
            f"Match1: Day={m1.get('matchday','')} Teams='{m1.get('hometeam','')} vs {m1.get('awayteam','')}' "
            f"Label='{m1.get('hometeam','')} vs {m1.get('awayteam','')}' "
            f"KO_DATE={m1.get('date','')} KO={m1.get('time','')} REMI={'Yes' if m1.get('is_remi') else 'No'} "
            f"WS={m1.get('ws','')} Stadium={m1.get('stadium','')}",
        ]

        # Only add Match 2 if present
        if m2:
            parts.append(
                f"Match2: Day={m2.get('matchday','')} Teams='{m2.get('hometeam','')} vs {m2.get('awayteam','')}' "
                f"Label='{m2.get('hometeam','')} vs {m2.get('awayteam','')}' "
                f"KO_DATE={m2.get('date','')} KO={m2.get('time','')} REMI={'Yes' if m2.get('is_remi') else 'No'} "
                f"WS={m2.get('ws','')} Stadium={m2.get('stadium','')}"
            )

        return " ".join(parts)

    # --- Supervisor status ping ---
    def _ping_supervisor(self):
        # We rely on Supervisor-originated PING_SUP; start as OFFLINE until it pings us.
        self.supPingDone.emit(False)

    def _apply_sup_status(self, online: bool):
        # detect transition
        was_online = getattr(self, "_sup_online", False)
        self._sup_online = online

        # NEW: if Supervisor just came online, ask to send one-shot catch-up on next toggle
        if online and not was_online:
            self._need_catchup = True
            _log("[SUP] Supervisor came ONLINE — will send catch-up snapshot on next task toggle.")

        # Status pill
        if self.sup_status_lbl:
            if online:
                self.sup_status_lbl.setText("Supervisor: ONLINE")
                self.sup_status_lbl.setStyleSheet(
                    "QLabel{background:#dcfce7;color:#065f46;border:1px solid #86efac;"
                    "border-radius:10px;padding:2px 8px;font-weight:700;}"
                )
            else:
                self.sup_status_lbl.setText("Supervisor: OFFLINE")
                self.sup_status_lbl.setStyleSheet(
                    "QLabel{background:#fee2e2;color:#7f1d1d;border:1px solid #fecaca;"
                    "border-radius:10px;padding:2px 8px;font-weight:700;}"
                )
        # restart the offline grace timer when we hear from Supervisor (GUI thread)
        if online:
            try:
                self._sup_offline_timer.start(30000)  # 10s
            except Exception:
                pass
        # Flip all Day-1 buttons at once
        for btn in list(getattr(self, "_day1_buttons", [])):
            try:
                btn.setEnabled(online)
                btn.setStyleSheet(
                    "QPushButton{background:#22c55e;color:#fff;font-weight:700;padding:6px 12px;border-radius:10px;}"
                    if online else
                    "QPushButton{background:#94a3b8;color:#fff;font-weight:700;padding:6px 12px;border-radius:10px;}"
                )
            except RuntimeError:
                pass


    def _send_day1_now(self):
        if not self._sup_online:
            QMessageBox.information(self, "Offline", "Supervisor is offline. Try again when ONLINE.")
            return
        sent = 0
        for match_idx in (1, 2):
            model = self.models.get(match_idx)
            if not model: continue
            for sec in model.get("sections", []):
                if "matchday -1" not in sec.get("title","").lower():
                    continue
                for it in sec.get("items", []):
                    if it.get("state") in ("done","approved"):
                        vars_list = getattr(self, f"tasks_vars_{match_idx}", [])
                        total = max(1, len(vars_list))
                        checked_cnt = sum(1 for c in vars_list if c.isChecked())
                        pct = int(round(checked_cnt * 100 / total))
                        self._queue_for_supervisor(
                                  self._format_item_update_message(it.get("text",""), True, pct, match_idx, tag="D1"))
                        sent += 1
        QMessageBox.information(self, "Day-1", f"Sent {sent} Day-1 items to Supervisor.")

    def _save_now(self):
        saved = 0
        for match_idx in (1, 2):
            model = self.models.get(match_idx)
            if not model:
                continue
            key = _match_key(self.payload.get(f"m{match_idx}", {}))
            save_current_states(key, model)
            saved += 1
        # also save setup page info
        save_config_payload(self.payload)
        QMessageBox.information(self, "Saved", f"Saved progress for {saved} match(es).")

    def _send_quick_message(self, match_idx: int):
        from PyQt5.QtWidgets import QInputDialog
        text, ok = QInputDialog.getText(self, f"Message Supervisor (Match {match_idx})", "Enter message:")
        if ok and text.strip():
            st = self.payload.get("station","")
            op = self.payload.get("operator","")
            safe_from = f"{st} — {op}".strip(" —")
            msg = f"REQUEST: CHAT Match={match_idx} From='{safe_from}' Text='{text.strip()}'"
            _log("[CHAT][TX] {msg}")
            self._queue_for_supervisor(msg)
        # --- ALSO log our message locally so it appears in Chat history
        try:
            ts = datetime.now().strftime("%H:%M:%S")
            self._chat_log.setdefault(match_idx, []).append((ts, "Me", text.strip()))
        except Exception:
            pass
    def _send_quick_report(self, match_idx: int):
        from PyQt5.QtWidgets import QInputDialog
        text, ok = QInputDialog.getText(
            self,
            f"Report to Supervisor (Match {match_idx})",
            "Enter report:"
        )
        # after you get the multi-line `text` from the dialog:
        if not ok or not text.strip():
            return

        st = (self.payload.get("station", "") or "").strip()
        op = (self.payload.get("operator", "") or "").strip()
        safe_from = f"{st} — {op}".strip(" —")

        # normalize CRLF and split into lines
        safe = text.replace("\r", "\n")
        parts = [p.strip() for p in safe.split("\n") if p.strip()]

        # reuse the same chunked sender used in _send_quick_report
        def _send_report_segment(txt: str):
            MAX = 900
            seg_idx = 1
            while txt:
                seg, txt = txt[:MAX], txt[MAX:]
                suffix = f" (cont. {seg_idx})" if txt else ""
                wire = (
                    f"REQUEST: REPORT Match={match_idx} From='{safe_from}' "
                    f"Text='{seg}{suffix}'"
                )
                _log(f"[REPORT][TX] {wire}")
                self._queue_for_supervisor(wire)
                seg_idx += 1

        for line in parts:
            _send_report_segment(line)


        # optional: record locally so it appears in your chat history (if you keep one)
        try:
            ts = datetime.now().strftime("%H:%M:%S")
            self._chat_log.setdefault(match_idx, []).append((ts, "Me (report)", text.strip()))
        except Exception:
            pass


    def _open_manual(self, target: str):
        """
        Open either a URL or a local manual file.
        - URLs open in the default browser.
        - Local files (pdf/doc/docx/ppt/pptx/jpg/png/gif, etc.) open with their
        default handler via the OS.
        """
        if not target:
            QMessageBox.information(self, "Manual", "No link or file specified for this item.")
            return

        target = target.strip()
        try:
            if _is_url(target):
                QDesktopServices.openUrl(QUrl(target))
                return

            # treat as a file reference
            path = _find_manual_file(target)
            if not path or not os.path.exists(path):
                QMessageBox.warning(
                    self, "Manual not found",
                    f"Couldn't find file:\n{target}\n\nLooked in:\n{MANUALS_ROOT}"
                )
                return

            # Open with default app
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        except Exception as e:
            QMessageBox.warning(self, "Open manual", f"Couldn't open:\n{target}\n\n{e}")


    def _render_checklist_page(self):
        # layout re-use
        lay = self.page_check.layout()
        if lay is None:
            lay = QVBoxLayout(self.page_check)
        else:
            _clear_layout(lay)

        # fresh registries
        self.task_widgets = {}
        setattr(self, "tasks_vars_1", [])
        setattr(self, "tasks_vars_2", [])
        self._timer_entries = {1: [], 2: []}
        lay.setSpacing(10)

        # Supervisor status bar
        status = QHBoxLayout(); lay.addLayout(status)
        self.sup_status_lbl = QLabel("Supervisor: checking…")
        self.sup_status_lbl.setStyleSheet("QLabel{background:#f3f4f6;color:#111;border:1px solid #e5e7eb;border-radius:10px;padding:2px 8px;font-weight:700;}")
        status.addWidget(self.sup_status_lbl)

        btn_save = QPushButton("Save progress")
        btn_save.clicked.connect(self._save_now)
        status.addWidget(btn_save)

        self.msg_btn = QPushButton("MSG Supervisor")
        self.msg_btn.setFixedWidth(200)
        self.msg_btn.setToolTip("Send message to Supervisor")

        menu = QMenu(self.msg_btn)
        menu.addAction("Message Match 1", lambda: self._send_quick_message(1))
        menu.addAction("Message Match 2", lambda: self._send_quick_message(2))

        # --- NEW: Report actions (yellow) using QWidgetAction ---
        rep_style = (
            "QPushButton{"
            "  color:#ffbf00; font-weight:600; text-align:left; padding:6px 12px;"
            "}"
            "QPushButton:hover{"
            "  background: rgba(255,191,0,0.15);"
            "}"
        )

        # Report Match 1
        rep1_act = QWidgetAction(self.msg_btn)
        rep1_btn = QPushButton("Report Match 1")
        rep1_btn.setFlat(True)
        rep1_btn.setStyleSheet(rep_style)
        rep1_btn.clicked.connect(lambda: (self._send_quick_report(1), menu.hide()))
        rep1_act.setDefaultWidget(rep1_btn)
        menu.addAction(rep1_act)

        # Report Match 2
        rep2_act = QWidgetAction(self.msg_btn)
        rep2_btn = QPushButton("Report Match 2")
        rep2_btn.setFlat(True)
        rep2_btn.setStyleSheet(rep_style)
        rep2_btn.clicked.connect(lambda: (self._send_quick_report(2), menu.hide()))
        rep2_act.setDefaultWidget(rep2_btn)
        menu.addAction(rep2_act)

        self.msg_btn.setMenu(menu)


        status.addWidget(self.msg_btn)
        # Who to send to: All (default) or a specific online supervisor
        status.addWidget(QLabel("→"))
        self.sup_target_combo = QComboBox()
        self.sup_target_combo.setFixedWidth(220)
        self.sup_target_combo.addItem("All supervisors", "ALL")
        status.addWidget(self.sup_target_combo)

        # 📘 Manuals
        status.addStretch(1)
        self._ping_supervisor()

        # 📘 Manuals
        self.book_btn = QPushButton("Manuals")
        self.book_btn.setFixedWidth(150)
        self.book_btn.setToolTip("Open manuals")
        book_menu = QMenu(self.book_btn)
        if self.manuals:
            for cat, items in self.manuals.items():
                sub = QMenu(cat, book_menu)
                for title, target in items:
                    act = sub.addAction(title or "(untitled)")
                    if target:
                        act.triggered.connect(lambda _=False, t=target: self._open_manual(t))
                    else:
                        act.setEnabled(False)
                book_menu.addMenu(sub)
        else:
            act = book_menu.addAction("No manuals found")
            act.setEnabled(False)
        self.book_btn.setMenu(book_menu)
        status.addWidget(self.book_btn)


        # Body (one or two columns)
        mc = self.payload.get("match_count", 1)
        if mc == 1:
            lay.addWidget(self._build_check_column(1))
        else:
            row = QHBoxLayout()
            row.addWidget(self._build_check_column(1), 1)
            row.addWidget(self._build_check_column(2), 1)
            lay.addLayout(row)

        # Footer
        fbar = QHBoxLayout(); lay.addLayout(fbar)
        btn_back = QPushButton("← Back"); btn_back.setObjectName("secondary"); btn_back.clicked.connect(lambda: self._show(self.page_setup))
        btn_finish = QPushButton("Finish"); btn_finish.setObjectName("accent"); btn_finish.clicked.connect(self._finish)
        fbar.addWidget(btn_back); fbar.addStretch(1); fbar.addWidget(btn_finish)

        self._ensure_timer()
        self._paint_timers_once()
        self._update_ko_countdowns()   # <-- add this one-time call
    def _build_check_column(self, idx: int) -> QWidget:
        info = self.payload.get(f"m{idx}", {})
        wrapper = QWidget(); v = QVBoxLayout(wrapper); v.setSpacing(8)

        # --- header (title row with button, then info/logo row) ---
        head = Section("")
        headv = QVBoxLayout(head)
        headv.setSpacing(6)
        headv.setContentsMargins(8, 6, 8, 8)

        # Title row
        titlebar = QHBoxLayout()
        title_lbl = QLabel(f"Match {idx}")
        title_lbl.setStyleSheet("font-weight:700;")
        titlebar.addWidget(title_lbl)

        stad = info.get("stadium", "").strip()
        iss = self._issues_for_stadium(stad)
        if iss:
            btn = QPushButton("Things to remember")
            btn.setCursor(Qt.PointingHandCursor)
            btn.setStyleSheet("""
                QPushButton{
                    background:#fff7ed;
                    border:1px solid #f59e0b;
                    color:#9a3412;
                    border-radius:10px;
                    padding:2px 8px;
                    font-weight:700;
                }
                QPushButton:hover{ background:#ffedd5; }
            """)
            btn.clicked.connect(lambda _=None, s=stad, items=iss: self._show_issues_popup(s, items))
            titlebar.addWidget(btn, 0, Qt.AlignLeft)

        # --- WS pill (read-only) shown inline on the title bar, before the [+] button
        ws_val = (info.get("ws") or "").strip()
        if not ws_val or ws_val.startswith("Choose"):
            ws_val = "—"  # fallback if somehow missing

        ws_pill = QLabel(f"WS {ws_val}")
        ws_pill.setAlignment(Qt.AlignCenter)
        ws_pill.setStyleSheet(
            "QLabel{background:#ffffff;color:#000000;border:1px solid #111827;border-radius:10px;padding:2px 8px;font-weight:700;}"
        )
        ws_pill.setFixedHeight(22)

        titlebar.addSpacing(8)
        titlebar.addWidget(ws_pill)

        # Small [+] to open chat history for this match
        chat_btn = QToolButton()
        chat_btn.setText("+")
        chat_btn.setToolTip("Show chat history")
        chat_btn.setFixedWidth(24)
        chat_btn.clicked.connect(lambda _=False, m=idx: self._show_chat_history(m))
        titlebar.addWidget(chat_btn)

        titlebar.addStretch(1)
        headv.addLayout(titlebar)

        # Info + logo row
        hv = QHBoxLayout()
        home = info.get('hometeam',''); away = info.get('awayteam','')
        md = info.get('matchday',''); ko = info.get('time',''); stad = info.get('stadium',''); dt = info.get('date','')
        info_html = (
            f"<div style='line-height:1.2'>"
            f"<b>{home} vs {away}</b><br>"
            f"Day {md}  |  Date {dt}  |  KO {ko}  |  {stad}"
            f"</div>"
        )
        lbl = QLabel(info_html)
        lbl.setTextFormat(Qt.RichText)
        lbl.setWordWrap(True)
        f = lbl.font(); f.setPointSize(12); lbl.setFont(f)
        hv.addWidget(lbl, 1)

        # --- right side: countdown pill above the logo
        logo = QLabel()
        logo.setFixedSize(QSize(96, 96))
        logo.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        logo.setStyleSheet("QLabel{background:transparent;}")

        # Countdown pill (HH:MM)
        ko_pill = QLabel("00:00")
        ko_pill.setAlignment(Qt.AlignCenter)
        ko_pill.setFixedWidth(72)
        ko_pill.setStyleSheet(
            "QLabel{background:#111827;color:#fff;border-radius:10px;padding:2px 8px;font-weight:700;}"
        )

        # Stack pill over logo
        right_v = QVBoxLayout()
        right_v.setContentsMargins(0, 0, 0, 0)
        right_v.setSpacing(6)
        right_v.addWidget(ko_pill, 0, Qt.AlignRight)
        right_v.addWidget(logo,   0, Qt.AlignRight)
        hv.addLayout(right_v, 0)

        # Load logo (same as before)
        path_logo, _ = self._find_logo_path(info.get("hometeam",""))
        if path_logo:
            try:
                if PIL_AVAILABLE:
                    img = Image.open(path_logo); img.thumbnail((96, 96))
                    tmp = os.path.join(SUPPORT_DIR, f"_tmp_logo_{idx}.png")
                    img.save(tmp)
                    logo.setPixmap(QPixmap(tmp))
                else:
                    logo.setPixmap(QPixmap(path_logo).scaled(96, 96, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            except Exception:
                pass

        # Register this pill + KO datetime for countdown updates
        try:
            ko_dt = _parse_ko_datetime(info.get("time",""), info.get("date",""))
        except Exception:
            ko_dt = None
        self._ko_labels[idx] = {"label": ko_pill, "ko": ko_dt}

        headv.addLayout(hv)
        v.addWidget(head)

        # checklist source (always inject Matchday -1 at top if missing)
        checklist_path, source_label = _choose_checklist_file(info)
        sections = _parse_checklist(checklist_path) or [{
            "title": "Checklist",
            "items": [
                {"text":"Power on / Devices connected","state":"open"},
                {"text":"Network verified","state":"open"},
                {"text":"Replay system ready","state":"open"},
                {"text":"Cameras synced","state":"open"},
                {"text":"Audio check","state":"open"},
                {"text":"Graphics updated","state":"open"},
                {"text":"Recording path set","state":"open"},
                {"text":"Storage space OK","state":"open"},
                {"text":"Backup plan verified","state":"open"},
                {"text":"Final quick test","state":"open"},
            ]
        }]
        sections = _inject_day1_if_missing(sections)
        _log("[CL] Using checklist: {os.path.basename(checklist_path)} ({source_label}) for Match {idx}")

        self._ensure_model(idx, info, sections)
        model = self.models.get(idx)

        # Load saved states + relocations if chosen
        saved_map = {}
        saved_reloc = []
        if getattr(self, "_prefer_load_saved", False):
            key = _match_key(info)
            saved_map, saved_reloc = load_saved_states(key)

        # --- Apply relocations (move items to their saved section) ---
        if saved_reloc:
            desired = { (r.get("text","").strip().lower()): (r.get("title","").strip().lower())
                        for r in saved_reloc if r.get("text") and r.get("title") }
            sec_by_title = { s.get("title","").strip().lower(): s for s in model.get("sections", []) }

            for sec in list(model.get("sections", [])):
                cur_title_low = sec.get("title","").strip().lower()
                for it in list(sec.get("items", [])):
                    t_low = it.get("text","").strip().lower()
                    want = desired.get(t_low)
                    if want and want in sec_by_title and want != cur_title_low:
                        try:
                            sec["items"].remove(it)
                            sec_by_title[want]["items"].append(it)
                        except ValueError:
                            pass

        # scroll body
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        body = QWidget(); sb = QVBoxLayout(body); sb.setSpacing(8)
        scroll.setWidget(body)
        v.addWidget(scroll, 1)

        vars_list = []
        for s_i, section in enumerate(model.get("sections", [])):
            # Section container
            box = Section("")
            sb.addWidget(box)
            b = QVBoxLayout(box)
            b.setSpacing(4)
            b.setContentsMargins(10, 8, 10, 10)

            # Header with timer
            hdr = QHBoxLayout()
            title_lbl2 = QLabel(section.get("title", ""))
            title_lbl2.setStyleSheet("font-weight:700;")
            timer_lbl = QLabel()
            timer_lbl.setStyleSheet("color:#0f766e; margin-left:8px;")
            hdr.addWidget(title_lbl2)
            hdr.addWidget(timer_lbl)
            hdr.addStretch(1)
            b.addLayout(hdr)
            # --- right-click menu on the *section* (category) for early-mark permission
            # right-click on the whole section area
            box.setContextMenuPolicy(Qt.CustomContextMenu)
            box.customContextMenuRequested.connect(
                lambda pos, mi=idx, si=s_i, w=box: self._open_section_menu(w, mi, si, pos)
            )

            # right-click on the header text (most reliable target)
            title_lbl2.setContextMenuPolicy(Qt.CustomContextMenu)
            title_lbl2.customContextMenuRequested.connect(
                lambda pos, mi=idx, si=s_i, w=title_lbl2: self._open_section_menu(w, mi, si, pos)
            )

            # Track this timer label
            self._timer_entries[idx].append({
                "label": timer_lbl,
                "start": section.get("start"),
                "due": section.get("due"),
                "ko": model.get("ko_dt"),
                "title": section.get("title",""),
            })

            for i_i, item in enumerate(section.get("items", [])):
                cb = QCheckBox(item.get("text",""))
                cb.setStyleSheet("QCheckBox{padding: 3px 0; font-size: 13px;} QCheckBox:disabled{color:#9ca3af;}")
                b.addWidget(cb)
                # register checkbox for multi-select
                self._cb_index[cb] = (idx, s_i, i_i)
                self._multi_sel.setdefault((idx, s_i), set())
                cb.installEventFilter(self)  # enable Shift+Up/Down range selection

                # apply saved state if available
                t_key = (section.get("title","").strip().lower(), item.get("text","").strip().lower())
                sv = saved_map.get(t_key)
                if sv in ("done","approved"):
                    cb.setChecked(True)
                    item["state"] = sv
                    if sv == "approved":
                        try: cb.setStyleSheet("color:#ca8a04;")
                        except RuntimeError: pass
                elif sv == "pending":
                    item["state"] = "pending"
                    cb.setText(cb.text() + "  [PENDING]")

                # wire
                cb.stateChanged.connect(
                    lambda _=None, it=item, varsl=vars_list, m=idx, ref=cb, s_title=section.get("title",""):
                        self._on_task_toggle(it, m, varsl, ref, s_title)
                )
                cb.setContextMenuPolicy(Qt.CustomContextMenu)
                cb.customContextMenuRequested.connect(
                    lambda pos, mi=idx, si=s_i, ii=i_i, w=cb: self._open_task_menu(w, mi, si, ii)
                )
                vars_list.append(cb)
                self.task_widgets[(idx, s_i, i_i)] = cb

            # Day-1 sender below the Day-1 section
            if "matchday -1" in section.get("title","").lower():
                spacer = QWidget(); spacer.setFixedHeight(6)
                b.addWidget(spacer)

                btn_day1 = QPushButton("Send Day-1 now")
                btn_day1.setCursor(Qt.PointingHandCursor)
                btn_day1.setEnabled(self._sup_online)
                btn_day1.setStyleSheet(
                    "QPushButton{background:#22c55e;color:#fff;font-weight:700;padding:6px 12px;border-radius:10px;}"
                    if self._sup_online else
                    "QPushButton{background:#94a3b8;color:#fff;font-weight:700;padding:6px 12px;border-radius:10px;}"
                )
                btn_day1.clicked.connect(lambda _=None, m=idx: self._send_day1_for_match(m))
                b.addWidget(btn_day1, 0, Qt.AlignLeft)
                self._day1_buttons.append(btn_day1)

        setattr(self, f"tasks_vars_{idx}", vars_list)
        _log("[UI] Match {idx} tasks: {len(vars_list)}")
        return wrapper

    def _update_ko_countdowns(self):
        """Update the KO-countdown 'pill' on each match card."""
        now = datetime.now()
        for idx in (1, 2):
            rec = getattr(self, "_ko_labels", {}).get(idx)
            if not rec:
                continue
            lbl = rec.get("label")
            ko  = rec.get("ko")
            if not lbl or not ko:
                continue
            remaining = (ko - now).total_seconds()
            if remaining <= 0:
                text = "00:00"
            else:
                h = int(remaining // 3600)
                m = int((remaining % 3600) // 60)
                text = f"{h:02d}:{m:02d}"
            lbl.setText(text)


    # ----- timers -----
    def _ensure_model(self, match_idx: int, info: dict, sections):
        if self.models.get(match_idx) is None:
            ko_dt = _parse_ko_datetime(info.get("time",""), info.get("date"))
            sections_aug = _augment_sections_with_windows(sections, ko_dt)
            self.models[match_idx] = {"ko_dt": ko_dt, "sections": sections_aug}
            _log("[MODEL] m{match_idx} KO={ko_dt} sections={len(sections_aug)}")
        else:
            model = self.models[match_idx]
            if not model.get("ko_dt"):
                model["ko_dt"] = _parse_ko_datetime(info.get("time",""), info.get("date"))
            if not model.get("sections"):
                model["sections"] = _augment_sections_with_windows(sections, model["ko_dt"])

    def _ensure_timer(self):
        if getattr(self, "_timer", None) is None:
            self._timer = QTimer(self)
            self._timer.timeout.connect(self._tick_timers)
            self._timer.timeout.connect(self._update_ko_countdowns)  # <-- add this line
            self._timer.timeout.connect(self._check_and_show_deadline_reminders)
            self._timer.start(TIMER_TICK_SECS * 1000)
            _log(f"[TIMER] Started {TIMER_TICK_SECS}s tick")
            self._maybe_emit_overdue()


    def _paint_timers_once(self):
        now = datetime.now()
        self._update_timer_labels(now); self._update_urgency_styles(now)

    def _tick_timers(self):
        now = datetime.now()
        self._blink_phase = not self._blink_phase
        self._update_timer_labels(now)
        self._update_urgency_styles(now)

    def _update_timer_labels(self, now: datetime):
        for match_idx in (1, 2):
            for e in list(getattr(self, "_timer_entries", {}).get(match_idx, [])):
                lbl = e.get("label")
                if not lbl: continue
                start, due = e.get("start"), e.get("due")
                text = ""
                if start and now < start:
                    text = f"Starts at {_fmt_hhmm(start)} (in {_human_delta(start, now)})"
                elif start and due and start <= now < due:
                    text = f"Due by {_fmt_hhmm(due)} (time left {_human_delta(due, now)})"
                elif due and now >= due:
                    text = f"Overdue by {_human_delta(now, due)} (was due {_fmt_hhmm(due)})"
                elif not due and start and now >= start:
                    text = f"Active since {_fmt_hhmm(start)}"
                lbl.setText(text)

    def _update_urgency_styles(self, now_dt):
        for match_idx in (1, 2):
            model = self.models.get(match_idx)
            if not model:
                continue
            for s_i, sec in enumerate(model.get("sections", [])):
                due = sec.get("due")
                start = sec.get("start")
                urgent = bool(
                    due and start and start <= now_dt < due and
                    (due - now_dt) <= timedelta(minutes=DUE_BLINK_THRESHOLD_MIN)
                )
                for i_i, item in enumerate(sec.get("items", [])):
                    cb = self.task_widgets.get((match_idx, s_i, i_i))
                    if not cb: continue

                    # Always allow clicking; if it's early we'll confirm in _on_task_toggle
                    # Always allow clicking; if it's early we'll confirm in _on_task_toggle
                    try:
                        cb.setEnabled(True)
                        # subtle hint when it’s early and not already done/approved
                        if start and now_dt < start and item.get("state") not in ("done", "approved"):
                            cb.setToolTip("Time not up yet — clicking will ask to notify Supervisor (EARLY)")
                        else:
                            cb.setToolTip("")
                    except RuntimeError:
                        continue




                    # colors + overdue handling
                    if item.get("state") in ("done","approved"):
                        try: cb.setStyleSheet("color:#16a34a;")   # green
                        except RuntimeError: pass
                        continue

                    if due and now_dt >= due:
                        # overdue task: blink red
                        try: cb.setStyleSheet("color:{};".format("#dc2626" if self._blink_phase else "#ef4444"))
                        except RuntimeError: pass
                        # send overdue notification ONCE
                        if item.get("state") == "open" and not item.get("_overdue_notified"):
                            item["_overdue_notified"] = True
                            _log("[OVERDUE] m{match_idx} '{item.get('text','')}' -> notifying supervisor")
                            self._queue_for_supervisor(
                                      self._format_item_update_message(item.get("text",""), False, 0, match_idx, tag="OVERDUE"))
                    elif urgent:
                        try: cb.setStyleSheet("color:{};".format("#dc2626" if self._blink_phase else "#ef4444"))
                        except RuntimeError: pass
                    else:
                        try: cb.setStyleSheet("color:#111;")
                        except RuntimeError: pass

    def _on_task_toggle(self, item: dict, match_idx: int, vars_list, cb_ref, s_title):
        # one-shot catch-up push if supervisor turned online after tech started
        if self._sup_online and getattr(self, "_need_catchup", False):
            try:
                self._send_catchup_snapshot()
            finally:
                self._need_catchup = False

        # default for our special-case switch
        _skip_early = False

        # The signal gives us the live checkbox; if it was deleted, just ignore
        try:
            checked = cb_ref.isChecked()
            # send the plain model text, not the decorated checkbox label
            text = (item.get("text", "") or "").strip()

            # --- SPECIAL: "Report all your issues for the match" -> prompt & send REPORT ---
            def _normkey(s: str) -> str:
                return re.sub(r"[^a-z0-9]+", "", (s or "").lower())

            # match ignoring case/punctuation and optional trailing dot
            _report_trigger = _normkey("Report all your issues for the match")
            is_report_marker = (_normkey(text).startswith(_report_trigger))

            if checked and is_report_marker:
                # momentarily untick so the user doesn't see it ticked before submitting
                try:
                    cb_ref.blockSignals(True)
                    cb_ref.setChecked(False)
                finally:
                    cb_ref.blockSignals(False)

                from PyQt5.QtWidgets import QInputDialog
                prompt = "Report Issues for your match.\nIf no issues, type 'No Issues'."
                msg, ok = QInputDialog.getMultiLineText(
                    self, "Report issues", prompt, text=""
                )
                if not ok:
                    # user canceled -> leave unchecked and stop
                    return

                msg = (msg or "").strip() or "No Issues"
                # avoid breaking the single-quoted wire format
                safe_msg = msg.replace("'", "’")

                # Build & send the same wire message the yellow buttons use
                try:
                    st = self.payload.get("station", "")
                    op = self.payload.get("operator", "")
                    safe_from = f"{st} — {op}".strip(" —")
                except Exception:
                    safe_from = "TECH"

                # Send one REQUEST per line (and chunk long lines)
                def _send_report_segment(txt: str):
                    MAX = 900
                    seg_idx = 1
                    while txt:
                        seg, txt = txt[:MAX], txt[MAX:]
                        suffix = f" (cont. {seg_idx})" if txt else ""
                        wire = (
                            f"REQUEST: REPORT Match={match_idx} From='{safe_from}' "
                            f"Text='{seg}{suffix}'"
                        )
                        _log(f"[REPORT][TX] {wire}")
                        self._queue_for_supervisor(wire)
                        seg_idx += 1

                # Normalize CRLF and split; skip blank-only lines
                for line in safe_msg.replace("\r", "\n").split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    _send_report_segment(line)


                # if a supervisor is online, attempt an immediate flush so it shows up right away
                try:
                    if self._sup_online:
                        self._flush_outbox_now()   # no-op if your sender doesn’t expose it; see note below
                except Exception:
                    pass


                # Now mark the checkbox as done (without re-entering the handler)
                try:
                    cb_ref.blockSignals(True)
                    cb_ref.setChecked(True)
                finally:
                    cb_ref.blockSignals(False)
                item["state"] = "done"
                _skip_early = True  # skip the early-warning flow for this item

        except RuntimeError:
            _log("[TASK][WARN] Toggle from deleted widget; ignoring")
            return

        # --- EARLY click notify (no approval required) ---
        if checked and not _skip_early:
            # find section to get planned start time
            sec = next((s for s in (self.models.get(match_idx) or {}).get("sections", [])
                        if (s.get("title","") or "") == (s_title or "")), None)
            start_dt = sec.get("start") if sec else None

            from datetime import datetime as _dt
            if start_dt and _dt.now() < start_dt:
                # 1) Immediately untick so user doesn't see a tick before confirming
                try:
                    cb_ref.blockSignals(True)
                    cb_ref.setChecked(False)
                finally:
                    cb_ref.blockSignals(False)

                # 2) Ask for confirmation
                resp = QMessageBox.question(
                    self,
                    "Too early?",
                    "Time not up yet.\nAre you sure you completed the task?\n\n"
                    "If you choose Yes, I'll notify Supervisor: EARLY.",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                if resp != QMessageBox.Yes:
                    # leave unchecked and stop here
                    return

                # 3) User confirmed: tick now (only after Yes)
                try:
                    cb_ref.blockSignals(True)
                    cb_ref.setChecked(True)
                finally:
                    cb_ref.blockSignals(False)
                checked = True  # ensure the next line marks it done locally

                # 4) Send a non-approvable notice to Supervisor (CHAT shows as yellow, no approval flow)
                try:
                    st = self.payload.get("station", "")
                    op = self.payload.get("operator", "")
                    safe_from = f"{st} — {op}".strip(" —")
                except Exception:
                    safe_from = "TECH"
                line = (
                    f"REQUEST: CHAT Match={match_idx} From='{safe_from}' "
                    f"Section='{s_title or ''}' Item='{text}' Text='EARLY — {text}'"
                )
                _log(f"[EARLY][NOTICE] {line}")
                self._queue_for_supervisor(line)




        item["state"] = "done" if checked else "open"

        # alive vars for progress
        alive = []
        for c in list(vars_list):
            try:
                _ = c.text()
                alive.append(c)
            except RuntimeError:
                continue

        total = len(alive) or 1
        checked_cnt = sum(1 for c in alive if c.isChecked())
        pct = int(round(checked_cnt * 100 / total))

        # For Day-1 ("Matchday -1") we **do not send** live; just save (push via the button)
        is_day1 = "matchday -1" in (s_title or "").lower()
        if is_day1:
            print(f"[D1] ({'done' if checked else 'open'}) m{match_idx} '{text}' saved locally ({pct}%)")
        else:
            _log("[TASK] m{match_idx} '{text}' -> {'done' if checked else 'open'} ({pct}%)")
            # Compute section due_ts (epoch) and total items in this section
            # Compute section due_ts (epoch) and total items in this section
            due_ts = None
            total  = None
            try:
                sec = next((s for s in (self.models.get(match_idx) or {}).get("sections", [])
                            if (s.get("title", "") or "") == (s_title or "")), None)
                if sec:
                    if sec.get("due"):
                        # top-level already imports: from datetime import datetime
                        if isinstance(sec["due"], datetime):
                            due_ts = int(sec["due"].timestamp())
                    # send the *section* size, not whole checklist
                    total = len(sec.get("items", [])) or None
            except Exception:
                pass


            self._queue_for_supervisor(
                self._format_item_update_message(
                    text, checked, pct, match_idx,
                    tag="UPDATE",
                    section=s_title,
                    due_ts=due_ts,
                    total=total
                )
            )
        # save current states to config
        key = _match_key(self.payload.get(f"m{match_idx}", {}))
        save_current_states(key, self.models.get(match_idx) or {})

        # instant visuals
        self._update_urgency_styles(datetime.now())

    def _format_item_update_message(
        self,
        item: str,
        checked: bool,
        pct: int,
        match_idx: int,
        tag: str = "UPDATE",
        section: str = "",
        due_ts: int | None = None,
        total: int | None = None,
        extra: dict | None = None,   # NEW
    ):
        st = self.payload.get("station",""); op = self.payload.get("operator","")
        state = "ON" if checked else "OFF"
        msg = (
            f"{tag}: Station={st} Operator={op} Match={match_idx} "
            f"Teams='{self.payload.get(f'm{match_idx}',{}).get('hometeam','')} vs "
            f"{self.payload.get(f'm{match_idx}',{}).get('awayteam','')}' "
            f"Label='{self.payload.get(f'm{match_idx}',{}).get('hometeam','')} vs "
            f"{self.payload.get(f'm{match_idx}',{}).get('awayteam','')}' "
            f"Section='{section}' Item='{item}' State={state} Progress={pct}%"
        )
        if isinstance(due_ts, int):
            msg += f" DueTS={due_ts}"
        if isinstance(total, int):
            msg += f" Total={total}"
        # NEW: arbitrary extra key/values (eg Catchup=1)
        if extra:
            for k, v in extra.items():
                if isinstance(v, (int, float)) or v in (True, False):
                    vv = int(v) if isinstance(v, bool) else v
                    msg += f" {k}={vv}"
                else:
                    sv = str(v).replace("'", "")  # keep it simple/safe
                    msg += f" {k}='{sv}'"
        _log("[DEBUG][FORMAT] Outgoing message: {msg}")
        return msg

    def _send_catchup_snapshot(self):
        """Send a one-time dump of current DONE/APPROVED items per section and any OPEN overdue items."""
        _log("[SUP] Sending catch-up snapshot…")
        for match_idx in (1, 2):
            self._send_catchup_for_match(match_idx)
    def _maybe_emit_overdue(self):
        """Called by the periodic timer—only emits OVERDUE once per item while it's overdue."""
        from datetime import datetime
        now = datetime.now()

        def _base_kv(m):
            st = (self.station_cb.currentText() or "").strip()
            op = (self.operator_cb.currentText() or "").strip()
            return f"station='{st}' operator='{op}' match={m}"

        for m in (1, 2):
            model = self.models.get(m)
            if not model:
                continue
            for sec in model.get("sections", []):
                title = sec.get("title", "")
                items = sec.get("items", [])
                due_dt = sec.get("due")
                try:
                    due_ts = int(due_dt.timestamp()) if due_dt else None
                except Exception:
                    due_ts = None
                try:
                    hours_before = _extract_hours_before(title)
                except Exception:
                    hours_before = None

                for it in items:
                    text = (it.get("text") or "").strip()
                    if not text:
                        continue
                    state = (it.get("state") or "open").lower()
                    checked = state in ("done", "approved", "ok")
                    key = (m, hours_before, text.lower())
                    overdue_now = (not checked) and (due_ts is not None) and (due_dt and now > due_dt)

                    # rising edge → send once
                    if overdue_now and key not in self._sent_overdue_keys:
                        self._sent_overdue_keys.add(key)
                        self._queue_for_supervisor(
                            "OVERDUE: "
                            f"{_base_kv(m)} section='{title}' item='{text}' "
                            f"due_ts={due_ts}"
                        )

                    # clear latch when resolved (so a later relapse can notify)
                    if (checked or not overdue_now) and key in self._sent_overdue_keys:
                        self._sent_overdue_keys.discard(key)

    def _send_catchup_for_match(self, match_idx: int):
        model = self.models.get(match_idx)
        if not model:
            return

        # overall progress (for consistency in lines we emit)
        vars_list = getattr(self, f"tasks_vars_{match_idx}", []) or []
        total_all = max(1, len(vars_list))
        checked_cnt = 0
        for cb in list(vars_list):
            try:
                if cb.isChecked():
                    checked_cnt += 1
            except RuntimeError:
                continue
        overall_pct = int(round(checked_cnt * 100 / total_all))

        now = datetime.now()

        for sec in model.get("sections", []):
            title = sec.get("title", "")
            items = sec.get("items", []) or []
            section_total = max(1, len(items))

            due_ts = None
            try:
                if isinstance(sec.get("due"), datetime):
                    due_ts = int(sec["due"].timestamp())
            except Exception:
                pass

            # Emit one baseline line per item so Supervisor can render the full list
            for it in items:
                text = (it.get("text","") or "").strip()
                if not text:
                    continue

                state = (it.get("state") or "").lower()
                checked = state in ("done", "approved", "ok")

                overdue_now = False
                if not checked and isinstance(sec.get("due"), datetime) and now >= sec["due"]:
                    overdue_now = True

                tag = "OVERDUE" if overdue_now else "UPDATE"

                self._queue_for_supervisor(
                    self._format_item_update_message(
                        text, checked, overall_pct, match_idx,
                        tag=tag, section=title, due_ts=due_ts, total=section_total,
                        extra={"Catchup": 1}
                    )
                )
    def _set_cb_selected_visual(self, match_idx: int, sec_i: int, item_i: int, on: bool):
        cb = self.task_widgets.get((match_idx, sec_i, item_i))
        if not cb:
            return
        base = "QCheckBox{padding: 3px 0; font-size: 13px;} QCheckBox:disabled{color:#9ca3af;}"
        if on:
            cb.setStyleSheet(base + " QCheckBox{background:#e0f2fe;border-radius:6px;}")
        else:
            cb.setStyleSheet(base)
    def _focus_task_checkbox(self, mi: int, si: int, ii: int) -> None:
        cb = self.task_widgets.get((mi, si, ii))
        if not cb:
            return
        try:
            cb.setFocus(Qt.TabFocusReason)
        except Exception:
            pass

    def eventFilter(self, obj, event):
        try:
            from PyQt5.QtCore import QEvent
            if obj not in self._cb_index:
                return False

            mi, si, ii = self._cb_index.get(obj, (None, None, None))
            if mi is None:
                return False

            # ---------- Keyboard ----------
            if event.type() == QEvent.KeyPress:
                key  = event.key()
                mods = event.modifiers()

                # Shift+Down / Shift+Up extends selection range AND moves the caret
                if (mods & Qt.ShiftModifier) and key in (Qt.Key_Down, Qt.Key_Up):
                    sel    = self._multi_sel.setdefault((mi, si), set())
                    anchor = self._sel_anchor.get((mi, si), ii)
                    step   = 1 if key == Qt.Key_Down else -1

                    # clamp target index inside this section
                    all_idx = list(self._iter_section_item_indices(mi, si))
                    if not all_idx:
                        return True
                    lo, hi  = min(all_idx), max(all_idx)
                    new_idx = max(lo, min(hi, ii + step))

                    # mark the whole inclusive range [anchor, new_idx]
                    sel.clear()
                    for j in range(min(anchor, new_idx), max(anchor, new_idx) + 1):
                        sel.add(j)

                    self._refresh_selection_visuals(mi, si)

                    # keep anchor fixed, but MOVE the caret to new_idx so repeated Shift+Arrows feel natural
                    self._sel_anchor[(mi, si)] = anchor
                    self._focus_task_checkbox(mi, si, new_idx)
                    return True


                # Move anchor with plain arrows
                if key in (Qt.Key_Down, Qt.Key_Up):
                    self._sel_anchor[(mi, si)] = ii
                    return False

                # Ctrl+A : select all in section
                if (mods & Qt.ControlModifier) and key == Qt.Key_A:
                    self._multi_sel[(mi, si)] = set(self._iter_section_item_indices(mi, si))
                    self._refresh_selection_visuals(mi, si)
                    return True

                # Ctrl+I : invert selection in section
                if (mods & Qt.ControlModifier) and key == Qt.Key_I:
                    full = set(self._iter_section_item_indices(mi, si))
                    cur  = self._multi_sel.setdefault((mi, si), set())
                    self._multi_sel[(mi, si)] = full.difference(cur)
                    self._refresh_selection_visuals(mi, si)
                    return True

                # Esc : clear selection
                if key == Qt.Key_Escape:
                    self._multi_sel[(mi, si)] = set()
                    self._refresh_selection_visuals(mi, si)
                    return True

            # ---------- Mouse ----------
            if event.type() == QEvent.MouseButtonPress:
                # Ctrl+Click toggles this one in/out of selection, no menu needed
                if event.modifiers() & Qt.ControlModifier:
                    sel = self._multi_sel.setdefault((mi, si), set())
                    if ii in sel:
                        sel.remove(ii)
                    else:
                        sel.add(ii)
                        # set anchor when starting new selection
                        if (mi, si) not in self._sel_anchor:
                            self._sel_anchor[(mi, si)] = ii
                    self._refresh_selection_visuals(mi, si)
                    return False  # let the click also toggle the checkbox normally

                # Plain click: update anchor to current row (useful before Shift+Arrows)
                self._sel_anchor[(mi, si)] = ii
                return False

        except Exception:
            pass
        return False


    def _open_section_menu(self, widget, match_idx: int, sec_i: int, pos):
        menu = QMenu(widget)
        act = menu.addAction("Ask permission to mark tasks green…")
        act.triggered.connect(lambda _=False, m=match_idx, s=sec_i: self._section_early_dialog(m, s))
        # show at the cursor position inside the widget
        menu.exec_(widget.mapToGlobal(pos))


    def _section_early_dialog(self, match_idx: int, sec_i: int):
        """Show a picker of *currently locked* & *unchecked* items in this section, then send requests."""
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QScrollArea, QWidget, QCheckBox, QDialogButtonBox
        model = self.models.get(match_idx)
        if not model: return
        section = model["sections"][sec_i]
        title = section.get("title","")

        # Determine which items are *eligible*: unchecked and currently disabled by the time window
        eligible = []
        for i_i, it in enumerate(section.get("items", [])):
            state = it.get("state","open")
            cb = self.task_widgets.get((match_idx, sec_i, i_i))
            if not cb: continue
            try:
                is_checked = cb.isChecked()
                is_enabled = cb.isEnabled()
            except RuntimeError:
                continue
            if state not in ("done","approved") and (not is_checked) and (not is_enabled):
                eligible.append((i_i, it.get("text","").strip()))

        if not eligible:
            QMessageBox.information(self, "Nothing to request",
                f"'{title}' has no locked and unchecked tasks to request right now.")
            return

        dlg = QDialog(self); dlg.setWindowTitle(f"Ask permission — {title}")
        lay = QVBoxLayout(dlg)
        lay.addWidget(QLabel("Select the locked tasks you want permission to mark green:"))

        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        inner = QWidget(); iv = QVBoxLayout(inner)
        checks = []
        for i_i, txt in eligible:
            cb = QCheckBox(txt)
            iv.addWidget(cb)
            checks.append((i_i, cb))
        iv.addStretch(1)
        scroll.setWidget(inner)
        lay.addWidget(scroll, 1)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        lay.addWidget(btns)

        def do_ok():
            picked = [(i_i, cb.text()) for (i_i, cb) in checks if cb.isChecked()]
            if not picked:
                dlg.reject(); return
            # Send *one request per item* so Supervisor can approve granularly
            for i_i, txt in picked:
                self._request_early_mark(match_idx, sec_i, i_i)
            dlg.accept()

        btns.accepted.connect(do_ok)
        btns.rejected.connect(dlg.reject)
        dlg.exec_()

    def _request_early_mark(self, match_idx: int, sec_i: int, item_i: int):
        """Queue an 'EARLY_MARK' permission request for a single item in a section."""
        model = self.models.get(match_idx); 
        if not model: return
        sec = model["sections"][sec_i]
        item = sec["items"][item_i]

        if item.get("state") in ("approved","done"):
            return  # nothing to do

        # mark locally as 'pending' (same visual treatment you used for NOT_POSSIBLE)
        item["state"] = "pending"
        cb = self.task_widgets.get((match_idx, sec_i, item_i))
        if cb and "[PENDING]" not in cb.text():
            cb.setText(cb.text() + "  [PENDING]")

        # send request
        line = f"REQUEST: EARLY_MARK Match={match_idx} Section='{sec.get('title','')}' Item='{item.get('text','')}'"
        _log("[TASK] EARLY_MARK requested m{match_idx} '{item.get('text','')}'")
        self._queue_for_supervisor(line)

        # persist
        key = _match_key(self.payload.get(f"m{match_idx}", {}))
        save_current_states(key, self.models.get(match_idx) or {})
    def _iter_section_item_indices(self, match_idx: int, sec_i: int):
        model = self.models.get(match_idx)
        if not model: 
            return range(0)
        sections = model.get("sections", [])
        if not (0 <= sec_i < len(sections)):
            return range(0)
        return range(len(sections[sec_i].get("items", [])))

    def _refresh_selection_visuals(self, match_idx: int, sec_i: int):
        sel = self._multi_sel.get((match_idx, sec_i), set())
        for i in self._iter_section_item_indices(match_idx, sec_i):
            self._set_cb_selected_visual(match_idx, sec_i, i, i in sel)

    def _open_task_menu(self, widget, match_idx: int, sec_i: int, item_i: int):
        menu = QMenu(self)

        # Compute next section & whether shifting is allowed
        next_i = self._next_hour_section_index(match_idx, sec_i)
        allow_shift = (next_i is not None)
        if allow_shift:
            next_title = self.models[match_idx]["sections"][next_i]["title"]
            if _extract_hours_before(next_title) == 1:
                allow_shift = False

        # --- shifting actions ---
        act_shift = menu.addAction("Shift to next hour category")
        act_shift.setEnabled(allow_shift)

        selected_idx = sorted(list(self._multi_sel.get((match_idx, sec_i), set())))
        act_shift_multi = None
        if allow_shift and selected_idx:
            act_shift_multi = menu.addAction(f"Shift {len(selected_idx)} selected to next hour")

        # --- selection helpers ---
        menu.addSeparator()
        act_sel_toggle = menu.addAction("Select/Deselect this item for multi-shift")
        act_sel_all    = menu.addAction("Select all in this section")
        act_sel_clear  = menu.addAction("Clear selection")
        act_sel_invert = menu.addAction("Invert selection")

        # --- request NP (existing) ---
        menu.addSeparator()
        act_np = menu.addAction("Not possible (request supervisor approval)")

        action = menu.exec_(widget.mapToGlobal(widget.rect().bottomLeft()))

        if action == act_shift and allow_shift:
            self._shift_task(match_idx, sec_i, item_i, next_i)
            return

        if act_shift_multi is not None and action == act_shift_multi and allow_shift:
            model = self.models.get(match_idx); sections = model.get("sections", [])
            # capture texts first (indices change as we shift)
            texts = []
            for ii in selected_idx:
                try:
                    texts.append((ii, (sections[sec_i]["items"][ii].get("text") or "").strip()))
                except Exception:
                    pass
            for _, txt in texts:
                cur_idx = None
                for j, it in enumerate(sections[sec_i]["items"]):
                    if (it.get("text") or "").strip() == txt:
                        cur_idx = j; break
                if cur_idx is not None and self._next_hour_section_index(match_idx, sec_i) == next_i:
                    self._shift_task(match_idx, sec_i, cur_idx, next_i)
            self._multi_sel[(match_idx, sec_i)] = set()
            self._refresh_selection_visuals(match_idx, sec_i)
            return

        if action == act_sel_toggle:
            sel = self._multi_sel.setdefault((match_idx, sec_i), set())
            if item_i in sel: sel.remove(item_i)
            else: sel.add(item_i)
            self._sel_anchor[(match_idx, sec_i)] = item_i
            self._refresh_selection_visuals(match_idx, sec_i)
            return

        if action == act_sel_all:
            self._multi_sel[(match_idx, sec_i)] = set(self._iter_section_item_indices(match_idx, sec_i))
            self._refresh_selection_visuals(match_idx, sec_i)
            return

        if action == act_sel_clear:
            self._multi_sel[(match_idx, sec_i)] = set()
            self._refresh_selection_visuals(match_idx, sec_i)
            return

        if action == act_sel_invert:
            full = set(self._iter_section_item_indices(match_idx, sec_i))
            cur  = self._multi_sel.setdefault((match_idx, sec_i), set())
            self._multi_sel[(match_idx, sec_i)] = full.difference(cur)
            self._refresh_selection_visuals(match_idx, sec_i)
            return

        if action == act_np:
            self._request_not_possible(match_idx, sec_i, item_i)

    def _next_hour_section_index(self, match_idx: int, sec_i: int):
        sections = self.models[match_idx]["sections"]
        for j in range(sec_i+1, len(sections)):
            if _extract_hours_before(sections[j]["title"]) is not None:
                return j
        return None

    def _shift_task(self, match_idx: int, sec_i: int, item_i: int, next_i: int):
        if next_i is None: return
        model = self.models[match_idx]
        sections = model["sections"]
        if _extract_hours_before(sections[next_i]["title"]) == 1:
            QMessageBox.information(self, "Not allowed", "Tasks cannot be shifted into the \"1 hour before KO\" category.")
            return
        item = sections[sec_i]["items"].pop(item_i)
        sections[next_i]["items"].append(item)
        _log("[TASK] SHIFT m{match_idx} '{item.get('text','')}' -> {sections[next_i]['title']}")
        self._queue_for_supervisor(
                  f"REQUEST: SHIFT Match={match_idx} Item='{item.get('text','')}' From='{sections[sec_i]['title']}' To='{sections[next_i]['title']}'")
        # persist after change
        key = _match_key(self.payload.get(f"m{match_idx}", {}))
        save_current_states(key, self.models.get(match_idx) or {})
        self._render_checklist_page()

    def _request_not_possible(self, match_idx: int, sec_i: int, item_i: int):
        model = self.models[match_idx]
        sec = model["sections"][sec_i]
        item = sec["items"][item_i]
        if item.get("state") in ("approved","done"): return
        item["state"] = "pending"
        _log("[TASK] NOT_POSSIBLE requested m{match_idx} '{item.get('text','')}'")
        self._queue_for_supervisor(
                  f"REQUEST: NOT_POSSIBLE Match={match_idx} Section='{sec.get('title','')}' Item='{item.get('text','')}'")
        cb = self.task_widgets.get((match_idx, sec_i, item_i))
        if cb and "[PENDING]" not in cb.text():
            cb.setText(cb.text() + "  [PENDING]")
        # persist
        key = _match_key(self.payload.get(f"m{match_idx}", {}))
        save_current_states(key, self.models.get(match_idx) or {})
    def _handle_sup_action(self, *, action: str, match_idx: int, section: str, item_text: str):
        """
        Runs on GUI thread via supActionRequested.
        action ∈ {"MARK_DONE", "SHIFT_NEXT"}  (alias "MOVE_NEXT" also accepted)
        """
        action = (action or "").upper().strip()
        model = self.models.get(match_idx)
        if not model:
            return

        # ---- locate section & item in the model ----
        sec_i = item_i = None
        sec_title = (section or "").strip()
        item_norm = (item_text or "").strip().lower()

        for s_idx, sec in enumerate(model.get("sections", [])):
            if (sec.get("title", "") or "") == sec_title:
                for i_idx, it in enumerate(sec.get("items", [])):
                    if (it.get("text", "") or "").strip().lower() == item_norm:
                        sec_i, item_i = s_idx, i_idx
                        break
            if sec_i is not None:
                break

        if sec_i is None or item_i is None:
            # Not found; nothing to do
            return

        # Convenience handles
        sec_obj = model["sections"][sec_i]
        item_obj = sec_obj["items"][item_i]

        if action == "MARK_DONE":
            # Update model state
            item_obj["state"] = "done"
            item_obj["progress"] = 100

            # Recompute section % from the model (robust; no widget assumptions)
            items = sec_obj.get("items", [])
            total = max(1, len(items))
            checked_cnt = 0
            for it in items:
                st = str(it.get("state", "")).lower()
                if st in ("done", "on", "true") or it.get("checked") is True or (it.get("progress", 0) >= 100):
                    checked_cnt += 1
            pct = int(round(checked_cnt * 100 / total))

            # Optional: include due timestamp if stored as datetime
            due_ts = None
            try:
                from datetime import datetime  # safe local import if not at file top
                if isinstance(sec_obj.get("due"), datetime):
                    due_ts = int(sec_obj["due"].timestamp())
            except Exception:
                pass

            # Notify Supervisor with a normal UPDATE
            self._queue_for_supervisor(
                self._format_item_update_message(
                    item_text, True, pct, match_idx,
                    tag="UPDATE", section=sec_title, due_ts=due_ts, total=total
                )
            )

            # Persist + refresh visuals
            key = _match_key(self.payload.get(f"m{match_idx}", {}))
            save_current_states(key, model)
            self._update_urgency_styles(datetime.now())
            self._render_checklist_page()

        elif action in ("SHIFT_NEXT", "MOVE_NEXT"):
            # Compute the next hour-bucket and shift using existing helper
            try:
                next_idx = self._next_hour_section_index(match_idx, sec_i)
                if next_idx is not None:
                    self._shift_task(match_idx, sec_i, item_i, next_idx)
            except Exception as e:
                _log(f"[SUP_ACTION][SHIFT][ERR] {e}")

        # else: ignore unknown actions silently

    # ----- logos -----
    def _find_logo_path(self, team_name: str):
        tried = []
        if not team_name: return None, tried
        key_norm = _normalize_key(team_name)
        mapped = self.logo_map.get(key_norm)
        if mapped:
            p = os.path.join(PATH_LOGOS_DIR, mapped); tried.append(p)
            if os.path.exists(p): return p, tried
        base_raw = team_name.strip()
        for ext in (".png", ".jpg", ".jpeg", ".bmp", ".gif"):
            p = os.path.join(PATH_LOGOS_DIR, base_raw + ext); tried.append(p)
            if os.path.exists(p): return p, tried
        base = _sanitize_filename(team_name)
        for ext in (".png", ".jpg", ".jpeg", ".bmp", ".gif"):
            p = os.path.join(PATH_LOGOS_DIR, base + ext); tried.append(p)
            if os.path.exists(p): return p, tried
        return None, tried

    def _set_logo(self, idx: int, team_name: str, label: QLabel):
        path, _ = self._find_logo_path(team_name)
        if not path:
            label.clear()
            return
        try:
            if PIL_AVAILABLE:
                img = Image.open(path); img.thumbnail((180, 120))
                tmp = os.path.join(SUPPORT_DIR, f"__logo_{idx}.png")
                img.save(tmp)
                label.setPixmap(QPixmap(tmp))
            else:
                label.setPixmap(QPixmap(path))
        except Exception as e:
            _log("[IMG][ERR] {e}")
            label.clear()

    # ----- Validation / Finish -----
    def _validate_setup(self):
        if not self.operator_cb.currentText().strip():
            QMessageBox.warning(self, "Missing", "Please select/enter your name."); return False
        if not self.station_cb.currentText().strip():
            QMessageBox.warning(self, "Missing", "Please select/enter your tech station."); return False
        if not self.m1_md_cb.currentText().strip() or not self.m1_match_cb.currentText().strip():
            QMessageBox.warning(self, "Missing", "Fill Matchday and Match for Match 1."); return False
        if not self.m1_time_cb.currentText().strip():
            QMessageBox.warning(self, "Missing", "Select KO Time for Match 1."); return False
        # Date is always set (default today / auto-bump), so no extra check
        if self.rb2.isChecked():
            if not self.m2_md_cb.currentText().strip() or not self.m2_match_cb.currentText().strip():
                QMessageBox.warning(self, "Missing", "Fill Matchday and Match for Match 2."); return False
            if not self.m2_time_cb.currentText().strip():
                QMessageBox.warning(self, "Missing", "Select KO Time for Match 2."); return False
        # WS is compulsory
        ws1 = getattr(self, "m1_ws_cb", None)
        if ws1 and (not ws1.currentText().strip() or ws1.currentText().startswith("Choose")):
            QMessageBox.warning(self, "Missing", "Please choose a Workstation (WS) for Match 1.")
            return False

        if self.rb2.isChecked():
            ws2 = getattr(self, "m2_ws_cb", None)
            if ws2 and (not ws2.currentText().strip() or ws2.currentText().startswith("Choose")):
                QMessageBox.warning(self, "Missing", "Please choose a Workstation (WS) for Match 2.")
                return False
        return True


    def _finish(self):
        # persist once more
        for idx in (1,2):
            if self.models.get(idx):
                key = _match_key(self.payload.get(f"m{idx}", {}))
                save_current_states(key, self.models.get(idx))

        for idx in (1,2):
            vars_list = getattr(self, f"tasks_vars_{idx}", None)
            if not vars_list: continue
            total = len(vars_list) or 1
            checked_cnt = sum(1 for cb in vars_list if cb.isChecked())
            pct = int(round(checked_cnt * 100 / total))
            _log("[FINISH] m{idx} -> {pct}%")
            self._queue_for_supervisor(self._format_item_update_message("ALL", checked_cnt==total, pct, idx))
        QMessageBox.information(self, "Done", "Checklist completed. You can close this window.")

        # ----- Supervisor → Tech inbound -----
    def _ack_server(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            bind_host = getattr(self, "bind_ip", "0.0.0.0") or "0.0.0.0"
            srv.bind((bind_host, int(self.ack_port)))
            srv.listen(5)
            _log(f"[ACK] Listening on {bind_host}:{self.ack_port}")
        except Exception as e:
            _log(f"[ACK][ERR] Failed to bind on {self.ack_port} -> {e}")
            return

        # --- ONLINE banner helper ---
        def _set_supervisor_status(online: bool):
            self._sup_online = online
            try:
                self.supPingDone.emit(online)
            except Exception:
                pass

        # --- Build one-line SETUP snapshot (fallback, always safe) ---
        def _build_setup_line() -> str:
            try:
                p = getattr(self, "payload", {}) or {}
            except Exception:
                p = {}

            # station/operator
            station  = (p.get("station")  or getattr(self, "station_id", "") or "").strip()
            operator = (p.get("operator") or getattr(self, "operator",   "") or "").strip()

            parts = [f"SETUP: Station={station} Operator={operator}"]

            # pull match info from payload -> matches[1/2] or m1/m2 shapes
            if "matches" in p and isinstance(p["matches"], dict):
                matches = p["matches"]
            else:
                matches = {1: p.get("m1", {}) or {}, 2: p.get("m2", {}) or {}}

            for mi in (1, 2):
                m = matches.get(mi, {}) or {}
                day   = (m.get("day") or m.get("matchday") or m.get("md") or "").strip()
                label = (m.get("label") or m.get("teams") or "").strip()
                ko    = (m.get("ko") or m.get("time") or "").strip()
                kdt   = (m.get("ko_date") or m.get("date") or "").strip()

                if day or label or ko or kdt:
                    seg = f" Match{mi}: Day={day} Teams='{label}' KO={ko}"
                    if kdt:
                        seg += f" KO_DATE={kdt}"
                    parts.append(seg)

            return " ".join(parts)

        def handle_line(line: str, conn):
            if not line:
                return
            msg = line.strip()
            low = msg.lower()
            _log(f"[ACK] << {msg}")

            # ---------- Presence / SYNC ----------
            if msg == "PING_SUP":
                _set_supervisor_status(True)
                try:
                    conn.sendall(b"PONG_TECH\n")
                except Exception:
                    pass
                return

            if msg == "SYNC":
                try:
                    # Build and send SETUP snapshot
                    try:
                        setup_line = self._format_setup_message() if hasattr(self, "_format_setup_message") else _build_setup_line()
                        if not setup_line:
                            setup_line = _build_setup_line()
                    except Exception:
                        setup_line = _build_setup_line()

                    conn.sendall((setup_line + "\n").encode("utf-8"))

                    # Catch-up snapshot (if you have one)
                    try:
                        self._send_catchup_snapshot()
                    except Exception:
                        pass

                    self._need_catchup = False

                    # Flush any queued lines while SUP was offline
                    for ln in list(self._outbox):
                        try:
                            conn.sendall((ln + "\n").encode("utf-8"))
                        except Exception as e:
                            _log(f"[ACK][SYNC][ERR] flush -> {e}")
                            break
                    self._outbox.clear()

                    _set_supervisor_status(True)
                except Exception as e:
                    _log(f"[ACK][SYNC][ERR] {e}")
                return

            # ---------- SUP_ACTION (NEW) ----------
            # Accept both "SUP_ACTION ..." and "SUP_ACTION: ..."
            if msg.upper().startswith("SUP_ACTION"):
                # strip optional leading "SUP_ACTION:" prefix
                body = msg.split(":", 1)[1].strip() if ":" in msg else msg[len("SUP_ACTION"):].strip()

                # Lightweight KV parser: Key=Value, supports quotes
                kv = {}
                for m in re.finditer(r"(\w+)\s*=\s*(?:'([^']*)'|\"([^\"]*)\"|([^ \t]+))", body):
                    k = (m.group(1) or "").strip().lower()
                    v = (m.group(2) or m.group(3) or m.group(4) or "").strip()
                    kv[k] = v

                action    = kv.get("type") or kv.get("action") or ""
                match_idx = int(kv.get("match", "1") or 1)
                section   = kv.get("section", "")
                item_text = kv.get("item", "")

                # Hand off to the GUI thread (prevents blank UI)
                self.supActionRequested.emit(action, match_idx, section, item_text)
                return

            # ---------- APPROVAL (existing) ----------
            if "approve" in low:
                m = re.search(r"(?:match|m)\s*[:=]?\s*(\d+)", msg, re.IGNORECASE)
                idx = int(m.group(1)) if m else 1
                m2 = (re.search(r"(?:^|\\b)item\\s*[:=]\\s*'([^']+)'", msg, re.IGNORECASE) or
                    re.search(r'(?:^|\\b)item\\s*[:=]\\s*"([^"]+)"', msg, re.IGNORECASE))
                item_text = m2.group(1) if m2 else msg[low.find("approve")+7:].strip().strip(":").strip()
                _log(f"[ACK] APPROVE m{idx} item='{item_text}'")
                self.approveRequested.emit(idx, item_text)
                return

            # ---------- MESSAGE / CHAT (REPORT-aware) ----------
            if re.match(r"^(?:MESSAGE\b|REQUEST:\s*CHAT\b)", msg, re.IGNORECASE):
                # match index
                m_match = re.search(r"(?:match|m)\s*[:=]?\s*(\d+)", msg, re.IGNORECASE)
                idx = int(m_match.group(1)) if m_match else 1

                # text
                m_text = (re.search(r"\btext\s*[:=]\s*(.*)$", msg, re.IGNORECASE) or
                        re.search(r"\bmsg\s*[:=]\s*(.*)$", msg, re.IGNORECASE)  or
                        re.search(r"\bmessage\s*[:=]\s*(.*)$", msg, re.IGNORECASE))
                text = (m_text.group(1).strip() if m_text
                        else (msg.split(":", 1)[-1].strip() if re.match(r"^message\b", msg, re.IGNORECASE) else ""))

                # strip trailing identity stamp (FromSupName='...') from text payload
                if text:
                    text = re.sub(r"\s*FromSupName\s*=\s*'[^']+'\s*$", "", text).strip()

                # Sender name for the popup label
                m_sender = re.search(r"FromSupName\s*=\s*'([^']+)'", msg)
                sender = (m_sender.group(1).strip() if m_sender else "Supervisor")

                # Detect report kind (Kind=REPORT)
                m_kind = re.search(r"\bkind\s*[:=]\s*(\w+)", msg, re.IGNORECASE)
                kind = (m_kind.group(1).strip().upper() if m_kind else "")

                # Day-1 nudge suppression (skip suppression for REPORT so it always shows)
                def _looks_like_day1_nudge(t: str) -> bool:
                    if not t:
                        return False
                    s = t.lower()
                    if "day-1" in s or "day 1" in s:
                        for kw in ("reminder", "send", "press", "checklist", "now"):
                            if kw in s:
                                return True
                    return False

                if kind != "REPORT" and _looks_like_day1_nudge(text):
                    _log("[ACK] MESSAGE suppressed: Day-1 nudge")
                    return

                if text:
                    show = f"[{sender}] {text}"
                    # Prefix marker so _popup_message() can render yellow “REPORTING” style
                    if kind == "REPORT":
                        show = "[REPORT] " + show
                    _log(f"[ACK] MESSAGE m{idx} text='{show}'")
                    self.popupRequested.emit(idx, show)
                return
            # ---------- end MESSAGE ----------

        # Main accept loop
        while True:
            try:
                conn, addr = srv.accept()
                try:
                    data = conn.recv(4096)
                    if not data:
                        conn.close()
                        continue
                    decoded = data.decode("utf-8", errors="ignore").replace("\r", "\n")
                    for line in decoded.split("\n"):
                        handle_line(line, conn)
                finally:
                    conn.close()
            except Exception as e:
                _log(f"[ACK][ERR] {e} (continuing)")
                continue

    def _ack_discovery_listener(self):
        """
        Listen for UDP 'DISCOVER_SUP port=XXXX [name=Alice]' beacons on our ACK port.
        When heard, push a fresh SETUP snapshot and flush any queued lines to that Supervisor.
        Maintains a live roster; UI refresh is dispatched to the GUI thread via self.rosterChanged.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            bind_host = getattr(self, "bind_ip", "0.0.0.0") or "0.0.0.0"
            sock.bind((bind_host, int(self.ack_port)))  # UDP bind

            while True:
                data, addr = sock.recvfrom(2048)
                txt = (data or b"").decode("utf-8", errors="ignore").strip()
                if not txt.upper().startswith("DISCOVER_SUP"):
                    continue

                # Parse supervisor IP/port/name
                m = re.search(r"port\s*=\s*(\d+)", txt, re.IGNORECASE)
                sup_port = int(m.group(1)) if m else 5000
                sup_ip = addr[0]
                mname = re.search(r"name\s*=\s*([^\s].*)$", txt, re.IGNORECASE)
                sup_name = (mname.group(1).strip() if mname else "Supervisor")

                _log("[ACK][RX] {txt}  ← from {sup_ip}:{sup_port}")

                # Update roster (data only; NO UI here)
                try:
                    self.supervisors_online[sup_ip] = {
                        "ip": sup_ip,
                        "name": sup_name,
                        "port": sup_port,
                        "last_seen": datetime.now(),
                    }
                    _log("[SUP] {sup_name} @ {sup_ip}:{sup_port} (online)")
                    # Tell GUI thread to refresh the dropdown safely
                    self.rosterChanged.emit()
                except Exception as e:
                    _log("[SUP][ERR] roster update: {e}")

                # Initial catch-up snapshot if needed
                if getattr(self, "_need_catchup", False):
                    try:
                        self._send_catchup_snapshot()
                        self._need_catchup = False
                    except Exception as e:
                        _log("[CATCHUP][ERR] {e}")

                # Build and send live SETUP snapshot
                try:
                    setup_line = self._format_setup_message()
                except Exception as e:
                    _log("[SETUP][ERR] {e}")
                    setup_line = ""

                if setup_line:
                    send_line(sup_ip, sup_port, setup_line, timeout=2.5)
                    self._need_catchup = False

                # Flush any queued lines (best-effort)
                if self._outbox:
                    all_sent = True
                    for ln in list(self._outbox):
                        ok, _ = send_line(sup_ip, sup_port, ln, timeout=2.5)
                        if not ok:
                            all_sent = False
                            break
                    if all_sent:
                        self._outbox.clear()

        except Exception as e:
            _log("[DISCOVERY][ERR] {e}")

    def _prune_supervisors(self):
        """Remove supervisors we haven't heard from recently and refresh the target dropdown."""
        try:
            now = datetime.now()
            ttl = getattr(self, "_sup_ttl_secs", 90)
            gone = []
            for ip, rec in list(self.supervisors_online.items()):
                last = rec.get("last_seen")
                if not last or (now - last).total_seconds() > ttl:
                    gone.append(ip)

            for ip in gone:
                self.supervisors_online.pop(ip, None)

            if gone:
                _log("[SUP] pruned offline: {', '.join(gone)}")
                # Notify GUI to rebuild the combo safely
                self.rosterChanged.emit()

        except Exception as e:
            _log("[SUP][PRUNE][ERR] {e}")


    def _refresh_sup_combo(self):
        """Rebuild target dropdown from self.supervisors_online."""
        try:
            if not hasattr(self, "sup_target_combo") or self.sup_target_combo is None:
                return
            cur = self.sup_target_combo.currentData()
            self.sup_target_combo.blockSignals(True)
            self.sup_target_combo.clear()
            self.sup_target_combo.addItem("All supervisors", "ALL")
            # sort by friendly name for readability
            for ip, rec in sorted(self.supervisors_online.items(), key=lambda kv: kv[1].get("name","")):
                self.sup_target_combo.addItem(f"{rec.get('name','Supervisor')} ({ip})", ip)
            # keep previous selection if still valid
            idx = self.sup_target_combo.findData(cur)
            if idx >= 0:
                self.sup_target_combo.setCurrentIndex(idx)
            self.sup_target_combo.blockSignals(False)
        except Exception:
            pass

    def _mark_item_supervisor_approved(self, match_idx: int, item_text: str):
        model = self.models.get(match_idx)
        if not model:
            _log("[APPROVE][WARN] No model for match {match_idx}")
            return
        for s_i, sec in enumerate(model.get("sections", [])):
            for i_i, it in enumerate(sec.get("items", [])):
                if it.get("text","").strip().lower() == (item_text or "").strip().lower():
                    it["state"] = "approved"
                    cb = self.task_widgets.get((match_idx, s_i, i_i))
                    if cb:
                        cb.setChecked(True)
                        cb.setStyleSheet("color:#ca8a04;")  # yellow
                    total = len(getattr(self, f"tasks_vars_{match_idx}", [])) or 1
                    checked_cnt = sum(1 for c in getattr(self, f"tasks_vars_{match_idx}", []) if c.isChecked())
                    pct = int(round(checked_cnt * 100 / total))
                    _log("[APPROVE] m{match_idx} '{it['text']}' -> approved ({pct}%)")
                    self._queue_for_supervisor (self._format_item_update_message(it["text"], True, pct, match_idx, tag="APPROVED"))
                    # persist
                    key = _match_key(self.payload.get(f"m{match_idx}", {}))
                    save_current_states(key, self.models.get(match_idx) or {})
                    return
        _log("[APPROVE][WARN] Item not found for match {match_idx}: '{item_text}'")

        # --- Supervisor message popup (with quick reply) ---
    def _popup_message(self, match_idx: int, text: str, *, is_report: bool = False):
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLineEdit, QDialogButtonBox

        # Auto-detect marker if caller didn't pass is_report
        if not is_report and text.startswith("[REPORT] "):
            is_report = True
            text = text[len("[REPORT] "):]

        # Suppress Day-1 nudges/reminders in the Tech UI (but never suppress REPORT popups)
        try:
            if (not is_report) and \
            re.search(r"day\s*-?\s*1", text or "", re.IGNORECASE) and \
            re.search(r"(reminder|send|press|checklist|now)", text or "", re.IGNORECASE):
                _log("[CHAT] popup suppressed: Day-1 nudge")
                return
        except Exception:
            pass

        # 1) Log the incoming supervisor line so it appears in history
        try:
            ts = datetime.now().strftime("%H:%M:%S")
            who = "Supervisor (report)" if is_report else "Supervisor"
            self._chat_log.setdefault(match_idx, []).append((ts, who, text))
        except Exception:
            pass

        dlg = QDialog(self)
        dlg.setWindowTitle(
            f"{'Supervisor — REPORTING' if is_report else 'Supervisor'} — Match {match_idx}"
        )
        dlg.setWindowModality(Qt.ApplicationModal)
        dlg.setWindowFlags(dlg.windowFlags() | Qt.WindowStaysOnTopHint)

        layout = QVBoxLayout(dlg)

        # Heading
        lbl = QLabel(f"{'Supervisor — REPORTING' if is_report else 'Supervisor'} (Match {match_idx}):")
        f = QFont(); f.setBold(True); f.setPointSize(f.pointSize() + 2)
        lbl.setFont(f)
        if is_report:
            lbl.setStyleSheet("background:#fff4cc; border-radius:6px; padding:6px 10px;")
        layout.addWidget(lbl)

        # Message body
        msg = QLabel(text)
        msg.setWordWrap(True)
        msg.setTextInteractionFlags(Qt.TextSelectableByMouse)
        if is_report:
            # Yellow look for reporting
            msg.setStyleSheet(
                "font-size: 25px; font-weight: 700; "
                "background:#fde047; padding:6px; color:#3b3b00;"
            )
        else:
            msg.setStyleSheet("font-size: 25px; font-weight: 600;")
        msg.setContentsMargins(6, 6, 6, 6)
        layout.addWidget(msg)

        # Optional quick reply (still sends as normal CHAT reply)
        entry = QLineEdit()
        entry.setPlaceholderText("Type a quick reply (optional)…")
        layout.addWidget(entry)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Close)
        layout.addWidget(buttons)

        def do_send():
            reply = entry.text().strip()
            if not reply:
                dlg.accept()
                return

            st = self.payload.get("station", "")
            op = self.payload.get("operator", "")
            safe_from = f"{st} — {op}".strip(" —")
            line = f"REQUEST: CHAT Match={match_idx} From='{safe_from}' Text='{reply}'"
            _log(f"[CHAT][TX] {line}")
            self._queue_for_supervisor(line)

            # 2) Log our own reply locally so it appears in history
            try:
                ts2 = datetime.now().strftime("%H:%M:%S")
                self._chat_log.setdefault(match_idx, []).append((ts2, "Me", reply))
            except Exception:
                pass

            dlg.accept()

        buttons.accepted.connect(do_send)
        buttons.rejected.connect(lambda: dlg.reject())
        entry.returnPressed.connect(do_send)

        dlg.setMinimumSize(520, 260)
        dlg.resize(640, 320)
        try:
            geo = self.geometry(); center = geo.center()
            dlg.move(QPoint(center.x() - dlg.width()//2, center.y() - dlg.height()//2))
        except Exception:
            pass

        dlg.exec_()


    def _show_chat_history(self, match_idx: int):
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QDialogButtonBox, QLabel
        from PyQt5.QtCore import Qt
        from html import escape

        dlg = QDialog(self)
        dlg.setWindowTitle(f"Chat — Match {match_idx}")
        lay = QVBoxLayout(dlg)

        title = QLabel(f"Supervisor ↔ Tech (Match {match_idx})")
        f = QFont(); f.setBold(True); title.setFont(f)
        lay.addWidget(title)

        # Build HTML with yellow highlight for "(report)" lines
        hist = self._chat_log.get(match_idx, [])
        if not hist:
            body_html = "<i>(no messages yet)</i>"
        else:
            parts = []
            for ts, who, txt in hist:
                safe_who = escape(who or "")
                safe_txt = escape(txt or "")
                line_html = f"[{escape(ts)}] {safe_who}: {safe_txt}"

                if "(report" in (who or "").lower():
                    # soft yellow chip for reporting rows
                    parts.append(
                        f'<div style="background:#fff7d1; border:1px solid #f5d77a; '
                        f'border-radius:6px; padding:4px 6px; margin:2px 0;">{line_html}</div>'
                    )
                else:
                    parts.append(f'<div style="margin:2px 0;">{line_html}</div>')
            body_html = "\n".join(parts)

        view = QLabel()
        view.setTextFormat(Qt.RichText)                 # enable HTML
        view.setText(body_html)
        view.setTextInteractionFlags(Qt.TextSelectableByMouse)
        view.setStyleSheet("background:#fff; border:1px solid #ccc; padding:6px;")
        view.setMinimumSize(500, 240)
        view.setWordWrap(True)
        lay.addWidget(view)

        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(dlg.reject)
        btns.accepted.connect(dlg.accept)
        lay.addWidget(btns)

        dlg.resize(640, 360)
        dlg.exec_()


    # ---- Stadium issues helpers ----
    def _issues_for_stadium(self, stadium: str):
        key = (stadium or "").replace("&", "and")
        key = _normalize_key(key)
        key = re.sub(r"\s+", " ", key).strip()
        if not key:
            return None

        lst = self.stadium_issues.get(key)
        if lst:
            return lst

        def _flat(s): return re.sub(r"[^a-z0-9]+", "", s)
        fk = _flat(key)
        for k, v in self.stadium_issues.items():
            if fk and (_flat(k) == fk or _flat(k) in fk or fk in _flat(k)):
                return v
        return None

    def _show_issues_popup(self, stadium: str, items: list):
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QDialogButtonBox
        dlg = QDialog(self)
        dlg.setWindowTitle(f"{stadium} — Things to remember")
        lay = QVBoxLayout(dlg)

        text = "\n".join(f"• {it}" for it in (items or []))
        box = QTextEdit()
        box.setReadOnly(True)
        box.setPlainText(text)
        box.setMinimumSize(420, 220)
        lay.addWidget(box)

        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(dlg.reject)
        btns.accepted.connect(dlg.accept)
        lay.addWidget(btns)

        dlg.exec_()

    def _reset_saved_for_current_selection(self):
        """
        Full wipe: remove ALL saved checklist states and LastUsed by
        deleting (or emptying) config.ini, then clear the UI.
        """
        ok = wipe_all_config_file()

        # Clear the UI fields on setup page so the user starts clean
        self.operator_cb.setCurrentText("")
        self.station_cb.setCurrentText("")
        self.rb1.setChecked(True)
        self.card2.setVisible(False)

        # Match 1 widgets
        self.m1_md_cb.setCurrentIndex(-1)
        self.m1_match_cb.setCurrentIndex(-1)
        self.m1_time_cb.setCurrentIndex(-1)
        self.m1_date_de.setDate(QDate.currentDate())
        self.m1_remi_yes.setChecked(False)

        # Match 2 widgets (if exist)
        if hasattr(self, "m2_md_cb"):
            self.m2_md_cb.setCurrentIndex(-1)
            self.m2_match_cb.setCurrentIndex(-1)
            self.m2_time_cb.setCurrentIndex(-1)
            if hasattr(self, "m2_date_de"):
                self.m2_date_de.setDate(QDate.currentDate())
            self.m2_remi_yes.setChecked(False)

        # Also clear any in-memory models and payload so the next save starts fresh
        self.models = {1: None, 2: None}
        self.payload = {}
        self._prefer_load_saved = True
        self.task_widgets.clear()
        self._timer_entries = {1: [], 2: []}

        QMessageBox.information(
            self,
            "Reset",
            "All saved data cleared and config.ini wiped." if ok else
            "Tried to wipe config.ini. Some files may still be locked; please check permissions."
        )


    def _load_last_used(self):
        cfg = load_config()
        if not cfg.has_section("LastUsed"):
            return

        sec = cfg["LastUsed"]

        # Operator & station
        self.operator_cb.setCurrentText(sec.get("operator", ""))
        self.station_cb.setCurrentText(sec.get("station", ""))

        # Matches count
        mc = sec.get("match_count", "1")
        if mc == "2":
            self.rb2.setChecked(True)
            self.card2.setVisible(True)
        else:
            self.rb1.setChecked(True)
            self.card2.setVisible(False)

        # Match 1
        self.m1_md_cb.setCurrentText(sec.get("m1_day", ""))
        match1_label = f"{sec.get('m1_home','')} vs {sec.get('m1_away','')}".strip()
        if match1_label != "vs":
            self.m1_match_cb.setCurrentText(match1_label)
        self.m1_time_cb.setCurrentText(sec.get("m1_time", ""))
        d1 = sec.get("m1_date","")
        if d1:
            qd = QDate.fromString(d1, "yyyy-MM-dd")
            if qd.isValid():
                self.m1_date_de.setDate(qd)
        self.m1_remi_yes.setChecked(sec.get("m1_remi", "no") == "yes")
        if hasattr(self, "m1_ws_cb"):
            self.m1_ws_cb.setCurrentText(sec.get("m1_ws", ""))
                

        # Match 2 (only if match_count=2)
        if mc == "2":
            self.m2_md_cb.setCurrentText(sec.get("m2_day", ""))
            match2_label = f"{sec.get('m2_home','')} vs {sec.get('m2_away','')}".strip()
            if match2_label != "vs":
                self.m2_match_cb.setCurrentText(match2_label)
            self.m2_time_cb.setCurrentText(sec.get("m2_time", ""))
            d2 = sec.get("m2_date","")
            if d2 and hasattr(self, "m2_date_de"):
                qd2 = QDate.fromString(d2, "yyyy-MM-dd")
                if qd2.isValid():
                    self.m2_date_de.setDate(qd2)
            self.m2_remi_yes.setChecked(sec.get("m2_remi", "no") == "yes")
            if hasattr(self, "m2_ws_cb"):
                self.m2_ws_cb.setCurrentText(sec.get("m2_ws", ""))

    def _send_day1_for_match(self, match_idx: int):
        if not self._sup_online:
            QMessageBox.warning(self, "Offline", "Supervisor is offline. Try again when ONLINE.")
            return

        confirm = QMessageBox.question(
            self, "Send Day-1",
            f"Send all Day-1 tasks for Match {match_idx} now?",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm != QMessageBox.Yes:
            return

        model = self.models.get(match_idx)
        if not model:
            return

        # --- compute expected count (all items in the Matchday -1 section) and send D1_EXPECT header
        expected = 0
        for sec in model.get("sections", []):
            if "matchday -1" in sec.get("title", "").lower():
                expected += len(sec.get("items", []))
        try:
            st = self.payload.get("station","")
            op = self.payload.get("operator","")
            msg = (
                f"D1_EXPECT: Station={st} Operator={op} Match={match_idx} "
                f"Teams='{self.payload.get(f'm{match_idx}',{}).get('hometeam','')} vs "
                f"{self.payload.get(f'm{match_idx}',{}).get('awayteam','')}' "
                f"Count={expected}"
            )
            self._queue_for_supervisor(msg)
        except Exception:
            pass

        sent = 0
        for sec in model.get("sections", []):
            if "matchday -1" not in sec.get("title","").lower():
                continue

            vars_list = getattr(self, f"tasks_vars_{match_idx}", [])

            for it in sec.get("items", []):
                # treat "checked in UI" as done too
                ui_checked = False
                it_text_norm = (it.get("text","") or "").strip().lower()

                # find the matching checkbox by its visible label
                for cb in vars_list:
                    cb_label = (cb.text() or "").strip()
                    # strip decorations like " — 30%" or "  (6 hours before KO)"
                    cb_label = cb_label.split(" — ")[0].split("  (")[0].strip().lower()
                    if cb_label == it_text_norm:
                        ui_checked = cb.isChecked()
                        break

                if ui_checked or it.get("state") in ("done", "approved"):
                    total = max(1, len(vars_list))
                    checked_cnt = sum(1 for c in vars_list if c.isChecked())
                    pct = int(round(checked_cnt * 100 / total))
                    self._queue_for_supervisor(
                        self._format_item_update_message(it.get("text",""), True, pct, match_idx, tag="D1")
                    )
                    sent += 1


# ---------- run ----------
if __name__ == "__main__":
    # ensure dirs exist
    try:
        os.makedirs(SUPPORT_DIR, exist_ok=True)
        os.makedirs(PATH_LOGOS_DIR, exist_ok=True)
        os.makedirs(PATH_CHECKLISTS, exist_ok=True)
        os.makedirs(PATH_STAD_CL, exist_ok=True)
    except Exception as e:
        _log("[FS][WARN] {e}")

    _log("[BOOT] Launching Tech UI...")
    app = QApplication([])
    win = MainWindow()
    win.show()
    app.exec_()