#!/usr/bin/env python3
"""
Linux Endpoint Telemetry Agent

Modes:
  scan    Run a scheduled clamscan, enrich detections, write events to the spool.
          Invoked by endpoint-scan.service (oneshot) from endpoint-scan.timer.
  worker  Long-running: ingest spooled events into the SQLite queue, emit health
          heartbeats, and forward events to Splunk HEC with retry/backoff.
  flush   One pass of ingest + send, then exit (testing / manual drain).
  test    Write a synthetic agent_test event to the spool (pipeline validation).

Standard library only. Compatible with Python 3.6+ (RHEL 8) and newer.
"""

import hashlib
import json
import logging
import logging.handlers
import os
import platform
import re
import signal
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

AGENT_VERSION = "0.2.0"


def env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return int(default)


AGENT_HOME = Path("/opt/linux-security-agent")
SPOOL = Path(os.getenv("AGENT_SPOOL", str(AGENT_HOME / "var/spool")))
STATE_DIR = Path(os.getenv("AGENT_STATE_DIR", str(AGENT_HOME / "var/lib")))
LOG_DIR = os.getenv("AGENT_LOG_DIR", "")
LOG_MAX_BYTES = env_int("AGENT_LOG_MAX_BYTES", 10485760)
LOG_BACKUPS = env_int("AGENT_LOG_BACKUPS", 5)
DATABASE = os.getenv("AGENT_DB", str(STATE_DIR / "events.db"))
LAST_SCAN_FILE = STATE_DIR / "last_scan.json"
SCAN_CONFIG = os.getenv("SCAN_CONFIG", str(AGENT_HOME / "etc/scan.json"))

HEC_URL = os.getenv("HEC_URL", "").rstrip("/")
HEC_TOKEN = os.getenv("HEC_TOKEN", "")
HEC_INDEX = os.getenv("HEC_INDEX", "")
HEC_SOURCETYPE = os.getenv("HEC_SOURCETYPE", "linux:security:telemetry")
HEC_CA_FILE = os.getenv("HEC_CA_FILE", "")
HEC_TIMEOUT = env_int("HEC_TIMEOUT", 15)

MAX_HASH_BYTES = env_int("MAX_HASH_BYTES", 536870912)
BATCH_SIZE = env_int("BATCH_SIZE", 25)
POLL_INTERVAL = env_int("POLL_INTERVAL", 5)
HEARTBEAT_INTERVAL = env_int("HEARTBEAT_INTERVAL", 3600)
MAX_QUEUE_EVENTS = env_int("MAX_QUEUE_EVENTS", 50000)

SCAN_DEFAULTS = {
    "clamscan": "/usr/bin/clamscan",
    "paths": ["/tmp", "/var/tmp", "/opt", "/usr/local"],
    "exclude_dirs": ["^/proc/", "^/sys/", "^/dev/", "^/run/", "^/home/", "^/mnt/",
                     "^%s/" % AGENT_HOME],
    "skip_fstypes": [
        "nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs",
        "glusterfs", "ceph", "9p", "autofs", "afs", "lustre",
    ],
    "max_filesize": "100M",
    "max_scansize": "400M",
    "tempdir": str(STATE_DIR / "tmp"),
    "database_dir": "",
    "max_detection_events": 1000,
    "extra_args": [],
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("endpoint-agent")


def setup_file_logging(mode):
    """Also log to LOG_DIR/<mode>.log; one file per mode since scan and worker run concurrently."""
    if not LOG_DIR:
        return
    try:
        Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            str(Path(LOG_DIR) / ("%s.log" % mode)),
            maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS)
    except OSError:
        log.exception("Cannot open log file in %s; logging to journal only", LOG_DIR)
        return
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logging.getLogger().addHandler(handler)


# --------------------------------------------------------------------------
# Common helpers
# --------------------------------------------------------------------------

def utc_iso(epoch=None):
    if epoch is None:
        epoch = time.time()
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def read_text(path):
    try:
        return Path(path).read_text().strip()
    except (OSError, UnicodeError):
        return None


def host_metadata():
    return {
        "hostname": socket.gethostname(),
        "machine_id": read_text("/etc/machine-id"),
        "boot_id": read_text("/proc/sys/kernel/random/boot_id"),
        "os": platform.platform(),
        "architecture": platform.machine(),
    }


def new_event(event_type, source, **fields):
    now = time.time()
    event = {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "timestamp": utc_iso(now),
        "epoch": now,
        "source": source,
        "agent_version": AGENT_VERSION,
        "host": host_metadata(),
    }
    event.update(fields)
    return event


def write_spool(event):
    """Atomically write one event file into the spool (mode 0600)."""
    SPOOL.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=str(SPOOL))
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(event, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, str(SPOOL / (event["event_id"] + ".json")))
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def atomic_write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(data, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, str(path))
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------
# File enrichment
# --------------------------------------------------------------------------

def hash_file(path, initial):
    """SHA256 of a regular file. Returns (digest or None, problem or None)."""
    if initial.st_size > MAX_HASH_BYTES:
        return None, "file_too_large"

    flags = (os.O_RDONLY
             | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))  # never block on a swapped-in FIFO
    try:
        fd = os.open(path, flags)
    except OSError:
        return None, "open_failed"

    digest = hashlib.sha256()
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode)
                or before.st_ino != initial.st_ino
                or before.st_dev != initial.st_dev):
            return None, "file_replaced"
        try:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        except OSError:
            return None, "read_failed"
        after = os.fstat(fd)

    if (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
        return digest.hexdigest(), "changed_during_read"
    return digest.hexdigest(), None


def enrich_file(path):
    result = {"path": path, "exists": False}
    try:
        info = os.lstat(path)
    except OSError as exc:
        result["metadata_error"] = exc.strerror or str(exc)
        return result

    is_regular = stat.S_ISREG(info.st_mode)
    is_symlink = stat.S_ISLNK(info.st_mode)
    result.update({
        "exists": True,
        "size": info.st_size,
        "inode": info.st_ino,
        "device": info.st_dev,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": oct(stat.S_IMODE(info.st_mode)),
        "mtime": utc_iso(info.st_mtime),
        "ctime": utc_iso(info.st_ctime),
        "file_type": "regular" if is_regular else "symlink" if is_symlink else "other",
    })

    if is_regular:
        digest, problem = hash_file(path, info)
        result["sha256"] = digest
        result["hash_status"] = problem or "complete"
    else:
        result["sha256"] = None
        result["hash_status"] = "not_regular_file"
    return result


# --------------------------------------------------------------------------
# Scheduled scan
# --------------------------------------------------------------------------

def load_scan_config():
    config = dict(SCAN_DEFAULTS)
    try:
        with open(SCAN_CONFIG) as handle:
            loaded = json.load(handle)
        if not isinstance(loaded, dict):
            raise ValueError("scan config must be a JSON object")
        config.update(loaded)
    except FileNotFoundError:
        log.warning("Scan config %s not found; using defaults", SCAN_CONFIG)
    for key in ("paths", "exclude_dirs", "skip_fstypes", "extra_args"):
        if not isinstance(config[key], list):
            raise ValueError("scan config '%s' must be a list" % key)
    return config


def _unescape_mount(value):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), value)


def mount_table():
    mounts = []
    try:
        with open("/proc/self/mounts") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 3:
                    mounts.append((_unescape_mount(parts[1]), parts[2]))
    except OSError:
        pass
    return mounts


def fstype_for(path, mounts):
    real = os.path.realpath(path)
    best, best_type = "", None
    for mountpoint, fstype in mounts:
        if mountpoint == "/":
            matches = True
        else:
            matches = real == mountpoint or real.startswith(mountpoint.rstrip("/") + "/")
        if matches and len(mountpoint) >= len(best):
            best, best_type = mountpoint, fstype
    return best_type


def resolve_scan_targets(config):
    mounts = mount_table()
    targets, skipped = [], []
    for path in config["paths"]:
        if not os.path.isabs(path):
            skipped.append({"path": path, "reason": "not_absolute"})
        elif not os.path.exists(path):
            skipped.append({"path": path, "reason": "missing"})
        else:
            fstype = fstype_for(path, mounts)
            if fstype in config["skip_fstypes"]:
                skipped.append({"path": path, "reason": "network_filesystem", "fstype": fstype})
            else:
                targets.append(path)
    return targets, skipped


def clamscan_version(binary, database_dir):
    """Parse 'ClamAV 1.0.7/27445/Sat Oct 31 08:23:45 2026'."""
    info = {"engine_version": None, "signature_version": None,
            "signature_date": None, "signature_age_days": None}
    cmd = [binary, "--version"]
    if database_dir:
        cmd.append("--database=" + database_dir)
    try:
        out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             universal_newlines=True, timeout=60,
                             env=dict(os.environ, LC_ALL="C")).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return info
    parts = out.split("/", 2)
    info["engine_version"] = parts[0].replace("ClamAV", "").strip() or None
    if len(parts) >= 2:
        info["signature_version"] = parts[1].strip()
    if len(parts) == 3:
        info["signature_date"] = parts[2].strip()
        try:
            built = datetime.strptime(parts[2].strip(), "%a %b %d %H:%M:%S %Y")
            info["signature_age_days"] = round(
                (datetime.now() - built).total_seconds() / 86400, 1)
        except ValueError:
            pass
    return info


def build_clamscan_command(config, targets):
    cmd = [
        config["clamscan"],
        "--recursive",
        "--infected",
        "--cross-fs=no",
        "--follow-dir-symlinks=0",
        "--follow-file-symlinks=0",
        "--max-filesize=" + str(config["max_filesize"]),
        "--max-scansize=" + str(config["max_scansize"]),
    ]
    if config.get("tempdir"):
        cmd.append("--tempdir=" + config["tempdir"])
    if config.get("database_dir"):
        cmd.append("--database=" + config["database_dir"])
    for pattern in config["exclude_dirs"]:
        cmd.append("--exclude-dir=" + pattern)
    cmd.extend(str(arg) for arg in config["extra_args"])
    cmd.extend(targets)
    return cmd


def _summary_key(text):
    return re.sub(r"[^a-z0-9]+", "_", text.strip().lower()).strip("_")


def _to_int(value):
    try:
        return int(str(value).split()[0])
    except (ValueError, IndexError, TypeError):
        return None


def run_clamscan(cmd):
    """Run clamscan, stream stdout, return (rc, detections, summary, stderr_lines)."""
    detections, summary, stdout_errors = [], {}, []
    in_summary = False
    with tempfile.TemporaryFile(mode="w+", errors="surrogateescape") as errfile:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=errfile,
            universal_newlines=True, errors="surrogateescape",
            env=dict(os.environ, LC_ALL="C"),
        )
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            if line.startswith("----------- SCAN SUMMARY"):
                in_summary = True
                continue
            if in_summary:
                if ":" in line:
                    key, value = line.split(":", 1)
                    summary[_summary_key(key)] = value.strip()
                continue
            if line.endswith(" FOUND"):
                path, sep, signature = line[:-len(" FOUND")].rpartition(": ")
                if sep:
                    detections.append((path, signature))
            elif line.endswith(" ERROR"):
                stdout_errors.append(line)
        rc = proc.wait()
        errfile.seek(0)
        stderr_lines = [l.rstrip("\n") for l in errfile if l.strip()]
    return rc, detections, summary, stdout_errors + stderr_lines


def scan():
    config = load_scan_config()
    scan_id = str(uuid.uuid4())
    started = time.time()
    if config.get("tempdir"):
        Path(config["tempdir"]).mkdir(parents=True, exist_ok=True)

    targets, skipped = resolve_scan_targets(config)
    engine = clamscan_version(config["clamscan"], config.get("database_dir"))

    base = {
        "scan_id": scan_id,
        "scan_type": "scheduled",
        "targets": targets,
        "skipped_paths": skipped,
    }

    if not targets:
        write_spool(new_event("scan_summary", "clamav", scan=dict(
            base, status="no_targets", started=utc_iso(started),
            finished=utc_iso(), duration_seconds=0), engine=engine))
        log.error("No scannable targets; skipped=%s", skipped)
        return 1

    cmd = build_clamscan_command(config, targets)
    log.info("Scan %s starting: %s", scan_id, " ".join(cmd))
    try:
        rc, detections, summary, errors = run_clamscan(cmd)
    except OSError as exc:
        write_spool(new_event("agent_error", "agent", error={
            "stage": "scan", "scan_id": scan_id, "message": str(exc)}))
        log.error("Could not execute clamscan: %s", exc)
        return 1

    finished = time.time()
    limit = int(config["max_detection_events"])

    for path, signature in detections[:limit]:
        write_spool(new_event(
            "malware_detection", "clamav",
            scan_id=scan_id,
            detection={
                "engine": "ClamAV",
                "engine_version": engine["engine_version"],
                "signature": signature,
                "signature_version": engine["signature_version"],
                "action": "detected",
                "scan_type": "scheduled",
            },
            file=enrich_file(path),
            # Scheduled scans cannot attribute a file to a process.
            process={"pid": None, "ppid": None, "executable": None, "command_line": None},
        ))

    if rc == 0:
        status = "clean"
    elif rc == 1:
        status = "infected"
    elif summary:
        status = "completed_with_errors"
    else:
        status = "failed"

    scan_info = dict(
        base,
        status=status,
        exit_code=rc,
        started=utc_iso(started),
        finished=utc_iso(finished),
        duration_seconds=round(finished - started, 1),
        scanned_files=_to_int(summary.get("scanned_files")),
        scanned_directories=_to_int(summary.get("scanned_directories")),
        infected_files=_to_int(summary.get("infected_files")),
        total_errors=_to_int(summary.get("total_errors")) or len(errors),
        data_scanned=summary.get("data_scanned"),
        detections_reported=min(len(detections), limit),
        detections_truncated=max(0, len(detections) - limit),
        error_sample=errors[:20],
    )
    write_spool(new_event("scan_summary", "clamav", scan=scan_info, engine=engine))

    atomic_write_json(LAST_SCAN_FILE, {
        "scan_id": scan_id,
        "status": status,
        "finished": utc_iso(finished),
        "finished_epoch": finished,
        "infected_files": scan_info["infected_files"],
        "signature_version": engine["signature_version"],
        "signature_age_days": engine["signature_age_days"],
    })

    log.info("Scan %s %s: rc=%s detections=%d duration=%.1fs",
             scan_id, status, rc, len(detections), finished - started)
    return 1 if status == "failed" else 0


# --------------------------------------------------------------------------
# Queue and forwarding
# --------------------------------------------------------------------------

def database():
    Path(DATABASE).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATABASE, timeout=30)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("""
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            event_json TEXT NOT NULL,
            attempts INTEGER DEFAULT 0,
            next_attempt REAL DEFAULT 0
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_next_attempt ON events(next_attempt)")
    db.commit()
    return db


class State(object):
    stop = False
    last_success = None
    dropped_events = 0
    last_heartbeat = 0.0


def enqueue(db, event):
    db.execute("INSERT OR IGNORE INTO events (event_id, event_json) VALUES (?, ?)",
               (event["event_id"], json.dumps(event)))


def ingest_spool(db):
    for event_file in sorted(SPOOL.glob("*.json")):
        try:
            with event_file.open() as handle:
                event = json.load(handle)
            if "event_id" not in event:
                raise ValueError("event has no event_id")
            event.setdefault("host", host_metadata())
            enqueue(db, event)
            db.commit()
            event_file.unlink()
        except (ValueError, KeyError):
            log.exception("Malformed spool file %s; renaming to .bad", event_file)
            try:
                event_file.rename(event_file.with_suffix(".bad"))
            except OSError:
                pass
        except Exception:
            log.exception("Failed processing %s", event_file)


def enforce_queue_bound(db):
    (count,) = db.execute("SELECT COUNT(*) FROM events").fetchone()
    excess = count - MAX_QUEUE_EVENTS
    if excess > 0:
        # Drop oldest non-detection events first, then oldest of anything.
        removed = db.execute("""
            DELETE FROM events WHERE rowid IN (
                SELECT rowid FROM events
                WHERE event_json NOT LIKE '%"event_type": "malware_detection"%'
                ORDER BY rowid LIMIT ?)""", (excess,)).rowcount
        if removed < excess:
            removed += db.execute("""
                DELETE FROM events WHERE rowid IN (
                    SELECT rowid FROM events ORDER BY rowid LIMIT ?)""",
                (excess - removed,)).rowcount
        db.commit()
        State.dropped_events += removed
        log.warning("Queue over %d events; dropped %d oldest", MAX_QUEUE_EVENTS, removed)


def ssl_context():
    return ssl.create_default_context(cafile=HEC_CA_FILE or None)


def send_batch(db, context):
    if not HEC_URL or not HEC_TOKEN:
        log.error("HEC configuration missing")
        return False

    rows = db.execute("""
        SELECT event_id, event_json, attempts FROM events
        WHERE next_attempt <= ? ORDER BY next_attempt, rowid LIMIT ?""",
        (time.time(), BATCH_SIZE)).fetchall()
    if not rows:
        return True

    envelopes = []
    for _event_id, event_json, _attempts in rows:
        event = json.loads(event_json)
        envelope = {
            "time": event.get("epoch", time.time()),
            "host": (event.get("host") or {}).get("hostname", socket.gethostname()),
            "source": "linux-endpoint-agent",
            "sourcetype": HEC_SOURCETYPE,
            "event": event,
        }
        if HEC_INDEX:
            envelope["index"] = HEC_INDEX
        envelopes.append(json.dumps(envelope))

    request = urllib.request.Request(
        HEC_URL + "/services/collector/event",
        data="\n".join(envelopes).encode(),
        headers={"Authorization": "Splunk " + HEC_TOKEN,
                 "Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=HEC_TIMEOUT, context=context) as response:
            result = json.loads(response.read().decode() or "{}")
            if response.status != 200 or result.get("code") != 0:
                raise RuntimeError("HEC rejected batch: %s" % result)
        # Accepted by HEC; not proof of indexing. See HEC indexer acknowledgment.
        db.executemany("DELETE FROM events WHERE event_id = ?", [(r[0],) for r in rows])
        db.commit()
        State.last_success = time.time()
        log.info("Forwarded %d events", len(rows))
        return True
    except Exception:
        log.exception("HEC transmission failed")
        now = time.time()
        for event_id, _event_json, attempts in rows:
            attempts += 1
            delay = min(3600, 2 ** min(attempts, 12))
            db.execute("UPDATE events SET attempts = ?, next_attempt = ? WHERE event_id = ?",
                       (attempts, now + delay, event_id))
        db.commit()
        return False


def heartbeat(db):
    (queue_depth,) = db.execute("SELECT COUNT(*) FROM events").fetchone()
    last_scan = None
    try:
        with LAST_SCAN_FILE.open() as handle:
            last_scan = json.load(handle)
        last_scan["age_hours"] = round(
            (time.time() - last_scan.get("finished_epoch", 0)) / 3600, 1)
    except (OSError, ValueError):
        pass
    enqueue(db, new_event("agent_health", "agent", health={
        "queue_depth": queue_depth,
        "spool_depth": len(list(SPOOL.glob("*.json"))),
        "bad_spool_files": len(list(SPOOL.glob("*.bad"))),
        "dropped_events_total": State.dropped_events,
        "last_hec_success": utc_iso(State.last_success) if State.last_success else None,
        "last_scan": last_scan,
    }))
    db.commit()
    State.last_heartbeat = time.time()


def _handle_stop(_signum, _frame):
    State.stop = True


def worker():
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)
    SPOOL.mkdir(parents=True, exist_ok=True)
    db = database()
    context = ssl_context()
    log.info("Endpoint agent %s worker started", AGENT_VERSION)

    while not State.stop:
        try:
            ingest_spool(db)
            if time.time() - State.last_heartbeat >= HEARTBEAT_INTERVAL:
                heartbeat(db)
            enforce_queue_bound(db)
            send_batch(db, context)
        except Exception:
            log.exception("Worker iteration failed")
        for _ in range(POLL_INTERVAL):
            if State.stop:
                break
            time.sleep(1)

    db.close()
    log.info("Endpoint agent worker stopped")
    return 0


def flush():
    db = database()
    context = ssl_context()
    ingest_spool(db)
    enforce_queue_bound(db)
    while True:
        (ready,) = db.execute("SELECT COUNT(*) FROM events WHERE next_attempt <= ?",
                              (time.time(),)).fetchone()
        if not ready or not send_batch(db, context):
            break
    (remaining,) = db.execute("SELECT COUNT(*) FROM events").fetchone()
    log.info("Flush complete; %d events remain queued", remaining)
    return 0 if remaining == 0 else 1


def test_event():
    write_spool(new_event("agent_test", "agent", message="pipeline test event"))
    log.info("Wrote test event to %s", SPOOL)
    return 0


MODES = {"scan": scan, "worker": worker, "flush": flush, "test": test_event}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in MODES:
        sys.exit("Usage: endpoint_agent.py [%s]" % "|".join(MODES))
    setup_file_logging(sys.argv[1])
    sys.exit(MODES[sys.argv[1]]())
