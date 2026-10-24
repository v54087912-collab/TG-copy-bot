import os
import re
import json
import asyncio
import time
import hashlib
import sqlite3
import urllib.parse
import hmac
import base64
import secrets
import logging
from datetime import datetime, timezone, timedelta

# Ensure asyncio event loop exists in Python 3.12+
try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())

import pyaes
from telebot.async_telebot import AsyncTeleBot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from pyrogram import Client
from pyrogram.raw import functions
from pyrogram.errors import (
    FloodWait,
    SessionPasswordNeeded,
    PeerFlood,
    ChatWriteForbidden,
    UserBannedInChannel,
    AuthKeyUnregistered,
    UserDeactivated,
    MessageIdInvalid,
)

# Application logger configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("telegram_copier")

# Load .env
if os.path.exists(".env"):
    with open(".env") as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                os.environ[k] = v

BOT_TOKEN = os.environ.get("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("Missing BOT_TOKEN in .env file")
bot = AsyncTeleBot(BOT_TOKEN)

# Database Encryption & Persistent Storage (AES-256 + HMAC)

DB_KEY_ENV = os.environ.get("DB_ENCRYPTION_KEY")
if not DB_KEY_ENV:
    DB_KEY_ENV = secrets.token_hex(32)
    os.environ["DB_ENCRYPTION_KEY"] = DB_KEY_ENV
    try:
        with open(".env", "a") as f:
            f.write(f"\nDB_ENCRYPTION_KEY={DB_KEY_ENV}\n")
        logger.info("Generated new AES-256 DB_ENCRYPTION_KEY and saved to .env")
    except Exception as e:
        logger.warning(f"Could not write encryption key to .env: {e}")

DB_CIPHER_KEY = hashlib.pbkdf2_hmac(
    "sha256",
    DB_KEY_ENV.encode("utf-8"),
    b"telegram_copier_db_salt_v1",
    100000,
    32
)

def make_pyaes_counter(iv_bytes):
    val = int.from_bytes(iv_bytes, byteorder="big")
    try:
        return pyaes.Counter(initial_value=val)
    except TypeError:
        return pyaes.Counter(val)

def encrypt_db_payload(plain_dict):
    raw_bytes = json.dumps(plain_dict).encode("utf-8")
    iv = os.urandom(16)
    counter = make_pyaes_counter(iv)
    aes = pyaes.AESModeOfOperationCTR(DB_CIPHER_KEY, counter=counter)
    ciphertext = aes.encrypt(raw_bytes)
    tag = hmac.new(DB_CIPHER_KEY, iv + ciphertext, hashlib.sha256).digest()

    return {
        "enc": True,
        "v": 1,
        "iv": base64.b64encode(iv).decode("utf-8"),
        "data": base64.b64encode(ciphertext).decode("utf-8"),
        "hmac": base64.b64encode(tag).decode("utf-8")
    }

def decrypt_db_payload(packed):
    iv = base64.b64decode(packed["iv"])
    ciphertext = base64.b64decode(packed["data"])
    expected_tag = base64.b64decode(packed["hmac"])

    tag = hmac.new(DB_CIPHER_KEY, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Database HMAC verification failed! File corrupted or encryption key mismatch.")

    counter = make_pyaes_counter(iv)
    aes = pyaes.AESModeOfOperationCTR(DB_CIPHER_KEY, counter=counter)
    decrypted_bytes = aes.decrypt(ciphertext)
    return json.loads(decrypted_bytes.decode("utf-8"))

def load_db():
    if not os.path.exists("db.json"):
        return {}
    try:
        with open("db.json", "r") as f:
            raw = json.load(f)

        if isinstance(raw, dict) and raw.get("enc") is True:
            data = decrypt_db_payload(raw)
            # Maintain backup
            try:
                with open("db.json.bak", "w") as bf:
                    json.dump(raw, bf)
            except Exception:
                pass
            return data

        # Legacy plain-text JSON detected -> automatically migrate to AES-256 encrypted storage!
        logger.info("Plain-text db.json detected. Migrating to AES-256 encrypted storage...")
        save_db(raw)
        return raw
    except Exception as e:
        logger.error(f"Error reading db.json: {e}")
        if os.path.exists("db.json.bak"):
            try:
                with open("db.json.bak", "r") as bf:
                    bak_raw = json.load(bf)
                logger.info("Restored db.json from backup.")
                return decrypt_db_payload(bak_raw)
            except Exception:
                pass
        return {}

def save_db(data):
    try:
        encrypted_dict = encrypt_db_payload(data)
        tmp_path = "db.json.tmp"
        with open(tmp_path, "w") as f:
            json.dump(encrypted_dict, f, indent=2)
        os.replace(tmp_path, "db.json")
    except Exception as e:
        logger.error(f"Error encrypting and saving db.json: {e}")

DB = load_db()

# State and session storage
user_states = {}            # user_id -> str
user_auth_data = {}         # user_id -> dict
user_clients = {}           # user_id -> Pyrogram Client
active_tasks = {}           # user_id -> bool
user_dialog_cache = {}      # user_id -> list of dicts: {"id", "title", "raw_title", "username", "type"}
user_dialog_last_fetch = {} # user_id -> timestamp
user_active_query = {}      # user_id -> active search query string or None
user_task_info = {}         # user_id -> dict for live progress status

CONTENT_TYPE_LABELS = {
    "all": "All Content 📁",
    "media": "Media Files Only 🎬🖼️",
    "video": "Videos Only 🎬",
    "photo": "Photos Only 🖼️",
    "document": "Documents/Files 📄",
    "text": "Text Only 📝",
    "text_extract": "Extract Captions as Text 📝⚡"
}

CONTENT_TYPE_CYCLE = ["all", "media", "video", "photo", "document", "text", "text_extract"]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEDUP_DB_PATH = os.path.join(BASE_DIR, "dedup.db")
STATS_DB_PATH = os.path.join(BASE_DIR, "stats.db")

# Message Deduplication Engine

user_dedup_cache = {}  # user_id -> set(file_hash)

def init_dedup_db():
    conn = sqlite3.connect(DEDUP_DB_PATH)
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA synchronous=NORMAL;")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS copied_hashes (
            user_id INTEGER,
            src_chat_id INTEGER,
            file_hash TEXT,
            copied_at REAL,
            PRIMARY KEY (user_id, file_hash)
        )
    """)
    conn.commit()
    conn.close()

def load_user_dedup_cache(user_id):
    if user_id in user_dedup_cache:
        return user_dedup_cache[user_id]
    hashes = set()
    try:
        conn = sqlite3.connect(DEDUP_DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT file_hash FROM copied_hashes WHERE user_id = ?", (user_id,))
        for row in cur.fetchall():
            hashes.add(row[0])
        conn.close()
    except Exception as e:
        logger.error(f"Error loading dedup cache for user {user_id}: {e}")
    user_dedup_cache[user_id] = hashes
    return hashes

def compute_quick_hash(msg):
    """
    Returns unique deterministic hash for message:
    - Media uses Telegram's file_unique_id (or fallback file_id hash)
    - Text uses MD5 hash of message text
    """
    if not msg:
        return None
    media = (
        getattr(msg, "photo", None)
        or getattr(msg, "video", None)
        or getattr(msg, "document", None)
        or getattr(msg, "audio", None)
        or getattr(msg, "voice", None)
        or getattr(msg, "animation", None)
        or getattr(msg, "sticker", None)
    )
    if media:
        uid = getattr(media, "file_unique_id", None)
        if uid:
            return f"media_{uid}"
        fid = getattr(media, "file_id", None)
        if fid:
            return f"media_{hashlib.md5(fid.encode('utf-8')).hexdigest()}"
    if getattr(msg, "text", None):
        t = msg.text.strip()
        if t:
            return f"text_{hashlib.md5(t.encode('utf-8')).hexdigest()}"
    return None

def is_hash_copied(user_id, file_hash):
    if not file_hash:
        return False
    cache = load_user_dedup_cache(user_id)
    return file_hash in cache

def record_copied_hashes_batch(user_id, src_chat_id, hash_list):
    if not hash_list:
        return
    valid = [h for h in hash_list if h]
    if not valid:
        return
    cache = load_user_dedup_cache(user_id)
    for h in valid:
        cache.add(h)
    now = time.time()
    try:
        s_id = int(src_chat_id) if str(src_chat_id).lstrip('-').isdigit() else 0
    except Exception:
        s_id = 0
    try:
        conn = sqlite3.connect(DEDUP_DB_PATH)
        cur = conn.cursor()
        cur.executemany(
            "INSERT OR IGNORE INTO copied_hashes (user_id, src_chat_id, file_hash, copied_at) VALUES (?, ?, ?, ?)",
            [(user_id, s_id, h, now) for h in valid]
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error recording copied hashes: {e}")

def get_user_dedup_count(user_id):
    cache = load_user_dedup_cache(user_id)
    return len(cache)

def clear_user_dedup_cache(user_id):
    user_dedup_cache[user_id] = set()
    try:
        conn = sqlite3.connect(DEDUP_DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM copied_hashes WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error clearing dedup cache for user {user_id}: {e}")

# Analytics & Job Telemetry Database

def init_stats_db():
    conn = sqlite3.connect(STATS_DB_PATH)
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA synchronous=NORMAL;")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS job_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            src_title TEXT,
            dst_title TEXT,
            total INTEGER,
            copied INTEGER,
            skipped_dup INTEGER,
            failed INTEGER,
            duration_sec REAL,
            avg_speed REAL,
            created_at REAL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS daily_stats (
            user_id INTEGER,
            date_str TEXT,
            messages_copied INTEGER,
            jobs_completed INTEGER,
            PRIMARY KEY (user_id, date_str)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS job_checkpoints (
            user_id INTEGER PRIMARY KEY,
            src INTEGER,
            dst INTEGER,
            src_title TEXT,
            dst_title TEXT,
            total INTEGER,
            copied_count INTEGER,
            current_index INTEGER,
            skipped_dup INTEGER,
            range_label TEXT,
            content_type TEXT,
            signature TEXT,
            is_protected INTEGER,
            messages_json TEXT,
            msg_hash_json TEXT,
            created_at REAL,
            updated_at REAL
        )
    """)
    conn.commit()
    conn.close()

# Account Health, Safety & Checkpoint Engine

user_floodwait_timestamps = {}  # user_id -> list of float timestamps
user_peerflood_until = {}       # user_id -> timestamp (float)

def record_floodwait_event(user_id):
    now = time.time()
    if user_id not in user_floodwait_timestamps:
        user_floodwait_timestamps[user_id] = []
    user_floodwait_timestamps[user_id] = [t for t in user_floodwait_timestamps[user_id] if now - t <= 3600]
    user_floodwait_timestamps[user_id].append(now)

def get_account_health(user_id):
    now = time.time()
    pf_until = user_peerflood_until.get(user_id, 0)
    if now < pf_until:
        rem_hrs = round((pf_until - now) / 3600, 1)
        return "🔴 RESTRICTED (PeerFlood)", f"Rest for {rem_hrs}h remaining", "red"

    fw_list = [t for t in user_floodwait_timestamps.get(user_id, []) if now - t <= 3600]
    user_floodwait_timestamps[user_id] = fw_list
    fw_count = len(fw_list)

    if fw_count >= 3:
        return f"🔴 HOT ({fw_count} FloodWaits/1h)", "Cooling down. Rest required!", "red"
    elif fw_count in (1, 2):
        return f"🟡 WARM ({fw_count} FloodWait)", "Adaptive safety pacing active", "yellow"
    else:
        return "🟢 HEALTHY", "Optimal safety standing", "green"

def mark_peerflood_blocked(user_id, hours=24):
    user_peerflood_until[user_id] = time.time() + (hours * 3600)

async def run_preflight_checks(u_client, user_id, chat_id, src, dst):
    """
    Pre-flight safety validation before copying starts:
    1. Checks if src == dst (infinite loop prevention)
    2. Checks Account Health Lock (PeerFlood / 3+ FloodWaits)
    3. Checks source chat existence & protection status
    4. Checks destination write permissions
    """
    try:
        s_id = int(src) if str(src).lstrip('-').isdigit() else src
        d_id = int(dst) if str(dst).lstrip('-').isdigit() else dst
        if s_id == d_id:
            return False, "❌ <b>Source and Destination are identical!</b> Blocked to prevent an infinite forwarding loop.", False
    except Exception:
        pass

    status_label, reason, color = get_account_health(user_id)
    if color == "red":
        return False, f"🛑 <b>Pre-flight Safety Block:</b>\nAccount standing is currently <b>{status_label}</b>: {reason}\n\nTask paused to protect your Telegram account from restrictions. Please allow the account to cool down before resuming.", False

    is_protected = False
    try:
        src_chat = await u_client.get_chat(src)
        is_protected = bool(getattr(src_chat, "has_protected_content", False))
    except Exception as e:
        return False, f"❌ <b>Source chat access error:</b> {e}\nCheck if user account has joined this channel.", False

    try:
        dst_chat = await u_client.get_chat(dst)
        perms = getattr(dst_chat, "permissions", None)
        if perms and not getattr(perms, "can_send_messages", True):
            return False, "❌ <b>Destination write access missing!</b> Send message permission is disabled in the destination chat.", is_protected
    except Exception as e:
        return False, f"❌ <b>Destination chat access error:</b> {e}\nCheck if destination exists and user is a member/admin.", is_protected

    return True, "Pre-flight checks passed", is_protected


def save_checkpoint(user_id, src, dst, src_title, dst_title, total, copied_count, current_index, skipped_dup, range_label, content_type, settings_dict, is_protected, messages, msg_hash_map):
    try:
        now = time.time()
        msgs_json = json.dumps(messages)
        hash_json = json.dumps(msg_hash_map)
        is_prot_int = 1 if is_protected else 0
        sig_str = json.dumps(settings_dict) if isinstance(settings_dict, dict) else (settings_dict or "")

        conn = sqlite3.connect(STATS_DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO job_checkpoints (
                user_id, src, dst, src_title, dst_title, total, copied_count, current_index, skipped_dup,
                range_label, content_type, signature, is_protected, messages_json, msg_hash_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                src = excluded.src,
                dst = excluded.dst,
                src_title = excluded.src_title,
                dst_title = excluded.dst_title,
                total = excluded.total,
                copied_count = excluded.copied_count,
                current_index = excluded.current_index,
                skipped_dup = excluded.skipped_dup,
                range_label = excluded.range_label,
                content_type = excluded.content_type,
                signature = excluded.signature,
                is_protected = excluded.is_protected,
                messages_json = excluded.messages_json,
                msg_hash_json = excluded.msg_hash_json,
                updated_at = excluded.updated_at
        """, (
            user_id, src, dst, src_title, dst_title, total, copied_count, current_index, skipped_dup,
            range_label, content_type, sig_str, is_prot_int, msgs_json, hash_json, now, now
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error saving job checkpoint: {e}")

def get_checkpoint(user_id):
    try:
        conn = sqlite3.connect(STATS_DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            SELECT user_id, src, dst, src_title, dst_title, total, copied_count, current_index, skipped_dup,
                   range_label, content_type, signature, is_protected, messages_json, msg_hash_json, created_at, updated_at
            FROM job_checkpoints WHERE user_id = ?
        """, (user_id,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        return {
            "user_id": row[0],
            "src": row[1],
            "dst": row[2],
            "src_title": row[3],
            "dst_title": row[4],
            "total": row[5],
            "copied_count": row[6],
            "current_index": row[7],
            "skipped_dup": row[8],
            "range_label": row[9],
            "content_type": row[10],
            "signature": row[11],
            "is_protected": bool(row[12]),
            "messages_json": row[13],
            "msg_hash_json": row[14],
            "created_at": row[15],
            "updated_at": row[16]
        }
    except Exception as e:
        logger.error(f"Error fetching checkpoint: {e}")
        return None

def update_checkpoint_progress(user_id, copied_count, current_index, skipped_dup):
    try:
        now = time.time()
        conn = sqlite3.connect(STATS_DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            UPDATE job_checkpoints
            SET copied_count = ?, current_index = ?, skipped_dup = ?, updated_at = ?
            WHERE user_id = ?
        """, (copied_count, current_index, skipped_dup, now, user_id))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error updating checkpoint progress: {e}")

def delete_checkpoint(user_id):
    try:
        conn = sqlite3.connect(STATS_DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM job_checkpoints WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        logger.info(f"Cleared checkpoint for user {user_id}")
    except Exception as e:
        logger.error(f"Error clearing checkpoint: {e}")

def record_job_stats(user_id, src_title, dst_title, total, copied, skipped_dup, failed, duration_sec):
    try:
        speed = round(copied / max(duration_sec, 0.1), 1)
        now = time.time()
        date_str = datetime.now().strftime("%Y-%m-%d")

        conn = sqlite3.connect(STATS_DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO job_stats (user_id, src_title, dst_title, total, copied, skipped_dup, failed, duration_sec, avg_speed, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, src_title, dst_title, total, copied, skipped_dup, failed, round(duration_sec, 2), speed, now))

        cur.execute("""
            INSERT INTO daily_stats (user_id, date_str, messages_copied, jobs_completed)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(user_id, date_str) DO UPDATE SET
                messages_copied = messages_copied + excluded.messages_copied,
                jobs_completed = jobs_completed + 1
        """, (user_id, date_str, copied))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error recording job stats: {e}")

def get_user_analytics_summary(user_id):
    try:
        conn = sqlite3.connect(STATS_DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            SELECT 
                COUNT(*), 
                COALESCE(SUM(copied), 0), 
                COALESCE(SUM(total), 0), 
                COALESCE(AVG(avg_speed), 0),
                COALESCE(SUM(duration_sec), 0)
            FROM job_stats WHERE user_id = ?
        """, (user_id,))
        row = cur.fetchone()
        total_jobs = row[0] if row else 0
        total_copied = row[1] if row else 0
        total_total = row[2] if row else 0
        avg_speed = row[3] if row else 0.0
        total_duration = row[4] if row else 0.0

        today_str = datetime.now().strftime("%Y-%m-%d")
        cur.execute("SELECT messages_copied, jobs_completed FROM daily_stats WHERE user_id = ? AND date_str = ?", (user_id, today_str))
        d_row = cur.fetchone()
        today_copied = d_row[0] if d_row else 0
        today_jobs = d_row[1] if d_row else 0

        conn.close()
        success_rate = round((total_copied / max(total_total, 1)) * 100, 1) if total_total > 0 else 100.0
        return {
            "total_jobs": total_jobs,
            "total_copied": total_copied,
            "avg_speed": round(avg_speed, 1),
            "total_duration": total_duration,
            "success_rate": success_rate,
            "today_copied": today_copied,
            "today_jobs": today_jobs
        }
    except Exception as e:
        logger.error(f"Error fetching analytics summary: {e}")
        return {
            "total_jobs": 0, "total_copied": 0, "avg_speed": 0.0,
            "total_duration": 0.0, "success_rate": 100.0, "today_copied": 0, "today_jobs": 0
        }

def get_user_7day_stats(user_id):
    result = []
    today = datetime.now().date()
    try:
        conn = sqlite3.connect(STATS_DB_PATH)
        cur = conn.cursor()
        for i in range(6, -1, -1):
            d = today - timedelta(days=i)
            d_str = d.strftime("%Y-%m-%d")
            display_d = d.strftime("%m/%d")
            cur.execute("SELECT messages_copied FROM daily_stats WHERE user_id = ? AND date_str = ?", (user_id, d_str))
            row = cur.fetchone()
            count = row[0] if row else 0
            result.append((display_d, count))
        conn.close()
    except Exception as e:
        logger.error(f"Error fetching 7-day stats: {e}")
        for i in range(6, -1, -1):
            d = today - timedelta(days=i)
            result.append((d.strftime("%m/%d"), 0))
    return result

def get_user_recent_jobs(user_id, limit=5):
    try:
        conn = sqlite3.connect(STATS_DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            SELECT src_title, dst_title, total, copied, skipped_dup, failed, duration_sec, avg_speed, created_at
            FROM job_stats
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
        """, (user_id, limit))
        rows = cur.fetchall()
        conn.close()
        return rows
    except Exception as e:
        logger.error(f"Error fetching recent jobs: {e}")
        return []

def clear_user_stats(user_id):
    try:
        conn = sqlite3.connect(STATS_DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM job_stats WHERE user_id = ?", (user_id,))
        cur.execute("DELETE FROM daily_stats WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error clearing user stats: {e}")

# Proxy Configuration & Routing Engine

def parse_proxy_string(text):
    text = text.strip()
    if not (text.startswith("socks5://") or text.startswith("socks4://") or text.startswith("http://") or text.startswith("https://")):
        parts = text.split(":")
        if len(parts) == 2:
            host, port = parts
            if port.strip().isdigit():
                return {
                    "scheme": "socks5",
                    "hostname": host.strip(),
                    "port": int(port.strip()),
                    "username": None,
                    "password": None
                }
        elif len(parts) == 4:
            host, port, user, pwd = parts
            if port.strip().isdigit():
                return {
                    "scheme": "socks5",
                    "hostname": host.strip(),
                    "port": int(port.strip()),
                    "username": user.strip(),
                    "password": pwd.strip()
                }
        return None

    try:
        p = urllib.parse.urlparse(text)
        scheme = p.scheme.lower()
        if scheme not in ["socks5", "socks4", "http", "https"]:
            return None
        hostname = p.hostname
        port = p.port
        if not hostname or not port:
            return None
        return {
            "scheme": scheme,
            "hostname": hostname,
            "port": int(port),
            "username": p.username,
            "password": p.password
        }
    except Exception:
        return None

async def test_proxy_ping(proxy_dict, timeout=4.0):
    start = time.time()
    try:
        hostname = proxy_dict["hostname"]
        port = int(proxy_dict["port"])
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        latency = int((time.time() - start) * 1000)
        return max(1, latency)
    except Exception:
        return None

def get_user_proxies(user_id):
    uid = str(user_id)
    if uid not in DB:
        DB[uid] = {}
    if "proxies" not in DB[uid]:
        DB[uid]["proxies"] = []
    return DB[uid]["proxies"]

def get_user_active_proxy(user_id):
    uid = str(user_id)
    if uid not in DB:
        return None
    active_id = DB[uid].get("active_proxy_id")
    if not active_id:
        return None
    for px in DB[uid].get("proxies", []):
        if px["id"] == active_id:
            return px
    return None

def build_pyrogram_proxy(px):
    if not px:
        return None
    arg = {
        "scheme": px["scheme"],
        "hostname": px["hostname"],
        "port": int(px["port"])
    }
    if px.get("username"):
        arg["username"] = px["username"]
    if px.get("password"):
        arg["password"] = px["password"]
    return arg

async def switch_user_proxy(user_id, proxy_id_or_none):
    if active_tasks.get(user_id, False):
        return False, "❌ A copy task is currently active. Please stop the running task before switching proxies."
    uid = str(user_id)
    if uid not in DB:
        return False, "User not found in database"

    DB[uid]["active_proxy_id"] = proxy_id_or_none
    save_db(DB)

    data = DB[uid]
    active_px = get_user_active_proxy(user_id)
    proxy_arg = build_pyrogram_proxy(active_px)

    old_client = user_clients.get(user_id)
    if old_client:
        try:
            if old_client.is_connected:
                await old_client.disconnect()
        except Exception:
            pass

    new_client = Client(
        f"user_{uid}",
        session_string=data["session"],
        api_id=data["api_id"],
        api_hash=data["api_hash"],
        proxy=proxy_arg,
        in_memory=True,
        sleep_threshold=60
    )
    try:
        await new_client.connect()
        try:
            new_client.me = await new_client.get_me()
        except Exception:
            pass
        user_clients[user_id] = new_client
        target_name = active_px["label"] if active_px else "Direct (No Proxy)"
        logger.info(f"User {user_id} switched proxy to {target_name}")
        return True, f"Connected via {target_name}"
    except Exception as e:
        logger.warning(f"Proxy connection failed for user {user_id} ({e}), falling back to direct connection")
        try:
            fallback = Client(
                f"user_{uid}",
                session_string=data["session"],
                api_id=data["api_id"],
                api_hash=data["api_hash"],
                proxy=None,
                in_memory=True,
                sleep_threshold=60
            )
            await fallback.connect()
            try:
                fallback.me = await fallback.get_me()
            except Exception:
                pass
            user_clients[user_id] = fallback
            DB[uid]["active_proxy_id"] = None
            save_db(DB)
            return False, f"Proxy connection failed ({e}). Reverted to Direct connection."
        except Exception as ex2:
            return False, f"Reconnection error: {ex2}"

# Initialize SQLite tables on startup
init_dedup_db()
init_stats_db()


# Multi-Layer Rate Limiting & Client Lifecycle

class ChatRateLimiter:
    """Enforces minimum interval between posts to the same chat (Telegram 1 msg/sec threshold)."""
    def __init__(self, min_interval=1.1):
        self.min_interval = min_interval
        self._last_call = {}
        self._lock = asyncio.Lock()

    async def acquire(self, chat_id):
        async with self._lock:
            now = time.time()
            last = self._last_call.get(chat_id, 0)
            elapsed = now - last
            if elapsed < self.min_interval:
                wait_time = self.min_interval - elapsed
                await asyncio.sleep(wait_time)
            self._last_call[chat_id] = time.time()

    wait_for_slot = acquire

chat_limiter = ChatRateLimiter(min_interval=1.1)

async def get_or_restore_user_client(user_id):
    """
    Retrieve active Pyrogram client or reconnect on-demand using the persisted session.
    Avoids requiring user re-authentication after service restarts or network blips.
    """
    if user_id in user_clients:
        c = user_clients[user_id]
        if getattr(c, "is_connected", False):
            return c
        try:
            await c.connect()
            return c
        except Exception:
            pass

    uid_str = str(user_id)
    if uid_str in DB and DB[uid_str].get("session"):
        data = DB[uid_str]
        try:
            active_px = get_user_active_proxy(user_id)
            proxy_arg = build_pyrogram_proxy(active_px)

            c = Client(
                f"user_{user_id}",
                session_string=data["session"],
                api_id=data["api_id"],
                api_hash=data["api_hash"],
                proxy=proxy_arg,
                in_memory=True,
                sleep_threshold=60
            )
            try:
                await c.connect()
            except Exception as pe:
                if proxy_arg:
                    logger.warning(f"Proxy failed for user {user_id}, falling back to direct connection...")
                    c = Client(
                        f"user_{user_id}",
                        session_string=data["session"],
                        api_id=data["api_id"],
                        api_hash=data["api_hash"],
                        proxy=None,
                        in_memory=True,
                        sleep_threshold=60
                    )
                    await c.connect()
                    DB[uid_str]["active_proxy_id"] = None
                    save_db(DB)
                else:
                    raise pe

            try:
                c.me = await c.get_me()
            except Exception:
                pass

            user_clients[user_id] = c
            logger.info(f"Reconnected session for user {user_id}")
            return c
        except Exception as e:
            logger.error(f"Could not reconnect session for user {user_id}: {e}")
            return None
    return None

async def init_saved_clients():
    """
    Initializes all saved user sessions on startup with network retry backoff.
    Guarantees session recovery even if VPS network interface takes seconds to initialize.
    """
    for uid_str, data in DB.items():
        try:
            uid = int(uid_str)
            if "session" not in data or not data.get("session"):
                logger.debug(f"No session string stored for user {uid}")
                continue

            active_px = get_user_active_proxy(uid)
            proxy_arg = build_pyrogram_proxy(active_px)

            c = Client(
                f"user_{uid}",
                session_string=data["session"],
                api_id=data["api_id"],
                api_hash=data["api_hash"],
                proxy=proxy_arg,
                in_memory=True,
                sleep_threshold=60
            )

            # Up to 3 connection attempts with backoff in case VPS network is still coming up
            connected = False
            for attempt in range(3):
                try:
                    await c.connect()
                    connected = True
                    break
                except Exception as ce:
                    if attempt < 2:
                        logger.warning(f"Network not ready on boot for user {uid} (attempt {attempt+1}/3: {ce}), retrying in 2.5s...")
                        await asyncio.sleep(2.5)
                    else:
                        raise ce

            if connected:
                user_clients[uid] = c
                px_name = active_px['label'] if active_px else 'Direct'
                logger.info(f"Loaded session for user {uid} (Proxy: {px_name})")
                try:
                    c.me = await c.get_me()
                except Exception:
                    pass

        except Exception as pe:
            if "proxy_arg" in locals() and proxy_arg:
                logger.warning(f"Proxy failed for user {uid_str} ({pe}), trying direct connection...")
                try:
                    fallback = Client(
                        f"user_{uid}",
                        session_string=data["session"],
                        api_id=data["api_id"],
                        api_hash=data["api_hash"],
                        proxy=None,
                        in_memory=True,
                        sleep_threshold=60
                    )
                    await fallback.connect()
                    user_clients[uid] = fallback
                    try:
                        fallback.me = await fallback.get_me()
                    except Exception:
                        pass
                    DB[uid_str]["active_proxy_id"] = None
                    save_db(DB)
                    logger.info(f"Fallback to direct connection successful for user {uid}")
                except Exception as ex2:
                    logger.error(f"Direct fallback also failed for user {uid_str}: {ex2}")
            else:
                logger.error(f"Session restore failed for user {uid_str}: {pe}")

# Input Parsing & Content Transformation Utilities

def parse_input(text):
    text = text.strip()
    if 't.me/+' in text or 't.me/joinchat/' in text:
        return 'INVITE_LINK', text
    m = re.search(r't\.me/c/(\d+)', text)
    if m:
        return 'CHAT_ID', int('-100' + m.group(1))
    m = re.search(r't\.me/([a-zA-Z0-9_]+)', text)
    if m and m.group(1) not in ('c', 'joinchat'):
        return 'USERNAME', m.group(1)
    if text.startswith('@'):
        return 'USERNAME', text[1:]
    if re.match(r'^-?\d+$', text):
        return 'CHAT_ID', int(text)
    return 'SEARCH_QUERY', text

def parse_id_range(text):
    text = text.strip()
    m = re.match(r'^(\d+)\s*(?:->|-|to)\s*(\d+)$', text, re.IGNORECASE)
    if m:
        min_id, max_id = int(m.group(1)), int(m.group(2))
        if min_id > max_id:
            min_id, max_id = max_id, min_id
        return min_id, max_id
    if re.match(r'^\d+$', text):
        mid = int(text)
        return mid, mid
    return None

def parse_date_range(text):
    text = text.strip()
    parts = re.split(r'\s*(?:->|to)\s*', text, flags=re.IGNORECASE)
    try:
        if len(parts) == 2:
            d1 = datetime.strptime(parts[0].strip(), '%Y-%m-%d')
            d2 = datetime.strptime(parts[1].strip(), '%Y-%m-%d')
            if d1 > d2:
                d1, d2 = d2, d1
            d2 = d2.replace(hour=23, minute=59, second=59)
            return d1, d2
        elif len(parts) == 1:
            d1 = datetime.strptime(parts[0].strip(), '%Y-%m-%d')
            d2 = datetime.now()
            return d1, d2
    except Exception:
        return None
    return None

def has_caption_modifications(settings):
    """Returns True if any caption or text transformation rule is active."""
    if not settings:
        return False
    if settings.get("strip_caption", False):
        return True
    if settings.get("extract_text", False) or settings.get("content_type") == "text_extract":
        return True
    if settings.get("clean_links", False):
        return True
    if settings.get("clean_mentions", False):
        return True
    if settings.get("clean_hashtags", False):
        return True
    if settings.get("find_replace_rules"):
        return True
    if settings.get("header"):
        return True
    if settings.get("footer") or settings.get("signature"):
        return True
    return False

def process_caption_and_text(raw_text, settings=None, src_title="", is_media=False):
    """
    Applies text transformation pipeline:
    1. Strip all text check (if is_media and strip_caption) -> returns ""
    2. Sequential Find & Replace rules
    3. Auto-cleaning (links, mentions, hashtags)
    4. Header & Footer templates ({channel} replacement & length safety limit)
    """
    if not settings:
        settings = {}

    if is_media and settings.get("strip_caption", False):
        # Strip original caption, but preserve custom header/footer templates if configured!
        header = (settings.get("header") or "").replace("{channel}", src_title).strip()
        footer = (settings.get("footer") or settings.get("signature") or "").replace("{channel}", src_title).strip()
        parts = [p for p in [header, footer] if p]
        return "\n\n".join(parts)

    text = raw_text or ""

    # 2. Sequential Find & Replace rules
    rules = settings.get("find_replace_rules") or []
    for r in rules:
        find_val = r.get("find", "")
        if not find_val:
            continue
        repl_val = r.get("replace", "")
        try:
            pattern = re.compile(re.escape(find_val), re.IGNORECASE)
            text = pattern.sub(repl_val, text)
        except Exception:
            text = text.replace(find_val, repl_val)

    # 3. Auto-cleaning
    if settings.get("clean_links", False):
        text = re.sub(r'(?:https?://|www\.|t\.me/)[^\s]+', '', text)
    if settings.get("clean_mentions", False):
        text = re.sub(r'@[a-zA-Z0-9_]+', '', text)
    if settings.get("clean_hashtags", False):
        text = re.sub(r'#[a-zA-Z0-9_\u0600-\u06FF]+', '', text)

    # Normalize whitespace & excess blank lines
    text = re.sub(r'[ \t]+', ' ', text)
    lines = [l.strip() for l in text.splitlines()]
    text = "\n".join(lines)
    text = re.sub(r'\n{3,}', '\n\n', text).strip()

    # 4. Prepend Header & Append Footer / Signature
    header = settings.get("header")
    footer = settings.get("footer") or settings.get("signature")

    if header:
        header = header.replace("{channel}", src_title).strip()
    if footer:
        footer = footer.replace("{channel}", src_title).strip()

    max_len = 1024 if is_media else 4096

    parts = []
    if header:
        parts.append(header)
    if text:
        parts.append(text)
    if footer:
        parts.append(footer)

    final_text = "\n\n".join(parts).strip()

    # Length safety check & middle truncation preserving Header & Footer
    if len(final_text) > max_len:
        h_len = (len(header) + 2) if header else 0
        f_len = (len(footer) + 2) if footer else 0
        avail = max_len - h_len - f_len - 3
        if avail > 10 and text:
            text = text[:avail].rstrip() + "..."
            parts = []
            if header:
                parts.append(header)
            if text:
                parts.append(text)
            if footer:
                parts.append(footer)
            final_text = "\n\n".join(parts).strip()
        else:
            final_text = final_text[:max_len]

    return final_text



async def resolve_chat(u_client, target_type, target_val):
    try:
        if target_type == 'INVITE_LINK':
            try:
                chat = await u_client.join_chat(target_val)
                title = chat.title or "Private Channel"
                return chat.id, title
            except Exception:
                chat = await u_client.get_chat(target_val)
                title = chat.title or "Private Channel"
                return chat.id, title
        else:
            chat = await u_client.get_chat(target_val)
            title = chat.title or chat.first_name or "Unknown Chat"
            return chat.id, title
    except Exception as e:
        return None, str(e)

def get_user_range_config(user_id):
    if user_id not in user_auth_data:
        user_auth_data[user_id] = {}
    if "range_config" not in user_auth_data[user_id]:
        user_auth_data[user_id]["range_config"] = {
            "type": "all",
            "label": "All messages (Full History)"
        }
    return user_auth_data[user_id]["range_config"]

def set_user_range_config(user_id, rtype, val=None, label=None, extra=None):
    if user_id not in user_auth_data:
        user_auth_data[user_id] = {}
    cfg = {"type": rtype, "label": label or rtype}
    if val is not None:
        cfg["value"] = val
    if extra:
        cfg.update(extra)
    user_auth_data[user_id]["range_config"] = cfg

def get_user_copy_settings(user_id):
    if user_id not in user_auth_data:
        user_auth_data[user_id] = {}
    if "copy_settings" not in user_auth_data[user_id]:
        user_auth_data[user_id]["copy_settings"] = {}

    settings = user_auth_data[user_id]["copy_settings"]
    settings.setdefault("content_type", "all")
    settings.setdefault("skip_service", True)
    settings.setdefault("skip_forwarded", False)
    settings.setdefault("skip_duplicates", False)
    settings.setdefault("drop_forward_tag", True)   # True: remove 'Forwarded from' attribution header
    settings.setdefault("strip_caption", False)     # Strip media captions
    settings.setdefault("extract_text", False)      # Post captions as standalone text (skip media files)
    settings.setdefault("clean_links", False)       # Strip URLs and web links
    settings.setdefault("clean_mentions", False)    # Strip @usernames
    settings.setdefault("clean_hashtags", False)    # Strip #hashtags
    settings.setdefault("find_replace_rules", [])   # Ordered list of find-and-replace rules
    settings.setdefault("header", None)             # Header template to prepend
    settings.setdefault("footer", None)             # Footer template to append
    settings.setdefault("signature", None)
    if settings.get("signature") and not settings.get("footer"):
        settings["footer"] = settings["signature"]
    return settings

# Cache user dialogs for fast pagination & search
async def refresh_user_dialogs(user_id):
    if user_id not in user_clients:
        return []
    u_client = user_clients[user_id]
    dialogs = []
    dialogs.append({
        "id": "me",
        "title": "Saved Messages 🔖",
        "raw_title": "Saved Messages",
        "username": "",
        "type": "personal"
    })
    try:
        me = getattr(u_client, "me", None)
        if not me:
            try:
                me = await u_client.get_me()
                u_client.me = me
            except Exception:
                me = None
        my_id = me.id if me else None

        async for d in u_client.get_dialogs(limit=250):
            if my_id and d.chat.id == my_id:
                continue
            title = d.chat.title or d.chat.first_name or "Unknown Chat"
            chat_type = str(d.chat.type).split('.')[-1].lower()
            icon = "📢" if "channel" in chat_type else "👥" if "group" in chat_type else "👤"
            username = getattr(d.chat, "username", "") or ""
            dialogs.append({
                "id": d.chat.id,
                "title": f"{icon} {title[:25]}",
                "raw_title": title,
                "username": username,
                "type": chat_type
            })
    except Exception as e:
        logger.error(f"Dialog fetch error for user {user_id}: {e}")
    user_dialog_cache[user_id] = dialogs
    user_dialog_last_fetch[user_id] = time.time()
    return dialogs

# Build paginated dialog keyboard with search & refresh support
def build_dialog_keyboard(user_id, mode, page=0, query=None):
    all_dialogs = user_dialog_cache.get(user_id, [])
    if query:
        q = query.lower().strip()
        dialogs = [
            d for d in all_dialogs
            if q in d.get("raw_title", "").lower()
            or q in d.get("title", "").lower()
            or q in d.get("username", "").lower()
        ]
    else:
        dialogs = all_dialogs

    ITEMS_PER_PAGE = 6
    total_pages = max(1, (len(dialogs) + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE)
    page = max(0, min(page, total_pages - 1))

    start = page * ITEMS_PER_PAGE
    end = start + ITEMS_PER_PAGE
    page_items = dialogs[start:end]

    kb = InlineKeyboardMarkup()
    for item in page_items:
        kb.add(InlineKeyboardButton(item["title"], callback_data=f"sel_{mode}_{item['id']}"))

    if query and len(dialogs) == 0:
        kb.add(InlineKeyboardButton("⚠️ No chats matched this search", callback_data="noop"))

    nav_buttons = []
    if page > 0:
        nav_buttons.append(InlineKeyboardButton("◀️ Prev", callback_data=f"p_{mode}_{page - 1}"))
    else:
        nav_buttons.append(InlineKeyboardButton("⏹️", callback_data="noop"))

    nav_buttons.append(InlineKeyboardButton(f"📄 {page + 1}/{total_pages}", callback_data="noop"))

    if page < total_pages - 1:
        nav_buttons.append(InlineKeyboardButton("Next ▶️", callback_data=f"p_{mode}_{page + 1}"))
    else:
        nav_buttons.append(InlineKeyboardButton("⏹️", callback_data="noop"))

    kb.row(*nav_buttons)

    if query:
        kb.add(InlineKeyboardButton("❌ Clear Search / Show All", callback_data=f"clear_search_{mode}"))
    else:
        kb.row(
            InlineKeyboardButton("🔄 Refresh Chats", callback_data=f"refresh_{mode}"),
            InlineKeyboardButton("🔖 Saved Messages", callback_data=f"sel_{mode}_me")
        )

    if mode == "dst":
        kb.add(InlineKeyboardButton("🔙 Back to Source Selection", callback_data="flow_pick_src"))
    kb.add(InlineKeyboardButton("🏠 Back to Main Menu", callback_data="nav_home"))
    return kb, page, total_pages, len(dialogs)

# UI View Builders & Navigation Keyboards

async def send_dashboard(chat_id, user_id, message_id=None):
    if user_id not in user_clients:
        await get_or_restore_user_client(user_id)
    is_logged_in = user_id in user_clients
    kb = InlineKeyboardMarkup()

    if is_logged_in:
        u_client = user_clients[user_id]
        me = getattr(u_client, "me", None)
        if not me:
            try:
                me = await u_client.get_me()
                u_client.me = me
            except Exception:
                me = None

        if me:
            name = me.first_name or "Telegram User"
            username = f"@{me.username}" if me.username else "No username"
            phone = me.phone_number or "Hidden"
        else:
            name, username, phone = "Logged In", "", ""

        is_running = active_tasks.get(user_id, False)
        status_text = "🟢 Active Copying..." if is_running else "⚪ Idle / Ready"
        health_label, health_desc, health_color = get_account_health(user_id)

        active_px = get_user_active_proxy(user_id)
        if active_px:
            ping_str = f" ({active_px.get('ping_ms', -1)}ms)" if active_px.get("ping_ms", -1) > 0 else ""
            proxy_display = f"🟢 {active_px['label']}{ping_str}"
        else:
            proxy_display = "⚪ Direct (No Proxy)"

        text = (
            "🤖 <b>Telegram Channel Copier — Dashboard</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"👤 <b>Account:</b> {name} ({username})\n"
            f"📱 <b>Phone:</b> +{phone}\n"
            f"🛡️ <b>Account Health:</b> {health_label}\n"
            f"📊 <b>Task Status:</b> {status_text}\n"
            f"🌐 <b>Proxy:</b> {proxy_display}\n"
            f"⚡ <b>Engine:</b> 100× MTProto / Dynamic Safety Limiter\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "Choose an option below to start:"
        )

        cp = get_checkpoint(user_id)
        if cp and not is_running:
            pct = round((cp['copied_count'] / max(cp['total'], 1)) * 100, 1)
            text += (
                "\n\n⚠️ <b>Unfinished Copy Job Detected!</b>\n"
                f"🔹 <b>From:</b> {cp['src_title']}\n"
                f"🔸 <b>To:</b> {cp['dst_title']}\n"
                f"📊 <b>Progress:</b> <b>{cp['copied_count']}/{cp['total']}</b> messages ({pct}%)\n"
                "Tap <b>Resume Copying</b> to continue from where you stopped:"
            )
            kb.add(InlineKeyboardButton(f"▶️ Resume Copying ({cp['copied_count']}/{cp['total']})", callback_data="resume_checkpoint"))
            kb.add(InlineKeyboardButton("🗑️ Discard Saved Checkpoint", callback_data="discard_checkpoint"))

        kb.add(InlineKeyboardButton("🚀 Start New Copy", callback_data="flow_pick_src"))
        if is_running:
            kb.add(InlineKeyboardButton("📊 View Active Task Progress", callback_data="view_task"))
        kb.row(
            InlineKeyboardButton("📊 My Analytics", callback_data="nav_analytics"),
            InlineKeyboardButton("🌐 Proxy Settings", callback_data="nav_proxy")
        )
        kb.row(
            InlineKeyboardButton("❓ Help & Guide", callback_data="nav_help"),
            InlineKeyboardButton("🚪 Logout", callback_data="nav_logout")
        )
    else:
        text = (
            "🤖 <b>Telegram Channel Copier v2.0</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "⚡ <b>Ultra-Fast 100× MTProto Batching Engine</b>\n"
            "🛡️ <b>Built-in Anti-Ban Safeguards</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "👋 Welcome! Please log in with your Telegram account to start copying channels and groups."
        )
        kb.add(InlineKeyboardButton("🔐 Login with Telegram", callback_data="start_login"))
        kb.add(InlineKeyboardButton("❓ Help & Instructions", callback_data="nav_help"))

    if message_id:
        try:
            await bot.edit_message_text(text, chat_id, message_id, reply_markup=kb, parse_mode="HTML")
            return
        except Exception:
            pass
    await bot.send_message(chat_id, text, reply_markup=kb, parse_mode="HTML")

# Range selection menu
async def show_range_selection(chat_id, user_id, message_id=None):
    user_states[user_id] = "PICK_RANGE"
    data = user_auth_data.get(user_id, {})
    src_title = data.get("src_title", "Selected Source")
    dst_title = data.get("dst_title", "Selected Destination")
    current_range = get_user_range_config(user_id).get("label", "All messages")

    text = (
        "📊 <b>Step 3/5: Select Message Range</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔹 <b>Source:</b> {src_title}\n"
        f"🔸 <b>Destination:</b> {dst_title}\n\n"
        f"📌 <b>Current Selection:</b> <code>{current_range}</code>\n\n"
        "Choose how many messages to copy:"
    )

    kb = InlineKeyboardMarkup()
    kb.row(
        InlineKeyboardButton("📥 Last 100", callback_data="range_last_100"),
        InlineKeyboardButton("📥 Last 500", callback_data="range_last_500")
    )
    kb.row(
        InlineKeyboardButton("📥 Last 1,000", callback_data="range_last_1000"),
        InlineKeyboardButton("📚 All Messages", callback_data="range_all")
    )
    kb.row(
        InlineKeyboardButton("🔢 Custom Message ID", callback_data="range_custom_id"),
        InlineKeyboardButton("📅 Date Range", callback_data="range_custom_date")
    )
    kb.row(
        InlineKeyboardButton("⬅️ Back to Destination", callback_data="flow_pick_dst"),
        InlineKeyboardButton("❌ Cancel", callback_data="nav_home")
    )

    if message_id:
        try:
            return await bot.edit_message_text(text, chat_id, message_id, reply_markup=kb, parse_mode="HTML")
        except Exception:
            pass
    await bot.send_message(chat_id, text, reply_markup=kb, parse_mode="HTML")

# Advanced copy settings and filters menu
async def show_copy_settings(chat_id, user_id, message_id=None):
    user_states[user_id] = "CONFIG_SETTINGS"
    settings = get_user_copy_settings(user_id)
    range_cfg = get_user_range_config(user_id)
    ctype = settings.get("content_type", "all")
    ctype_label = CONTENT_TYPE_LABELS.get(ctype, "All Content")
    skip_fwd = settings.get("skip_forwarded", False)
    fwd_icon = "✅ YES (Skip)" if skip_fwd else "⬜ NO (Include)"
    skip_dup = settings.get("skip_duplicates", False)
    dup_icon = "✅ YES (Skip)" if skip_dup else "⬜ NO (Copy All)"
    dedup_count = get_user_dedup_count(user_id)

    drop_tag = settings.get("drop_forward_tag", True)
    tag_label = "🚫 Clean (No Forward Tag)" if drop_tag else "🏷️ Keep Forward Tag"

    mods_active = []
    if settings.get("strip_caption"):
        mods_active.append("🚫 Strip All")
    if settings.get("extract_text"):
        mods_active.append("📄 Extract Text Only")
    if settings.get("clean_links"):
        mods_active.append("🔗 Links Cleaned")
    if settings.get("clean_mentions"):
        mods_active.append("👤 Mentions Cleaned")
    if settings.get("clean_hashtags"):
        mods_active.append("#️⃣ Tags Cleaned")
    rules = settings.get("find_replace_rules", [])
    if rules:
        mods_active.append(f"🔄 {len(rules)} Replace Rules")
    if settings.get("header"):
        mods_active.append("🔝 Header")
    if settings.get("footer") or settings.get("signature"):
        mods_active.append("🔚 Footer")

    caption_summary = ", ".join(mods_active) if mods_active else "Original Captions (Keep)"

    text = (
        "⚙️ <b>Step 4/5: Advanced Filters & Options</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📊 <b>Range:</b> {range_cfg.get('label')}\n"
        f"📄 <b>Content Filter:</b> <b>{ctype_label}</b>\n"
        f"🏷️ <b>Forward Tag:</b> <b>{tag_label}</b>\n"
        f"📦 <b>Skip Forwarded:</b> {fwd_icon}\n"
        f"⚡ <b>Skip Duplicates:</b> {dup_icon} (<code>{dedup_count}</code> indexed)\n"
        f"📝 <b>Caption Rules:</b> <b>{caption_summary}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "Tap buttons below to toggle options, or tap <b>Continue</b>:"
    )

    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton(f"📄 Content Filter: {ctype_label}", callback_data="toggle_content_type"))
    kb.row(
        InlineKeyboardButton(f"🏷️ Tag: {'Clean' if drop_tag else 'Keep Tag'}", callback_data="toggle_drop_fwd_tag"),
        InlineKeyboardButton(f"📦 Skip Fwd: {fwd_icon}", callback_data="toggle_skip_fwd")
    )
    kb.row(
        InlineKeyboardButton(f"⚡ Skip Dup: {dup_icon}", callback_data="toggle_skip_dup"),
        InlineKeyboardButton("📝 Caption & Text Rules ➔", callback_data="flow_caption_rules")
    )
    kb.add(InlineKeyboardButton("✅ Continue to Review ➔", callback_data="flow_confirm"))
    kb.row(
        InlineKeyboardButton("⬅️ Back to Range", callback_data="flow_pick_range"),
        InlineKeyboardButton("🔄 Reset Defaults", callback_data="reset_settings")
    )

    if message_id:
        try:
            return await bot.edit_message_text(text, chat_id, message_id, reply_markup=kb, parse_mode="HTML")
        except Exception:
            pass
    await bot.send_message(chat_id, text, reply_markup=kb, parse_mode="HTML")

# Caption and text customization sub-menu
async def show_caption_menu(chat_id, user_id, message_id=None):
    user_states[user_id] = "CONFIG_CAPTIONS"
    settings = get_user_copy_settings(user_id)

    strip_cap = settings.get("strip_caption", False)
    strip_icon = "✅ ON (Stripped)" if strip_cap else "⬜ OFF (Kept)"

    extract_txt = settings.get("extract_text", False) or settings.get("content_type") == "text_extract"
    extract_icon = "✅ ON (Text Only)" if extract_txt else "⬜ OFF"

    c_links = settings.get("clean_links", False)
    c_links_icon = "✅ Remove" if c_links else "⬜ Keep"

    c_mentions = settings.get("clean_mentions", False)
    c_mentions_icon = "✅ Remove" if c_mentions else "⬜ Keep"

    c_tags = settings.get("clean_hashtags", False)
    c_tags_icon = "✅ Remove" if c_tags else "⬜ Keep"

    rules = settings.get("find_replace_rules", [])
    header = settings.get("header")
    footer = settings.get("footer") or settings.get("signature")

    header_disp = f"<code>{header[:25]}...</code>" if header else "None (Off)"
    footer_disp = f"<code>{footer[:25]}...</code>" if footer else "None (Off)"

    text = (
        "📝 <b>Caption & Text Customization (Category 1)</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🚫 <b>Strip All Captions:</b> {strip_icon}\n"
        f"   <i>(Media is copied with zero caption/text)</i>\n\n"
        f"📄 <b>Extract Text Only:</b> {extract_icon}\n"
        f"   <i>(Extracts captions from media as text without downloading files)</i>\n\n"
        "🧹 <b>Auto-Clean Spam:</b>\n"
        f"   • Links / URLs: <b>{c_links_icon}</b>\n"
        f"   • @Mentions: <b>{c_mentions_icon}</b>\n"
        f"   • #Hashtags: <b>{c_tags_icon}</b>\n\n"
        f"🔄 <b>Find & Replace:</b> <b>{len(rules)}</b> active rule(s)\n"
        f"🔝 <b>Header (Top):</b> {header_disp}\n"
        f"🔚 <b>Footer (Bottom):</b> {footer_disp}\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "Tap buttons to configure your rules:"
    )

    kb = InlineKeyboardMarkup()
    kb.row(
        InlineKeyboardButton(f"🚫 Strip Captions: {strip_icon}", callback_data="toggle_strip_caption"),
        InlineKeyboardButton(f"📄 Extract Text: {extract_icon}", callback_data="toggle_extract_text")
    )
    kb.row(
        InlineKeyboardButton(f"🔗 Links: {c_links_icon}", callback_data="toggle_clean_links"),
        InlineKeyboardButton(f"👤 Mentions: {c_mentions_icon}", callback_data="toggle_clean_mentions"),
        InlineKeyboardButton(f"#️⃣ Tags: {c_tags_icon}", callback_data="toggle_clean_hashtags")
    )
    kb.add(InlineKeyboardButton(f"🔄 Find & Replace Rules ({len(rules)}) ➔", callback_data="menu_find_replace"))
    kb.row(
        InlineKeyboardButton("🔝 Set Header", callback_data="btn_set_header"),
        InlineKeyboardButton("🔚 Set Footer", callback_data="btn_set_footer")
    )
    if header or footer:
        kb.row(
            InlineKeyboardButton("🗑️ Clear Header", callback_data="btn_clear_header"),
            InlineKeyboardButton("🗑️ Clear Footer", callback_data="btn_clear_footer")
        )
    kb.row(
        InlineKeyboardButton("⬅️ Back to Settings", callback_data="flow_settings"),
        InlineKeyboardButton("🔄 Reset Caption Rules", callback_data="reset_caption_rules")
    )

    if message_id:
        try:
            return await bot.edit_message_text(text, chat_id, message_id, reply_markup=kb, parse_mode="HTML")
        except Exception:
            pass
    await bot.send_message(chat_id, text, reply_markup=kb, parse_mode="HTML")

# Sub-menu: Find & Replace Rules Screen
async def show_find_replace_menu(chat_id, user_id, message_id=None):
    user_states[user_id] = "CONFIG_FIND_REPLACE"
    settings = get_user_copy_settings(user_id)
    rules = settings.get("find_replace_rules", [])

    if rules:
        rule_lines = []
        for idx, r in enumerate(rules, 1):
            find_txt = r.get("find", "")
            repl_txt = r.get("replace", "")
            repl_disp = f"<code>{repl_txt}</code>" if repl_txt else "<i>[DELETED]</i>"
            rule_lines.append(f"{idx}. <code>{find_txt}</code> ➔ {repl_disp}")
        rules_str = "\n".join(rule_lines)
    else:
        rules_str = "<i>No replacement rules active yet.</i>"

    text = (
        "🔄 <b>Find & Replace Rules in Captions</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "Rules are applied sequentially to captions and messages:\n\n"
        f"{rules_str}\n\n"
        "💡 <b>Tip:</b> Leave replacement blank to remove unwanted words or spam links.\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )

    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("➕ Add New Replacement Rule", callback_data="btn_add_find_replace"))
    if rules:
        kb.add(InlineKeyboardButton("🗑️ Clear All Rules", callback_data="btn_clear_find_replace"))
    kb.add(InlineKeyboardButton("⬅️ Back to Caption Rules", callback_data="flow_caption_rules"))

    if message_id:
        try:
            return await bot.edit_message_text(text, chat_id, message_id, reply_markup=kb, parse_mode="HTML")
        except Exception:
            pass
    await bot.send_message(chat_id, text, reply_markup=kb, parse_mode="HTML")

# Final review and confirmation menu
async def show_confirmation(chat_id, user_id, message_id=None):
    user_states[user_id] = "CONFIRM"
    data = user_auth_data.get(user_id, {})
    src_title = data.get("src_title", "Unknown")
    dst_title = data.get("dst_title", "Unknown")
    src_id = data.get("source", "Unknown")
    dst_id = data.get("dest", "Unknown")
    range_cfg = get_user_range_config(user_id)
    settings = get_user_copy_settings(user_id)

    ctype = settings.get("content_type", "all")
    ctype_label = CONTENT_TYPE_LABELS.get(ctype, "All Content")
    skip_fwd = "✅ Yes" if settings.get("skip_forwarded") else "⬜ No"
    skip_dup = "✅ Yes (dedup.db)" if settings.get("skip_duplicates") else "⬜ No"
    drop_tag = settings.get("drop_forward_tag", True)
    tag_label = "🚫 Clean (No Forward Tag)" if drop_tag else "🏷️ Keep Forward Tag"

    cap_details = []
    if settings.get("strip_caption"):
        cap_details.append("🚫 Strip All Captions (Raw Media Only)")
    if settings.get("extract_text"):
        cap_details.append("📄 Extract Captions as Text (Skip Media)")
    if settings.get("clean_links"):
        cap_details.append("🔗 Links Removed")
    if settings.get("clean_mentions"):
        cap_details.append("👤 @Mentions Removed")
    if settings.get("clean_hashtags"):
        cap_details.append("#️⃣ #Hashtags Removed")
    rules = settings.get("find_replace_rules", [])
    if rules:
        cap_details.append(f"🔄 {len(rules)} Find/Replace rule(s)")
    if settings.get("header"):
        cap_details.append("🔝 Header Template Active")
    if settings.get("footer") or settings.get("signature"):
        cap_details.append("🔚 Footer Template Active")

    cap_display = "\n   • " + "\n   • ".join(cap_details) if cap_details else "Original Captions Kept"

    text = (
        "📋 <b>Step 5/5: Final Review & Confirmation</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔹 <b>FROM (Source):</b> {src_title}\n"
        f"   └ <code>{src_id}</code>\n\n"
        f"🔸 <b>TO (Destination):</b> {dst_title}\n"
        f"   └ <code>{dst_id}</code>\n\n"
        f"📊 <b>Range:</b> {range_cfg.get('label')}\n"
        f"📄 <b>Content Filter:</b> {ctype_label}\n"
        f"🏷️ <b>Forward Tag:</b> {tag_label}\n"
        f"📦 <b>Skip Forwarded:</b> {skip_fwd}\n"
        f"⚡ <b>Skip Duplicates:</b> {skip_dup}\n"
        f"📝 <b>Caption Rules:</b> {cap_display}\n"
        "⚡ <b>Engine:</b> 100× MTProto Batching / Caption Bypass (3x)\n"
        "🛡️ <b>Anti-Ban:</b> Tuned Delays & Auto-Breather Active\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "Ready to begin? Click <b>Confirm & Start Copying</b> below:"
    )

    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("▶️ Confirm & Start Copying", callback_data="confirm_copy"))
    kb.row(
        InlineKeyboardButton("📊 Range", callback_data="flow_pick_range"),
        InlineKeyboardButton("⚙️ Settings", callback_data="flow_settings"),
        InlineKeyboardButton("📝 Captions", callback_data="flow_caption_rules")
    )
    kb.add(InlineKeyboardButton("❌ Cancel Job", callback_data="nav_home"))

    if message_id:
        try:
            return await bot.edit_message_text(text, chat_id, message_id, reply_markup=kb, parse_mode="HTML")
        except Exception:
            pass
    await bot.send_message(chat_id, text, reply_markup=kb, parse_mode="HTML")


# Analytics Views & Proxy Interface

async def show_analytics(chat_id, user_id, message_id=None):
    summary = get_user_analytics_summary(user_id)
    dedup_count = get_user_dedup_count(user_id)

    mins = int(summary["total_duration"] // 60)
    secs = int(summary["total_duration"] % 60)
    duration_fmt = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"

    text = (
        "📊 <b>Live Analytics Dashboard</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"👤 <b>User ID:</b> <code>{user_id}</code>\n\n"
        "📈 <b>All-Time Performance:</b>\n"
        f"• Messages Copied: <b>{summary['total_copied']:,}</b>\n"
        f"• Total Jobs Run: <b>{summary['total_jobs']}</b>\n"
        f"• Success Rate: <b>{summary['success_rate']}%</b>\n"
        f"• Average Speed: <b>{summary['avg_speed']} msg/s</b>\n"
        f"• Total Duration: <b>{duration_fmt}</b>\n\n"
        "📅 <b>Today's Activity:</b>\n"
        f"• Messages Copied: <b>{summary['today_copied']:,}</b>\n"
        f"• Jobs Completed: <b>{summary['today_jobs']}</b>\n\n"
        "🛡️ <b>Deduplication Engine:</b>\n"
        f"• Unique Hashes Indexed: <b>{dedup_count:,}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )

    kb = InlineKeyboardMarkup()
    kb.row(
        InlineKeyboardButton("📈 7-Day Chart", callback_data="analytics_chart"),
        InlineKeyboardButton("🕒 Recent 5 Jobs", callback_data="analytics_recent")
    )
    if dedup_count > 0:
        kb.add(InlineKeyboardButton("🧹 Clear Dedup Cache", callback_data="dedup_clear_prompt"))
    kb.add(InlineKeyboardButton("🏠 Back to Dashboard", callback_data="nav_home"))

    if message_id:
        try:
            return await bot.edit_message_text(text, chat_id, message_id, reply_markup=kb, parse_mode="HTML")
        except Exception:
            pass
    await bot.send_message(chat_id, text, reply_markup=kb, parse_mode="HTML")

async def show_analytics_chart(chat_id, user_id, message_id=None):
    stats = get_user_7day_stats(user_id)
    total_7d = sum(c for _, c in stats)
    max_val = max([c for _, c in stats] + [1])

    lines = []
    for d_str, count in stats:
        bar_len = int((count / max_val) * 10) if max_val > 0 else 0
        bar = "▰" * bar_len + "▱" * (10 - bar_len)
        lines.append(f"<code>{d_str}</code> {bar} <b>{count:,}</b>")

    chart_body = "\n".join(lines)
    text = (
        "📈 <b>7-Day Activity Chart</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📊 <b>Total (Last 7 Days):</b> <b>{total_7d:,} messages</b>\n\n"
        f"{chart_body}\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "<i>Proportional bars indicate daily volume.</i>"
    )

    kb = InlineKeyboardMarkup()
    kb.row(
        InlineKeyboardButton("⬅️ Back to Analytics", callback_data="nav_analytics"),
        InlineKeyboardButton("🏠 Home", callback_data="nav_home")
    )

    if message_id:
        try:
            return await bot.edit_message_text(text, chat_id, message_id, reply_markup=kb, parse_mode="HTML")
        except Exception:
            pass
    await bot.send_message(chat_id, text, reply_markup=kb, parse_mode="HTML")

async def show_analytics_recent(chat_id, user_id, message_id=None):
    jobs = get_user_recent_jobs(user_id, 5)
    if not jobs:
        recent_text = "<i>No copy jobs recorded yet.</i>"
    else:
        items = []
        for i, job in enumerate(jobs, 1):
            src_t, dst_t, total_cnt, copied_cnt, dup_cnt, fail_cnt, dur, spd, created = job
            pct = round((copied_cnt / max(total_cnt, 1)) * 100, 1) if total_cnt > 0 else 100
            dt_str = datetime.fromtimestamp(created).strftime("%m/%d %H:%M")
            items.append(
                f"<b>{i}. {src_t[:15]} ➔ {dst_t[:15]}</b>\n"
                f"   └ Copied: <b>{copied_cnt}/{total_cnt}</b> ({pct}%) | ⚡ {spd} msg/s\n"
                f"   └ Dups: {dup_cnt} | Time: {dur:.1f}s | {dt_str}"
            )
        recent_text = "\n\n".join(items)

    text = (
        "🕒 <b>Recent Copy Jobs (Last 5)</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"{recent_text}\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )

    kb = InlineKeyboardMarkup()
    if jobs:
        kb.add(InlineKeyboardButton("🗑️ Clear Job History", callback_data="analytics_clear_prompt"))
    kb.row(
        InlineKeyboardButton("⬅️ Back to Analytics", callback_data="nav_analytics"),
        InlineKeyboardButton("🏠 Home", callback_data="nav_home")
    )

    if message_id:
        try:
            return await bot.edit_message_text(text, chat_id, message_id, reply_markup=kb, parse_mode="HTML")
        except Exception:
            pass
    await bot.send_message(chat_id, text, reply_markup=kb, parse_mode="HTML")

async def show_proxy_menu(chat_id, user_id, message_id=None):
    proxies = get_user_proxies(user_id)
    active_px = get_user_active_proxy(user_id)
    active_id = DB.get(str(user_id), {}).get("active_proxy_id")

    if active_px:
        ping_str = f" ({active_px.get('ping_ms', -1)}ms)" if active_px.get("ping_ms", -1) > 0 else ""
        current_status = f"🟢 <b>{active_px['label']}</b>{ping_str}"
    else:
        current_status = "⚪ <b>Direct Connection</b> (No Proxy)"

    text = (
        "🌐 <b>Proxy Configuration & Hot-Swap</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🛡️ <b>Current Mode:</b> {current_status}\n"
        f"📦 <b>Saved Proxies:</b> {len(proxies)}/5\n\n"
        "Use proxies to bypass Telegram geo-restrictions, prevent IP bans, and stabilize downloads."
    )

    kb = InlineKeyboardMarkup()
    if proxies:
        for px in proxies:
            pid = px["id"]
            is_act = (pid == active_id)
            act_mark = "✅ " if is_act else "⚡ "
            ping_val = px.get("ping_ms", -1)
            ping_txt = f"{ping_val}ms" if ping_val > 0 else "N/A"

            btn_label = f"{act_mark}{px['label'][:20]}"
            kb.row(
                InlineKeyboardButton(btn_label, callback_data=f"proxy_use_{pid}"),
                InlineKeyboardButton(f"📶 {ping_txt}", callback_data=f"proxy_ping_{pid}"),
                InlineKeyboardButton("🗑️", callback_data=f"proxy_del_{pid}")
            )
        if active_id:
            kb.add(InlineKeyboardButton("🔌 Switch to Direct Connection (No Proxy)", callback_data="proxy_use_direct"))
    else:
        text += "\n\n<i>No proxies added yet. Tap 'Add New Proxy' below to add one.</i>"

    if len(proxies) < 5:
        kb.add(InlineKeyboardButton("➕ Add New Proxy", callback_data="proxy_add"))
    kb.add(InlineKeyboardButton("🏠 Back to Dashboard", callback_data="nav_home"))

    if message_id:
        try:
            return await bot.edit_message_text(text, chat_id, message_id, reply_markup=kb, parse_mode="HTML")
        except Exception:
            pass
    await bot.send_message(chat_id, text, reply_markup=kb, parse_mode="HTML")

# Bot Command Handlers (/start, /help, /logout)

@bot.message_handler(commands=['start'])
async def start_cmd(message):
    user_id = message.from_user.id
    user_states[user_id] = None
    user_active_query[user_id] = None
    await send_dashboard(message.chat.id, user_id)

@bot.message_handler(commands=['help'])
async def help_cmd(message):
    await show_help(message.chat.id)

@bot.message_handler(commands=['logout'])
async def logout_cmd(message):
    await perform_logout(message.chat.id, message.from_user.id)

async def show_help(chat_id, message_id=None):
    help_text = (
        "🤖 <b>Channel Copier Bot — User Guide</b>\n\n"
        "This bot copies messages from any channel/group to another with <b>100× MTProto Batching</b>.\n\n"
        "<b>📌 New Features Added:</b>\n"
        "1. <b>📊 Message Range Selector:</b> Copy Last 100, 500, 1000, Custom ID, or Date ranges without scanning the entire channel.\n"
        "2. <b>📄 Content Type Filters:</b> Copy Videos only, Photos only, Documents only, or Text only.\n"
        "3. <b>✍️ Custom Signature:</b> Append your channel link/tag to all copied messages automatically (use <code>{channel}</code>).\n"
        "4. <b>⚡ Parallel Bypass:</b> Bypasses protected/restricted channels using 6 concurrent workers.\n"
        "5. <b>🔄 Refresh Button:</b> Instantly fetch newly joined channels.\n\n"
        "👨‍💻 <b>Developer:</b> @R3v_x"
    )
    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("🏠 Back to Dashboard", callback_data="nav_home"))

    if message_id:
        try:
            await bot.edit_message_text(help_text, chat_id, message_id, reply_markup=kb, parse_mode="HTML")
            return
        except Exception:
            pass
    await bot.send_message(chat_id, help_text, reply_markup=kb, parse_mode="HTML")

async def perform_logout(chat_id, user_id, message_id=None):
    if active_tasks.get(user_id, False):
        active_tasks[user_id] = False
        await asyncio.sleep(2.0)

    if user_id in user_clients:
        try:
            await user_clients[user_id].log_out()
        except Exception:
            pass
        del user_clients[user_id]

    if str(user_id) in DB:
        del DB[str(user_id)]
        save_db(DB)

    user_states[user_id] = None
    user_auth_data[user_id] = {}
    user_dialog_cache[user_id] = []
    user_active_query[user_id] = None
    active_tasks[user_id] = False

    msg = "🚪 <b>Logged Out Successfully.</b>\nYour session and credentials have been cleared."
    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("🔐 Login Again", callback_data="start_login"))

    if message_id:
        try:
            await bot.edit_message_text(msg, chat_id, message_id, reply_markup=kb, parse_mode="HTML")
            return
        except Exception:
            pass
    await bot.send_message(chat_id, msg, reply_markup=kb, parse_mode="HTML")

# Interactive Callback Query Handlers

@bot.callback_query_handler(func=lambda call: call.data == "noop")
async def noop_cb(call):
    await bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "nav_home")
async def nav_home_cb(call):
    user_id = call.from_user.id
    user_states[user_id] = None
    user_active_query[user_id] = None
    await send_dashboard(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "nav_help")
async def nav_help_cb(call):
    await show_help(call.message.chat.id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "nav_logout")
async def nav_logout_cb(call):
    await perform_logout(call.message.chat.id, call.from_user.id, call.message.message_id)

# Refresh Chats callback
@bot.callback_query_handler(func=lambda call: call.data in ("refresh_src", "refresh_dst"))
async def refresh_chats_cb(call):
    user_id = call.from_user.id
    mode = "src" if "src" in call.data else "dst"
    await bot.answer_callback_query(call.id, "🔄 Fetching latest chats from Telegram...")
    await refresh_user_dialogs(user_id)
    query = user_active_query.get(user_id)
    kb, page, total, count = build_dialog_keyboard(user_id, mode, page=0, query=query)
    step_title = "SOURCE (Copy FROM)" if mode == "src" else "DESTINATION (Copy TO)"
    text = (
        f"📍 <b>Select {step_title}</b> (✅ Chats Refreshed: {count} available)\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "Tap a chat below, <b>OR</b> simply type/paste in chat:\n"
        "• Channel Link: <code>https://t.me/...</code>\n"
        "• Username: <code>@channel_name</code>\n"
        "• Chat ID: <code>-100...</code>\n"
        "• Or <b>forward any message</b> from the channel here!"
    )
    try:
        await bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=kb, parse_mode="HTML")
    except Exception:
        pass

# Clear active search
@bot.callback_query_handler(func=lambda call: call.data in ("clear_search_src", "clear_search_dst"))
async def clear_search_cb(call):
    user_id = call.from_user.id
    mode = "src" if "src" in call.data else "dst"
    user_active_query[user_id] = None
    await bot.answer_callback_query(call.id, "Search cleared.")
    kb, page, total, count = build_dialog_keyboard(user_id, mode, page=0)
    step_title = "SOURCE (Copy FROM)" if mode == "src" else "DESTINATION (Copy TO)"
    text = (
        f"📍 <b>Select {step_title}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "Tap a chat below, <b>OR</b> simply type/paste in chat:\n"
        "• Channel Link: <code>https://t.me/...</code>\n"
        "• Username: <code>@channel_name</code>\n"
        "• Chat ID: <code>-100...</code>\n"
        "• Or <b>forward any message</b> from the channel here!"
    )
    try:
        await bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=kb, parse_mode="HTML")
    except Exception:
        pass

# Start source channel selection flow
@bot.callback_query_handler(func=lambda call: call.data == "flow_pick_src")
async def flow_pick_src_cb(call):
    user_id = call.from_user.id
    if user_id not in user_clients:
        return await bot.answer_callback_query(call.id, "Please login first!", show_alert=True)

    user_states[user_id] = "PICK_SRC"
    user_active_query[user_id] = None
    if user_id not in user_auth_data:
        user_auth_data[user_id] = {}

    await bot.answer_callback_query(call.id)

    now = time.time()
    cache_age = now - user_dialog_last_fetch.get(user_id, 0)
    if user_dialog_cache.get(user_id) and cache_age < 30:
        kb, page, total, count = build_dialog_keyboard(user_id, "src", page=0)
        text = (
            "📍 <b>Step 1/5: Select SOURCE Chat (Copy FROM)</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "Tap a chat below, <b>OR</b> simply type/paste in chat:\n"
            "• Search by Name: <code>movies</code>, <code>tech</code>, etc.\n"
            "• Channel Link: <code>https://t.me/...</code>\n"
            "• Username: <code>@channel_name</code>\n"
            "• Or <b>forward any message</b> from the source channel here!"
        )
        try:
            return await bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=kb, parse_mode="HTML")
        except Exception:
            return await bot.send_message(call.message.chat.id, text, reply_markup=kb, parse_mode="HTML")

    temp_kb = InlineKeyboardMarkup()
    temp_kb.add(InlineKeyboardButton("Saved Messages 🔖", callback_data="sel_src_me"))
    temp_kb.add(InlineKeyboardButton("🏠 Back to Main Menu", callback_data="nav_home"))
    loading_text = (
        "📍 <b>Step 1/5: Select SOURCE Chat</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "⏳ <i>Loading latest chats...</i>\n\n"
        "💡 <b>You can already type or paste:</b>\n"
        "• Search name: <code>movies</code>, <code>news</code>, etc.\n"
        "• Channel Link: <code>https://t.me/...</code>\n"
        "• Username: <code>@channel_name</code>\n"
        "• Or <b>forward any message</b> from the channel!"
    )
    try:
        await bot.edit_message_text(loading_text, call.message.chat.id, call.message.message_id, reply_markup=temp_kb, parse_mode="HTML")
    except Exception:
        pass

    await refresh_user_dialogs(user_id)
    kb, page, total, count = build_dialog_keyboard(user_id, "src", page=0)
    text = (
        "📍 <b>Step 1/5: Select SOURCE Chat (Copy FROM)</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "Tap a chat below, <b>OR</b> simply type/paste in chat:\n"
        "• Search by Name: <code>movies</code>, <code>tech</code>, etc.\n"
        "• Channel Link: <code>https://t.me/...</code>\n"
        "• Username: <code>@channel_name</code>\n"
        "• Or <b>forward any message</b> from the source channel here!"
    )
    try:
        await bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=kb, parse_mode="HTML")
    except Exception:
        await bot.send_message(call.message.chat.id, text, reply_markup=kb, parse_mode="HTML")

# Start destination channel selection flow
@bot.callback_query_handler(func=lambda call: call.data == "flow_pick_dst")
async def flow_pick_dst_cb(call):
    user_id = call.from_user.id
    if user_id not in user_clients:
        return await bot.answer_callback_query(call.id, "Please login first!", show_alert=True)

    user_states[user_id] = "PICK_DST"
    user_active_query[user_id] = None
    src_title = user_auth_data.get(user_id, {}).get("src_title", "Selected Source")

    await bot.answer_callback_query(call.id)

    now = time.time()
    cache_age = now - user_dialog_last_fetch.get(user_id, 0)
    if not user_dialog_cache.get(user_id) or cache_age > 30:
        await refresh_user_dialogs(user_id)

    kb, page, total, count = build_dialog_keyboard(user_id, "dst", page=0)
    text = (
        "📍 <b>Step 2/5: Select DESTINATION Chat (Copy TO)</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"Selected Source: <b>{src_title}</b>\n\n"
        "Tap a chat below, <b>OR</b> simply type/paste in chat:\n"
        "• Search by Name: <code>movies</code>, <code>backup</code>, etc.\n"
        "• Channel Link: <code>https://t.me/...</code>\n"
        "• Username: <code>@channel_name</code>\n"
        "• Or <b>forward any message</b> from the destination channel here!"
    )
    try:
        await bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=kb, parse_mode="HTML")
    except Exception:
        await bot.send_message(call.message.chat.id, text, reply_markup=kb, parse_mode="HTML")

# Pagination handler for dialog buttons
@bot.callback_query_handler(func=lambda call: call.data.startswith("p_"))
async def pagination_cb(call):
    user_id = call.from_user.id
    parts = call.data.split("_")
    mode = parts[1]
    page = int(parts[2])
    query = user_active_query.get(user_id)

    kb, page, total, count = build_dialog_keyboard(user_id, mode, page=page, query=query)
    try:
        await bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=kb)
    except Exception:
        pass
    await bot.answer_callback_query(call.id)

# Dialog selection: Source chosen via button
@bot.callback_query_handler(func=lambda call: call.data.startswith("sel_src_"))
async def sel_src_cb(call):
    user_id = call.from_user.id
    raw_id = call.data.replace("sel_src_", "")
    target = "me" if raw_id == "me" else int(raw_id)

    u_client = user_clients[user_id]
    chat_id, title = await resolve_chat(u_client, 'CHAT_ID', target)
    if not chat_id:
        return await bot.answer_callback_query(call.id, f"Error: {title}", show_alert=True)

    if user_id not in user_auth_data:
        user_auth_data[user_id] = {}
    user_auth_data[user_id]["source"] = chat_id
    user_auth_data[user_id]["src_title"] = title
    user_active_query[user_id] = None

    await bot.answer_callback_query(call.id, f"Source: {title[:20]}")
    await flow_pick_dst_cb(call)

# Dialog selection: Destination chosen via button
@bot.callback_query_handler(func=lambda call: call.data.startswith("sel_dst_"))
async def sel_dst_cb(call):
    user_id = call.from_user.id
    raw_id = call.data.replace("sel_dst_", "")
    target = "me" if raw_id == "me" else int(raw_id)

    u_client = user_clients[user_id]
    chat_id, title = await resolve_chat(u_client, 'CHAT_ID', target)
    if not chat_id:
        return await bot.answer_callback_query(call.id, f"Error: {title}", show_alert=True)

    user_auth_data[user_id]["dest"] = chat_id
    user_auth_data[user_id]["dst_title"] = title
    user_active_query[user_id] = None

    await bot.answer_callback_query(call.id, f"Destination: {title[:20]}")
    await show_range_selection(call.message.chat.id, user_id, call.message.message_id)

# Message Range Selection Callbacks

@bot.callback_query_handler(func=lambda call: call.data == "flow_pick_range")
async def flow_pick_range_cb(call):
    user_id = call.from_user.id
    await bot.answer_callback_query(call.id)
    await show_range_selection(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "range_last_100")
async def range_last_100_cb(call):
    user_id = call.from_user.id
    set_user_range_config(user_id, "last_n", val=100, label="Last 100 messages")
    await bot.answer_callback_query(call.id, "Range set: Last 100 messages")
    await show_copy_settings(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "range_last_500")
async def range_last_500_cb(call):
    user_id = call.from_user.id
    set_user_range_config(user_id, "last_n", val=500, label="Last 500 messages")
    await bot.answer_callback_query(call.id, "Range set: Last 500 messages")
    await show_copy_settings(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "range_last_1000")
async def range_last_1000_cb(call):
    user_id = call.from_user.id
    set_user_range_config(user_id, "last_n", val=1000, label="Last 1,000 messages")
    await bot.answer_callback_query(call.id, "Range set: Last 1,000 messages")
    await show_copy_settings(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "range_all")
async def range_all_cb(call):
    user_id = call.from_user.id
    set_user_range_config(user_id, "all", label="All messages (Full History)")
    await bot.answer_callback_query(call.id, "Range set: All messages")
    await show_copy_settings(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "range_custom_id")
async def range_custom_id_cb(call):
    user_id = call.from_user.id
    user_states[user_id] = "WAIT_CUSTOM_ID"
    await bot.answer_callback_query(call.id)

    kb = InlineKeyboardMarkup().add(InlineKeyboardButton("⬅️ Back to Range Options", callback_data="flow_pick_range"))
    text = (
        "🔢 <b>Custom Message ID Range</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "Send the message ID range in one of these formats:\n\n"
        "• Range: <code>100 -> 500</code> (or <code>100-500</code>)\n"
        "• Single Message ID: <code>250</code>\n\n"
        "Send your message ID input below:"
    )
    await bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=kb, parse_mode="HTML")

@bot.callback_query_handler(func=lambda call: call.data == "range_custom_date")
async def range_custom_date_cb(call):
    user_id = call.from_user.id
    user_states[user_id] = "WAIT_CUSTOM_DATE"
    await bot.answer_callback_query(call.id)

    kb = InlineKeyboardMarkup().add(InlineKeyboardButton("⬅️ Back to Range Options", callback_data="flow_pick_range"))
    text = (
        "📅 <b>Custom Date Range</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "Send date range in this format (YYYY-MM-DD):\n\n"
        "• Range: <code>2024-01-01 -> 2024-06-30</code>\n"
        "• From Date to Now: <code>2024-06-01</code>\n\n"
        "Send your date range below:"
    )
    await bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=kb, parse_mode="HTML")

# Advanced Settings & Content Filter Callbacks

@bot.callback_query_handler(func=lambda call: call.data == "flow_settings")
async def flow_settings_cb(call):
    user_id = call.from_user.id
    await bot.answer_callback_query(call.id)
    await show_copy_settings(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "toggle_content_type")
async def toggle_content_type_cb(call):
    user_id = call.from_user.id
    settings = get_user_copy_settings(user_id)
    current = settings.get("content_type", "all")
    idx = CONTENT_TYPE_CYCLE.index(current) if current in CONTENT_TYPE_CYCLE else 0
    next_type = CONTENT_TYPE_CYCLE[(idx + 1) % len(CONTENT_TYPE_CYCLE)]
    settings["content_type"] = next_type

    # Keep extract_text synchronized with content_type filter
    if next_type == "text_extract":
        settings["extract_text"] = True
        settings["strip_caption"] = False  # Mutually exclusive
    else:
        settings["extract_text"] = False

    await bot.answer_callback_query(call.id, f"Filter: {CONTENT_TYPE_LABELS.get(next_type)}")
    await show_copy_settings(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "toggle_skip_fwd")
async def toggle_skip_fwd_cb(call):
    user_id = call.from_user.id
    settings = get_user_copy_settings(user_id)
    settings["skip_forwarded"] = not settings.get("skip_forwarded", False)
    status = "ON (Skip forwarded)" if settings["skip_forwarded"] else "OFF (Include forwarded)"
    await bot.answer_callback_query(call.id, f"Skip Forwarded: {status}")
    await show_copy_settings(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "toggle_drop_fwd_tag")
async def toggle_drop_fwd_tag_cb(call):
    user_id = call.from_user.id
    settings = get_user_copy_settings(user_id)
    settings["drop_forward_tag"] = not settings.get("drop_forward_tag", True)
    tag_status = "Clean (No Tag)" if settings["drop_forward_tag"] else "Keep Original Tag"
    await bot.answer_callback_query(call.id, f"Forward Tag: {tag_status}")
    await show_copy_settings(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "flow_caption_rules")
async def flow_caption_rules_cb(call):
    user_id = call.from_user.id
    await bot.answer_callback_query(call.id)
    await show_caption_menu(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "toggle_strip_caption")
async def toggle_strip_caption_cb(call):
    user_id = call.from_user.id
    settings = get_user_copy_settings(user_id)
    settings["strip_caption"] = not settings.get("strip_caption", False)

    # Maintain mutual exclusivity between strip_caption and extract_text
    if settings["strip_caption"]:
        settings["extract_text"] = False
        if settings.get("content_type") == "text_extract":
            settings["content_type"] = "media"
        st = "ON (All media captions stripped)"
    else:
        st = "OFF (Original captions kept)"

    await bot.answer_callback_query(call.id, f"Strip Captions: {st}")
    await show_caption_menu(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "toggle_extract_text")
async def toggle_extract_text_cb(call):
    user_id = call.from_user.id
    settings = get_user_copy_settings(user_id)
    settings["extract_text"] = not settings.get("extract_text", False)

    # Maintain mutual exclusivity between extract_text and strip_caption
    if settings["extract_text"]:
        settings["strip_caption"] = False
        settings["content_type"] = "text_extract"
        st = "ON (Captions copied as text, media skipped)"
    else:
        if settings.get("content_type") == "text_extract":
            settings["content_type"] = "all"
        st = "OFF (Media transfer restored)"

    await bot.answer_callback_query(call.id, f"Extract Text: {st}")
    await show_caption_menu(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "toggle_clean_links")
async def toggle_clean_links_cb(call):
    user_id = call.from_user.id
    settings = get_user_copy_settings(user_id)
    settings["clean_links"] = not settings.get("clean_links", False)
    st = "ON (URLs & links removed)" if settings["clean_links"] else "OFF (Links kept)"
    await bot.answer_callback_query(call.id, f"Remove Links: {st}")
    await show_caption_menu(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "toggle_clean_mentions")
async def toggle_clean_mentions_cb(call):
    user_id = call.from_user.id
    settings = get_user_copy_settings(user_id)
    settings["clean_mentions"] = not settings.get("clean_mentions", False)
    st = "ON (@mentions removed)" if settings["clean_mentions"] else "OFF (@mentions kept)"
    await bot.answer_callback_query(call.id, f"Remove Mentions: {st}")
    await show_caption_menu(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "toggle_clean_hashtags")
async def toggle_clean_hashtags_cb(call):
    user_id = call.from_user.id
    settings = get_user_copy_settings(user_id)
    settings["clean_hashtags"] = not settings.get("clean_hashtags", False)
    st = "ON (#hashtags removed)" if settings["clean_hashtags"] else "OFF (#hashtags kept)"
    await bot.answer_callback_query(call.id, f"Remove Hashtags: {st}")
    await show_caption_menu(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "menu_find_replace")
async def menu_find_replace_cb(call):
    user_id = call.from_user.id
    await bot.answer_callback_query(call.id)
    await show_find_replace_menu(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "btn_add_find_replace")
async def btn_add_find_replace_cb(call):
    user_id = call.from_user.id
    user_states[user_id] = "WAIT_FIND_REPLACE"
    await bot.answer_callback_query(call.id)

    kb = InlineKeyboardMarkup().add(InlineKeyboardButton("⬅️ Back to Find & Replace", callback_data="menu_find_replace"))
    text = (
        "🔄 <b>Add Find & Replace Rule</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "Send your replacement rule in this format:\n"
        "<code>find text -> replacement text</code>\n\n"
        "<b>Examples:</b>\n"
        "• <code>@OldChannel -> @MyNewChannel</code>\n"
        "• <code>Join for free -> </code> <i>(Deletes phrase)</i>\n"
        "• <code>spam.com -> mywebsite.com</code>\n\n"
        "Send your replacement rule below in chat (or send /cancel):"
    )
    await bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=kb, parse_mode="HTML")

@bot.callback_query_handler(func=lambda call: call.data == "btn_clear_find_replace")
async def btn_clear_find_replace_cb(call):
    user_id = call.from_user.id
    settings = get_user_copy_settings(user_id)
    settings["find_replace_rules"] = []
    await bot.answer_callback_query(call.id, "All replacement rules cleared.")
    await show_find_replace_menu(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "btn_set_header")
async def btn_set_header_cb(call):
    user_id = call.from_user.id
    user_states[user_id] = "WAIT_HEADER"
    await bot.answer_callback_query(call.id)

    kb = InlineKeyboardMarkup().add(InlineKeyboardButton("⬅️ Back to Caption Rules", callback_data="flow_caption_rules"))
    text = (
        "🔝 <b>Set Caption Header (Top Text)</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "This text will be prepended at the very top of each message or caption.\n\n"
        "💡 Use <code>{channel}</code> to insert the source channel's name!\n\n"
        "<b>Example:</b>\n"
        "<code>📢 Shared from: {channel}</code>\n\n"
        "Send your header text below (or send <code>/clear</code> to remove):"
    )
    await bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=kb, parse_mode="HTML")

@bot.callback_query_handler(func=lambda call: call.data == "btn_clear_header")
async def btn_clear_header_cb(call):
    user_id = call.from_user.id
    settings = get_user_copy_settings(user_id)
    settings["header"] = None
    await bot.answer_callback_query(call.id, "Header removed.")
    await show_caption_menu(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data in ("btn_set_footer", "btn_set_sig"))
async def btn_set_footer_cb(call):
    user_id = call.from_user.id
    user_states[user_id] = "WAIT_FOOTER"
    await bot.answer_callback_query(call.id)

    kb = InlineKeyboardMarkup().add(InlineKeyboardButton("⬅️ Back to Caption Rules", callback_data="flow_caption_rules"))
    text = (
        "🔚 <b>Set Caption Footer / Signature (Bottom Text)</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "This text will be appended at the bottom of each message or caption.\n\n"
        "💡 Use <code>{channel}</code> to insert the source channel's name!\n\n"
        "<b>Example:</b>\n"
        "<code>📥 Source: {channel}\n"
        "🔔 Join: @MyNewChannel</code>\n\n"
        "Send your footer text below (or send <code>/clear</code> to remove):"
    )
    await bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=kb, parse_mode="HTML")

@bot.callback_query_handler(func=lambda call: call.data in ("btn_clear_footer", "btn_clear_sig"))
async def btn_clear_footer_cb(call):
    user_id = call.from_user.id
    settings = get_user_copy_settings(user_id)
    settings["footer"] = None
    settings["signature"] = None
    await bot.answer_callback_query(call.id, "Footer / Signature removed.")
    await show_caption_menu(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "reset_caption_rules")
async def reset_caption_rules_cb(call):
    user_id = call.from_user.id
    settings = get_user_copy_settings(user_id)
    settings["strip_caption"] = False
    settings["extract_text"] = False
    settings["clean_links"] = False
    settings["clean_mentions"] = False
    settings["clean_hashtags"] = False
    settings["find_replace_rules"] = []
    settings["header"] = None
    settings["footer"] = None
    settings["signature"] = None
    if settings.get("content_type") == "text_extract":
        settings["content_type"] = "all"
    await bot.answer_callback_query(call.id, "Caption rules reset to defaults.")
    await show_caption_menu(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "reset_settings")
async def reset_settings_cb(call):
    user_id = call.from_user.id
    user_auth_data[user_id]["copy_settings"] = {
        "content_type": "all",
        "skip_service": True,
        "skip_forwarded": False,
        "skip_duplicates": False,
        "drop_forward_tag": True,
        "strip_caption": False,
        "extract_text": False,
        "clean_links": False,
        "clean_mentions": False,
        "clean_hashtags": False,
        "find_replace_rules": [],
        "header": None,
        "footer": None,
        "signature": None
    }
    await bot.answer_callback_query(call.id, "All settings reset to defaults.")
    await show_copy_settings(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "flow_confirm")
async def flow_confirm_cb(call):
    user_id = call.from_user.id
    await bot.answer_callback_query(call.id)
    await show_confirmation(call.message.chat.id, user_id, call.message.message_id)


@bot.callback_query_handler(func=lambda call: call.data == "toggle_skip_dup")
async def toggle_skip_dup_cb(call):
    user_id = call.from_user.id
    settings = get_user_copy_settings(user_id)
    settings["skip_duplicates"] = not settings.get("skip_duplicates", False)
    status = "ON (Skip duplicates)" if settings["skip_duplicates"] else "OFF (Copy all)"
    await bot.answer_callback_query(call.id, f"Skip Duplicates: {status}")
    await show_copy_settings(call.message.chat.id, user_id, call.message.message_id)

# Analytics & History Callbacks

@bot.callback_query_handler(func=lambda call: call.data == "nav_analytics")
async def nav_analytics_cb(call):
    await bot.answer_callback_query(call.id)
    await show_analytics(call.message.chat.id, call.from_user.id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "analytics_chart")
async def analytics_chart_cb(call):
    await bot.answer_callback_query(call.id)
    await show_analytics_chart(call.message.chat.id, call.from_user.id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "analytics_recent")
async def analytics_recent_cb(call):
    await bot.answer_callback_query(call.id)
    await show_analytics_recent(call.message.chat.id, call.from_user.id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "analytics_clear_prompt")
async def analytics_clear_prompt_cb(call):
    await bot.answer_callback_query(call.id)
    kb = InlineKeyboardMarkup()
    kb.row(
        InlineKeyboardButton("⚠️ Yes, Delete All History", callback_data="analytics_clear_confirm"),
        InlineKeyboardButton("❌ Cancel", callback_data="nav_analytics")
    )
    text = (
        "⚠️ <b>Clear Analytics History?</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "This will permanently delete all your past job records and daily statistics.\n"
        "Are you sure?"
    )
    await bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=kb, parse_mode="HTML")

@bot.callback_query_handler(func=lambda call: call.data == "analytics_clear_confirm")
async def analytics_clear_confirm_cb(call):
    clear_user_stats(call.from_user.id)
    await bot.answer_callback_query(call.id, "✅ History cleared successfully!", show_alert=True)
    await show_analytics(call.message.chat.id, call.from_user.id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "dedup_clear_prompt")
async def dedup_clear_prompt_cb(call):
    await bot.answer_callback_query(call.id)
    kb = InlineKeyboardMarkup()
    kb.row(
        InlineKeyboardButton("⚠️ Yes, Clear Dedup Cache", callback_data="dedup_clear_confirm"),
        InlineKeyboardButton("❌ Cancel", callback_data="nav_analytics")
    )
    text = (
        "🧹 <b>Clear Deduplication Cache?</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "This will remove all indexed message hashes.\n"
        "Previously copied messages will no longer be recognized as duplicates.\n"
        "Are you sure?"
    )
    await bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=kb, parse_mode="HTML")

@bot.callback_query_handler(func=lambda call: call.data == "dedup_clear_confirm")
async def dedup_clear_confirm_cb(call):
    clear_user_dedup_cache(call.from_user.id)
    await bot.answer_callback_query(call.id, "✅ Dedup cache cleared!", show_alert=True)
    await show_analytics(call.message.chat.id, call.from_user.id, call.message.message_id)

# Proxy Management Callbacks

@bot.callback_query_handler(func=lambda call: call.data == "nav_proxy")
async def nav_proxy_cb(call):
    user_states[call.from_user.id] = None
    await bot.answer_callback_query(call.id)
    await show_proxy_menu(call.message.chat.id, call.from_user.id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "proxy_add")
async def proxy_add_cb(call):
    user_id = call.from_user.id
    user_states[user_id] = "WAIT_PROXY"
    await bot.answer_callback_query(call.id)

    kb = InlineKeyboardMarkup().add(InlineKeyboardButton("⬅️ Back to Proxy Menu", callback_data="nav_proxy"))
    text = (
        "🌐 <b>Add New Proxy</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "Send your proxy below in one of these formats:\n\n"
        "• <code>socks5://1.2.3.4:1080</code>\n"
        "• <code>socks5://user:pass@1.2.3.4:1080</code>\n"
        "• <code>http://1.2.3.4:8080</code>\n"
        "• <code>1.2.3.4:1080:user:pass</code>\n"
        "• <code>1.2.3.4:1080</code>\n\n"
        "💡 <i>Bot will automatically test connection latency before saving.</i>"
    )
    await bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=kb, parse_mode="HTML")

@bot.callback_query_handler(func=lambda call: call.data.startswith("proxy_use_"))
async def proxy_use_cb(call):
    user_id = call.from_user.id
    pid = call.data.replace("proxy_use_", "")
    await bot.answer_callback_query(call.id, "🔄 Connecting to proxy...")
    target_id = None if pid == "direct" else pid
    ok, msg = await switch_user_proxy(user_id, target_id)
    if ok:
        await bot.answer_callback_query(call.id, f"✅ {msg}")
    else:
        await bot.answer_callback_query(call.id, f"⚠️ {msg}", show_alert=True)
    await show_proxy_menu(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data.startswith("proxy_ping_"))
async def proxy_ping_cb(call):
    user_id = call.from_user.id
    pid = call.data.replace("proxy_ping_", "")
    await bot.answer_callback_query(call.id, "📶 Testing latency...")

    proxies = get_user_proxies(user_id)
    px = next((p for p in proxies if p["id"] == pid), None)
    if px:
        latency = await test_proxy_ping(px)
        px["ping_ms"] = latency if latency is not None else -1
        save_db(DB)
        if latency:
            await bot.answer_callback_query(call.id, f"📶 Ping: {latency}ms (Online)")
        else:
            await bot.answer_callback_query(call.id, "❌ Ping failed: Offline / Unreachable", show_alert=True)
    await show_proxy_menu(call.message.chat.id, user_id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data.startswith("proxy_del_"))
async def proxy_del_cb(call):
    user_id = call.from_user.id
    pid = call.data.replace("proxy_del_", "")
    proxies = get_user_proxies(user_id)
    proxies = [p for p in proxies if p["id"] != pid]
    DB[str(user_id)]["proxies"] = proxies

    # If deleted proxy was active, switch to direct
    if DB.get(str(user_id), {}).get("active_proxy_id") == pid:
        await switch_user_proxy(user_id, None)
    else:
        save_db(DB)

    await bot.answer_callback_query(call.id, "🗑️ Proxy deleted.")
    await show_proxy_menu(call.message.chat.id, user_id, call.message.message_id)

# Confirm Copy Job
@bot.callback_query_handler(func=lambda call: call.data == "confirm_copy")
async def confirm_copy_cb(call):
    user_id = call.from_user.id
    data = user_auth_data.get(user_id, {})
    src = data.get("source")
    dst = data.get("dest")

    if not src or not dst:
        return await bot.answer_callback_query(call.id, "Session expired. Please select again.", show_alert=True)

    # Prevent concurrent tasks for the same account
    if active_tasks.get(user_id, False):
        return await bot.answer_callback_query(call.id, "⚠️ A copy task is already in progress. Please wait for it to complete or stop it first.", show_alert=True)

    u_client = user_clients.get(user_id)
    if not u_client:
        return await bot.answer_callback_query(call.id, "Telegram client not connected. Please log in again.", show_alert=True)

    # Run pre-flight health and permissions checks
    await bot.answer_callback_query(call.id, "🔍 Running pre-flight safety checks...")
    ok, reason, is_prot = await run_preflight_checks(u_client, user_id, call.message.chat.id, src, dst)
    if not ok:
        return await bot.send_message(call.message.chat.id, reason, parse_mode="HTML")

    user_states[user_id] = None
    user_active_query[user_id] = None
    active_tasks[user_id] = True

    await bot.edit_message_text(
        "🚀 <b>Initializing Copy Engine...</b>\nScanning messages matching your selected range and filters...",
        call.message.chat.id,
        call.message.message_id,
        parse_mode="HTML"
    )
    asyncio.create_task(copy_messages(user_id, call.message.chat.id, src, dst, preflight_protected=is_prot))

# Stop Copying Handler
@bot.callback_query_handler(func=lambda call: call.data == "stop_copy")
async def stop_copy_cb(call):
    user_id = call.from_user.id
    active_tasks[user_id] = False
    await bot.answer_callback_query(call.id, "🛑 Stopping copy process...", show_alert=True)
    try:
        await bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=None)
    except Exception:
        pass

# View Active Task Progress
@bot.callback_query_handler(func=lambda call: call.data == "view_task")
async def view_task_cb(call):
    user_id = call.from_user.id
    task = user_task_info.get(user_id)
    if not task or not active_tasks.get(user_id, False):
        return await bot.answer_callback_query(call.id, "No active copy task running.", show_alert=True)

    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("Stop Copying 🛑", callback_data="stop_copy"))
    kb.add(InlineKeyboardButton("🏠 Back to Dashboard", callback_data="nav_home"))

    text = (
        "⚡ <b>Active Copy Job</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔹 <b>From:</b> {task.get('src_title')}\n"
        f"🔸 <b>To:</b> {task.get('dst_title')}\n"
        f"📊 <b>Progress:</b> {task.get('count', 0)} / {task.get('total', 0)} messages\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )
    await bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=kb, parse_mode="HTML")


# Checkpoint Resume & Management Callbacks

@bot.callback_query_handler(func=lambda call: call.data == "resume_checkpoint")
async def resume_checkpoint_cb(call):
    user_id = call.from_user.id
    cp = get_checkpoint(user_id)
    if not cp:
        return await bot.answer_callback_query(call.id, "No active checkpoint found.", show_alert=True)
    if active_tasks.get(user_id, False):
        return await bot.answer_callback_query(call.id, "A copy job is already running!", show_alert=True)

    await bot.answer_callback_query(call.id, "▶️ Resuming copy job...")
    active_tasks[user_id] = True
    asyncio.create_task(copy_messages(user_id, call.message.chat.id, cp["src"], cp["dst"], resume_cp=cp))

@bot.callback_query_handler(func=lambda call: call.data == "discard_checkpoint")
async def discard_checkpoint_cb(call):
    user_id = call.from_user.id
    delete_checkpoint(user_id)
    await bot.answer_callback_query(call.id, "🗑️ Checkpoint discarded.")
    await send_dashboard(call.message.chat.id, user_id, call.message.message_id)

# Interactive Telegram Account Login Wizard

@bot.callback_query_handler(func=lambda call: call.data == "start_login")
async def start_login_cb(call):
    user_id = call.from_user.id
    old = user_clients.get(user_id)
    if old:
        try:
            if old.is_connected:
                await old.disconnect()
        except Exception:
            pass
        user_clients.pop(user_id, None)

    user_states[user_id] = "WAIT_API_ID"
    user_auth_data[user_id] = {}

    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("❌ Cancel Login", callback_data="nav_home"))

    text = (
        "🔐 <b>Telegram Login [Step 1 of 4]</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "Please send your <b>API ID</b> (obtained from my.telegram.org):\n\n"
        "<i>(Send numbers only)</i>"
    )
    await bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=kb, parse_mode="HTML")

# Text & Forwarded Message Dispatcher

@bot.message_handler(func=lambda m: True)
async def handle_text_and_forwards(message):
    user_id = message.from_user.id
    if user_id not in user_clients:
        await get_or_restore_user_client(user_id)
    state = user_states.get(user_id)
    chat_id = message.chat.id
    cancel_kb = InlineKeyboardMarkup().add(InlineKeyboardButton("❌ Cancel", callback_data="nav_home"))

    # Forwarded message handler during selection
    forward_chat = getattr(message, "forward_from_chat", None)
    if forward_chat and state in ("PICK_SRC", "PICK_DST"):
        target = forward_chat.id
        title = forward_chat.title or "Forwarded Channel"
        if state == "PICK_SRC":
            user_auth_data[user_id]["source"] = target
            user_auth_data[user_id]["src_title"] = title
            user_states[user_id] = "PICK_DST"
            user_active_query[user_id] = None
            await bot.send_message(chat_id, f"✅ <b>Source Selected:</b> {title}\nNow select or paste DESTINATION chat:")
            return await flow_pick_dst_text(chat_id, user_id)
        else:
            user_auth_data[user_id]["dest"] = target
            user_auth_data[user_id]["dst_title"] = title
            user_active_query[user_id] = None
            await bot.send_message(chat_id, f"✅ <b>Destination Selected:</b> {title}")
            return await show_range_selection(chat_id, user_id)

    if not state:
        return await send_dashboard(chat_id, user_id)

    text = message.text.strip() if message.text else ""

    # Range Custom Inputs
    if state == "WAIT_CUSTOM_ID":
        parsed = parse_id_range(text)
        if parsed:
            min_id, max_id = parsed
            set_user_range_config(user_id, "id", label=f"IDs {min_id} to {max_id}", extra={"min": min_id, "max": max_id})
            await bot.send_message(chat_id, f"✅ <b>Message ID Range set:</b> IDs {min_id} to {max_id}", parse_mode="HTML")
            return await show_copy_settings(chat_id, user_id)
        else:
            return await bot.send_message(
                chat_id,
                "⚠️ <b>Invalid format!</b>\nPlease send range like <code>100 -> 500</code> (or single ID like <code>250</code>):",
                reply_markup=InlineKeyboardMarkup().add(InlineKeyboardButton("⬅️ Back to Range Options", callback_data="flow_pick_range")),
                parse_mode="HTML"
            )

    elif state == "WAIT_CUSTOM_DATE":
        parsed = parse_date_range(text)
        if parsed:
            d1, d2 = parsed
            set_user_range_config(user_id, "date", label=f"{d1.strftime('%Y-%m-%d')} to {d2.strftime('%Y-%m-%d')}", extra={"from": d1, "to": d2})
            await bot.send_message(chat_id, f"✅ <b>Date Range set:</b> {d1.strftime('%Y-%m-%d')} to {d2.strftime('%Y-%m-%d')}", parse_mode="HTML")
            return await show_copy_settings(chat_id, user_id)
        else:
            return await bot.send_message(
                chat_id,
                "⚠️ <b>Invalid date format!</b>\nPlease send like <code>2024-01-01 -> 2024-06-30</code> (YYYY-MM-DD):",
                reply_markup=InlineKeyboardMarkup().add(InlineKeyboardButton("⬅️ Back to Range Options", callback_data="flow_pick_range")),
                parse_mode="HTML"
            )

    elif state == "WAIT_HEADER":
        settings = get_user_copy_settings(user_id)
        if text.strip().lower() in ("/cancel", "cancel"):
            user_states[user_id] = None
            return await show_caption_menu(chat_id, user_id)
        if text.strip().lower() in ("/clear", "clear"):
            settings["header"] = None
            await bot.send_message(chat_id, "🗑️ <b>Header removed.</b>", parse_mode="HTML")
        else:
            settings["header"] = text
            await bot.send_message(chat_id, f"✅ <b>Header saved!</b>\n\nPreview:\n<i>{text}</i>", parse_mode="HTML")
        user_states[user_id] = None
        return await show_caption_menu(chat_id, user_id)

    elif state in ("WAIT_FOOTER", "WAIT_SIGNATURE"):
        settings = get_user_copy_settings(user_id)
        if text.strip().lower() in ("/cancel", "cancel"):
            user_states[user_id] = None
            return await show_caption_menu(chat_id, user_id)
        if text.strip().lower() in ("/clear", "clear"):
            settings["footer"] = None
            settings["signature"] = None
            await bot.send_message(chat_id, "🗑️ <b>Footer / Signature removed.</b>", parse_mode="HTML")
        else:
            settings["footer"] = text
            settings["signature"] = text
            await bot.send_message(chat_id, f"✅ <b>Footer / Signature saved!</b>\n\nPreview:\n<i>{text}</i>", parse_mode="HTML")
        user_states[user_id] = None
        return await show_caption_menu(chat_id, user_id)

    elif state == "WAIT_FIND_REPLACE":
        settings = get_user_copy_settings(user_id)
        if text.strip().lower() in ("/cancel", "cancel"):
            user_states[user_id] = None
            return await show_find_replace_menu(chat_id, user_id)

        if "->" in text:
            parts = text.split("->", 1)
        elif "=>" in text:
            parts = text.split("=>", 1)
        else:
            parts = [text, ""]

        find_str = parts[0].strip()
        repl_str = parts[1].strip() if len(parts) > 1 else ""

        if not find_str:
            return await bot.send_message(
                chat_id,
                "⚠️ <b>Find text cannot be empty!</b>\nFormat: <code>find text -> replace text</code>\n(Send /cancel to return)",
                parse_mode="HTML"
            )

        if "find_replace_rules" not in settings or not isinstance(settings["find_replace_rules"], list):
            settings["find_replace_rules"] = []

        settings["find_replace_rules"].append({
            "find": find_str,
            "replace": repl_str
        })
        user_states[user_id] = None
        repl_disp = f"<code>{repl_str}</code>" if repl_str else "<i>[DELETED]</i>"
        await bot.send_message(
            chat_id,
            f"✅ <b>Replacement Rule Added!</b>\n<code>{find_str}</code> ➔ {repl_disp}",
            parse_mode="HTML"
        )
        return await show_find_replace_menu(chat_id, user_id)

    elif state == "WAIT_PROXY":
        parsed = parse_proxy_string(text)
        if not parsed:
            return await bot.send_message(
                chat_id,
                "⚠️ <b>Invalid proxy format!</b>\n\n"
                "Please send in one of these formats:\n"
                "• <code>socks5://1.2.3.4:1080</code>\n"
                "• <code>socks5://user:pass@1.2.3.4:1080</code>\n"
                "• <code>http://1.2.3.4:8080</code>\n"
                "• <code>1.2.3.4:1080:user:pass</code>\n"
                "• <code>1.2.3.4:1080</code>",
                reply_markup=InlineKeyboardMarkup().add(InlineKeyboardButton("⬅️ Back to Proxy Menu", callback_data="nav_proxy")),
                parse_mode="HTML"
            )

        test_msg = await bot.send_message(chat_id, f"⏳ <b>Testing latency to {parsed['hostname']}:{parsed['port']}...</b>", parse_mode="HTML")
        latency = await test_proxy_ping(parsed)

        proxies = get_user_proxies(user_id)
        pid = f"px_{int(time.time() * 1000)}"
        label = f"{parsed['scheme'].upper()} {parsed['hostname']}:{parsed['port']}"
        proxy_item = {
            "id": pid,
            "scheme": parsed["scheme"],
            "hostname": parsed["hostname"],
            "port": parsed["port"],
            "username": parsed.get("username"),
            "password": parsed.get("password"),
            "label": label,
            "ping_ms": latency if latency is not None else -1
        }
        proxies.append(proxy_item)
        DB[str(user_id)]["proxies"] = proxies
        save_db(DB)
        user_states[user_id] = None

        try:
            await bot.delete_message(chat_id, test_msg.message_id)
        except Exception:
            pass

        kb = InlineKeyboardMarkup()
        kb.row(
            InlineKeyboardButton("⚡ Activate This Proxy", callback_data=f"proxy_use_{pid}"),
            InlineKeyboardButton("🌐 Proxy Menu", callback_data="nav_proxy")
        )
        ping_report = f"🟢 Ping: <b>{latency}ms</b> (Online)" if latency else "⚠️ Ping: <b>Offline / Unreachable</b>"
        await bot.send_message(
            chat_id,
            f"✅ <b>Proxy Added Successfully!</b>\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🌐 <b>Host:</b> {parsed['hostname']}:{parsed['port']}\n"
            f"🛡️ <b>Type:</b> {parsed['scheme'].upper()}\n"
            f"📶 <b>Status:</b> {ping_report}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            reply_markup=kb,
            parse_mode="HTML"
        )
        return

    # Channel Selection: Search & Target Resolution
    elif state in ("PICK_SRC", "PICK_DST"):
        target_type, target_val = parse_input(text)
        mode = "src" if state == "PICK_SRC" else "dst"

        if target_type == 'SEARCH_QUERY':
            now = time.time()
            if now - user_dialog_last_fetch.get(user_id, 0) > 20 or not user_dialog_cache.get(user_id):
                await refresh_user_dialogs(user_id)

            user_active_query[user_id] = target_val
            kb, page, total, match_count = build_dialog_keyboard(user_id, mode, page=0, query=target_val)
            step_name = "SOURCE" if mode == "src" else "DESTINATION"

            if match_count > 0:
                msg_text = (
                    f"🔍 <b>Found {match_count} chat(s) matching '<i>{target_val}</i>':</b>\n"
                    f"Tap your {step_name} chat from the results below:"
                )
            else:
                msg_text = (
                    f"❌ <b>No chat found matching '<code>{target_val}</code>' in your joined chats.</b>\n\n"
                    "💡 <b>Tips:</b>\n"
                    "• If you just joined this channel, tap <b>🔄 Refresh Chats</b> below.\n"
                    "• Or send the exact channel link: <code>https://t.me/...</code>\n"
                    "• Or send its username: <code>@channel_username</code>\n"
                    "• Or forward any message from that channel here!"
                )
            return await bot.send_message(chat_id, msg_text, reply_markup=kb, parse_mode="HTML")

        else:
            u_client = user_clients.get(user_id)
            resolved_id, title = await resolve_chat(u_client, target_type, target_val)

            if resolved_id:
                if mode == "src":
                    user_auth_data[user_id]["source"] = resolved_id
                    user_auth_data[user_id]["src_title"] = title
                    user_states[user_id] = "PICK_DST"
                    user_active_query[user_id] = None
                    await bot.send_message(chat_id, f"✅ <b>Source Selected:</b> {title} (<code>{resolved_id}</code>)\nNow choose or paste DESTINATION chat:")
                    return await flow_pick_dst_text(chat_id, user_id)
                else:
                    user_auth_data[user_id]["dest"] = resolved_id
                    user_auth_data[user_id]["dst_title"] = title
                    user_active_query[user_id] = None
                    await bot.send_message(chat_id, f"✅ <b>Destination Selected:</b> {title} (<code>{resolved_id}</code>)")
                    return await show_range_selection(chat_id, user_id)
            else:
                return await bot.send_message(
                    chat_id,
                    f"❌ <b>Could not access channel:</b> {title}\n\n"
                    "Please verify your Telegram account has access to this channel, or forward any message from it directly to this bot.",
                    parse_mode="HTML"
                )

    # Login Flow Authentication Steps
    elif state == "WAIT_API_ID":
        try:
            user_auth_data[user_id]["api_id"] = int(text)
            user_states[user_id] = "WAIT_API_HASH"
            await bot.send_message(chat_id, "🔐 <b>Telegram Login [Step 2 of 4]</b>\nNow send your <b>API HASH</b>:", reply_markup=cancel_kb, parse_mode="HTML")
        except ValueError:
            await bot.send_message(chat_id, "⚠️ API ID must be numeric numbers. Please try again:", reply_markup=cancel_kb)

    elif state == "WAIT_API_HASH":
        user_auth_data[user_id]["api_hash"] = text
        user_states[user_id] = "WAIT_PHONE"
        await bot.send_message(chat_id, "📱 <b>Telegram Login [Step 3 of 4]</b>\nSend your phone number with country code (e.g., <code>+919876543210</code>):", reply_markup=cancel_kb, parse_mode="HTML")

    elif state == "WAIT_PHONE":
        phone = text
        user_auth_data[user_id]["phone"] = phone
        api_id = user_auth_data[user_id]["api_id"]
        api_hash = user_auth_data[user_id]["api_hash"]

        u_client = Client(f"user_{user_id}", api_id=api_id, api_hash=api_hash, in_memory=True, sleep_threshold=60)
        await u_client.connect()

        try:
            sent_code = await u_client.send_code(phone)
            user_auth_data[user_id]["phone_code_hash"] = sent_code.phone_code_hash
            user_clients[user_id] = u_client
            user_states[user_id] = "WAIT_OTP"
            await bot.send_message(
                chat_id,
                "💬 <b>Telegram Login [Step 4 of 4]</b>\n"
                "OTP code has been sent to your Telegram app!\n\n"
                "⚠️ <b>IMPORTANT:</b> Send OTP with spaces between numbers (e.g. <code>1 2 3 4 5</code>) so Telegram doesn't cancel it.",
                reply_markup=cancel_kb,
                parse_mode="HTML"
            )
        except Exception as e:
            try:
                if u_client.is_connected:
                    await u_client.disconnect()
            except Exception:
                pass
            await bot.send_message(chat_id, f"❌ Error sending OTP: {e}\nPlease send your phone number again:", reply_markup=cancel_kb)

    elif state == "WAIT_OTP":
        otp = text.replace(" ", "")
        u_client = user_clients[user_id]
        phone = user_auth_data[user_id]["phone"]
        phone_code_hash = user_auth_data[user_id]["phone_code_hash"]

        try:
            await u_client.sign_in(phone, phone_code_hash, otp)
            await save_user_session(user_id, u_client)
            user_states[user_id] = None
            try:
                u_client.me = await u_client.get_me()
            except Exception:
                pass
            await refresh_user_dialogs(user_id)
            await bot.send_message(chat_id, "🎉 <b>Login Successful!</b> Welcome to Channel Copier.")
            await send_dashboard(chat_id, user_id)
        except SessionPasswordNeeded:
            user_states[user_id] = "WAIT_PASSWORD"
            await bot.send_message(chat_id, "🔐 <b>Two-Step Verification:</b>\nPlease enter your 2FA Cloud Password:", reply_markup=cancel_kb, parse_mode="HTML")
        except Exception as e:
            user_states[user_id] = "WAIT_PHONE"
            await bot.send_message(chat_id, f"❌ Error: {e}\n\nOTP expired or invalid. Send your phone number again to request a fresh OTP:", reply_markup=cancel_kb)

    elif state == "WAIT_PASSWORD":
        u_client = user_clients[user_id]
        try:
            await u_client.check_password(text)
            await save_user_session(user_id, u_client)
            user_states[user_id] = None
            try:
                u_client.me = await u_client.get_me()
            except Exception:
                pass
            await refresh_user_dialogs(user_id)
            await bot.send_message(chat_id, "🎉 <b>Login Successful!</b> Welcome to Channel Copier.")
            await send_dashboard(chat_id, user_id)
        except Exception as e:
            await bot.send_message(chat_id, f"❌ Wrong password: {e}\nPlease try again:", reply_markup=cancel_kb)

    else:
        # Catch-all handler for unhandled text while user is viewing inline menus
        if text.startswith("/"):
            return  # Allow bot commands like /start, /help, /logout to process
        await bot.send_message(
            chat_id,
            "💡 <i>Please tap one of the buttons on the menu above, or send /start to open the dashboard.</i>",
            parse_mode="HTML"
        )
        return

async def flow_pick_dst_text(chat_id, user_id):
    kb, page, total, count = build_dialog_keyboard(user_id, "dst", page=0)
    text = (
        "📍 <b>Step 2/5: Select DESTINATION Chat</b>\n"
        "Tap a chat below, or type search name, paste link/ID, or forward a message:"
    )
    await bot.send_message(chat_id, text, reply_markup=kb, parse_mode="HTML")

async def save_user_session(user_id, u_client):
    session = await u_client.export_session_string()
    uid = str(user_id)
    if uid not in DB:
        DB[uid] = {}
    DB[uid]["session"] = session
    DB[uid]["api_id"] = user_auth_data[user_id]["api_id"]
    DB[uid]["api_hash"] = user_auth_data[user_id]["api_hash"]
    save_db(DB)

# Single Message & Media Content Protection Bypass Engine

async def copy_single_message(u_client, dst, src, msg_id, signature=None, src_title="", is_protected=False, settings=None):
    if settings is None:
        if isinstance(signature, dict):
            settings = signature
        elif signature:
            settings = {"footer": signature, "signature": signature}
        else:
            settings = {}

    has_mods = has_caption_modifications(settings)
    drop_tag = settings.get("drop_forward_tag", True)

    # 1. If NOT protected AND NO caption modifications, attempt fast server-side copy
    if not is_protected and not has_mods:
        try:
            if drop_tag:
                await u_client.copy_message(dst, src, msg_id)
            else:
                await u_client.forward_messages(dst, src, msg_id)
            return True
        except FloodWait as fw:
            await asyncio.sleep(fw.value + 1)
            try:
                if drop_tag:
                    await u_client.copy_message(dst, src, msg_id)
                else:
                    await u_client.forward_messages(dst, src, msg_id)
                return True
            except Exception:
                pass
        except Exception:
            pass

    # Content protection bypass & custom caption transformations
    try:
        msg = await u_client.get_messages(src, msg_id)
        if not msg or msg.empty or msg.service:
            return False

        # Priority guard: if user selected content_type="media" or strip_caption, extract_text is disabled
        is_extract_text = (settings.get("extract_text", False) or settings.get("content_type") == "text_extract") and (settings.get("content_type") != "media") and not settings.get("strip_caption", False)

        # Case A: Text message
        if msg.text:
            text_to_send = process_caption_and_text(msg.text, settings, src_title, is_media=False)
            has_wp = getattr(msg, "web_page", None) or getattr(msg, "web_page_preview", None)
            no_wp = not bool(has_wp)
            entities = list(msg.entities) if (getattr(msg, "entities", None) and not has_mods) else None
            try:
                await chat_limiter.acquire(dst)
                await u_client.send_message(
                    chat_id=dst,
                    text=text_to_send,
                    entities=entities,
                    disable_web_page_preview=no_wp
                )
                return True
            except FloodWait as fw:
                await asyncio.sleep(fw.value + 1)
                await chat_limiter.acquire(dst)
                await u_client.send_message(
                    chat_id=dst,
                    text=text_to_send,
                    entities=entities,
                    disable_web_page_preview=no_wp
                )
                return True

        # Extract Text Mode: forward media captions as text messages without downloading media
        if is_extract_text:
            caption = msg.caption or ""
            if not caption.strip():
                # Media without caption cannot be converted to text; skip cleanly
                return False
            text_to_send = process_caption_and_text(caption, settings, src_title, is_media=False)
            if not text_to_send.strip():
                # Text became empty after filter rules; skip cleanly
                return False
            try:
                await chat_limiter.acquire(dst)
                await u_client.send_message(
                    chat_id=dst,
                    text=text_to_send,
                    disable_web_page_preview=True
                )
                return True
            except FloodWait as fw:
                await asyncio.sleep(fw.value + 1)
                await chat_limiter.acquire(dst)
                await u_client.send_message(
                    chat_id=dst,
                    text=text_to_send,
                    disable_web_page_preview=True
                )
                return True

        # Case C: Media message (Photos, Videos, Documents, Audio, Voice, Stickers, Animations)
        if msg.media:
            caption = process_caption_and_text(msg.caption or "", settings, src_title, is_media=True)

            # Explicit caption arguments: empty string strips caption; None preserves original
            if settings.get("strip_caption", False):
                cap_arg = ""
            elif has_mods:
                cap_arg = caption
            else:
                cap_arg = None

            # If not protected, try fast server-side copy_message with custom caption
            if not is_protected:
                try:
                    await chat_limiter.acquire(dst)
                    await u_client.copy_message(dst, src, msg_id, caption=cap_arg)
                    return True
                except Exception:
                    pass

            # Download & Re-upload (Bypass protected content)
            try:
                temp_file = await u_client.download_media(msg)
            except Exception as de:
                logger.error(f"Download failed for msg {msg_id}: {type(de).__name__}: {de}")
                return False

            if not temp_file or not os.path.exists(temp_file):
                logger.warning(f"Downloaded file not found on disk for msg {msg_id}")
                return False

            # Check 0KB download failure
            try:
                fsize = os.path.getsize(temp_file)
            except Exception:
                fsize = 0

            if fsize == 0:
                logger.warning(f"Downloaded 0KB empty file for msg {msg_id}, skipping")
                try:
                    os.remove(temp_file)
                except Exception:
                    pass
                return False

            fsize_mb = fsize / (1024 * 1024)
            logger.info(f"Downloaded msg {msg_id} ({fsize_mb:.2f} MB), uploading...")

            upload_caption = caption if caption else None

            async def _send_media_file():
                if msg.photo:
                    return await u_client.send_photo(dst, temp_file, caption=upload_caption)
                elif msg.video:
                    return await u_client.send_video(dst, temp_file, caption=upload_caption)
                elif msg.document:
                    return await u_client.send_document(dst, temp_file, caption=upload_caption)
                elif msg.audio:
                    return await u_client.send_audio(dst, temp_file, caption=upload_caption)
                elif msg.voice:
                    return await u_client.send_voice(dst, temp_file, caption=upload_caption)
                elif msg.animation:
                    return await u_client.send_animation(dst, temp_file, caption=upload_caption)
                elif msg.sticker:
                    return await u_client.send_sticker(dst, temp_file)
                else:
                    return await u_client.send_document(dst, temp_file, caption=upload_caption)

            try:
                await chat_limiter.acquire(dst)
                await _send_media_file()
                logger.info(f"Uploaded msg {msg_id} successfully")
                return True
            except FloodWait as fw:
                logger.warning(f"Upload FloodWait on msg {msg_id}: resting {fw.value + 1}s...")
                await asyncio.sleep(fw.value + 1)
                try:
                    await chat_limiter.acquire(dst)
                    await _send_media_file()
                    logger.info(f"Upload retry succeeded for msg {msg_id}")
                    return True
                except Exception as ex2:
                    logger.error(f"Upload retry failed for msg {msg_id}: {ex2}")
                    return False
            except Exception as ue:
                logger.error(f"Upload failed for msg {msg_id}: {ue}")
                return False
            finally:
                try:
                    if temp_file and os.path.exists(temp_file):
                        os.remove(temp_file)
                except Exception:
                    pass
    except Exception as e:
        logger.error(f"Bypass error for message {msg_id}: {type(e).__name__}: {e}")
        return False

    return False

# High-Throughput Batch Forwarding & Parallel Copy Engine

async def copy_messages(user_id, chat_id, src, dst, resume_cp=None, preflight_protected=False):
    u_client = user_clients[user_id]
    count = 0
    messages = []
    msg_hash_map = {}
    seen_hashes = set()
    skipped_dup = 0
    start_time = time.time()
    start_index = 0

    stop_kb = InlineKeyboardMarkup()
    stop_kb.add(InlineKeyboardButton("Stop Copying 🛑", callback_data="stop_copy"))

    if resume_cp:
        # Resume directly from checkpoint without scanning history!
        src_title = resume_cp["src_title"]
        dst_title = resume_cp["dst_title"]
        total = resume_cp["total"]
        count = resume_cp["copied_count"]
        start_index = resume_cp["current_index"]
        skipped_dup = resume_cp["skipped_dup"]
        ctype = resume_cp["content_type"]
        raw_sig = resume_cp.get("signature")
        if raw_sig and raw_sig.startswith("{"):
            try:
                settings = json.loads(raw_sig)
            except Exception:
                settings = {"signature": raw_sig, "footer": raw_sig}
        else:
            settings = {"signature": raw_sig, "footer": raw_sig} if raw_sig else {}
        is_protected = resume_cp["is_protected"]
        messages = json.loads(resume_cp["messages_json"])
        msg_hash_map = json.loads(resume_cp["msg_hash_json"])

        prog_msg = await bot.send_message(
            chat_id,
            f"▶️ <b>Resuming copy job...</b>\nFrom: <b>{src_title}</b>\nResuming at: <b>{count}/{total}</b> messages",
            reply_markup=stop_kb,
            parse_mode="HTML"
        )
    else:
        src_title = user_auth_data.get(user_id, {}).get("src_title", "Source")
        dst_title = user_auth_data.get(user_id, {}).get("dst_title", "Destination")
        range_cfg = get_user_range_config(user_id)
        settings = get_user_copy_settings(user_id)

        rtype = range_cfg.get("type", "all")
        ctype = settings.get("content_type", "all")
        skip_fwd = settings.get("skip_forwarded", False)
        skip_dup = settings.get("skip_duplicates", False)
        is_extract_mode = (settings.get("extract_text", False) or ctype == "text_extract") and (ctype != "media") and not settings.get("strip_caption", False)

        prog_msg = await bot.send_message(
            chat_id,
            f"⏳ <b>Scanning message history...</b>\nFrom: <b>{src_title}</b>\nRange: <code>{range_cfg.get('label')}</code>\nFilter: <b>{CONTENT_TYPE_LABELS.get(ctype)}</b>",
            reply_markup=stop_kb,
            parse_mode="HTML"
        )

        is_protected = preflight_protected
        if is_protected:
            logger.info(f"Source channel '{src_title}' ({src}) has Content Protection ON")
            await bot.send_message(
                chat_id,
                "⚠️ <b>Source channel has Content Protection ON.</b>\n"
                "Bot <b>Parallel Bypass Engine (3x concurrent)</b> use karega.",
                parse_mode="HTML"
            )

        try:
            fetch_count = 0
            last_fetch_edit = 0
            kwargs = {}
            if rtype == "last_n":
                kwargs["limit"] = range_cfg.get("value", 500)

            async for msg in u_client.get_chat_history(src, **kwargs):
                if not active_tasks.get(user_id, True):
                    try:
                        await bot.edit_message_text("🛑 <b>Cancelled while fetching history.</b>", chat_id, prog_msg.message_id, parse_mode="HTML")
                    except Exception:
                        pass
                    return

                if rtype == "id":
                    min_id = range_cfg.get("min", 1)
                    max_id = range_cfg.get("max", 999999999)
                    if msg.id > max_id:
                        continue
                    if msg.id < min_id:
                        break

                if rtype == "date":
                    d_from = range_cfg.get("from")
                    d_to = range_cfg.get("to")
                    msg_dt = msg.date.replace(tzinfo=None) if msg.date else None
                    if msg_dt:
                        if msg_dt > d_to:
                            continue
                        if msg_dt < d_from:
                            break

                if msg.service or msg.empty:
                    continue

                has_media = bool(msg.photo or msg.video or msg.document or msg.audio or msg.voice or msg.animation or msg.sticker)
                is_text = bool(msg.text)
                has_caption = bool(msg.caption)

                if ctype == "media" and not has_media:
                    continue
                if ctype == "video" and not msg.video:
                    continue
                if ctype == "photo" and not msg.photo:
                    continue
                if ctype == "document" and not msg.document:
                    continue
                if ctype == "text" and not is_text:
                    continue
                if is_extract_mode and not (is_text or has_caption):
                    continue

                if skip_fwd and (msg.forward_from_chat or msg.forward_from or msg.forward_sender_name):
                    continue

                if is_extract_mode:
                    txt = msg.text or msg.caption or ""
                    h = f"text_{hashlib.md5(txt.strip().encode('utf-8')).hexdigest()}" if txt.strip() else None
                else:
                    h = compute_quick_hash(msg)

                if skip_dup and h:
                    if is_hash_copied(user_id, h) or (h in seen_hashes):
                        skipped_dup += 1
                        continue
                    seen_hashes.add(h)

                if h:
                    msg_hash_map[msg.id] = h

                messages.append(msg.id)
                fetch_count += 1
                now = time.time()
                if now - last_fetch_edit >= 3.0:
                    last_fetch_edit = now
                    try:
                        dup_info = f"\n⏭️ Duplicates skipped: <b>{skipped_dup}</b>" if skipped_dup > 0 else ""
                        await bot.edit_message_text(
                            f"⏳ <b>Scanning messages ({range_cfg.get('label')})...</b>\nFound <b>{fetch_count}</b> matching messages so far...{dup_info}\nScanning at MTProto speed...",
                            chat_id,
                            prog_msg.message_id,
                            reply_markup=stop_kb,
                            parse_mode="HTML"
                        )
                    except Exception:
                        pass
        except Exception as e:
            await bot.send_message(chat_id, f"❌ Error reading source: {e}")
            return

        messages.reverse()
        total = len(messages)
        if total == 0:
            dup_note = f" (⏭️ {skipped_dup} duplicate messages skipped)" if skipped_dup > 0 else ""
            return await bot.send_message(chat_id, f"⚠️ Source chat has no copyable messages matching your filter (<b>{CONTENT_TYPE_LABELS.get(ctype)}</b>) and range!{dup_note}", parse_mode="HTML")

        # Save initial checkpoint
        save_checkpoint(user_id, src, dst, src_title, dst_title, total, 0, 0, skipped_dup, range_cfg.get('label', ''), ctype, settings, is_protected, messages, msg_hash_map)

    # Resolve peers once
    try:
        from_peer = await u_client.resolve_peer(src)
    except Exception:
        try:
            await u_client.get_chat(src)
            from_peer = await u_client.resolve_peer(src)
        except Exception as e:
            return await bot.send_message(chat_id, f"❌ Error resolving source chat: {e}")

    try:
        to_peer = await u_client.resolve_peer(dst)
    except Exception:
        try:
            await u_client.get_chat(dst)
            to_peer = await u_client.resolve_peer(dst)
        except Exception as e:
            return await bot.send_message(chat_id, f"❌ Error resolving destination chat: {e}")

    user_task_info[user_id] = {
        "src_title": src_title,
        "dst_title": dst_title,
        "count": count,
        "total": total
    }

    has_mods = has_caption_modifications(settings)
    is_extract_mode = (settings.get("extract_text", False) or ctype == "text_extract") and (ctype != "media") and not settings.get("strip_caption", False)

    if is_protected:
        mode_label = "Parallel Bypass (3x)"
    elif is_extract_mode:
        mode_label = "Caption Extraction (3x)"
    elif has_mods:
        mode_label = "Caption Processor (3x)"
    else:
        mode_label = "100× MTProto Batching"

    # Batch parameters and rate limit pacing
    BATCH_SIZE = 15
    SAFE_DELAY = 1.2  # Safe baseline pacing (~12 msg/s max bulk throughput)
    clean_batches = 0
    total_batches = (total + BATCH_SIZE - 1) // BATCH_SIZE
    msgs_since_cooldown = 0

    job_state = {
        "count": count,
        "batch_num": (start_index // BATCH_SIZE) + 1,
        "total_batches": total_batches,
        "current_batch_size": min(BATCH_SIZE, total - count),
        "status_note": "🚀 Starting copy...",
        "mode_label": mode_label
    }

    copy_done_event = asyncio.Event()
    last_rendered_text = ""
    last_edit_time = 0

    def format_time(secs):
        m, s = divmod(int(secs), 60)
        return f"{m:02d}:{s:02d}"

    def build_progress_card():
        cur = job_state["count"]
        tot = total
        percent = (cur / tot) * 100 if tot > 0 else 0
        filled = min(10, int(percent / 10))
        bar = "▰" * filled + "▱" * (10 - filled)

        now = time.time()
        elapsed = max(0.1, now - start_time)
        speed = round((cur - (resume_cp["copied_count"] if resume_cp else 0)) / elapsed, 1)
        remaining = max(0, tot - cur)

        if speed > 0 and remaining > 0:
            eta_secs = int(remaining / speed)
            eta_m, eta_s = divmod(eta_secs, 60)
            eta_str = f"{eta_m}m {eta_s}s" if eta_m > 0 else f"{eta_s}s"
        elif remaining == 0:
            eta_str = "Done"
        else:
            eta_str = "--"

        b_num = job_state["batch_num"]
        b_tot = job_state["total_batches"]
        b_size = job_state["current_batch_size"]

        dup_line = f"\n⏭️ <b>Duplicates Skipped:</b> {skipped_dup}" if skipped_dup > 0 else ""
        note = job_state.get("status_note", "")
        note_line = f"\n<i>{note}</i>" if note else ""

        text = (
            f"⚡ <b>{job_state['mode_label']}</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🔹 <b>From:</b> {src_title}\n"
            f"🔸 <b>To:</b> {dst_title}\n"
            f"📄 <b>Filter:</b> {CONTENT_TYPE_LABELS.get(ctype)}\n\n"
            f"{bar} <b>{percent:.2f}%</b>\n"
            f"Copied: <b>{cur}/{tot}</b> messages{dup_line}\n"
            f"🚀 <b>Batch:</b> {b_num}/{b_tot} ({b_size} msgs)\n\n"
            f"⏱️ <b>Elapsed:</b> {format_time(elapsed)}   ⚡ <b>Speed:</b> {speed} msg/s\n"
            f"⏳ <b>ETA:</b> ~{eta_str}\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            f"{note_line}"
        )
        return text

    async def do_ui_render(force=False):
        nonlocal last_rendered_text, last_edit_time
        now = time.time()
        if not force and (now - last_edit_time < 1.8):
            return
        text = build_progress_card()
        if text != last_rendered_text or force:
            last_rendered_text = text
            last_edit_time = now
            try:
                await bot.edit_message_text(
                    text,
                    chat_id,
                    prog_msg.message_id,
                    reply_markup=stop_kb,
                    parse_mode="HTML"
                )
            except Exception:
                pass

    async def heartbeat_worker():
        while not copy_done_event.is_set():
            if not active_tasks.get(user_id, True):
                break
            user_task_info[user_id]["count"] = job_state["count"]
            await do_ui_render()
            try:
                await asyncio.sleep(2.0)
            except asyncio.CancelledError:
                break

    heartbeat_task = asyncio.create_task(heartbeat_worker())
    stopped_by_user = False

    try:
        await do_ui_render(force=True)

        for i in range(start_index, total, BATCH_SIZE):
            if not active_tasks.get(user_id, True):
                stopped_by_user = True
                break

            batch = messages[i:i + BATCH_SIZE]
            batch_num = (i // BATCH_SIZE) + 1
            job_state["batch_num"] = batch_num
            job_state["current_batch_size"] = len(batch)
            job_state["status_note"] = f"🚀 Batch {batch_num}/{total_batches} ({len(batch)} msgs)..."

            # Adaptive anti-ban pacing: apply extended breather if account hit recent FloodWaits
            recent_fw = len([t for t in user_floodwait_timestamps.get(user_id, []) if time.time() - t <= 600])
            cooldown_thresh = 500 if recent_fw > 0 else 1000
            cooldown_duration = 20 if recent_fw > 0 else 3

            if msgs_since_cooldown >= cooldown_thresh:
                msgs_since_cooldown = 0
                if cooldown_duration > 5:
                    job_state["status_note"] = f"🛡️ Anti-ban cooldown: {cooldown_duration}s breather (account hot)..."
                    start_cd = time.time()
                    while time.time() - start_cd < cooldown_duration:
                        if not active_tasks.get(user_id, True):
                            stopped_by_user = True
                            break
                        rem_cd = int(cooldown_duration - (time.time() - start_cd))
                        job_state["status_note"] = f"🛡️ Anti-ban cooldown: resting {rem_cd}s safely..."
                        await do_ui_render()
                        await asyncio.sleep(min(2.0, max(0.1, rem_cd)))

                    if stopped_by_user or not active_tasks.get(user_id, True):
                        stopped_by_user = True
                        break
                else:
                    # Healthy account: quick 3s pacing pause without disrupting high throughput
                    job_state["status_note"] = "🛡️ Pacing check (3s)..."
                    await do_ui_render()
                    await asyncio.sleep(3.0)

            batch_success = False
            has_mods = has_caption_modifications(settings)
            drop_tag = settings.get("drop_forward_tag", True)

            # If NOT protected AND NO custom caption modifications, use ForwardMessages with robust FloodWait retry loop
            if not is_protected and not has_mods:
                max_fw_attempts = 3
                for fw_attempt in range(max_fw_attempts):
                    if not active_tasks.get(user_id, True):
                        stopped_by_user = True
                        break
                    try:
                        await u_client.invoke(
                            functions.messages.ForwardMessages(
                                to_peer=to_peer,
                                from_peer=from_peer,
                                id=batch,
                                drop_author=drop_tag,
                                random_id=[u_client.rnd_id() for _ in batch]
                            )
                        )
                        count += len(batch)
                        msgs_since_cooldown += len(batch)
                        clean_batches += 1
                        if clean_batches >= 4:
                            clean_batches = 0
                            SAFE_DELAY = max(1.1, round(SAFE_DELAY * 0.96, 2))  # Gradually recover towards baseline safe speed
                        job_state["count"] = count
                        batch_success = True

                        # Update persistent checkpoint progress (lightweight O(1))
                        update_checkpoint_progress(user_id, count, i + len(batch), skipped_dup)

                        batch_hashes = [msg_hash_map[m] for m in batch if m in msg_hash_map]
                        if batch_hashes:
                            record_copied_hashes_batch(user_id, src, batch_hashes)

                        logger.info(f"Forwarded batch of {len(batch)} messages ({count}/{total})")
                        job_state["status_note"] = f"✅ Batch {batch_num}/{total_batches} completed"
                        await do_ui_render()
                        # Anti-metronome random jitter (0.10s - 0.35s)
                        batch_jitter = 0.10 + (secrets.randbelow(26) / 100.0)
                        await asyncio.sleep(SAFE_DELAY + batch_jitter)
                        break  # Forward success, exit retry loop!

                    except PeerFlood:
                        # Account-level action restriction detected: halt immediately to prevent ban
                        active_tasks[user_id] = False
                        mark_peerflood_blocked(user_id, hours=24)
                        save_checkpoint(user_id, src, dst, src_title, dst_title, total, count, i, skipped_dup, "", ctype, settings, is_protected, messages, msg_hash_map)
                        logger.error(f"PeerFlood restriction detected on account {user_id}. Immediate halt.")
                        await bot.send_message(
                            chat_id,
                            "🚨 <b>Critical Safety Alert: Telegram PeerFlood Detected</b>\n\n"
                            "Telegram has placed a temporary outbound restriction on this account.\n"
                            "⚠️ <b>Account Protection Active:</b> Copying was stopped immediately to prevent account penalties.\n"
                            f"🛡️ <b>Checkpoint Saved:</b> Progress ({count}/{total}) is safely stored.\n"
                            "⏳ Please allow the account to rest for <b>12–24 hours</b> before resuming.",
                            parse_mode="HTML"
                        )
                        return

                    except FloodWait as e:
                        clean_batches = 0
                        wait_time = e.value + 5  # 5s safety buffer
                        record_floodwait_event(user_id)
                        logger.warning(f"Batch forward FloodWait (attempt {fw_attempt+1}/{max_fw_attempts}): waiting {wait_time}s")

                        # Dynamic Rate Limiter: 3+ FloodWaits in 1 hour triggers Auto-Safety Stop
                        recent_fws = len([t for t in user_floodwait_timestamps.get(user_id, []) if time.time() - t <= 3600])
                        if recent_fws >= 3:
                            active_tasks[user_id] = False
                            save_checkpoint(user_id, src, dst, src_title, dst_title, total, count, i, skipped_dup, "", ctype, settings, is_protected, messages, msg_hash_map)
                            await bot.send_message(
                                chat_id,
                                f"🛑 <b>Safety Pause: High FloodWait Activity</b>\n\n"
                                f"Detected <b>{recent_fws} FloodWaits</b> within the past hour.\n"
                                "Copying has been paused to protect your account standing.\n\n"
                                f"🛡️ <b>Checkpoint saved at {count}/{total} messages.</b>\n"
                                "Allow the account to rest, then resume anytime from the dashboard.",
                                parse_mode="HTML"
                            )
                            return

                        # Adaptive backoff on FloodWait: increase SAFE_DELAY by 40% (ceiling 4.5s)
                        SAFE_DELAY = min(4.5, round(SAFE_DELAY * 1.4, 2))

                        # If unusually long FloodWait (> 300s), notify user
                        if wait_time > 300:
                            mins, secs = divmod(wait_time, 60)
                            try:
                                await bot.send_message(
                                    chat_id,
                                    f"⏳ <b>Telegram FloodWait ({mins}m {secs}s)</b>\n\n"
                                    f"Telegram has requested a wait period.\n"
                                    f"🛡️ <b>Checkpoint is safely saved at {count}/{total} messages.</b>\n\n"
                                    f"• Bot is resting safely in background.\n"
                                    f"• Or you can tap <b>Stop Copying</b> and resume anytime later!",
                                    parse_mode="HTML"
                                )
                            except Exception:
                                pass

                        # Responsive chunked sleep (2s chunks) so user can Stop anytime
                        start_wait = time.time()
                        while time.time() - start_wait < wait_time:
                            if not active_tasks.get(user_id, True):
                                stopped_by_user = True
                                break
                            rem_wait = int(wait_time - (time.time() - start_wait))
                            rem_m, rem_s = divmod(rem_wait, 60)
                            rem_str = f"{rem_m}m {rem_s:02d}s" if rem_m > 0 else f"{rem_s}s"
                            job_state["status_note"] = f"⏳ FloodWait: resting {rem_str} safely..."
                            await do_ui_render()
                            await asyncio.sleep(min(2.0, max(0.1, rem_wait)))

                        if stopped_by_user or not active_tasks.get(user_id, True):
                            stopped_by_user = True
                            break
                        continue

                    except Exception as e:
                        err_str = str(e)
                        if "PEER_FLOOD" in err_str or "420" in err_str:
                            active_tasks[user_id] = False
                            mark_peerflood_blocked(user_id, hours=24)
                            save_checkpoint(user_id, src, dst, src_title, dst_title, total, count, i, skipped_dup, "", ctype, settings, is_protected, messages, msg_hash_map)
                            await bot.send_message(
                                chat_id,
                                "🚨 <b>Safety Alert: PeerFlood Error</b> Telegram account restricted. Copying stopped.",
                                parse_mode="HTML"
                            )
                            return
                        logger.warning(f"Batch forward failed ({e}). Switching to parallel fallback.")
                        batch_success = False
                        break

            # If protected, or custom caption modifications, or batch forward failed: run high-speed parallel workers
            if not batch_success and active_tasks.get(user_id, True):
                if preflight_protected:
                    is_protected = True

                is_extract_mode = (settings.get("extract_text", False) or ctype == "text_extract") and (ctype != "media") and not settings.get("strip_caption", False)
                if is_protected:
                    job_state["mode_label"] = "Parallel Bypass (3x)"
                    job_state["status_note"] = "Downloading & re-uploading media..."
                elif is_extract_mode:
                    job_state["mode_label"] = "Caption Extraction (3x)"
                    job_state["status_note"] = "Extracting captions as text..."
                else:
                    job_state["mode_label"] = "Caption Processor (3x)"
                    job_state["status_note"] = "Processing custom captions..."

                sem = asyncio.Semaphore(3)
                batch_collected_hashes = []

                async def _copy_one(mid):
                    nonlocal count, msgs_since_cooldown
                    async with sem:
                        if not active_tasks.get(user_id, True):
                            return 0
                        try:
                            # Safe jittered pacing before per-message operation (1.0s - 1.25s)
                            await asyncio.sleep(1.0 + (secrets.randbelow(26) / 100.0))
                            ok = await copy_single_message(
                                u_client, dst, src, mid,
                                src_title=src_title,
                                is_protected=is_protected,
                                settings=settings
                            )
                            if ok:
                                count += 1
                                msgs_since_cooldown += 1
                                job_state["count"] = count
                                mid_h = msg_hash_map.get(mid)
                                if mid_h:
                                    batch_collected_hashes.append(mid_h)
                                job_state["status_note"] = f"✅ Copied msg {mid} ({count}/{total})"
                                await do_ui_render()
                                return 1
                            else:
                                logger.warning(f"Message {mid} skipped or copy failed")
                                return 0
                        except Exception as ex:
                            logger.error(f"Parallel copy failed for msg {mid}: {type(ex).__name__}: {ex}")
                            return 0

                await asyncio.gather(*[_copy_one(m) for m in batch], return_exceptions=False)

                # Commit deduplication hashes in bulk per batch
                if batch_collected_hashes:
                    record_copied_hashes_batch(user_id, src, batch_collected_hashes)

                # Update checkpoint progress (lightweight O(1))
                update_checkpoint_progress(user_id, count, i + len(batch), skipped_dup)

                # Safe rate limit delay after bypass batch with jitter
                fallback_jitter = 0.10 + (secrets.randbelow(26) / 100.0)
                await asyncio.sleep(SAFE_DELAY + fallback_jitter)
                await do_ui_render()

    finally:
        copy_done_event.set()
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass

    active_tasks[user_id] = False
    duration_sec = time.time() - start_time
    failed_count = max(0, total - count)
    speed = round(count / max(duration_sec, 0.1), 1)

    record_job_stats(user_id, src_title, dst_title, total, count, skipped_dup, failed_count, duration_sec)

    if stopped_by_user:
        # Checkpoint is kept so user can resume anytime!
        try:
            await bot.edit_message_text(
                f"🛑 <b>Copying paused/stopped!</b>\nProgress saved at <b>{count}/{total}</b> messages.\nYou can resume anytime from the dashboard.",
                chat_id,
                prog_msg.message_id,
                reply_markup=None,
                parse_mode="HTML"
            )
        except Exception:
            pass
        kb = InlineKeyboardMarkup()
        kb.add(InlineKeyboardButton(f"▶️ Resume Copying ({count}/{total})", callback_data="resume_checkpoint"))
        kb.add(InlineKeyboardButton("🏠 Back to Dashboard", callback_data="nav_home"))
        await bot.send_message(chat_id, f"🛑 <b>Copy job paused!</b>\nSuccessfully copied {count}/{total} messages.\nCheckpoint is safely saved.", reply_markup=kb, parse_mode="HTML")
        return

    # Job completely finished -> clear checkpoint
    delete_checkpoint(user_id)

    done_kb = InlineKeyboardMarkup()
    done_kb.row(
        InlineKeyboardButton("📊 View Analytics", callback_data="nav_analytics"),
        InlineKeyboardButton("🏠 Dashboard", callback_data="nav_home")
    )
    try:
        await bot.edit_message_text(
            f"✅ <b>Copy Completed!</b>\n▰▰▰▰▰▰▰▰▰▰ 100.00%\nSuccessfully copied <b>{count}/{total}</b> messages.",
            chat_id,
            prog_msg.message_id,
            reply_markup=None,
            parse_mode="HTML"
        )
    except Exception:
        pass

    summary_text = (
        "🎉 <b>Job Finished Successfully!</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔹 <b>From:</b> {src_title}\n"
        f"🔸 <b>To:</b> {dst_title}\n"
        f"📄 <b>Filter:</b> {CONTENT_TYPE_LABELS.get(ctype)}\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📦 <b>Total Scanned:</b> {total}\n"
        f"✅ <b>Successfully Copied:</b> {count}\n"
        f"⏭️ <b>Duplicates Skipped:</b> {skipped_dup}\n"
        f"❌ <b>Failed / Incomplete:</b> {failed_count}\n"
        f"⏱️ <b>Duration:</b> {duration_sec:.1f}s\n"
        f"⚡ <b>Average Speed:</b> {speed} msg/s\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )
    await bot.send_message(chat_id, summary_text, reply_markup=done_kb, parse_mode="HTML")

# Application Entry Point

async def main():
    await init_saved_clients()
    logger.info("Bot started polling via Telegram Bot API...")
    await bot.polling(non_stop=True)

if __name__ == "__main__":
    asyncio.run(main())
