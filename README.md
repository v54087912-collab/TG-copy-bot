# Telegram Channel Copier Bot

An enterprise-grade, high-performance asynchronous Telegram channel cloner and forwarder. Built with Python using **Pyrogram (MTProto API)** for user-account cloning and **AsyncTeleBot (Telegram Bot API)** for an intuitive, interactive inline interface.

---

## Key Highlights

- **100× MTProto Batching**: Clones up to 100 messages in a single raw MTProto call with author headers stripped (`drop_author=True`).
- **Protected Content Bypass**: Automatically detects restricted channels (`has_protected_content`) and falls back to a 3-worker parallel download/re-upload engine.
- **Resumable Checkpoints**: Interrupted or stopped jobs save their exact state to SQLite, allowing instant resumption without re-scanning history.
- **Deduplication Engine**: Uses SHA-256 and Telegram `file_unique_id` hashing to prevent duplicate posts across runs.
- **Comprehensive Text Manipulation**: Sequential find & replace, auto-cleaning (links, mentions, hashtags), and header/footer templates with variable expansion.
- **4-Layer Anti-Ban Architecture**: Multi-level rate limiting, adaptive cooldown breathers, anti-metronome random jitter, and automatic FloodWait/PeerFlood protection.
- **Encrypted Session Storage**: AES-256 CTR + HMAC-SHA256 authenticated encryption for session credentials at rest.
- **In-Chat Proxy Manager**: Support for HTTP, SOCKS4, and SOCKS5 proxies with live latency ping checks and automatic direct fallback.

---

## Architecture Overview

```
                      +-----------------------------+
                      |      Telegram Bot Chat      |
                      |    (Interactive User UI)    |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |   AsyncTeleBot Controller   |
                      |  - Inline Menus & Keyboards |
                      |  - Throttled Progress Cards |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |   Pyrogram MTProto Client   |
                      |    (User Account Session)   |
                      +--------------+--------------+
                                     |
                 +-------------------+-------------------+
                 |                                       |
                 v                                       v
    [Standard Channels]                     [Protected Channels / Custom Text]
+--------------------------+               +---------------------------------+
| 100x MTProto Batch Mode  |               |  Parallel Bypass Engine (3x)    |
| - ForwardMessages RPC    |               |  - download_media to temp disk  |
| - drop_author=True       |               |  - Apply caption & text rules   |
| - High-throughput pacing |               |  - Upload & unlink temp media   |
+------------+-------------+               +----------------+----------------+
             |                                              |
             +-----------------------+----------------------+
                                     |
                                     v
                      +-----------------------------+
                      | 4-Layer Anti-Ban Protection |
                      | - 1.1s chat rate limiter    |
                      | - Anti-metronome jitter     |
                      | - Adaptive flood breathers  |
                      | - PeerFlood safety lock     |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |   Destination Chat/Channel  |
                      +-----------------------------+
```

---

## Features In Detail

### 1. Dual-Engine Copying Pipeline
* **High-Speed Batch Forwarding**: Uses `pyrogram.raw.functions.messages.ForwardMessages` passing chunks of up to 100 message IDs. Strips forwarding attribution headers so messages appear clean in the destination chat.
* **Parallel Media Bypass**: For channels with content restrictions or jobs with custom caption rules, the bot spawns a 3-worker concurrency pool (`asyncio.Semaphore(3)`). Media is securely downloaded to temporary storage, modified, uploaded, and immediately unlinked.

### 2. Flexible Range Selection
* **All Messages**: Clones the entire history of the source channel from oldest to newest.
* **Quick Presets**: Select the latest **100**, **500**, or **1,000** messages.
* **Message ID Range**: Specify custom boundaries (e.g., `100 -> 500` or `1250`).
* **Date Range**: Filter messages published within a calendar range (e.g., `2024-01-01 -> 2024-06-30` or `2024-05-01`).

### 3. Content Filters & Text Extraction
* **Content Filtering**: Filter messages by type:
  * All Content
  * Media Only (Photos, Videos, Audio, Documents, Stickers, Animations)
  * Videos Only
  * Photos Only
  * Documents/Files Only
  * Text Only
* **Caption Extraction**: Extract captions from media messages and post them as standalone text messages, skipping the heavy media download entirely.

### 4. Caption & Text Transformation Rules
* **Find & Replace**: Define sequential, case-insensitive find-and-replace rules (e.g., replace `@oldchannel` with `@newchannel`).
* **Auto-Sanitization**:
  * Strip web links and URLs (`http://`, `https://`, `t.me/`).
  * Strip user mentions (`@username`).
  * Strip hashtags (`#tag`).
* **Header & Footer Templates**: Prepend custom headers or append custom footers to every message. Supports dynamic variable replacement:
  * `{channel}` is automatically replaced with the source channel name.
  * Preserves message length constraints (1,024 characters for media captions, 4,096 for text).

### 5. Multi-Layer Anti-Ban & Health Safeguards
* **Chat Rate Limiter**: Enforces a minimum interval of 1.1 seconds between posts to the same destination chat, adhering to Telegram's 1 message/second limit.
* **Adaptive Cooldown Breathers**: Every 500–1,000 messages, the bot automatically takes a breather (3 seconds if account standing is clean, 20 seconds if FloodWaits occurred recently).
* **Anti-Metronome Random Jitter**: Injects randomized micro-delays (0.10s–0.35s) between operations to prevent automated traffic detection.
* **FloodWait Handling**: Multiplies safe delay by 1.4× upon encountering rate limits. Pauses safely and saves a checkpoint if 3 or more FloodWaits occur within one hour.
* **PeerFlood Protection**: Automatically catches outbound spam restrictions (`PeerFlood`), immediately halts copying, triggers a 24-hour safety cooldown, and saves state to prevent account bans.

### 6. Resumable Checkpoints & State Persistence
* Checkpoints are committed to SQLite (`stats.db`). If a job is manually stopped, encounters network failure, or hits a rate limit, users can resume with a single tap from the dashboard—without scanning history again.

### 7. Proxy Management Engine
* Configure custom proxies per user directly from the bot UI.
* Supports `HTTP`, `HTTPS`, `SOCKS4`, and `SOCKS5` protocols with username/password authentication.
* Features a built-in ping test to verify proxy reachability and latency before running jobs.
* Automatically falls back to a direct connection if an active proxy drops during startup.

---

## Prerequisites

Before starting, ensure you have:
1. **Python 3.8+** installed on Linux, macOS, or Windows.
2. A **Telegram Bot Token** from [@BotFather](https://t.me/BotFather).
3. Your **API ID** and **API HASH** from [my.telegram.org](https://my.telegram.org) (used during in-chat login).

---

## Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/telegram-copier-bot.git
cd telegram-copier-bot/telegram_copier_bot
```

### 2. Create and Activate a Virtual Environment
```bash
# Linux / macOS
python3 -m venv venv
source venv/bin/activate

# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

*Installed libraries:*
* `pyrogram` — Asynchronous MTProto Telegram client library.
* `tgcrypto` — Fast C-extensions for Telegram MTProto encryption/decryption.
* `pyTelegramBotAPI` — AsyncTeleBot framework for Bot API interaction.
* `pysocks` — SOCKS proxy support for MTProto connections.
* `pyaes` — Cryptographic engine for credential database encryption.

### 4. Configure Environment Variables
Create a `.env` file in the same directory as `bot.py`:

```env
BOT_TOKEN=1234567890:ABCdefGhIJKlmNoPQRsTUVwxyZ_example
```

> **Note**: Do not add your personal API ID or API Hash to `.env`. You will enter those securely inside the Telegram chat during the interactive login wizard. On first launch, the bot automatically generates an AES-256 encryption key and appends `DB_ENCRYPTION_KEY` to `.env`.

### 5. Run the Bot
```bash
python bot.py
```

When started, the bot logs:
```text
2026-10-24 12:00:00 [INFO] telegram_copier: Bot started polling via Telegram Bot API...
```

---

## User Guide: Step-by-Step Walkthrough

### Step 1: Initialize the Bot
1. Open your bot in Telegram and send `/start`.
2. Click **Start Login** to begin the authentication wizard.

### Step 2: In-Chat Login
Follow the 4-step wizard:
1. **API ID**: Enter your numeric Telegram API ID.
2. **API HASH**: Enter your 32-character API Hash string.
3. **Phone Number**: Send your phone number in international format (e.g., `+1234567890`).
4. **OTP Code**: Send the login code sent by Telegram.  
   > **Important**: Send the code with spaces between digits (e.g., `1 2 3 4 5`) to prevent Telegram from auto-expiring it.
5. **2FA Password**: If Two-Step Verification is enabled on your account, enter your cloud password when prompted.

Once verified, your session string is encrypted with AES-256 and saved in `db.json`. You will not need to log in again on future bot restarts.

### Step 3: Select Source Chat
1. Tap **Select SOURCE Chat** from the dashboard.
2. Choose from your dialog list using pagination buttons (`Prev`, `Next`), or type a channel username (e.g., `@example_channel`), private invite link (`t.me/+...`), or numeric chat ID directly in chat.

### Step 4: Select Destination Chat
1. Tap **Select DESTINATION Chat**.
2. Select your target channel, group, or **Saved Messages** 🔖.

### Step 5: Configure Message Range
Choose one of the following:
* **All Messages**: Copy the complete history.
* **Last 100 / 500 / 1000 Messages**: Quick slice from the latest post backwards.
* **Custom ID Range**: Send `min_id -> max_id` (e.g., `500 -> 1500`).
* **Custom Date Range**: Send `YYYY-MM-DD -> YYYY-MM-DD` (e.g., `2024-01-01 -> 2024-06-30`).

### Step 6: Configure Settings & Filters (Optional)
Tap **Advanced Settings & Filters** to adjust:
* **Content Filter**: All, Media Only, Video, Photo, Document, Text, or Extract Captions.
* **Skip Forwarded**: Exclude forwarded messages from other chats.
* **Forward Attribution**: Toggle whether to keep or remove the original author header.
* **Deduplication**: Toggle SHA-256 duplicate skipping.
* **Caption Rules**: Set find-and-replace rules, header/footer templates, or strip links/mentions/hashtags.

### Step 7: Start & Monitor the Copy Job
1. Tap **Start Copying** to begin.
2. The bot runs pre-flight safety checks (verifies write permissions, content protection status, and account health).
3. A live progress card displays elapsed time, ETA, speed (msgs/sec), duplicate count, and batch status.
4. Tap **Stop Copying 🛑** at any time to pause safely and write a checkpoint.

---

## Production Deployment (Linux VPS / systemd)

To keep the bot running 24/7 on a Linux server, configure a `systemd` service:

### 1. Create a Service File
```bash
sudo nano /etc/systemd/system/telegram-copier.service
```

### 2. Paste the Service Configuration
```ini
[Unit]
Description=Telegram Channel Copier Bot Service
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/telegram_copier_bot
ExecStart=/home/ubuntu/telegram_copier_bot/venv/bin/python bot.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### 3. Enable and Start the Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable telegram-copier
sudo systemctl start telegram-copier
```

### 4. Monitor Live Logs
```bash
sudo journalctl -u telegram-copier -f
```

---

## File and Storage Structure

```
telegram_copier_bot/
├── bot.py             # Main application logic and handlers
├── requirements.txt   # Python package dependencies
├── .env               # BOT_TOKEN and auto-generated DB_ENCRYPTION_KEY
├── db.json            # AES-256 CTR + HMAC-SHA256 encrypted user sessions
├── db.json.bak        # Automatic backup of session database
├── dedup.db           # SQLite database for SHA-256 deduplication hashes
└── stats.db           # SQLite database for job checkpoints & daily analytics
```

### Database Schemas (SQLite WAL Mode)

#### `dedup.db`
```sql
CREATE TABLE copied_hashes (
    user_id INTEGER,
    src_chat_id INTEGER,
    file_hash TEXT,
    copied_at REAL,
    PRIMARY KEY (user_id, file_hash)
);
```

#### `stats.db`
```sql
-- Job Performance Metrics
CREATE TABLE job_stats (
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
);

-- Daily Telemetry
CREATE TABLE daily_stats (
    user_id INTEGER,
    date_str TEXT,
    messages_copied INTEGER,
    jobs_completed INTEGER,
    PRIMARY KEY (user_id, date_str)
);

-- Checkpoint State Machine
CREATE TABLE job_checkpoints (
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
);
```

---

## Frequently Asked Questions

#### Q: How does the bot bypass Telegram's content restriction?
When a channel has `has_protected_content` enabled (forwarding and saving disabled), standard forwarding fails. The bot automatically switches to parallel download mode: it downloads the media using your user account session, writes it to temporary storage, uploads it as a clean new message to your destination channel, and immediately unlinks the temporary file.

#### Q: Will using this bot get my Telegram account banned?
The bot is engineered with strict defensive safeguards:
- Hard 1.1-second minimum spacing per target chat.
- Adaptive cooldown breathers every 500–1,000 messages.
- Anti-metronome jitter to prevent bot fingerprinting.
- Automatic halt and 24-hour lockout if `PeerFlood` is detected.
- Cooldown pause if 3+ `FloodWait` events occur within one hour.

To maintain account health, avoid running concurrent high-volume jobs on brand new Telegram accounts.

#### Q: How do I switch or test a proxy?
From the main menu, navigate to **Proxy Settings 🌐** -> **Add Proxy**. Paste your proxy string (`socks5://user:pass@host:port` or `http://host:port`). Use the **Test Ping** button to measure round-trip latency, then tap **Use** to route your MTProto connection through that proxy.

#### Q: Where are downloaded files stored during bypass?
Media files are temporarily downloaded to the local directory, streamed to the destination chat, and immediately removed in a `finally` block to prevent disk bloat.

---

## Commands Reference

| Command | Description |
| :--- | :--- |
| `/start` | Launch the interactive dashboard, view chats, or resume checkpoints |
| `/help` | Display usage instructions and setup tips |
| `/logout` | Disconnect the active Pyrogram client and wipe encrypted session data |

---

## Disclaimer

This project is intended for legitimate backup, archiving, and channel migration purposes. Ensure you have the necessary rights or permissions from channel owners before cloning or redistributing content. Adhere to Telegram's Terms of Service and API usage guidelines.
