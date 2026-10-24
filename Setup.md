# Telegram Channel Copier Bot - Setup Guide

This bot allows you to copy all messages from any Telegram channel or group to another with **100× MTProto Batching**, maintaining the exact original order.

## Features
- **⚡ 100× Ultra-Fast Batch Mode**: Forwards up to 100 messages in a single MTProto API call without the "Forwarded from" header (`drop_author=True`).
- **🛡️ Built-in Anti-Ban Safeguards**: Paced batch delays, 5-second automatic breathers every 2,000 messages, and strict `FloodWait` compliance.
- **🔄 Robust Fallback**: If a batch encounters restricted/pinned messages, it gracefully falls back to per-message copies so nothing is lost.
- **In-Chat Login**: Login securely via the bot without touching the code.
- **Persistent Sessions**: Your login session is saved so you only log in once.
- **Smart Search**: Type a channel's name to quickly filter through your chats with rate-limit-safe progress tracking.
- **Live Progress**: Throttled real-time progress bar preventing Telegram Bot API `429 Too Many Requests`.
- **Stop Button**: Cancel copy operations instantly.

---

## Prerequisites
1. Python 3.8+ installed on your system.
2. A Telegram Bot Token from [@BotFather](https://t.me/BotFather).
3. Your Telegram API ID and API HASH from [my.telegram.org](https://my.telegram.org).

---

## Installation

**1. Clone or download this project folder.**

**2. Install dependencies:**
Install the required Python libraries using pip:
```bash
pip install -r requirements.txt
```
*(Packages installed: `pyrogram`, `tgcrypto`, `pyTelegramBotAPI`)*

**3. Configure your .env file:**
Create a `.env` file in the same directory as `bot.py` (if it doesn't already exist) and add your Bot Token:
```env
BOT_TOKEN=your:bot_token_here
```

*(Note: API ID and API HASH are not needed in this file; you will provide them securely inside the bot chat!)*

---

## Running the Bot

Start the bot by running:
```bash
python bot.py
```
You should see: `Bot is polling via HTTP...` in your terminal.

---

## How to Use
1. Open your bot in Telegram and send `/start`.
2. Click **Login** and follow the prompt:
   - Send your **API ID**.
   - Send your **API HASH**.
   - Send your **Phone Number** (with country code, e.g., `+91...`).
   - Telegram will send you an OTP. **Important:** Send it with spaces (e.g., `1 2 3 4 5`) to prevent Telegram's security from expiring it.
   - Enter your 2FA password (if enabled).
3. Once logged in, the bot will show a list of your chats. 
4. Select the **SOURCE** chat (or type its name to search).
5. Select the **DESTINATION** chat.
6. The bot will begin fetching and 100× batch copying! You can click the 🛑 Stop button at any time.

## Commands
- `/start` - Launch the bot and view chats.
- `/help` - View usage instructions.
- `/logout` - Securely log out and clear your session data.
