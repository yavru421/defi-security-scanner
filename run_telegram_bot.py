#!/usr/bin/env python3
"""
Run script for DeFi Security Scanner Telegram Bot
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Check for required environment variables
if not os.getenv('TELEGRAM_BOT_TOKEN'):
    print("❌ Error: TELEGRAM_BOT_TOKEN environment variable not set!")
    print("Please create a .env file with your bot token:")
    print("TELEGRAM_BOT_TOKEN=your_bot_token_from_botfather")
    sys.exit(1)

# Import and run the bot
from defi_security_telegram_bot import main

if __name__ == "__main__":
    main()