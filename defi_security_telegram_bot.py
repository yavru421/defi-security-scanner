#!/usr/bin/env python3
"""
DeFi Security Scanner Telegram Bot
Telegram interface for the DeFi Security Scanner service
"""

import os
import sys
import asyncio
import logging
from typing import Dict, Any
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

# APT Strict Mode
import strict_mode  # noqa: F401

from defi_security_scanner import DeFiSecurityService

class DeFiSecurityTelegramBot:
    """Telegram bot for DeFi Security Scanner service"""

    def __init__(self, token: str):
        self.token = token
        self.service = DeFiSecurityService()
        self.logger = logging.getLogger("DeFiSecurityTelegramBot")
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # User session data
        self.user_sessions: Dict[int, Dict[str, Any]] = {}

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Send a message when the command /start is issued."""
        user = update.effective_user
        self.logger.info(f"User {user.id} ({user.username}) started the bot")

        welcome_message = """
🛡️ *DeFi Security Scanner Bot*

Welcome to the professional DeFi security analysis service!

I can help you:
• 🔍 Scan smart contracts for vulnerabilities
• 💰 Check service pricing
• 📊 Get security reports
• 🔔 Monitor protocols for threats

*Commands:*
/scan - Start a security scan
/pricing - View service pricing
/help - Show this help message

Get started by sending me a smart contract address or use /scan for guided scanning.
        """

        keyboard = [
            [InlineKeyboardButton("🔍 Start Scan", callback_data="start_scan")],
            [InlineKeyboardButton("💰 View Pricing", callback_data="show_pricing")],
            [InlineKeyboardButton("📚 Help", callback_data="show_help")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text(
            welcome_message,
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Send a message when the command /help is issued."""
        help_text = """
🛡️ *DeFi Security Scanner Bot - Help*

*Available Commands:*
/start - Welcome message and main menu
/scan - Start a security scan
/pricing - View service pricing
/help - Show this help message

*How to use:*
1. Send a smart contract address (0x...)
2. Choose scan type (Basic/FULL/Monitoring)
3. Receive professional security report

*Example:*
Send: `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`
Or use /scan for step-by-step guidance

*Pricing:*
• Basic Scan: $500
• Full Audit: $2,500
• Monitoring: $1,000/month

For questions or support, contact our team.
        """

        await update.message.reply_text(help_text, parse_mode='Markdown')

    async def pricing_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Show service pricing"""
        pricing = self.service.get_service_pricing()

        pricing_text = f"""
💰 *DeFi Security Scanner Pricing*

*Services:*
• 🔍 Basic Scan: ${pricing['services']['basic_scan']}
• 📋 Full Audit: ${pricing['services']['full_audit']}
• 👀 Monitoring: ${pricing['services']['monitoring']}/month

*Features Included:*
• Automated vulnerability detection
• ERC-20 permit analysis
• Known threat database checks
• Professional security reports
• Ongoing monitoring options

*Currency:* {pricing['currency']}

Ready to secure your DeFi protocol? Use /scan to get started!
        """

        keyboard = [
            [InlineKeyboardButton("🔍 Start Scan", callback_data="start_scan")],
            [InlineKeyboardButton("📞 Contact Sales", url="https://t.me/defisecurity_support")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text(
            pricing_text,
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )

    async def scan_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Start the scanning process"""
        user_id = update.effective_user.id

        # Initialize user session
        self.user_sessions[user_id] = {
            "state": "waiting_for_address",
            "scan_data": {}
        }

        scan_message = """
🔍 *Start Security Scan*

Please send me the smart contract address you want to scan.

*Format:* `0x...` (Ethereum address)

*Example:* `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` (USDC)

After you send the address, I'll ask for:
1. Protocol name
2. Scan type (Basic/Full/Monitoring)
        """

        await update.message.reply_text(scan_message, parse_mode='Markdown')

    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle incoming messages"""
        user_id = update.effective_user.id
        message_text = update.message.text.strip()

        if user_id not in self.user_sessions:
            await self.handle_unknown_input(update, context)
            return

        session = self.user_sessions[user_id]
        state = session.get("state")

        if state == "waiting_for_address":
            await self.handle_address_input(update, message_text)
        elif state == "waiting_for_name":
            await self.handle_name_input(update, message_text)
        elif state == "waiting_for_scan_type":
            await self.handle_scan_type_input(update, message_text)
        else:
            await self.handle_unknown_input(update, context)

    async def handle_address_input(self, update: Update, address: str) -> None:
        """Handle smart contract address input"""
        user_id = update.effective_user.id

        # Basic address validation
        if not address.startswith("0x") or len(address) != 42:
            await update.message.reply_text(
                "❌ Invalid address format. Please send a valid Ethereum address starting with 0x"
            )
            return

        # Store address and move to next step
        self.user_sessions[user_id]["scan_data"]["address"] = address
        self.user_sessions[user_id]["state"] = "waiting_for_name"

        await update.message.reply_text(
            f"✅ Address received: `{address}`\n\n"
            "Now, please send me the protocol/token name.\n\n"
            "*Example:* `USD Coin` or `Uniswap V3`",
            parse_mode='Markdown'
        )

    async def handle_name_input(self, update: Update, name: str) -> None:
        """Handle protocol name input"""
        user_id = update.effective_user.id

        if len(name.strip()) < 2:
            await update.message.reply_text("❌ Please provide a valid protocol name (at least 2 characters)")
            return

        # Store name and move to scan type selection
        self.user_sessions[user_id]["scan_data"]["name"] = name.strip()
        self.user_sessions[user_id]["state"] = "waiting_for_scan_type"

        keyboard = [
            [InlineKeyboardButton("🔍 Basic Scan ($500)", callback_data="scan_basic")],
            [InlineKeyboardButton("📋 Full Audit ($2500)", callback_data="scan_full")],
            [InlineKeyboardButton("👀 Monitoring ($1000/mo)", callback_data="scan_monitoring")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text(
            f"✅ Protocol name: *{name}*\n\n"
            "Choose your scan type:",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )

    async def handle_scan_type_input(self, update: Update, scan_type: str) -> None:
        """Handle scan type selection"""
        # This is handled by callback queries, but keep for text input
        scan_types = {
            "basic": "basic_scan",
            "full": "full_audit",
            "monitoring": "monitoring"
        }

        if scan_type.lower() not in scan_types:
            await update.message.reply_text(
                "❌ Invalid scan type. Please choose: basic, full, or monitoring"
            )
            return

        await self.perform_scan(update, scan_types[scan_type.lower()])

    async def handle_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle callback queries from inline keyboards"""
        query = update.callback_query
        await query.answer()

        user_id = update.effective_user.id
        callback_data = query.data

        if callback_data == "start_scan":
            await self.scan_command(update, context)
        elif callback_data == "show_pricing":
            await self.pricing_command(update, context)
        elif callback_data == "show_help":
            await self.help_command(update, context)
        elif callback_data.startswith("scan_"):
            scan_type_map = {
                "scan_basic": "basic_scan",
                "scan_full": "full_audit",
                "scan_monitoring": "monitoring"
            }
            if callback_data in scan_type_map:
                await self.perform_scan(update, scan_type_map[callback_data])

    async def perform_scan(self, update: Update, scan_type: str) -> None:
        """Perform the actual security scan"""
        user_id = update.effective_user.id

        if user_id not in self.user_sessions or "scan_data" not in self.user_sessions[user_id]:
            await update.callback_query.message.reply_text(
                "❌ Scan session expired. Please start over with /scan"
            )
            return

        scan_data = self.user_sessions[user_id]["scan_data"]
        address = scan_data["address"]
        name = scan_data["name"]

        # Send processing message
        processing_msg = await update.callback_query.message.reply_text(
            f"🔍 Scanning *{name}* at `{address}`...\n\n"
            "This may take a few moments. Please wait...",
            parse_mode='Markdown'
        )

        try:
            # Perform the scan
            client_id = f"telegram_user_{user_id}"
            results = await self.service.perform_paid_scan(
                client_id=client_id,
                protocol_address=address,
                protocol_name=name,
                scan_type=scan_type
            )

            # Format and send results
            await self.send_scan_results(update, results, scan_type)

            # Clean up session
            del self.user_sessions[user_id]

        except Exception as e:
            self.logger.error(f"Scan failed for user {user_id}: {e}")
            await processing_msg.edit_text(
                f"❌ Scan failed: {str(e)}\n\n"
                "Please try again or contact support if the issue persists."
            )

    async def send_scan_results(self, update: Update, results: Dict[str, Any], scan_type: str) -> None:
        """Send formatted scan results to user"""
        risk_score = results["risk_score"]
        findings_count = results["findings_count"]

        # Risk level emoji and color
        if risk_score >= 80:
            risk_emoji = "🔴"
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_emoji = "🟠"
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_emoji = "🟡"
            risk_level = "MEDIUM"
        elif risk_score >= 20:
            risk_emoji = "🟢"
            risk_level = "LOW"
        else:
            risk_emoji = "🟢"
            risk_level = "VERY LOW"

        # Format summary message
        summary = f"""
{risk_emoji} *Security Scan Complete*

*Risk Score:* {risk_score}/100 ({risk_level})
*Findings:* {findings_count} issues detected
*Scan Type:* {scan_type.replace('_', ' ').title()}

*Summary:*
"""

        # Add key findings (first 3)
        report_lines = results["report"].split('\n')
        findings_section = False
        finding_count = 0

        for line in report_lines:
            if line.startswith('## Findings'):
                findings_section = True
                continue
            elif findings_section and line.startswith('##'):
                break
            elif findings_section and line.startswith('###') and finding_count < 3:
                summary += f"• {line.replace('###', '').strip()}\n"
                finding_count += 1

        # Add recommendations preview
        summary += "\n*Next Steps:*\n"
        if risk_score >= 60:
            summary += "• Address critical findings immediately\n"
            summary += "• Consider full security audit\n"
        else:
            summary += "• Review findings and implement fixes\n"
            summary += "• Schedule regular security scans\n"

        summary += "\n💰 *Payment Required*\n"
        summary += "Contact our team to complete the scan and receive the full report."

        keyboard = [
            [InlineKeyboardButton("📞 Contact Sales", url="https://t.me/defisecurity_support")],
            [InlineKeyboardButton("🔍 New Scan", callback_data="start_scan")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.callback_query.message.reply_text(
            summary,
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )

    async def handle_unknown_input(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle unknown input"""
        help_text = """
🤔 I didn't understand that command.

Available commands:
• /start - Main menu
• /scan - Start security scan
• /pricing - View pricing
• /help - Show help

Or send me a smart contract address (0x...) to begin scanning!
        """

        await update.message.reply_text(help_text)

    def run(self) -> None:
        """Run the bot"""
        application = Application.builder().token(self.token).build()

        # Add handlers
        application.add_handler(CommandHandler("start", self.start))
        application.add_handler(CommandHandler("help", self.help_command))
        application.add_handler(CommandHandler("pricing", self.pricing_command))
        application.add_handler(CommandHandler("scan", self.scan_command))
        application.add_handler(CallbackQueryHandler(self.handle_callback))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))

        # Start the bot
        self.logger.info("Starting DeFi Security Scanner Telegram Bot...")
        application.run_polling(allowed_updates=Update.ALL_TYPES)


def main():
    """Main function to run the Telegram bot"""
    print("DeFi Security Scanner - Telegram Bot")
    print("=" * 40)

    # Get bot token from environment
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not token:
        print("❌ TELEGRAM_BOT_TOKEN environment variable not set!")
        print("Please set your bot token from @BotFather")
        print("Example: export TELEGRAM_BOT_TOKEN='your_bot_token_here'")
        sys.exit(1)

    bot = DeFiSecurityTelegramBot(token)
    bot.run()


if __name__ == "__main__":
    main()