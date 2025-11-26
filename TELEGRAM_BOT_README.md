# DeFi Security Scanner Telegram Bot

A Telegram bot interface for the DeFi Security Scanner service, allowing users to scan smart contracts for vulnerabilities directly through Telegram.

## Features

- 🔍 **Smart Contract Scanning**: Scan Ethereum smart contracts for security vulnerabilities
- 💰 **Service Pricing**: View current pricing for different scan types
- 📊 **Security Reports**: Receive professional security analysis reports
- 🔔 **Interactive Interface**: User-friendly commands and inline keyboards
- 🔒 **Commercial Service**: Integrated with paid scanning service

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Create Telegram Bot

1. Message [@BotFather](https://t.me/botfather) on Telegram
2. Send `/newbot` and follow the instructions
3. Copy the bot token

### 3. Environment Configuration

Create a `.env` file or set environment variables:

```bash
# Telegram Bot Token (from BotFather)
TELEGRAM_BOT_TOKEN=your_bot_token_here

# Infura API for Web3 connectivity (optional, demo mode if not set)
INFURA_API_KEY=your_infura_key
INFURA_HTTPS=https://mainnet.infura.io/v3/your_infura_key
```

### 4. Run the Bot

```bash
python defi_security_telegram_bot.py
```

## Usage

### Commands

- `/start` - Welcome message and main menu
- `/scan` - Start a security scan
- `/pricing` - View service pricing
- `/help` - Show help information

### Scanning Process

1. Send `/scan` or a smart contract address (0x...)
2. Provide protocol/token name
3. Choose scan type (Basic/Full/Monitoring)
4. Receive security report summary
5. Contact sales for full report and payment

### Example Interaction

```
User: /scan
Bot: Please send me the smart contract address...

User: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
Bot: Address received. Now send me the protocol name...

User: USD Coin
Bot: Choose your scan type...

User: [Clicks "Basic Scan"]
Bot: 🔍 Scanning USD Coin...
Bot: 🔴 Risk Score: 25/100 (LOW)
      Findings: 2 issues detected
```

## Service Pricing

- **Basic Scan**: $500 - Automated vulnerability detection
- **Full Audit**: $2,500 - Comprehensive protocol review
- **Monitoring**: $1,000/month - Ongoing security monitoring

## Architecture

The bot integrates with the existing `DeFiSecurityService` class and provides:

- User session management
- Interactive conversation flow
- Callback query handling
- Error handling and logging
- Markdown-formatted responses

## Security Features

- Input validation for Ethereum addresses
- Session-based user state management
- Error handling with user-friendly messages
- Integration with existing security scanning service

## Development

### Adding New Features

1. Add new command handlers in the `DeFiSecurityTelegramBot` class
2. Update the help text and command list
3. Add new callback data handlers for interactive buttons
4. Test with the Telegram Bot API

### Customization

- Modify pricing in `defi_security_scanner.py`
- Update welcome messages and help text
- Add new scan types or analysis features
- Customize the report formatting

## Support

For support or questions:

- Telegram: [@defisecurity_support](https://t.me/defisecurity_support)
- Email: support@defisecurityscanner.com

## License

Commercial service - contact for licensing information.