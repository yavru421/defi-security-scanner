# DeFi Security Scanner Telegram Bot

A professional Telegram bot for automated DeFi protocol security analysis. Scan smart contracts for vulnerabilities, get risk assessments, and receive detailed security reports.

## 🚀 Features

- 🔍 **Automated Security Scanning** - Comprehensive vulnerability detection
- 💰 **Commercial Service** - Professional security reports with pricing
- 📊 **Risk Assessment** - Detailed risk scoring and recommendations
- 🔔 **Telegram Integration** - Easy-to-use bot interface
- 🔒 **ERC-20 Analysis** - Permit vulnerability detection
- ⚡ **Real-time Results** - Instant security analysis

## 💰 Pricing

- **Basic Scan**: $500 - Individual smart contract analysis
- **Full Audit**: $2,500 - Complete protocol assessment
- **Monitoring**: $1,000/month - Ongoing security monitoring

## 🛠️ Quick Start

### Prerequisites
- Python 3.8+
- Telegram Bot Token (from [@BotFather](https://t.me/botfather))
- Infura API Key (optional, for full Web3 functionality)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/defi-security-scanner.git
cd defi-security-scanner

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your bot token and API keys
```

### Local Development

```bash
# Run the bot locally
python run_telegram_bot.py
```

### Production Deployment

#### Railway (Recommended)
1. Connect your GitHub repository to Railway
2. Set environment variables in Railway dashboard
3. Deploy automatically

#### Docker
```bash
docker build -t defi-security-bot .
docker run -d --env-file .env defi-security-bot
```

## 📱 Usage

1. Start a chat with your bot on Telegram
2. Send `/start` to begin
3. Send `/scan` to start security scanning
4. Provide contract address and protocol name
5. Choose scan type (Basic/Full/Monitoring)
6. Receive professional security report

### Example Commands

```
/start - Welcome message and help
/scan - Start security scan
/pricing - View service pricing
/help - Show available commands
```

## 🏗️ Architecture

- **`defi_security_scanner.py`** - Core security scanning engine
- **`defi_security_telegram_bot.py`** - Telegram bot interface
- **`run_telegram_bot.py`** - Application launcher
- **Deployment configs** - Railway, Docker, Heroku support

## 🔧 Configuration

### Environment Variables

```bash
# Required
TELEGRAM_BOT_TOKEN=your_bot_token_from_botfather

# Optional (enables full Web3 functionality)
INFURA_API_KEY=your_infura_project_id
INFURA_HTTPS=https://mainnet.infura.io/v3/your_infura_project_id
```

### Security Features

- ERC-20 permit vulnerability detection
- Malicious address database checks
- Bytecode analysis for high-risk opcodes
- Reentrancy and access control analysis

## 📊 Security Analysis

The scanner performs comprehensive analysis including:

- **Contract Bytecode Analysis**
  - SELFDESTRUCT detection
  - Delegatecall usage review
  - High-risk opcode identification

- **ERC-20 Permit Vulnerabilities**
  - Unlimited approval risks
  - Implementation security checks

- **Threat Intelligence**
  - Known malicious address database
  - Suspicious pattern detection

## 🚀 Deployment Options

- **Railway** - Auto-deployment from GitHub
- **Heroku** - Traditional PaaS deployment
- **Docker** - Containerized deployment
- **VPS** - Full server control

See [HOSTING_GUIDE.md](HOSTING_GUIDE.md) for detailed deployment instructions.

## 📚 Documentation

- [Telegram Bot Guide](TELEGRAM_BOT_README.md) - Bot usage and features
- [Hosting Guide](HOSTING_GUIDE.md) - Deployment instructions
- [API Documentation](TELEGRAM_BOT_README.md) - Technical details

## 🤝 Contributing

This is a commercial security service. For contributions or custom development:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request
4. Contact for commercial licensing

## 📞 Support

- **Telegram**: [@defisecurity_support](https://t.me/defisecurity_support)
- **Email**: support@defisecurityscanner.com
- **Issues**: GitHub Issues

## ⚖️ License

Commercial service - contact for licensing information.

## 🔒 Security Notice

This tool is for educational and commercial security assessment purposes. Always conduct thorough security audits before deploying to mainnet. The scanner provides automated analysis but should be supplemented with manual expert review for critical applications.

---

**Built with ❤️ for DeFi security**