# Hosting Guide for DeFi Security Scanner Telegram Bot

This guide covers multiple hosting options for deploying your Telegram bot to production.

## 🚀 Quick Start Options

### Option 1: Railway (Recommended for Beginners)
Railway is the easiest way to deploy Python apps with built-in databases and zero config.

1. **Sign up**: Go to [Railway.app](https://railway.app) and create an account
2. **Connect GitHub**: Link your GitHub repository
3. **Deploy**: Railway auto-detects Python and deploys automatically
4. **Set Environment Variables**: Add your bot token and API keys in Railway dashboard

### Option 2: Heroku (Classic Choice)
Heroku is reliable but has some costs for the free tier changes.

1. **Install Heroku CLI**: `npm install -g heroku`
2. **Login**: `heroku login`
3. **Create App**: `heroku create your-bot-name`
4. **Set Environment**: `heroku config:set TELEGRAM_BOT_TOKEN=your_token`
5. **Deploy**: `git push heroku main`

### Option 3: DigitalOcean App Platform
Good balance of ease and control.

1. **Create Droplet** or use **App Platform**
2. **Connect Repository**
3. **Configure Environment Variables**
4. **Deploy**

## 📋 Prerequisites

Before hosting, ensure you have:

1. **Telegram Bot Token** from [@BotFather](https://t.me/botfather)
2. **Infura API Key** (optional, for full Web3 functionality)
3. **GitHub Repository** with your bot code

## 🐳 Docker Deployment (Recommended)

### 1. Create Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd --create-home --shell /bin/bash app \\
    && chown -R app:app /app
USER app

# Run the bot
CMD ["python", "run_telegram_bot.py"]
```

### 2. Create docker-compose.yml (Optional)

```yaml
version: '3.8'
services:
  defi-bot:
    build: .
    env_file:
      - .env
    restart: unless-stopped
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

### 3. Build and Run

```bash
# Build image
docker build -t defi-security-bot .

# Run container
docker run -d --env-file .env defi-security-bot

# Or with docker-compose
docker-compose up -d
```

## ☁️ Cloud Platform Guides

### Railway Deployment

1. **Connect Repository**:
   - Go to Railway.app
   - Click "New Project" → "Deploy from GitHub repo"
   - Select your repository

2. **Environment Variables**:
   ```
   TELEGRAM_BOT_TOKEN=your_bot_token
   INFURA_API_KEY=your_infura_key
   INFURA_HTTPS=https://mainnet.infura.io/v3/your_infura_key
   ```

3. **Deploy**: Railway automatically detects Python and deploys

### Heroku Deployment

1. **Create Heroku App**:
   ```bash
   heroku create your-defi-bot
   ```

2. **Set Buildpacks**:
   ```bash
   heroku buildpacks:add heroku/python
   ```

3. **Environment Variables**:
   ```bash
   heroku config:set TELEGRAM_BOT_TOKEN=your_token
   heroku config:set INFURA_API_KEY=your_key
   ```

4. **Deploy**:
   ```bash
   git push heroku main
   ```

5. **Scale** (if needed):
   ```bash
   heroku ps:scale worker=1
   ```

### Render Deployment

1. **Connect Repository**:
   - Go to [Render.com](https://render.com)
   - Create "Web Service" from Git
   - Select your repository

2. **Configure**:
   - Runtime: Python 3
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `python run_telegram_bot.py`

3. **Environment Variables**: Add in Render dashboard

### DigitalOcean App Platform

1. **Create App**:
   - Go to DigitalOcean → Apps
   - Create App from GitHub repository

2. **Resource Settings**:
   - Type: Worker (since it's a bot)
   - Runtime: Python

3. **Environment Variables**: Configure in DO dashboard

## 🖥️ VPS Hosting (Advanced)

### Ubuntu/Debian Server

1. **Update System**:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Install Python**:
   ```bash
   sudo apt install python3 python3-pip python3-venv -y
   ```

3. **Clone Repository**:
   ```bash
   git clone https://github.com/yourusername/llamamachinery.git
   cd llamamachinery-main
   ```

4. **Setup Virtual Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

5. **Configure Environment**:
   ```bash
   cp .env.example .env
   nano .env  # Add your tokens
   ```

6. **Run with PM2** (process manager):
   ```bash
   sudo npm install -g pm2
   pm2 start run_telegram_bot.py --name "defi-bot"
   pm2 save
   pm2 startup
   ```

### Systemd Service (Production)

Create `/etc/systemd/system/defi-bot.service`:

```ini
[Unit]
Description=DeFi Security Scanner Telegram Bot
After=network.target

[Service]
Type=simple
User=your_user
WorkingDirectory=/path/to/your/bot
Environment=PATH=/path/to/venv/bin
ExecStart=/path/to/venv/bin/python run_telegram_bot.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable defi-bot
sudo systemctl start defi-bot
sudo systemctl status defi-bot
```

## 🔧 Environment Configuration

### Required Variables

```bash
# Telegram Bot Token (REQUIRED)
TELEGRAM_BOT_TOKEN=your_bot_token_from_botfather

# Infura API (RECOMMENDED for full functionality)
INFURA_API_KEY=your_infura_project_id
INFURA_HTTPS=https://mainnet.infura.io/v3/your_infura_project_id

# Optional: Custom logging
LOG_LEVEL=INFO
```

### Security Notes

- Never commit `.env` files to Git
- Use strong, unique API keys
- Rotate tokens regularly
- Monitor bot usage for abuse

## 📊 Monitoring & Maintenance

### Health Checks

Add to your bot code:
```python
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}
```

### Logging

```python
# Configure logging for production
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)
```

### Backup Strategy

- Environment variables are in your deployment platform
- Code is in Git
- Consider database backup if you add persistence

## 🚨 Troubleshooting

### Common Issues

1. **Bot not responding**:
   - Check bot token is correct
   - Verify bot is running: `ps aux | grep python`
   - Check logs for errors

2. **Web3 connection failed**:
   - Verify Infura API key
   - Check network connectivity
   - Bot runs in demo mode without Infura

3. **Memory issues**:
   - Monitor RAM usage
   - Consider upgrading hosting plan
   - Implement connection pooling

### Logs

```bash
# Railway
railway logs

# Heroku
heroku logs -t

# Docker
docker logs container_name

# PM2
pm2 logs defi-bot
```

## 💰 Cost Comparison

| Platform | Free Tier | Paid Plan | Best For |
|----------|-----------|-----------|----------|
| Railway | 512MB RAM, $5 credit | $5+/month | Beginners |
| Heroku | 550 hours/month | $7+/month | Hobby projects |
| Render | 750 hours/month | $7+/month | Web services |
| DigitalOcean | - | $6+/month | Control |
| VPS | - | $5+/month | Full control |

## 🔐 Production Checklist

- [ ] Bot token configured
- [ ] Environment variables set
- [ ] HTTPS enabled (if web interface)
- [ ] Logging configured
- [ ] Monitoring alerts setup
- [ ] Backup strategy in place
- [ ] Rate limiting implemented
- [ ] Error handling robust
- [ ] Security headers (if web)
- [ ] SSL certificates (if web)

## 📞 Support

For hosting issues:
- Check platform documentation
- Review bot logs
- Test locally first
- Community forums for specific platforms

---

*Choose the platform that best fits your needs and technical comfort level. Railway is recommended for first-time deployments.*