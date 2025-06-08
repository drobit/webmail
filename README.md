# 📧 High-Performance Rust Webmail Client

A blazingly fast, modern webmail client built with Rust, featuring a Roundcube-inspired UI and optimized IMAP/SMTP operations.

**🆓 Open Source** | **⚡ High Performance** | **🛡️ Secure** | **📱 Responsive**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Open Source](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)](https://opensource.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

## ✨ Features

- **⚡ Ultra-Fast Performance**: Batch IMAP fetching with UID-based lookups
- **🎨 Modern UI**: Roundcube-inspired responsive design
- **📦 Batch Operations**: Fetch headers and bodies in single connection
- **🔄 Smart Caching**: PostgreSQL-backed email storage with intelligent updates
- **📱 Responsive Design**: Works seamlessly on desktop and mobile
- **🛡️ Secure**: TLS/SSL encryption for all email operations
- **🚀 Real-time Updates**: Auto-refresh with new email notifications
- **📧 Full CRUD**: Read, compose, send, and manage emails

## 🏗️ Architecture

### Backend (Rust)
- **Framework**: Actix-web for high-performance HTTP server
- **Email**: `async-imap` for IMAP, `lettre` for SMTP
- **Database**: PostgreSQL with SQLx for async operations
- **Security**: TLS encryption with `rustls` and `webpki-roots`

### Frontend
- **Pure Web**: Vanilla JavaScript with modern ES6+ features
- **Styling**: Custom CSS with responsive design
- **Architecture**: Class-based component system
- **Real-time**: WebSocket-like polling for updates

### Database Schema
```sql
-- Core email storage
CREATE TABLE emails (
    id SERIAL PRIMARY KEY,
    message_id VARCHAR(255) UNIQUE,
    from_address TEXT NOT NULL,
    to_address TEXT NOT NULL,
    subject TEXT,
    body TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    fetched_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    imap_uid INTEGER,
    is_seen BOOLEAN DEFAULT FALSE,
    is_recent BOOLEAN DEFAULT FALSE,
    body_preview TEXT
);

-- Sent email tracking
CREATE TABLE sent_emails (
    id SERIAL PRIMARY KEY,
    to_address TEXT NOT NULL,
    subject TEXT,
    body TEXT,
    sent_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    status VARCHAR(50) DEFAULT 'sent'
);
```

## 🚀 Quick Start

### Prerequisites

- **Rust** (1.70+): [Install Rust](https://rustup.rs/)
- **PostgreSQL** (12+): [Install PostgreSQL](https://www.postgresql.org/download/)
- **Gmail App Password**: [Setup Guide](https://support.google.com/accounts/answer/185833)

### 1. Clone & Setup

```bash
git clone <your-repo-url>
cd webmail
```

### 2. Database Setup

```bash
# Create database and user
createdb webmail_db
psql webmail_db < database_schema.sql
```

### 3. Environment Configuration

```bash
# Copy and configure environment
cp .env.example .env
```

Edit `.env` with your credentials:
```bash
DATABASE_URL=postgresql://webmail_user:your_password@localhost:5432/webmail_db
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_16_character_app_password
IMAP_USER=your_email@gmail.com
IMAP_PASS=your_16_character_app_password
```

### 4. Build & Run

```bash
# Install dependencies and build
cargo build --release

# Run the server
cargo run

# Server starts on http://127.0.0.1:3001
```

### 5. Frontend Setup

```bash
# Build WebAssembly frontend (optional - HTML version included)
cd frontend
wasm-pack build --target web --out-dir pkg
```

Open `frontend/index.html` in your browser or serve it via a web server.

## 📖 API Documentation

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/emails?limit=50` | Fetch email list |
| `GET` | `/emails?refresh=true` | Force refresh from IMAP |
| `GET` | `/email/{id}` | Get specific email details |
| `GET` | `/emails/new?since=timestamp` | Check for new emails |
| `POST` | `/send` | Send new email |
| `GET` | `/health` | Health check endpoint |

### Request/Response Examples

#### Fetch Emails
```bash
curl "http://127.0.0.1:3001/emails?limit=20"
```

Response:
```json
[
  {
    "id": "uid_12345",
    "from": "sender@example.com",
    "subject": "Important Update",
    "date": "2024-01-15 10:30:00",
    "is_seen": false,
    "is_recent": true
  }
]
```

#### Send Email
```bash
curl -X POST "http://127.0.0.1:3001/send" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "recipient@example.com",
    "subject": "Hello World",
    "body": "This is a test email."
  }'
```

## ⚡ Performance Optimizations

### IMAP Batch Fetching
- **Single Connection**: One IMAP connection per request
- **Bulk Operations**: Fetch headers and bodies together
- **UID-based Indexing**: Fast lookups using IMAP UIDs
- **Smart Caching**: Database-backed with intelligent updates

### Frontend Optimizations
- **Debounced Requests**: Prevent duplicate API calls
- **Smart Polling**: Check for new emails every 30 seconds
- **Local Caching**: Store email list in memory
- **Progressive Loading**: Load email bodies on demand

### Database Optimizations
- **Indexed Queries**: Fast lookups on message_id and UID
- **Prepared Statements**: SQLx with compile-time query verification
- **Connection Pooling**: Efficient database connection management

## 🔧 Configuration

### Email Provider Settings

#### Gmail
```bash
SMTP_SERVER=smtp.gmail.com:587
IMAP_SERVER=imap.gmail.com:993
```

#### Outlook/Hotmail
```bash
SMTP_SERVER=smtp-mail.outlook.com:587
IMAP_SERVER=outlook.office365.com:993
```

#### Custom IMAP/SMTP
Modify `src/main.rs` to use different servers:
```rust
let mailer = SmtpTransport::starttls_relay("your-smtp-server.com")
    .unwrap()
    .port(587)
    .credentials(creds)
    .build();
```

### Performance Tuning

#### Database
```bash
# Increase connection pool size
DATABASE_MAX_CONNECTIONS=20

# Enable query logging
SQLX_LOGGING=true
```

#### IMAP Settings
```rust
// Adjust batch size in src/main.rs
let fetch_limit = limit.min(25); // Increase for faster bulk operations
```

## 🧪 Testing

### Run Tests
```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Test specific module
cargo test lib::tests
```

### Load Testing
```bash
# Install wrk
brew install wrk  # macOS
# or
sudo apt-get install wrk  # Ubuntu

# Test email fetching
wrk -t4 -c100 -d30s http://127.0.0.1:3001/emails

# Test health endpoint
wrk -t4 -c100 -d10s http://127.0.0.1:3001/health
```

## 🐛 Troubleshooting

### Common Issues

#### IMAP Connection Failed
```bash
Error: IMAP login failed
```
**Solutions:**
- Enable "Less secure app access" or use App Passwords
- Check firewall settings for port 993
- Verify IMAP credentials in `.env`

#### Database Connection Error
```bash
Error: Database connection failed
```
**Solutions:**
- Ensure PostgreSQL is running: `sudo service postgresql start`
- Check DATABASE_URL format
- Verify database exists: `psql -l`

#### SMTP Send Failed
```bash
Error: Email send failed
```
**Solutions:**
- Use Gmail App Password (not account password)
- Check SMTP credentials in `.env`
- Verify port 587 is accessible

### Debug Mode

Enable detailed logging:
```bash
RUST_LOG=debug cargo run
```

### Health Check

Verify all systems:
```bash
curl http://127.0.0.1:3001/health
```

Expected response:
```json
{
  "status": "ok",
  "database": "healthy",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## 🚀 Deployment

### Docker (Recommended)

```dockerfile
FROM rust:1.70-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/webmail .
COPY frontend/ ./frontend/
EXPOSE 3001
CMD ["./webmail"]
```

Build and run:
```bash
docker build -t webmail .
docker run -p 3001:3001 --env-file .env webmail
```

### Production Setup

1. **Reverse Proxy** (nginx):
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

2. **SSL Certificate**:
```bash
# Using Let's Encrypt
certbot --nginx -d your-domain.com
```

3. **Systemd Service**:
```ini
[Unit]
Description=Webmail Server
After=network.target

[Service]
Type=simple
User=webmail
WorkingDirectory=/opt/webmail
ExecStart=/opt/webmail/target/release/webmail
Restart=always

[Install]
WantedBy=multi-user.target
```

## 🤝 Contributing

**This is an open source project - contributions are welcome!**

We encourage contributions from developers of all skill levels. Whether you're fixing bugs, adding features, improving documentation, or suggesting ideas, your help makes this project better for everyone.

### Quick Start for Contributors

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature-name`
3. **Make** your changes following our coding standards
4. **Test** your changes: `cargo test`
5. **Submit** a Pull Request

### Contributing Guidelines

For detailed information about contributing, including:
- 🛠️ **Development setup**
- 📝 **Coding standards**
- 🧪 **Testing guidelines**
- 🔄 **Pull request process**
- 🐛 **Issue reporting**

Please see our **[CONTRIBUTING.md](CONTRIBUTING.md)** file.

### Types of Contributions Needed

- 🐛 **Bug fixes** and stability improvements
- ⚡ **Performance optimizations**
- 🎨 **UI/UX enhancements**
- 📚 **Documentation** improvements
- 🧪 **Tests** and quality assurance
- 🌐 **Internationalization** (i18n)
- 📱 **Mobile responsiveness** improvements
- 🔒 **Security** enhancements

### Development Setup

```bash
# Install development dependencies
cargo install cargo-watch

# Auto-rebuild on changes
cargo watch -x run

# Format code
cargo fmt

# Run lints
cargo clippy
```

For detailed development setup and guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).

## 📝 License

This project is **open source** and available under the [MIT License](LICENSE).

### What this means:
- ✅ **Free to use** for personal and commercial projects
- ✅ **Modify and distribute** as you wish
- ✅ **No warranty** - use at your own risk
- ✅ **Attribution required** - keep the license notice

See the [LICENSE](LICENSE) file for the full license text.

## 🙏 Acknowledgments

- **Roundcube** for UI inspiration
- **Rust Community** for excellent async ecosystem
- **Actix-web** for high-performance web framework
- **SQLx** for type-safe database operations

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/drobit/webmail/issues)
- **Discussions**: [GitHub Discussions](https://github.com/drobit/webmail/discussions)
- **Telegram**: https://t.me/d_serg
- **Email**: drobit.github@gmail.com

---

⭐ **Star this repo** if you find it useful!

Built with ❤️ and ⚡ by [Serhii Drobot](https://github.com/drobit)