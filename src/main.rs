// src/main.rs
use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpRequest, HttpResponse, HttpServer};
use chrono::Utc;
use futures::stream::StreamExt;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::collections::HashMap;
use std::env;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tokio_util::compat::TokioAsyncReadCompatExt;
use webpki_roots;

// Import auth module
mod auth;
use auth::{get_user_credentials, get_user_session, SessionStore};

// Import from lib.rs
use webmail::{EmailDetail, EmailListItem, EmailRequest};

#[derive(Clone)]
struct AppState {
    db: PgPool,
    session_store: SessionStore,
}

async fn init_db() -> PgPool {
    println!("🔌 Connecting to existing database...");
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
        println!("⚠️ DATABASE_URL not set, using default");
        "postgresql://webmail_user:your_password@localhost:5432/webmail_db".to_string()
    });

    match PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
    {
        Ok(pool) => {
            println!("✅ Database connected");
            pool
        }
        Err(e) => {
            println!("❌ Database connection failed: {:?}", e);
            println!("📝 Make sure PostgreSQL is running and DATABASE_URL is correct");
            std::process::exit(1);
        }
    }
}

// Authentication middleware - requires valid session for email endpoints
fn require_auth(
    req: &HttpRequest,
    session_store: &SessionStore,
) -> Result<auth::UserSession, HttpResponse> {
    match get_user_session(req, session_store) {
        Some(session) => Ok(session),
        None => Err(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Authentication required",
            "redirect": "/login.html"
        }))),
    }
}

async fn send_email(
    req: HttpRequest,
    data: web::Json<EmailRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    // Authenticate user
    let user_session = match require_auth(&req, &state.session_store) {
        Ok(session) => session,
        Err(response) => return response,
    };

    let (smtp_user, smtp_pass) = match get_user_credentials(&user_session) {
        Ok(creds) => creds,
        Err(e) => {
            return HttpResponse::InternalServerError().body(format!("Credential error: {}", e))
        }
    };

    let email = match Message::builder()
        .from(smtp_user.parse().unwrap())
        .to(data.to.parse().unwrap())
        .subject(&data.subject)
        .body(data.body.clone())
    {
        Ok(email) => email,
        Err(e) => return HttpResponse::BadRequest().body(format!("Email building error: {:?}", e)),
    };

    let creds = Credentials::new(smtp_user, smtp_pass);

    // Use user's SMTP settings
    let mailer = if user_session.smtp_port == 465 {
        SmtpTransport::relay(&user_session.smtp_server)
            .unwrap()
            .port(user_session.smtp_port)
            .credentials(creds)
            .build()
    } else {
        SmtpTransport::starttls_relay(&user_session.smtp_server)
            .unwrap()
            .port(user_session.smtp_port)
            .credentials(creds)
            .build()
    };

    match mailer.send(&email) {
        Ok(_) => {
            let _ = sqlx::query(
                "INSERT INTO sent_emails (to_address, subject, body) VALUES ($1, $2, $3)",
            )
            .bind(&data.to)
            .bind(&data.subject)
            .bind(&data.body)
            .execute(&state.db)
            .await;

            HttpResponse::Ok().body("Email sent successfully!")
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Email send failed: {:?}", e)),
    }
}

// Modified database schema to include user-specific emails
async fn update_db_schema(pool: &PgPool) -> Result<(), sqlx::Error> {
    let schema_updates = [
        "ALTER TABLE emails ADD COLUMN IF NOT EXISTS user_email VARCHAR(255)",
        "ALTER TABLE emails ADD COLUMN IF NOT EXISTS imap_uid INTEGER",
        "ALTER TABLE emails ADD COLUMN IF NOT EXISTS is_seen BOOLEAN DEFAULT FALSE",
        "ALTER TABLE emails ADD COLUMN IF NOT EXISTS is_recent BOOLEAN DEFAULT FALSE",
        "ALTER TABLE emails ADD COLUMN IF NOT EXISTS body_preview TEXT",
        "ALTER TABLE sent_emails ADD COLUMN IF NOT EXISTS user_email VARCHAR(255)",
    ];

    for update in &schema_updates {
        if let Err(e) = sqlx::query(update).execute(pool).await {
            println!("⚠️ Schema update warning: {} - {}", update, e);
        }
    }

    // Create indexes
    let indexes = [
        "CREATE INDEX IF NOT EXISTS idx_emails_user_email ON emails(user_email)",
        "CREATE INDEX IF NOT EXISTS idx_emails_imap_uid ON emails(imap_uid)",
        "CREATE INDEX IF NOT EXISTS idx_sent_emails_user_email ON sent_emails(user_email)",
    ];

    for index in &indexes {
        let _ = sqlx::query(index).execute(pool).await;
    }

    Ok(())
}

// Get cached emails for specific user
async fn get_cached_emails(
    pool: &PgPool,
    user_email: &str,
    limit: i64,
) -> Result<Vec<EmailListItem>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT message_id, from_address, subject, created_at, is_seen, is_recent, imap_uid
         FROM emails
         WHERE user_email = $1 OR user_email IS NULL
         ORDER BY created_at DESC NULLS LAST
         LIMIT $2",
    )
    .bind(user_email)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            let created_at: Option<chrono::DateTime<chrono::Utc>> = row.get("created_at");
            let is_recent: bool = row.get::<Option<bool>, _>("is_recent").unwrap_or(false);
            let is_seen: bool = row.get::<Option<bool>, _>("is_seen").unwrap_or(true);
            let imap_uid: Option<i32> = row.get("imap_uid");

            let id = if let Some(uid) = imap_uid {
                format!("uid_{}", uid)
            } else {
                row.get::<Option<String>, _>("message_id")
                    .unwrap_or_else(|| "unknown".to_string())
            };

            EmailListItem {
                id,
                from: row.get("from_address"),
                subject: row
                    .get::<Option<String>, _>("subject")
                    .unwrap_or_else(|| "No Subject".to_string()),
                date: created_at.map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string()),
                is_seen,
                is_recent,
            }
        })
        .collect())
}

// Get email detail for specific user
async fn get_email_detail(
    pool: &PgPool,
    user_email: &str,
    message_id: &str,
) -> Result<Option<EmailDetail>, sqlx::Error> {
    let query = if message_id.starts_with("uid_") {
        if let Ok(uid) = message_id[4..].parse::<i32>() {
            sqlx::query(
                "SELECT message_id, from_address, subject, body, created_at, is_seen, is_recent, imap_uid
                 FROM emails
                 WHERE imap_uid = $1 AND (user_email = $2 OR user_email IS NULL)",
            )
                .bind(uid)
                .bind(user_email)
                .fetch_optional(pool)
                .await?
        } else {
            return Ok(None);
        }
    } else {
        sqlx::query(
            "SELECT message_id, from_address, subject, body, created_at, is_seen, is_recent, imap_uid
             FROM emails
             WHERE message_id = $1 AND (user_email = $2 OR user_email IS NULL)",
        )
            .bind(message_id)
            .bind(user_email)
            .fetch_optional(pool)
            .await?
    };

    if let Some(row) = query {
        let created_at: Option<chrono::DateTime<chrono::Utc>> = row.get("created_at");
        let is_recent: bool = row.get::<Option<bool>, _>("is_recent").unwrap_or(false);
        let is_seen: bool = row.get::<Option<bool>, _>("is_seen").unwrap_or(true);
        let imap_uid: Option<i32> = row.get("imap_uid");

        let id = if let Some(uid) = imap_uid {
            format!("uid_{}", uid)
        } else {
            row.get::<Option<String>, _>("message_id")
                .unwrap_or_else(|| "unknown".to_string())
        };

        Ok(Some(EmailDetail {
            id,
            from: row.get("from_address"),
            subject: row
                .get::<Option<String>, _>("subject")
                .unwrap_or_else(|| "No Subject".to_string()),
            body: row
                .get::<Option<String>, _>("body")
                .unwrap_or_else(|| "Click to load content...".to_string()),
            date: created_at.map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string()),
            is_seen,
            is_recent,
        }))
    } else {
        Ok(None)
    }
}

// BATCH fetch with user credentials
async fn batch_fetch_emails_with_bodies(
    user_session: &auth::UserSession,
    limit: u32,
) -> Result<Vec<EmailDetail>, Box<dyn std::error::Error + Send + Sync>> {
    println!(
        "🚀 BATCH fetching {} emails for {}",
        limit, user_session.email
    );
    let start_time = std::time::Instant::now();

    let (imap_user, imap_pass) = get_user_credentials(user_session)?;

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(config));

    let tcp_stream =
        TcpStream::connect((user_session.imap_server.as_str(), user_session.imap_port)).await?;
    let tls_stream = connector
        .connect(
            rustls::pki_types::ServerName::try_from(user_session.imap_server.as_str())?.to_owned(),
            tcp_stream,
        )
        .await?;

    let compat_stream = tls_stream.compat();
    let client = async_imap::Client::new(compat_stream);
    let mut imap_session = client
        .login(&imap_user, &imap_pass)
        .await
        .map_err(|e| format!("IMAP login failed: {:?}", e))?;

    println!("✅ Connected in {:?}", start_time.elapsed());

    let mailbox = imap_session.select("INBOX").await?;
    let message_count = mailbox.exists;

    if message_count == 0 {
        let _ = imap_session.logout().await;
        return Ok(Vec::new());
    }

    let fetch_limit = limit.min(15);
    let start_uid = if message_count > fetch_limit {
        message_count - fetch_limit + 1
    } else {
        1
    };
    let fetch_range = format!("{}:{}", start_uid, message_count);

    println!(
        "📦 BATCH fetching range: {} ({} emails)",
        fetch_range, fetch_limit
    );

    let messages_stream = imap_session
        .fetch(
            &fetch_range,
            "(UID FLAGS INTERNALDATE BODY[HEADER.FIELDS (FROM SUBJECT MESSAGE-ID)] BODY[TEXT])",
        )
        .await?;

    let messages: Vec<_> = messages_stream
        .take(fetch_limit as usize)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .filter_map(Result::ok)
        .collect();

    println!(
        "📦 BATCH fetched {} messages in {:?}",
        messages.len(),
        start_time.elapsed()
    );

    let mut emails = Vec::with_capacity(messages.len());
    let now = Utc::now();

    for message in messages.iter() {
        let uid = message.uid.unwrap_or(0);
        let mut from = "Unknown".to_string();
        let mut subject = "No Subject".to_string();

        if let Some(header_data) = message.header() {
            let header_str = String::from_utf8_lossy(header_data);
            for line in header_str.lines().take(10) {
                let line_lower = line.to_lowercase();
                if line_lower.starts_with("from:") && from == "Unknown" {
                    from = line[5..].trim().chars().take(50).collect();
                } else if line_lower.starts_with("subject:") && subject == "No Subject" {
                    subject = webmail::decode_mime_header_simple(line[8..].trim())
                        .chars()
                        .take(80)
                        .collect();
                }
            }
        }

        let body = message
            .text()
            .map(|b| extract_body_content(b))
            .unwrap_or_else(|| "No content available".to_string());

        let date = message
            .internal_date()
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string());

        let flags: Vec<_> = message.flags().collect();
        let is_seen = flags
            .iter()
            .any(|f| matches!(f, async_imap::types::Flag::Seen));
        let is_recent = message
            .internal_date()
            .map(|dt| now.signed_duration_since(dt).num_hours() < 24)
            .unwrap_or(false);

        emails.push(EmailDetail {
            id: format!("uid_{}", uid),
            from,
            subject,
            body,
            date,
            is_seen,
            is_recent,
        });
    }

    let _ = imap_session.logout().await;
    emails.reverse();

    println!(
        "🚀 BATCH completed {} emails in {:?}",
        emails.len(),
        start_time.elapsed()
    );
    Ok(emails)
}

// Cache update with user email
async fn cache_emails_with_uid(
    pool: &PgPool,
    user_email: &str,
    emails: &[EmailDetail],
) -> Result<(), sqlx::Error> {
    for email in emails {
        let uid = if email.id.starts_with("uid_") {
            email.id[4..].parse::<i32>().ok()
        } else {
            None
        };

        sqlx::query(
            "INSERT INTO emails (message_id, from_address, to_address, subject, body, created_at, fetched_at, is_seen, is_recent, imap_uid, body_preview, user_email)
             VALUES ($1, $2, '', $3, $4, NOW(), NOW(), $5, $6, $7, LEFT($4, 200), $8)
             ON CONFLICT (message_id) DO UPDATE SET
                body = EXCLUDED.body,
                fetched_at = NOW(),
                is_seen = EXCLUDED.is_seen,
                is_recent = EXCLUDED.is_recent,
                imap_uid = EXCLUDED.imap_uid,
                body_preview = EXCLUDED.body_preview,
                user_email = EXCLUDED.user_email"
        )
            .bind(&email.id)
            .bind(&email.from)
            .bind(&email.subject)
            .bind(&email.body)
            .bind(email.is_seen)
            .bind(email.is_recent)
            .bind(uid)
            .bind(user_email)
            .execute(pool)
            .await?;
    }
    Ok(())
}

async fn fetch_emails(
    req: HttpRequest,
    query: web::Query<HashMap<String, String>>,
    state: web::Data<AppState>,
) -> HttpResponse {
    // Authenticate user
    let user_session = match require_auth(&req, &state.session_store) {
        Ok(session) => session,
        Err(response) => return response,
    };

    println!("📧 Email list requested for {}", user_session.email);

    let limit = query
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(50)
        .min(50);

    let force_refresh = query.get("refresh").map(|s| s == "true").unwrap_or(false);

    if !force_refresh {
        match get_cached_emails(&state.db, &user_session.email, limit).await {
            Ok(cached_emails) if !cached_emails.is_empty() => {
                println!("⚡ INSTANT: Serving {} cached emails", cached_emails.len());
                return HttpResponse::Ok().json(cached_emails);
            }
            _ => {}
        }
    }

    println!("🚀 Fetching fresh emails with BATCH method");
    match batch_fetch_emails_with_bodies(&user_session, 15).await {
        Ok(emails) => {
            let db_clone = state.db.clone();
            let user_email = user_session.email.clone();
            let emails_clone = emails.clone();
            tokio::spawn(async move {
                if let Err(e) = cache_emails_with_uid(&db_clone, &user_email, &emails_clone).await {
                    println!("⚠️ Cache update failed: {}", e);
                }
            });

            let email_list: Vec<EmailListItem> = emails
                .into_iter()
                .map(|email| EmailListItem {
                    id: email.id,
                    from: email.from,
                    subject: email.subject,
                    date: email.date,
                    is_seen: email.is_seen,
                    is_recent: email.is_recent,
                })
                .collect();

            HttpResponse::Ok().json(email_list)
        }
        Err(e) => match get_cached_emails(&state.db, &user_session.email, limit).await {
            Ok(cached_emails) if !cached_emails.is_empty() => {
                println!("📄 Serving cached emails as fallback");
                HttpResponse::Ok().json(cached_emails)
            }
            _ => HttpResponse::InternalServerError().body(format!("Failed to fetch emails: {}", e)),
        },
    }
}

async fn check_new_emails(
    req: HttpRequest,
    _query: web::Query<HashMap<String, String>>,
    state: web::Data<AppState>,
) -> HttpResponse {
    // Authenticate user
    let _user_session = match require_auth(&req, &state.session_store) {
        Ok(session) => session,
        Err(response) => return response,
    };

    HttpResponse::Ok().json(Vec::<EmailListItem>::new())
}

async fn get_email(
    req: HttpRequest,
    path: web::Path<String>,
    state: web::Data<AppState>,
) -> HttpResponse {
    // Authenticate user
    let user_session = match require_auth(&req, &state.session_store) {
        Ok(session) => session,
        Err(response) => return response,
    };

    let message_id = path.into_inner();
    println!(
        "📖 Email requested: {} for {}",
        message_id, user_session.email
    );

    match get_email_detail(&state.db, &user_session.email, &message_id).await {
        Ok(Some(email)) => {
            if email.body != "Click to load content..." && !email.body.is_empty() {
                println!("⚡ INSTANT: Serving cached email body");
                return HttpResponse::Ok().json(email);
            }

            let mut email_with_loading = email;
            email_with_loading.body = "Loading email content...".to_string();
            HttpResponse::Ok().json(email_with_loading)
        }
        Ok(None) => HttpResponse::NotFound().body("Email not found"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {:?}", e)),
    }
}

async fn health_check(state: web::Data<AppState>) -> HttpResponse {
    let db_status = match sqlx::query("SELECT 1").fetch_one(&state.db).await {
        Ok(_) => "healthy",
        Err(_) => "unhealthy",
    };

    let session_count = {
        let session_store = state.session_store.lock().unwrap();
        session_store.len()
    };

    let response = serde_json::json!({
        "status": "ok",
        "database": db_status,
        "active_sessions": session_count,
        "timestamp": Utc::now().to_rfc3339()
    });

    HttpResponse::Ok().json(response)
}

// Serve login page
async fn serve_login_page() -> HttpResponse {
    // Login page HTML content
    let login_html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Webmail Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }
        .login-container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
            width: 100%;
            max-width: 420px;
            overflow: hidden;
        }
        .login-header {
            background: #f8f9fa;
            padding: 2rem;
            text-align: center;
            border-bottom: 1px solid #e9ecef;
        }
        .login-header h1 {
            font-size: 1.5rem;
            color: #333;
            margin-bottom: 0.5rem;
        }
        .login-header p {
            color: #666;
            font-size: 0.9rem;
        }
        .login-form {
            padding: 2rem;
        }
        .form-group {
            margin-bottom: 1.5rem;
        }
        .form-label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: #333;
            font-size: 0.9rem;
        }
        .form-control {
            width: 100%;
            padding: 0.75rem;
            border: 2px solid #e9ecef;
            border-radius: 6px;
            font-size: 0.9rem;
            transition: border-color 0.3s, box-shadow 0.3s;
        }
        .form-control:focus {
            outline: none;
            border-color: #007bff;
            box-shadow: 0 0 0 3px rgba(0, 123, 255, 0.1);
        }
        .login-btn {
            width: 100%;
            padding: 0.75rem;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.3s;
        }
        .login-btn:hover:not(:disabled) {
            background: #0056b3;
        }
        .login-btn:disabled {
            background: #6c757d;
            cursor: not-allowed;
        }
        .alert {
            padding: 0.75rem;
            margin-bottom: 1rem;
            border-radius: 6px;
            font-size: 0.85rem;
        }
        .alert-danger {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .help-text {
            font-size: 0.75rem;
            color: #666;
            margin-top: 0.25rem;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>📧 Webmail</h1>
            <p>Sign in to access your emails</p>
        </div>

        <form id="login-form" class="login-form">
            <div id="login-alerts"></div>

            <div class="form-group">
                <label class="form-label" for="email">Email Address</label>
                <input type="email" id="email" class="form-control" placeholder="your.email@example.com" required>
            </div>

            <div class="form-group">
                <label class="form-label" for="password">Password / App Password</label>
                <input type="password" id="password" class="form-control" placeholder="Enter your password" required>
                <div class="help-text">For Gmail, use an App Password instead of your regular password</div>
            </div>

            <button type="submit" id="login-btn" class="login-btn">
                🔐 Sign In
            </button>
        </form>
    </div>

    <script>
        document.getElementById('login-form').addEventListener('submit', async (e) => {
            e.preventDefault();

            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const loginBtn = document.getElementById('login-btn');

            loginBtn.disabled = true;
            loginBtn.textContent = 'Connecting...';

            try {
                // Determine provider and settings
                let provider = 'custom';
                let imap_server = 'imap.gmail.com';
                let imap_port = 993;
                let smtp_server = 'smtp.gmail.com';
                let smtp_port = 587;

                if (email.includes('@gmail.com')) {
                    provider = 'gmail';
                } else if (email.includes('@outlook.com') || email.includes('@hotmail.com')) {
                    provider = 'outlook';
                    imap_server = 'outlook.office365.com';
                    smtp_server = 'smtp-mail.outlook.com';
                }

                const response = await fetch('/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email,
                        password,
                        imap_server,
                        imap_port,
                        smtp_server,
                        smtp_port,
                        provider
                    })
                });

                const result = await response.json();

                if (result.success) {
                    localStorage.setItem('webmail_session', result.session_token);
                    window.location.href = '/';
                } else {
                    throw new Error(result.error || 'Login failed');
                }

            } catch (error) {
                document.getElementById('login-alerts').innerHTML =
                    `<div class="alert alert-danger">${error.message}</div>`;
            } finally {
                loginBtn.disabled = false;
                loginBtn.textContent = '🔐 Sign In';
            }
        });
    </script>
</body>
</html>"#;

    HttpResponse::Ok()
        .content_type("text/html")
        .body(login_html)
}

// Serve main app (redirect to login if not authenticated)
async fn serve_main_app(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    // Always check authentication via session token from headers first
    if let Some(session) = get_user_session(&req, &state.session_store) {
        // User is authenticated, serve main app
        let user_email = &session.email;
        let main_html = format!(
            r#"<!DOCTYPE html>
<html><head><title>Webmail - {user_email}</title>
<style>
body {{ font-family: system-ui, sans-serif; padding: 2rem; background: #f5f5f5; margin: 0; }}
.container {{ max-width: 800px; margin: 0 auto; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
.header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; border-bottom: 1px solid #eee; padding-bottom: 1rem; }}
.user-info {{ font-size: 0.9rem; color: #666; }}
.logout-btn {{ background: #dc3545; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; }}
.logout-btn:hover {{ background: #c82333; }}
.status {{ padding: 1rem; background: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px; color: #155724; margin-bottom: 1rem; }}
.btn {{ background: #007bff; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 4px; cursor: pointer; margin: 0.5rem; }}
.btn:hover {{ background: #0056b3; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 2rem 0; }}
.card {{ background: #f8f9fa; padding: 1.5rem; border-radius: 8px; border: 1px solid #dee2e6; }}
.card h3 {{ margin: 0 0 1rem 0; color: #495057; }}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>📧 Webmail Dashboard</h1>
<div>
<span class="user-info">Logged in as: <strong>{user_email}</strong></span>
<button class="logout-btn" onclick="logout()">🚪 Logout</button>
</div>
</div>
<div class="status">✅ Authentication successful! Welcome to your secure webmail interface.</div>

<div class="grid">
<div class="card">
<h3>📬 Your Emails</h3>
<p>Access and manage your email messages</p>
<button class="btn" onclick="testEmailList()">View Emails</button>
</div>
<div class="card">
<h3>📤 Send Email</h3>
<p>Compose and send new messages</p>
<button class="btn" onclick="testSend()">Send Test Email</button>
</div>
<div class="card">
<h3>🔧 System Status</h3>
<p>Check server and session health</p>
<button class="btn" onclick="showHealth()">Health Check</button>
</div>
<div class="card">
<h3>👥 Sessions</h3>
<p>View active user sessions</p>
<button class="btn" onclick="showSessions()">View Sessions</button>
</div>
</div>

<div id="test-results" style="margin-top: 2rem; padding: 1rem; background: #f8f9fa; border-radius: 4px; display: none;">
<h3>Results:</h3>
<pre id="results-content" style="background: white; padding: 1rem; border-radius: 4px; overflow-x: auto;"></pre>
</div>
</div>

<script>
async function makeAuthRequest(url, options) {{
    const token = localStorage.getItem('webmail_session');
    if (!token) {{
        window.location.href = '/login.html';
        return;
    }}

    const requestOptions = options || {{}};
    requestOptions.headers = requestOptions.headers || {{}};
    requestOptions.headers['Authorization'] = 'Bearer ' + token;

    const response = await fetch(url, requestOptions);

    if (response.status === 401) {{
        localStorage.removeItem('webmail_session');
        window.location.href = '/login.html';
        return;
    }}

    return response;
}}

async function logout() {{
    try {{
        await makeAuthRequest('/auth/logout', {{ method: 'POST' }});
    }} catch (error) {{
        console.error('Logout error:', error);
    }}
    localStorage.removeItem('webmail_session');
    window.location.href = '/login.html';
}}

async function testEmailList() {{
    const results = document.getElementById('test-results');
    const content = document.getElementById('results-content');

    try {{
        const response = await makeAuthRequest('/emails?limit=5');
        const data = await response.json();

        content.textContent = 'Email List (' + data.length + ' emails):\\n\\n' + JSON.stringify(data, null, 2);
        results.style.display = 'block';
    }} catch (error) {{
        content.textContent = 'Error fetching emails: ' + error.message;
        results.style.display = 'block';
    }}
}}

async function testSend() {{
    const to = prompt('Send test email to (email address):');
    if (!to) return;

    const results = document.getElementById('test-results');
    const content = document.getElementById('results-content');

    const emailBody = 'Hello!\\n\\nThis is a test email sent from your authenticated webmail system.\\n\\n✅ Authentication: Working\\n📧 Email delivery: Testing\\n🔒 Security: Enabled\\n\\nBest regards,\\nYour Webmail System';

    try {{
        const response = await makeAuthRequest('/send', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{
                to: to,
                subject: 'Test Email from Secure Webmail',
                body: emailBody
            }})
        }});

        const result = await response.text();
        content.textContent = 'Send Email Result:\\n\\n' + result;
        results.style.display = 'block';
    }} catch (error) {{
        content.textContent = 'Error sending email: ' + error.message;
        results.style.display = 'block';
    }}
}}

async function showHealth() {{
    const results = document.getElementById('test-results');
    const content = document.getElementById('results-content');

    try {{
        const response = await fetch('/health');
        const data = await response.json();

        content.textContent = 'System Health:\\n\\n' + JSON.stringify(data, null, 2);
        results.style.display = 'block';
    }} catch (error) {{
        content.textContent = 'Error checking health: ' + error.message;
        results.style.display = 'block';
    }}
}}

async function showSessions() {{
    const results = document.getElementById('test-results');
    const content = document.getElementById('results-content');

    try {{
        const response = await makeAuthRequest('/auth/sessions');
        const data = await response.json();

        content.textContent = 'Active Sessions:\\n\\n' + JSON.stringify(data, null, 2);
        results.style.display = 'block';
    }} catch (error) {{
        content.textContent = 'Error fetching sessions: ' + error.message;
        results.style.display = 'block';
    }}
}}
</script>
</body></html>"#
        );

        HttpResponse::Ok().content_type("text/html").body(main_html)
    } else {
        // User is not authenticated, always redirect to login
        HttpResponse::Found()
            .append_header(("Location", "/login.html"))
            .finish()
    }
}

// Include the content extraction functions from the original code
fn extract_body_content(raw_body: &[u8]) -> String {
    let body_str = String::from_utf8_lossy(raw_body);

    if body_str.contains("Content-Type: multipart/") {
        return extract_multipart_content(&body_str);
    }

    let decoded_content = decode_email_content(&body_str);

    if decoded_content.to_lowercase().contains("<html")
        || decoded_content.to_lowercase().contains("<!doctype")
        || decoded_content.contains("<div")
        || decoded_content.contains("<p>")
    {
        return extract_html_content(&decoded_content);
    }

    extract_plain_text(&decoded_content)
}

fn extract_multipart_content(content: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let mut result = Vec::new();
    let mut in_text_part = false;
    let mut in_html_part = false;
    let mut current_content = Vec::new();
    let mut boundary = String::new();

    for line in &lines {
        if line.contains("boundary=") {
            if let Some(boundary_part) = line.split("boundary=").nth(1) {
                boundary = boundary_part
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string();
                if boundary.starts_with('"') && boundary.ends_with('"') {
                    boundary = boundary[1..boundary.len() - 1].to_string();
                }
                break;
            }
        }
    }

    if boundary.is_empty() {
        return extract_plain_text(content);
    }

    for line in lines {
        if line.contains(&boundary) {
            if in_text_part || in_html_part {
                let content_str = current_content.join("\n");
                if in_html_part {
                    result.push(extract_html_content(&content_str));
                } else {
                    result.push(extract_plain_text(&content_str));
                }
                current_content.clear();
            }
            in_text_part = false;
            in_html_part = false;
            continue;
        }

        let line_lower = line.to_lowercase();
        if line_lower.starts_with("content-type:") {
            if line_lower.contains("text/plain") {
                in_text_part = true;
                in_html_part = false;
            } else if line_lower.contains("text/html") {
                in_html_part = true;
                in_text_part = false;
            }
            continue;
        }

        if line.starts_with("Content-") || line.starts_with("MIME-") {
            continue;
        }

        if (in_text_part || in_html_part) && !line.trim().is_empty() {
            current_content.push(line.to_string());
        }
    }

    if !current_content.is_empty() && (in_text_part || in_html_part) {
        let content_str = current_content.join("\n");
        if in_html_part {
            result.push(extract_html_content(&content_str));
        } else {
            result.push(extract_plain_text(&content_str));
        }
    }

    if result.is_empty() {
        extract_fallback_content(content)
    } else {
        result.join("\n\n---\n\n")
    }
}

fn extract_fallback_content(content: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let mut readable_lines = Vec::new();

    for line in lines {
        let trimmed = line.trim();

        if trimmed.is_empty()
            || trimmed.starts_with("--")
            || trimmed.starts_with("Content-")
            || trimmed.starts_with("MIME-")
            || trimmed.len() < 10
            || trimmed.chars().filter(|c| c.is_ascii_hexdigit()).count() > trimmed.len() / 2
        {
            continue;
        }

        let word_chars = trimmed.chars().filter(|c| c.is_alphabetic()).count();
        let total_chars = trimmed.chars().count();

        if total_chars > 0 && (word_chars as f32 / total_chars as f32) > 0.3 {
            readable_lines.push(trimmed.to_string());

            if readable_lines.join(" ").len() > 1000 {
                break;
            }
        }
    }

    if readable_lines.is_empty() {
        "This email contains technical content that cannot be displayed in a readable format."
            .to_string()
    } else {
        let result = readable_lines.join("\n");
        if result.len() > 1500 {
            format!(
                "{}...\n\n[Content truncated for readability]",
                &result[..1500]
            )
        } else {
            result
        }
    }
}

fn decode_email_content(content: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let mut decoded_lines = Vec::new();
    let mut current_encoding = "7bit";
    let mut in_headers = true;

    for line in &lines {
        let line_lower = line.to_lowercase();

        if in_headers {
            if line.trim().is_empty() {
                in_headers = false;
                continue;
            }

            if line_lower.starts_with("content-transfer-encoding:") {
                current_encoding = line.split(':').nth(1).unwrap_or("7bit").trim();
                continue;
            }

            if line_lower.starts_with("content-type:") && line_lower.contains("charset=") {
                if let Some(charset_part) = line_lower.split("charset=").nth(1) {
                    let _charset = charset_part.split(';').next().unwrap_or("utf-8").trim();
                }
                continue;
            }
            continue;
        }

        if line.starts_with("--") || line_lower.starts_with("content-") {
            continue;
        }

        let decoded_line = match current_encoding.to_lowercase().as_str() {
            "base64" => {
                use base64::{engine::general_purpose, Engine as _};
                if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(line.trim()) {
                    String::from_utf8_lossy(&decoded_bytes).to_string()
                } else {
                    line.to_string()
                }
            }
            "quoted-printable" => decode_quoted_printable(line),
            _ => line.to_string(),
        };

        if !decoded_line.trim().is_empty() && decoded_line.len() > 2 {
            decoded_lines.push(decoded_line);
        }

        if decoded_lines.join("").len() > 3000 {
            break;
        }
    }

    decoded_lines.join("\n")
}

fn decode_quoted_printable(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '=' {
            if chars.peek() == Some(&'\n') || chars.peek() == Some(&'\r') {
                chars.next();
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                continue;
            }

            if let (Some(h1), Some(h2)) = (chars.next(), chars.next()) {
                if let (Some(d1), Some(d2)) = (h1.to_digit(16), h2.to_digit(16)) {
                    let byte_value = (d1 * 16 + d2) as u8;
                    if let Ok(ch) = std::str::from_utf8(&[byte_value]) {
                        result.push_str(ch);
                    } else {
                        result.push(byte_value as char);
                    }
                } else {
                    result.push(c);
                    result.push(h1);
                    result.push(h2);
                }
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }

    result
}

fn extract_html_content(html: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    let mut in_script = false;
    let mut in_style = false;
    let mut current_tag = String::new();

    let chars: Vec<char> = html.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        if c == '<' {
            in_tag = true;
            current_tag.clear();
        } else if c == '>' && in_tag {
            in_tag = false;

            let tag_lower = current_tag.to_lowercase();
            if tag_lower.starts_with("script") {
                in_script = true;
            } else if tag_lower.starts_with("/script") {
                in_script = false;
            } else if tag_lower.starts_with("style") {
                in_style = true;
            } else if tag_lower.starts_with("/style") {
                in_style = false;
            } else if tag_lower == "br" || tag_lower == "br/" {
                result.push('\n');
            } else if tag_lower == "p" || tag_lower.starts_with("p ") {
                result.push_str("\n\n");
            } else if tag_lower == "/p" {
                result.push('\n');
            } else if tag_lower == "div" || tag_lower.starts_with("div ") {
                result.push('\n');
            }

            current_tag.clear();
        } else if in_tag {
            current_tag.push(c);
        } else if !in_script && !in_style {
            result.push(c);
        }

        i += 1;
    }

    let mut cleaned = result
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&rsquo;", "'")
        .replace("&ldquo;", "\"")
        .replace("&rdquo;", "\"")
        .replace("&mdash;", "—")
        .replace("&ndash;", "–");

    while cleaned.contains("  ") {
        cleaned = cleaned.replace("  ", " ");
    }

    while cleaned.contains("\n\n\n") {
        cleaned = cleaned.replace("\n\n\n", "\n\n");
    }

    let final_text = cleaned.trim().to_string();

    if final_text.len() > 2000 {
        format!("{}...\n\n[Content truncated]", &final_text[..2000])
    } else if final_text.is_empty() {
        "This email appears to contain only images or unsupported content.".to_string()
    } else {
        final_text
    }
}

fn extract_plain_text(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let mut content = Vec::new();

    for line in lines.iter().take(100) {
        let trimmed = line.trim();

        if trimmed.is_empty()
            || trimmed.starts_with("--")
            || trimmed.to_lowercase().contains("content-")
            || trimmed.len() < 3
        {
            continue;
        }

        let readable_chars = trimmed
            .chars()
            .filter(|c| c.is_alphabetic() || c.is_whitespace() || ".,!?-()[]{}:;\"'".contains(*c))
            .count();

        let total_chars = trimmed.chars().count();
        if total_chars > 0 && (readable_chars as f32 / total_chars as f32) > 0.6 {
            content.push(trimmed);

            if content.join(" ").len() > 1500 {
                break;
            }
        }
    }

    if content.is_empty() {
        "This email contains no readable text content.".to_string()
    } else {
        let result = content.join("\n");
        if result.len() > 2000 {
            format!("{}...\n\n[Content truncated]", &result[..2000])
        } else {
            result
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    println!("🚀 Starting Secure Webmail Server with Authentication...");

    let pool = init_db().await;

    if let Err(e) = update_db_schema(&pool).await {
        println!("⚠️ Schema update failed: {}", e);
    }

    let session_store = auth::create_session_store();

    let state = web::Data::new(AppState {
        db: pool,
        session_store: session_store.clone(),
    });

    println!("🌐 Server starting on http://127.0.0.1:3001");
    println!("🔐 Authentication Features:");
    println!("   🔑 Login page with credential testing");
    println!("   🛡️ Session-based authentication");
    println!("   👤 Per-user email isolation");
    println!("   📧 Multiple email provider support");
    println!("   🔒 Secure credential storage");

    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .wrap(Logger::default())
            .app_data(state.clone())
            .app_data(web::Data::new(session_store.clone()))
            // Authentication routes
            .route("/auth/login", web::post().to(auth::login_handler))
            .route("/auth/verify", web::get().to(auth::verify_handler))
            .route("/auth/logout", web::post().to(auth::logout_handler))
            .route(
                "/auth/provider/{provider}",
                web::get().to(auth::provider_config_handler),
            )
            .route("/auth/sessions", web::get().to(auth::list_sessions_handler))
            .route(
                "/auth/cleanup",
                web::post().to(auth::cleanup_sessions_handler),
            )
            // Email routes (require authentication)
            .route("/emails", web::get().to(fetch_emails))
            .route("/emails/new", web::get().to(check_new_emails))
            .route("/email/{id}", web::get().to(get_email))
            .route("/send", web::post().to(send_email))
            // Static routes
            .route("/login.html", web::get().to(serve_login_page))
            .route("/", web::get().to(serve_main_app))
            .route("/health", web::get().to(health_check))
    })
    .bind("127.0.0.1:3001")?
    .run()
    .await
}
