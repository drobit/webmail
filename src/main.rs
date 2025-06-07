use actix_web::{web, App, HttpResponse, HttpServer};
use actix_cors::Cors;
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, postgres::PgPoolOptions, Row};
use std::env;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use webpki_roots;
use futures::stream::StreamExt;
use tokio_util::compat::TokioAsyncReadCompatExt;
use chrono::Utc;

#[derive(Serialize, Deserialize)]
struct EmailRequest {
    to: String,
    subject: String,
    body: String,
}

#[derive(Serialize, Clone)]
struct EmailListItem {
    id: String,
    from: String,
    subject: String,
    date: Option<String>,
    is_seen: bool,
    is_recent: bool,
}

#[derive(Serialize, Clone)]
struct EmailDetail {
    id: String,
    from: String,
    subject: String,
    body: String,
    date: Option<String>,
    is_seen: bool,
    is_recent: bool,
}

#[derive(Clone)]
struct AppState {
    db: PgPool,
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
        },
        Err(e) => {
            println!("❌ Database connection failed: {:?}", e);
            println!("📝 Make sure PostgreSQL is running and DATABASE_URL is correct");
            std::process::exit(1);
        }
    }
}

async fn send_email(data: web::Json<EmailRequest>, state: web::Data<AppState>) -> HttpResponse {
    let smtp_user = env::var("SMTP_USER").unwrap_or_default();
    let smtp_pass = env::var("SMTP_PASS").unwrap_or_default();

    if smtp_user.is_empty() || smtp_pass.is_empty() {
        return HttpResponse::BadRequest().body("SMTP credentials not configured");
    }

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
    let mailer = SmtpTransport::starttls_relay("smtp.gmail.com")
        .unwrap()
        .port(587)
        .credentials(creds)
        .build();

    match mailer.send(&email) {
        Ok(_) => {
            // Log sent email to database
            let _ = sqlx::query(
                "INSERT INTO sent_emails (to_address, subject, body) VALUES ($1, $2, $3)"
            )
                .bind(&data.to)
                .bind(&data.subject)
                .bind(&data.body)
                .execute(&state.db)
                .await;

            HttpResponse::Ok().body("Email sent successfully!")
        },
        Err(e) => HttpResponse::InternalServerError().body(format!("Email send failed: {:?}", e)),
    }
}

fn decode_mime_word_fast(encoded: &str) -> String {
    if !encoded.starts_with("=?") || !encoded.ends_with("?=") {
        return encoded.to_string();
    }

    if let Some(start) = encoded.find("?B?") {
        use base64::{Engine as _, engine::general_purpose};
        if let Ok(decoded) = general_purpose::STANDARD.decode(&encoded[start+3..encoded.len()-2]) {
            return String::from_utf8_lossy(&decoded).to_string();
        }
    }

    encoded.to_string()
}

fn strip_html_tags(html: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;

    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ => if !in_tag { result.push(c); }
        }
    }

    result.trim().to_string()
}

fn clean_email_body_fast(raw_body: &[u8]) -> String {
    let body_str = String::from_utf8_lossy(raw_body);

    let lines: Vec<&str> = body_str.lines().collect();
    let mut in_text_part = false;
    let mut in_html_part = false;
    let mut text_content = Vec::new();
    let mut current_encoding = "7bit".to_string();
    let mut is_multipart = false;

    for line in &lines {
        if line.to_lowercase().contains("content-type: multipart") {
            is_multipart = true;
            break;
        }
    }

    for line in lines {
        let line_lower = line.to_lowercase();

        if line_lower.starts_with("content-type:") {
            if line_lower.contains("text/plain") {
                in_text_part = true;
                in_html_part = false;
                continue;
            } else if line_lower.contains("text/html") {
                in_text_part = false;
                in_html_part = true;
                continue;
            } else if line_lower.contains("multipart") || line_lower.contains("image") || line_lower.contains("application") {
                in_text_part = false;
                in_html_part = false;
                continue;
            }
        }

        if line_lower.starts_with("content-transfer-encoding:") {
            current_encoding = line.split(':').nth(1).unwrap_or("7bit").trim().to_lowercase();
            continue;
        }

        if line.starts_with("--") ||
            line_lower.starts_with("content-") ||
            line_lower.starts_with("mime-version") ||
            line_lower.starts_with("date:") ||
            line_lower.starts_with("from:") ||
            line_lower.starts_with("to:") ||
            line_lower.starts_with("subject:") ||
            line.trim().is_empty() {
            continue;
        }

        if !is_multipart && !line_lower.contains("content-") && !line_lower.contains(":") {
            in_text_part = true;
        }

        if in_text_part || (!is_multipart && text_content.is_empty()) {
            let decoded_line = match current_encoding.as_str() {
                "base64" => {
                    use base64::{Engine as _, engine::general_purpose};
                    if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(line.trim()) {
                        String::from_utf8_lossy(&decoded_bytes).to_string()
                    } else {
                        line.to_string()
                    }
                }
                "quoted-printable" => {
                    line.replace("=\r\n", "").replace("=\n", "").replace("_", " ")
                }
                _ => line.to_string()
            };

            if !decoded_line.chars().all(|c| c.is_control() || c as u32 > 127) {
                text_content.push(decoded_line);
            }

            if text_content.join("\n").len() > 500 {
                break;
            }
        }

        if in_html_part && text_content.is_empty() {
            let cleaned_html = strip_html_tags(line);
            if !cleaned_html.trim().is_empty() && cleaned_html.len() > 10 {
                text_content.push(cleaned_html);
                if text_content.join("\n").len() > 300 {
                    break;
                }
            }
        }
    }

    let result = text_content.join("\n").trim().to_string();

    if result.is_empty() || result.len() < 20 {
        let readable_lines: Vec<String> = body_str
            .lines()
            .filter(|line| {
                !line.starts_with("--") &&
                    !line.to_lowercase().contains("content-") &&
                    !line.trim().is_empty() &&
                    line.len() > 5 &&
                    line.chars().filter(|c| c.is_alphabetic()).count() > line.len() / 3
            })
            .take(5)
            .map(|s| s.to_string())
            .collect();

        if !readable_lines.is_empty() {
            return readable_lines.join(" ").chars().take(300).collect();
        }
    }

    if result.is_empty() {
        "No readable content found".to_string()
    } else {
        result.chars().take(300).collect()
    }
}

async fn get_cached_emails(pool: &PgPool, limit: i64) -> Result<Vec<EmailListItem>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT message_id, from_address, subject, created_at
         FROM emails
         ORDER BY created_at DESC NULLS LAST, id DESC
         LIMIT $1"
    )
        .bind(limit)
        .fetch_all(pool)
        .await?;

    Ok(rows.into_iter().map(|row| {
        let created_at: Option<chrono::DateTime<chrono::Utc>> = row.get("created_at");
        let is_recent = created_at
            .map(|dt| Utc::now().signed_duration_since(dt).num_hours() < 24)
            .unwrap_or(false);

        EmailListItem {
            id: row.get::<Option<String>, _>("message_id").unwrap_or_else(|| "unknown".to_string()),
            from: row.get("from_address"),
            subject: row.get::<Option<String>, _>("subject").unwrap_or_else(|| "No Subject".to_string()),
            date: created_at.map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string()),
            is_seen: true,
            is_recent,
        }
    }).collect())
}

async fn get_email_detail(pool: &PgPool, message_id: &str) -> Result<Option<EmailDetail>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT message_id, from_address, subject, body, created_at
         FROM emails
         WHERE message_id = $1"
    )
        .bind(message_id)
        .fetch_optional(pool)
        .await?;

    if let Some(row) = row {
        let created_at: Option<chrono::DateTime<chrono::Utc>> = row.get("created_at");
        let is_recent = created_at
            .map(|dt| Utc::now().signed_duration_since(dt).num_hours() < 24)
            .unwrap_or(false);

        Ok(Some(EmailDetail {
            id: row.get::<Option<String>, _>("message_id").unwrap_or_else(|| "unknown".to_string()),
            from: row.get("from_address"),
            subject: row.get::<Option<String>, _>("subject").unwrap_or_else(|| "No Subject".to_string()),
            body: row.get::<Option<String>, _>("body").unwrap_or_else(|| "No content".to_string()),
            date: created_at.map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string()),
            is_seen: true,
            is_recent,
        }))
    } else {
        Ok(None)
    }
}

async fn cache_emails(pool: &PgPool, emails: &[EmailDetail]) -> Result<(), sqlx::Error> {
    if emails.is_empty() {
        return Ok(());
    }

    for email in emails {
        sqlx::query(
            "INSERT INTO emails (message_id, from_address, to_address, subject, body, created_at, fetched_at)
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
             ON CONFLICT (message_id)
             DO UPDATE SET
                fetched_at = NOW()"
        )
            .bind(&email.id)
            .bind(&email.from)
            .bind("")
            .bind(&email.subject)
            .bind(&email.body)
            .execute(pool)
            .await?;
    }

    Ok(())
}

async fn fetch_emails_from_imap(limit: u32) -> Result<Vec<EmailDetail>, Box<dyn std::error::Error + Send + Sync>> {
    let imap_user = env::var("IMAP_USER")?;
    let imap_pass = env::var("IMAP_PASS")?;

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(config));

    let tcp_stream = TcpStream::connect(("imap.gmail.com", 993)).await?;
    let tls_stream = connector
        .connect(
            rustls::pki_types::ServerName::try_from("imap.gmail.com")?.to_owned(),
            tcp_stream,
        )
        .await?;

    let compat_stream = tls_stream.compat();
    let client = async_imap::Client::new(compat_stream);
    let mut imap_session = client.login(&imap_user, &imap_pass).await
        .map_err(|e| format!("IMAP login failed: {:?}", e))?;

    let mailbox = imap_session.select("INBOX").await?;
    let message_count = mailbox.exists;

    if message_count == 0 {
        return Ok(Vec::new());
    }

    let start_uid = if message_count > limit { message_count - limit + 1 } else { 1 };
    let fetch_range = format!("{}:{}", start_uid, message_count);

    let messages_stream = imap_session
        .fetch(&fetch_range, "(FLAGS ENVELOPE BODY[TEXT] INTERNALDATE UID)")
        .await?;

    let messages: Vec<_> = messages_stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .filter_map(Result::ok)
        .collect();

    let now = Utc::now();
    let mut emails = Vec::with_capacity(messages.len());

    for (i, message) in messages.iter().enumerate() {
        if let Some(envelope) = message.envelope() {
            let cleaned_body = message
                .text()
                .map(|b: &[u8]| clean_email_body_fast(b))
                .unwrap_or_default();

            let subject = envelope.subject
                .as_ref()
                .map(|s| decode_mime_word_fast(&String::from_utf8_lossy(s)))
                .unwrap_or("No Subject".to_string());

            let from = envelope.from
                .as_ref()
                .and_then(|addrs| addrs.first())
                .map(|addr| {
                    let name = addr.name.as_ref()
                        .map(|n| decode_mime_word_fast(&String::from_utf8_lossy(n)))
                        .unwrap_or_default();
                    let mailbox = addr.mailbox.as_ref()
                        .map(|m| String::from_utf8_lossy(m).to_string())
                        .unwrap_or_default();
                    let host = addr.host.as_ref()
                        .map(|h| String::from_utf8_lossy(h).to_string())
                        .unwrap_or_default();

                    if !name.is_empty() {
                        format!("{} <{}@{}>", name, mailbox, host)
                    } else {
                        format!("{}@{}", mailbox, host)
                    }
                })
                .unwrap_or("Unknown".to_string());

            let date = message.internal_date()
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string());

            let flags: Vec<_> = message.flags().collect();
            let is_seen = flags.iter().any(|f| matches!(f, async_imap::types::Flag::Seen));
            let is_recent = message.internal_date()
                .map(|dt| now.signed_duration_since(dt).num_hours() < 24)
                .unwrap_or(false);

            emails.push(EmailDetail {
                id: envelope.message_id
                    .as_ref()
                    .map(|id| String::from_utf8_lossy(id).to_string())
                    .unwrap_or_else(|| format!("msg_{}", i)),
                from,
                subject,
                body: cleaned_body,
                date,
                is_seen,
                is_recent,
            });
        }
    }

    let _ = imap_session.logout().await;
    emails.reverse();
    Ok(emails)
}

async fn fetch_emails(
    query: web::Query<std::collections::HashMap<String, String>>,
    state: web::Data<AppState>
) -> HttpResponse {
    let limit = query.get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(50)
        .min(200);

    let force_refresh = query.get("refresh").map(|s| s == "true").unwrap_or(false);

    if !force_refresh {
        if let Ok(cached_emails) = get_cached_emails(&state.db, limit).await {
            if !cached_emails.is_empty() {
                return HttpResponse::Ok().json(cached_emails);
            }
        }
    }

    match fetch_emails_from_imap(limit as u32).await {
        Ok(emails) => {
            let _ = cache_emails(&state.db, &emails).await;

            let email_list: Vec<EmailListItem> = emails.into_iter().map(|email| {
                EmailListItem {
                    id: email.id,
                    from: email.from,
                    subject: email.subject,
                    date: email.date,
                    is_seen: email.is_seen,
                    is_recent: email.is_recent,
                }
            }).collect();

            HttpResponse::Ok().json(email_list)
        },
        Err(e) => {
            match get_cached_emails(&state.db, limit).await {
                Ok(cached_emails) if !cached_emails.is_empty() => {
                    HttpResponse::Ok().json(cached_emails)
                },
                _ => HttpResponse::InternalServerError().body(format!("Failed to fetch emails: {}", e))
            }
        }
    }
}

async fn check_new_emails(
    query: web::Query<std::collections::HashMap<String, String>>,
    state: web::Data<AppState>
) -> HttpResponse {
    let since = query.get("since").cloned();

    let since_timestamp = if let Some(since_str) = since {
        since_str
    } else {
        match sqlx::query("SELECT MAX(created_at) as latest FROM emails")
            .fetch_one(&state.db)
            .await
        {
            Ok(row) => {
                let latest: Option<chrono::DateTime<chrono::Utc>> = row.get("latest");
                latest.map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "1970-01-01 00:00:00".to_string())
            },
            Err(_) => "1970-01-01 00:00:00".to_string()
        }
    };

    match fetch_emails_from_imap(10).await {
        Ok(emails) => {
            let new_emails: Vec<_> = emails.into_iter()
                .filter(|email| {
                    if let Some(email_date) = &email.date {
                        email_date > &since_timestamp
                    } else {
                        false
                    }
                })
                .collect();

            if !new_emails.is_empty() {
                let _ = cache_emails(&state.db, &new_emails).await;

                let email_list: Vec<EmailListItem> = new_emails.into_iter().map(|email| {
                    EmailListItem {
                        id: email.id,
                        from: email.from,
                        subject: email.subject,
                        date: email.date,
                        is_seen: email.is_seen,
                        is_recent: email.is_recent,
                    }
                }).collect();

                HttpResponse::Ok().json(email_list)
            } else {
                HttpResponse::Ok().json(Vec::<EmailListItem>::new())
            }
        },
        Err(e) => {
            HttpResponse::InternalServerError().body(format!("Failed to check for new emails: {}", e))
        }
    }
}

async fn get_email(
    path: web::Path<String>,
    state: web::Data<AppState>
) -> HttpResponse {
    let message_id = path.into_inner();

    match get_email_detail(&state.db, &message_id).await {
        Ok(Some(email)) => HttpResponse::Ok().json(email),
        Ok(None) => HttpResponse::NotFound().body("Email not found"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {:?}", e)),
    }
}

async fn health_check(state: web::Data<AppState>) -> HttpResponse {
    let db_status = match sqlx::query("SELECT 1").fetch_one(&state.db).await {
        Ok(_) => "healthy",
        Err(_) => "unhealthy",
    };

    let response = serde_json::json!({
        "status": "ok",
        "database": db_status,
        "timestamp": Utc::now().to_rfc3339()
    });

    HttpResponse::Ok().json(response)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    println!("🚀 Starting Roundcube-Style Rust Webmail Server...");

    let pool = init_db().await;
    let state = web::Data::new(AppState { db: pool });

    println!("🌐 Server starting on http://127.0.0.1:3001");
    println!("📋 Endpoints:");
    println!("   GET  /emails             - Get email list");
    println!("   GET  /emails?refresh=true - Force refresh from IMAP");
    println!("   GET  /emails/new         - Check for new emails only");
    println!("   GET  /email/{{id}}         - Get full email detail");
    println!("   POST /send               - Send email");
    println!("   GET  /health             - Health check");

    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .app_data(state.clone())
            .route("/emails", web::get().to(fetch_emails))
            .route("/emails/new", web::get().to(check_new_emails))
            .route("/email/{id}", web::get().to(get_email))
            .route("/send", web::post().to(send_email))
            .route("/health", web::get().to(health_check))
    })
        .bind("127.0.0.1:3001")?
        .run()
        .await
}