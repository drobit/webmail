use actix_cors::Cors;
use actix_web::{web, App, HttpResponse, HttpServer};
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

// Import from lib.rs
use webmail::{EmailDetail, EmailListItem, EmailRequest};

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
        }
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

// Modified database schema to include UID for fast access
async fn update_db_schema(pool: &PgPool) -> Result<(), sqlx::Error> {
    // Add missing columns if they don't exist
    let schema_updates = [
        "ALTER TABLE emails ADD COLUMN IF NOT EXISTS imap_uid INTEGER",
        "ALTER TABLE emails ADD COLUMN IF NOT EXISTS is_seen BOOLEAN DEFAULT FALSE",
        "ALTER TABLE emails ADD COLUMN IF NOT EXISTS is_recent BOOLEAN DEFAULT FALSE",
        "ALTER TABLE emails ADD COLUMN IF NOT EXISTS body_preview TEXT",
    ];

    for update in &schema_updates {
        if let Err(e) = sqlx::query(update).execute(pool).await {
            println!("⚠️ Schema update warning: {} - {}", update, e);
        }
    }

    // Create index on UID for fast lookups (ignore if exists)
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_emails_imap_uid ON emails(imap_uid)")
        .execute(pool)
        .await;

    Ok(())
}

// Get cached emails with optimized query
async fn get_cached_emails(pool: &PgPool, limit: i64) -> Result<Vec<EmailListItem>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT message_id, from_address, subject, created_at, is_seen, is_recent, imap_uid
         FROM emails
         ORDER BY created_at DESC NULLS LAST
         LIMIT $1",
    )
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

            // Use UID-based ID for faster access
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

// Get email detail with UID support
async fn get_email_detail(
    pool: &PgPool,
    message_id: &str,
) -> Result<Option<EmailDetail>, sqlx::Error> {
    let query = if message_id.starts_with("uid_") {
        // Fast UID-based lookup
        if let Ok(uid) = message_id[4..].parse::<i32>() {
            sqlx::query(
                "SELECT message_id, from_address, subject, body, created_at, is_seen, is_recent, imap_uid
                 FROM emails
                 WHERE imap_uid = $1",
            )
                .bind(uid)
                .fetch_optional(pool)
                .await?
        } else {
            return Ok(None);
        }
    } else {
        // Fallback to message_id lookup
        sqlx::query(
            "SELECT message_id, from_address, subject, body, created_at, is_seen, is_recent, imap_uid
             FROM emails
             WHERE message_id = $1",
        )
            .bind(message_id)
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

// BATCH fetch with full email content - one connection, multiple emails
async fn batch_fetch_emails_with_bodies(
    limit: u32,
) -> Result<Vec<EmailDetail>, Box<dyn std::error::Error + Send + Sync>> {
    println!("🚀 BATCH fetching {} emails with bodies", limit);
    let start_time = std::time::Instant::now();

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

    let fetch_limit = limit.min(15); // Reasonable limit for batch
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

    // CRITICAL: Fetch EVERYTHING in one go - headers AND bodies
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

        // Parse headers
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

        // Extract body text
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
            id: format!("uid_{}", uid), // Always use UID for fast access
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

// Better content extraction with proper decoding
fn extract_body_content(raw_body: &[u8]) -> String {
    let body_str = String::from_utf8_lossy(raw_body);

    // Handle multipart emails (like the delivery failure notification)
    if body_str.contains("Content-Type: multipart/") {
        return extract_multipart_content(&body_str);
    }

    // First, try to detect and handle different content encodings
    let decoded_content = decode_email_content(&body_str);

    // Check if it's HTML content
    if decoded_content.to_lowercase().contains("<html")
        || decoded_content.to_lowercase().contains("<!doctype")
        || decoded_content.contains("<div")
        || decoded_content.contains("<p>")
    {
        return extract_html_content(&decoded_content);
    }

    // Plain text processing
    extract_plain_text(&decoded_content)
}

// Handle multipart email content
fn extract_multipart_content(content: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let mut result = Vec::new();
    let mut in_text_part = false;
    let mut in_html_part = false;
    let mut current_content = Vec::new();
    let mut boundary = String::new();

    // Find the boundary
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
        // Check for boundary markers
        if line.contains(&boundary) {
            // Process accumulated content
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

        // Check content type headers
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

        // Skip other headers in parts
        if line.starts_with("Content-") || line.starts_with("MIME-") {
            continue;
        }

        // Collect content if we're in a text or HTML part
        if (in_text_part || in_html_part) && !line.trim().is_empty() {
            current_content.push(line.to_string());
        }
    }

    // Process any remaining content
    if !current_content.is_empty() && (in_text_part || in_html_part) {
        let content_str = current_content.join("\n");
        if in_html_part {
            result.push(extract_html_content(&content_str));
        } else {
            result.push(extract_plain_text(&content_str));
        }
    }

    if result.is_empty() {
        // Fallback: try to extract any readable text
        extract_fallback_content(content)
    } else {
        result.join("\n\n---\n\n")
    }
}

// Fallback content extraction for complex emails
fn extract_fallback_content(content: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let mut readable_lines = Vec::new();

    for line in lines {
        let trimmed = line.trim();

        // Skip technical lines
        if trimmed.is_empty()
            || trimmed.starts_with("--")
            || trimmed.starts_with("Content-")
            || trimmed.starts_with("MIME-")
            || trimmed.len() < 10
            || trimmed.chars().filter(|c| c.is_ascii_hexdigit()).count() > trimmed.len() / 2
        {
            continue;
        }

        // Look for lines with actual readable content
        let word_chars = trimmed.chars().filter(|c| c.is_alphabetic()).count();
        let total_chars = trimmed.chars().count();

        if total_chars > 0 && (word_chars as f32 / total_chars as f32) > 0.3 {
            readable_lines.push(trimmed.to_string());

            // Stop if we have enough content
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

// Decode email content handling various encodings
fn decode_email_content(content: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let mut decoded_lines = Vec::new();
    let mut current_encoding = "7bit";
    let mut in_headers = true;
    let _charset = "utf-8";

    for line in &lines {
        let line_lower = line.to_lowercase();

        // Check for encoding information in headers
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

        // Skip MIME boundaries and other technical lines
        if line.starts_with("--") || line_lower.starts_with("content-") {
            continue;
        }

        // Decode based on encoding
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

        // Only add lines with actual content
        if !decoded_line.trim().is_empty() && decoded_line.len() > 2 {
            decoded_lines.push(decoded_line);
        }

        // Stop if we have enough content
        if decoded_lines.join("").len() > 3000 {
            break;
        }
    }

    decoded_lines.join("\n")
}

// Decode quoted-printable encoding
fn decode_quoted_printable(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '=' {
            // Handle soft line breaks (=\n or =\r\n)
            if chars.peek() == Some(&'\n') || chars.peek() == Some(&'\r') {
                chars.next(); // consume \n or \r
                if chars.peek() == Some(&'\n') {
                    chars.next(); // consume \n if we had \r\n
                }
                continue; // soft line break, don't add anything
            }

            // Handle hex encoding (=XX)
            if let (Some(h1), Some(h2)) = (chars.next(), chars.next()) {
                if let (Some(d1), Some(d2)) = (h1.to_digit(16), h2.to_digit(16)) {
                    let byte_value = (d1 * 16 + d2) as u8;
                    if let Ok(ch) = std::str::from_utf8(&[byte_value]) {
                        result.push_str(ch);
                    } else {
                        result.push(byte_value as char);
                    }
                } else {
                    // Invalid hex, add as-is
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

    // Clean up the result
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

    // Remove excessive whitespace
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

        // Skip empty lines and technical content
        if trimmed.is_empty()
            || trimmed.starts_with("--")
            || trimmed.to_lowercase().contains("content-")
            || trimmed.len() < 3
        {
            continue;
        }

        // Check if line contains readable text (not just encoded garbage)
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

// Cache update with UID support
async fn cache_emails_with_uid(pool: &PgPool, emails: &[EmailDetail]) -> Result<(), sqlx::Error> {
    for email in emails {
        let uid = if email.id.starts_with("uid_") {
            email.id[4..].parse::<i32>().ok()
        } else {
            None
        };

        sqlx::query(
            "INSERT INTO emails (message_id, from_address, to_address, subject, body, created_at, fetched_at, is_seen, is_recent, imap_uid, body_preview)
             VALUES ($1, $2, '', $3, $4, NOW(), NOW(), $5, $6, $7, LEFT($4, 200))
             ON CONFLICT (message_id) DO UPDATE SET
                body = EXCLUDED.body,
                fetched_at = NOW(),
                is_seen = EXCLUDED.is_seen,
                is_recent = EXCLUDED.is_recent,
                imap_uid = EXCLUDED.imap_uid,
                body_preview = EXCLUDED.body_preview"
        )
            .bind(&email.id)
            .bind(&email.from)
            .bind(&email.subject)
            .bind(&email.body)
            .bind(email.is_seen)
            .bind(email.is_recent)
            .bind(uid)
            .execute(pool)
            .await?;
    }
    Ok(())
}

async fn fetch_emails(
    query: web::Query<HashMap<String, String>>,
    state: web::Data<AppState>,
) -> HttpResponse {
    println!("📧 Email list requested");

    let limit = query
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(50)
        .min(50);

    let force_refresh = query.get("refresh").map(|s| s == "true").unwrap_or(false);

    // Always try cache first for instant response
    if !force_refresh {
        match get_cached_emails(&state.db, limit).await {
            Ok(cached_emails) if !cached_emails.is_empty() => {
                println!("⚡ INSTANT: Serving {} cached emails", cached_emails.len());
                return HttpResponse::Ok().json(cached_emails);
            }
            _ => {}
        }
    }

    // Need to fetch from IMAP - use batch method
    println!("🚀 Fetching fresh emails with BATCH method");
    match batch_fetch_emails_with_bodies(15).await {
        Ok(emails) => {
            // Cache in background
            let db_clone = state.db.clone();
            let emails_clone = emails.clone();
            tokio::spawn(async move {
                if let Err(e) = cache_emails_with_uid(&db_clone, &emails_clone).await {
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
        Err(e) => {
            // Fallback to cache if IMAP fails
            match get_cached_emails(&state.db, limit).await {
                Ok(cached_emails) if !cached_emails.is_empty() => {
                    println!("📄 Serving cached emails as fallback");
                    HttpResponse::Ok().json(cached_emails)
                }
                _ => HttpResponse::InternalServerError()
                    .body(format!("Failed to fetch emails: {}", e)),
            }
        }
    }
}

async fn check_new_emails(
    _query: web::Query<HashMap<String, String>>,
    _state: web::Data<AppState>,
) -> HttpResponse {
    HttpResponse::Ok().json(Vec::<EmailListItem>::new())
}

async fn get_email(path: web::Path<String>, state: web::Data<AppState>) -> HttpResponse {
    let message_id = path.into_inner();
    println!("📖 Email requested: {}", message_id);

    // Try cache first - should be instant since we batch fetch with bodies
    match get_email_detail(&state.db, &message_id).await {
        Ok(Some(email)) => {
            // Check if we have the body already
            if email.body != "Click to load content..." && !email.body.is_empty() {
                println!("⚡ INSTANT: Serving cached email body");
                return HttpResponse::Ok().json(email);
            }

            // If no body, return what we have with a loading message
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

    println!("🚀 Starting TRULY FAST Webmail Server...");

    let pool = init_db().await;

    // Update database schema
    if let Err(e) = update_db_schema(&pool).await {
        println!("⚠️ Schema update failed: {}", e);
    }

    let state = web::Data::new(AppState { db: pool });

    println!("🌐 Server starting on http://127.0.0.1:3001");
    println!("⚡ TRULY FAST Features:");
    println!("   📦 BATCH fetching (headers + bodies together)");
    println!("   🔢 UID-based fast lookups");
    println!("   🎯 HTML content extraction");
    println!("   ⚡ Target: INSTANT email opening");

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
