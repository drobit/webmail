use actix_web::{web, App, HttpResponse, HttpServer};
use actix_cors::Cors;
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::env;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use webpki_roots;
use futures::stream::StreamExt;
use tokio_util::compat::TokioAsyncReadCompatExt;


#[derive(Serialize, Deserialize)]
struct EmailRequest {
    to: String,
    subject: String,
    body: String,
}

#[derive(Serialize)]
struct Email {
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
    println!("Skipping database connection for now...");
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://localhost/dummy".to_string());
    match PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            println!("Database connection failed (continuing anyway): {:?}", e);
            panic!("Database connection failed: {:?}", e);
        }
    }
}

async fn send_email(data: web::Json<EmailRequest>, _state: web::Data<AppState>) -> HttpResponse {
    let smtp_user = env::var("SMTP_USER").unwrap_or_default();
    let smtp_pass = env::var("SMTP_PASS").unwrap_or_default();

    println!("SMTP_USER: '{}', SMTP_PASS length: {}", smtp_user, smtp_pass.len());

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

    println!("Attempting to send email...");
    match mailer.send(&email) {
        Ok(_) => {
            println!("Email sent successfully!");
            HttpResponse::Ok().body("Email sent successfully!")
        },
        Err(e) => {
            println!("Email send error: {:?}", e);
            HttpResponse::InternalServerError().body(format!("Email send failed: {:?}", e))
        },
    }
}

fn decode_mime_encoded_word(encoded: &str) -> String {
    // Simple decoder for =?charset?encoding?data?= format
    if encoded.starts_with("=?") && encoded.ends_with("?=") {
        let parts: Vec<&str> = encoded[2..encoded.len()-2].split('?').collect();
        if parts.len() == 3 {
            let _charset = parts[0];
            let encoding = parts[1].to_uppercase();
            let data = parts[2];

            match encoding.as_str() {
                "B" => {
                    // Base64 decode
                    use base64::{Engine as _, engine::general_purpose};
                    if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(data) {
                        return String::from_utf8_lossy(&decoded_bytes).to_string();
                    }
                }
                "Q" => {
                    // Quoted-printable decode (simplified)
                    return data.replace("_", " ");
                }
                _ => {}
            }
        }
    }
    encoded.to_string()
}

fn clean_email_body(raw_body: &[u8]) -> String {
    let body_str = String::from_utf8_lossy(raw_body);

    // Try to extract plain text from multipart MIME
    let lines: Vec<&str> = body_str.lines().collect();
    let mut in_text_part = false;
    let mut _in_html_part = false;
    let mut text_content = Vec::new();
    let mut current_encoding = "7bit".to_string();

    for line in lines {
        // Check for content type headers
        if line.to_lowercase().starts_with("content-type: text/plain") {
            in_text_part = true;
            _in_html_part = false;
            continue;
        } else if line.to_lowercase().starts_with("content-type: text/html") {
            in_text_part = false;
            _in_html_part = true;
            continue;
        } else if line.to_lowercase().starts_with("content-type:") && !line.to_lowercase().contains("text/") {
            in_text_part = false;
            _in_html_part = false;
            continue;
        }

        // Check for content encoding
        if line.to_lowercase().starts_with("content-transfer-encoding:") {
            current_encoding = line.split(':').nth(1).unwrap_or("7bit").trim().to_lowercase();
            continue;
        }

        // Skip headers and MIME boundaries
        if line.starts_with("--") || line.contains("Content-") || line.trim().is_empty() {
            continue;
        }

        // If we're in a text part, collect the content
        if in_text_part {
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
                    // Basic quoted-printable decoding
                    line.replace("=\r\n", "").replace("=\n", "")
                }
                _ => line.to_string()
            };
            text_content.push(decoded_line);

            // Limit content length
            if text_content.join("\n").len() > 500 {
                break;
            }
        }
    }

    let result = text_content.join("\n").trim().to_string();

    // If no text content found, try to get first few lines of raw content
    if result.is_empty() {
        body_str.lines()
            .filter(|line| !line.starts_with("--") && !line.contains("Content-") && !line.trim().is_empty())
            .take(3)
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(200)
            .collect()
    } else {
        result.chars().take(300).collect()
    }
}

async fn fetch_emails(_state: web::Data<AppState>) -> HttpResponse {
    let imap_user = env::var("IMAP_USER").unwrap_or_default();
    let imap_pass = env::var("IMAP_PASS").unwrap_or_default();

    if imap_user.is_empty() || imap_pass.is_empty() {
        return HttpResponse::BadRequest().body("IMAP credentials not configured");
    }

    println!("Attempting IMAP connection to Gmail...");

    let domain = "imap.gmail.com";
    let port = 993;
    let socket_addr = (domain, port);

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(std::sync::Arc::new(config));

    let tcp_stream = match TcpStream::connect(socket_addr).await {
        Ok(stream) => {
            println!("TCP connection established");
            stream
        },
        Err(e) => {
            println!("TCP connect error: {:?}", e);
            return HttpResponse::InternalServerError().body(format!("TCP connect error: {:?}", e));
        }
    };

    let tls_stream = match connector
        .connect(
            rustls::pki_types::ServerName::try_from(domain).unwrap().to_owned(),
            tcp_stream,
        )
        .await
    {
        Ok(stream) => {
            println!("TLS connection established");
            stream
        },
        Err(e) => {
            println!("TLS connect error: {:?}", e);
            return HttpResponse::InternalServerError().body(format!("TLS connect error: {:?}", e));
        }
    };

    let compat_stream = tls_stream.compat();
    let client = async_imap::Client::new(compat_stream);

    let mut imap_session = match client.login(&imap_user, &imap_pass).await {
        Ok(session) => {
            println!("IMAP login successful");
            session
        },
        Err(e) => {
            println!("IMAP login error: {:?}", e);
            return HttpResponse::InternalServerError().body(format!("IMAP login error: {:?}", e));
        }
    };

    let mailbox = match imap_session.select("INBOX").await {
        Ok(mailbox) => {
            println!("INBOX selected successfully. Messages: {}", mailbox.exists);
            mailbox
        },
        Err(e) => {
            println!("Select error: {:?}", e);
            return HttpResponse::InternalServerError().body(format!("Select error: {:?}", e));
        }
    };

    // Get the last 20 messages (most recent)
    let message_count = mailbox.exists;
    let start_uid = if message_count > 20 { message_count - 19 } else { 1 };
    let fetch_range = format!("{}:{}", start_uid, message_count);

    println!("Fetching messages: {}", fetch_range);

    let messages_stream = match imap_session.fetch(&fetch_range, "(FLAGS ENVELOPE BODY[TEXT] INTERNALDATE)").await {
        Ok(stream) => {
            println!("Fetch command sent successfully");
            stream
        },
        Err(e) => {
            println!("Fetch error: {:?}", e);
            return HttpResponse::InternalServerError().body(format!("Fetch error: {:?}", e));
        }
    };

    let messages: Vec<_> = messages_stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .filter_map(Result::ok)
        .collect();

    println!("Collected {} messages", messages.len());

    let mut emails = vec![];
    for (i, message) in messages.iter().enumerate() {
        println!("Processing message {}", i + 1);

        if let Some(envelope) = message.envelope() {
            let cleaned_body = message
                .text()
                .map(|b: &[u8]| clean_email_body(b))
                .unwrap_or_default();

            let subject = envelope.subject
                .as_ref()
                .map(|s| decode_mime_encoded_word(&String::from_utf8_lossy(s)))
                .unwrap_or("No Subject".to_string());

            let from = envelope.from
                .as_ref()
                .and_then(|addrs| addrs.first())
                .map(|addr| {
                    let name = addr.name.as_ref()
                        .map(|n| decode_mime_encoded_word(&String::from_utf8_lossy(n)))
                        .unwrap_or_default();
                    let mailbox = addr.mailbox.as_ref()
                        .map(|m| String::from_utf8_lossy(m))
                        .unwrap_or_default();
                    let host = addr.host.as_ref()
                        .map(|h| String::from_utf8_lossy(h))
                        .unwrap_or_default();

                    if !name.is_empty() {
                        format!("{} <{}@{}>", name, mailbox, host)
                    } else {
                        format!("{}@{}", mailbox, host)
                    }
                })
                .unwrap_or("Unknown".to_string());

            let date = message.internal_date()
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string());

            let flags: Vec<_> = message.flags().collect();
            let is_seen = flags.iter().any(|f| matches!(f, async_imap::types::Flag::Seen));
            let is_recent = flags.iter().any(|f| matches!(f, async_imap::types::Flag::Recent));

            emails.push(Email {
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

    // Sort by date (newest first) - use message order as proxy since Gmail returns in date order
    emails.reverse();

    if let Err(e) = imap_session.logout().await {
        println!("Logout error (non-fatal): {:?}", e);
    }

    println!("Returning {} emails", emails.len());
    HttpResponse::Ok().json(emails)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();

    // Install default crypto provider for rustls
    rustls::crypto::ring::default_provider().install_default().expect("Failed to install rustls crypto provider");

    println!("Starting webmail server...");

    let pool = init_db().await;
    let state = web::Data::new(AppState { db: pool });

    println!("Database connected, starting HTTP server on 127.0.0.1:3001");

    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .app_data(state.clone())
            .route("/send", web::post().to(send_email))
            .route("/fetch", web::get().to(fetch_emails))
    })
        .bind("127.0.0.1:3001")?
        .run()
        .await
}