use actix_web::{web, App, HttpResponse, HttpServer};
use actix_cors::Cors;
use lettre::{Message, SmtpTransport, Transport};
use lettre::message::header::ContentType;
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
}

#[derive(Clone)]
struct AppState {
    db: PgPool,
}

async fn init_db() -> PgPool {
    // Temporarily comment out database connection for testing
    println!("Skipping database connection for now...");
    // We'll return a dummy pool that we won't actually use
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://localhost/dummy".to_string());
    match PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            println!("Database connection failed (continuing anyway): {:?}", e);
            // For now, let's panic to see the exact error
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
        .header(ContentType::TEXT_PLAIN)
        .body(data.body.clone())
    {
        Ok(email) => email,
        Err(e) => return HttpResponse::BadRequest().body(format!("Email building error: {:?}", e)),
    };

    let creds = Credentials::new(smtp_user, smtp_pass);
    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .port(587)
        .credentials(creds)
        .build();

    println!("Attempting to send email...");
    match mailer.send(&email) {
        Ok(_) => {
            println!("Email sent successfully!");
            HttpResponse::Ok().body("Email sent")
        },
        Err(e) => {
            println!("Email send error: {:?}", e);
            HttpResponse::InternalServerError().body(format!("Error: {:?}", e))
        },
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

    match imap_session.select("INBOX").await {
        Ok(_) => println!("INBOX selected successfully"),
        Err(e) => {
            println!("Select error: {:?}", e);
            return HttpResponse::InternalServerError().body(format!("Select error: {:?}", e));
        }
    };

    let messages_stream = match imap_session.fetch("1:5", "(FLAGS ENVELOPE BODY[TEXT])").await {
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
            let body = message
                .text()
                .map(|b: &[u8]| {
                    let text = String::from_utf8_lossy(b).to_string();
                    // Truncate long bodies for display
                    if text.len() > 200 {
                        format!("{}...", &text[..200])
                    } else {
                        text
                    }
                })
                .unwrap_or_default();

            let subject = envelope.subject
                .as_ref()
                .map(|s| String::from_utf8_lossy(s).to_string())
                .unwrap_or("No Subject".to_string());

            let from = envelope.from
                .as_ref()
                .and_then(|addrs| addrs.first())
                .map(|addr| {
                    let name = addr.name.as_ref().map(|n| String::from_utf8_lossy(n)).unwrap_or_default();
                    let mailbox = addr.mailbox.as_ref().map(|m| String::from_utf8_lossy(m)).unwrap_or_default();
                    let host = addr.host.as_ref().map(|h| String::from_utf8_lossy(h)).unwrap_or_default();

                    if !name.is_empty() {
                        format!("{} <{}@{}>", name, mailbox, host)
                    } else {
                        format!("{}@{}", mailbox, host)
                    }
                })
                .unwrap_or("Unknown".to_string());

            emails.push(Email {
                id: envelope.message_id
                    .as_ref()
                    .map(|id| String::from_utf8_lossy(id).to_string())
                    .unwrap_or_else(|| format!("msg_{}", i)),
                from,
                subject,
                body,
            });
        }
    }

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