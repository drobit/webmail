use actix_web::{web, App, HttpResponse, HttpServer};
use lettre::{Message, SmtpTransport, Transport};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use imap::ClientBuilder;
use serde::{Deserialize, Serialize};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use std::env;

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
    db: SqlitePool,
}

// Initialize database
async fn init_db() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite://webmail.db")
        .await
        .unwrap();
    sqlx::query("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT, password TEXT)")
        .execute(&pool)
        .await
        .unwrap();
    pool
}

// Send email via SMTP
async fn send_email(data: web::Json<EmailRequest>, state: web::Data<AppState>) -> HttpResponse {
    let smtp_user = env::var("SMTP_USER").unwrap_or_default();
    let smtp_pass = env::var("SMTP_PASS").unwrap_or_default();

    let email = Message::builder()
        .from(format!("Sender <{}>", smtp_user).parse().unwrap())
        .to(data.to.parse().unwrap())
        .subject(&data.subject)
        .header(ContentType::TEXT_PLAIN)
        .body(data.body.clone())
        .unwrap();

    let creds = Credentials::new(smtp_user, smtp_pass);
    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .port(587)
        .credentials(creds)
        .build();

    match mailer.send(&email).await {
        Ok(_) => HttpResponse::Ok().body("Email sent"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {:?}", e)),
    }
}

// Fetch emails via IMAP
async fn fetch_emails(state: web::Data<AppState>) -> HttpResponse {
    let imap_user = env::var("IMAP_USER").unwrap_or_default();
    let imap_pass = env::var("IMAP_PASS").unwrap_or_default();

    let mut imap = match ClientBuilder::new("imap.gmail.com", 993)
        .credential(&imap_user, &imap_pass)
        .connect()
    {
        Ok(imap) => imap,
        Err(e) => return HttpResponse::InternalServerError().body(format!("IMAP error: {:?}", e)),
    };

    let mailbox = match imap.select("INBOX") {
        Ok(mailbox) => mailbox,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Select error: {:?}", e)),
    };

    let messages = match mailbox.fetch("1:10", "(FLAGS ENVELOPE BODY[TEXT])") {
        Ok(messages) => messages,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Fetch error: {:?}", e)),
    };

    let mut emails = vec![];
    for message in messages {
        if let Some(envelope) = message.envelope() {
            let body = message
                .body()
                .map(|b| String::from_utf8_lossy(b).to_string())
                .unwrap_or_default();
            emails.push(Email {
                id: message.message_id().map(|id| String::from_utf8_lossy(id).to_string()).unwrap_or_default(),
                from: envelope.from.as_ref().map(|addr| format!("{:?}", addr)).unwrap_or_default(),
                subject: envelope.subject.as_ref().map(|s| String::from_utf8_lossy(s).to_string()).unwrap_or_default(),
                body,
            });
        }
    }

    imap.logout().unwrap();
    HttpResponse::Ok().json(emails)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    let pool = init_db().await;
    let state = web::Data::new(AppState { db: pool });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/send", web::post().to(send_email))
            .route("/fetch", web::get().to(fetch_emails))
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}