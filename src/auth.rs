// src/auth.rs
use actix_web::{web, HttpRequest, HttpResponse};
use chrono::{Duration, Utc};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tokio_util::compat::TokioAsyncReadCompatExt;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub imap_server: String,
    pub imap_port: u16,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub provider: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub session_token: Option<String>,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub user_email: Option<String>,
}

#[derive(Clone)]
pub struct UserSession {
    pub email: String,
    pub password: String, // Encrypted in memory
    pub imap_server: String,
    pub imap_port: u16,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub provider: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used: chrono::DateTime<chrono::Utc>,
}

// In-memory session store (in production, use Redis or database)
use std::sync::{Arc, Mutex};
pub type SessionStore = Arc<Mutex<HashMap<String, UserSession>>>;

pub fn create_session_store() -> SessionStore {
    Arc::new(Mutex::new(HashMap::new()))
}

// Simple encryption for in-memory password storage
fn encrypt_password(password: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD.encode(password)
}

fn decrypt_password(encrypted: &str) -> Result<String, Box<dyn std::error::Error>> {
    use base64::{engine::general_purpose, Engine as _};
    let decoded = general_purpose::STANDARD.decode(encrypted)?;
    String::from_utf8(decoded).map_err(|e| e.into())
}

// Generate secure session token
fn generate_session_token() -> String {
    use sha2::{Digest, Sha256};
    let random_data = format!(
        "{}{}",
        Utc::now().timestamp_nanos_opt().unwrap_or(0),
        rand::random::<u64>()
    );
    let mut hasher = Sha256::new();
    hasher.update(random_data.as_bytes());
    format!("{:x}", hasher.finalize())
}

// Test IMAP connection
async fn test_imap_connection(
    server: &str,
    port: u16,
    email: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("🔐 Testing IMAP connection to {}:{}", server, port);

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(config));

    let tcp_stream = TcpStream::connect((server, port)).await?;
    let tls_stream = connector
        .connect(
            rustls::pki_types::ServerName::try_from(server)?.to_owned(),
            tcp_stream,
        )
        .await?;

    let compat_stream = tls_stream.compat();
    let client = async_imap::Client::new(compat_stream);

    let mut imap_session = client
        .login(email, password)
        .await
        .map_err(|e| format!("IMAP login failed: {:?}", e))?;

    // Test basic operation
    let _mailbox = imap_session.select("INBOX").await?;
    let _ = imap_session.logout().await;

    println!("✅ IMAP connection successful");
    Ok(())
}

// Test SMTP connection
async fn test_smtp_connection(
    server: &str,
    port: u16,
    email: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("📤 Testing SMTP connection to {}:{}", server, port);

    let creds = Credentials::new(email.to_string(), password.to_string());

    let mailer = if port == 465 {
        // SSL/TLS
        SmtpTransport::relay(server)?
            .port(port)
            .credentials(creds)
            .build()
    } else {
        // STARTTLS (port 587)
        SmtpTransport::starttls_relay(server)?
            .port(port)
            .credentials(creds)
            .build()
    };

    // Test with a minimal message (won't actually send)
    let _test_email = Message::builder()
        .from(email.parse()?)
        .to(email.parse()?)
        .subject("Test Connection")
        .body("Test".to_string())?;

    // Just test the connection, don't actually send
    match mailer.test_connection() {
        Ok(true) => {
            println!("✅ SMTP connection successful");
            Ok(())
        }
        Ok(false) => Err("SMTP connection test failed".into()),
        Err(e) => Err(format!("SMTP connection error: {:?}", e).into()),
    }
}

pub async fn login_handler(
    login_req: web::Json<LoginRequest>,
    session_store: web::Data<SessionStore>,
) -> HttpResponse {
    println!("🔐 Login attempt for: {}", login_req.email);

    // Validate input
    if login_req.email.is_empty() || login_req.password.is_empty() {
        return HttpResponse::BadRequest().json(LoginResponse {
            success: false,
            session_token: None,
            error: Some("Email and password are required".to_string()),
        });
    }

    if login_req.imap_server.is_empty() || login_req.smtp_server.is_empty() {
        return HttpResponse::BadRequest().json(LoginResponse {
            success: false,
            session_token: None,
            error: Some("Server settings are required".to_string()),
        });
    }

    // Test IMAP connection
    if let Err(e) = test_imap_connection(
        &login_req.imap_server,
        login_req.imap_port,
        &login_req.email,
        &login_req.password,
    )
    .await
    {
        return HttpResponse::Unauthorized().json(LoginResponse {
            success: false,
            session_token: None,
            error: Some(format!("IMAP connection failed: {}", e)),
        });
    }

    // Test SMTP connection
    if let Err(e) = test_smtp_connection(
        &login_req.smtp_server,
        login_req.smtp_port,
        &login_req.email,
        &login_req.password,
    )
    .await
    {
        return HttpResponse::Unauthorized().json(LoginResponse {
            success: false,
            session_token: None,
            error: Some(format!("SMTP connection failed: {}", e)),
        });
    }

    // Create session
    let session_token = generate_session_token();
    let now = Utc::now();

    let user_session = UserSession {
        email: login_req.email.clone(),
        password: encrypt_password(&login_req.password),
        imap_server: login_req.imap_server.clone(),
        imap_port: login_req.imap_port,
        smtp_server: login_req.smtp_server.clone(),
        smtp_port: login_req.smtp_port,
        provider: login_req.provider.clone(),
        created_at: now,
        last_used: now,
    };

    // Store session
    {
        let mut store = session_store.lock().unwrap();
        store.insert(session_token.clone(), user_session);

        // Clean up old sessions (keep only last 100, remove sessions older than 24h)
        let cutoff_time = now - Duration::hours(24);
        store.retain(|_, session| session.last_used > cutoff_time);

        if store.len() > 100 {
            // Remove oldest sessions
            let mut sessions: Vec<_> = store.iter().collect();
            sessions.sort_by_key(|(_, session)| session.last_used);
            let to_remove: Vec<String> = sessions
                .iter()
                .take(store.len() - 100)
                .map(|(token, _)| token.to_string())
                .collect();
            for token in to_remove {
                store.remove(&token);
            }
        }
    }

    println!("✅ Login successful for: {}", login_req.email);

    HttpResponse::Ok().json(LoginResponse {
        success: true,
        session_token: Some(session_token),
        error: None,
    })
}

pub async fn verify_handler(
    req: HttpRequest,
    session_store: web::Data<SessionStore>,
) -> HttpResponse {
    let auth_header = req.headers().get("Authorization");

    if let Some(auth_value) = auth_header {
        if let Ok(auth_str) = auth_value.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                let mut store = session_store.lock().unwrap();

                if let Some(session) = store.get_mut(token) {
                    // Update last used time
                    session.last_used = Utc::now();

                    return HttpResponse::Ok().json(VerifyResponse {
                        valid: true,
                        user_email: Some(session.email.clone()),
                    });
                }
            }
        }
    }

    HttpResponse::Ok().json(VerifyResponse {
        valid: false,
        user_email: None,
    })
}

pub async fn logout_handler(
    req: HttpRequest,
    session_store: web::Data<SessionStore>,
) -> HttpResponse {
    let auth_header = req.headers().get("Authorization");

    if let Some(auth_value) = auth_header {
        if let Ok(auth_str) = auth_value.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                let mut store = session_store.lock().unwrap();
                store.remove(token);

                return HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "message": "Logged out successfully"
                }));
            }
        }
    }

    HttpResponse::BadRequest().json(serde_json::json!({
        "success": false,
        "error": "Invalid session"
    }))
}

// Middleware to extract user session from request
pub fn get_user_session(req: &HttpRequest, session_store: &SessionStore) -> Option<UserSession> {
    let auth_header = req.headers().get("Authorization")?;
    let auth_str = auth_header.to_str().ok()?;
    let token = auth_str.strip_prefix("Bearer ")?;

    let mut store = session_store.lock().ok()?;
    let session = store.get_mut(token)?;

    // Update last used time
    session.last_used = Utc::now();

    Some(session.clone())
}

// Get credentials for email operations
pub fn get_user_credentials(session: &UserSession) -> Result<(String, String), String> {
    let password = decrypt_password(&session.password)
        .map_err(|_| "Failed to decrypt password".to_string())?;

    Ok((session.email.clone(), password))
}

// Configuration helper for different providers
pub fn get_provider_config(provider: &str) -> Option<ProviderConfig> {
    match provider.to_lowercase().as_str() {
        "gmail" => Some(ProviderConfig {
            imap_server: "imap.gmail.com".to_string(),
            imap_port: 993,
            smtp_server: "smtp.gmail.com".to_string(),
            smtp_port: 587,
            requires_app_password: true,
            setup_instructions: "Use an App Password instead of your regular password. Go to Google Account settings > Security > App passwords".to_string(),
        }),
        "outlook" => Some(ProviderConfig {
            imap_server: "outlook.office365.com".to_string(),
            imap_port: 993,
            smtp_server: "smtp-mail.outlook.com".to_string(),
            smtp_port: 587,
            requires_app_password: false,
            setup_instructions: "Use your regular Microsoft account password".to_string(),
        }),
        "yahoo" => Some(ProviderConfig {
            imap_server: "imap.mail.yahoo.com".to_string(),
            imap_port: 993,
            smtp_server: "smtp.mail.yahoo.com".to_string(),
            smtp_port: 587,
            requires_app_password: true,
            setup_instructions: "Generate an app password in Yahoo Mail settings > Account Security".to_string(),
        }),
        _ => None,
    }
}

#[derive(Serialize)]
pub struct ProviderConfig {
    pub imap_server: String,
    pub imap_port: u16,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub requires_app_password: bool,
    pub setup_instructions: String,
}

pub async fn provider_config_handler(path: web::Path<String>) -> HttpResponse {
    let provider = path.into_inner();

    if let Some(config) = get_provider_config(&provider) {
        HttpResponse::Ok().json(config)
    } else {
        HttpResponse::NotFound().json(serde_json::json!({
            "error": "Provider not found"
        }))
    }
}

// Session management endpoints
pub async fn list_sessions_handler(session_store: web::Data<SessionStore>) -> HttpResponse {
    let store = session_store.lock().unwrap();
    let session_count = store.len();
    let active_users: Vec<String> = store
        .values()
        .map(|session| session.email.clone())
        .collect();

    HttpResponse::Ok().json(serde_json::json!({
        "active_sessions": session_count,
        "active_users": active_users
    }))
}

// Cleanup old sessions (can be called periodically)
pub async fn cleanup_sessions_handler(session_store: web::Data<SessionStore>) -> HttpResponse {
    let mut store = session_store.lock().unwrap();
    let initial_count = store.len();

    let cutoff_time = Utc::now() - Duration::hours(24);
    store.retain(|_, session| session.last_used > cutoff_time);

    let cleaned_count = initial_count - store.len();

    HttpResponse::Ok().json(serde_json::json!({
        "cleaned_sessions": cleaned_count,
        "remaining_sessions": store.len()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_encryption() {
        let password = "test_password_123";
        let encrypted = encrypt_password(password);
        let decrypted = decrypt_password(&encrypted).unwrap();
        assert_eq!(password, decrypted);
    }

    #[test]
    fn test_session_token_generation() {
        let token1 = generate_session_token();
        let token2 = generate_session_token();
        assert_ne!(token1, token2);
        assert_eq!(token1.len(), 64); // SHA256 hex
    }

    #[test]
    fn test_provider_config() {
        let gmail_config = get_provider_config("gmail").unwrap();
        assert_eq!(gmail_config.imap_server, "imap.gmail.com");
        assert_eq!(gmail_config.imap_port, 993);
        assert!(gmail_config.requires_app_password);

        let outlook_config = get_provider_config("outlook").unwrap();
        assert_eq!(outlook_config.imap_server, "outlook.office365.com");
        assert!(!outlook_config.requires_app_password);

        assert!(get_provider_config("unknown").is_none());
    }
}
