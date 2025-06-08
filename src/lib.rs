use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EmailRequest {
    pub to: String,
    pub subject: String,
    pub body: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct EmailListItem {
    pub id: String,
    pub from: String,
    pub subject: String,
    pub date: Option<String>,
    pub is_seen: bool,
    pub is_recent: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct EmailDetail {
    pub id: String,
    pub from: String,
    pub subject: String,
    pub body: String,
    pub date: Option<String>,
    pub is_seen: bool,
    pub is_recent: bool,
}

// Utility functions that can be tested
pub fn format_email_address(email: &str) -> String {
    if email.contains('<') && email.contains('>') {
        email.to_string()
    } else {
        format!("<{}>", email)
    }
}

pub fn extract_domain_from_email(email: &str) -> Option<String> {
    email.split('@').nth(1).map(|s| s.to_string())
}

pub fn validate_email_format(email: &str) -> bool {
    // Basic email validation
    if !email.contains('@') || email.len() < 5 {
        return false;
    }

    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    // Local part validation
    if local.is_empty() || local.len() > 64 {
        return false;
    }

    // Domain part validation
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return false;
    }

    // Domain should not start or end with dot or hyphen
    if domain.starts_with('.') || domain.ends_with('.') || domain.starts_with('-') || domain.ends_with('-') {
        return false;
    }

    // Check for valid characters (basic check)
    for c in email.chars() {
        if !c.is_ascii_alphanumeric() && !"._-@".contains(c) {
            return false;
        }
    }

    true
}

pub fn truncate_subject(subject: &str, max_length: usize) -> String {
    if subject.len() <= max_length {
        subject.to_string()
    } else {
        format!("{}...", &subject[..max_length.saturating_sub(3)])
    }
}

pub fn decode_mime_header_simple(header: &str) -> String {
    if !header.contains("=?") {
        return header.to_string();
    }

    if let Some(start) = header.find("=?UTF-8?B?") {
        if let Some(end) = header[start..].find("?=") {
            let encoded = &header[start + 10..start + end];
            use base64::{Engine as _, engine::general_purpose};
            if let Ok(decoded) = general_purpose::STANDARD.decode(encoded) {
                if let Ok(text) = String::from_utf8(decoded) {
                    return text;
                }
            }
        }
    }

    header.to_string()
}

pub fn extract_plain_text_preview(content: &str, max_length: usize) -> String {
    let cleaned = content
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('>'))
        .take(10)
        .collect::<Vec<_>>()
        .join(" ");

    truncate_subject(&cleaned, max_length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_email_address() {
        assert_eq!(format_email_address("test@example.com"), "<test@example.com>");
        assert_eq!(format_email_address("John Doe <john@example.com>"), "John Doe <john@example.com>");
    }

    #[test]
    fn test_extract_domain_from_email() {
        assert_eq!(extract_domain_from_email("test@example.com"), Some("example.com".to_string()));
        assert_eq!(extract_domain_from_email("invalid-email"), None);
    }

    #[test]
    fn test_validate_email_format() {
        assert!(validate_email_format("test@example.com"));
        assert!(!validate_email_format("invalid"));
        assert!(!validate_email_format("@example.com"));
        assert!(!validate_email_format("test@"));
    }

    #[test]
    fn test_truncate_subject() {
        assert_eq!(truncate_subject("Short", 10), "Short");
        assert_eq!(truncate_subject("This is a very long subject line", 15), "This is a ve...");
    }

    #[test]
    fn test_decode_mime_header_simple() {
        assert_eq!(decode_mime_header_simple("Simple Header"), "Simple Header");
        // Test basic functionality - actual MIME decoding would need more complex test data
        assert_eq!(decode_mime_header_simple("No encoding here"), "No encoding here");
    }

    #[test]
    fn test_extract_plain_text_preview() {
        let content = "Line 1\n\nLine 2\n> Quoted line\nLine 3";
        let preview = extract_plain_text_preview(content, 20);
        assert!(preview.len() <= 20);
        assert!(!preview.contains("> Quoted"));
    }

    #[test]
    fn test_email_request_serialization() {
        let email = EmailRequest {
            to: "test@example.com".to_string(),
            subject: "Test Subject".to_string(),
            body: "Test Body".to_string(),
        };

        let json = serde_json::to_string(&email).unwrap();
        let deserialized: EmailRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(email.to, deserialized.to);
        assert_eq!(email.subject, deserialized.subject);
        assert_eq!(email.body, deserialized.body);
    }
}