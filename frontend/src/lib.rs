use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{console, window, Document, Element, HtmlInputElement, HtmlTextAreaElement};
use gloo_net::http::Request;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct EmailRequest {
    to: String,
    subject: String,
    body: String,
}

#[derive(Serialize, Deserialize)]
struct Email {
    id: String,
    from: String,
    subject: String,
    body: String,
}

#[wasm_bindgen(start)]
pub fn main() {
    console::log_1(&"🚀 Rust WASM Webmail frontend loaded!".into());

    let window = window().unwrap();
    let document = window.document().unwrap();

    // Set up event listeners
    setup_event_listeners(&document);

    // Auto-fetch emails on load
    wasm_bindgen_futures::spawn_local(async {
        fetch_emails().await;
    });

    // Set up auto-refresh every 30 seconds
    let closure = Closure::wrap(Box::new(move || {
        wasm_bindgen_futures::spawn_local(async {
            fetch_emails().await;
        });
    }) as Box<dyn Fn()>);

    window.set_interval_with_callback_and_timeout_and_arguments_0(
        closure.as_ref().unchecked_ref(),
        30000,
    ).unwrap();
    closure.forget();
}

fn setup_event_listeners(document: &Document) {
    // Tab switching
    let inbox_tab = document.get_element_by_id("inbox-tab").unwrap();
    let compose_tab = document.get_element_by_id("compose-tab").unwrap();

    let inbox_tab_clone = inbox_tab.clone();
    let compose_tab_clone = compose_tab.clone();
    let document_clone = document.clone();

    let inbox_closure = Closure::wrap(Box::new(move |_event: web_sys::Event| {
        show_tab("inbox", &document_clone);
        inbox_tab_clone.set_class_name("tab active");
        compose_tab_clone.set_class_name("tab");

        // Auto-fetch when switching to inbox
        wasm_bindgen_futures::spawn_local(async {
            fetch_emails().await;
        });
    }) as Box<dyn Fn(_)>);

    inbox_tab.add_event_listener_with_callback("click", inbox_closure.as_ref().unchecked_ref()).unwrap();
    inbox_closure.forget();

    let inbox_tab_clone2 = inbox_tab.clone();
    let compose_tab_clone2 = compose_tab.clone();
    let document_clone2 = document.clone();

    let compose_closure = Closure::wrap(Box::new(move |_event: web_sys::Event| {
        show_tab("compose", &document_clone2);
        compose_tab_clone2.set_class_name("tab active");
        inbox_tab_clone2.set_class_name("tab");
    }) as Box<dyn Fn(_)>);

    compose_tab.add_event_listener_with_callback("click", compose_closure.as_ref().unchecked_ref()).unwrap();
    compose_closure.forget();

    // Refresh button
    let refresh_btn = document.get_element_by_id("refresh-btn").unwrap();
    let refresh_closure = Closure::wrap(Box::new(move |_event: web_sys::Event| {
        wasm_bindgen_futures::spawn_local(async {
            fetch_emails().await;
        });
    }) as Box<dyn Fn(_)>);

    refresh_btn.add_event_listener_with_callback("click", refresh_closure.as_ref().unchecked_ref()).unwrap();
    refresh_closure.forget();

    // Send form
    let form = document.get_element_by_id("email-form").unwrap();
    let form_closure = Closure::wrap(Box::new(move |event: web_sys::Event| {
        event.prevent_default();
        wasm_bindgen_futures::spawn_local(async {
            send_email().await;
        });
    }) as Box<dyn Fn(_)>);

    form.add_event_listener_with_callback("submit", form_closure.as_ref().unchecked_ref()).unwrap();
    form_closure.forget();
}

fn show_tab(tab_name: &str, document: &Document) {
    // Hide all tab contents
    if let Some(inbox) = document.get_element_by_id("inbox") {
        inbox.set_class_name("tab-content");
    }
    if let Some(compose) = document.get_element_by_id("compose") {
        compose.set_class_name("tab-content");
    }

    // Show selected tab
    if let Some(selected_tab) = document.get_element_by_id(tab_name) {
        selected_tab.set_class_name("tab-content active");
    }
}

async fn fetch_emails() {
    let window = window().unwrap();
    let document = window.document().unwrap();

    // Update UI to show loading
    if let Some(refresh_text) = document.get_element_by_id("refresh-text") {
        refresh_text.set_inner_html("🔄 Loading...");
    }

    show_status("inbox-status", "📡 Fetching your emails...", "loading", &document);

    match Request::get("http://127.0.0.1:3001/fetch").send().await {
        Ok(response) => {
            match response.json::<Vec<Email>>().await {
                Ok(emails) => {
                    display_emails(emails, &document);
                    show_status("inbox-status", "✅ Emails loaded successfully!", "success", &document);
                },
                Err(e) => {
                    console::log_1(&format!("JSON parse error: {:?}", e).into());
                    show_error("inbox-status", "Failed to parse email data", &document);
                }
            }
        },
        Err(e) => {
            console::log_1(&format!("Fetch error: {:?}", e).into());
            show_error("inbox-status", "Failed to fetch emails. Make sure backend is running on port 3001.", &document);
        }
    }

    // Reset refresh button
    if let Some(refresh_text) = document.get_element_by_id("refresh-text") {
        refresh_text.set_inner_html("🔄 Refresh");
    }
}

fn display_emails(emails: Vec<Email>, document: &Document) {
    let email_list = document.get_element_by_id("email-list").unwrap();

    if emails.is_empty() {
        email_list.set_inner_html(r#"
            <div class="empty-state">
                <h3>📭 No emails found</h3>
                <p>Your inbox is empty or no emails could be retrieved.</p>
            </div>
        "#);
    } else {
        let emails_html = emails.iter().map(|email| {
            format!(r#"
                <li class="email-item">
                    <div class="email-header">
                        <div class="email-from">From: {}</div>
                    </div>
                    <div class="email-subject">{}</div>
                    <div class="email-body">{}</div>
                </li>
            "#,
                    html_escape(&email.from),
                    html_escape(&email.subject),
                    html_escape(&email.body.chars().take(200).collect::<String>())
            )
        }).collect::<Vec<_>>().join("");

        email_list.set_inner_html(&emails_html);
    }
}

async fn send_email() {
    let window = window().unwrap();
    let document = window.document().unwrap();

    // Get form values
    let to_input: HtmlInputElement = document.get_element_by_id("to").unwrap().dyn_into().unwrap();
    let subject_input: HtmlInputElement = document.get_element_by_id("subject").unwrap().dyn_into().unwrap();
    let body_input: HtmlTextAreaElement = document.get_element_by_id("body").unwrap().dyn_into().unwrap();

    let email_data = EmailRequest {
        to: to_input.value(),
        subject: subject_input.value(),
        body: body_input.value(),
    };

    // Update UI
    if let Some(send_btn) = document.get_element_by_id("send-btn") {
        send_btn.set_attribute("disabled", "true").unwrap();
    }
    if let Some(send_text) = document.get_element_by_id("send-text") {
        send_text.set_inner_html("📤 Sending...");
    }

    show_status("send-status", "📤 Sending your email...", "loading", &document);

    match Request::post("http://127.0.0.1:3001/send")
        .header("Content-Type", "application/json")
        .json(&email_data)
        .unwrap()
        .send()
        .await
    {
        Ok(response) => {
            if response.ok() {
                show_status("send-status", "✅ Email sent successfully!", "success", &document);
                // Clear form
                to_input.set_value("");
                subject_input.set_value("");
                body_input.set_value("");
            } else {
                let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                show_status("send-status", &format!("❌ Failed to send: {}", error_text), "error", &document);
            }
        },
        Err(e) => {
            console::log_1(&format!("Send error: {:?}", e).into());
            show_status("send-status", "❌ Failed to send email. Check your connection.", "error", &document);
        }
    }

    // Reset button
    if let Some(send_btn) = document.get_element_by_id("send-btn") {
        send_btn.remove_attribute("disabled").unwrap();
    }
    if let Some(send_text) = document.get_element_by_id("send-text") {
        send_text.set_inner_html("📤 Send Email");
    }
}

fn show_status(element_id: &str, message: &str, status_type: &str, document: &Document) {
    if let Some(status_el) = document.get_element_by_id(element_id) {
        status_el.set_inner_html(&format!(r#"<div class="status {}">{}</div>"#, status_type, message));

        if status_type == "success" {
            let status_el_clone = status_el.clone();
            let closure = Closure::wrap(Box::new(move || {
                status_el_clone.set_inner_html("");
            }) as Box<dyn Fn()>);

            window().unwrap().set_timeout_with_callback_and_timeout_and_arguments_0(
                closure.as_ref().unchecked_ref(),
                3000,
            ).unwrap();
            closure.forget();
        }
    }
}

fn show_error(element_id: &str, message: &str, document: &Document) {
    show_status(element_id, &format!("❌ {}", message), "error", document);
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}