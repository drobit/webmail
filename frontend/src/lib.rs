use yew::prelude::*;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use wasm_logger::init as init_logger;
use log::Level;

#[derive(Serialize, Deserialize, Clone, PartialEq)]
struct Email {
    id: String,
    from: String,
    subject: String,
    body: String,
}

#[derive(Serialize, Deserialize)]
struct EmailRequest {
    to: String,
    subject: String,
    body: String,
}

#[function_component(App)]
fn app() -> Html {
    init_logger(Level::Info);
    let emails = use_state(|| vec![]);
    let to = use_state(|| String::new());
    let subject = use_state(|| String::new());
    let body = use_state(|| String::new());

    let fetch_emails = {
        let emails = emails.clone();
        Callback::from(move |_| {
            let emails = emails.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let fetched = Client::new()
                    .get("http://127.0.0.1:8080/fetch")
                    .send()
                    .await
                    .unwrap()
                    .json::<Vec<Email>>()
                    .await
                    .unwrap();
                emails.set(fetched);
            });
        })
    };

    let send_email = {
        let to = to.clone();
        let subject = subject.clone();
        let body = body.clone();
        Callback::from(move |_| {
            let to = to.clone();
            let subject = subject.clone();
            let body = body.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let request = EmailRequest {
                    to: (*to).clone(),
                    subject: (*subject).clone(),
                    body: (*body).clone(),
                };
                Client::new()
                    .post("http://127.0.0.1:8080/send")
                    .json(&request)
                    .send()
                    .await
                    .unwrap();
            });
        })
    };

    let on_to_change = {
        let to = to.clone();
        Callback::from(move |e: InputEvent| {
            to.set(e.target_unchecked_into::<web_sys::HtmlInputElement>().value());
        })
    };

    let on_subject_change = {
        let subject = subject.clone();
        Callback::from(move |e: InputEvent| {
            subject.set(e.target_unchecked_into::<web_sys::HtmlInputElement>().value());
        })
    };

    let on_body_change = {
        let body = body.clone();
        Callback::from(move |e: InputEvent| {
            body.set(e.target_unchecked_into::<web_sys::HtmlInputElement>().value());
        })
    };

    html! {
        <div class="container">
            <h1>{ "Webmail" }</h1>
            <button onclick={fetch_emails}>{ "Fetch Emails" }</button>
            <h2>{ "Compose Email" }</h2>
            <input placeholder="To" oninput={on_to_change} class="input" />
            <input placeholder="Subject" oninput={on_subject_change} class="input" />
            <textarea placeholder="Body" oninput={on_body_change} class="textarea"></textarea>
            <button onclick={send_email} class="button">{ "Send Email" }</button>
            <h2>{ "Inbox" }</h2>
            <ul class="email-list">
                { for emails.iter().map(|email| html! {
                    <li class="email-item">
                        <strong>{ "From: " }</strong>{ &email.from }<br/>
                        <strong>{ "Subject: " }</strong>{ &email.subject }<br/>
                        <p>{ &email.body }</p>
                    </li>
                })}
            </ul>
        </div>
    }
}

#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn run_app() {
    yew::Renderer::<App>::new().render();
}