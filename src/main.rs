#![windows_subsystem = "windows"]

slint::include_modules!();

use slint::ComponentHandle;
use std::thread;
use url::Url;
use open;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json;
use std::net::{TcpListener, TcpStream}; // Import TcpStream
use std::io::{Read, Write};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as base64_url, Engine as _};

// --- Credentials ---
const CLIENT_ID: &str = "67209719768-tmsbmibv2rtt1l8r2b4edef9k7347u5r.apps.googleusercontent.com";
const CLIENT_SECRET: &str = "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";
const REDIRECT_URI: &str = "http://localhost:8080";
const SUCCESS_REDIRECT_URL: &str = "https://scioskola.cz";
const REQUIRED_EMAIL_DOMAIN: &str = "@scioskola.cz";

#[derive(Deserialize, Debug)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    refresh_token: Option<String>,
    scope: String,
    token_type: String,
    id_token: Option<String>,
}

#[derive(Deserialize, Debug)]
struct IdTokenPayload {
    email: Option<String>,
    email_verified: Option<bool>,
}

// --- Helper: Decode JWT Payload --- (Same as before)
fn decode_email_from_jwt_payload(jwt: &str) -> Result<Option<String>, String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() < 2 { return Err("Invalid JWT format.".to_string()); }
    let payload_base64url = parts[1];
    match base64_url.decode(payload_base64url) {
        Ok(payload_bytes) => match serde_json::from_slice::<IdTokenPayload>(&payload_bytes) {
            Ok(payload) => Ok(payload.email),
            Err(e) => Err(format!("JWT JSON decoding error: {}", e)),
        },
        Err(e) => Err(format!("JWT Base64 decoding error: {}", e)),
    }
}

// --- Helper: Update Slint UI Status --- (Same as before)
fn update_status(ui_weak: &slint::Weak<MainWindow>, message: String) {
    let message_shared: slint::SharedString = message.into();
    let weak_handle_clone = ui_weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak_handle_clone.upgrade() {
            ui.set_status(message_shared);
        } else {
             eprintln!("UI invalid in update_status for: {}", message_shared);
        }
    });
}

// --- Helper: Send HTTP Response to Browser Stream ---
fn send_http_response(stream: &mut TcpStream, response_str: &str) {
    if let Err(e) = stream.write_all(response_str.as_bytes()) {
        eprintln!("Error writing HTTP response to browser: {}", e);
    }
    if let Err(e) = stream.flush() {
        eprintln!("Error flushing HTTP stream to browser: {}", e);
    }
    // Stream will be closed when it goes out of scope after this function returns in the main logic
}

// --- Helper: Create HTML Error Page Response ---
fn create_html_error_response(message: &str) -> String {
    // Basic HTML escaping for the message to prevent XSS if message contains < or >
    let escaped_message = message.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nCache-Control: no-cache, no-store, must-revalidate\r\nPragma: no-cache\r\nExpires: 0\r\n\r\n\
        <!DOCTYPE html>\
        <html>\
          <head>\
            <meta charset=\"utf-8\">\
            <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\
            <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\
            <title>Login Error</title>\
            <style>body {{ font-family: sans-serif; padding: 2em; }}</style>\
          </head>\
          <body>\
            <h1>Login Error</h1>\
            <p style=\"color: red;\">{}</p>\
            <p>You can now close this browser tab or window.</p>\
          </body>\
        </html>",
        escaped_message
    )
}

// --- Helper: Create Success Redirect Response ---
fn create_success_redirect_response(url: &str) -> String {
     format!(
        "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\nCache-Control: no-cache, no-store, must-revalidate\r\nPragma: no-cache\r\nExpires: 0\r\n\r\n",
        url
    )
}


fn main() -> Result<(), slint::PlatformError> {
    let ui = MainWindow::new()?;
    ui.window().set_fullscreen(true);
    let ui_handle = ui.as_weak();

    ui.set_status("Ready. Click Login to start.".into());

    let ui_handle_clone = ui_handle.clone();
    ui.on_login_clicked(move || {
        let ui_weak = ui_handle_clone.clone();
        update_status(&ui_weak, "Starting login...".to_string());

        // --- Background Thread Logic ---
        thread::spawn(move || {
            let auth_url = format!( /* ... same as before ... */
                 "https://accounts.google.com/o/oauth2/v2/auth?\
                client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&access_type=offline&prompt=consent",
                CLIENT_ID, REDIRECT_URI
            );

            let listener = match TcpListener::bind(format!("127.0.0.1:{}", Url::parse(REDIRECT_URI).unwrap().port().unwrap_or(80))) {
                 Ok(l) => l,
                 Err(e) => { update_status(&ui_weak, format!("Error: Bind failed: {}", e)); return; }
            };
            update_status(&ui_weak, "Waiting for Google redirect... Check browser.".to_string());

            if let Err(e) = open::that(&auth_url) {
                 update_status(&ui_weak, format!("Error: Cannot open browser: {}", e));
                 // Continue, user might copy URL manually
            }

            // --- Accept Connection from Browser ---
            match listener.accept() {
                Ok((mut stream, remote_addr)) => { // stream needs to be mutable
                    println!("Received connection from: {}", remote_addr);
                    let mut buffer = [0; 2048];
                    let code: Option<String>;

                    // --- Read Request and Extract Code ---
                    match stream.read(&mut buffer) {
                        Ok(bytes_read) => {
                            let request_str = String::from_utf8_lossy(&buffer[..bytes_read]);
                             println!("Received request:\n{}", request_str);
                            code = request_str.lines().find(|line| line.starts_with("GET /?"))
                                .and_then(|get_line| get_line.split_whitespace().nth(1))
                                .and_then(|path_query| Url::parse(&format!("{}{}", REDIRECT_URI, path_query)).ok())
                                .and_then(|url| url.query_pairs().find(|(key, _)| key == "code").map(|(_, value)| value.into_owned()));
                            println!("Extracted code: {:?}", code);
                        }
                        Err(e) => {
                            let err_msg = format!("Error reading redirect request: {}", e);
                            update_status(&ui_weak, err_msg);
                            let response = create_html_error_response("Failed to read request from browser.");
                            send_http_response(&mut stream, &response); // Try send error page
                            return; // Exit thread
                        }
                    }

                    // --- Process Code and Validate *Before* Responding to Browser ---
                    if let Some(auth_code) = code {
                        update_status(&ui_weak, "Code received. Exchanging for token... (Browser waiting)".to_string());

                        let client = Client::new();
                        let params = [ /* ... same params ... */
                            ("code", auth_code.as_str()), ("client_id", CLIENT_ID),
                            ("client_secret", CLIENT_SECRET), ("redirect_uri", REDIRECT_URI),
                            ("grant_type", "authorization_code"),
                        ];

                        // --- Token Exchange ---
                        match client.post("https://oauth2.googleapis.com/token").form(&params).send() {
                            Ok(resp) => {
                                let status = resp.status();
                                match resp.text() {
                                    Ok(text) => {
                                        if status.is_success() {
                                            // --- Parse Token Response ---
                                            match serde_json::from_str::<TokenResponse>(&text) {
                                                Ok(token_info) => {
                                                    // --- Check for ID Token ---
                                                    if let Some(ref id_token_str) = token_info.id_token { // Borrow id_token
                                                         // --- Decode Email ---
                                                         match decode_email_from_jwt_payload(id_token_str) {
                                                            Ok(Some(user_email)) => {
                                                                // --- Check Domain ---
                                                                if user_email.ends_with(REQUIRED_EMAIL_DOMAIN) {
                                                                    // *** FINAL SUCCESS ***
                                                                    update_status(&ui_weak, format!("Login Successful: Email '{}' verified.", user_email));
                                                                    println!("Domain matched. Token: {:?}", token_info);
                                                                    // Send SUCCESS redirect to browser
                                                                    let response = create_success_redirect_response(SUCCESS_REDIRECT_URL);
                                                                    send_http_response(&mut stream, &response);
                                                                } else {
                                                                    // *** DOMAIN MISMATCH ***
                                                                    let error_msg = format!("Email '{}' does not belong to the required domain ({}).", user_email, REQUIRED_EMAIL_DOMAIN);
                                                                    update_status(&ui_weak, format!("Login Failed: {}", error_msg));
                                                                    // Send HTML ERROR to browser
                                                                    let response = create_html_error_response(&error_msg);
                                                                    send_http_response(&mut stream, &response);
                                                                }
                                                            }
                                                            Ok(None) => { // Email missing in payload
                                                                let error_msg = "Email address not found in ID token.";
                                                                update_status(&ui_weak, format!("Login Error: {}", error_msg));
                                                                let response = create_html_error_response(error_msg);
                                                                send_http_response(&mut stream, &response);
                                                            }
                                                            Err(e) => { // Error decoding payload
                                                                 let error_msg = format!("Could not process ID token: {}", e);
                                                                 update_status(&ui_weak, format!("Login Error: {}", error_msg));
                                                                 let response = create_html_error_response(&error_msg);
                                                                 send_http_response(&mut stream, &response);
                                                            }
                                                         } // End email decoding match
                                                    } else { // id_token missing
                                                        let error_msg = "ID token missing in response.";
                                                        update_status(&ui_weak, format!("Login Error: {}", error_msg));
                                                        let response = create_html_error_response(error_msg);
                                                        send_http_response(&mut stream, &response);
                                                    } // End id_token check
                                                } // End TokenResponse parsing Ok
                                                Err(e) => { // Error parsing TokenResponse JSON
                                                    let error_msg = format!("Internal error parsing token response JSON: {}", e);
                                                    update_status(&ui_weak, format!("Login Error: {}", error_msg));
                                                    let response = create_html_error_response("Internal error processing token response.");
                                                    send_http_response(&mut stream, &response);
                                                } // End TokenResponse parsing Err
                                            } // End TokenResponse parsing match
                                        } else { // Token exchange HTTP status not success
                                             let error_msg = format!("Token exchange failed with status {}: {}", status, text);
                                             update_status(&ui_weak, format!("Login Error: {}", error_msg));
                                             let response = create_html_error_response("Failed to get token from provider.");
                                             send_http_response(&mut stream, &response);
                                        } // End status check
                                    } // End resp.text() Ok
                                    Err(e) => { // Error reading token response text
                                        let error_msg = format!("Internal error reading token response: {}", e);
                                        update_status(&ui_weak, format!("Login Error: {}", error_msg));
                                        let response = create_html_error_response("Internal error reading token response.");
                                        send_http_response(&mut stream, &response);
                                    } // End resp.text() Err
                                } // End resp.text() match
                            } // End token exchange Ok
                            Err(e) => { // Network error during token exchange
                                 let error_msg = format!("Network error during token request: {}", e);
                                 update_status(&ui_weak, format!("Login Error: {}", error_msg));
                                 let response = create_html_error_response("Network error during token request.");
                                 send_http_response(&mut stream, &response);
                            } // End token exchange Err
                        } // End token exchange match
                    } else { // Auth code missing from initial redirect
                         let error_msg = "Authorization code missing in redirect from provider.";
                         update_status(&ui_weak, format!("Login Error: {}", error_msg));
                         let response = create_html_error_response(error_msg);
                         send_http_response(&mut stream, &response);
                    } // End code check

                } // End listener.accept() Ok block
                Err(e) => { // Error accepting connection
                    update_status(&ui_weak, format!("Login Error: Failed to accept connection: {}", e));
                    // Cannot send response to browser here
                } // End listener.accept() Err
            } // End listener.accept() match
        }); // End thread::spawn
    }); // End ui.on_login_clicked

    ui.run()
} // End main