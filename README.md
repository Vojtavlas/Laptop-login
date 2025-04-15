# Google Auth Desktop Gateway

A Rust desktop application that provides Google OAuth 2.0 authentication with domain validation for @scioskola.cz emails.

## Features

- Fullscreen desktop UI built with Slint
- Google OAuth 2.0 authentication flow
- Email domain validation (@scioskola.cz)
- Local HTTP server for OAuth callback handling
- Automatic browser opening for authentication
- Success/failure feedback in UI and browser

## Requirements

- Rust (latest stable version)
- Cargo
- Google OAuth credentials (client ID and secret)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/vojta/Laptop-login.git
   cd Laptop-login
   ```

2. Build the application:
   ```bash
   cargo build --release
   ```

## Configuration

Before running, you need to:

1. Obtain Google OAuth credentials:
   - Create a project in Google Cloud Console
   - Configure OAuth consent screen
   - Create OAuth 2.0 credentials
   - Add `http://localhost:8080` as authorized redirect URI

2. Update the credentials in `src/main.rs`:
   ```rust
   const CLIENT_ID: &str = "your-client-id.apps.googleusercontent.com";
   const CLIENT_SECRET: &str = "your-client-secret";
   ```

## Usage

Run the application:
```bash
cargo run --release
```

The application will:
1. Show a fullscreen window with "Login with Google" button
2. Open your default browser to Google's authentication page when clicked
3. Validate the email domain after successful authentication
4. Redirect to https://scioskola.cz on success

