// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use base64::{engine::general_purpose, Engine as _};
use reqwest::Client;
use rpassword;
use signal_hook::{consts::SIGINT, iterator::Signals};
use std::error::Error;
use std::io::{self, Write};
use std::process::Command;
use std::{fs, sync::Arc};

fn check_prerequisites() -> Result<(), Box<dyn std::error::Error>> {
    // NGINX?
    if Command::new("nginx").arg("-v").output().is_err() {
        eprintln!("NGINX not installed here.");
        install_nginx()?
    } else {
        println!("NGINX is installed");
    }

    // Certbot
    if Command::new("certbot").arg("--version").output().is_err() {
        eprintln!("Certbot is not installed.");
        install_certbot()?;
    } else {
        println!("Certbot is installed.");
    }

    println!("Everything ok");
    Ok(())
}

fn install_nginx() -> Result<(), Box<dyn std::error::Error>> {
    println!("Installing NGINX...");

    // Determine OS and install
    if cfg!(target_os = "linux") {
        Command::new("sudo").args(["apt", "update"]).status()?;
        Command::new("sudo")
            .args(["apt", "-y", "install", "nginx"])
            .status()?;
    } else {
        return Err(
            "Unsupported operating system for auto installation. Please install NGINX manually"
                .into(),
        );
    }

    println!("NGINX installed successfully.");
    Ok(())
}

fn install_certbot() -> Result<(), Box<dyn std::error::Error>> {
    println!("Installing Certbot...");

    if cfg!(target_os = "linux") {
        Command::new("sudo")
            .args(["apt", "-y", "install", "certbot", "python3-certbot-nginx"])
            .status()?;
    } else {
        return Err(
            "Unsupported operating system for auto installation. Please install Certbot manually"
                .into(),
        );
    }

    println!("Certbot installed successfully.");
    Ok(())
}

fn setup_reverse_proxy() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Reverse Proxy Setup ===");

    // Step 1: Prompt for router IP and domain
    let router_ip = prompt_input_with_default(
        "Enter your router's IP address (default 192.168.2.1): ",
        "192.168.2.1",
    )?;
    let domain = prompt_input_with_default(
        "Enter your domain name (default aetheloid.online): ",
        "aetheloid.online",
    )?;

    // Step 2: Prompt for custom ports with default values
    println!("You can set custom ports for the reverse proxy (default ports are 80 for HTTP and 443 for HTTPS).");

    let http_port = get_custom_port_with_default("Enter the HTTP port (default 8482): ", 8482)?;
    let https_port = get_custom_port_with_default("Enter the HTTPS port (default 8849): ", 8879)?;

    println!(
        "Setting up reverse proxy with HTTP port {} and HTTPS port {}...",
        http_port, https_port
    );

    // Step 3: Open the firewall ports using ufw
    println!("Opening firewall ports...");
    open_firewall_ports(http_port, https_port)?;

    // Step 4: Configure signal handling to close ports on termination
    println!("Setting up termination handler to close opened ports...");
    configure_signal_handler(http_port, https_port);

    // Step 5: Generate NGINX configuration
    let nginx_config_path = "/etc/nginx/sites-available/router_proxy";
    let nginx_config = format!(
        r#"
server {{
    listen {https_port} ssl;  # Custom HTTPS port
    server_name {domain};

    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;

    location / {{
        proxy_pass http://{router_ip};  # Router's HTTP address
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }}

    access_log /var/log/nginx/reverse_proxy_access.log;
    error_log /var/log/nginx/reverse_proxy_error.log;
}}

server {{
    listen {http_port};  # Custom HTTP port
    server_name {domain};

    # Redirect HTTP to HTTPS on the custom port
    return 301 https://$host:{https_port}$request_uri;
}}
        "#,
        domain = domain,
        router_ip = router_ip,
        http_port = http_port,
        https_port = https_port
    );

    // Step 6: Write the NGINX configuration file
    println!("Writing NGINX configuration to: {}", nginx_config_path);
    fs::write(nginx_config_path, nginx_config)?;

    // Step 7: Enable the site in NGINX
    println!("Enabling the NGINX site...");
    Command::new("ln")
        .args([
            "-s",
            nginx_config_path,
            "/etc/nginx/sites-enabled/router_proxy",
        ])
        .output()?;

    // Step 8: Reload NGINX
    println!("Reloading NGINX to apply the changes...");
    restart_nginx()?;

    // Step 9: Obtain SSL certificate using Certbot
    println!("Obtaining an SSL certificate for domain: {}", domain);
    obtain_ssl_certificate(&domain)?;

    println!(
        "Reverse proxy setup completed! HTTP is available on port {} and HTTPS on port {}.",
        http_port, https_port
    );
    println!(
        "You can now access your service at: https://{}:{}",
        domain, https_port
    );

    Ok(())
}

fn prompt_input_with_default(prompt: &str, default: &str) -> Result<String, io::Error> {
    use std::io::{self, Write};

    // Prompt the user
    print!("{}", prompt);
    io::stdout().flush()?;

    // Read user input
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    // Use the default if the input is empty
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn get_custom_port_with_default(
    prompt: &str,
    default: u16,
) -> Result<u16, Box<dyn std::error::Error>> {
    use std::io::{self, Write};

    loop {
        // Prompt the user
        print!("{}", prompt);
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        // Use the default if the input is empty
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(default);
        }

        // Otherwise validate the input
        if let Ok(port) = trimmed.parse::<u16>() {
            if port >= 1024 && port <= 65535 {
                return Ok(port);
            } else {
                println!("Port must be between 1024 and 65535. Please try again.");
            }
        } else {
            println!("Invalid input. Please enter a valid port number.");
        }
    }
}

fn open_firewall_ports(http_port: u16, https_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    println!("Opening HTTP port {}...", http_port);
    Command::new("sudo")
        .args(["ufw", "allow", &format!("{}/tcp", http_port)])
        .status()?;

    println!("Opening HTTPS port {}...", https_port);
    Command::new("sudo")
        .args(["ufw", "allow", &format!("{}/tcp", https_port)])
        .status()?;

    println!("Ports opened successfully.");
    Ok(())
}

fn close_firewall_ports(http_port: u16, https_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    println!("Closing HTTP port {}...", http_port);
    Command::new("sudo")
        .args(["ufw", "deny", &format!("{}/tcp", http_port)])
        .status()?;

    println!("Closing HTTPS port {}...", https_port);
    Command::new("sudo")
        .args(["ufw", "deny", &format!("{}/tcp", https_port)])
        .status()?;

    println!("Ports closed successfully.");
    Ok(())
}

fn configure_signal_handler(http_port: u16, https_port: u16) {
    let mut signals = Signals::new([SIGINT]).expect("Failed to set up signal handling");
    let http_port = Arc::new(http_port);
    let https_port = Arc::new(https_port);

    let _http_port_handler = http_port.clone();
    let _https_port_handler = https_port.clone();

    std::thread::spawn(move || {
        for _ in signals.forever() {
            println!("\nTerminating program. Closing opened ports...");
            if let Err(err) = close_firewall_ports(*_http_port_handler, *_https_port_handler) {
                eprintln!("Error closing ports: {:?}", err);
            }
            std::process::exit(0);
        }
    });
}

fn restart_nginx() -> Result<(), io::Error> {
    Command::new("sudo")
        .args(["systemctl", "restart", "nginx"])
        .status()?;
    Ok(())
}

fn obtain_ssl_certificate(domain: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Attempt to obtain an SSL certificate with Certbot
    let result = Command::new("sudo")
        .args([
            "certbot", "--nginx", // Automatically configure SSL in NGINX
            "-d", domain, // Domain name
        ])
        .output()?;

    if !result.status.success() {
        eprintln!("Failed to obtain an SSL certificate. Check Certbot logs for more information.");
        return Err("Certbot failed to obtain an SSL certificate.".into());
    }

    println!(
        "SSL certificate obtained successfully for domain: {}",
        domain
    );
    Ok(())
}

// Structure for storing user input (for cleaner reuse across functions)
struct RouterDetails {
    router_ip: String,
    auth_header: String,
}

// Prompt for user-specific router details
fn prompt_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

// Base64 encode username and password for Basic Auth using `general_purpose::STANDARD`
fn encode_basic_auth(username: &str, password: &str) -> String {
    let credentials = format!("{}:{}", username, password);
    general_purpose::STANDARD.encode(credentials) // Using the modern Engine API
}

// Fetch SMS messages from the router API with plain text response handling
async fn fetch_sms(client: &Client, router: &RouterDetails) -> Result<(), Box<dyn Error>> {
    let url = format!(
        "http://{}/cgi-bin/sms.cgi?action=get_sms_list",
        router.router_ip
    );

    let response = client
        .get(&url)
        .header("Authorization", &router.auth_header)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("Failed to fetch SMS messages: {}", response.status()).into());
    }

    // Handle plain text response
    let plain_response = response.text().await?;
    println!("\n--- SMS Messages ---");
    println!("{}", plain_response); // Print the plain response directly
    println!("\n{}", "-".repeat(30));

    Ok(())
}

// Send SMS using the router API with plain text response handling
async fn send_sms(
    client: &Client,
    router: &RouterDetails,
    number: &str,
    message: &str,
) -> Result<(), Box<dyn Error>> {
    let url = format!("http://{}/cgi-bin/sms.cgi?action=send", router.router_ip);
    let payload = serde_json::json!({
        "number": number,
        "message": message
    });

    let response = client
        .post(&url)
        .header("Authorization", &router.auth_header)
        .json(&payload)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!(
            "Failed to send SMS: {}",
            response.text().await.unwrap_or_default()
        )
        .into());
    }

    // Handle plain text response
    let plain_response = response.text().await?;
    println!("\nResponse: {}", plain_response);

    Ok(())
}

// Main function

async fn run_sms_gateway() -> Result<(), Box<dyn Error>> {
    let client = Client::new();

    // Gather router details from the user
    println!("Welcome to the 3methxan crude SMS App!");
    let router_ip = prompt_input("Enter your router IP (e.g., 192.168.1.1): ");
    let username = prompt_input("Enter your username: ");
    let password = match rpassword::prompt_password("Enter your password: ") {
        Ok(password) => password,
        Err(e) => {
            eprintln!("Failed to read password: {}", e);
            return Err(Box::new(e));
        }
    };
    let auth_header = format!("Basic {}", encode_basic_auth(&username, &password));
    let router_details = RouterDetails {
        router_ip,
        auth_header,
    };

    // Menu loop for user interaction
    loop {
        println!("\nMenu:");
        println!("1. Fetch SMS");
        println!("2. Send SMS");
        println!("3. Exit");

        let choice = prompt_input("Choose an option: ");

        match choice.as_str() {
            "1" => {
                fetch_sms(&client, &router_details).await?;
            }
            "2" => {
                let number = prompt_input("Enter recipient's phone number: ");
                let message = prompt_input("Enter your message: ");

                send_sms(&client, &router_details, &number, &message).await?;
            }
            "3" => {
                println!("Exiting...");
                break;
            }
            _ => println!("Invalid option, try again."),
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Synchronous operations
    check_prerequisites()?;
    setup_reverse_proxy()?;

    // Async operations
    run_sms_gateway().await?;

    Ok(())
}
