use super::*;

use crate::cli_client::{admin_client, resolve_client_endpoint};

pub(crate) async fn handle_secrets(subcommand: SecretCommands) -> Result<()> {
    let config = client_config::ClientConfig::load().ok().unwrap_or_default();
    let (socket_path, tcp_port) = resolve_client_endpoint(None, &config);
    let client = admin_client(socket_path, tcp_port, &config);

    match subcommand {
        SecretCommands::Add { key, value } => {
            let existed = match client
                .send_admin(server::AdminRequest::SecretExists { key: key.clone() })
                .await
            {
                Ok(server::AdminResponse::SecretExists { exists }) => exists,
                Ok(server::AdminResponse::Error { .. }) | Err(_) => {
                    match client.send_admin(server::AdminRequest::SecretList).await? {
                        server::AdminResponse::SecretList { keys } => {
                            keys.iter().any(|k| k == &key)
                        }
                        server::AdminResponse::Error { message } => anyhow::bail!("{}", message),
                        other => anyhow::bail!("unexpected admin response: {:?}", other),
                    }
                }
                Ok(other) => anyhow::bail!("unexpected admin response: {:?}", other),
            };
            let secret_value = if let Some(v) = value {
                v
            } else if !std::io::stdin().is_terminal() {
                let mut value = String::new();
                std::io::stdin()
                    .read_to_string(&mut value)
                    .context("failed to read secret value from stdin")?;
                if value.ends_with('\n') {
                    value.pop();
                    if value.ends_with('\r') {
                        value.pop();
                    }
                }
                value
            } else {
                rpassword::prompt_password("Secret value: ")?
            };
            match client
                .send_admin(server::AdminRequest::SecretSet {
                    key: key.clone(),
                    value: secret_value,
                })
                .await?
            {
                server::AdminResponse::Ok => {
                    if existed {
                        eprintln!(
                            "warning: secret '{}' already existed and was overwritten",
                            key
                        );
                    }
                    println!("Secret '{}' stored", key);
                    Ok(())
                }
                server::AdminResponse::Error { message } => {
                    anyhow::bail!("{}", message);
                }
                other => anyhow::bail!("unexpected admin response: {:?}", other),
            }
        }
        SecretCommands::List { detailed } => {
            let request = if detailed {
                server::AdminRequest::SecretListDetailed
            } else {
                server::AdminRequest::SecretList
            };
            match client.send_admin(request).await? {
                server::AdminResponse::SecretList { keys } => {
                    if keys.is_empty() {
                        println!("No secrets stored");
                    } else {
                        for key in keys {
                            println!("  - {}", key);
                        }
                    }
                    Ok(())
                }
                server::AdminResponse::SecretListDetailed { items } => {
                    if items.is_empty() {
                        println!("No secrets stored");
                    } else {
                        for item in items {
                            if item.legacy {
                                println!("  - {}  origin=legacy", item.key);
                            } else if let Some(uid) = item.uid {
                                println!("  - {}  uid={}", item.key, uid);
                            } else if let Some(principal) = &item.principal {
                                println!("  - {}  principal={}", item.key, principal);
                            } else {
                                println!("  - {}", item.key);
                            }
                        }
                    }
                    Ok(())
                }
                server::AdminResponse::Error { message } => {
                    anyhow::bail!("{}", message);
                }
                other => anyhow::bail!("unexpected admin response: {:?}", other),
            }
        }
        SecretCommands::Remove { key } => {
            match client
                .send_admin(server::AdminRequest::SecretDelete { key: key.clone() })
                .await?
            {
                server::AdminResponse::Ok => {
                    println!("Secret '{}' removed", key);
                    Ok(())
                }
                server::AdminResponse::Error { message } => {
                    anyhow::bail!("{}", message);
                }
                server::AdminResponse::SecretExists { .. } => {
                    anyhow::bail!("unexpected admin response: secret_exists")
                }
                other => anyhow::bail!("unexpected admin response: {:?}", other),
            }
        }
    }
}
