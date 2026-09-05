use super::{print_json, SecretCommands, JSON_SCHEMA_VERSION};
use crate::cli_client::{admin_client, load_client_config, resolve_client_endpoint};
use crate::server;
use anyhow::{Context, Result};
use std::io::{IsTerminal, Read};

pub(crate) async fn handle_secrets(subcommand: SecretCommands) -> Result<()> {
    let json = matches!(&subcommand, SecretCommands::List { json: true, .. });
    let config = load_client_config(json)?;
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
                    cli_println!("Secret '{}' stored", key);
                    Ok(())
                }
                server::AdminResponse::Error { message } => {
                    anyhow::bail!("{}", message);
                }
                other => anyhow::bail!("unexpected admin response: {:?}", other),
            }
        }
        SecretCommands::List { detailed, json } => {
            let request = if detailed {
                server::AdminRequest::SecretListDetailed
            } else {
                server::AdminRequest::SecretList
            };
            match client.send_admin(request).await? {
                server::AdminResponse::SecretList { keys } => {
                    if json {
                        let items = keys
                            .into_iter()
                            .map(|key| serde_json::json!({ "key": key }))
                            .collect::<Vec<_>>();
                        return print_json(&serde_json::json!({
                            "schema_version": JSON_SCHEMA_VERSION,
                            "type": "secret_list",
                            "detailed": false,
                            "items": items,
                        }));
                    }
                    if keys.is_empty() {
                        cli_println!("No secrets stored");
                    } else {
                        for key in keys {
                            cli_println!("  - {}", key);
                        }
                    }
                    Ok(())
                }
                server::AdminResponse::SecretListDetailed { items } => {
                    if json {
                        return print_json(&serde_json::json!({
                            "schema_version": JSON_SCHEMA_VERSION,
                            "type": "secret_list",
                            "detailed": true,
                            "items": items,
                        }));
                    }
                    if items.is_empty() {
                        cli_println!("No secrets stored");
                    } else {
                        for item in items {
                            if item.legacy {
                                cli_println!("  - {}  origin=legacy", item.key);
                            } else if let Some(uid) = item.uid {
                                cli_println!("  - {}  uid={}", item.key, uid);
                            } else if let Some(principal) = &item.principal {
                                cli_println!("  - {}  principal={}", item.key, principal);
                            } else {
                                cli_println!("  - {}", item.key);
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
                    cli_println!("Secret '{}' removed", key);
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
