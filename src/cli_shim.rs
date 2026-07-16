use super::{env_pairs_to_map, print_json, JSON_SCHEMA_VERSION};
use crate::{shim, tool_config};
use anyhow::Result;
use std::path::PathBuf;

pub(crate) struct ShimOptions {
    pub(crate) tools: Option<Vec<String>>,
    pub(crate) list: bool,
    pub(crate) remove: bool,
    pub(crate) path: Option<PathBuf>,
    pub(crate) env_vars: Vec<(String, String)>,
    pub(crate) secret_vars: Vec<(String, String)>,
    pub(crate) user: Option<String>,
    pub(crate) json: bool,
}

pub(crate) async fn handle_shim(options: ShimOptions) -> Result<()> {
    let ShimOptions {
        tools,
        list,
        remove,
        path,
        env_vars,
        secret_vars,
        user,
        json,
    } = options;
    let env_vars = env_pairs_to_map(env_vars).map_err(anyhow::Error::msg)?;
    let secret_vars = env_pairs_to_map(secret_vars).map_err(anyhow::Error::msg)?;
    if json && !list && (remove || tools.is_some()) {
        anyhow::bail!("--json is supported for shim listing, not installation or removal");
    }
    let shim_dir = path.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".guard/shims")
    });

    if list {
        return print_installed_shims(shim_dir, json);
    }

    if remove {
        let generator = shim::ShimGenerator::new(std::env::current_exe()?, shim_dir);
        if let Some(tools) = tools {
            let tools_refs: Vec<&str> = tools.iter().map(|s| s.as_str()).collect();
            generator.remove(&tools_refs)?;
            // Also remove tool configs
            if let Ok(mut registry) = tool_config::ToolRegistry::load_default() {
                for t in &tools_refs {
                    let _ = registry.remove(t);
                }
            }
        } else {
            generator.remove_all()?;
        }
        println!("Removed shims");
        return Ok(());
    }

    // Installing is an explicit action: bare `guard shim` only reports what is
    // installed, so a stray invocation never writes shim scripts.
    let Some(tools_to_install) = tools else {
        if !env_vars.is_empty() || !secret_vars.is_empty() || user.is_some() {
            anyhow::bail!(
                "no tools named; specify which tools to configure, e.g. `guard shim ssh,scp --env KEY=VALUE`"
            );
        }
        return print_installed_shims(shim_dir, json);
    };
    let generator = shim::ShimGenerator::new(std::env::current_exe()?, shim_dir.clone());
    let tools_refs: Vec<&str> = tools_to_install.iter().map(|s| s.as_str()).collect();
    generator.generate(&tools_refs)?;
    println!("Installed shims to: {}", shim_dir.display());

    // Register tool configs if env/secret flags were provided
    if !env_vars.is_empty() || !secret_vars.is_empty() {
        let mut registry = tool_config::ToolRegistry::load_default()
            .unwrap_or_else(|_| tool_config::ToolRegistry::empty());

        for tool_name in &tools_to_install {
            let mut existing = registry.get(tool_name).cloned().unwrap_or_default();

            if let Some(ref user_key) = user {
                // Per-user override: store under users.<user_key>
                let user_override = existing.users.entry(user_key.clone()).or_default();

                for (k, v) in &env_vars {
                    user_override.env.insert(k.clone(), v.clone());
                }
                for (k, v) in &secret_vars {
                    user_override.secrets.insert(k.clone(), v.clone());
                }
                println!(
                    "Registered per-user ({}) config for: {}",
                    user_key, tool_name
                );
            } else {
                // Base tool config
                for (k, v) in &env_vars {
                    existing.env.insert(k.clone(), v.clone());
                }
                for (k, v) in &secret_vars {
                    existing.secrets.insert(k.clone(), v.clone());
                }
                println!("Registered tool config for: {}", tool_name);
            }

            registry.set(tool_name, existing)?;
        }
    }

    Ok(())
}

fn print_installed_shims(shim_dir: PathBuf, json: bool) -> Result<()> {
    let generator = shim::ShimGenerator::new(std::env::current_exe()?, shim_dir);
    let installed = generator.list_installed()?;
    if json {
        let registry = tool_config::ToolRegistry::load_default()
            .unwrap_or_else(|_| tool_config::ToolRegistry::empty());
        let items = installed
            .iter()
            .map(|name| {
                let config = registry.get(name);
                serde_json::json!({
                    "name": name,
                    "env": config.map(|value| &value.env),
                    "secrets": config.map(|value| &value.secrets),
                    "users": config.map(|value| &value.users),
                })
            })
            .collect::<Vec<_>>();
        return print_json(&serde_json::json!({
            "schema_version": JSON_SCHEMA_VERSION,
            "type": "shim_list",
            "items": items,
        }));
    }
    if installed.is_empty() {
        println!("No shims installed");
    } else {
        let registry = tool_config::ToolRegistry::load_default()
            .unwrap_or_else(|_| tool_config::ToolRegistry::empty());
        for s in installed {
            print!("  - {}", s);
            if let Some(tc) = registry.get(&s) {
                let parts: Vec<String> = tc
                    .env
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .chain(tc.secrets.iter().map(|(k, v)| format!("{k}=<secret:{v}>")))
                    .collect();
                if !parts.is_empty() {
                    print!("  [{}]", parts.join(", "));
                }
                for (uid, user_override) in &tc.users {
                    let user_parts: Vec<String> = user_override
                        .env
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .chain(
                            user_override
                                .secrets
                                .iter()
                                .map(|(k, v)| format!("{k}=<secret:{v}>")),
                        )
                        .collect();
                    if !user_parts.is_empty() {
                        print!("  user({uid}): [{}]", user_parts.join(", "));
                    }
                }
            }
            println!();
        }
    }
    Ok(())
}
