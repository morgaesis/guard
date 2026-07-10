use super::*;

pub(crate) async fn handle_shim(
    tools: Option<Vec<String>>,
    list: bool,
    remove: bool,
    path: Option<PathBuf>,
    env_vars: Vec<(String, String)>,
    secret_vars: Vec<(String, String)>,
    user: Option<String>,
) -> Result<()> {
    let env_vars = env_pairs_to_map(env_vars).map_err(anyhow::Error::msg)?;
    let secret_vars = env_pairs_to_map(secret_vars).map_err(anyhow::Error::msg)?;
    let shim_dir = path.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".guard/shims")
    });

    if list {
        let generator = shim::ShimGenerator::new(std::env::current_exe()?, shim_dir);
        let installed = generator.list_installed()?;
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
        return Ok(());
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

    // Default: install shims
    let tools_to_install = tools.unwrap_or_else(|| vec!["ssh".to_string(), "scp".to_string()]);
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
