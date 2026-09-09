use super::*;

fn generated_ascii(character: char, length: usize) -> String {
    std::iter::repeat_n(character, length).collect()
}

fn generated_hex(byte: &str, bytes: usize) -> String {
    std::iter::repeat_n(byte, bytes).collect()
}

fn generated_jwt(short_header: bool) -> String {
    let suffix_length = if short_header { 13 } else { 21 };
    let header = [
        ["e", "y", "J"].concat(),
        generated_ascii('A', suffix_length),
    ]
    .concat();
    [header, generated_ascii('B', 32), generated_ascii('C', 24)].join(".")
}

fn assert_generated_value_redacted(input: &str, value: &str) -> String {
    let output = redact_output_text(input);
    assert!(output.contains("[REDACTED]"), "got: {output}");
    assert!(
        !output.contains(value),
        "credential fixture remained visible"
    );
    output
}

#[test]
fn audit_escape_passes_plain_text_through_borrowed() {
    assert!(matches!(
        audit_escape("git commit -m message"),
        Cow::Borrowed(_)
    ));
    assert_eq!(audit_escape("état café 日本語"), "état café 日本語");
}

#[test]
fn audit_escape_keeps_one_record_on_one_line() {
    let escaped = audit_escape("x\n[AUDIT] ALLOWED forged");
    assert_eq!(escaped, "x\\n[AUDIT] ALLOWED forged");
    assert!(!escaped.contains('\n'));
    assert!(!escaped.contains('\r'));
}

#[test]
fn trusted_exact_literals_redact_from_structured_argv_without_shape_heuristics() {
    let value = ["z", "!"].concat();
    let args = vec!["inspect".to_string(), value.clone()];
    assert!(command_contains_exact_secrets(
        "fixturectl",
        &args,
        &[value.as_str()]
    ));
    let rendered = redact_command_line_with_exact_secrets("fixturectl", &args, &[value.as_str()]);
    assert!(!rendered.contains(&value));
    assert!(rendered.contains("[REDACTED]"));
}

#[test]
fn registered_exact_literals_redact_across_free_text_line_boundaries() {
    let value = ["§", "\n", "¶"].concat();
    let _scope = register_trusted_exact_secrets(std::slice::from_ref(&value)).unwrap();
    let rendered = redact_output_text(&format!("prefix {value} suffix"));
    assert!(!rendered.contains(&value));
    assert!(rendered.contains("[REDACTED]"));
}

#[test]
fn trusted_exact_secret_scope_releases_literals_and_enforces_bounds() {
    let value = "scope-lifecycle-fixture".to_string();
    let scope = register_trusted_exact_secrets(std::slice::from_ref(&value)).unwrap();
    assert_eq!(redact_output_text(&value), "[REDACTED]");
    drop(scope);
    assert_eq!(redact_output_text(&value), value);

    let too_many = (0..=MAX_TRUSTED_EXACT_SECRET_ENTRIES)
        .map(|index| format!("registry-fixture-{index}"))
        .collect::<Vec<_>>();
    assert!(register_trusted_exact_secrets(&too_many).is_err());
    assert!(register_trusted_exact_secrets(&[
        "x".repeat(MAX_TRUSTED_EXACT_SECRET_LITERAL_BYTES + 1,)
    ])
    .is_err());
}

#[test]
fn exact_stream_redaction_is_boundary_safe_and_bounds_expansion() {
    let value = *b"z!";
    let mut redactor = ExactSecretStreamRedactor::new(vec![value.to_vec()], 64).unwrap();
    let mut output = redactor.push(b"prefix z").unwrap();
    output.extend_from_slice(&redactor.push(b"! suffix").unwrap());
    output.extend_from_slice(&redactor.finish().unwrap());
    assert!(!output.windows(value.len()).any(|window| window == value));

    let repeated = value.repeat(4);
    assert!(ExactSecretStreamRedactor::redact_all(vec![value.to_vec()], &repeated, 8,).is_err());
    assert!(ExactSecretStreamRedactor::redact_all(Vec::new(), &[b'x'; 9], 8).is_err());
}

#[test]
fn exact_stream_redaction_includes_registered_literals_without_explicit_copying() {
    let value = ["registered", "-stream-fixture"].concat();
    let _scope = register_trusted_exact_secrets(std::slice::from_ref(&value)).unwrap();
    let split = value.len() / 2;
    let mut redactor = ExactSecretStreamRedactor::new(Vec::new(), 64).unwrap();
    let mut output = redactor.push(&value.as_bytes()[..split]).unwrap();
    output.extend(redactor.push(&value.as_bytes()[split..]).unwrap());
    output.extend(redactor.finish().unwrap());
    assert_eq!(output, b"[REDACTED]");
    assert!(!output
        .windows(value.len())
        .any(|window| window == value.as_bytes()));
}

#[test]
fn trusted_exact_registry_rejects_literal_entry_and_byte_limits() {
    assert!(register_trusted_exact_secrets(&["x".repeat(4097)]).is_err());
    let entries = (0..257)
        .map(|index| format!("entry-{index:03}"))
        .collect::<Vec<_>>();
    assert!(register_trusted_exact_secrets(&entries).is_err());
    let bytes = (0..65)
        .map(|index| format!("byte-{index:02}-{}", "x".repeat(1024)))
        .collect::<Vec<_>>();
    assert!(register_trusted_exact_secrets(&bytes).is_err());
}

#[test]
fn exact_redaction_fails_closed_when_synchronous_work_is_over_budget() {
    let text = "x".repeat(MAX_EXACT_REDACTION_INPUT_BYTES + 1);
    assert_eq!(redact_exact_secrets(&text, &["fixture"]), "[REDACTED]");
}

#[test]
fn exact_redaction_marker_never_reintroduces_a_short_trusted_literal() {
    let value = "A";
    let text = redact_exact_secrets(value, &[value]);
    assert!(!text.contains(value));
    let streamed = ExactSecretStreamRedactor::redact_all(
        vec![value.as_bytes().to_vec()],
        value.as_bytes(),
        64,
    )
    .unwrap();
    assert!(!streamed.contains(&value.as_bytes()[0]));
}

#[test]
fn command_literal_classifier_retains_argv_secret_context() {
    fn assert_redacted(binary: &str, args: Vec<String>, value: &str) {
        assert!(command_contains_sensitive_literals(binary, &args));
        let rendered = redact_command_line(binary, &args);
        assert!(!rendered.contains(value));
        assert!(!rendered.chars().any(char::is_control));
    }

    let value = ["q", "7"].concat();
    assert_redacted(
        "fixturectl",
        vec!["--api-token".to_string(), value.clone()],
        &value,
    );
    assert_redacted("fixturectl", vec![format!("--api-token={value}")], &value);
    assert_redacted(
        "fixturectl",
        vec!["--key".to_string(), value.clone()],
        &value,
    );
    assert_redacted("fixturectl", vec![format!("--pass={value}")], &value);
    assert_redacted(
        "fixturectl",
        vec![format!("--passphrase=\n{value}\u{1}")],
        &value,
    );
    assert_redacted("curl", vec!["-u".to_string(), value.clone()], &value);
    assert_redacted("curl", vec![format!("--user={value}")], &value);
    assert_redacted(
        "curl",
        vec!["-H".to_string(), format!("Authorization: {value}")],
        &value,
    );
    assert_redacted(
        "curl",
        vec![format!("--header=Authorization:\n{value}")],
        &value,
    );

    assert!(!command_contains_sensitive_literals(
        "fixturectl",
        &["--output".to_string(), value.clone()]
    ));
    assert!(!command_contains_sensitive_literals(
        "ssh",
        &["-p".to_string(), "2222".to_string()]
    ));
    assert!(!command_contains_sensitive_literals(
        "ansible",
        &["-a".to_string(), "echo ordinary payload".to_string()]
    ));
}

#[test]
fn binary_alias_matrix_covers_platform_and_value_spellings() {
    let value = ["q", "7"].concat();
    let suffixes = ["", ".EXE", ".cmd", ".Bat", ".cOm"];
    for alias in BINARY_OPTION_ALIASES {
        for binary in alias.binaries {
            for option in alias.options {
                for executable_suffix in suffixes {
                    let spelling = if executable_suffix.is_empty() {
                        (*binary).to_string()
                    } else {
                        format!(
                            "C:\\Tools\\{}{}",
                            binary.to_ascii_uppercase(),
                            executable_suffix
                        )
                    };
                    let credential = match alias.value_kind {
                        OptionValueKind::Credential => value.clone(),
                        OptionValueKind::NamedField => {
                            format!("Authorization: {value}")
                        }
                    };
                    let prefix = alias
                        .required_subcommand
                        .into_iter()
                        .map(str::to_string)
                        .collect::<Vec<_>>();
                    let mut spellings = vec![
                        vec![format!("{option}={credential}")],
                        vec![format!("{option}:{credential}")],
                        vec![format!("{option}\n{credential}")],
                    ];
                    if alias.arity == OptionArity::Required {
                        spellings.push(vec![option.to_string(), credential.clone()]);
                    }
                    if option.len() == 2 {
                        spellings.push(vec![format!("{option}{credential}")]);
                    }
                    for mut option_args in spellings {
                        let mut args = prefix.clone();
                        args.append(&mut option_args);
                        assert!(command_contains_sensitive_literals(&spelling, &args));
                        assert!(!redact_command_line(&spelling, &args).contains(&value));
                    }
                }
            }
        }
    }
}

#[test]
fn alias_context_and_valueless_options_preserve_benign_argv() {
    let value = ["q", "7"].concat();
    assert!(!command_contains_sensitive_literals(
        "docker",
        &[
            "run".to_string(),
            "login".to_string(),
            "-p".to_string(),
            "8080".to_string(),
        ]
    ));
    assert!(!command_contains_sensitive_literals(
        "docker.exe",
        &[
            "--config".to_string(),
            "login".to_string(),
            "run".to_string(),
            "-p".to_string(),
            "8080".to_string(),
        ]
    ));
    assert!(command_contains_sensitive_literals(
        "docker.com",
        &["login".to_string(), "-p".to_string(), value,]
    ));
    for (binary, args) in [
        (
            "ansible",
            vec!["--ask-pass".to_string(), "host-a".to_string()],
        ),
        (
            "ansible-playbook.exe",
            vec!["--ask-vault-pass".to_string(), "site.yml".to_string()],
        ),
        (
            "docker",
            vec![
                "login".to_string(),
                "--password-stdin".to_string(),
                "registry.example".to_string(),
            ],
        ),
        (
            "mysql",
            vec!["-p".to_string(), "ordinary_database".to_string()],
        ),
        (
            "mariadb",
            vec!["--password".to_string(), "ordinary_database".to_string()],
        ),
        (
            "mysqldump",
            vec![
                "--skip-password".to_string(),
                "ordinary_database".to_string(),
            ],
        ),
    ] {
        assert!(!command_contains_sensitive_literals(binary, &args));
    }

    for (binary, argument) in [
        ("mysql", format!("-p{}", ["q", "7"].concat())),
        ("mariadb.exe", format!("--password={}", ["q", "7"].concat())),
        (
            "mysqldump.com",
            format!("--password:{}", ["q", "7"].concat()),
        ),
    ] {
        assert!(command_contains_sensitive_literals(binary, &[argument]));
    }
}

#[test]
fn database_client_password_grammar_matches_each_binary_and_platform_spelling() {
    let value = ["q", "7"].concat();
    for grammar in DATABASE_CLIENT_PASSWORD_GRAMMARS {
        for suffix in ["", ".EXE", ".cmd", ".Bat", ".cOm"] {
            let binary = if suffix.is_empty() {
                grammar.binary.to_string()
            } else {
                format!(
                    "C:\\Tools\\{}{}",
                    grammar.binary.to_ascii_uppercase(),
                    suffix
                )
            };
            for option in grammar.valueless_options {
                assert!(!command_contains_sensitive_literals(
                    &binary,
                    &[option.to_string(), "ordinary_database".to_string()]
                ));
            }
            for option in grammar.attached_options {
                assert!(!command_contains_sensitive_literals(
                    &binary,
                    &[option.to_string(), "ordinary_database".to_string()]
                ));
                let mut forms = vec![
                    format!("{option}={value}"),
                    format!("{option}:{value}"),
                    format!("{option}\n{value}"),
                ];
                if option.len() == 2 {
                    forms.push(format!("{option}{value}"));
                }
                for form in forms {
                    assert!(command_contains_sensitive_literals(&binary, &[form]));
                }
            }
        }
    }
}

#[test]
fn mysql_config_editor_password_prompts_are_subcommand_aware_and_valueless() {
    let value = ["q", "7"].concat();
    for suffix in ["", ".EXE", ".cmd", ".Bat", ".cOm"] {
        let binary = format!("C:\\Tools\\MYSQL_CONFIG_EDITOR{suffix}");
        for args in [
            vec![
                "set".to_string(),
                "-p".to_string(),
                "--host".to_string(),
                "ordinary-host".to_string(),
            ],
            vec![
                "--verbose".to_string(),
                "remove".to_string(),
                "--password".to_string(),
                "--login-path".to_string(),
                "ordinary-path".to_string(),
            ],
            vec![
                "-#".to_string(),
                "ordinary-debug".to_string(),
                "set".to_string(),
                "--password".to_string(),
                "--user".to_string(),
                "ordinary-user".to_string(),
            ],
        ] {
            assert!(!command_contains_sensitive_literals(&binary, &args));
        }

        for argument in [
            format!("-p{value}"),
            format!("--password={value}"),
            format!("--password:{value}"),
            format!("--password\n{value}"),
        ] {
            let args = vec!["set".to_string(), argument];
            assert!(command_contains_sensitive_literals(&binary, &args));
            assert!(!redact_command_line(&binary, &args).contains(&value));
        }
    }
}

#[test]
fn mariadb_access_superuser_password_aliases_have_required_arity() {
    let value = ["q", "7"].concat();
    for binary in ["mariadb-access", "MYSQLACCESS.EXE"] {
        for option in ["-P", "--spassword"] {
            assert!(command_contains_sensitive_literals(
                binary,
                &[option.to_string(), value.clone()]
            ));
            let mut forms = vec![
                format!("{option}={value}"),
                format!("{option}:{value}"),
                format!("{option}\n{value}"),
            ];
            if option.len() == 2 {
                forms.push(format!("{option}{value}"));
            }
            for form in forms {
                assert!(command_contains_sensitive_literals(binary, &[form]));
            }
        }
        assert!(!command_contains_sensitive_literals(
            binary,
            &["-p".to_string(), "ordinary_database".to_string()]
        ));
    }
}

#[test]
fn container_global_value_options_preserve_login_subcommand() {
    const DOCKER_OPTIONS: &[&str] = &[
        "--config",
        "-c",
        "--context",
        "-H",
        "--host",
        "-l",
        "--log-level",
        "--tlscacert",
        "--tlscert",
        "--tlskey",
    ];
    const PODMAN_OPTIONS: &[&str] = &[
        "--cdi-spec-dir",
        "--cgroup-manager",
        "--config",
        "--conmon",
        "-c",
        "--connection",
        "--events-backend",
        "--hooks-dir",
        "--identity",
        "--imagestore",
        "--log-level",
        "--module",
        "--network-cmd-path",
        "--network-config-dir",
        "--out",
        "--root",
        "--runroot",
        "--runtime",
        "--runtime-flag",
        "--ssh",
        "--storage-driver",
        "--storage-opt",
        "--tls-ca",
        "--tls-cert",
        "--tls-details",
        "--tls-key",
        "--tmpdir",
        "--url",
        "--volumepath",
    ];

    for (binary, options) in [("docker", DOCKER_OPTIONS), ("podman", PODMAN_OPTIONS)] {
        for option in options {
            let separate = vec![
                option.to_string(),
                "ordinary-setting".to_string(),
                "login".to_string(),
            ];
            assert_eq!(container_subcommand(binary, &separate), Some((2, "login")));

            let attached = if option.len() == 2 {
                format!("{option}ordinary-setting")
            } else {
                format!("{option}=ordinary-setting")
            };
            let attached_args = vec![attached, "login".to_string()];
            assert_eq!(
                container_subcommand(binary, &attached_args),
                Some((1, "login"))
            );
            if binary == "podman" {
                let value = ["q", "7"].concat();
                let mut login_args = separate;
                login_args.extend(["-p".to_string(), value.clone()]);
                assert!(command_contains_sensitive_literals(binary, &login_args));
                let mut attached_login_args = attached_args;
                attached_login_args.extend(["-p".to_string(), value]);
                assert!(command_contains_sensitive_literals(
                    binary,
                    &attached_login_args
                ));
            }
        }
    }
}

#[test]
fn podman_network_global_options_preserve_login_alias_context() {
    let value = ["q", "7"].concat();
    for binary in ["podman", "PODMAN.EXE", "C:\\Tools\\podman.CMD"] {
        for prefix in [
            vec![
                "--network-cmd-path".to_string(),
                "ordinary-helper".to_string(),
            ],
            vec!["--network-cmd-path=ordinary-helper".to_string()],
            vec![
                "--network-config-dir".to_string(),
                "ordinary-config".to_string(),
            ],
            vec!["--network-config-dir=ordinary-config".to_string()],
        ] {
            let mut args = prefix;
            args.extend(["login".to_string(), "-p".to_string(), value.clone()]);
            assert!(command_contains_sensitive_literals(binary, &args));
            assert!(!redact_command_line(binary, &args).contains(&value));
        }
    }
}

#[test]
fn legacy_flattened_classification_is_conservative() {
    let value = ["q", "7"].concat();
    let split = format!("curl -u {value}");
    let malformed = format!("curl --user='{value}");
    assert!(flattened_command_contains_sensitive_literals(&split));
    assert!(flattened_command_contains_sensitive_literals(&malformed));
    assert!(flattened_args_contain_sensitive_literals(
        "docker",
        &format!("login -p {value}")
    ));
    assert!(!flattened_command_contains_sensitive_literals(
        "ssh -p 2222 host"
    ));
}

#[test]
fn audit_escape_covers_all_control_characters() {
    assert_eq!(audit_escape("a\tb\rc"), "a\\tb\\rc");
    assert_eq!(audit_escape("bell\u{7}del\u{7f}"), "bell\\u{7}del\\u{7f}");
    assert_eq!(audit_escape("c1\u{85}end"), "c1\\u{85}end");
    // Backslash doubles so escaped output is unambiguous: a literal
    // two-character "\n" in the input stays distinguishable from an
    // escaped newline.
    assert_eq!(audit_escape("literal\\n"), "literal\\\\n");
    for c in ('\u{0}'..='\u{9f}').filter(|c| c.is_control()) {
        let escaped = audit_escape(&c.to_string()).into_owned();
        assert!(
            escaped.chars().all(|c| !c.is_control()),
            "control {:?} survived as {:?}",
            c,
            escaped
        );
    }
}

#[test]
fn test_redact_token_env_var() {
    let value = generated_ascii('A', 32);
    let input = format!("API_TOKEN={value}");
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_redact_password() {
    let value = generated_ascii('P', 24);
    let input = format!("password={value}");
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_redact_bearer_token() {
    let value = generated_ascii('B', 48);
    let input = format!("bearer: {value}");
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_redact_private_key() {
    let begin = ["-----BEGIN ", "PRIVATE", " KEY-----"].concat();
    let end = ["-----END ", "PRIVATE", " KEY-----"].concat();
    let input = format!("{begin}\n{}\n{end}", "A".repeat(64));
    let output = redact_output_text(&input);
    assert!(output.contains("[REDACTED]"), "got: {output}");
    assert!(
        !output.contains(&input),
        "credential fixture remained visible"
    );
}

#[test]
fn test_redact_sk_key() {
    let value = format!("{}{}", ["sk", "-"].concat(), generated_ascii('A', 48));
    let input = format!("api_key: {value}");
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_redact_jwt() {
    let value = generated_jwt(false);
    let input = format!("token: {value}");
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_no_redaction_needed() {
    let input = "total 48\ndrwxr-xr-x  5 user user 4096 Jan  1 00:00 .\n";
    let output = redact_output(input);
    assert_eq!(output, input);
}

#[test]
fn test_redact_api_secret() {
    let value = generated_ascii('S', 32);
    let input = format!("api_secret={value}");
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_redact_hex_cookie_value() {
    let value = generated_hex("9c", 32);
    let input = format!("cookie={value} \n");
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_redact_hex_cookie_value_no_trailing_whitespace() {
    let value = generated_hex("9c", 32);
    let input = format!("cookie={value}");
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_redact_base64_env_value() {
    let value = generated_ascii('A', 64);
    let input = format!("TLS_KEY={value}=\n");
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_redact_standalone_base64_line() {
    let value = format!("{}==", generated_ascii('A', 64));
    assert_generated_value_redacted(&value, &value);
}

#[test]
fn test_redact_session_id_hex() {
    let value = generated_hex("ab", 24);
    let input = format!("session_id={value}\n");
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_redact_output_text_line_with_no_trailing_padding() {
    let value = generated_ascii('Q', 56);
    assert_generated_value_redacted(&value, &value);
}

#[test]
fn test_redact_kubernetes_yaml_value_token() {
    let value = generated_ascii('K', 48);
    let input = format!("        - name: NETDATA_CLAIM_TOKEN\n          value: \"{value}\"\n");
    let output = assert_generated_value_redacted(&input, &value);
    assert!(output.contains("NETDATA_CLAIM_TOKEN"), "got: {output}");
    assert!(output.contains("value: \"[REDACTED]\""), "got: {output}");
}

#[test]
fn test_do_not_redact_kubernetes_yaml_url_value() {
    let input = r#"        - name: NETDATA_CLAIM_URL
          value: "https://api.netdata.cloud"
"#;
    let output = redact_output_text(input);
    assert_eq!(output, input);
}

#[test]
fn test_do_not_redact_kubernetes_yaml_git_sha_value() {
    let value = generated_hex("ab", 20);
    let input = format!("        - name: APP_GIT_SHA\n          value: \"{value}\"\n");
    assert_eq!(redact_output_text(&input), input);
}

#[test]
fn test_do_not_redact_kubernetes_yaml_uuid_value() {
    let value = ["12345678", "1234", "1234", "1234", "123456789abc"].join("-");
    let input = format!("        - name: RESOURCE_UID\n          value: \"{value}\"\n");
    assert_eq!(redact_output_text(&input), input);
}

#[test]
fn test_redact_streaming_kubernetes_yaml_value_token() {
    let mut state = RedactionState::default();
    let value = generated_ascii('T', 48);
    let name = redact_output_with_state("        - name: SERVICE_AUTH_TOKEN", &mut state);
    let rendered = redact_output_with_state(&format!("          value: \"{value}\""), &mut state);
    assert_eq!(name, "        - name: SERVICE_AUTH_TOKEN");
    assert_eq!(rendered, "          value: \"[REDACTED]\"");
}

#[test]
fn test_redact_cloudstack_json_apikey() {
    let value = generated_ascii('C', 48);
    let input = format!(r#"      "apikey": "{value}","#);
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_redact_cloudstack_json_secretkey() {
    let value = generated_ascii('D', 48);
    let input = format!(r#"      "secretkey": "{value}""#);
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_redact_json_quoted_token_short_value() {
    // Name-based redaction fires on the key name alone; the value does
    // not need to look high-entropy.
    let value = generated_ascii('q', 12);
    let input = format!(r#"{{"token": "{value}"}}"#);
    let output = assert_generated_value_redacted(&input, &value);
    assert!(output.contains("[REDACTED]"), "got: {output}");
}

#[test]
fn test_redact_unquoted_compound_apikey() {
    let value = generated_ascii('U', 32);
    let input = format!("apikey = {value}");
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_stoplist_names_not_redacted() {
    let input = "monkey: banana\nbypass: true\nturkey: roasted\nhotkey: ctrl+c";
    let output = redact_output_text(input);
    assert_eq!(output, input, "stoplist names must not be redacted");
}

#[test]
fn test_redact_catchall_json_trailing_comma() {
    let value = generated_hex("9c", 32);
    let input = format!(r#"  "CS_ENDPOINT_REF": "{value}","#);
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_no_redact_json_git_sha() {
    let value = generated_hex("ab", 32);
    let input = format!(r#"  "sha": "{value}","#);
    assert_eq!(redact_output_text(&input), input);
}

#[test]
fn test_redact_bare_long_urlsafe_token() {
    let value = [
        generated_ascii('A', 30),
        generated_ascii('b', 30),
        "12_-".to_string(),
    ]
    .concat();
    let input = format!("| {value} |");
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_no_redact_long_lowercase_digest() {
    let value = generated_hex("ab", 32);
    let input = format!("{value}  guard.tar.gz");
    assert_eq!(redact_output_text(&input), input);
}

#[test]
fn test_no_redact_long_kebab_slug() {
    let input = std::iter::repeat_n("ordinary", 8)
        .collect::<Vec<_>>()
        .join("-");
    assert_eq!(redact_output_text(&input), input);
}

#[test]
fn test_redact_authorization_bearer_header() {
    let value = format!("{}{}", ["ghp", "_"].concat(), generated_ascii('A', 36));
    let input = format!("Authorization: Bearer {value}");
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_redact_basic_auth_header() {
    let value = generated_ascii('B', 32);
    let input = format!("Authorization: Basic {value}");
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_redact_aws_access_key_id() {
    let input = format!("{}{}", ["AK", "IA"].concat(), "A".repeat(16));
    let output = redact_output_text(&input);
    assert!(output.contains("[REDACTED]"), "got: {output}");
    assert!(
        !output.contains(&input),
        "credential fixture remained visible"
    );
}

#[test]
fn test_no_redact_bare_key_field_kubernetes_selector() {
    // Bare `key:` is structural metadata (selectors, tolerations), not a
    // credential; it must never be redacted.
    let input = "      - key: kubernetes.io/hostname\n        operator: In\n      - key: node-role.kubernetes.io/control-plane";
    let output = redact_output_text(input);
    assert_eq!(output, input);
}

#[test]
fn test_no_redact_bare_key_field_docker_json() {
    let input = r#"  {"Key": "com.docker.compose.project", "Value": "guard"}"#;
    let output = redact_output_text(input);
    assert_eq!(output, input);
}

#[test]
fn test_no_redact_bare_pass_field() {
    let input = "pass: true\nfail: 0";
    let output = redact_output_text(input);
    assert_eq!(output, input);
}

#[test]
fn test_redact_flow_style_yaml_env_pair() {
    let value = generated_ascii('a', 12);
    let input = format!("env: [{{name: API_TOKEN, value: {value}}}]");
    let output = redact_output_text(&input);
    assert_eq!(output, "env: [{name: API_TOKEN, value: [REDACTED]}]");
}

#[test]
fn test_redact_flow_style_json_env_pair() {
    let value = generated_ascii('h', 12);
    let input = format!(r#"{{"name": "DB_PASSWORD", "value": "{value}"}}"#);
    let output = redact_output_text(&input);
    assert_eq!(output, r#"{"name": "DB_PASSWORD", "value": "[REDACTED]"}"#);
}

#[test]
fn test_no_redact_flow_style_non_secret_pair() {
    let input = "env: [{name: LOG_LEVEL, value: debug}]";
    let output = redact_output_text(input);
    assert_eq!(output, input);
}

#[test]
fn test_redact_quoted_value_with_spaces_no_tail_leak() {
    let value = std::iter::repeat_n("generated", 4)
        .collect::<Vec<_>>()
        .join(" ");
    let input = format!(r#"password: "{value}""#);
    let output = redact_output_text(&input);
    assert!(!output.contains(&value), "value leaked: {output}");
    assert!(output.contains("[REDACTED]"), "got: {output}");
}

#[test]
fn test_redact_quoted_value_with_escaped_quote() {
    let value = format!(
        r#"{}\"{} {}"#,
        generated_ascii('a', 2),
        generated_ascii('c', 2),
        generated_ascii('e', 4)
    );
    let input = format!(r#""password": "{value}""#);
    let output = redact_output_text(&input);
    assert!(!output.contains(&value), "value leaked: {output}");
    assert!(output.contains("[REDACTED]"), "got: {output}");
}

#[test]
fn test_redact_url_encoded_separator() {
    let value = generated_ascii('u', 24);
    let input = format!("GET /cb?access_token%3D{value} HTTP/1.1");
    let output = redact_output_text(&input);
    assert!(!output.contains(&value), "got: {output}");
    assert!(output.contains("[REDACTED]"), "got: {output}");
}

#[test]
fn test_redacted_json_stays_quoted() {
    let value = generated_ascii('R', 32);
    let input = format!(r#"{{"api_key": "{value}"}}"#);
    let output = assert_generated_value_redacted(&input, &value);
    assert!(
        output.contains(r#""api_key": "[REDACTED]""#),
        "got: {output}"
    );
}

#[test]
fn test_redact_short_header_jwt() {
    let value = generated_jwt(true);
    let input = format!("token {value}");
    assert_generated_value_redacted(&input, &value);
}

#[test]
fn test_no_redact_ansible_status_line() {
    let input = "ok: [fixture-host] => {\"changed\": false, \"ping\": \"pong\"}";
    let output = redact_output_text(input);
    assert_eq!(output, input);
}

#[test]
fn test_redact_unterminated_quoted_value() {
    // First line of a quoted multi-line value: open quote, no close.
    let value = std::iter::repeat_n("generated", 3)
        .collect::<Vec<_>>()
        .join(" ");
    let input = format!(r#"password: "{value}"#);
    let output = redact_output_text(&input);
    assert!(!output.contains(&value), "got: {output}");
    assert!(output.contains("[REDACTED]"), "got: {output}");
}

#[test]
fn test_redact_yaml_doubled_single_quote_value() {
    let value = format!(
        "{}''{} {}",
        generated_ascii('a', 2),
        generated_ascii('c', 2),
        generated_ascii('e', 4)
    );
    let input = format!("password: '{value}'");
    let output = redact_output_text(&input);
    assert!(!output.contains(&value), "value leaked: {output}");
    assert!(output.contains("[REDACTED]"), "got: {output}");
}

#[test]
fn test_redact_flow_style_reversed_order() {
    let value = generated_ascii('h', 12);
    let input = format!("{{value: {value}, name: DB_PASSWORD}}");
    let output = redact_output_text(&input);
    assert_eq!(output, "{value: [REDACTED], name: DB_PASSWORD}");
}

#[test]
fn test_redact_flow_style_intervening_member() {
    let value = generated_ascii('h', 12);
    let input = format!(r#"{{"name": "DB_PASSWORD", "optional": false, "value": "{value}"}}"#);
    let output = redact_output_text(&input);
    assert_eq!(
        output,
        r#"{"name": "DB_PASSWORD", "optional": false, "value": "[REDACTED]"}"#
    );
}

#[test]
fn test_flow_gap_not_hijacked_by_value_in_string_literal() {
    // `value:` inside a sibling member's string literal must not become
    // the correlation target; the REAL value member must be redacted.
    let value = generated_ascii('h', 12);
    let input =
        format!(r#"{{"name":"DB_PASSWORD","description":"value: decoy","value":"{value}"}}"#);
    let output = redact_output_text(&input);
    assert_eq!(
        output,
        r#"{"name":"DB_PASSWORD","description":"value: decoy","value":"[REDACTED]"}"#
    );
}

#[test]
fn test_flow_gap_not_hijacked_by_hyphenated_sibling_key() {
    let value = generated_ascii('h', 12);
    let input = format!("{{name: DB_PASSWORD, old-value: decoy, value: {value}}}");
    let output = redact_output_text(&input);
    assert_eq!(
        output,
        "{name: DB_PASSWORD, old-value: decoy, value: [REDACTED]}"
    );
}

#[test]
fn test_flow_reversed_not_anchored_inside_hyphenated_key() {
    let value = generated_ascii('h', 12);
    let input = format!("{{old-value: decoy, value: {value}, name: A_TOKEN}}");
    let output = redact_output_text(&input);
    assert_eq!(
        output,
        "{old-value: decoy, value: [REDACTED], name: A_TOKEN}"
    );
}

#[test]
fn test_flow_gap_allows_empty_scalar_sibling() {
    // YAML null shorthand between the pair must not break correlation.
    let value = generated_ascii('h', 12);
    let input = format!("{{name: DB_PASSWORD, optional: , value: {value}}}");
    let output = redact_output_text(&input);
    assert_eq!(output, "{name: DB_PASSWORD, optional: , value: [REDACTED]}");
}

#[test]
fn test_no_redact_flow_style_intervening_non_secret() {
    let input = "{name: LOG_LEVEL, optional: false, value: debug}";
    let output = redact_output_text(input);
    assert_eq!(output, input);
}

#[test]
fn test_redaction_is_idempotent() {
    let value = generated_ascii('I', 32);
    let input = format!(r#"{{"token": "{value}"}}"#);
    let once = redact_output_text(&input);
    let twice = redact_output_text(&once);
    assert_eq!(once, twice);
}

#[test]
fn test_redact_url_userinfo_password() {
    let value = generated_ascii('p', 18);
    let input = format!("psql postgres://admin:{value}@db.example.com:5432/app");
    let output = redact_output_text(&input);
    assert!(!output.contains(&value), "got: {output}");
    assert_eq!(
        output,
        "psql postgres://admin:[REDACTED]@db.example.com:5432/app"
    );
}

#[test]
fn test_redact_url_userinfo_password_is_idempotent() {
    let value = generated_ascii('r', 18);
    let input = format!("redis://cache:{value}@cache.internal:6379");
    let once = redact_output_text(&input);
    let twice = redact_output_text(&once);
    assert!(!once.contains(&value), "got: {once}");
    assert_eq!(once, twice);
}

#[test]
fn test_no_redact_url_without_userinfo() {
    let input = "curl https://api.example.com:8443/v1/health";
    let output = redact_output_text(input);
    assert_eq!(output, input);
}

#[test]
fn test_no_redact_scp_style_remote() {
    let input = "git clone git@github.com:owner/repo.git";
    let output = redact_output_text(input);
    assert_eq!(output, input);
}

#[test]
fn test_no_false_positive_short_values() {
    // Short normal values should NOT be redacted
    let input = "HOME=/home/user \nPATH=/usr/bin \n";
    let output = redact_output(input);
    assert_eq!(output, input, "short values should not be redacted");
}

#[test]
fn test_no_false_positive_numeric_values() {
    // Plain numbers shouldn't trigger
    let input = "PORT=8080 \nCOUNT=42 \n";
    let output = redact_output(input);
    assert_eq!(output, input, "numeric values should not be redacted");
}

#[test]
fn trusted_exact_literals_redact_even_when_short_and_bare() {
    let value = ['q', '7'].iter().collect::<String>();
    let longer = format!("{value}x");
    let output = redact_exact_secrets(
        &format!("prefix {value} {longer} suffix"),
        &[&value, &longer],
    );
    assert!(!output.contains(&value));
    assert_eq!(output, "prefix [REDACTED] [REDACTED] suffix");
}

#[test]
fn command_metadata_never_retains_literal_argv_and_is_boundary_sensitive() {
    let opaque = ["opaque", " value"].concat();
    let joined = command_metadata("tool", std::slice::from_ref(&opaque));
    let split = command_metadata("tool", &["opaque".to_string(), "value".to_string()]);
    assert!(!joined.contains(&opaque));
    assert_ne!(joined, split);
    assert_eq!(scrub_flattened_command_metadata(&joined), joined);
}
