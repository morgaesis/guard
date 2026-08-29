use super::*;

fn config(path: PathBuf, min_approvals: u32) -> AllowPromotionConfig {
    AllowPromotionConfig {
        path,
        enabled: true,
        min_approvals,
    }
}

fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn repeated_reversible_approvals_become_ready_once() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 2)).unwrap();
    let a = args(&["get", "pods", "-n", "foo"]);

    let first = store
        .record_approval(
            "kubectl",
            &a,
            "kubectl get pods -n foo",
            Some(1),
            Some(Reversibility::Reversible),
            "read-only",
        )
        .unwrap()
        .unwrap();
    assert!(!first.ready_to_synthesize);

    let second = store
        .record_approval(
            "kubectl",
            &a,
            "kubectl get pods -n foo",
            Some(1),
            Some(Reversibility::Reversible),
            "read-only",
        )
        .unwrap()
        .unwrap();
    assert!(second.ready_to_synthesize);

    // A third approval before the next multiple must not re-trigger.
    let third = store
        .record_approval(
            "kubectl",
            &a,
            "kubectl get pods -n foo",
            Some(1),
            Some(Reversibility::Reversible),
            "read-only",
        )
        .unwrap()
        .unwrap();
    assert!(!third.ready_to_synthesize);
}

#[test]
fn failed_allow_promotion_write_keeps_memory_and_durable_state_unchanged() {
    let temp = crate::learned_rules::authority_tempdir();
    let path = temp.path().join("allow.yaml");
    let mut store = AllowPromotionStore::load(config(path.clone(), 2)).unwrap();
    let command_args = args(&["get", "pods"]);
    store
        .record_approval(
            "kubectl",
            &command_args,
            "kubectl get pods",
            Some(1),
            Some(Reversibility::Reversible),
            "safe",
        )
        .unwrap();
    let before_memory = store.data.clone();
    let before_file = std::fs::read(&path).unwrap();
    let blocker = temp.path().join("blocker");
    crate::learned_rules::write_authority_file(&blocker, "not a directory").unwrap();
    store.config.path = blocker.join("allow.yaml");

    assert!(store
        .record_approval(
            "kubectl",
            &command_args,
            "kubectl get pods",
            Some(1),
            Some(Reversibility::Reversible),
            "safe",
        )
        .is_err());
    assert_eq!(store.data, before_memory);
    assert_eq!(std::fs::read(path).unwrap(), before_file);
}

#[test]
fn sensitive_allow_observations_are_rejected_and_purged_idempotently() {
    let temp = crate::learned_rules::authority_tempdir();
    let path = temp.path().join("allow.yaml");
    let config = config(path.clone(), 2);
    let mut store = AllowPromotionStore::load(config.clone()).unwrap();
    let safe = args(&["get", "pods"]);
    store
        .record_approval(
            "kubectl",
            &safe,
            "kubectl get pods",
            Some(1),
            Some(Reversibility::Reversible),
            "safe",
        )
        .unwrap();
    assert!(store
        .data
        .observations
        .values()
        .all(|observation| observation.last_command.contains("[argv-sha256:")));
    let safe_bytes = std::fs::read(&path).unwrap();
    let value = ["q", "7"].concat();
    assert!(store
        .record_approval(
            "redis-cli",
            &["-a".to_string(), value.clone()],
            &format!("redis-cli -a {value}"),
            Some(1),
            Some(Reversibility::Reversible),
            "ignored",
        )
        .unwrap()
        .is_none());
    assert_eq!(std::fs::read(&path).unwrap(), safe_bytes);

    let mut contaminated = store.data.clone();
    contaminated
        .observations
        .values_mut()
        .for_each(|observation| observation.last_command = "kubectl get pods".to_string());
    let mut observation = contaminated.observations.values().next().unwrap().clone();
    observation.binary = "redis-cli".to_string();
    observation.samples = vec![vec!["-a".to_string(), value.clone()]];
    observation.last_command = format!("redis-cli -a {value}");
    contaminated
        .observations
        .insert("sensitive".to_string(), observation);
    write_learning_file_atomically(&path, &serde_yaml_ng::to_string(&contaminated).unwrap())
        .unwrap();

    let loaded = AllowPromotionStore::load(config.clone()).unwrap();
    assert_eq!(loaded.data.observations.len(), 1);
    assert!(loaded
        .data
        .observations
        .values()
        .all(|observation| observation
            .last_command
            .starts_with("[legacy-command-sha256:")));
    let sanitized = std::fs::read(&path).unwrap();
    assert!(!sanitized
        .windows(value.len())
        .any(|window| window == value.as_bytes()));
    AllowPromotionStore::load(config).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), sanitized);
}

#[test]
fn allow_promotion_prose_is_sanitized_without_changing_samples() {
    let temp = crate::learned_rules::authority_tempdir();
    let path = temp.path().join("allow.yaml");
    let config = config(path.clone(), 2);
    let value = ["q", "7"].concat();
    let reason = format!("password={value}");
    let safe = args(&["get", "pods"]);
    let mut store = AllowPromotionStore::load(config.clone()).unwrap();
    store
        .record_approval(
            "kubectl",
            &safe,
            "kubectl get pods",
            Some(1),
            Some(Reversibility::Reversible),
            &reason,
        )
        .unwrap();
    let expected_samples = store
        .data
        .observations
        .values()
        .next()
        .unwrap()
        .samples
        .clone();
    assert!(!std::fs::read(&path)
        .unwrap()
        .windows(value.len())
        .any(|window| window == value.as_bytes()));

    let mut contaminated = store.data.clone();
    contaminated
        .observations
        .values_mut()
        .for_each(|observation| observation.last_reason = reason.clone());
    write_learning_file_atomically(&path, &serde_yaml_ng::to_string(&contaminated).unwrap())
        .unwrap();
    let loaded = AllowPromotionStore::load(config.clone()).unwrap();
    assert_eq!(
        loaded.data.observations.values().next().unwrap().samples,
        expected_samples
    );
    let sanitized = std::fs::read(&path).unwrap();
    assert!(!sanitized
        .windows(value.len())
        .any(|window| window == value.as_bytes()));
    AllowPromotionStore::load(config).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), sanitized);
}

#[test]
fn promoted_verb_description_and_evidence_are_sanitized() {
    let value = ["q", "7"].concat();
    let contaminated = format!("password={value}");
    let verb = build_candidate_verb(
        "fixturectl",
        "fixture-status".to_string(),
        contaminated.clone(),
        vec!["status".to_string()],
        BTreeMap::new(),
        Reversibility::Reversible,
        None,
        contaminated,
        "fixture-stamp".to_string(),
    )
    .unwrap();
    let encoded = serde_json::to_vec(&verb).unwrap();
    assert!(!encoded
        .windows(value.len())
        .any(|window| window == value.as_bytes()));
}

#[test]
fn promoted_verb_provenance_replays_observations_and_claims_no_probes() {
    let verb = build_candidate_verb(
        "fixturectl",
        "fixture-status".to_string(),
        "Show fixture status".to_string(),
        vec!["status".to_string()],
        BTreeMap::new(),
        Reversibility::Reversible,
        None,
        "evidence".to_string(),
        "fixture-stamp".to_string(),
    )
    .unwrap();
    assert!(verb.auto_promoted);
    assert_eq!(verb.consequence, Reversibility::Reversible);
    let provenance = verb.coverage[0].provenance.as_ref().unwrap();
    assert_eq!(provenance.source, "automatic_evaluator_promotion");
    assert!(
        provenance.probes.is_empty(),
        "nothing was executed against the matcher, so no probe may be claimed"
    );
    assert_eq!(provenance.observation_replays.len(), 2);
    assert!(provenance
        .observation_replays
        .iter()
        .any(|replay| replay.dimension == "observed_shape" && replay.template_match));
    assert!(provenance
        .observation_replays
        .iter()
        .any(|replay| replay.dimension == "outside_shape" && !replay.template_match));
}

#[test]
fn build_candidate_verb_refuses_any_class_above_reversible() {
    for class in [Reversibility::Recoverable, Reversibility::Irreversible] {
        let error = build_candidate_verb(
            "fixturectl",
            "fixture-restart".to_string(),
            "Restart fixture".to_string(),
            vec!["restart".to_string()],
            BTreeMap::new(),
            class,
            None,
            "evidence".to_string(),
            "fixture-stamp".to_string(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("only statically read-only"));
    }
}

#[test]
fn irreversible_is_never_recorded() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 1)).unwrap();
    let result = store
        .record_approval(
            "kubectl",
            &args(&["delete", "namespace", "prod"]),
            "kubectl delete namespace prod",
            Some(1),
            Some(Reversibility::Irreversible),
            "reason",
        )
        .unwrap();
    assert!(result.is_none());
    assert_eq!(store.observation_count(), 0);
}

#[test]
fn missing_reversibility_is_never_recorded() {
    // Gate mode off: no classification at all. This module must stay
    // completely inert rather than guessing.
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 1)).unwrap();
    let result = store
        .record_approval(
            "kubectl",
            &args(&["get", "pods"]),
            "kubectl get pods",
            Some(1),
            None,
            "reason",
        )
        .unwrap();
    assert!(result.is_none());
}

#[test]
fn risk_at_or_above_ceiling_is_not_recorded() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 1)).unwrap();
    // Reversible ceiling is EXECUTE_NOW_MAX_RISK (4).
    let result = store
        .record_approval(
            "kubectl",
            &args(&["get", "pods"]),
            "kubectl get pods",
            Some(4),
            Some(Reversibility::Reversible),
            "reason",
        )
        .unwrap();
    assert!(result.is_none());
}

#[test]
fn mixed_classification_permanently_disqualifies_the_bucket() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 2)).unwrap();
    let a = args(&["scale", "deployment", "web", "--replicas", "3"]);
    store
        .record_approval(
            "kubectl",
            &a,
            "kubectl scale deployment web --replicas 3",
            Some(1),
            Some(Reversibility::Reversible),
            "reason",
        )
        .unwrap();
    let second = store
        .record_approval(
            "kubectl",
            &a,
            "kubectl scale deployment web --replicas 3",
            Some(1),
            Some(Reversibility::Recoverable),
            "reason",
        )
        .unwrap()
        .unwrap();
    assert!(!second.ready_to_synthesize);
    // Even after crossing the threshold on a later, consistent vote, a
    // permanently mixed bucket must never become eligible.
    let third = store
        .record_approval(
            "kubectl",
            &a,
            "kubectl scale deployment web --replicas 3",
            Some(1),
            Some(Reversibility::Recoverable),
            "reason",
        )
        .unwrap()
        .unwrap();
    assert!(!third.ready_to_synthesize);
}

#[test]
fn dangerous_command_is_never_recorded() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 1)).unwrap();
    let result = store
        .record_approval(
            "sh",
            &args(&["-c", "rm -rf /"]),
            "sh -c rm -rf /",
            Some(1),
            Some(Reversibility::Reversible),
            "reason",
        )
        .unwrap();
    assert!(result.is_none());
}

#[test]
fn derive_template_finds_varying_and_constant_positions() {
    let samples = vec![
        args(&["get", "pods", "-n", "foo"]),
        args(&["get", "pods", "-n", "bar"]),
    ];
    let slots = derive_template(&samples).unwrap();
    assert_eq!(slots[0], TemplateSlot::Literal("get".to_string()));
    assert_eq!(slots[1], TemplateSlot::Literal("pods".to_string()));
    assert_eq!(slots[2], TemplateSlot::Literal("-n".to_string()));
    assert!(matches!(&slots[3], TemplateSlot::Param(v) if v.len() == 2));
    assert!(!is_fully_literal(&slots));
}

#[test]
fn derive_template_all_constant_is_fully_literal() {
    let samples = vec![args(&["get", "pods"]), args(&["get", "pods"])];
    let slots = derive_template(&samples).unwrap();
    assert!(is_fully_literal(&slots));
}

#[test]
fn build_args_and_params_pins_exact_observed_values() {
    let samples = vec![
        args(&["get", "pods", "-n", "foo"]),
        args(&["get", "pods", "-n", "bar"]),
    ];
    let slots = derive_template(&samples).unwrap();
    let (built_args, params) = build_args_and_params(&slots);
    assert_eq!(built_args[0], "get");
    assert_eq!(built_args[1], "pods");
    assert_eq!(built_args[2], "-n");
    assert_eq!(built_args[3], "{n}");
    let spec = params.get("n").unwrap();
    assert!(spec.pattern == "^(bar|foo)$" || spec.pattern == "^(foo|bar)$");
    // A value outside the observed set must not match.
    let re = regex::Regex::new(&spec.pattern).unwrap();
    assert!(!re.is_match("kube-system"));
    assert!(re.is_match("foo"));
    assert!(re.is_match("bar"));
}

#[test]
fn build_args_and_params_preserves_spaced_promql_values_as_bounded_single_argv() {
    let api_query = r#"sum(rate(http_requests_total{job="api"}[5m])) by (job)"#;
    let worker_query = r#"sum(rate(http_requests_total{job="worker"}[5m])) by (job)"#;
    let samples = vec![
        args(&["get", "pods", "--query", api_query]),
        args(&["get", "pods", "--query", worker_query]),
    ];
    let slots = derive_template(&samples).unwrap();
    let (built_args, params) = build_args_and_params(&slots);

    assert_eq!(built_args, args(&["get", "pods", "--query", "{query}"]));
    let spec = params.get("query").unwrap();
    assert_eq!(
        spec.value_type(),
        crate::gating::verb::ParamValueType::SingleArgv
    );
    assert_eq!(
        spec.max_length(),
        Some(api_query.chars().count().max(worker_query.chars().count()))
    );
    let re = regex::Regex::new(spec.pattern_text()).unwrap();
    assert!(re.is_match(api_query));
    assert!(re.is_match(worker_query));
    assert!(!re.is_match(r#"sum(rate(http_requests_total[5m])) by (job)"#));
}

#[test]
fn cwd_dependent_opaque_carriers_are_excluded_from_automatic_promotion() {
    assert!(is_cwd_dependent_opaque_carrier("ansible-playbook"));
    assert!(is_cwd_dependent_opaque_carrier("terraform"));
    assert!(is_cwd_dependent_opaque_carrier("helm.exe"));
    assert!(is_cwd_dependent_opaque_carrier("Ansible.ExE"));
    assert!(!is_cwd_dependent_opaque_carrier("kubectl"));
}

#[test]
fn build_args_and_params_escapes_regex_metacharacters_in_values() {
    let samples = vec![
        args(&["get", "pods", "-n", "a.b"]),
        args(&["get", "pods", "-n", "a+b"]),
    ];
    let slots = derive_template(&samples).unwrap();
    let (_, params) = build_args_and_params(&slots);
    let spec = params.get("n").unwrap();
    let re = regex::Regex::new(&spec.pattern).unwrap();
    assert!(re.is_match("a.b"));
    assert!(re.is_match("a+b"));
    // Unescaped `.` or `+` would otherwise admit unrelated values.
    assert!(!re.is_match("aXb"));
    assert!(!re.is_match("aaab"));
}

#[test]
fn deterministic_name_is_kebab_case() {
    let name = deterministic_verb_name("kubectl", "get", 4);
    assert!(is_kebab_name(&name), "{name} must be kebab-case");
}

#[test]
fn choose_verb_name_prefers_valid_model_proposal() {
    let chosen = choose_verb_name(Some("k-get-pods"), "kubectl", "get", 4);
    assert_eq!(chosen, "k-get-pods");
    let fallback = choose_verb_name(Some("Not Kebab"), "kubectl", "get", 4);
    assert!(is_kebab_name(&fallback));
    let none = choose_verb_name(None, "kubectl", "get", 4);
    assert!(is_kebab_name(&none));
}

#[test]
fn param_name_falls_back_to_positional_with_no_preceding_flag() {
    // The varying position is first in the argv (index 0), so there is
    // no preceding literal token at all to derive a name from.
    let slots = vec![TemplateSlot::Param(
        ["foo".to_string(), "bar".to_string()].into_iter().collect(),
    )];
    assert_eq!(param_name(&slots, 0, 1), "arg1");

    // A preceding literal that isn't flag-shaped (no leading dash) also
    // falls back positionally.
    let slots = vec![
        TemplateSlot::Literal("get".to_string()),
        TemplateSlot::Param(["a".to_string(), "b".to_string()].into_iter().collect()),
    ];
    assert_eq!(param_name(&slots, 1, 1), "arg1");
}

#[test]
fn build_args_and_params_disambiguates_colliding_names() {
    // Two independent varying positions both preceded by the same
    // repeated flag (e.g. `rsync --exclude A --exclude B`) must not
    // collapse into one shared parameter -- each needs its own name so
    // both can vary independently.
    let samples = vec![
        args(&["--exclude", "A", "--exclude", "C"]),
        args(&["--exclude", "B", "--exclude", "D"]),
    ];
    let slots = derive_template(&samples).unwrap();
    let (built_args, params) = build_args_and_params(&slots);
    assert_eq!(built_args.len(), 4);
    assert_ne!(
        built_args[1], built_args[3],
        "the two varying positions must get distinct placeholders"
    );
    assert_eq!(params.len(), 2, "each varying position needs its own param");
    // Each param independently enumerates only its own column's values.
    let pattern1 = &params[built_args[1].trim_matches(['{', '}'])].pattern;
    let pattern2 = &params[built_args[3].trim_matches(['{', '}'])].pattern;
    let re1 = regex::Regex::new(pattern1).unwrap();
    let re2 = regex::Regex::new(pattern2).unwrap();
    assert!(re1.is_match("A") && re1.is_match("B"));
    assert!(re2.is_match("C") && re2.is_match("D"));
}

#[test]
fn degenerate_min_approvals_does_not_fire_on_the_first_approval() {
    // AllowPromotionConfig's fields are public and constructible
    // directly; record_approval must clamp to >= 2 itself rather than
    // trusting every call site already did (defense in depth alongside
    // main.rs's own `.max(2)` at the CLI layer). "Repeated" approvals is
    // this module's entire premise, so 0 or 1 must not degenerate into
    // treating a single approval as sufficient.
    for degenerate in [0u32, 1] {
        let temp = crate::learned_rules::authority_tempdir();
        let mut degenerate_config = config(temp.path().join("allow.yaml"), 1);
        degenerate_config.min_approvals = degenerate;
        let mut store = AllowPromotionStore::load(degenerate_config).unwrap();
        let outcome = store
            .record_approval(
                "kubectl",
                &args(&["get", "pods"]),
                "kubectl get pods",
                Some(1),
                Some(Reversibility::Reversible),
                "ok",
            )
            .unwrap()
            .unwrap();
        assert!(
            !outcome.ready_to_synthesize,
            "a single approval must not be treated as sufficient just because \
                 min_approvals was {degenerate}"
        );
    }
}

#[test]
fn resolved_bucket_never_becomes_ready_again() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 2)).unwrap();
    let a = args(&["get", "pods"]);
    store
        .record_approval(
            "kubectl",
            &a,
            "kubectl get pods",
            Some(1),
            Some(Reversibility::Reversible),
            "ok",
        )
        .unwrap();
    let second = store
        .record_approval(
            "kubectl",
            &a,
            "kubectl get pods",
            Some(1),
            Some(Reversibility::Reversible),
            "ok",
        )
        .unwrap()
        .unwrap();
    assert!(second.ready_to_synthesize);

    // Simulate a definitive verdict (promoted, or permanently failed).
    store.mark_resolved("kubectl", "kubectl", "get", 2).unwrap();

    // Even as approvals keep climbing past further min_approvals
    // multiples, a resolved bucket must never fire again.
    for _ in 0..10 {
        let outcome = store
            .record_approval(
                "kubectl",
                &a,
                "kubectl get pods",
                Some(1),
                Some(Reversibility::Reversible),
                "ok",
            )
            .unwrap()
            .unwrap();
        assert!(
            !outcome.ready_to_synthesize,
            "a resolved bucket must never re-fire, got approvals={}",
            outcome.approvals
        );
    }
}

#[test]
fn mark_resolved_on_missing_bucket_is_a_harmless_noop() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 2)).unwrap();
    // No observation was ever recorded for this key; this must not error.
    store
        .mark_resolved("nonexistent", "nope", "nope", 0)
        .unwrap();
}

#[test]
fn observation_buckets_are_capped_by_evicting_the_oldest() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = AllowPromotionStore::load(config(temp.path().join("allow.yaml"), 2)).unwrap();

    for i in 0..MAX_OBSERVATION_BUCKETS {
        store.data.observations.insert(
            format!("service-{i}|bin-{i}|get|1"),
            AllowObservation {
                service: format!("service-{i}"),
                binary: format!("bin-{i}"),
                subcommand: "get".to_string(),
                arity: 1,
                approvals: 1,
                samples: Vec::new(),
                class_seen: Some(Reversibility::Reversible),
                mixed_class: false,
                resolved: false,
                max_risk_seen: 1,
                first_seen_unix: i as u64,
                last_seen_unix: i as u64,
                last_command: String::new(),
                last_reason: String::new(),
                last_attempt_at_approvals: 0,
            },
        );
    }
    assert_eq!(store.observation_count(), MAX_OBSERVATION_BUCKETS);

    store
        .record_approval(
            "brand-new-bin",
            &args(&["x"]),
            "brand-new-bin x",
            Some(1),
            Some(Reversibility::Reversible),
            "new",
        )
        .unwrap();
    assert_eq!(store.observation_count(), MAX_OBSERVATION_BUCKETS);
    assert!(!store
        .data
        .observations
        .contains_key("service-0|bin-0|get|1"));
}

#[test]
fn stale_allow_instances_reapply_commutative_observations() {
    let temp = crate::learned_rules::authority_tempdir();
    let config = config(temp.path().join("allow.yaml"), 2);
    let mut first = AllowPromotionStore::load(config.clone()).unwrap();
    let mut second = AllowPromotionStore::load(config.clone()).unwrap();
    let argv = args(&["status"]);

    first
        .record_approval(
            "fixturectl",
            &argv,
            "fixturectl status",
            Some(1),
            Some(Reversibility::Reversible),
            "safe",
        )
        .unwrap();
    let outcome = second
        .record_approval(
            "fixturectl",
            &argv,
            "fixturectl status",
            Some(1),
            Some(Reversibility::Reversible),
            "safe",
        )
        .unwrap()
        .unwrap();
    assert_eq!(outcome.approvals, 2);

    let loaded = AllowPromotionStore::load(config).unwrap();
    assert_eq!(
        loaded.data.observations.values().next().unwrap().approvals,
        2
    );
}
