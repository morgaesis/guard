use super::*;
use crate::proxy::RevertConstructible;

fn config(path: PathBuf, min_approvals: u32, min_denials: u32) -> ApiPromotionConfig {
    ApiPromotionConfig {
        path,
        enabled: true,
        min_approvals,
        min_denials,
        generated_ttl_secs: DEFAULT_GENERATED_TTL_SECS,
    }
}

#[test]
fn delayed_refresh_cannot_restore_coverage_after_a_completed_clear() {
    let temp = crate::learned_rules::authority_tempdir();
    let config = config(temp.path().join("api.yaml"), 2, 2);
    let request = summary("get");
    let mut baseline = ApiPromotionStore::load(config).unwrap();
    baseline
        .record_allow(
            &request,
            Some(1),
            Some(Reversibility::Reversible),
            "safe",
            "regime",
        )
        .unwrap();
    baseline
        .record_allow(
            &request,
            Some(1),
            Some(Reversibility::Reversible),
            "safe",
            "regime",
        )
        .unwrap();
    let delayed_refresh = baseline.clone();
    let refresh_baseline = baseline.clone();
    assert!(baseline.has_generated_coverage());
    assert_eq!(baseline.clear_generated().unwrap(), 1);

    assert!(baseline
        .adopt_async_result(&refresh_baseline, delayed_refresh)
        .is_err());
    assert!(!baseline.has_generated_coverage());
    assert!(baseline.learned_allow(&request, "regime").is_none());
}

fn summary(name: &str) -> ApiRequestSummary {
    ApiRequestSummary {
        protocol: "kubernetes".to_string(),
        verb: "get".to_string(),
        path: format!("/apis/apps/v1/namespaces/dev/deployments/{name}"),
        redacted_query: String::new(),
        group: "apps".to_string(),
        version: "v1".to_string(),
        resource: "deployments".to_string(),
        subresource: None,
        namespace: Some("dev".to_string()),
        name: Some(name.to_string()),
        dry_run: false,
        authority_selectors: BTreeMap::new(),
        coverage_body_shape: "{\"spec\":{\"replicas\":<number>}}".to_string(),
        redacted_body_shape: "{\"spec\":{\"replicas\":<number>}}".to_string(),
        authorized_body_sha256: "digest".to_string(),
        revert_constructible: RevertConstructible::RestorePriorState,
        rarity: false,
        endpoint: "default".to_string(),
        session_fingerprint: None,
        session_revision: None,
        session_intent: None,
        credential_ref: "upstream".to_string(),
    }
}

#[test]
fn approvals_promote_at_threshold_with_max_risk_and_class() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 3)).unwrap();
    let s = summary("api");

    assert!(store
        .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "")
        .unwrap()
        .is_none());
    let outcome = store
        .record_allow(&s, Some(3), Some(Reversibility::Reversible), "ok", "")
        .unwrap()
        .unwrap();

    match outcome {
        ApiPromotionOutcome::AllowPromoted {
            approvals,
            risk,
            reversibility,
            ..
        } => {
            assert_eq!(approvals, 2);
            assert_eq!(risk, 3);
            assert_eq!(reversibility, Reversibility::Reversible);
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
    let learned = store.learned_allow(&s, "").unwrap();
    assert_eq!(learned.risk, 3);
    assert_eq!(learned.reversibility, Reversibility::Reversible);
}

#[test]
fn failed_durable_write_does_not_commit_api_learning_state() {
    let temp = crate::learned_rules::authority_tempdir();
    let path = temp.path().join("api.yaml");
    let mut store = ApiPromotionStore::load(config(path.clone(), 3, 2)).unwrap();
    let request = summary("api");
    store.record_deny(&request, "no", "regime").unwrap();
    let before_memory = store.data.clone();
    let before_file = std::fs::read(&path).unwrap();

    store.fail_writes_for_test();
    assert!(store.record_deny(&request, "no", "regime").is_err());
    assert_eq!(store.data, before_memory);
    assert_eq!(std::fs::read(path).unwrap(), before_file);
    assert!(store.learned_deny(&request, "regime").is_none());
}

#[test]
fn corrupt_api_coverage_fails_closed_and_deduplicates_verified_copies() {
    let temp = crate::learned_rules::authority_tempdir();
    let path = temp.path().join("api.yaml");
    let config = config(path.clone(), 3, 1);
    let request = summary("api");
    let mut store = ApiPromotionStore::load(config.clone()).unwrap();
    store.record_deny(&request, "no", "regime").unwrap();
    let mut corrupt = std::fs::read(&path).unwrap();
    corrupt.push(0xff);
    crate::learned_rules::write_authority_file(&path, &corrupt).unwrap();

    assert!(ApiPromotionStore::load(config.clone()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    assert!(ApiPromotionStore::load(config).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    let copies = std::fs::read_dir(temp.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".api.yaml.corrupt-")
        })
        .collect::<Vec<_>>();
    assert_eq!(copies.len(), 1);
    assert!(copies
        .iter()
        .all(|entry| std::fs::read(entry.path()).unwrap() == corrupt));
}

#[test]
fn current_api_coverage_rejects_newer_schema_unknown_fields_and_key_mismatch() {
    let temp = crate::learned_rules::authority_tempdir();
    let path = temp.path().join("api.yaml");
    let cfg = config(path.clone(), 2, 1);
    let request = summary("api");
    let mut store = ApiPromotionStore::load(cfg.clone()).unwrap();
    store.record_deny(&request, "no", "regime").unwrap();
    let original = std::fs::read(&path).unwrap();

    let mut newer = store.data.clone();
    newer.version = default_version() + 1;
    crate::learned_rules::write_authority_file(&path, serde_yaml_ng::to_string(&newer).unwrap())
        .unwrap();
    assert!(ApiPromotionStore::load(cfg.clone()).is_err());

    let mut unknown = String::from_utf8(original.clone()).unwrap();
    unknown.push_str("unknown_authority_field: true\n");
    crate::learned_rules::write_authority_file(&path, unknown).unwrap();
    assert!(ApiPromotionStore::load(cfg.clone()).is_err());

    let mut missing_version: serde_yaml_ng::Value = serde_yaml_ng::from_slice(&original).unwrap();
    missing_version
        .as_mapping_mut()
        .unwrap()
        .remove(serde_yaml_ng::Value::String("version".to_string()));
    crate::learned_rules::write_authority_file(
        &path,
        serde_yaml_ng::to_string(&missing_version).unwrap(),
    )
    .unwrap();
    assert!(ApiPromotionStore::load(cfg.clone()).is_err());

    let mut mismatched = store.data.clone();
    let (key, bucket) = mismatched.buckets.pop_first().unwrap();
    mismatched.buckets.insert(format!("{key}-changed"), bucket);
    crate::learned_rules::write_authority_file(
        &path,
        serde_yaml_ng::to_string(&mismatched).unwrap(),
    )
    .unwrap();
    assert!(ApiPromotionStore::load(cfg).is_err());
}

#[test]
fn legacy_api_key_collision_fails_closed_without_rewriting_authority() {
    let temp = crate::learned_rules::authority_tempdir();
    let path = temp.path().join("api.yaml");
    let cfg = config(path.clone(), 2, 1);
    let request = summary("api");
    let mut store = ApiPromotionStore::load(cfg.clone()).unwrap();
    store.record_deny(&request, "no", "regime").unwrap();
    let bucket = store.data.buckets.values().next().unwrap().clone();
    let mut legacy = ApiPromotionFile {
        version: default_version() - 1,
        buckets: BTreeMap::new(),
    };
    legacy
        .buckets
        .insert("legacy-one".to_string(), bucket.clone());
    legacy.buckets.insert("legacy-two".to_string(), bucket);
    let bytes = serde_yaml_ng::to_string(&legacy).unwrap();
    crate::learned_rules::write_authority_file(&path, &bytes).unwrap();

    assert!(ApiPromotionStore::load(cfg).is_err());
    assert_eq!(std::fs::read_to_string(path).unwrap(), bytes);
}

#[test]
fn sensitive_api_authority_is_rejected_without_changing_safe_state() {
    let value = ["q", "7"].concat();
    let temp = crate::learned_rules::authority_tempdir();
    let path = temp.path().join("api.yaml");
    let config = config(path.clone(), 2, 2);
    let mut store = ApiPromotionStore::load(config.clone()).unwrap();
    let safe = summary("safe");
    store.record_deny(&safe, "no", "regime").unwrap();
    let before_memory = store.data.clone();
    let before_file = std::fs::read(&path).unwrap();
    let mut sensitive = summary("sensitive");
    sensitive
        .authority_selectors
        .insert("password".to_string(), value.clone());

    assert!(store.record_deny(&sensitive, "no", "regime").is_err());
    assert_eq!(store.data, before_memory);
    assert_eq!(std::fs::read(&path).unwrap(), before_file);
    assert!(store
        .record_deny(&safe, "no", &format!("password={value}"))
        .is_err());
    assert_eq!(store.data, before_memory);
    assert_eq!(std::fs::read(&path).unwrap(), before_file);

    let mut contaminated = before_memory;
    let mut bucket = contaminated.buckets.values().next().unwrap().clone();
    bucket
        .authority_selectors
        .insert("password".to_string(), value.clone());
    contaminated
        .buckets
        .insert("contaminated".to_string(), bucket);
    let bytes = serde_yaml_ng::to_string(&contaminated).unwrap();
    crate::learned_rules::write_authority_file(&path, &bytes).unwrap();
    assert!(ApiPromotionStore::load(config).is_err());
    assert_eq!(std::fs::read_to_string(path).unwrap(), bytes);
}

#[test]
fn api_reason_fields_are_sanitized_on_mutation_and_reload() {
    let value = ["q", "7"].concat();
    let temp = crate::learned_rules::authority_tempdir();
    let path = temp.path().join("api.yaml");
    let config = config(path.clone(), 2, 1);
    let mut store = ApiPromotionStore::load(config.clone()).unwrap();
    let request = summary("api");
    store
        .record_deny(&request, &format!("password={value}"), "fixture")
        .unwrap();
    assert!(!std::fs::read_to_string(&path).unwrap().contains(&value));

    let bucket = store.data.buckets.values_mut().next().unwrap();
    bucket.last_reason = format!("password={value}");
    store.save_data(&store.data).unwrap();
    let reloaded = ApiPromotionStore::load(config).unwrap();
    let hit = reloaded.learned_deny(&request, "fixture").unwrap();
    assert!(!hit.reason.contains(&value));
    assert!(!std::fs::read_to_string(path).unwrap().contains(&value));
}

#[test]
fn value_bearing_mutations_never_promote_without_field_constraints() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 3)).unwrap();
    let mut write = summary("api");
    write.verb = "patch".to_string();

    for _ in 0..4 {
        assert!(store
            .record_allow(
                &write,
                Some(1),
                Some(Reversibility::Reversible),
                "ok",
                "regime-A",
            )
            .unwrap()
            .is_none());
    }
    assert_eq!(store.bucket_count(), 0);
    assert!(store.learned_allow(&write, "regime-A").is_none());
}

#[test]
fn evaluator_evidence_never_mutates_operator_coverage() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();
    let request = summary("api");
    let shape = ApiShape::from_summary(&request);
    store
        .record_deny(&request, "operator decision seed", "regime-A")
        .unwrap();
    let bucket = store.data.buckets.get_mut(&shape.key()).unwrap();
    bucket.provenance = ApiCoverageProvenance::Operator;
    bucket.last_reason = "operator deny".to_string();
    bucket.learned_deny = true;
    let before = serde_yaml_ng::to_string(bucket).unwrap();

    store
        .record_allow(
            &request,
            Some(1),
            Some(Reversibility::Reversible),
            "evaluator allow",
            "regime-B",
        )
        .unwrap();
    store
        .record_deny(&request, "evaluator deny", "regime-B")
        .unwrap();

    let after = serde_yaml_ng::to_string(store.data.buckets.get(&shape.key()).unwrap()).unwrap();
    assert_eq!(after, before);
    assert_eq!(
        store
            .learned_deny(&request, "unrelated-regime")
            .unwrap()
            .provenance,
        ApiCoverageProvenance::Operator
    );
}

#[test]
fn mixed_classes_disqualify_allow_promotion() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 3)).unwrap();
    let s = summary("api");

    store
        .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "")
        .unwrap();
    let second = store
        .record_allow(&s, Some(1), Some(Reversibility::Recoverable), "ok", "")
        .unwrap();

    assert!(second.is_none());
    assert!(store.learned_allow(&s, "").is_none());
}

#[test]
fn full_session_revision_partitions_coverage_and_unchanged_revision_hits() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();
    let mut first = summary("api");
    first.session_fingerprint = Some("session".to_string());
    first.session_revision = Some("revision-one".to_string());
    for _ in 0..2 {
        store
            .record_allow(
                &first,
                Some(1),
                Some(Reversibility::Reversible),
                "ok",
                "regime-one",
            )
            .unwrap();
    }
    assert!(store.learned_allow(&first, "regime-one").is_some());
    assert!(store.learned_allow(&first.clone(), "regime-one").is_some());

    let mut edited = first.clone();
    edited.session_revision = Some("revision-two".to_string());
    assert!(store.learned_allow(&edited, "regime-one").is_none());
    assert_ne!(
        ApiShape::from_summary(&first).key(),
        ApiShape::from_summary(&edited).key()
    );
}

#[test]
fn authority_selectors_partition_typed_coverage() {
    let mut first = summary("api");
    first
        .authority_selectors
        .insert("teamId".to_string(), "team-a".to_string());
    let mut second = first.clone();
    second
        .authority_selectors
        .insert("teamId".to_string(), "team-b".to_string());
    assert_ne!(
        ApiShape::from_summary(&first).key(),
        ApiShape::from_summary(&second).key()
    );
}

#[test]
fn risk_ceiling_blocks_allow_promotion_evidence() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 3)).unwrap();
    let s = summary("api");

    let result = store
        .record_allow(
            &s,
            Some(EXECUTE_NOW_MAX_RISK),
            Some(Reversibility::Reversible),
            "too risky",
            "",
        )
        .unwrap();

    // An over-ceiling allow does not promote, and it disqualifies the shape
    // (recorded, not dropped) so a later low-risk subset cannot promote it.
    assert!(result.is_none());
    assert_eq!(store.bucket_count(), 1);
    assert!(store.learned_allow(&s, "").is_none());
}

#[test]
fn denials_learn_fast_deny_at_threshold() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = ApiPromotionStore::load(config(temp.path().join("api.yaml"), 5, 2)).unwrap();
    let s = summary("api");

    assert!(store.record_deny(&s, "no", "").unwrap().is_none());
    let outcome = store.record_deny(&s, "no", "").unwrap().unwrap();

    match outcome {
        ApiPromotionOutcome::DenyLearned { denials, .. } => assert_eq!(denials, 2),
        other => panic!("unexpected outcome: {other:?}"),
    }
    assert_eq!(store.learned_deny(&s, "").unwrap().denials, 2);
}

#[test]
fn observation_buckets_are_lru_capped() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();

    let mut seeded_keys = Vec::new();
    for i in 0..MAX_BUCKETS {
        let bucket = ApiShapeBucket {
            endpoint: String::new(),
            session_fingerprint: None,
            session_revision: None,
            protocol: format!("p{i}"),
            verb: "get".to_string(),
            group: String::new(),
            version: "v1".to_string(),
            resource: "pods".to_string(),
            subresource: None,
            namespace: Some(format!("ns{i}")),
            authority_selectors: BTreeMap::new(),
            body_shape: "{}".to_string(),
            approvals: 1,
            denials: 0,
            evidence: Vec::new(),
            class_seen: Some(Reversibility::Reversible),
            mixed_class: false,
            disqualified: false,
            promoted_allow: false,
            learned_deny: false,
            stamp: String::new(),
            provenance: ApiCoverageProvenance::Evaluator,
            expires_at_unix: None,
            max_risk_seen: 1,
            first_seen_unix: i as u64,
            last_seen_unix: i as u64,
            last_reason: String::new(),
        };
        let key = shape_from_bucket(&bucket).key();
        seeded_keys.push(key.clone());
        store.data.buckets.insert(key, bucket);
    }
    store
        .data
        .buckets
        .get_mut(&seeded_keys[0])
        .unwrap()
        .provenance = ApiCoverageProvenance::Operator;
    assert_eq!(store.bucket_count(), MAX_BUCKETS);

    store
        .record_deny(&summary("brand-new"), "no", "")
        .expect("record deny");

    assert_eq!(store.bucket_count(), MAX_BUCKETS);
    assert!(store.data.buckets.contains_key(&seeded_keys[0]));
    assert!(!store.data.buckets.contains_key(&seeded_keys[1]));
}

#[test]
fn yaml_round_trip_preserves_promoted_shape() {
    let temp = crate::learned_rules::authority_tempdir();
    let path = temp.path().join("api.yaml");
    let s = summary("api");
    {
        let mut store = ApiPromotionStore::load(config(path.clone(), 2, 2)).unwrap();
        store
            .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "")
            .unwrap();
        store
            .record_allow(&s, Some(2), Some(Reversibility::Reversible), "ok", "")
            .unwrap();
    }

    let store = ApiPromotionStore::load(config(path, 2, 2)).unwrap();
    assert!(store.learned_allow(&s, "").is_some());
}

#[test]
fn object_name_is_excluded_from_keying() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 3)).unwrap();

    store
        .record_allow(
            &summary("api-a"),
            Some(1),
            Some(Reversibility::Reversible),
            "ok",
            "",
        )
        .unwrap();
    store
        .record_allow(
            &summary("api-b"),
            Some(1),
            Some(Reversibility::Reversible),
            "ok",
            "",
        )
        .unwrap();

    assert_eq!(store.bucket_count(), 1);
    assert!(store.learned_allow(&summary("api-c"), "").is_some());
}

#[test]
fn dry_run_requests_never_feed_promotion() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();
    let mut s = summary("api");
    s.dry_run = true;

    for _ in 0..5 {
        assert!(store
            .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "")
            .unwrap()
            .is_none());
    }
    // A real request of the same shape must still be judged fresh.
    let mut real = summary("api");
    real.dry_run = false;
    assert!(store.learned_allow(&real, "").is_none());
    assert_eq!(store.bucket_count(), 0);
}

#[test]
fn a_different_body_shape_is_a_different_bucket() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();
    let base = summary("api");
    store
        .record_allow(&base, Some(1), Some(Reversibility::Reversible), "ok", "")
        .unwrap();
    store
        .record_allow(&base, Some(1), Some(Reversibility::Reversible), "ok", "")
        .unwrap();
    assert!(store.learned_allow(&base, "").is_some());

    // Same verb/resource/namespace, different body structure: not covered.
    let mut other = summary("api");
    other.coverage_body_shape = "{\"spec\":{\"image\":<string>}}".to_string();
    other.redacted_body_shape = "{\"spec\":{\"image\":<string>}}".to_string();
    assert!(store.learned_allow(&other, "").is_none());
}

#[test]
fn guard_preconditions_do_not_change_the_stable_coverage_bucket() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();
    let base = summary("api");
    for _ in 0..2 {
        store
            .record_allow(&base, Some(1), Some(Reversibility::Reversible), "ok", "")
            .unwrap();
    }
    let mut guarded = base.clone();
    guarded.redacted_body_shape =
        "{\"metadata\":{\"resourceVersion\":<string>},\"spec\":{\"replicas\":<number>}}"
            .to_string();
    guarded.authorized_body_sha256 = "different-final-digest".to_string();
    assert!(store.learned_allow(&guarded, "").is_some());
}

#[test]
fn an_ineligible_allow_disqualifies_the_shape() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();
    let s = summary("api");
    // One low-risk allow, then a high-risk allow of the same shape.
    store
        .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "")
        .unwrap();
    store
        .record_allow(&s, Some(99), Some(Reversibility::Reversible), "risky", "")
        .unwrap();
    // Further low-risk allows must not resurrect promotion.
    store
        .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "")
        .unwrap();
    store
        .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "")
        .unwrap();
    assert!(
        store.learned_allow(&s, "").is_none(),
        "a shape with any ineligible observation must never fast-path allow"
    );
}

#[test]
fn a_stamp_change_invalidates_prior_learning() {
    let temp = crate::learned_rules::authority_tempdir();
    let path = temp.path().join("api.yaml");
    let s = summary("api");
    {
        let mut store = ApiPromotionStore::load(config(path.clone(), 2, 2)).unwrap();
        store
            .record_allow(
                &s,
                Some(1),
                Some(Reversibility::Reversible),
                "ok",
                "regime-A",
            )
            .unwrap();
        store
            .record_allow(
                &s,
                Some(1),
                Some(Reversibility::Reversible),
                "ok",
                "regime-A",
            )
            .unwrap();
        assert!(store.learned_allow(&s, "regime-A").is_some());
    }
    // Reload and consult under a narrowed intent (new stamp): the old
    // promotion is not trusted, and a fresh allow starts the count over.
    let mut store = ApiPromotionStore::load(config(path, 2, 2)).unwrap();
    assert!(store.learned_allow(&s, "regime-B").is_none());
    assert!(store
        .record_allow(
            &s,
            Some(1),
            Some(Reversibility::Reversible),
            "ok",
            "regime-B"
        )
        .unwrap()
        .is_none());
    assert!(store.learned_allow(&s, "regime-B").is_none());
}

#[test]
fn old_generated_coverage_migrates_to_bounded_expiry() {
    let temp = crate::learned_rules::authority_tempdir();
    let path = temp.path().join("api.yaml");
    crate::learned_rules::write_authority_file(
        &path,
        r#"version: 1
buckets:
  old:
    protocol: kubernetes
    verb: get
    group: ''
    version: v1
    resource: pods
    approvals: 5
    denials: 0
    promoted_allow: true
    stamp: old-regime
    max_risk_seen: 1
    first_seen_unix: 1
    last_seen_unix: 1
    last_reason: ok
"#,
    )
    .unwrap();
    let store = ApiPromotionStore::load(config(path, 2, 2)).unwrap();
    let entries = store.coverage();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].provenance, ApiCoverageProvenance::Evaluator);
    assert!(entries[0].expires_at_unix.is_some());
    assert!(!entries[0].active, "ancient migrated coverage is stale");
}

#[test]
fn old_bucket_keys_migrate_to_the_default_endpoint() {
    let temp = crate::learned_rules::authority_tempdir();
    let path = temp.path().join("api.yaml");
    let now = now_unix();
    crate::learned_rules::write_authority_file(
        &path,
        format!(
            r#"version: 1
buckets:
  kubernetes|get|apps|v1|deployments||dev|body:
    protocol: kubernetes
    verb: get
    group: apps
    version: v1
    resource: deployments
    namespace: dev
    body_shape: '{{"spec":{{"replicas":<number>}}}}'
    approvals: 5
    denials: 0
    class_seen: reversible
    promoted_allow: true
    stamp: old-regime
    max_risk_seen: 1
    first_seen_unix: {now}
    last_seen_unix: {now}
    last_reason: ok
"#
        ),
    )
    .unwrap();
    let store = ApiPromotionStore::load(config(path, 2, 2)).unwrap();
    let s = summary("api");
    assert!(store.learned_allow(&s, "old-regime").is_some());
    let entries = store.coverage();
    assert_eq!(entries[0].endpoint, "default");
}

#[test]
fn any_deny_disqualifies_an_existing_generated_allow() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();
    let s = summary("api");
    for _ in 0..2 {
        store
            .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "regime")
            .unwrap();
    }
    assert!(store.learned_allow(&s, "regime").is_some());

    store
        .record_deny(&s, "unsafe value in this shape", "regime")
        .unwrap();
    assert!(store.learned_allow(&s, "regime").is_none());
    store
        .record_deny(&s, "unsafe value in this shape", "regime")
        .unwrap();
    assert!(store.learned_deny(&s, "regime").is_some());
    assert_eq!(store.coverage()[0].decision, "deny");
}

#[test]
fn generated_coverage_is_scoped_by_endpoint_and_session() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();
    let mut scoped = summary("api");
    scoped.endpoint = "cluster-a".to_string();
    scoped.session_fingerprint = Some("session-a".to_string());
    for _ in 0..2 {
        store
            .record_allow(
                &scoped,
                Some(1),
                Some(Reversibility::Reversible),
                "ok",
                "regime",
            )
            .unwrap();
    }
    assert!(store.learned_allow(&scoped, "regime").is_some());
    let mut other_session = scoped.clone();
    other_session.session_fingerprint = Some("session-b".to_string());
    assert!(store.learned_allow(&other_session, "regime").is_none());
    let mut other_endpoint = scoped.clone();
    other_endpoint.endpoint = "cluster-b".to_string();
    assert!(store.learned_allow(&other_endpoint, "regime").is_none());
    assert_eq!(store.clear_generated().unwrap(), 1);
    assert!(store.coverage().is_empty());
}

#[test]
fn expired_coverage_restarts_evidence_collection() {
    let temp = crate::learned_rules::authority_tempdir();
    let mut store = ApiPromotionStore::load(config(temp.path().join("api.yaml"), 2, 2)).unwrap();
    let s = summary("api");
    for _ in 0..2 {
        store
            .record_allow(&s, Some(1), Some(Reversibility::Reversible), "ok", "regime")
            .unwrap();
    }
    assert!(store.learned_allow(&s, "regime").is_some());
    let bucket = store
        .data
        .buckets
        .get_mut(&ApiShape::from_summary(&s).key())
        .unwrap();
    bucket.expires_at_unix = Some(now_unix());

    store
        .record_allow(
            &s,
            Some(1),
            Some(Reversibility::Reversible),
            "fresh",
            "regime",
        )
        .unwrap();
    assert!(
        store.learned_allow(&s, "regime").is_none(),
        "one observation must not reactivate expired generated coverage"
    );
}

#[test]
fn stale_api_instances_merge_observations_and_preserve_concurrent_denies() {
    let temp = crate::learned_rules::authority_tempdir();
    let config = config(temp.path().join("api.yaml"), 2, 1);
    let mut first = ApiPromotionStore::load(config.clone()).unwrap();
    let mut second = ApiPromotionStore::load(config.clone()).unwrap();
    let request = summary("api");

    first
        .record_allow(
            &request,
            Some(1),
            Some(Reversibility::Reversible),
            "safe",
            "regime",
        )
        .unwrap();
    second
        .record_allow(
            &request,
            Some(1),
            Some(Reversibility::Reversible),
            "safe",
            "regime",
        )
        .unwrap();
    assert!(second.learned_allow(&request, "regime").is_some());

    let mut deny_writer = ApiPromotionStore::load(config.clone()).unwrap();
    let mut stale_allow_writer = ApiPromotionStore::load(config.clone()).unwrap();
    deny_writer
        .record_deny(&request, "unsafe", "regime")
        .unwrap();
    stale_allow_writer
        .record_allow(
            &request,
            Some(1),
            Some(Reversibility::Reversible),
            "safe",
            "regime",
        )
        .unwrap();

    let loaded = ApiPromotionStore::load(config).unwrap();
    assert!(loaded.learned_allow(&request, "regime").is_none());
    assert!(loaded.learned_deny(&request, "regime").is_some());
}

#[test]
fn stale_api_fast_path_refreshes_a_concurrent_deny_before_allowing() {
    let temp = crate::learned_rules::authority_tempdir();
    let config = config(temp.path().join("api.yaml"), 2, 1);
    let request = summary("api");
    let mut stale = ApiPromotionStore::load(config.clone()).unwrap();
    for _ in 0..2 {
        stale
            .record_allow(
                &request,
                Some(1),
                Some(Reversibility::Reversible),
                "safe",
                "regime",
            )
            .unwrap();
    }
    assert!(stale.learned_allow(&request, "regime").is_some());

    let mut writer = ApiPromotionStore::load(config).unwrap();
    writer.record_deny(&request, "deny", "regime").unwrap();

    stale = stale.refreshed_copy().unwrap();
    assert!(stale.learned_allow(&request, "regime").is_none());
    assert!(stale.learned_deny(&request, "regime").is_some());
}

#[test]
fn stale_clear_commits_against_fresh_generated_coverage() {
    let temp = crate::learned_rules::authority_tempdir();
    let config = config(temp.path().join("api.yaml"), 1, 1);
    let request = summary("api");
    let mut stale = ApiPromotionStore::load(config.clone()).unwrap();
    let mut writer = ApiPromotionStore::load(config.clone()).unwrap();
    writer
        .record_allow(
            &request,
            Some(1),
            Some(Reversibility::Reversible),
            "safe",
            "regime",
        )
        .unwrap();
    assert!(writer.has_generated_coverage());

    assert_eq!(stale.clear_generated().unwrap(), 1);
    assert!(!stale.has_generated_coverage());
    let first_restart = ApiPromotionStore::load(config.clone()).unwrap();
    assert!(!first_restart.has_generated_coverage());
    let second_restart = ApiPromotionStore::load(config).unwrap();
    assert!(!second_restart.has_generated_coverage());
}
