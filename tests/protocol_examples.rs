//! End-to-end tests of the example protocol plug-ins (GitHub, Vercel) through
//! the shared proxy loop, against hit-recording mock upstreams.
//!
//! Each mock records every request that reaches it, so a denial can be
//! asserted as "the upstream was never contacted", not just as a 403. The
//! mocks deliberately overshare where it matters: the GitHub secrets mock
//! returns plaintext `value` fields the real API would never send, proving the
//! proxy redacts on its own classification rather than trusting the upstream
//! shape. Malformed requests that a normalizing HTTP client cannot express
//! (dot-segment traversal) are sent over a raw TLS connection.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::{self, pki_types};

use guard::proxy::{
    ApiPolicy, ApiProxy, GithubProtocol, ProtocolConfig, ProxyTls, Upstream, VercelProtocol,
};

/// Requests the mock upstream actually served: (method, path?query).
type Hits = Arc<Mutex<Vec<(String, String)>>>;

async fn spawn_recording_upstream(
    hits: Hits,
    body_for: fn(&str) -> Value,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            let hits = hits.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let hits = hits.clone();
                    async move {
                        let path_q = req
                            .uri()
                            .path_and_query()
                            .map(|pq| pq.to_string())
                            .unwrap_or_default();
                        hits.lock()
                            .unwrap()
                            .push((req.method().to_string(), path_q));
                        let body = body_for(req.uri().path());
                        Ok::<_, Infallible>(
                            Response::builder()
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body.to_string())))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    (format!("http://{addr}"), task)
}

struct TestProxy {
    client: reqwest::Client,
    base: String,
    port: u16,
    ca_pem: String,
    hits: Hits,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl TestProxy {
    fn hit_count(&self) -> usize {
        self.hits.lock().unwrap().len()
    }

    fn hits(&self) -> Vec<(String, String)> {
        self.hits.lock().unwrap().clone()
    }
}

impl Drop for TestProxy {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Stand up mock upstream + proxy for one protocol and policy; return a client
/// trusting the proxy's ephemeral CA.
async fn spawn_proxy(
    protocol: Arc<dyn ProtocolConfig>,
    body_for: fn(&str) -> Value,
    policy_yaml: &str,
) -> TestProxy {
    let hits: Hits = Arc::new(Mutex::new(Vec::new()));
    let (mock_base, upstream_task) = spawn_recording_upstream(hits.clone(), body_for).await;
    let kubeconfig = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n  - name: c\n    cluster: {{server: \"{mock_base}\"}}\ncontexts:\n  - name: ctx\n    context: {{cluster: c, user: u}}\nusers:\n  - name: u\n    user: {{}}\n"
    );
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(policy_yaml).expect("policy");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy test listener");
    let listen = listener.local_addr().expect("proxy test listener address");
    let port = listen.port();
    let proxy = Arc::new(ApiProxy::with_protocol(
        protocol, listen, tls, upstream, policy, None,
    ));
    let proxy_task = tokio::spawn(async move {
        proxy
            .serve_on(listener)
            .await
            .expect("serve proxy test listener");
    });
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    TestProxy {
        client,
        base: format!("https://127.0.0.1:{port}"),
        port,
        ca_pem,
        hits,
        tasks: vec![upstream_task, proxy_task],
    }
}

/// Send one raw HTTP/1.1 request over TLS and return the full response text.
/// Needed for paths a spec-conforming client would normalize away before
/// sending (`..` and `%2e` dot segments).
async fn raw_tls_request(proxy: &TestProxy, method: &str, raw_path: &str) -> String {
    let b64: String = proxy
        .ca_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let ca_der = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("CA PEM body decodes");
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(pki_types::CertificateDer::from(ca_der))
        .expect("add CA root");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", proxy.port))
        .await
        .expect("connect proxy");
    let sni = pki_types::ServerName::try_from("127.0.0.1")
        .expect("server name")
        .to_owned();
    let mut stream = connector.connect(sni, tcp).await.expect("tls handshake");
    let req =
        format!("{method} {raw_path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write request");
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    String::from_utf8_lossy(&buf).to_string()
}

// ---------------------------------------------------------------------------
// GitHub
// ---------------------------------------------------------------------------

fn github_body(path: &str) -> Value {
    if path.contains("/secrets") {
        if path.ends_with("/secrets") {
            // Hostile upstream: value fields the real API never returns.
            json!({
                "total_count": 2,
                "secrets": [
                    {"name": "DEPLOY_KEY", "created_at": "2026-01-01T00:00:00Z", "value": "leaked-plaintext"},
                    {"name": "API_TOKEN", "created_at": "2026-01-01T00:00:00Z", "encrypted_value": "leaked-cipher"}
                ]
            })
        } else {
            json!({"name": "DEPLOY_KEY", "created_at": "2026-01-01T00:00:00Z", "value": "leaked-plaintext"})
        }
    } else if path.contains("/issues") {
        json!({"number": 42, "title": "an issue", "state": "open"})
    } else {
        json!({"ok": true})
    }
}

const GITHUB_READS: &str = r#"
default: deny
rules:
  - verbs: [get, list]
    resources: ["*"]
    action: allow
"#;

const ALLOW_ALL: &str = "default: allow\nrules: []\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_allowed_read_forwards_and_writes_default_deny() {
    let p = spawn_proxy(Arc::new(GithubProtocol), github_body, GITHUB_READS).await;

    // An allowed read reaches the mock and returns its body.
    let resp = p
        .client
        .get(format!("{}/repos/octo/hello/issues/42", p.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["number"], 42);
    assert_eq!(
        p.hits(),
        vec![("GET".to_string(), "/repos/octo/hello/issues/42".to_string())]
    );

    // A modeled write falls to the policy default (deny) and never forwards.
    let resp = p
        .client
        .post(format!("{}/repos/octo/hello/issues", p.base))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // An unmodeled path's write is blocked as a non-resource write.
    let resp = p
        .client
        .post(format!("{}/gists", p.base))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(p.hit_count(), 1, "denied writes never reach the upstream");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_secret_reads_are_redacted_without_any_rule_flag() {
    // The read rule carries no redact flag: redaction is forced by the
    // protocol's classification, not by policy wording.
    let p = spawn_proxy(Arc::new(GithubProtocol), github_body, GITHUB_READS).await;

    let resp = p
        .client
        .get(format!("{}/repos/octo/hello/actions/secrets", p.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["total_count"], 2);
    assert_eq!(body["secrets"][0]["name"], "DEPLOY_KEY");
    assert!(body["secrets"][0].get("value").is_none(), "value stripped");
    assert!(
        body["secrets"][1].get("encrypted_value").is_none(),
        "encrypted_value stripped"
    );

    let resp = p
        .client
        .get(format!(
            "{}/repos/octo/hello/actions/secrets/DEPLOY_KEY",
            p.base
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let one: Value = resp.json().await.unwrap();
    assert_eq!(one["name"], "DEPLOY_KEY");
    assert!(one.get("value").is_none());

    // The upstream did serve the values; the proxy stripped them.
    assert_eq!(p.hit_count(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_credential_writes_and_archives_never_reach_upstream() {
    // Even an allow-everything policy cannot forward these: deny_outright
    // preempts policy entirely.
    let p = spawn_proxy(Arc::new(GithubProtocol), github_body, ALLOW_ALL).await;

    for (method, path) in [
        ("PUT", "/repos/octo/hello/actions/secrets/DEPLOY"),
        ("DELETE", "/orgs/acme/dependabot/secrets/TOKEN"),
        ("PUT", "/repos/octo/hello/codespaces/secrets/T"),
        // The same write disguised through a nested route.
        ("PUT", "/repos/octo/hello/environments/prod/secrets/T"),
        // Case variation on the store path.
        ("PUT", "/repos/octo/hello/ACTIONS/SECRETS/T"),
        // Bulk source exfiltration streams.
        ("GET", "/repos/octo/hello/tarball/main"),
        ("GET", "/repos/octo/hello/zipball/main"),
    ] {
        let resp = p
            .client
            .request(method.parse().unwrap(), format!("{}{}", p.base, path))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "{method} {path} must be denied");
    }
    assert_eq!(p.hit_count(), 0, "nothing reached the mock upstream");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_paths_that_alter_on_forward_are_rejected_before_upstream() {
    let p = spawn_proxy(Arc::new(GithubProtocol), github_body, ALLOW_ALL).await;

    // Dot-segment traversal, raw and percent-encoded: a conforming client
    // normalizes these before sending, so they arrive only from a client
    // deliberately writing its own request line.
    for path in [
        "/repos/octo/hello/../../user",
        "/repos/octo/hello/%2e%2e/%2e%2e/user",
        "/repos/octo/hello/%2E%2E/admin",
    ] {
        let resp = raw_tls_request(&p, "GET", path).await;
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "{path} must 403, got: {}",
            resp.lines().next().unwrap_or("")
        );
    }

    // Encoded separators survive client URL parsing, so they also arrive via
    // a normal client; the proxy rejects them the same way.
    for path in [
        "/repos/octo%2Fhello/issues",
        "/repos/octo%5Chello/issues",
        "/repos/octo/hello/issues/%00",
    ] {
        let resp = p
            .client
            .get(format!("{}{}", p.base, path))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "{path} must be rejected");
    }

    assert_eq!(p.hit_count(), 0, "no rejected path reached the upstream");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_query_strings_do_not_change_classification() {
    let p = spawn_proxy(Arc::new(GithubProtocol), github_body, GITHUB_READS).await;

    // Kubernetes-style watch flags and path-shaped query values neither flip
    // the verb nor dodge redaction; the query is forwarded untouched.
    let resp = p
        .client
        .get(format!(
            "{}/repos/octo/hello/actions/secrets?watch=true&path=/etc",
            p.base
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["secrets"][0].get("value").is_none(), "still redacted");
    let hits = p.hits();
    assert_eq!(hits.len(), 1);
    assert!(
        hits[0].1.contains("watch=true") && hits[0].1.contains("path=/etc"),
        "query forwarded verbatim: {}",
        hits[0].1
    );

    // A query cannot upgrade a denied write either.
    let resp = p
        .client
        .post(format!("{}/repos/octo/hello/issues?dryRun=All", p.base))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "GitHub has no dry-run; write stays denied"
    );
    assert_eq!(p.hit_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_policy_scopes_by_repo_namespace() {
    let policy = r#"
default: deny
rules:
  - verbs: [get, list]
    resources: ["*"]
    namespaces: ["octo/hello"]
    action: allow
"#;
    let p = spawn_proxy(Arc::new(GithubProtocol), github_body, policy).await;

    let ok = p
        .client
        .get(format!("{}/repos/octo/hello/issues/42", p.base))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    ok.bytes().await.expect("consume allowed response body");

    // Another repository is outside the namespace grant. Case variation on
    // the route literals does not create a third namespace either.
    for path in ["/repos/evil/repo/issues/1", "/REPOS/evil/repo/ISSUES/1"] {
        let denied = p
            .client
            .get(format!("{}{}", p.base, path))
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), 403, "{path} is outside octo/hello");
        denied.bytes().await.expect("consume denied response body");
    }
    assert_eq!(p.hit_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_policy_mixed_responses_reuse_connections_reliably() {
    let policy = r#"
default: deny
rules:
  - verbs: [get, list]
    resources: ["*"]
    namespaces: ["octo/hello"]
    action: allow
"#;
    let p = spawn_proxy(Arc::new(GithubProtocol), github_body, policy).await;

    tokio::time::timeout(Duration::from_secs(10), async {
        for _ in 0..32 {
            let allowed = p
                .client
                .get(format!("{}/repos/octo/hello/issues/42", p.base))
                .send()
                .await
                .expect("allowed request");
            assert_eq!(allowed.status(), 200);
            allowed
                .bytes()
                .await
                .expect("consume allowed response body");

            let denied = p
                .client
                .get(format!("{}/repos/evil/repo/issues/1", p.base))
                .send()
                .await
                .expect("denied request");
            assert_eq!(denied.status(), 403);
            denied.bytes().await.expect("consume denied response body");
        }
    })
    .await
    .expect("mixed responses complete within the harness bound");

    assert_eq!(p.hit_count(), 32, "only allowed requests reach upstream");
}

// ---------------------------------------------------------------------------
// Vercel
// ---------------------------------------------------------------------------

fn vercel_body(path: &str) -> Value {
    if path.ends_with("/env") || path.ends_with("/ENV") {
        json!({
            "envs": [
                {"id": "e1", "key": "DATABASE_URL", "value": "postgres://user:pw@host/db", "target": ["production"]},
                {"id": "e2", "key": "PUBLIC_FLAG", "value": "on", "target": ["preview"]}
            ]
        })
    } else if path.contains("/env/") {
        json!({"id": "e1", "key": "DATABASE_URL", "value": "postgres://user:pw@host/db"})
    } else if path.contains("/projects") {
        json!({"id": "prj_123", "name": "web"})
    } else {
        json!({"ok": true})
    }
}

const VERCEL_READS: &str = r#"
default: deny
rules:
  - verbs: [get, list]
    resources: ["*"]
    action: allow
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vercel_reads_forward_and_env_values_are_redacted() {
    let p = spawn_proxy(Arc::new(VercelProtocol), vercel_body, VERCEL_READS).await;

    let resp = p
        .client
        .get(format!("{}/v9/projects/prj_123", p.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["id"], "prj_123");

    // Env list: keys and targets survive, every value is stripped.
    let resp = p
        .client
        .get(format!("{}/v9/projects/prj_123/env", p.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let envs: Value = resp.json().await.unwrap();
    assert_eq!(envs["envs"][0]["key"], "DATABASE_URL");
    assert_eq!(envs["envs"][0]["target"][0], "production");
    assert!(envs["envs"][0].get("value").is_none());
    assert!(envs["envs"][1].get("value").is_none());

    // Single env object, and a case-varied route, are redacted the same way.
    let resp = p
        .client
        .get(format!("{}/v9/projects/prj_123/env/e1", p.base))
        .send()
        .await
        .unwrap();
    let one: Value = resp.json().await.unwrap();
    assert!(one.get("value").is_none());
    let resp = p
        .client
        .get(format!("{}/V9/PROJECTS/prj_123/ENV", p.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let envs: Value = resp.json().await.unwrap();
    assert!(
        envs["envs"][0].get("value").is_none(),
        "case-varied route still redacts"
    );

    assert_eq!(p.hit_count(), 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vercel_log_streams_and_unknown_writes_never_reach_upstream() {
    let p = spawn_proxy(Arc::new(VercelProtocol), vercel_body, ALLOW_ALL).await;

    // Deployment log/event streams are denied outright, past any policy.
    for path in [
        "/v6/deployments/dpl_1/events",
        "/v2/deployments/dpl_1/logs/build",
    ] {
        let resp = p
            .client
            .get(format!("{}{}", p.base, path))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "{path} must be denied");
    }

    // A write to an un-versioned (unmodeled) path is a non-resource write.
    let resp = p
        .client
        .post(format!("{}/login", p.base))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(p.hit_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vercel_project_write_grant_does_not_cover_env_writes() {
    // Writes to the project object are granted; its nested env collection is a
    // different resource, so planting a credential there stays denied.
    let policy = r#"
default: deny
rules:
  - verbs: [get, list]
    resources: ["*"]
    action: allow
  - verbs: [create, update, patch]
    resources: [projects]
    action: allow
"#;
    let p = spawn_proxy(Arc::new(VercelProtocol), vercel_body, policy).await;

    let resp = p
        .client
        .patch(format!("{}/v9/projects/prj_123", p.base))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "project update is granted");

    for (method, path) in [
        ("POST", "/v9/projects/prj_123/env"),
        ("PATCH", "/v9/projects/prj_123/env/e1"),
        // A project delete needs its own grant (only create/update/patch given).
        ("DELETE", "/v9/projects/prj_123"),
    ] {
        let resp = p
            .client
            .request(method.parse().unwrap(), format!("{}{}", p.base, path))
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "{method} {path} must be denied");
    }
    assert_eq!(
        p.hit_count(),
        1,
        "only the granted project update forwarded"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vercel_altering_paths_and_query_params_are_contained() {
    let p = spawn_proxy(Arc::new(VercelProtocol), vercel_body, VERCEL_READS).await;

    // Traversal out of the versioned tree (raw request line).
    let resp = raw_tls_request(&p, "GET", "/v9/projects/prj_123/../../login").await;
    assert!(
        resp.starts_with("HTTP/1.1 403"),
        "traversal must 403, got: {}",
        resp.lines().next().unwrap_or("")
    );

    // An encoded separator in the project id.
    let resp = p
        .client
        .get(format!("{}/v9/projects/prj%2F123/env", p.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Query-string parameters: `decrypt=true` and a path-shaped value change
    // neither the classification nor the redaction.
    let resp = p
        .client
        .get(format!(
            "{}/v9/projects/prj_123/env?decrypt=true&path=/etc",
            p.base
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let envs: Value = resp.json().await.unwrap();
    assert!(envs["envs"][0].get("value").is_none(), "still redacted");
    let hits = p.hits();
    assert_eq!(hits.len(), 1, "only the legitimate read forwarded");
    assert!(
        hits[0].1.contains("decrypt=true"),
        "query forwarded verbatim"
    );
}

/// The shipped example policies for the GitHub and Vercel protocols parse and
/// route representative operations the way their comments promise.
#[test]
fn shipped_github_policy_parses_and_behaves() {
    use guard::proxy::ApiAction;
    let p = ApiPolicy::from_yaml(include_str!("../examples/github-policy.yaml"))
        .expect("examples/github-policy.yaml must parse");
    let gh = GithubProtocol;
    let op = |m: &str, path: &str| gh.parse_op(m, path, "").expect("parse op");

    // Reads are allowed anywhere.
    assert_eq!(
        p.decide(&op("GET", "/repos/octo-org/sandbox/issues"))
            .action,
        ApiAction::Allow
    );
    // Issue writes are allowed only in the sandbox repository.
    assert_eq!(
        p.decide(&op("POST", "/repos/octo-org/sandbox/issues"))
            .action,
        ApiAction::Allow
    );
    assert_eq!(
        p.decide(&op("POST", "/repos/octo-org/prod/issues")).action,
        ApiAction::Deny
    );
    // Content writes hold; deletes hold.
    assert_eq!(
        p.decide(&op("PUT", "/repos/octo-org/sandbox/contents/README.md"))
            .action,
        ApiAction::Hold
    );
    assert_eq!(
        p.decide(&op("DELETE", "/repos/octo-org/sandbox/labels/bug"))
            .action,
        ApiAction::Hold
    );
}

#[test]
fn shipped_vercel_policy_parses_and_behaves() {
    use guard::proxy::ApiAction;
    let p = ApiPolicy::from_yaml(include_str!("../examples/vercel-policy.yaml"))
        .expect("examples/vercel-policy.yaml must parse");
    let vc = VercelProtocol;
    let op = |m: &str, path: &str| vc.parse_op(m, path, "").expect("parse op");

    // Reads are allowed anywhere, env values redacted by classification.
    let read = p.decide(&op("GET", "/v9/projects/my-preview-app/env"));
    assert_eq!(read.action, ApiAction::Allow);
    // Env writes are allowed only in the named project.
    assert_eq!(
        p.decide(&op("POST", "/v9/projects/my-preview-app/env"))
            .action,
        ApiAction::Allow
    );
    assert_eq!(
        p.decide(&op("POST", "/v9/projects/prod-site/env")).action,
        ApiAction::Deny
    );
    // Deployment triggers and deletes hold.
    assert_eq!(
        p.decide(&op("POST", "/v13/deployments")).action,
        ApiAction::Hold
    );
    assert_eq!(
        p.decide(&op("DELETE", "/v9/projects/my-preview-app/env/abc"))
            .action,
        ApiAction::Hold
    );
}
