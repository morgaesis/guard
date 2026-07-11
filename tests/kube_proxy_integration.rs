//! End-to-end test of the Kubernetes API proxy loop without a real cluster.
//!
//! A mock apiserver (plain HTTP) stands in for the upstream. The proxy
//! TLS-terminates the test client, gates each request against the shipped
//! example policy, redacts Secret reads, denies interactive subresources, and
//! re-originates allowed requests to the mock. The client trusts only the
//! proxy's ephemeral CA and connects over TLS, exactly as a brokered client
//! would.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};

use guard::gating::Reversibility;
use guard::proxy::{
    ApiJudge, ApiJudgeVerdict, ApiPolicy, ApiProxy, ApiRequestSummary, GateSink, ProxyTls, Upstream,
};

/// Mock apiserver: returns a Secret (with data), a ConfigMap (with data), or a
/// generic OK for everything else. Records nothing; the proxy is what we test.
async fn mock_handler(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path().to_string();
    let body: Value = if path.contains("/secrets/") {
        json!({
            "kind": "Secret",
            "apiVersion": "v1",
            "metadata": {"name": "db", "namespace": "dev"},
            "type": "Opaque",
            "data": {"password": "c2VjcmV0"}
        })
    } else if path.contains("/configmaps/") {
        json!({
            "kind": "ConfigMap",
            "apiVersion": "v1",
            "metadata": {"name": "cm", "namespace": "dev"},
            "data": {"key": "value"}
        })
    } else {
        json!({"kind": "Status", "apiVersion": "v1", "status": "Success"})
    };
    Ok(Response::builder()
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap())
}

async fn spawn_mock_upstream() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(mock_handler))
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn kubeconfig_for(mock_base: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n  - name: c\n    cluster: {{server: \"{mock_base}\"}}\ncontexts:\n  - name: ctx\n    context: {{cluster: c, user: u}}\nusers:\n  - name: u\n    user: {{}}\n"
    )
}

async fn start_proxy_with(
    mock_base: String,
    policy_yaml: &str,
    judge: Option<Arc<dyn ApiJudge>>,
    gate: Option<Arc<dyn GateSink>>,
    rarity_threshold: u64,
) -> (String, reqwest::Client) {
    let kubeconfig = kubeconfig_for(&mock_base);
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(policy_yaml).expect("policy");
    let port = free_port();
    let listen = format!("127.0.0.1:{port}").parse().unwrap();
    let mut proxy = ApiProxy::new(listen, tls, upstream, policy, None);
    if rarity_threshold > 0 {
        proxy = proxy.with_rarity_escalation(rarity_threshold);
    }
    let proxy = Arc::new(proxy);
    if let Some(gate) = gate {
        proxy.attach_gate(gate);
    }
    if let Some(judge) = judge {
        proxy.attach_judge(judge);
    }
    tokio::spawn(proxy.clone().serve());
    tokio::time::sleep(Duration::from_millis(150)).await;
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    (format!("https://127.0.0.1:{port}"), client)
}

#[derive(Clone)]
struct RecordingJudge {
    verdicts: Arc<std::sync::Mutex<VecDeque<ApiJudgeVerdict>>>,
    summaries: Arc<std::sync::Mutex<Vec<ApiRequestSummary>>>,
}

impl RecordingJudge {
    fn new(verdicts: Vec<ApiJudgeVerdict>) -> Self {
        Self {
            verdicts: Arc::new(std::sync::Mutex::new(verdicts.into())),
            summaries: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

#[async_trait::async_trait]
impl ApiJudge for RecordingJudge {
    async fn judge(&self, summary: &ApiRequestSummary) -> ApiJudgeVerdict {
        self.summaries.lock().unwrap().push(summary.clone());
        self.verdicts
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| ApiJudgeVerdict::Error("no mock verdict queued".to_string()))
    }
}

fn judge_allow(risk: Option<i32>, reversibility: Option<Reversibility>) -> ApiJudgeVerdict {
    ApiJudgeVerdict::Allow {
        reason: "mock allow".to_string(),
        risk,
        reversibility,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_gates_redacts_and_forwards() {
    // Upstream: the mock apiserver over plain HTTP (no creds needed).
    let mock_base = spawn_mock_upstream().await;
    let kubeconfig = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n  - name: c\n    cluster: {{server: \"{mock_base}\"}}\ncontexts:\n  - name: ctx\n    context: {{cluster: c, user: u}}\nusers:\n  - name: u\n    user: {{}}\n"
    );
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");

    // Proxy: ephemeral CA, shipped example policy.
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(include_str!("../examples/api-policy.yaml")).expect("policy");
    let port = free_port();
    let listen = format!("127.0.0.1:{port}").parse().unwrap();
    let proxy = Arc::new(ApiProxy::new(listen, tls, upstream, policy, None));

    // The brokered config must point at the proxy and carry no credential.
    let brokered = proxy.brokered_kubeconfig();
    guard::proxy::validate_brokered_kubeconfig(&brokered).expect("brokered config credential-free");
    assert!(brokered.contains(&format!("https://127.0.0.1:{port}")));

    tokio::spawn(proxy.clone().serve());
    // Give the listener a moment to bind.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let base = format!("https://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();

    // 1. Reading a Secret is allowed but its values are redacted.
    let resp = client
        .get(format!("{base}/api/v1/namespaces/dev/secrets/db"))
        .send()
        .await
        .expect("secret read");
    assert_eq!(resp.status(), 200, "secret read should be allowed");
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["metadata"]["name"], "db", "metadata survives");
    assert!(v.get("data").is_none(), "Secret data must be redacted");

    // 2. A ConfigMap read passes through unredacted (not a Secret).
    let resp = client
        .get(format!("{base}/api/v1/namespaces/dev/configmaps/cm"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["data"]["key"], "value", "ConfigMap data is not redacted");

    // 3. A policy-held delete with no approval queue attached (no gate sink
    //    here) fails closed -> 403, apiserver never hit.
    let resp = client
        .delete(format!("{base}/api/v1/namespaces/dev/pods/web-0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "delete should be held");
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["kind"], "Status");
    assert!(v["message"]
        .as_str()
        .unwrap()
        .contains("requires operator approval"));

    // 4. An interactive subresource is denied outright.
    let resp = client
        .post(format!("{base}/api/v1/namespaces/dev/pods/web-0/exec"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "exec must be denied");
    let v: Value = resp.json().await.unwrap();
    assert!(v["message"].as_str().unwrap().contains("exec"));

    // 5. A write in a production namespace falls to default-deny.
    let resp = client
        .post(format!("{base}/api/v1/namespaces/prod/pods"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "prod write should be denied");

    // 6. A write in a non-production namespace is allowed and forwarded.
    let resp = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "dev write should be forwarded to upstream"
    );

    // 7. Watching Secret values is denied (the stream cannot be redacted yet).
    let resp = client
        .get(format!("{base}/api/v1/namespaces/dev/secrets?watch=true"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "secret watch must be denied");
}

/// Records the reverts the proxy synthesizes, standing in for the daemon's
/// consequence machinery.
#[derive(Clone, Default)]
struct RecordingSink {
    calls: Arc<std::sync::Mutex<Vec<guard::proxy::ApiMutation>>>,
    resolved: Arc<std::sync::Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl guard::proxy::GateSink for RecordingSink {
    async fn arm_revert(&self, mutation: guard::proxy::ApiMutation) -> Option<String> {
        let handle = format!("test-handle-{}", self.calls.lock().unwrap().len());
        self.calls.lock().unwrap().push(mutation);
        Some(handle)
    }

    async fn resolve(&self, handle: &str) {
        self.resolved.lock().unwrap().push(handle.to_string());
    }
}

/// Mock apiserver for the write path: returns a created Pod for POST, and a
/// Deployment (with resourceVersion) for the snapshot GET and the PATCH.
async fn write_mock_handler(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let is_create = req.method() == hyper::Method::POST;
    let (code, body) = if is_create {
        (
            201,
            json!({"kind": "Pod", "apiVersion": "v1", "metadata": {"name": "web-123", "namespace": "dev"}}),
        )
    } else {
        (
            200,
            json!({
                "kind": "Deployment",
                "apiVersion": "apps/v1",
                "metadata": {"name": "api", "namespace": "dev", "resourceVersion": "42"},
                "spec": {"replicas": 3}
            }),
        )
    };
    Ok(Response::builder()
        .status(code)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap())
}

async fn spawn_write_mock() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(write_mock_handler))
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_arms_auto_revert_for_writes() {
    let mock_base = spawn_write_mock().await;
    let kubeconfig = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n  - name: c\n    cluster: {{server: \"{mock_base}\"}}\ncontexts:\n  - name: ctx\n    context: {{cluster: c, user: u}}\nusers:\n  - name: u\n    user: {{}}\n"
    );
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(include_str!("../examples/api-policy.yaml")).expect("policy");
    let port = free_port();
    let listen = format!("127.0.0.1:{port}").parse().unwrap();
    let proxy = Arc::new(ApiProxy::new(listen, tls, upstream, policy, None));

    let sink = RecordingSink::default();
    proxy.attach_gate(Arc::new(sink.clone()));

    tokio::spawn(proxy.clone().serve());
    tokio::time::sleep(Duration::from_millis(150)).await;

    let base = format!("https://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();

    // A create in a non-prod namespace is forwarded and a delete-revert is armed.
    let resp = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "create forwarded");

    // A patch on a named object snapshots the prior state and arms a restore.
    let resp = client
        .patch(format!(
            "{base}/apis/apps/v1/namespaces/dev/deployments/api"
        ))
        .header("content-type", "application/merge-patch+json")
        .body(r#"{"spec":{"replicas":5}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "patch forwarded");

    // Let the async arming settle.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let calls = sink.calls.lock().unwrap();
    assert_eq!(calls.len(), 2, "both writes armed a revert");

    // The create armed a DELETE for the server-assigned object name.
    assert_eq!(calls[0].revert.method, "DELETE");
    assert_eq!(calls[0].revert.path, "/api/v1/namespaces/dev/pods/web-123");
    let body: Value = serde_json::from_slice(calls[0].revert.body.as_ref().unwrap()).unwrap();
    assert_eq!(body["propagationPolicy"], "Background");

    // The patch armed a restore from the snapshotted prior object.
    assert_eq!(calls[1].revert.method, "PUT");
    assert_eq!(
        calls[1].revert.path,
        "/apis/apps/v1/namespaces/dev/deployments/api"
    );
    let v: Value = serde_json::from_slice(calls[1].revert.body.as_ref().unwrap()).unwrap();
    assert_eq!(v["metadata"]["name"], "api");
    assert!(v["metadata"].get("resourceVersion").is_none());
}

/// Mock apiserver that echoes the request headers it received back as a JSON
/// object, so a test can assert on what the proxy actually forwarded.
async fn header_echo_handler(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let headers: serde_json::Map<String, Value> = req
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                Value::String(v.to_str().unwrap_or("").to_string()),
            )
        })
        .collect();
    let body = json!({"kind": "Status", "apiVersion": "v1", "status": "Success", "receivedHeaders": headers});
    Ok(Response::builder()
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap())
}

async fn spawn_header_echo_upstream() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(header_echo_handler))
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

/// Regression test: the proxy must deny the `proxy` subresource outright (it
/// tunnels an arbitrary HTTP request to the target's network endpoint, which
/// a verb/resource policy rule cannot see into) and must never forward
/// client-supplied `Impersonate-*` / `X-Remote-*` identity headers upstream
/// (the operator's own credential may hold the `impersonate` RBAC verb, which
/// would let an agent re-author a request under an arbitrary identity).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_denies_subresource_and_strips_identity_headers() {
    let mock_base = spawn_header_echo_upstream().await;
    let kubeconfig = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n  - name: c\n    cluster: {{server: \"{mock_base}\"}}\ncontexts:\n  - name: ctx\n    context: {{cluster: c, user: u}}\nusers:\n  - name: u\n    user: {{}}\n"
    );
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(include_str!("../examples/api-policy.yaml")).expect("policy");
    let port = free_port();
    let listen = format!("127.0.0.1:{port}").parse().unwrap();
    let proxy = Arc::new(ApiProxy::new(listen, tls, upstream, policy, None));

    tokio::spawn(proxy.clone().serve());
    tokio::time::sleep(Duration::from_millis(150)).await;

    let base = format!("https://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();

    // 1. The `proxy` subresource is denied outright, like exec/attach/portforward.
    let resp = client
        .get(format!(
            "{base}/api/v1/namespaces/dev/pods/web-0/proxy/metrics"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "pod proxy subresource must be denied");
    let v: Value = resp.json().await.unwrap();
    assert!(v["message"].as_str().unwrap().contains("proxy"));

    // Node proxy reaches the kubelet API, an even larger blast radius -- must
    // also be denied.
    let resp = client
        .get(format!("{base}/api/v1/nodes/node-1/proxy/runningpods"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "node proxy subresource must be denied");

    // 2. An allowed request carrying spoofed identity headers must not have
    // them forwarded upstream; the mock echoes back what it actually saw.
    let resp = client
        .get(format!("{base}/api/v1/namespaces/dev/pods"))
        .header("Impersonate-User", "system:masters")
        .header("Impersonate-Group", "system:masters")
        .header("X-Remote-User", "admin")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "the underlying read is allowed");
    let v: Value = resp.json().await.unwrap();
    let received = v["receivedHeaders"]
        .as_object()
        .expect("receivedHeaders object");
    assert!(
        !received.contains_key("impersonate-user"),
        "Impersonate-User must not reach the apiserver, got headers: {received:?}"
    );
    assert!(
        !received.contains_key("impersonate-group"),
        "Impersonate-Group must not reach the apiserver, got headers: {received:?}"
    );
    assert!(
        !received.contains_key("x-remote-user"),
        "X-Remote-User must not reach the apiserver, got headers: {received:?}"
    );
}

/// A `SelfSubjectAccessReview` (`kubectl auth can-i`) is forwarded with the same
/// single upstream credential the proxy injects on every request, so the
/// self-check reflects the identity that actually performs writes rather than a
/// separate or stale one. The header-echo upstream reports the Authorization it
/// received.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_self_access_review_carries_upstream_credential() {
    let mock_base = spawn_header_echo_upstream().await;
    // The operator kubeconfig carries a bearer token; the proxy injects it on
    // every forwarded request, including the self-access review.
    let kubeconfig = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n  - name: c\n    cluster: {{server: \"{mock_base}\"}}\ncontexts:\n  - name: ctx\n    context: {{cluster: c, user: u}}\nusers:\n  - name: u\n    user: {{token: operator-secret-token}}\n"
    );
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    // Allow the review create (cluster-scoped) so it reaches the upstream.
    let policy = ApiPolicy::from_yaml(
        "default: deny\nrules:\n  - verbs: [create]\n    resources: [selfsubjectaccessreviews]\n    namespaces: [\"*\"]\n    action: allow\n",
    )
    .expect("policy");
    let port = free_port();
    let listen = format!("127.0.0.1:{port}").parse().unwrap();
    let proxy = Arc::new(ApiProxy::new(listen, tls, upstream, policy, None));

    tokio::spawn(proxy.clone().serve());
    tokio::time::sleep(Duration::from_millis(150)).await;

    let base = format!("https://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();

    let review = json!({
        "kind": "SelfSubjectAccessReview",
        "apiVersion": "authorization.k8s.io/v1",
        "spec": {"resourceAttributes": {"namespace": "dev", "verb": "create", "resource": "pods"}}
    });
    let resp = client
        .post(format!(
            "{base}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
        ))
        .header("content-type", "application/json")
        .body(review.to_string())
        .send()
        .await
        .expect("self access review");
    assert_eq!(resp.status(), 200, "the review is forwarded");
    let v: Value = resp.json().await.unwrap();
    let received = v["receivedHeaders"].as_object().expect("headers");
    assert_eq!(
        received.get("authorization").and_then(Value::as_str),
        Some("Bearer operator-secret-token"),
        "can-i must carry the same upstream credential writes use, got: {received:?}"
    );
}

/// Mock apiserver for the provenance test: a POST returns a created Pod named
/// `check-pod`; a DELETE returns a success Status (the object removed).
async fn create_delete_mock_handler(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (code, body) = match *req.method() {
        hyper::Method::POST => (
            201,
            json!({"kind": "Pod", "apiVersion": "v1", "metadata": {"name": "check-pod", "namespace": "dev"}}),
        ),
        hyper::Method::DELETE => (
            200,
            json!({"kind": "Status", "apiVersion": "v1", "status": "Success"}),
        ),
        _ => (
            200,
            json!({"kind": "Status", "apiVersion": "v1", "status": "Success"}),
        ),
    };
    Ok(Response::builder()
        .status(code)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap())
}

async fn spawn_create_delete_mock() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(create_delete_mock_handler))
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

/// A delete of a resource guard itself created earlier in the session is
/// contained cleanup (e.g. a Helm post-install hook removing its own check
/// resource): it is allowed and its now-moot auto-revert is resolved, rather
/// than being held like an unrecorded destructive delete. A delete of a
/// resource with no creation record keeps the strict policy handling (hold).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_allows_contained_delete_of_created_resource() {
    let mock_base = spawn_create_delete_mock().await;
    let kubeconfig = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n  - name: c\n    cluster: {{server: \"{mock_base}\"}}\ncontexts:\n  - name: ctx\n    context: {{cluster: c, user: u}}\nusers:\n  - name: u\n    user: {{}}\n"
    );
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(include_str!("../examples/api-policy.yaml")).expect("policy");
    let port = free_port();
    let listen = format!("127.0.0.1:{port}").parse().unwrap();
    let proxy = Arc::new(ApiProxy::new(listen, tls, upstream, policy, None));

    let sink = RecordingSink::default();
    proxy.attach_gate(Arc::new(sink.clone()));

    tokio::spawn(proxy.clone().serve());
    tokio::time::sleep(Duration::from_millis(150)).await;

    let base = format!("https://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();

    // A delete with no creation record is held for operator approval (strict).
    let resp = client
        .delete(format!("{base}/api/v1/namespaces/dev/pods/other-pod"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "delete of an unrecorded resource stays held"
    );

    // Create a resource through the proxy; guard records its provenance.
    let resp = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "create forwarded");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        sink.calls.lock().unwrap().len(),
        1,
        "the create armed exactly one revert"
    );

    // Deleting that same resource is now contained cleanup: allowed and forwarded.
    let resp = client
        .delete(format!("{base}/api/v1/namespaces/dev/pods/check-pod"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "delete of a guard-created resource is contained and allowed"
    );

    // The now-moot auto-revert for the create was resolved.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let resolved_count = sink.resolved.lock().unwrap().len();
    assert_eq!(resolved_count, 1, "the create's auto-revert was resolved");
    assert_eq!(
        sink.calls.lock().unwrap().len(),
        1,
        "contained delete forwards without arming a delete-restore revert"
    );

    // Provenance is single-use: a second delete of the same name has no record
    // and falls back to the strict hold.
    let resp = client
        .delete(format!("{base}/api/v1/namespaces/dev/pods/check-pod"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "provenance is consumed; a repeat delete is held again"
    );
}

/// Mock apiserver that returns a Secret read as a 200 with a non-JSON
/// content-type. A compliant apiserver would honor the proxy's forced
/// `Accept: application/json`, but a misbehaving aggregated/older server might
/// not; the proxy must not stream such a body through unredacted.
async fn non_json_secret_mock_handler(
    _req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let body = json!({
        "kind": "Secret",
        "metadata": {"name": "db", "namespace": "dev"},
        "data": {"password": "c2VjcmV0"}
    });
    Ok(Response::builder()
        .status(200)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap())
}

async fn spawn_non_json_secret_mock() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(non_json_secret_mock_handler))
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

/// Redaction must fail closed when a Secret read comes back with a content-type
/// the proxy cannot parse: the raw body (with `data` intact) must never reach
/// the client. The proxy returns a 502 instead of streaming it through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_fails_closed_on_non_json_secret_response() {
    let mock_base = spawn_non_json_secret_mock().await;
    let kubeconfig = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n  - name: c\n    cluster: {{server: \"{mock_base}\"}}\ncontexts:\n  - name: ctx\n    context: {{cluster: c, user: u}}\nusers:\n  - name: u\n    user: {{}}\n"
    );
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(include_str!("../examples/api-policy.yaml")).expect("policy");
    let port = free_port();
    let listen = format!("127.0.0.1:{port}").parse().unwrap();
    let proxy = Arc::new(ApiProxy::new(listen, tls, upstream, policy, None));

    tokio::spawn(proxy.clone().serve());
    tokio::time::sleep(Duration::from_millis(150)).await;

    let base = format!("https://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();

    let resp = client
        .get(format!("{base}/api/v1/namespaces/dev/secrets/db"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        502,
        "a non-JSON Secret response fails closed"
    );
    let text = resp.text().await.unwrap();
    assert!(
        !text.contains("c2VjcmV0"),
        "the secret value must not leak in the fail-closed response"
    );
}

async fn eviction_mock_handler(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (code, body) = match *req.method() {
        // The eviction subresource echoes the evicted pod's name/namespace.
        hyper::Method::POST => (
            201,
            json!({"kind": "Eviction", "apiVersion": "policy/v1", "metadata": {"name": "critical-0", "namespace": "dev"}}),
        ),
        _ => (
            200,
            json!({"kind": "Status", "apiVersion": "v1", "status": "Success"}),
        ),
    };
    Ok(Response::builder()
        .status(code)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap())
}

async fn spawn_eviction_mock() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(eviction_mock_handler))
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

/// A write to a subresource must not seed create/delete provenance. Evicting a
/// pod (`POST pods/{name}/eviction`) returns an Eviction object echoing the
/// pod's name, but the pod pre-existed and was terminated, not created. If that
/// echo poisoned the provenance registry, a same-connection `DELETE pods/{name}`
/// would be treated as contained cleanup and skip policy. It must stay held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_eviction_does_not_launder_a_later_delete() {
    let mock_base = spawn_eviction_mock().await;
    let kubeconfig = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n  - name: c\n    cluster: {{server: \"{mock_base}\"}}\ncontexts:\n  - name: ctx\n    context: {{cluster: c, user: u}}\nusers:\n  - name: u\n    user: {{}}\n"
    );
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    // Allow the eviction subresource in dev, but hold plain pod deletes.
    let policy = ApiPolicy::from_yaml(
        r#"
default: deny
rules:
  - verbs: [create]
    resources: [pods]
    namespaces: [dev]
    subresources: [eviction]
    action: allow
  - verbs: [delete]
    resources: [pods]
    namespaces: [dev]
    action: hold
"#,
    )
    .expect("policy");
    let port = free_port();
    let listen = format!("127.0.0.1:{port}").parse().unwrap();
    let proxy = Arc::new(ApiProxy::new(listen, tls, upstream, policy, None));

    let sink = RecordingSink::default();
    proxy.attach_gate(Arc::new(sink.clone()));

    tokio::spawn(proxy.clone().serve());
    tokio::time::sleep(Duration::from_millis(150)).await;

    let base = format!("https://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();

    // Evict the pod: allowed by the eviction rule.
    let resp = client
        .post(format!(
            "{base}/api/v1/namespaces/dev/pods/critical-0/eviction"
        ))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "eviction forwarded");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // No auto-revert was armed for a subresource write, so no provenance exists.
    assert_eq!(
        sink.calls.lock().unwrap().len(),
        0,
        "a subresource write arms no auto-revert and seeds no provenance"
    );

    // Deleting the evicted pod must stay held: the eviction did not launder it.
    let resp = client
        .delete(format!("{base}/api/v1/namespaces/dev/pods/critical-0"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "delete of the evicted pod is not contained; policy holds it"
    );
}

/// Mock apiserver that returns a Helm release-storage Secret: type
/// `helm.sh/release.v1` with a single opaque `data.release` blob (Helm's
/// doubly-base64-and-gzip-encoded release state), which is not a structured type
/// the proxy models.
async fn helm_release_mock_handler(
    _req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let body = json!({
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {
            "name": "sh.helm.release.v1.cert-manager.v1",
            "namespace": "dev",
            "labels": {"owner": "helm", "name": "cert-manager"}
        },
        "type": "helm.sh/release.v1",
        "data": {"release": "SDRzSUFBQUFBQUFDLzZvR0FBWU5BUUFBQUE9PQ=="}
    });
    Ok(Response::builder()
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap())
}

async fn spawn_helm_release_mock() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(helm_release_mock_handler))
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

/// Regression test: reading Helm's release-storage Secret must return a
/// redacted-but-successful response. The opaque `data.release` blob is not a
/// type the proxy can parse, so redaction masks it by default rather than
/// hard-erroring the whole response -- otherwise `helm list`/`status`/`upgrade`,
/// which read this Secret, would all fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_redacts_helm_release_secret_without_erroring() {
    let mock_base = spawn_helm_release_mock().await;
    let kubeconfig = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n  - name: c\n    cluster: {{server: \"{mock_base}\"}}\ncontexts:\n  - name: ctx\n    context: {{cluster: c, user: u}}\nusers:\n  - name: u\n    user: {{}}\n"
    );
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(include_str!("../examples/api-policy.yaml")).expect("policy");
    let port = free_port();
    let listen = format!("127.0.0.1:{port}").parse().unwrap();
    let proxy = Arc::new(ApiProxy::new(listen, tls, upstream, policy, None));

    tokio::spawn(proxy.clone().serve());
    tokio::time::sleep(Duration::from_millis(150)).await;

    let base = format!("https://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();

    let resp = client
        .get(format!(
            "{base}/api/v1/namespaces/dev/secrets/sh.helm.release.v1.cert-manager.v1"
        ))
        .send()
        .await
        .expect("helm release secret read");
    assert_eq!(
        resp.status(),
        200,
        "reading the Helm release Secret must succeed, not error on the opaque blob"
    );
    let v: Value = resp.json().await.unwrap();
    assert!(
        v.get("data").is_none(),
        "the opaque release blob is redacted"
    );
    assert_eq!(
        v["type"], "helm.sh/release.v1",
        "the release Secret type survives so helm can identify it"
    );
    assert_eq!(v["metadata"]["labels"]["owner"], "helm");
}

/// Gate sink standing in for the daemon's approval queue with an operator who
/// approves every held request.
#[derive(Clone, Default)]
struct ApprovingSink;

#[async_trait::async_trait]
impl guard::proxy::GateSink for ApprovingSink {
    async fn arm_revert(&self, _mutation: guard::proxy::ApiMutation) -> Option<String> {
        None
    }

    async fn hold_request(&self, _label: &str, _reason: &str) -> guard::proxy::HoldDecision {
        guard::proxy::HoldDecision::Approved {
            handle: "test-approved".to_string(),
        }
    }
}

/// A policy `hold` routes through the attached approval queue: an approved hold
/// forwards to the upstream, while a proxy running without any queue (no gate
/// sink) fails the hold closed with a 403 that names the missing gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_hold_forwards_on_approval_and_fails_closed_without_queue() {
    let mock_base = spawn_mock_upstream().await;
    let kubeconfig = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n  - name: c\n    cluster: {{server: \"{mock_base}\"}}\ncontexts:\n  - name: ctx\n    context: {{cluster: c, user: u}}\nusers:\n  - name: u\n    user: {{}}\n"
    );
    let policy_yaml = r#"
default: deny
rules:
  - verbs: [delete]
    resources: [pods]
    namespaces: [dev]
    action: hold
"#;

    // No gate sink attached: the hold cannot queue anywhere, so it denies and
    // says why.
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(policy_yaml).expect("policy");
    let port = free_port();
    let listen = format!("127.0.0.1:{port}").parse().unwrap();
    let proxy = Arc::new(ApiProxy::new(listen, tls, upstream, policy, None));
    tokio::spawn(proxy.clone().serve());
    tokio::time::sleep(Duration::from_millis(150)).await;

    let base = format!("https://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let resp = client
        .delete(format!("{base}/api/v1/namespaces/dev/pods/web-0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "hold without a queue fails closed");
    let text = resp.text().await.unwrap();
    assert!(
        text.contains("--gate consequence"),
        "the denial names the missing approval queue: {text}"
    );

    // Approval queue attached and the operator approves: the held delete is
    // released and forwarded to the upstream.
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(policy_yaml).expect("policy");
    let port = free_port();
    let listen = format!("127.0.0.1:{port}").parse().unwrap();
    let proxy = Arc::new(ApiProxy::new(listen, tls, upstream, policy, None));
    proxy.attach_gate(Arc::new(ApprovingSink));
    tokio::spawn(proxy.clone().serve());
    tokio::time::sleep(Duration::from_millis(150)).await;

    let base = format!("https://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let resp = client
        .delete(format!("{base}/api/v1/namespaces/dev/pods/web-0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "an approved hold is forwarded upstream");
}

/// Gate sink that counts hold requests and approves each, so a test can assert
/// how many requests were escalated to the queue.
#[derive(Clone, Default)]
struct CountingSink {
    holds: Arc<std::sync::Mutex<u32>>,
}

#[async_trait::async_trait]
impl guard::proxy::GateSink for CountingSink {
    async fn arm_revert(&self, _mutation: guard::proxy::ApiMutation) -> Option<String> {
        None
    }

    async fn hold_request(&self, _label: &str, _reason: &str) -> guard::proxy::HoldDecision {
        *self.holds.lock().unwrap() += 1;
        guard::proxy::HoldDecision::Approved {
            handle: "test-approved".to_string(),
        }
    }
}

/// Rarity escalation holds a policy-allowed request while its shape is still
/// rare (seen fewer than `threshold` times), then lets the shape flow without a
/// hold once it is established. Object name is not part of the shape, so
/// distinctly-named reads of the same resource share one rare window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_rarity_escalation_holds_only_rare_shapes() {
    let mock_base = spawn_mock_upstream().await;
    let kubeconfig = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n  - name: c\n    cluster: {{server: \"{mock_base}\"}}\ncontexts:\n  - name: ctx\n    context: {{cluster: c, user: u}}\nusers:\n  - name: u\n    user: {{}}\n"
    );
    // A broad read-allow rule: every read is permitted by policy, so only rarity
    // escalation can hold one.
    let policy = ApiPolicy::from_yaml(
        "default: deny\nrules:\n  - verbs: [get, list]\n    resources: [\"*\"]\n    namespaces: [\"*\"]\n    action: allow\n",
    )
    .expect("policy");
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let port = free_port();
    let listen = format!("127.0.0.1:{port}").parse().unwrap();
    // Threshold 2: the first two occurrences of a shape are escalated.
    let proxy =
        Arc::new(ApiProxy::new(listen, tls, upstream, policy, None).with_rarity_escalation(2));
    let sink = CountingSink::default();
    proxy.attach_gate(Arc::new(sink.clone()));
    tokio::spawn(proxy.clone().serve());
    tokio::time::sleep(Duration::from_millis(150)).await;

    let base = format!("https://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();

    // Four reads of the same shape (configmaps in dev), different object names.
    // The first two are within the rare window -> escalated (but approved, so
    // still 200); the last two flow without a hold.
    for name in ["a", "b", "c", "d"] {
        let resp = client
            .get(format!("{base}/api/v1/namespaces/dev/configmaps/{name}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "read {name} forwards (approved)");
    }
    // A read of a different shape (a new namespace) is rare on its own.
    let resp = client
        .get(format!("{base}/api/v1/namespaces/prod/configmaps/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    tokio::time::sleep(Duration::from_millis(50)).await;
    let holds = *sink.holds.lock().unwrap();
    assert_eq!(
        holds, 3,
        "2 holds for the first shape's rare window + 1 for the new-namespace shape"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_evaluate_allow_and_deny_verdicts_route_correctly() {
    let policy = r#"
default: deny
rules:
  - verbs: [get]
    resources: [configmaps]
    namespaces: [dev]
    action: evaluate
  - verbs: [patch]
    resources: [deployments]
    namespaces: [dev]
    action: evaluate
"#;

    let judge = RecordingJudge::new(vec![judge_allow(Some(1), Some(Reversibility::Reversible))]);
    let (base, client) = start_proxy_with(
        spawn_mock_upstream().await,
        policy,
        Some(Arc::new(judge)),
        None,
        0,
    )
    .await;
    let resp = client
        .get(format!("{base}/api/v1/namespaces/dev/configmaps/cm"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "low-risk reversible allow forwards");

    let judge = RecordingJudge::new(vec![ApiJudgeVerdict::Deny {
        reason: "not in scope".to_string(),
    }]);
    let (base, client) = start_proxy_with(
        spawn_mock_upstream().await,
        policy,
        Some(Arc::new(judge)),
        None,
        0,
    )
    .await;
    let resp = client
        .get(format!("{base}/api/v1/namespaces/dev/configmaps/cm"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "judge deny is a proxy 403");

    let judge = RecordingJudge::new(vec![ApiJudgeVerdict::Error("transport down".to_string())]);
    let (base, client) = start_proxy_with(
        spawn_mock_upstream().await,
        policy,
        Some(Arc::new(judge)),
        None,
        0,
    )
    .await;
    let resp = client
        .get(format!("{base}/api/v1/namespaces/dev/configmaps/cm"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "judge error denies and fails closed, matching the command path"
    );

    let (base, client) = start_proxy_with(spawn_mock_upstream().await, policy, None, None, 0).await;
    let resp = client
        .get(format!("{base}/api/v1/namespaces/dev/configmaps/cm"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "evaluate without a judge routes to hold"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_evaluate_respects_decide_gate_floor_and_constructibility() {
    let policy = r#"
default: deny
rules:
  - verbs: [get]
    resources: [configmaps]
    namespaces: [dev]
    action: evaluate
  - verbs: [patch]
    resources: [deployments]
    namespaces: [dev]
    action: evaluate
"#;

    for verdict in [
        judge_allow(Some(1), None),
        judge_allow(None, Some(Reversibility::Reversible)),
        judge_allow(Some(1), Some(Reversibility::Irreversible)),
    ] {
        let judge = RecordingJudge::new(vec![verdict]);
        let (base, client) = start_proxy_with(
            spawn_mock_upstream().await,
            policy,
            Some(Arc::new(judge)),
            None,
            0,
        )
        .await;
        let resp = client
            .get(format!("{base}/api/v1/namespaces/dev/configmaps/cm"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            403,
            "missing class, missing risk, and irreversible allows all hold"
        );
    }

    let sink = RecordingSink::default();
    let judge = RecordingJudge::new(vec![judge_allow(Some(4), Some(Reversibility::Recoverable))]);
    let (base, client) = start_proxy_with(
        spawn_write_mock().await,
        policy,
        Some(Arc::new(judge)),
        Some(Arc::new(sink.clone())),
        0,
    )
    .await;
    let resp = client
        .patch(format!(
            "{base}/apis/apps/v1/namespaces/dev/deployments/api"
        ))
        .header("content-type", "application/merge-patch+json")
        .body(r#"{"spec":{"replicas":5}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "recoverable with snapshot forwards");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        sink.calls.lock().unwrap().len(),
        1,
        "recoverable evaluate allow arms containment revert"
    );

    let judge = RecordingJudge::new(vec![judge_allow(Some(4), Some(Reversibility::Recoverable))]);
    let (base, client) = start_proxy_with(
        spawn_write_mock().await,
        policy,
        Some(Arc::new(judge)),
        None,
        0,
    )
    .await;
    let resp = client
        .patch(format!(
            "{base}/apis/apps/v1/namespaces/dev/deployments/api"
        ))
        .header("content-type", "application/merge-patch+json")
        .body(r#"{"spec":{"replicas":5}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "recoverable without a constructible revert holds"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_evaluate_rarity_uses_judge_when_available() {
    let policy = r#"
default: deny
rules:
  - verbs: [get]
    resources: ["*"]
    namespaces: ["*"]
    action: allow
"#;

    let judge = RecordingJudge::new(vec![judge_allow(Some(1), Some(Reversibility::Reversible))]);
    let summaries = judge.summaries.clone();
    let (base, client) = start_proxy_with(
        spawn_mock_upstream().await,
        policy,
        Some(Arc::new(judge)),
        None,
        1,
    )
    .await;
    let resp = client
        .get(format!("{base}/api/v1/namespaces/dev/configmaps/cm"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "rare allow is judged and forwarded");
    assert!(
        summaries.lock().unwrap()[0].rarity,
        "judge receives rarity=true for rare allow shape"
    );

    let (base, client) = start_proxy_with(spawn_mock_upstream().await, policy, None, None, 1).await;
    let resp = client
        .get(format!("{base}/api/v1/namespaces/dev/configmaps/cm"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "rare allow without judge is held");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_evaluate_body_shape_never_includes_leaf_values() {
    let policy = r#"
default: deny
rules:
  - verbs: [create]
    resources: [configmaps]
    namespaces: [dev]
    action: evaluate
"#;
    let judge = RecordingJudge::new(vec![
        ApiJudgeVerdict::Deny {
            reason: "stop".to_string(),
        },
        ApiJudgeVerdict::Deny {
            reason: "stop".to_string(),
        },
        ApiJudgeVerdict::Deny {
            reason: "stop".to_string(),
        },
    ]);
    let summaries = judge.summaries.clone();
    let (base, client) = start_proxy_with(
        spawn_mock_upstream().await,
        policy,
        Some(Arc::new(judge)),
        None,
        0,
    )
    .await;

    let secret_value = "super-secret-value";
    let resp = client
        .post(format!("{base}/api/v1/namespaces/dev/configmaps"))
        .header("content-type", "application/json")
        .body(
            json!({
                "metadata": {"name": "cm"},
                "data": {"password": secret_value, "replicas": 3, "enabled": true, "none": null},
                "items": [{"key": "value"}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let resp = client
        .post(format!("{base}/api/v1/namespaces/dev/configmaps"))
        .body("not-json-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let resp = client
        .post(format!("{base}/api/v1/namespaces/dev/configmaps"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let summaries = summaries.lock().unwrap();
    assert_eq!(summaries.len(), 3);
    assert!(
        !summaries[0].redacted_body_shape.contains(secret_value),
        "JSON leaf values must not enter the judge summary: {}",
        summaries[0].redacted_body_shape
    );
    assert!(summaries[0].redacted_body_shape.contains("<string>"));
    assert!(summaries[0].redacted_body_shape.contains("<number>"));
    assert!(summaries[0].redacted_body_shape.contains("<bool>"));
    assert!(summaries[0].redacted_body_shape.contains("<null>"));
    assert_eq!(
        summaries[1].redacted_body_shape,
        "(non-JSON body, 15 bytes)"
    );
    assert_eq!(summaries[2].redacted_body_shape, "(no body)");
}

async fn counting_snapshot_handler(
    req: Request<Incoming>,
    gets: Arc<std::sync::atomic::AtomicUsize>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() == hyper::Method::GET {
        gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    write_mock_handler(req).await
}

async fn spawn_counting_snapshot_mock() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    let gets = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gets_for_task = gets.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            let gets = gets_for_task.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req| counting_snapshot_handler(req, gets.clone())),
                    )
                    .await;
            });
        }
    });
    (format!("http://{addr}"), gets)
}

/// Snapshot mock whose GET succeeds once (the pre-judge constructibility check)
/// then fails (the forward-time re-fetch), while writes always succeed. Models a
/// mutation of the prior object during the evaluator round trip.
async fn flaky_snapshot_handler(
    req: Request<Incoming>,
    gets: Arc<std::sync::atomic::AtomicUsize>,
    writes: Arc<std::sync::atomic::AtomicUsize>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() == hyper::Method::GET {
        let n = gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n >= 1 {
            return Ok(Response::builder()
                .status(404)
                .body(Full::new(Bytes::from("gone")))
                .unwrap());
        }
        return write_mock_handler(req).await;
    }
    writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    write_mock_handler(req).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_evaluate_holds_when_contained_revert_cannot_be_reestablished() {
    let policy = r#"
default: deny
rules:
  - verbs: [patch]
    resources: [deployments]
    namespaces: [dev]
    action: evaluate
"#;
    let gets = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let writes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (mock_base, _) = spawn_flaky_snapshot_mock(gets.clone(), writes.clone()).await;
    // Recoverable + mid risk: decide_gate returns Contain only because a revert
    // is promised. A gate is attached (so the write is tracked and the marker is
    // constructible at judge time), can_arm_revert is true, but the forward-time
    // snapshot re-fetch 404s, so containment cannot be re-established and the
    // write must be held (RecordingSink's default hold denies → 403).
    let judge = RecordingJudge::new(vec![judge_allow(Some(5), Some(Reversibility::Recoverable))]);
    let sink = RecordingSink::default();
    let (base, client) = start_proxy_with(
        mock_base,
        policy,
        Some(Arc::new(judge)),
        Some(Arc::new(sink)),
        0,
    )
    .await;
    let resp = client
        .patch(format!(
            "{base}/apis/apps/v1/namespaces/dev/deployments/api"
        ))
        .header("content-type", "application/merge-patch+json")
        .body(r#"{"spec":{"replicas":9}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "a contained write whose revert cannot be re-established must be held, not forwarded"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        writes.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the uncontained mutation must never reach the upstream"
    );
}

/// A gate that can never arm a revert (e.g. capacity exhausted, or an unsafe
/// revert directory), and denies any hold.
#[derive(Default)]
struct CannotArmSink {
    writes_armed: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl guard::proxy::GateSink for CannotArmSink {
    async fn can_arm_revert(&self) -> bool {
        false
    }
    async fn arm_revert(&self, _mutation: guard::proxy::ApiMutation) -> Option<String> {
        self.writes_armed
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        None
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_evaluate_holds_when_sink_cannot_arm() {
    let policy = r#"
default: deny
rules:
  - verbs: [patch]
    resources: [deployments]
    namespaces: [dev]
    action: evaluate
"#;
    let (mock_base, gets) = spawn_counting_snapshot_mock().await;
    let judge = RecordingJudge::new(vec![judge_allow(Some(5), Some(Reversibility::Recoverable))]);
    let armed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sink = CannotArmSink {
        writes_armed: armed.clone(),
    };
    let (base, client) = start_proxy_with(
        mock_base,
        policy,
        Some(Arc::new(judge)),
        Some(Arc::new(sink)),
        0,
    )
    .await;
    let resp = client
        .patch(format!(
            "{base}/apis/apps/v1/namespaces/dev/deployments/api"
        ))
        .header("content-type", "application/merge-patch+json")
        .body(r#"{"spec":{"replicas":9}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "a contained write must be held when the sink cannot arm a revert"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        armed.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no revert arming should be attempted for a held write"
    );
    // Only the pre-judge constructibility GET ran; no forward-time fetch and no
    // write, since the request was held before forwarding.
    assert_eq!(gets.load(std::sync::atomic::Ordering::SeqCst), 1);
}

async fn spawn_flaky_snapshot_mock(
    gets: Arc<std::sync::atomic::AtomicUsize>,
    writes: Arc<std::sync::atomic::AtomicUsize>,
) -> (String, ()) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            let gets = gets.clone();
            let writes = writes.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req| {
                            flaky_snapshot_handler(req, gets.clone(), writes.clone())
                        }),
                    )
                    .await;
            });
        }
    });
    (format!("http://{addr}"), ())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_evaluate_reuses_prior_snapshot_for_arming() {
    let policy = r#"
default: deny
rules:
  - verbs: [patch]
    resources: [deployments]
    namespaces: [dev]
    action: evaluate
"#;
    let (mock_base, gets) = spawn_counting_snapshot_mock().await;
    let sink = RecordingSink::default();
    let judge = RecordingJudge::new(vec![judge_allow(Some(4), Some(Reversibility::Recoverable))]);
    let (base, client) = start_proxy_with(
        mock_base,
        policy,
        Some(Arc::new(judge)),
        Some(Arc::new(sink)),
        0,
    )
    .await;
    let resp = client
        .patch(format!(
            "{base}/apis/apps/v1/namespaces/dev/deployments/api"
        ))
        .header("content-type", "application/merge-patch+json")
        .body(r#"{"spec":{"replicas":5}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    tokio::time::sleep(Duration::from_millis(100)).await;
    // The prior object is fetched twice on the evaluate path: once before the
    // judge to decide whether a revert is constructible (an input to the
    // verdict), and again at forward time so the armed revert restores state as
    // it was at the write, not as it was before the evaluator round trip.
    assert_eq!(
        gets.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "evaluate path validates constructibility, then re-fetches fresh for arming"
    );
}
