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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{json, Value};
use tokio_rustls::rustls::{self, pki_types};

use guard::gating::Reversibility;
use guard::proxy::{
    ApiAuthorizationKind, ApiCoverageVerdict, ApiEvaluationMode, ApiForwardHandoff,
    ApiForwardRequirement, ApiHoldSnapshot, ApiJudge, ApiJudgeVerdict, ApiListenerMode, ApiPolicy,
    ApiProxy, ApiRequestSummary, ApiSessionContext, ApiSessionEvent, ApiSessionSink, GateSink,
    ProxyTls, Upstream,
};

const CREATE_PROVENANCE_ANNOTATION: &str = "guard.morgaesis.dev/provisional";
// Keep end-to-end handoff probes bounded without treating shared-runner
// scheduling delays as a failed authority transition.
const PROXY_INTEGRATION_TIMEOUT: Duration = Duration::from_secs(30);
#[derive(Clone, Default)]
struct CreateObservation {
    provenance: Option<String>,
    name: Option<String>,
    namespace: Option<String>,
    body_sha256: Option<String>,
}

type CreateProvenance = Arc<std::sync::Mutex<CreateObservation>>;

async fn reject_test_cleanup(_handoff: &mut dyn ApiForwardHandoff) -> Result<(), String> {
    Err("test cleanup authority is unavailable".to_string())
}

async fn observe_create_provenance(
    request: Request<Incoming>,
    provenance: &CreateProvenance,
) -> (hyper::Method, String) {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    if method == hyper::Method::POST {
        let body = request.into_body().collect().await.unwrap().to_bytes();
        if let Ok(value) = serde_json::from_slice::<Value>(&body) {
            *provenance.lock().unwrap() = CreateObservation {
                provenance: value
                    .pointer(&format!(
                        "/metadata/annotations/{}",
                        CREATE_PROVENANCE_ANNOTATION
                            .replace('~', "~0")
                            .replace('/', "~1")
                    ))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                name: value
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                namespace: value
                    .pointer("/metadata/namespace")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                body_sha256: Some({
                    use sha2::Digest;
                    sha2::Sha256::digest(&body)
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect()
                }),
            };
        }
    }
    (method, path)
}

fn attach_create_provenance(object: &mut Value, provenance: &CreateProvenance) {
    let observation = provenance.lock().unwrap().clone();
    let Some(marker) = observation.provenance else {
        return;
    };
    object["metadata"]["annotations"][CREATE_PROVENANCE_ANNOTATION] = Value::String(marker);
    if let Some(name) = observation.name {
        object["metadata"]["name"] = Value::String(name);
    }
    if let Some(namespace) = observation.namespace {
        object["metadata"]["namespace"] = Value::String(namespace);
    }
}

async fn authorize_test_session(
    sink: &(impl ApiSessionSink + ?Sized),
    token: &str,
    expected: &ApiSessionContext,
    handoff: &mut dyn ApiForwardHandoff,
) -> Result<(), String> {
    if sink.resolve(token).await.as_ref() == Some(expected) {
        handoff.forward().await
    } else {
        Err("session authority changed".to_string())
    }
}

struct LiveSessionSink;

#[async_trait::async_trait]
impl ApiSessionSink for LiveSessionSink {
    async fn resolve(&self, token: &str) -> Option<ApiSessionContext> {
        (token == "live-session").then(|| ApiSessionContext {
            fingerprint: "session-fingerprint".to_string(),
            revision: "live-session-revision".to_string(),
            secret_entitlements: None,
            intent: Some("manage development pods".to_string()),
            evaluation_mode: ApiEvaluationMode::Evaluator,
            can_evaluate_api_override: true,
        })
    }

    async fn authorize_forward(
        &self,
        token: &str,
        expected: &ApiSessionContext,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        authorize_test_session(self, token, expected, handoff).await
    }

    async fn record(&self, _token: &str, _event: ApiSessionEvent) {}
}

struct RestrictedCredentialSessionSink;

#[async_trait::async_trait]
impl ApiSessionSink for RestrictedCredentialSessionSink {
    async fn resolve(&self, token: &str) -> Option<ApiSessionContext> {
        (token == "restricted-session").then(|| ApiSessionContext {
            fingerprint: "restricted-session-fingerprint".to_string(),
            revision: "restricted-session-revision".to_string(),
            secret_entitlements: Some(vec!["another-endpoint/token".to_string()]),
            intent: Some("inspect development pods".to_string()),
            evaluation_mode: ApiEvaluationMode::Evaluator,
            can_evaluate_api_override: true,
        })
    }

    async fn authorize_forward(
        &self,
        token: &str,
        expected: &ApiSessionContext,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        authorize_test_session(self, token, expected, handoff).await
    }

    async fn record(&self, _token: &str, _event: ApiSessionEvent) {}
}

struct H2SessionSink;

#[async_trait::async_trait]
impl ApiSessionSink for H2SessionSink {
    async fn resolve(&self, token: &str) -> Option<ApiSessionContext> {
        (token == "h2-live").then(|| ApiSessionContext {
            fingerprint: "h2-live-authority".to_string(),
            revision: "h2-live-revision".to_string(),
            secret_entitlements: None,
            intent: Some("inspect discovery".to_string()),
            evaluation_mode: ApiEvaluationMode::Evaluator,
            can_evaluate_api_override: true,
        })
    }

    async fn authorize_forward(
        &self,
        token: &str,
        expected: &ApiSessionContext,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        authorize_test_session(self, token, expected, handoff).await
    }

    async fn record(&self, _token: &str, _event: ApiSessionEvent) {}
}

#[derive(Clone, Default)]
struct RecordingSessionSink {
    events: Arc<std::sync::Mutex<Vec<ApiSessionEvent>>>,
}

#[async_trait::async_trait]
impl ApiSessionSink for RecordingSessionSink {
    async fn resolve(&self, token: &str) -> Option<ApiSessionContext> {
        let secret_entitlements = match token {
            "live-session" => None,
            "restricted-session" => Some(vec!["another-endpoint/token".to_string()]),
            _ => return None,
        };
        Some(ApiSessionContext {
            fingerprint: "session-fingerprint".to_string(),
            revision: "live-session-revision".to_string(),
            secret_entitlements,
            intent: Some("manage development pods".to_string()),
            evaluation_mode: ApiEvaluationMode::Evaluator,
            can_evaluate_api_override: true,
        })
    }

    async fn authorize_forward(
        &self,
        token: &str,
        expected: &ApiSessionContext,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        authorize_test_session(self, token, expected, handoff).await
    }

    async fn record(&self, _token: &str, event: ApiSessionEvent) {
        self.events.lock().unwrap().push(event);
    }
}

struct ChangingSessionSink {
    resolutions: AtomicUsize,
}

#[derive(Clone)]
struct LinearizedSessionSink {
    context: ApiSessionContext,
    live: Arc<tokio::sync::RwLock<Option<ApiSessionContext>>>,
    reached_handoff: Arc<tokio::sync::Semaphore>,
    release_handoff: Arc<tokio::sync::Semaphore>,
    pause_handoff: bool,
}

impl LinearizedSessionSink {
    fn new(pause_handoff: bool) -> Self {
        let context = ApiSessionContext {
            fingerprint: "linearized-session".to_string(),
            revision: "linearized-revision".to_string(),
            secret_entitlements: None,
            intent: Some("inspect development resources".to_string()),
            evaluation_mode: ApiEvaluationMode::Evaluator,
            can_evaluate_api_override: true,
        };
        Self {
            live: Arc::new(tokio::sync::RwLock::new(Some(context.clone()))),
            context,
            reached_handoff: Arc::new(tokio::sync::Semaphore::new(0)),
            release_handoff: Arc::new(tokio::sync::Semaphore::new(0)),
            pause_handoff,
        }
    }
}

#[async_trait::async_trait]
impl ApiSessionSink for LinearizedSessionSink {
    async fn resolve(&self, token: &str) -> Option<ApiSessionContext> {
        if token != "live-session" {
            return None;
        }
        self.live.read().await.clone()
    }

    async fn authorize_forward(
        &self,
        token: &str,
        expected: &ApiSessionContext,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        if token != "live-session" {
            return Err("unknown session".to_string());
        }
        let guard = self.live.clone().read_owned().await;
        if guard.as_ref() != Some(expected) {
            return Err("session authority changed".to_string());
        }
        self.reached_handoff.add_permits(1);
        if self.pause_handoff {
            self.release_handoff
                .acquire()
                .await
                .map_err(|_| "session handoff closed".to_string())?
                .forget();
        }
        let result = handoff.forward().await;
        drop(guard);
        result
    }

    async fn record(&self, _token: &str, _event: ApiSessionEvent) {}
}

struct PrincipalSessionSink;

#[async_trait::async_trait]
impl ApiSessionSink for PrincipalSessionSink {
    async fn resolve(&self, token: &str) -> Option<ApiSessionContext> {
        let fingerprint = match token {
            "principal-a" => "principal-a-fingerprint",
            "principal-b" => "principal-b-fingerprint",
            _ => return None,
        };
        Some(ApiSessionContext {
            fingerprint: fingerprint.to_string(),
            revision: "authority-revision-1".to_string(),
            secret_entitlements: None,
            intent: Some("manage one development deployment".to_string()),
            evaluation_mode: ApiEvaluationMode::Evaluator,
            can_evaluate_api_override: false,
        })
    }

    async fn authorize_forward(
        &self,
        token: &str,
        expected: &ApiSessionContext,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        authorize_test_session(self, token, expected, handoff).await
    }

    async fn record(&self, _token: &str, _event: ApiSessionEvent) {}
}

#[derive(Clone)]
struct BudgetSessionSink {
    remaining_resolutions: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ApiSessionSink for BudgetSessionSink {
    async fn resolve(&self, token: &str) -> Option<ApiSessionContext> {
        if token != "budget-session" {
            return None;
        }
        let admitted = self
            .remaining_resolutions
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                (remaining > 0).then(|| remaining - 1)
            })
            .is_ok();
        admitted.then(|| ApiSessionContext {
            fingerprint: "budget-session-authority".to_string(),
            revision: "budget-session-revision".to_string(),
            secret_entitlements: None,
            intent: Some("manage development pods".to_string()),
            evaluation_mode: ApiEvaluationMode::Evaluator,
            can_evaluate_api_override: true,
        })
    }

    async fn authorize_forward(
        &self,
        token: &str,
        expected: &ApiSessionContext,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        if token == "budget-session" && expected.revision == "budget-session-revision" {
            handoff.forward().await
        } else {
            Err("session authority changed".to_string())
        }
    }

    async fn record(&self, _token: &str, _event: ApiSessionEvent) {}
}

#[async_trait::async_trait]
impl ApiSessionSink for ChangingSessionSink {
    async fn resolve(&self, token: &str) -> Option<ApiSessionContext> {
        let attempt = self.resolutions.fetch_add(1, Ordering::SeqCst);
        (token == "live-then-edited").then(|| ApiSessionContext {
            fingerprint: "stable-audit-fingerprint".to_string(),
            revision: if attempt < 5 {
                "original-session-revision"
            } else {
                "edited-session-revision"
            }
            .to_string(),
            secret_entitlements: None,
            intent: Some("manage development pods".to_string()),
            evaluation_mode: ApiEvaluationMode::Evaluator,
            can_evaluate_api_override: true,
        })
    }

    async fn authorize_forward(
        &self,
        token: &str,
        expected: &ApiSessionContext,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        authorize_test_session(self, token, expected, handoff).await
    }

    async fn record(&self, _token: &str, _event: ApiSessionEvent) {}
}

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
    } else if req.method() == hyper::Method::GET && path.contains("/pods/") {
        json!({
            "kind": "Pod",
            "apiVersion": "v1",
            "metadata": {
                "name": "web-0",
                "namespace": "dev",
                "uid": "web-0-uid",
                "resourceVersion": "12"
            },
            "spec": {"containers": []}
        })
    } else {
        json!({"kind": "Status", "apiVersion": "v1", "status": "Success"})
    };
    Ok(Response::builder()
        .header("content-type", "application/json")
        .header("set-cookie", "upstream-session=secret")
        .header("authorization", "Bearer upstream-response-secret")
        .header("www-authenticate", "Bearer realm=upstream")
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

async fn spawn_counting_upstream() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let observed = count.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => continue,
            };
            let requests = observed.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |request| {
                            requests.fetch_add(1, Ordering::SeqCst);
                            mock_handler(request)
                        }),
                    )
                    .await;
            });
        }
    });
    (format!("http://{addr}"), count)
}

async fn spawn_stalled_upstream() -> (String, Arc<tokio::sync::Semaphore>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let reached = Arc::new(tokio::sync::Semaphore::new(0));
    let observed = reached.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => continue,
            };
            let reached = observed.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |_request| {
                            reached.add_permits(1);
                            std::future::pending::<Result<Response<Full<Bytes>>, Infallible>>()
                        }),
                    )
                    .await;
            });
        }
    });
    (format!("http://{addr}"), reached)
}

async fn spawn_success_headers_stalled_body() -> String {
    type MockBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let provenance = CreateProvenance::default();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let provenance = provenance.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let provenance = provenance.clone();
                    async move {
                        let (method, path) = observe_create_provenance(request, &provenance).await;
                        if method == hyper::Method::GET {
                            let mut object = created_pod_object();
                            if let Some(name) = path.rsplit('/').next() {
                                object["metadata"]["name"] = Value::String(name.to_string());
                            }
                            attach_create_provenance(&mut object, &provenance);
                            let body = Full::new(Bytes::from(object.to_string()))
                                .map_err(std::io::Error::other)
                                .boxed();
                            return Ok::<Response<MockBody>, Infallible>(
                                Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .body(body)
                                    .unwrap(),
                            );
                        }
                        let frames =
                            futures::stream::pending::<Result<Frame<Bytes>, std::io::Error>>();
                        Ok(Response::builder()
                            .status(201)
                            .header("content-type", "application/json")
                            .body(StreamBody::new(frames).boxed())
                            .unwrap())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

async fn spawn_create_status_upstream(
    status: u16,
    content_encoding: Option<&'static str>,
) -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let deletes = Arc::new(AtomicUsize::new(0));
    let observed_deletes = deletes.clone();
    let provenance = CreateProvenance::default();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let deletes = observed_deletes.clone();
            let provenance = provenance.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let deletes = deletes.clone();
                    let provenance = provenance.clone();
                    async move {
                        let (method, path) = observe_create_provenance(request, &provenance).await;
                        let mut builder =
                            Response::builder().header("content-type", "application/json");
                        let response_status = if method == hyper::Method::POST {
                            status
                        } else if method == hyper::Method::DELETE {
                            deletes.fetch_add(1, Ordering::SeqCst);
                            200
                        } else {
                            200
                        };
                        if let Some(encoding) = content_encoding {
                            builder = builder.header("content-encoding", encoding);
                        }
                        let mut object = created_pod_object();
                        if method == hyper::Method::GET {
                            if let Some(name) = path.rsplit('/').next() {
                                object["metadata"]["name"] = Value::String(name.to_string());
                            }
                        }
                        attach_create_provenance(&mut object, &provenance);
                        Ok::<_, Infallible>(
                            builder
                                .status(response_status)
                                .body(Full::new(Bytes::from(object.to_string())))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (format!("http://{addr}"), deletes)
}

#[derive(Clone, Copy)]
enum OversizedBodyKind {
    Declared,
    Chunked,
}

async fn spawn_oversized_body_upstream(kind: OversizedBodyKind) -> String {
    type MockBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(move |_request: Request<Incoming>| async move {
                    let body: MockBody = match kind {
                        OversizedBodyKind::Declared => Full::new(Bytes::from(vec![b'x'; 129]))
                            .map_err(std::io::Error::other)
                            .boxed(),
                        OversizedBodyKind::Chunked => {
                            let frames = futures::stream::iter([
                                Ok::<_, std::io::Error>(Frame::data(Bytes::from(vec![b'x'; 65]))),
                                Ok(Frame::data(Bytes::from(vec![b'y'; 65]))),
                            ]);
                            StreamBody::new(frames).boxed()
                        }
                    };
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(body)
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

async fn spawn_cleanup_oversized_upstream(kind: OversizedBodyKind) -> String {
    type MockBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let provenance = CreateProvenance::default();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let provenance = provenance.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let provenance = provenance.clone();
                    async move {
                        let (method, path) = observe_create_provenance(request, &provenance).await;
                        if method == hyper::Method::DELETE {
                            let body: MockBody = match kind {
                                OversizedBodyKind::Declared => {
                                    Full::new(Bytes::from(vec![b'x'; 513]))
                                        .map_err(std::io::Error::other)
                                        .boxed()
                                }
                                OversizedBodyKind::Chunked => {
                                    let frames = futures::stream::iter([
                                        Ok::<_, std::io::Error>(Frame::data(Bytes::from(vec![
                                            b'x';
                                            257
                                        ]))),
                                        Ok(Frame::data(Bytes::from(vec![b'y'; 257]))),
                                    ]);
                                    StreamBody::new(frames).boxed()
                                }
                            };
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .body(body)
                                    .unwrap(),
                            );
                        }
                        let mut object = created_pod_object();
                        if let Some(name) = path
                            .rsplit('/')
                            .next()
                            .filter(|_| method == hyper::Method::GET)
                        {
                            object["metadata"]["name"] = Value::String(name.to_string());
                        }
                        attach_create_provenance(&mut object, &provenance);
                        let status = if method == hyper::Method::POST {
                            201
                        } else {
                            200
                        };
                        Ok(Response::builder()
                            .status(status)
                            .header("content-type", "application/json")
                            .body(
                                Full::new(Bytes::from(object.to_string()))
                                    .map_err(std::io::Error::other)
                                    .boxed(),
                            )
                            .unwrap())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

async fn spawn_transport_error_upstream() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(|_request: Request<Incoming>| async move {
                    Err::<Response<Full<Bytes>>, _>(std::io::Error::other(
                        "simulated upstream transport failure",
                    ))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

async fn spawn_replaceable_create_upstream() -> (String, Arc<AtomicBool>, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let replacement = Arc::new(AtomicBool::new(false));
    let deletes = Arc::new(AtomicUsize::new(0));
    let state = replacement.clone();
    let observed_deletes = deletes.clone();
    let provenance = CreateProvenance::default();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let replacement = state.clone();
            let deletes = observed_deletes.clone();
            let provenance = provenance.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let replacement = replacement.clone();
                    let deletes = deletes.clone();
                    let provenance = provenance.clone();
                    async move {
                        let (method, path) = observe_create_provenance(request, &provenance).await;
                        if method == hyper::Method::DELETE {
                            deletes.fetch_add(1, Ordering::SeqCst);
                        }
                        let mut object = created_pod_object();
                        if let Some(name) = path.rsplit('/').next() {
                            object["metadata"]["name"] = Value::String(name.to_string());
                        }
                        attach_create_provenance(&mut object, &provenance);
                        if replacement.load(Ordering::SeqCst) {
                            object["metadata"]["uid"] =
                                Value::String("replacement-resource-uid".to_string());
                        }
                        let status = if method == hyper::Method::POST {
                            201
                        } else {
                            200
                        };
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(object.to_string())))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (format!("http://{addr}"), replacement, deletes)
}

async fn spawn_create_without_get_upstream() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gets = Arc::new(AtomicUsize::new(0));
    let observed_gets = gets.clone();
    let provenance = CreateProvenance::default();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let provenance = provenance.clone();
            let gets = observed_gets.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let provenance = provenance.clone();
                    let gets = gets.clone();
                    async move {
                        let (method, _) = observe_create_provenance(request, &provenance).await;
                        if method == hyper::Method::GET {
                            gets.fetch_add(1, Ordering::SeqCst);
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(403)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            );
                        }
                        let mut object = created_pod_object();
                        attach_create_provenance(&mut object, &provenance);
                        Ok(Response::builder()
                            .status(201)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(object.to_string())))
                            .unwrap())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (format!("http://{addr}"), gets)
}

async fn spawn_policy_barrier_upstream(
    block_method: hyper::Method,
) -> (
    String,
    Arc<tokio::sync::Semaphore>,
    Arc<tokio::sync::Semaphore>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let reached = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let observed = reached.clone();
    let continuation = release.clone();
    let provenance = CreateProvenance::default();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let reached = observed.clone();
            let release = continuation.clone();
            let block_method = block_method.clone();
            let provenance = provenance.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let reached = reached.clone();
                    let release = release.clone();
                    let block_method = block_method.clone();
                    let provenance = provenance.clone();
                    async move {
                        let (method, _) = observe_create_provenance(request, &provenance).await;
                        if method == block_method {
                            reached.add_permits(1);
                            release.acquire().await.unwrap().forget();
                        }
                        let status = if method == hyper::Method::POST {
                            201
                        } else {
                            200
                        };
                        let mut object = created_pod_object();
                        attach_create_provenance(&mut object, &provenance);
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(object.to_string())))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (format!("http://{addr}"), reached, release)
}

#[derive(Clone)]
struct ArbitrationMock {
    object: Arc<std::sync::Mutex<Value>>,
    forwarded_mutations: Arc<AtomicUsize>,
    mutation_bodies: Arc<std::sync::Mutex<Vec<(hyper::Method, Value)>>>,
    mutation_digests: Arc<std::sync::Mutex<Vec<String>>>,
}

impl ArbitrationMock {
    fn new() -> Self {
        Self {
            object: Arc::new(std::sync::Mutex::new(json!({
                "kind": "Deployment",
                "apiVersion": "apps/v1",
                "metadata": {
                    "name": "api",
                    "namespace": "dev",
                    "uid": "deployment-uid",
                    "resourceVersion": "1",
                    "labels": {"owner": "platform"}
                },
                "spec": {"replicas": 2},
                "status": {"readyReplicas": 2}
            }))),
            forwarded_mutations: Arc::new(AtomicUsize::new(0)),
            mutation_bodies: Arc::new(std::sync::Mutex::new(Vec::new())),
            mutation_digests: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn advance_status(&self) {
        let mut object = self.object.lock().unwrap();
        let next = next_resource_version(&object);
        object["metadata"]["resourceVersion"] = json!(next);
        object["status"]["readyReplicas"] = json!(1);
    }

    fn advance_spec(&self) {
        let mut object = self.object.lock().unwrap();
        let next = next_resource_version(&object);
        object["metadata"]["resourceVersion"] = json!(next);
        object["spec"]["replicas"] = json!(7);
    }
}

fn next_resource_version(object: &Value) -> String {
    object["metadata"]["resourceVersion"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap()
        .saturating_add(1)
        .to_string()
}

async fn arbitration_mock_handler(
    req: Request<Incoming>,
    mock: ArbitrationMock,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() == hyper::Method::GET {
        let object = mock.object.lock().unwrap().clone();
        return Ok(Response::builder()
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(object.to_string())))
            .unwrap());
    }

    mock.forwarded_mutations.fetch_add(1, Ordering::SeqCst);
    let method = req.method().clone();
    let bytes = req.into_body().collect().await.unwrap().to_bytes();
    mock.mutation_digests.lock().unwrap().push({
        use sha2::Digest;
        sha2::Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    });
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    mock.mutation_bodies
        .lock()
        .unwrap()
        .push((method.clone(), body.clone()));
    let mut object = mock.object.lock().unwrap();
    let expected_uid = object["metadata"]["uid"].as_str().unwrap();
    let expected_version = object["metadata"]["resourceVersion"].as_str().unwrap();
    let guarded = match method {
        hyper::Method::PUT => {
            body["metadata"]["resourceVersion"].as_str() == Some(expected_version)
        }
        hyper::Method::PATCH if body.is_array() => body.as_array().is_some_and(|operations| {
            operations.first().is_some_and(|operation| {
                operation["op"] == "test"
                    && operation["path"] == "/metadata/uid"
                    && operation["value"] == expected_uid
            }) && operations.get(1).is_some_and(|operation| {
                operation["op"] == "test"
                    && operation["path"] == "/metadata/resourceVersion"
                    && operation["value"] == expected_version
            })
        }),
        hyper::Method::PATCH => {
            body["metadata"]["resourceVersion"].as_str() == Some(expected_version)
        }
        hyper::Method::DELETE => {
            body["preconditions"]["uid"].as_str() == Some(expected_uid)
                && body["preconditions"]["resourceVersion"].as_str() == Some(expected_version)
        }
        hyper::Method::POST => true,
        _ => false,
    };
    if !guarded {
        return Ok(Response::builder()
            .status(409)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(
                json!({"kind":"Status","status":"Failure","reason":"Conflict","code":409})
                    .to_string(),
            )))
            .unwrap());
    }
    if method == hyper::Method::DELETE {
        return Ok(Response::builder()
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(
                json!({"kind":"Status","status":"Success"}).to_string(),
            )))
            .unwrap());
    }
    if let Some(replicas) = body.pointer("/spec/replicas").cloned() {
        object["spec"]["replicas"] = replicas;
    }
    let next = next_resource_version(&object);
    object["metadata"]["resourceVersion"] = json!(next);
    Ok(Response::builder()
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(object.to_string())))
        .unwrap())
}

async fn spawn_arbitration_mock() -> (String, ArbitrationMock) {
    let mock = ArbitrationMock::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_mock = mock.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let connection_mock = server_mock.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    arbitration_mock_handler(request, connection_mock.clone())
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (format!("http://{addr}"), mock)
}

async fn spawn_blocking_arbitration_mock(
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
) -> (String, ArbitrationMock) {
    let mock = ArbitrationMock::new();
    let get_count = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_mock = mock.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let connection_mock = server_mock.clone();
            let connection_get_count = get_count.clone();
            let connection_started = started.clone();
            let connection_release = release.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let request_mock = connection_mock.clone();
                    let request_get_count = connection_get_count.clone();
                    let request_started = connection_started.clone();
                    let request_release = connection_release.clone();
                    async move {
                        if request.method() == hyper::Method::GET
                            && request_get_count.fetch_add(1, Ordering::SeqCst) == 1
                        {
                            request_started.notify_one();
                            request_release.notified().await;
                        }
                        arbitration_mock_handler(request, request_mock).await
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (format!("http://{addr}"), mock)
}

async fn start_arbitration_proxy(
    upstream_base: &str,
    mode: Option<ApiListenerMode>,
) -> (String, reqwest::Client) {
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(upstream_base), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml("default: allow\n").unwrap();
    let (listener, listen) = reserve_listener().await;
    let mut proxy = ApiProxy::new(listen, tls, upstream, policy, None);
    if let Some(mode) = mode {
        proxy = proxy.with_listener_mode(mode);
    }
    let proxy = Arc::new(proxy);
    proxy.attach_session_sink(Arc::new(PrincipalSessionSink));
    tokio::spawn(proxy.serve_on(listener));
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    (format!("https://{listen}"), client)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_default_listener_cannot_mutate_under_allow_policy() {
    let (upstream, mock) = spawn_arbitration_mock().await;
    let (base, client) = start_arbitration_proxy(&upstream, None).await;

    for response in [
        client
            .post(format!("{base}/api/v1/namespaces/dev/configmaps"))
            .body("{}")
            .send()
            .await
            .unwrap(),
        client
            .patch(format!(
                "{base}/apis/apps/v1/namespaces/dev/deployments/api"
            ))
            .header("content-type", "application/merge-patch+json")
            .body(r#"{"spec":{"replicas":3}}"#)
            .send()
            .await
            .unwrap(),
    ] {
        assert_eq!(response.status(), 403);
        assert!(response.text().await.unwrap().contains("attributable"));
    }
    assert_eq!(mock.forwarded_mutations.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn observations_are_principal_bound_and_arbitrate_interleaved_writes() {
    let (upstream, mock) = spawn_arbitration_mock().await;
    let (base, client) = start_arbitration_proxy(&upstream, Some(ApiListenerMode::Policy)).await;
    let object_url = format!("{base}/apis/apps/v1/namespaces/dev/deployments/api");

    let observed_by_a = client
        .get(&object_url)
        .bearer_auth("principal-a")
        .send()
        .await
        .unwrap();
    assert_eq!(observed_by_a.status(), 200);

    let unobserved_b = client
        .patch(&object_url)
        .bearer_auth("principal-b")
        .header("content-type", "application/merge-patch+json")
        .body(r#"{"spec":{"replicas":3}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(unobserved_b.status(), 409);
    assert_eq!(mock.forwarded_mutations.load(Ordering::SeqCst), 0);

    assert_eq!(
        client
            .get(&object_url)
            .bearer_auth("principal-b")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .patch(&object_url)
            .bearer_auth("principal-a")
            .header("content-type", "application/merge-patch+json")
            .body(r#"{"spec":{"replicas":3}}"#)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let stale_b = client
        .patch(&object_url)
        .bearer_auth("principal-b")
        .header("content-type", "application/merge-patch+json")
        .body(r#"{"spec":{"replicas":4}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(stale_b.status(), 409);
    assert_eq!(mock.forwarded_mutations.load(Ordering::SeqCst), 1);

    mock.advance_status();
    let status_churn = client
        .put(&object_url)
        .bearer_auth("principal-a")
        .header("content-type", "application/json")
        .body(r#"{"metadata":{"name":"api","namespace":"dev"},"spec":{"replicas":5}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(status_churn.status(), 200);
    {
        let bodies = mock.mutation_bodies.lock().unwrap();
        assert_eq!(bodies.last().unwrap().0, hyper::Method::PUT);
        assert_eq!(
            bodies.last().unwrap().1["metadata"]["resourceVersion"],
            "3",
            "status-only churn advances the atomic precondition to the live version"
        );
    }

    mock.advance_spec();
    let conflicting_spec = client
        .delete(&object_url)
        .bearer_auth("principal-a")
        .send()
        .await
        .unwrap();
    assert_eq!(conflicting_spec.status(), 409);
    assert_eq!(mock.forwarded_mutations.load(Ordering::SeqCst), 2);

    assert_eq!(
        client
            .get(&object_url)
            .bearer_auth("principal-a")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .delete(&object_url)
            .bearer_auth("principal-a")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let bodies = mock.mutation_bodies.lock().unwrap();
    let delete = bodies.last().unwrap();
    assert_eq!(delete.0, hyper::Method::DELETE);
    assert_eq!(delete.1["preconditions"]["uid"], "deployment-uid");
    assert_eq!(delete.1["preconditions"]["resourceVersion"], "5");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn held_kubernetes_mutations_approve_the_exact_guarded_bytes() {
    let cases = [
        (
            reqwest::Method::PUT,
            Some("application/json"),
            Some(r#"{"metadata":{"name":"api","namespace":"dev"},"spec":{"replicas":3}}"#),
        ),
        (
            reqwest::Method::PATCH,
            Some("application/merge-patch+json"),
            Some(r#"{"spec":{"replicas":3}}"#),
        ),
        (
            reqwest::Method::PATCH,
            Some("application/json-patch+json"),
            Some(r#"[{"op":"replace","path":"/spec/replicas","value":3}]"#),
        ),
        (reqwest::Method::DELETE, None, None),
    ];
    for (method, content_type, body) in cases {
        let (upstream, mock) = spawn_arbitration_mock().await;
        let upstream =
            Upstream::from_kubeconfig_str(&kubeconfig_for(&upstream), None).expect("upstream");
        let tls = ProxyTls::generate().expect("tls");
        let ca_pem = tls.ca_pem().to_string();
        let policy = ApiPolicy::from_yaml(
            "default: deny\nrules:\n  - verbs: [get]\n    resources: [deployments]\n    namespaces: [dev]\n    action: allow\n  - verbs: [update, patch, delete]\n    resources: [deployments]\n    namespaces: [dev]\n    action: hold\n",
        )
        .unwrap();
        let (listener, listen) = reserve_listener().await;
        let proxy = Arc::new(
            ApiProxy::new(listen, tls, upstream, policy, None)
                .with_listener_mode(ApiListenerMode::Policy),
        );
        let sink = SnapshotSink::default();
        proxy.attach_gate(Arc::new(sink.clone()));
        proxy.attach_session_sink(Arc::new(PrincipalSessionSink));
        tokio::spawn(proxy.serve_on(listener));
        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
            .build()
            .unwrap();
        let url = format!("https://{listen}/apis/apps/v1/namespaces/dev/deployments/api");
        assert_eq!(
            client
                .get(&url)
                .bearer_auth("principal-a")
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        let mut request = client
            .request(method.clone(), &url)
            .bearer_auth("principal-a");
        if let Some(content_type) = content_type {
            request = request.header("content-type", content_type);
        }
        if let Some(body) = body {
            request = request.body(body);
        }
        let response = request.send().await.unwrap();
        let status = response.status();
        let detail = response.text().await.unwrap();
        assert!(
            status.is_success(),
            "{method} ({content_type:?}) approval returned {status}: {detail}"
        );
        let snapshots = sink.snapshots.lock().unwrap();
        let digests = mock.mutation_digests.lock().unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(digests.len(), 1);
        assert_eq!(snapshots[0].body_sha256, digests[0]);
    }
}

fn guarded_mutation_cases() -> Vec<(reqwest::Method, Option<&'static str>, Option<&'static str>)> {
    vec![
        (
            reqwest::Method::PUT,
            Some("application/json"),
            Some(r#"{"metadata":{"name":"api","namespace":"dev"},"spec":{"replicas":3}}"#),
        ),
        (
            reqwest::Method::PATCH,
            Some("application/merge-patch+json"),
            Some(r#"{"spec":{"replicas":3}}"#),
        ),
        (
            reqwest::Method::PATCH,
            Some("application/json-patch+json"),
            Some(r#"[{"op":"replace","path":"/spec/replicas","value":3}]"#),
        ),
        (reqwest::Method::DELETE, None, None),
    ]
}

async fn send_guarded_mutation(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    method: reqwest::Method,
    content_type: Option<&str>,
    body: Option<&str>,
) -> reqwest::StatusCode {
    let url = format!("{base}/apis/apps/v1/namespaces/dev/deployments/api");
    assert_eq!(
        client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let mut request = client.request(method, url).bearer_auth(token);
    if let Some(content_type) = content_type {
        request = request.header("content-type", content_type);
    }
    if let Some(body) = body {
        request = request.body(body.to_string());
    }
    request.send().await.unwrap().status()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evaluator_consequence_holds_bind_every_guarded_mutation_byte() {
    let policy = "default: deny\nrules:\n  - verbs: [get]\n    resources: [deployments]\n    namespaces: [dev]\n    action: allow\n  - verbs: [update, patch, delete]\n    resources: [deployments]\n    namespaces: [dev]\n    action: evaluate\n";
    for (method, content_type, body) in guarded_mutation_cases() {
        let (upstream, mock) = spawn_arbitration_mock().await;
        let judge = RecordingJudge::new(vec![judge_allow(
            Some(9),
            Some(Reversibility::Irreversible),
        )]);
        let summaries = judge.summaries.clone();
        let sink = SnapshotSink::default();
        let (base, client) = start_proxy_with(
            upstream,
            policy,
            Some(Arc::new(judge)),
            Some(Arc::new(sink.clone())),
            0,
        )
        .await;
        assert!(
            send_guarded_mutation(&client, &base, "live-session", method, content_type, body)
                .await
                .is_success()
        );
        let digest = mock.mutation_digests.lock().unwrap()[0].clone();
        assert_eq!(summaries.lock().unwrap()[0].authorized_body_sha256, digest);
        assert_eq!(sink.snapshots.lock().unwrap()[0].body_sha256, digest);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_evaluator_paths_bind_the_final_guarded_bytes() {
    let policy = "default: deny\nrules:\n  - verbs: [get]\n    resources: [deployments]\n    namespaces: [dev]\n    action: allow\n  - verbs: [patch]\n    resources: [deployments]\n    namespaces: [dev]\n    action: evaluate\n";
    for verdict in [
        judge_allow(Some(1), Some(Reversibility::Reversible)),
        judge_allow(Some(4), Some(Reversibility::Recoverable)),
    ] {
        let (upstream, mock) = spawn_arbitration_mock().await;
        let judge = RecordingJudge::new(vec![verdict]);
        let summaries = judge.summaries.clone();
        let sink = RecordingSink::default();
        let (base, client) = start_proxy_with(
            upstream,
            policy,
            Some(Arc::new(judge)),
            Some(Arc::new(sink)),
            0,
        )
        .await;
        assert!(send_guarded_mutation(
            &client,
            &base,
            "live-session",
            reqwest::Method::PATCH,
            Some("application/json-patch+json"),
            Some(r#"[{"op":"replace","path":"/spec/replicas","value":3}]"#),
        )
        .await
        .is_success());
        assert_eq!(
            summaries.lock().unwrap()[0].authorized_body_sha256,
            mock.mutation_digests.lock().unwrap()[0]
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rarity_and_coverage_holds_bind_every_guarded_mutation_byte() {
    type CoverageCase = (
        Option<Arc<dyn ApiJudge>>,
        u64,
        Arc<dyn ApiSessionSink>,
        &'static str,
    );
    let allow_policy = "default: deny\nrules:\n  - verbs: [get, update, patch, delete]\n    resources: [deployments]\n    namespaces: [dev]\n    action: allow\n";
    for coverage in [false, true] {
        for (method, content_type, body) in guarded_mutation_cases() {
            let (upstream, mock) = spawn_arbitration_mock().await;
            let sink = SnapshotSink::default();
            let coverage_judge = HeldCoverageJudge::default();
            let summaries = coverage_judge.summaries.clone();
            let (judge, rarity, session_sink, token): CoverageCase = if coverage {
                (
                    Some(Arc::new(coverage_judge)),
                    0,
                    Arc::new(ModeSessionSink),
                    "readonly",
                )
            } else {
                (None, 1, Arc::new(LiveSessionSink), "live-session")
            };
            let (base, client) = start_proxy_with_session_sink(
                upstream,
                allow_policy,
                judge,
                Some(Arc::new(sink.clone())),
                rarity,
                session_sink,
            )
            .await;
            assert!(
                send_guarded_mutation(&client, &base, token, method, content_type, body)
                    .await
                    .is_success()
            );
            let digest = mock.mutation_digests.lock().unwrap()[0].clone();
            assert_eq!(
                sink.snapshots.lock().unwrap().last().unwrap().body_sha256,
                digest
            );
            if coverage {
                let summaries = summaries.lock().unwrap();
                assert_eq!(summaries[0].authorized_body_sha256, digest);
                assert_ne!(
                    summaries[0].coverage_body_shape, summaries[0].redacted_body_shape,
                    "guard preconditions must be excluded from coverage identity"
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn object_change_after_hold_cannot_rewrite_approved_mutation_bytes() {
    let (upstream, mock) = spawn_arbitration_mock().await;
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(&upstream), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(
        "default: deny\nrules:\n  - verbs: [get]\n    resources: [deployments]\n    namespaces: [dev]\n    action: allow\n  - verbs: [patch]\n    resources: [deployments]\n    namespaces: [dev]\n    action: hold\n",
    )
    .unwrap();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, None)
            .with_listener_mode(ApiListenerMode::Policy),
    );
    let sink = BlockingSnapshotSink::default();
    proxy.attach_gate(Arc::new(sink.clone()));
    proxy.attach_session_sink(Arc::new(PrincipalSessionSink));
    tokio::spawn(proxy.serve_on(listener));
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let url = format!("https://{listen}/apis/apps/v1/namespaces/dev/deployments/api");
    assert_eq!(
        client
            .get(&url)
            .bearer_auth("principal-a")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let pending = tokio::spawn({
        let client = client.clone();
        let url = url.clone();
        async move {
            client
                .patch(url)
                .bearer_auth("principal-a")
                .header("content-type", "application/merge-patch+json")
                .body(r#"{"spec":{"replicas":3}}"#)
                .send()
                .await
                .unwrap()
        }
    });
    sink.reached.acquire().await.unwrap().forget();
    mock.advance_spec();
    sink.release.add_permits(1);
    assert_eq!(pending.await.unwrap().status(), 409);
    let snapshots = sink.state.snapshots.lock().unwrap();
    let digests = mock.mutation_digests.lock().unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(digests.len(), 1);
    assert_eq!(snapshots[0].body_sha256, digests[0]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_reload_during_arbitration_prevents_mutable_forwarding() {
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let (upstream_base, mock) =
        spawn_blocking_arbitration_mock(started.clone(), release.clone()).await;
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(&upstream_base), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let temp = tempfile::tempdir().unwrap();
    let policy_path = temp.path().join("api-policy.yaml");
    let allow_policy = "default: allow\n";
    std::fs::write(&policy_path, allow_policy).unwrap();
    let policy = ApiPolicy::load_file(&policy_path).unwrap();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, Some(policy_path.clone()))
            .with_listener_mode(ApiListenerMode::Policy)
            .with_policy_reload_interval(Duration::from_millis(50)),
    );
    proxy.attach_session_sink(Arc::new(PrincipalSessionSink));
    tokio::spawn(proxy.clone().serve_on(listener));
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let object_url = format!("https://{listen}/apis/apps/v1/namespaces/dev/deployments/api");
    assert_eq!(
        client
            .get(&object_url)
            .bearer_auth("principal-a")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    let request = tokio::spawn({
        let client = client.clone();
        let object_url = object_url.clone();
        async move {
            client
                .patch(object_url)
                .bearer_auth("principal-a")
                .header("content-type", "application/merge-patch+json")
                .body(r#"{"spec":{"replicas":3}}"#)
                .send()
                .await
                .unwrap()
        }
    });
    started.notified().await;
    let deny_policy = "default: deny\n";
    let authority_baseline = proxy.authority_transition_generation();
    std::fs::write(&policy_path, deny_policy).unwrap();
    tokio::time::timeout(
        Duration::from_secs(3),
        proxy.wait_for_authority_transition_after(authority_baseline),
    )
    .await
    .expect("policy reloader publishes odd authority before arbitration release");
    release.notify_one();

    assert_eq!(request.await.unwrap().status(), 403);
    assert_eq!(mock.forwarded_mutations.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_handoff_holds_authority_until_upstream_response_headers() {
    let (upstream_base, read_reached, release_read) =
        spawn_policy_barrier_upstream(hyper::Method::GET).await;
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(&upstream_base), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let temp = tempfile::tempdir().unwrap();
    let policy_path = temp.path().join("api-policy.yaml");
    let allow_policy = "default: allow\n";
    std::fs::write(&policy_path, allow_policy).unwrap();
    let policy = ApiPolicy::load_file(&policy_path).unwrap();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, Some(policy_path.clone()))
            .with_listener_mode(ApiListenerMode::Policy)
            .with_policy_reload_interval(Duration::from_millis(50)),
    );
    proxy.attach_session_sink(Arc::new(PrincipalSessionSink));
    tokio::spawn(proxy.clone().serve_on(listener));
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let url = format!("https://{listen}/api/v1/namespaces/dev/configmaps/cm");
    let request = tokio::spawn({
        let client = client.clone();
        let url = url.clone();
        async move {
            client
                .get(url)
                .bearer_auth("principal-a")
                .send()
                .await
                .unwrap()
        }
    });
    read_reached.acquire().await.unwrap().forget();
    let deny_policy = "default: deny\n";
    let authority_baseline = proxy.authority_transition_generation();
    std::fs::write(&policy_path, deny_policy).unwrap();
    tokio::time::timeout(
        Duration::from_secs(3),
        proxy.wait_for_authority_transition_after(authority_baseline),
    )
    .await
    .expect("policy reloader reaches authority coordination");
    release_read.add_permits(1);
    assert_eq!(request.await.unwrap().status(), 200);
    wait_for_policy_reload(&proxy, deny_policy).await;
    assert_eq!(
        client
            .get(url)
            .bearer_auth("principal-a")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evaluated_read_handoff_holds_authority_until_upstream_response_headers() {
    let (upstream_base, read_reached, release_read) =
        spawn_policy_barrier_upstream(hyper::Method::GET).await;
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(&upstream_base), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let temp = tempfile::tempdir().unwrap();
    let policy_path = temp.path().join("api-policy.yaml");
    let evaluate_policy = "default: deny\nrules:\n  - verbs: [get]\n    resources: [configmaps]\n    namespaces: [dev]\n    action: evaluate\n";
    std::fs::write(&policy_path, evaluate_policy).unwrap();
    let policy = ApiPolicy::load_file(&policy_path).unwrap();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, Some(policy_path.clone()))
            .with_listener_mode(ApiListenerMode::Policy)
            .with_policy_reload_interval(Duration::from_millis(50)),
    );
    proxy
        .attach_judge(Arc::new(RecordingJudge::new(vec![judge_allow(
            Some(1),
            Some(Reversibility::Reversible),
        )])))
        .await;
    proxy.attach_session_sink(Arc::new(PrincipalSessionSink));
    tokio::spawn(proxy.clone().serve_on(listener));
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let url = format!("https://{listen}/api/v1/namespaces/dev/configmaps/cm");
    let request = tokio::spawn({
        let client = client.clone();
        let url = url.clone();
        async move {
            client
                .get(url)
                .bearer_auth("principal-a")
                .send()
                .await
                .unwrap()
        }
    });
    read_reached.acquire().await.unwrap().forget();
    let deny_policy = "default: deny\n";
    let authority_baseline = proxy.authority_transition_generation();
    std::fs::write(&policy_path, deny_policy).unwrap();
    tokio::time::timeout(
        Duration::from_secs(3),
        proxy.wait_for_authority_transition_after(authority_baseline),
    )
    .await
    .expect("policy reloader reaches authority coordination");
    release_read.add_permits(1);
    assert_eq!(request.await.unwrap().status(), 200);
    wait_for_policy_reload(&proxy, deny_policy).await;
    assert_eq!(
        client
            .get(url)
            .bearer_auth("principal-a")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_does_not_queue_behind_reload_waiting_for_a_stalled_mutation() {
    let (upstream_base, mutation_reached, release_mutation) =
        spawn_policy_barrier_upstream(hyper::Method::POST).await;
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(&upstream_base), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let temp = tempfile::tempdir().unwrap();
    let policy_path = temp.path().join("api-policy.yaml");
    let allow_policy = "default: allow\n";
    std::fs::write(&policy_path, allow_policy).unwrap();
    let policy = ApiPolicy::load_file(&policy_path).unwrap();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, Some(policy_path.clone()))
            .with_listener_mode(ApiListenerMode::Policy)
            .with_policy_reload_interval(Duration::from_millis(50)),
    );
    proxy.attach_session_sink(Arc::new(PrincipalSessionSink));
    tokio::spawn(proxy.clone().serve_on(listener));
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let mutation = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .post(format!("https://{listen}/api/v1/namespaces/dev/pods"))
                .bearer_auth("principal-a")
                .body(r#"{"metadata":{"name":"blocked-pod"}}"#)
                .send()
                .await
                .unwrap()
        }
    });
    mutation_reached.acquire().await.unwrap().forget();
    let deny_policy = "default: deny\n";
    let authority_baseline = proxy.authority_transition_generation();
    std::fs::write(&policy_path, deny_policy).unwrap();
    tokio::time::timeout(
        Duration::from_secs(3),
        proxy.wait_for_authority_transition_after(authority_baseline),
    )
    .await
    .expect("policy reloader reaches authority coordination");
    let read = tokio::time::timeout(
        Duration::from_secs(2),
        client
            .get(format!(
                "https://{listen}/api/v1/namespaces/dev/configmaps/cm"
            ))
            .bearer_auth("principal-a")
            .send(),
    )
    .await
    .expect("read authority does not queue behind mutation reload")
    .unwrap();
    assert_eq!(read.status(), 403);
    release_mutation.add_permits(1);
    assert_eq!(mutation.await.unwrap().status(), 201);
    wait_for_policy_reload(&proxy, deny_policy).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn final_denial_releases_policy_authority_before_staged_cleanup() {
    let (upstream_base, _) = spawn_counting_upstream().await;
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(&upstream_base), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let temp = tempfile::tempdir().unwrap();
    let policy_path = temp.path().join("api-policy.yaml");
    let allow_policy = "default: allow\n";
    std::fs::write(&policy_path, allow_policy).unwrap();
    let policy = ApiPolicy::load_file(&policy_path).unwrap();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, Some(policy_path.clone()))
            .with_listener_mode(ApiListenerMode::Policy)
            .with_policy_reload_interval(Duration::from_millis(50)),
    );
    let sink = BlockingCancelSink {
        stage_reached: Arc::new(tokio::sync::Semaphore::new(0)),
        release_stage: Arc::new(tokio::sync::Semaphore::new(0)),
        cancel_reached: Arc::new(tokio::sync::Semaphore::new(0)),
        release_cancel: Arc::new(tokio::sync::Semaphore::new(0)),
    };
    proxy.attach_gate(Arc::new(sink.clone()));
    proxy.attach_session_sink(Arc::new(PrincipalSessionSink));
    tokio::spawn(proxy.clone().serve_on(listener));
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let request = tokio::spawn(async move {
        client
            .post(format!("https://{listen}/api/v1/namespaces/dev/pods"))
            .bearer_auth("principal-a")
            .body(r#"{"metadata":{"name":"denied-pod"}}"#)
            .send()
            .await
            .unwrap()
    });
    sink.stage_reached.acquire().await.unwrap().forget();
    let deny_policy = "default: deny\n";
    std::fs::write(&policy_path, deny_policy).unwrap();
    wait_for_policy_reload(&proxy, deny_policy).await;
    sink.release_stage.add_permits(1);
    sink.cancel_reached.acquire().await.unwrap().forget();

    std::fs::write(&policy_path, allow_policy).unwrap();
    tokio::time::timeout(
        Duration::from_secs(2),
        wait_for_policy_reload(&proxy, allow_policy),
    )
    .await
    .expect("policy reload completes while durable cleanup remains blocked");
    sink.release_cancel.add_permits(1);
    assert_eq!(request.await.unwrap().status(), 403);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_loopback_listener_serves_with_matching_tls_identity() {
    let mock_base = spawn_mock_upstream().await;
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(&mock_base), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let listener = tokio::net::TcpListener::bind("[::1]:0")
        .await
        .expect("bind IPv6 localhost");
    let listen = listener.local_addr().unwrap();
    let proxy = Arc::new(ApiProxy::new(
        listen,
        tls,
        upstream,
        ApiPolicy::deny_all(),
        None,
    ));
    assert_eq!(proxy.proxy_url(), format!("https://{listen}"));
    tokio::spawn(proxy.serve_on(listener));

    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .no_proxy()
        .build()
        .unwrap();
    let response = client
        .get(format!("https://{listen}/version"))
        .send()
        .await
        .expect("request IPv6 loopback proxy");
    assert_eq!(response.status(), 200);
}

/// Reserve a loopback listener up front so the proxy's address is bound with
/// no release-and-rebind window: the same listener is handed to
/// [`ApiProxy::serve_on`], so a concurrently starting test can never steal the
/// port. The bound socket doubles as the readiness signal (a client connect
/// succeeds as soon as the listener exists), so no startup sleep is needed.
async fn reserve_listener() -> (tokio::net::TcpListener, std::net::SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

/// Wait for the proxy's reload generation signal until `yaml` is published.
async fn wait_for_policy_reload(proxy: &ApiProxy, yaml: &str) {
    let expected = ApiPolicy::from_yaml(yaml)
        .expect("reloaded policy parses")
        .authority_fingerprint();
    if proxy.policy_fingerprint().await == expected {
        return;
    }
    tokio::time::timeout(
        Duration::from_secs(30),
        proxy.wait_for_policy_fingerprint(&expected),
    )
    .await
    .expect("policy reload was not observed within the bounded deadline");
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
    start_proxy_with_session_sink(
        mock_base,
        policy_yaml,
        judge,
        gate,
        rarity_threshold,
        Arc::new(LiveSessionSink),
    )
    .await
}

async fn start_proxy_with_session_sink(
    mock_base: String,
    policy_yaml: &str,
    judge: Option<Arc<dyn ApiJudge>>,
    gate: Option<Arc<dyn GateSink>>,
    rarity_threshold: u64,
    session_sink: Arc<dyn ApiSessionSink>,
) -> (String, reqwest::Client) {
    start_proxy_with_session_sink_and_timeout(
        mock_base,
        policy_yaml,
        judge,
        gate,
        rarity_threshold,
        session_sink,
        Duration::from_secs(30),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn start_proxy_with_session_sink_and_timeout(
    mock_base: String,
    policy_yaml: &str,
    judge: Option<Arc<dyn ApiJudge>>,
    gate: Option<Arc<dyn GateSink>>,
    rarity_threshold: u64,
    session_sink: Arc<dyn ApiSessionSink>,
    handoff_timeout: Duration,
) -> (String, reqwest::Client) {
    start_proxy_with_timeouts(
        mock_base,
        policy_yaml,
        judge,
        gate,
        rarity_threshold,
        session_sink,
        handoff_timeout,
        Duration::from_secs(30),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn start_proxy_with_timeouts(
    mock_base: String,
    policy_yaml: &str,
    judge: Option<Arc<dyn ApiJudge>>,
    gate: Option<Arc<dyn GateSink>>,
    rarity_threshold: u64,
    session_sink: Arc<dyn ApiSessionSink>,
    handoff_timeout: Duration,
    body_timeout: Duration,
) -> (String, reqwest::Client) {
    start_proxy_with_limits(
        mock_base,
        policy_yaml,
        judge,
        gate,
        rarity_threshold,
        session_sink,
        handoff_timeout,
        body_timeout,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn start_proxy_with_limits(
    mock_base: String,
    policy_yaml: &str,
    judge: Option<Arc<dyn ApiJudge>>,
    gate: Option<Arc<dyn GateSink>>,
    rarity_threshold: u64,
    session_sink: Arc<dyn ApiSessionSink>,
    handoff_timeout: Duration,
    body_timeout: Duration,
    body_limit: Option<usize>,
) -> (String, reqwest::Client) {
    let kubeconfig = kubeconfig_for(&mock_base);
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(policy_yaml).expect("policy");
    let (listener, listen) = reserve_listener().await;
    let mut proxy = ApiProxy::new(listen, tls, upstream, policy, None)
        .with_listener_mode(ApiListenerMode::Policy)
        .with_upstream_handoff_timeout(handoff_timeout)
        .with_upstream_body_timeout(body_timeout);
    if let Some(limit) = body_limit {
        proxy = proxy.with_upstream_body_limit(limit);
    }
    if rarity_threshold > 0 {
        proxy = proxy.with_rarity_escalation(rarity_threshold);
    }
    let proxy = Arc::new(proxy);
    if let Some(gate) = gate {
        proxy.attach_gate(gate);
    }
    if let Some(judge) = judge {
        proxy.attach_judge(judge).await;
    }
    proxy.attach_session_sink(session_sink);
    tokio::spawn(proxy.clone().serve_on(listener));
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        "Bearer live-session".parse().unwrap(),
    );
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .default_headers(headers)
        .build()
        .unwrap();
    (format!("https://{listen}"), client)
}

#[derive(Clone)]
struct RecordingJudge {
    verdicts: Arc<std::sync::Mutex<VecDeque<ApiJudgeVerdict>>>,
    summaries: Arc<std::sync::Mutex<Vec<ApiRequestSummary>>>,
}

#[derive(Clone)]
struct BlockingJudge {
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl ApiJudge for BlockingJudge {
    async fn authorize_forward(
        &self,
        _summary: &ApiRequestSummary,
        _requirement: ApiForwardRequirement,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        handoff.forward().await
    }

    async fn judge(&self, _summary: &ApiRequestSummary) -> ApiJudgeVerdict {
        self.started.notify_one();
        self.release.notified().await;
        judge_allow(Some(1), Some(Reversibility::Reversible))
    }
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
    async fn authorize_forward(
        &self,
        _summary: &ApiRequestSummary,
        _requirement: ApiForwardRequirement,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        handoff.forward().await
    }

    async fn judge(&self, summary: &ApiRequestSummary) -> ApiJudgeVerdict {
        self.summaries.lock().unwrap().push(summary.clone());
        self.verdicts
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| ApiJudgeVerdict::Error("no mock verdict queued".to_string()))
    }
}

#[derive(Clone, Default)]
struct ModeCoverageJudge {
    judge_calls: Arc<AtomicUsize>,
}

struct SkippedHandoffCoverageJudge;

#[derive(Clone, Default)]
struct HeldCoverageJudge {
    summaries: Arc<std::sync::Mutex<Vec<ApiRequestSummary>>>,
}

#[async_trait::async_trait]
impl ApiJudge for HeldCoverageJudge {
    fn evaluator_enabled(&self) -> bool {
        false
    }

    async fn coverage(&self, summary: &ApiRequestSummary) -> ApiCoverageVerdict {
        self.summaries.lock().unwrap().push(summary.clone());
        ApiCoverageVerdict::Allow {
            risk: 9,
            reversibility: Reversibility::Irreversible,
        }
    }

    async fn authorize_forward(
        &self,
        _summary: &ApiRequestSummary,
        _requirement: ApiForwardRequirement,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        handoff.forward().await
    }

    async fn judge(&self, _summary: &ApiRequestSummary) -> ApiJudgeVerdict {
        ApiJudgeVerdict::Error("unexpected evaluator call".to_string())
    }
}

#[async_trait::async_trait]
impl ApiJudge for SkippedHandoffCoverageJudge {
    async fn coverage(&self, _summary: &ApiRequestSummary) -> ApiCoverageVerdict {
        ApiCoverageVerdict::Allow {
            risk: 1,
            reversibility: Reversibility::Reversible,
        }
    }

    async fn authorize_forward(
        &self,
        _summary: &ApiRequestSummary,
        _requirement: ApiForwardRequirement,
        _handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn judge(&self, _summary: &ApiRequestSummary) -> ApiJudgeVerdict {
        ApiJudgeVerdict::Error("unexpected evaluator call".to_string())
    }
}

#[async_trait::async_trait]
impl ApiJudge for ModeCoverageJudge {
    async fn coverage(&self, summary: &ApiRequestSummary) -> ApiCoverageVerdict {
        if summary.session_fingerprint.as_deref() == Some("readonly-authorized")
            && summary.session_revision.as_deref() == Some("readonly-revision")
            && summary.verb == "create"
            && summary.resource == "pods"
            && summary.coverage_body_shape == "{}"
        {
            ApiCoverageVerdict::Allow {
                risk: 1,
                reversibility: Reversibility::Reversible,
            }
        } else {
            ApiCoverageVerdict::None
        }
    }

    async fn authorize_forward(
        &self,
        _summary: &ApiRequestSummary,
        _requirement: ApiForwardRequirement,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        handoff.forward().await
    }

    async fn judge(&self, _summary: &ApiRequestSummary) -> ApiJudgeVerdict {
        self.judge_calls.fetch_add(1, Ordering::SeqCst);
        judge_allow(Some(1), Some(Reversibility::Reversible))
    }
}

#[derive(Clone)]
struct LinearizedJudge {
    coverage: bool,
    hold: bool,
    active: Arc<AtomicBool>,
    coordination: Arc<tokio::sync::RwLock<()>>,
    reached_handoff: Arc<tokio::sync::Semaphore>,
    release_handoff: Arc<tokio::sync::Semaphore>,
}

impl LinearizedJudge {
    fn new(coverage: bool) -> Self {
        Self {
            coverage,
            hold: false,
            active: Arc::new(AtomicBool::new(true)),
            coordination: Arc::new(tokio::sync::RwLock::new(())),
            reached_handoff: Arc::new(tokio::sync::Semaphore::new(0)),
            release_handoff: Arc::new(tokio::sync::Semaphore::new(0)),
        }
    }

    fn held() -> Self {
        Self {
            hold: true,
            ..Self::new(false)
        }
    }
}

#[async_trait::async_trait]
impl ApiJudge for LinearizedJudge {
    async fn coverage(&self, _summary: &ApiRequestSummary) -> ApiCoverageVerdict {
        if self.coverage {
            ApiCoverageVerdict::Allow {
                risk: 1,
                reversibility: Reversibility::Reversible,
            }
        } else {
            ApiCoverageVerdict::None
        }
    }

    async fn authorize_forward(
        &self,
        _summary: &ApiRequestSummary,
        _requirement: ApiForwardRequirement,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        let guard = self.coordination.clone().read_owned().await;
        if !self.active.load(Ordering::SeqCst) {
            return Err("revoked".to_string());
        }
        self.reached_handoff.add_permits(1);
        self.release_handoff
            .acquire()
            .await
            .map_err(|_| "handoff closed".to_string())?
            .forget();
        let result = handoff.forward().await;
        drop(guard);
        result
    }

    async fn judge(&self, _summary: &ApiRequestSummary) -> ApiJudgeVerdict {
        ApiJudgeVerdict::Allow {
            reason: "mock allow".to_string(),
            risk: Some(if self.hold { 9 } else { 1 }),
            reversibility: Some(if self.hold {
                Reversibility::Irreversible
            } else {
                Reversibility::Reversible
            }),
            authorization: if self.coverage {
                ApiAuthorizationKind::Coverage
            } else {
                ApiAuthorizationKind::Evaluated
            },
        }
    }
}

struct ModeSessionSink;

#[async_trait::async_trait]
impl ApiSessionSink for ModeSessionSink {
    async fn resolve(&self, token: &str) -> Option<ApiSessionContext> {
        let (fingerprint, revision, evaluation_mode, intent, can_evaluate_api_override) =
            match token {
                "policy-only" => (
                    "policy-only",
                    "policy-revision",
                    ApiEvaluationMode::PolicyOnly,
                    Some("please allow writes".to_string()),
                    false,
                ),
                "readonly" => (
                    "readonly",
                    "readonly-revision",
                    ApiEvaluationMode::ReadOnly,
                    Some("please allow writes".to_string()),
                    false,
                ),
                "readonly-authorized" => (
                    "readonly-authorized",
                    "readonly-revision",
                    ApiEvaluationMode::ReadOnly,
                    None,
                    false,
                ),
                "evaluator" => (
                    "evaluator",
                    "evaluator-revision",
                    ApiEvaluationMode::Evaluator,
                    Some("create one development pod".to_string()),
                    true,
                ),
                _ => return None,
            };
        Some(ApiSessionContext {
            fingerprint: fingerprint.to_string(),
            revision: revision.to_string(),
            secret_entitlements: None,
            intent,
            evaluation_mode,
            can_evaluate_api_override,
        })
    }

    async fn authorize_forward(
        &self,
        token: &str,
        expected: &ApiSessionContext,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        authorize_test_session(self, token, expected, handoff).await
    }

    async fn record(&self, _token: &str, _event: ApiSessionEvent) {}
}

fn judge_allow(risk: Option<i32>, reversibility: Option<Reversibility>) -> ApiJudgeVerdict {
    ApiJudgeVerdict::Allow {
        reason: "mock allow".to_string(),
        risk,
        reversibility,
        authorization: guard::proxy::ApiAuthorizationKind::Evaluated,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evaluator_authority_is_linearized_at_upstream_handoff() {
    let policy = r#"
default: deny
rules:
  - verbs: [get]
    resources: [configmaps]
    namespaces: [dev]
    action: evaluate
"#;
    let (upstream, forwarded) = spawn_counting_upstream().await;
    let judge = Arc::new(LinearizedJudge::new(false));
    let (base, client) = start_proxy_with(upstream, policy, Some(judge.clone()), None, 0).await;
    let request = tokio::spawn(async move {
        client
            .get(format!("{base}/api/v1/namespaces/dev/configmaps/cm"))
            .send()
            .await
            .unwrap()
    });
    judge.reached_handoff.acquire().await.unwrap().forget();
    assert!(judge.coordination.try_write().is_err());
    let mutation_judge = judge.clone();
    let revoke = tokio::spawn(async move {
        let _guard = mutation_judge.coordination.write().await;
        mutation_judge.active.store(false, Ordering::SeqCst);
    });
    judge.release_handoff.add_permits(1);

    assert_eq!(request.await.unwrap().status(), 200);
    revoke.await.unwrap();
    assert_eq!(forwarded.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn coverage_revoked_before_upstream_handoff_prevents_forwarding() {
    let policy = r#"
default: deny
rules:
  - verbs: [create]
    resources: [pods]
    namespaces: [dev]
    action: evaluate
"#;
    let (upstream, forwarded) = spawn_counting_upstream().await;
    let judge = Arc::new(LinearizedJudge::new(true));
    judge.active.store(false, Ordering::SeqCst);
    let (base, client) = start_proxy_with_session_sink(
        upstream,
        policy,
        Some(judge),
        None,
        0,
        Arc::new(ModeSessionSink),
    )
    .await;
    let response = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("readonly-authorized")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(forwarded.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn coverage_allow_cannot_forward_without_invoking_the_authorized_handoff() {
    let policy = r#"
default: deny
rules:
  - verbs: [create]
    resources: [pods]
    namespaces: [dev]
    action: evaluate
"#;
    let (upstream, forwarded) = spawn_counting_upstream().await;
    let (base, client) = start_proxy_with_session_sink(
        upstream,
        policy,
        Some(Arc::new(SkippedHandoffCoverageJudge)),
        None,
        0,
        Arc::new(ModeSessionSink),
    )
    .await;
    let response = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("readonly-authorized")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(forwarded.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_revocation_or_amendment_before_handoff_prevents_upstream_forwarding() {
    let policy = r#"
default: deny
rules:
  - verbs: [get]
    resources: [configmaps]
    namespaces: [dev]
    action: evaluate
"#;
    for revoke in [false, true] {
        let (upstream, forwarded) = spawn_counting_upstream().await;
        let judge = Arc::new(LinearizedJudge::new(false));
        let session = Arc::new(LinearizedSessionSink::new(false));
        let (base, client) = start_proxy_with_session_sink(
            upstream,
            policy,
            Some(judge.clone()),
            None,
            0,
            session.clone(),
        )
        .await;
        let request = tokio::spawn(async move {
            client
                .get(format!("{base}/api/v1/namespaces/dev/configmaps/cm"))
                .send()
                .await
                .unwrap()
        });
        judge.reached_handoff.acquire().await.unwrap().forget();
        let replacement = if revoke {
            None
        } else {
            let mut amended = session.context.clone();
            amended.revision = "amended-revision".to_string();
            Some(amended)
        };
        *session.live.write().await = replacement;
        judge.release_handoff.add_permits(1);

        assert_eq!(request.await.unwrap().status(), 403);
        assert_eq!(forwarded.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_lease_linearizes_at_the_finite_upstream_handoff() {
    let (upstream, forwarded) = spawn_counting_upstream().await;
    let session = Arc::new(LinearizedSessionSink::new(true));
    let (base, client) =
        start_proxy_with_session_sink(upstream, "default: allow\n", None, None, 0, session.clone())
            .await;
    let request = tokio::spawn(async move {
        client
            .get(format!("{base}/api/v1/namespaces/dev/configmaps/cm"))
            .send()
            .await
            .unwrap()
    });
    session.reached_handoff.acquire().await.unwrap().forget();
    let live = session.live.clone();
    let revoke = tokio::spawn(async move {
        *live.write().await = None;
    });
    assert!(session.live.try_write().is_err());
    session.release_handoff.add_permits(1);

    assert_eq!(request.await.unwrap().status(), 200);
    revoke.await.unwrap();
    assert_eq!(forwarded.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_upstream_handoff_times_out_and_releases_authority() {
    let (upstream, reached_upstream) = spawn_stalled_upstream().await;
    let session = Arc::new(LinearizedSessionSink::new(false));
    let judge = Arc::new(LinearizedJudge::new(false));
    judge.release_handoff.add_permits(1);
    let (base, client) = start_proxy_with_session_sink_and_timeout(
        upstream,
        "default: deny\nrules:\n  - verbs: [get]\n    resources: [configmaps]\n    namespaces: [dev]\n    action: evaluate\n",
        Some(judge.clone()),
        None,
        0,
        session.clone(),
        Duration::from_millis(200),
    )
    .await;
    let request = tokio::spawn(async move {
        client
            .get(format!("{base}/api/v1/namespaces/dev/configmaps/cm"))
            .send()
            .await
            .unwrap()
    });
    reached_upstream.acquire().await.unwrap().forget();
    let live = session.live.clone();
    let revoke = tokio::spawn(async move {
        *live.write().await = None;
    });
    let judge_for_revoke = judge.clone();
    let coverage_revoke = tokio::spawn(async move {
        let _guard = judge_for_revoke.coordination.write().await;
        judge_for_revoke.active.store(false, Ordering::SeqCst);
    });
    assert!(session.live.try_write().is_err());
    assert!(judge.coordination.try_write().is_err());

    assert_eq!(request.await.unwrap().status(), 504);
    tokio::time::timeout(Duration::from_secs(2), revoke)
        .await
        .expect("session authority lease is released after handoff timeout")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), coverage_revoke)
        .await
        .expect("evaluator authority lease is released after handoff timeout")
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_dispatch_marker_is_committed_at_the_final_send_boundary() {
    let (upstream, reached_upstream) = spawn_stalled_upstream().await;
    let sink = BlockingDispatchSink::default();
    let reached_dispatch = sink.reached.clone();
    let release_dispatch = sink.release.clone();
    let state = sink.state.clone();
    let (base, client) = start_proxy_with_timeouts(
        upstream,
        "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n",
        None,
        Some(Arc::new(sink)),
        0,
        Arc::new(LiveSessionSink),
        Duration::from_millis(200),
        Duration::from_secs(2),
    )
    .await;
    let request = tokio::spawn(async move {
        client
            .post(format!("{base}/api/v1/namespaces/dev/pods"))
            .body(r#"{"metadata":{"name":"dispatch-boundary"}}"#)
            .send()
            .await
            .unwrap()
    });
    reached_dispatch.acquire().await.unwrap().forget();
    assert!(reached_upstream.try_acquire().is_err());
    release_dispatch.add_permits(1);
    reached_upstream.acquire().await.unwrap().forget();
    assert_eq!(request.await.unwrap().status(), 504);
    assert_eq!(state.dispatching.lock().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_dispatch_marker_cancels_inert_state_without_sending() {
    let (upstream, forwarded) = spawn_counting_upstream().await;
    let sink = DispatchFailSink::default();
    let state = sink.state.clone();
    let (base, client) = start_proxy_with(
        upstream,
        "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n",
        None,
        Some(Arc::new(sink)),
        0,
    )
    .await;
    let response = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .body(r#"{"metadata":{"name":"dispatch-failure"}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(forwarded.load(Ordering::SeqCst), 0);
    assert_eq!(state.cancelled.lock().unwrap().len(), 1);
    assert!(state.indeterminate.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_create_body_preserves_indeterminate_containment_without_uid() {
    let sink = RecordingSink::default();
    let (base, client) = start_proxy_with_timeouts(
        spawn_success_headers_stalled_body().await,
        "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n",
        None,
        Some(Arc::new(sink.clone())),
        0,
        Arc::new(LiveSessionSink),
        Duration::from_secs(2),
        Duration::from_millis(150),
    )
    .await;
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        client
            .post(format!("{base}/api/v1/namespaces/dev/pods"))
            .bearer_auth("live-session")
            .body(r#"{"metadata":{"name":"stalled-pod"}}"#)
            .send(),
    )
    .await
    .expect("proxy applies a bounded body timeout")
    .unwrap();
    assert_eq!(response.status(), 502);
    assert_eq!(sink.calls.lock().unwrap().len(), 1);
    assert!(sink.activated.lock().unwrap().is_empty());
    assert_eq!(
        sink.indeterminate.lock().unwrap().as_slice(),
        ["test-handle-0"]
    );
    assert!(sink
        .resource_uids
        .lock()
        .unwrap()
        .first()
        .is_some_and(Option::is_none));
    assert_eq!(
        response
            .headers()
            .get("x-guard-provisional")
            .and_then(|value| value.to_str().ok()),
        Some("test-handle-0")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutation_identity_buffer_rejects_declared_and_chunked_oversize() {
    for kind in [OversizedBodyKind::Declared, OversizedBodyKind::Chunked] {
        let sink = RecordingSink::default();
        let (base, client) = start_proxy_with_limits(
            spawn_oversized_body_upstream(kind).await,
            "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n",
            None,
            Some(Arc::new(sink.clone())),
            0,
            Arc::new(LiveSessionSink),
            Duration::from_secs(2),
            Duration::from_secs(2),
            Some(64),
        )
        .await;
        let response = client
            .post(format!("{base}/api/v1/namespaces/dev/pods"))
            .body(r#"{"metadata":{"name":"bounded-pod"}}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 502);
        assert_eq!(sink.indeterminate.lock().unwrap().len(), 1);
        assert!(sink.activated.lock().unwrap().is_empty());
        assert!(sink
            .resource_uids
            .lock()
            .unwrap()
            .first()
            .is_some_and(Option::is_none));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redacted_read_buffer_rejects_declared_and_chunked_oversize() {
    for kind in [OversizedBodyKind::Declared, OversizedBodyKind::Chunked] {
        let (base, client) = start_proxy_with_limits(
            spawn_oversized_body_upstream(kind).await,
            "default: deny\nrules:\n  - verbs: [get]\n    resources: [secrets]\n    namespaces: [dev]\n    action: allow\n",
            None,
            None,
            0,
            Arc::new(LiveSessionSink),
            Duration::from_secs(2),
            Duration::from_secs(2),
            Some(64),
        )
        .await;
        let response = client
            .get(format!("{base}/api/v1/namespaces/dev/secrets/example"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 502);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutation_handoff_timeout_preserves_operator_decision_without_an_unsafe_uid() {
    let (upstream, reached_upstream) = spawn_stalled_upstream().await;
    let sink = RecordingSink::default();
    let (base, client) = start_proxy_with_timeouts(
        upstream,
        "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n",
        None,
        Some(Arc::new(sink.clone())),
        0,
        Arc::new(LiveSessionSink),
        Duration::from_millis(150),
        Duration::from_secs(2),
    )
    .await;
    let request = tokio::spawn(async move {
        client
            .post(format!("{base}/api/v1/namespaces/dev/pods"))
            .bearer_auth("live-session")
            .body(r#"{"metadata":{"name":"timeout-pod"}}"#)
            .send()
            .await
            .unwrap()
    });
    reached_upstream.acquire().await.unwrap().forget();
    let response = request.await.unwrap();
    assert_eq!(response.status(), 504);
    assert_eq!(
        response
            .headers()
            .get("x-guard-provisional")
            .and_then(|value| value.to_str().ok()),
        Some("test-handle-0")
    );
    assert_eq!(sink.handoffs.lock().unwrap().len(), 1);
    assert_eq!(sink.indeterminate.lock().unwrap().len(), 1);
    assert!(sink
        .resource_uids
        .lock()
        .unwrap()
        .first()
        .is_some_and(Option::is_none));
    assert!(sink.cancelled.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutation_transport_error_preserves_an_actionable_provisional() {
    let sink = RecordingSink::default();
    let (base, client) = start_proxy_with(
        spawn_transport_error_upstream().await,
        "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n",
        None,
        Some(Arc::new(sink.clone())),
        0,
    )
    .await;
    let response = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("live-session")
        .body(r#"{"metadata":{"name":"transport-pod"}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    assert!(response.headers().contains_key("x-guard-provisional"));
    assert_eq!(sink.handoffs.lock().unwrap().len(), 1);
    assert_eq!(sink.indeterminate.lock().unwrap().len(), 1);
    assert!(sink.cancelled.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_error_preserves_indeterminate_containment_without_uid() {
    let (upstream, forwarded_deletes) = spawn_create_status_upstream(500, None).await;
    let sink = RecordingSink::default();
    let (base, client) = start_proxy_with(
        upstream,
        "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n  - verbs: [delete]\n    resources: [pods]\n    namespaces: [dev]\n    action: hold\n",
        None,
        Some(Arc::new(sink.clone())),
        0,
    )
    .await;
    let response = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("live-session")
        .body(r#"{"metadata":{"name":"failed-pod"}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 500);
    assert!(response.headers().contains_key("x-guard-provisional"));
    assert_eq!(sink.indeterminate.lock().unwrap().len(), 1);
    assert!(sink
        .resource_uids
        .lock()
        .unwrap()
        .first()
        .is_some_and(Option::is_none));
    assert!(sink.activated.lock().unwrap().is_empty());
    assert!(sink.cancelled.lock().unwrap().is_empty());

    let delete = client
        .delete(format!("{base}/api/v1/namespaces/dev/pods/failed-pod"))
        .bearer_auth("live-session")
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), 403);
    assert_eq!(forwarded_deletes.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejected_create_retires_dispatch_without_create_provenance() {
    let (upstream, forwarded_deletes) = spawn_create_status_upstream(409, None).await;
    let sink = RecordingSink::default();
    let (base, client) = start_proxy_with(
        upstream,
        "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n  - verbs: [delete]\n    resources: [pods]\n    namespaces: [dev]\n    action: hold\n",
        None,
        Some(Arc::new(sink.clone())),
        0,
    )
    .await;
    let response = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("live-session")
        .body(r#"{"metadata":{"name":"existing-pod"}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 409);
    assert!(!response.headers().contains_key("x-guard-provisional"));
    assert!(sink.indeterminate.lock().unwrap().is_empty());
    assert!(sink.activated.lock().unwrap().is_empty());
    assert!(sink.cancelled.lock().unwrap().is_empty());
    assert_eq!(sink.rejected.lock().unwrap().len(), 1);

    let delete = client
        .delete(format!("{base}/api/v1/namespaces/dev/pods/existing-pod"))
        .bearer_auth("live-session")
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), 403);
    assert_eq!(forwarded_deletes.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replacement_uid_cannot_use_created_resource_cleanup_authority() {
    let (upstream, replacement, forwarded_deletes) = spawn_replaceable_create_upstream().await;
    let sink = RecordingSink::default();
    let (base, client) = start_proxy_with(
        upstream,
        "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n  - verbs: [delete]\n    resources: [pods]\n    namespaces: [dev]\n    action: hold\n",
        None,
        Some(Arc::new(sink)),
        0,
    )
    .await;
    let created = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("live-session")
        .body(r#"{"metadata":{"name":"replaceable-pod"}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    replacement.store(true, Ordering::SeqCst);

    let delete = client
        .delete(format!("{base}/api/v1/namespaces/dev/pods/replaceable-pod"))
        .bearer_auth("live-session")
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), 403);
    assert_eq!(forwarded_deletes.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_response_uid_arms_without_follow_up_get_authority() {
    let (upstream, gets) = spawn_create_without_get_upstream().await;
    let sink = RecordingSink::default();
    let (base, client) = start_proxy_with(
        upstream,
        "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n",
        None,
        Some(Arc::new(sink.clone())),
        0,
    )
    .await;
    let response = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .body(r#"{"metadata":{"name":"response-authority"}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    assert_eq!(gets.load(Ordering::SeqCst), 0);
    assert_eq!(sink.activated.lock().unwrap().len(), 1);
    assert!(sink
        .resource_uids
        .lock()
        .unwrap()
        .first()
        .is_some_and(Option::is_some));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cleanup_buffer_rejects_declared_and_chunked_oversize_without_resolution() {
    for kind in [OversizedBodyKind::Declared, OversizedBodyKind::Chunked] {
        let sink = RecordingSink::default();
        let (base, client) = start_proxy_with_limits(
            spawn_cleanup_oversized_upstream(kind).await,
            "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n  - verbs: [delete]\n    resources: [pods]\n    namespaces: [dev]\n    action: hold\n",
            None,
            Some(Arc::new(sink.clone())),
            0,
            Arc::new(LiveSessionSink),
            Duration::from_secs(2),
            Duration::from_secs(2),
            Some(512),
        )
        .await;
        let create = client
            .post(format!("{base}/api/v1/namespaces/dev/pods"))
            .body(r#"{"metadata":{"name":"cleanup-bounded"}}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(create.status(), 201);
        create
            .bytes()
            .await
            .expect("create response completes before same-connection cleanup");
        let cleanup = client
            .delete(format!("{base}/api/v1/namespaces/dev/pods/cleanup-bounded"))
            .send()
            .await
            .unwrap();
        assert_eq!(cleanup.status(), 502);
        assert!(sink.resolved.lock().unwrap().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cleanup_revocation_linearizes_at_the_final_header_handoff() {
    for (pause, expected_status, expected_deletes) in [
        (CleanupLeasePause::BeforeLease, 403, 0),
        (CleanupLeasePause::AfterLease, 200, 1),
    ] {
        let (upstream, _, deletes) = spawn_replaceable_create_upstream().await;
        let sink = Arc::new(CleanupLeaseSink::new(pause));
        let (base, client) = start_proxy_with(
            upstream,
            "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n  - verbs: [delete]\n    resources: [pods]\n    namespaces: [dev]\n    action: hold\n",
            None,
            Some(sink.clone()),
            0,
        )
        .await;
        let created = client
            .post(format!("{base}/api/v1/namespaces/dev/pods"))
            .body(r#"{"metadata":{"name":"lease-linearized"}}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(created.status(), 201);
        created
            .bytes()
            .await
            .expect("create response completes before cleanup handoff");

        let cleanup = tokio::spawn(async move {
            client
                .delete(format!(
                    "{base}/api/v1/namespaces/dev/pods/lease-linearized"
                ))
                .send()
                .await
                .unwrap()
        });
        tokio::time::timeout(PROXY_INTEGRATION_TIMEOUT, sink.reached.acquire())
            .await
            .expect("cleanup reaches the final authority handoff")
            .unwrap()
            .forget();
        let coordination = sink.coordination.clone();
        let mut revoke = tokio::spawn(async move {
            *coordination.write().await = false;
        });
        if matches!(pause, CleanupLeasePause::AfterLease) {
            assert!(sink.coordination.try_write().is_err());
        } else {
            tokio::time::timeout(Duration::from_secs(2), &mut revoke)
                .await
                .expect("pre-handoff revocation completes before cleanup send")
                .unwrap();
        }
        sink.release.add_permits(1);
        assert_eq!(
            tokio::time::timeout(PROXY_INTEGRATION_TIMEOUT, cleanup)
                .await
                .expect("cleanup completes after final authority handoff")
                .unwrap()
                .status(),
            expected_status
        );
        if matches!(pause, CleanupLeasePause::AfterLease) {
            tokio::time::timeout(Duration::from_secs(2), &mut revoke)
                .await
                .expect("post-handoff revocation completes after cleanup send")
                .unwrap();
        }
        assert_eq!(deletes.load(Ordering::SeqCst), expected_deletes);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn encoded_success_keeps_activated_containment() {
    let (upstream, _) = spawn_create_status_upstream(201, Some("gzip")).await;
    let sink = RecordingSink::default();
    let (base, client) = start_proxy_with(
        upstream,
        "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n",
        None,
        Some(Arc::new(sink.clone())),
        0,
    )
    .await;
    let response = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("live-session")
        .body(r#"{"metadata":{"name":"encoded-pod"}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    assert!(response.headers().contains_key("x-guard-provisional"));
    assert_eq!(sink.activated.lock().unwrap().len(), 1);
    assert!(sink.cancelled.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_activation_failure_cannot_return_upstream_success() {
    let (upstream, _) = spawn_create_status_upstream(201, None).await;
    let sink = ActivationFailSink::default();
    let state = sink.state.clone();
    let (base, client) = start_proxy_with(
        upstream,
        "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n",
        None,
        Some(Arc::new(sink)),
        0,
    )
    .await;
    let response = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("live-session")
        .body(r#"{"metadata":{"name":"activation-pod"}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    assert!(response.headers().contains_key("x-guard-provisional"));
    assert_eq!(state.handoffs.lock().unwrap().len(), 2);
    assert_eq!(state.activated.lock().unwrap().len(), 1);
    assert_eq!(state.indeterminate.lock().unwrap().len(), 1);
    assert!(state.cancelled.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_containment_classification_never_advertises_an_uncommitted_handle() {
    let (upstream, _) = spawn_create_status_upstream(201, None).await;
    let sink = ClassificationFailSink::default();
    let state = sink.state.clone();
    let (base, client) = start_proxy_with(
        upstream,
        "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n",
        None,
        Some(Arc::new(sink)),
        0,
    )
    .await;
    let response = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("live-session")
        .body(r#"{"metadata":{"name":"classification-pod"}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    assert!(!response.headers().contains_key("x-guard-provisional"));
    assert!(state.activated.lock().unwrap().is_empty());
    assert!(state.indeterminate.lock().unwrap().is_empty());
    assert!(state.cancelled.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_mutation_handoff_preserves_containment() {
    let (upstream, reached_upstream) = spawn_stalled_upstream().await;
    let sink = RecordingSink::default();
    let (base, client) = start_proxy_with_timeouts(
        upstream,
        "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n",
        None,
        Some(Arc::new(sink.clone())),
        0,
        Arc::new(LiveSessionSink),
        Duration::from_secs(5),
        Duration::from_secs(2),
    )
    .await;
    let request = tokio::spawn(async move {
        let _ = client
            .post(format!("{base}/api/v1/namespaces/dev/pods"))
            .bearer_auth("live-session")
            .body(r#"{"metadata":{"name":"cancelled-pod"}}"#)
            .send()
            .await;
    });
    reached_upstream.acquire().await.unwrap().forget();
    request.abort();
    tokio::time::timeout(Duration::from_secs(3), sink.indeterminate_signal.acquire())
        .await
        .expect("cancelled request preserves an actionable provisional")
        .unwrap()
        .forget();
    assert_eq!(sink.handoffs.lock().unwrap().len(), 1);
    assert!(sink.cancelled.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_during_uid_transition_keeps_richer_identity() {
    let (upstream, _) = spawn_create_status_upstream(201, None).await;
    let sink = BlockingUidTransitionSink::default();
    let state = sink.state.clone();
    let reached = sink.reached.clone();
    let release = sink.release.clone();
    let (base, client) = start_proxy_with(
        upstream,
        "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n",
        None,
        Some(Arc::new(sink)),
        0,
    )
    .await;
    let request = tokio::spawn(async move {
        let _ = client
            .post(format!("{base}/api/v1/namespaces/dev/pods"))
            .body(r#"{"metadata":{"name":"cancel-transition"}}"#)
            .send()
            .await;
    });
    reached.acquire().await.unwrap().forget();
    request.abort();
    release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(2), state.activated_signal.acquire())
        .await
        .expect("detached UID transition completes after caller cancellation")
        .unwrap()
        .forget();
    assert!(state.indeterminate.lock().unwrap().is_empty());
    assert!(state.cancelled.lock().unwrap().is_empty());
    assert!(state
        .resource_uids
        .lock()
        .unwrap()
        .first()
        .is_some_and(Option::is_some));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evaluator_authority_revoked_during_an_approved_hold_prevents_forwarding() {
    let policy = r#"
default: deny
rules:
  - verbs: [create]
    resources: [configmaps]
    namespaces: [dev]
    action: evaluate
"#;
    let (upstream, forwarded) = spawn_counting_upstream().await;
    let judge = Arc::new(LinearizedJudge::held());
    judge.active.store(false, Ordering::SeqCst);
    let (base, client) = start_proxy_with(
        upstream,
        policy,
        Some(judge),
        Some(Arc::new(ApprovingSink)),
        0,
    )
    .await;
    let response = client
        .post(format!("{base}/api/v1/namespaces/dev/configmaps"))
        .body(r#"{"metadata":{"name":"held-config"}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(forwarded.load(Ordering::SeqCst), 0);
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
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, None)
            .with_listener_mode(ApiListenerMode::Policy),
    );
    proxy.attach_session_sink(Arc::new(LiveSessionSink));

    // The brokered config must point at the proxy and carry no credential.
    let brokered = proxy.brokered_kubeconfig();
    guard::proxy::validate_brokered_kubeconfig(&brokered).expect("brokered config credential-free");
    assert!(brokered.contains(&format!("https://{listen}")));

    tokio::spawn(proxy.clone().serve_on(listener));

    let base = format!("https://{listen}");
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

    // 3. An anonymous mutation fails before policy routing because writes need
    //    attributable Guard session authority.
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
        .contains("require an attributable Guard session"));

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
        .bearer_auth("live-session")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "prod write should be denied");

    // 6. A write in a non-production namespace is allowed and forwarded.
    let resp = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("live-session")
        .body(r#"{"metadata":{"name":"web-123"}}"#)
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

    let resp = client.get(format!("{base}/metrics")).send().await.unwrap();
    assert_eq!(resp.status(), 403, "unknown Kubernetes reads must deny");
    let resp = client.head(format!("{base}/metrics")).send().await.unwrap();
    assert_eq!(resp.status(), 403, "unknown Kubernetes HEAD must deny");
    for path in [
        "/version",
        "/api",
        "/apis/apps/v1",
        "/openapi/v3/apis/apps/v1",
        "/healthz",
        "/livez",
        "/readyz?verbose",
    ] {
        let resp = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(resp.status(), 200, "discovery path {path} must forward");
    }
    for path in ["/readyz/etcd", "/healthz/", "/livez?exclude=log"] {
        let resp = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(
            resp.status(),
            403,
            "unapproved health path {path} must deny"
        );
    }
    let resp = client.head(format!("{base}/readyz")).send().await.unwrap();
    assert_eq!(resp.status(), 200, "exact health HEAD must forward");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http2_multiplexes_session_authentication_failures_independently() {
    let mock_base = spawn_mock_upstream().await;
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(&mock_base), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(ApiProxy::new(
        listen,
        tls,
        upstream,
        ApiPolicy::deny_all(),
        None,
    ));
    proxy.attach_session_sink(Arc::new(H2SessionSink));
    tokio::spawn(proxy.serve_on(listener));

    let ca_der = base64::engine::general_purpose::STANDARD
        .decode(
            ca_pem
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<String>(),
        )
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pki_types::CertificateDer::from(ca_der)).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let tcp = tokio::net::TcpStream::connect(listen).await.unwrap();
    let server_name = pki_types::ServerName::try_from("127.0.0.1")
        .unwrap()
        .to_owned();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();
    assert_eq!(tls_stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls_stream))
            .await
            .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });

    let authority = format!("https://{listen}/version");
    let requests = vec![
        Request::builder()
            .uri(&authority)
            .header("authorization", "Bearer h2-live")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        Request::builder()
            .uri(&authority)
            .body(Full::new(Bytes::new()))
            .unwrap(),
        Request::builder()
            .uri(&authority)
            .header("authorization", "Bearer h2-live")
            .header("x-guard-session", "different")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        Request::builder()
            .uri(&authority)
            .header("authorization", "Bearer expired")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        Request::builder()
            .uri(&authority)
            .header("authorization", "Bearer suspended")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    ];
    let responses = futures::future::join_all(requests.into_iter().map(|request| {
        let mut sender = sender.clone();
        async move { sender.send_request(request).await.unwrap() }
    }))
    .await;
    let mut statuses = Vec::new();
    for response in responses {
        statuses.push(response.status().as_u16());
        response.into_body().collect().await.unwrap();
    }
    assert_eq!(statuses, vec![200, 200, 403, 403, 403]);
}

/// Records the reverts the proxy synthesizes, standing in for the daemon's
/// consequence machinery.
#[derive(Clone)]
struct RecordingSink {
    calls: Arc<std::sync::Mutex<Vec<guard::proxy::ApiMutation>>>,
    handoffs: Arc<std::sync::Mutex<Vec<String>>>,
    activated: Arc<std::sync::Mutex<Vec<String>>>,
    indeterminate: Arc<std::sync::Mutex<Vec<String>>>,
    resource_uids: Arc<std::sync::Mutex<Vec<Option<String>>>>,
    cancelled: Arc<std::sync::Mutex<Vec<String>>>,
    resolved: Arc<std::sync::Mutex<Vec<String>>>,
    dispatching: Arc<std::sync::Mutex<Vec<String>>>,
    rejected: Arc<std::sync::Mutex<Vec<String>>>,
    deadline_unix: Arc<AtomicU64>,
    activated_signal: Arc<tokio::sync::Semaphore>,
    indeterminate_signal: Arc<tokio::sync::Semaphore>,
    resolved_signal: Arc<tokio::sync::Semaphore>,
}

impl Default for RecordingSink {
    fn default() -> Self {
        Self {
            calls: Arc::default(),
            handoffs: Arc::default(),
            activated: Arc::default(),
            indeterminate: Arc::default(),
            resource_uids: Arc::default(),
            cancelled: Arc::default(),
            resolved: Arc::default(),
            dispatching: Arc::default(),
            rejected: Arc::default(),
            deadline_unix: Arc::new(AtomicU64::new(0)),
            activated_signal: Arc::new(tokio::sync::Semaphore::new(0)),
            indeterminate_signal: Arc::new(tokio::sync::Semaphore::new(0)),
            resolved_signal: Arc::new(tokio::sync::Semaphore::new(0)),
        }
    }
}

#[async_trait::async_trait]
impl guard::proxy::GateSink for RecordingSink {
    async fn arm_revert(&self, mutation: guard::proxy::ApiMutation) -> Option<String> {
        let handle = format!("test-handle-{}", self.calls.lock().unwrap().len());
        self.calls.lock().unwrap().push(mutation);
        Some(handle)
    }

    async fn mark_revert_dispatching(&self, handle: &str) -> bool {
        self.dispatching.lock().unwrap().push(handle.to_string());
        true
    }

    async fn mark_revert_forwarded(&self, handle: &str, resource_uid: Option<&str>) -> bool {
        self.handoffs.lock().unwrap().push(handle.to_string());
        self.activated.lock().unwrap().push(handle.to_string());
        self.resource_uids
            .lock()
            .unwrap()
            .push(resource_uid.map(str::to_string));
        self.activated_signal.add_permits(1);
        true
    }

    async fn provisional_deadline(&self, _handle: &str) -> Option<u64> {
        match self.deadline_unix.load(Ordering::SeqCst) {
            0 => None,
            deadline => Some(deadline),
        }
    }

    async fn mark_revert_indeterminate(
        &self,
        handle: &str,
        _reason: &str,
        resource_uid: Option<&str>,
    ) -> bool {
        self.handoffs.lock().unwrap().push(handle.to_string());
        self.indeterminate.lock().unwrap().push(handle.to_string());
        self.resource_uids
            .lock()
            .unwrap()
            .push(resource_uid.map(str::to_string));
        self.indeterminate_signal.add_permits(1);
        true
    }

    async fn cancel_staged_revert(&self, handle: &str) -> bool {
        self.cancelled.lock().unwrap().push(handle.to_string());
        true
    }

    async fn mark_revert_rejected(&self, handle: &str, _reason: &str) -> bool {
        self.handoffs.lock().unwrap().push(handle.to_string());
        self.rejected.lock().unwrap().push(handle.to_string());
        true
    }

    async fn resolve(&self, handle: &str) -> bool {
        self.resolved.lock().unwrap().push(handle.to_string());
        self.resolved_signal.add_permits(1);
        true
    }

    async fn authorize_cleanup(
        &self,
        handle: &str,
        resource_uid: &str,
        create_provenance: &str,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        let index = self
            .activated
            .lock()
            .unwrap()
            .iter()
            .position(|active| active == handle)
            .ok_or_else(|| "test cleanup authority is inactive".to_string())?;
        if self
            .resource_uids
            .lock()
            .unwrap()
            .get(index)
            .and_then(Option::as_deref)
            != Some(resource_uid)
            || self
                .calls
                .lock()
                .unwrap()
                .get(index)
                .and_then(|mutation| mutation.create_provenance.as_deref())
                != Some(create_provenance)
        {
            return Err("test cleanup authority identity changed".to_string());
        }
        handoff.forward().await
    }
}

#[derive(Clone, Default)]
struct ActivationFailSink {
    state: RecordingSink,
}

#[derive(Clone, Default)]
struct ClassificationFailSink {
    state: RecordingSink,
}

#[async_trait::async_trait]
impl guard::proxy::GateSink for ClassificationFailSink {
    async fn arm_revert(&self, mutation: guard::proxy::ApiMutation) -> Option<String> {
        self.state.arm_revert(mutation).await
    }

    async fn mark_revert_dispatching(&self, handle: &str) -> bool {
        self.state.mark_revert_dispatching(handle).await
    }

    async fn mark_revert_forwarded(&self, _handle: &str, _resource_uid: Option<&str>) -> bool {
        false
    }

    async fn mark_revert_indeterminate(
        &self,
        _handle: &str,
        _reason: &str,
        _resource_uid: Option<&str>,
    ) -> bool {
        false
    }

    async fn mark_revert_rejected(&self, _handle: &str, _reason: &str) -> bool {
        false
    }

    async fn cancel_staged_revert(&self, handle: &str) -> bool {
        self.state.cancel_staged_revert(handle).await
    }

    async fn resolve(&self, handle: &str) -> bool {
        self.state.resolve(handle).await
    }

    async fn authorize_cleanup(
        &self,
        handle: &str,
        resource_uid: &str,
        create_provenance: &str,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        self.state
            .authorize_cleanup(handle, resource_uid, create_provenance, handoff)
            .await
    }
}

#[async_trait::async_trait]
impl guard::proxy::GateSink for ActivationFailSink {
    async fn arm_revert(&self, mutation: guard::proxy::ApiMutation) -> Option<String> {
        self.state.arm_revert(mutation).await
    }

    async fn mark_revert_dispatching(&self, handle: &str) -> bool {
        self.state.mark_revert_dispatching(handle).await
    }

    async fn mark_revert_forwarded(&self, handle: &str, _resource_uid: Option<&str>) -> bool {
        self.state.handoffs.lock().unwrap().push(handle.to_string());
        self.state
            .activated
            .lock()
            .unwrap()
            .push(handle.to_string());
        false
    }

    async fn mark_revert_indeterminate(
        &self,
        handle: &str,
        reason: &str,
        resource_uid: Option<&str>,
    ) -> bool {
        self.state
            .mark_revert_indeterminate(handle, reason, resource_uid)
            .await
    }

    async fn cancel_staged_revert(&self, handle: &str) -> bool {
        self.state.cancel_staged_revert(handle).await
    }

    async fn mark_revert_rejected(&self, handle: &str, reason: &str) -> bool {
        self.state.mark_revert_rejected(handle, reason).await
    }

    async fn resolve(&self, handle: &str) -> bool {
        self.state.resolve(handle).await
    }

    async fn authorize_cleanup(
        &self,
        handle: &str,
        resource_uid: &str,
        create_provenance: &str,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        self.state
            .authorize_cleanup(handle, resource_uid, create_provenance, handoff)
            .await
    }
}

#[derive(Clone)]
struct BlockingCancelSink {
    stage_reached: Arc<tokio::sync::Semaphore>,
    release_stage: Arc<tokio::sync::Semaphore>,
    cancel_reached: Arc<tokio::sync::Semaphore>,
    release_cancel: Arc<tokio::sync::Semaphore>,
}

#[derive(Clone)]
struct BlockingUidTransitionSink {
    state: RecordingSink,
    reached: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}

#[derive(Clone)]
struct BlockingDispatchSink {
    state: RecordingSink,
    reached: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}

#[derive(Clone, Default)]
struct DispatchFailSink {
    state: RecordingSink,
}

impl Default for BlockingDispatchSink {
    fn default() -> Self {
        Self {
            state: RecordingSink::default(),
            reached: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        }
    }
}

impl Default for BlockingUidTransitionSink {
    fn default() -> Self {
        Self {
            state: RecordingSink::default(),
            reached: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        }
    }
}

#[derive(Clone, Copy)]
enum CleanupLeasePause {
    BeforeLease,
    AfterLease,
}

#[derive(Clone)]
struct CleanupLeaseSink {
    state: RecordingSink,
    coordination: Arc<tokio::sync::RwLock<bool>>,
    reached: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
    pause: CleanupLeasePause,
}

impl CleanupLeaseSink {
    fn new(pause: CleanupLeasePause) -> Self {
        Self {
            state: RecordingSink::default(),
            coordination: Arc::new(tokio::sync::RwLock::new(true)),
            reached: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
            pause,
        }
    }
}

#[async_trait::async_trait]
impl guard::proxy::GateSink for CleanupLeaseSink {
    async fn arm_revert(&self, mutation: guard::proxy::ApiMutation) -> Option<String> {
        self.state.arm_revert(mutation).await
    }

    async fn mark_revert_dispatching(&self, handle: &str) -> bool {
        self.state.mark_revert_dispatching(handle).await
    }

    async fn mark_revert_forwarded(&self, handle: &str, resource_uid: Option<&str>) -> bool {
        self.state.mark_revert_forwarded(handle, resource_uid).await
    }

    async fn mark_revert_indeterminate(
        &self,
        handle: &str,
        reason: &str,
        resource_uid: Option<&str>,
    ) -> bool {
        self.state
            .mark_revert_indeterminate(handle, reason, resource_uid)
            .await
    }

    async fn cancel_staged_revert(&self, handle: &str) -> bool {
        self.state.cancel_staged_revert(handle).await
    }

    async fn mark_revert_rejected(&self, handle: &str, reason: &str) -> bool {
        self.state.mark_revert_rejected(handle, reason).await
    }

    async fn resolve(&self, handle: &str) -> bool {
        self.state.resolve(handle).await
    }

    async fn authorize_cleanup(
        &self,
        handle: &str,
        resource_uid: &str,
        create_provenance: &str,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        if matches!(self.pause, CleanupLeasePause::BeforeLease) {
            self.reached.add_permits(1);
            self.release
                .acquire()
                .await
                .map_err(|_| "cleanup test barrier closed".to_string())?
                .forget();
        }
        let active = self.coordination.read().await;
        if matches!(self.pause, CleanupLeasePause::AfterLease) {
            self.reached.add_permits(1);
            self.release
                .acquire()
                .await
                .map_err(|_| "cleanup test barrier closed".to_string())?
                .forget();
        }
        if !*active {
            return Err("cleanup authority was revoked".to_string());
        }
        self.state
            .authorize_cleanup(handle, resource_uid, create_provenance, handoff)
            .await
    }
}

#[async_trait::async_trait]
impl guard::proxy::GateSink for BlockingUidTransitionSink {
    async fn arm_revert(&self, mutation: guard::proxy::ApiMutation) -> Option<String> {
        self.state.arm_revert(mutation).await
    }

    async fn mark_revert_dispatching(&self, handle: &str) -> bool {
        self.state.mark_revert_dispatching(handle).await
    }

    async fn mark_revert_forwarded(&self, handle: &str, resource_uid: Option<&str>) -> bool {
        self.reached.add_permits(1);
        if self.release.acquire().await.is_err() {
            return false;
        }
        self.state.mark_revert_forwarded(handle, resource_uid).await
    }

    async fn mark_revert_indeterminate(
        &self,
        handle: &str,
        reason: &str,
        resource_uid: Option<&str>,
    ) -> bool {
        self.state
            .mark_revert_indeterminate(handle, reason, resource_uid)
            .await
    }

    async fn cancel_staged_revert(&self, handle: &str) -> bool {
        self.state.cancel_staged_revert(handle).await
    }

    async fn mark_revert_rejected(&self, handle: &str, reason: &str) -> bool {
        self.state.mark_revert_rejected(handle, reason).await
    }

    async fn resolve(&self, handle: &str) -> bool {
        self.state.resolve(handle).await
    }

    async fn authorize_cleanup(
        &self,
        handle: &str,
        resource_uid: &str,
        create_provenance: &str,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        self.state
            .authorize_cleanup(handle, resource_uid, create_provenance, handoff)
            .await
    }
}

#[async_trait::async_trait]
impl guard::proxy::GateSink for BlockingDispatchSink {
    async fn arm_revert(&self, mutation: guard::proxy::ApiMutation) -> Option<String> {
        self.state.arm_revert(mutation).await
    }

    async fn mark_revert_dispatching(&self, handle: &str) -> bool {
        self.reached.add_permits(1);
        let Ok(permit) = self.release.acquire().await else {
            return false;
        };
        permit.forget();
        self.state.mark_revert_dispatching(handle).await
    }

    async fn mark_revert_forwarded(&self, handle: &str, resource_uid: Option<&str>) -> bool {
        self.state.mark_revert_forwarded(handle, resource_uid).await
    }

    async fn mark_revert_indeterminate(
        &self,
        handle: &str,
        reason: &str,
        resource_uid: Option<&str>,
    ) -> bool {
        self.state
            .mark_revert_indeterminate(handle, reason, resource_uid)
            .await
    }

    async fn cancel_staged_revert(&self, handle: &str) -> bool {
        self.state.cancel_staged_revert(handle).await
    }

    async fn mark_revert_rejected(&self, handle: &str, reason: &str) -> bool {
        self.state.mark_revert_rejected(handle, reason).await
    }

    async fn resolve(&self, handle: &str) -> bool {
        self.state.resolve(handle).await
    }

    async fn authorize_cleanup(
        &self,
        handle: &str,
        resource_uid: &str,
        create_provenance: &str,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        self.state
            .authorize_cleanup(handle, resource_uid, create_provenance, handoff)
            .await
    }
}

#[async_trait::async_trait]
impl guard::proxy::GateSink for DispatchFailSink {
    async fn arm_revert(&self, mutation: guard::proxy::ApiMutation) -> Option<String> {
        self.state.arm_revert(mutation).await
    }

    async fn mark_revert_dispatching(&self, _handle: &str) -> bool {
        false
    }

    async fn mark_revert_forwarded(&self, _handle: &str, _resource_uid: Option<&str>) -> bool {
        false
    }

    async fn mark_revert_indeterminate(
        &self,
        _handle: &str,
        _reason: &str,
        _resource_uid: Option<&str>,
    ) -> bool {
        false
    }

    async fn cancel_staged_revert(&self, handle: &str) -> bool {
        self.state.cancel_staged_revert(handle).await
    }

    async fn mark_revert_rejected(&self, _handle: &str, _reason: &str) -> bool {
        false
    }

    async fn resolve(&self, _handle: &str) -> bool {
        false
    }

    async fn authorize_cleanup(
        &self,
        _handle: &str,
        _resource_uid: &str,
        _create_provenance: &str,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        reject_test_cleanup(handoff).await
    }
}

#[async_trait::async_trait]
impl guard::proxy::GateSink for BlockingCancelSink {
    async fn arm_revert(&self, _mutation: guard::proxy::ApiMutation) -> Option<String> {
        self.stage_reached.add_permits(1);
        self.release_stage.acquire().await.ok()?.forget();
        Some("blocked-cancel-handle".to_string())
    }

    async fn mark_revert_dispatching(&self, _handle: &str) -> bool {
        true
    }

    async fn mark_revert_forwarded(&self, _handle: &str, _resource_uid: Option<&str>) -> bool {
        false
    }

    async fn mark_revert_indeterminate(
        &self,
        _handle: &str,
        _reason: &str,
        _resource_uid: Option<&str>,
    ) -> bool {
        false
    }

    async fn cancel_staged_revert(&self, _handle: &str) -> bool {
        self.cancel_reached.add_permits(1);
        if self.release_cancel.acquire().await.is_err() {
            return false;
        }
        true
    }

    async fn mark_revert_rejected(&self, _handle: &str, _reason: &str) -> bool {
        false
    }

    async fn resolve(&self, _handle: &str) -> bool {
        false
    }

    async fn authorize_cleanup(
        &self,
        _handle: &str,
        _resource_uid: &str,
        _create_provenance: &str,
        _handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        Err("test cleanup authority is unavailable".to_string())
    }
}

/// Mock apiserver for the write path: returns a created Pod for POST, and a
/// Deployment (with resourceVersion) for the snapshot GET and the PATCH.
async fn write_mock_handler(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    write_mock_handler_with_provenance(req, &CreateProvenance::default()).await
}

async fn write_mock_handler_with_provenance(
    req: Request<Incoming>,
    provenance: &CreateProvenance,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (method, path) = observe_create_provenance(req, provenance).await;
    let is_create = method == hyper::Method::POST;
    let is_created_pod = path.ends_with("/pods/web-123");
    let (code, mut body) = if is_create || is_created_pod {
        (
            if is_create { 201 } else { 200 },
            json!({"kind": "Pod", "apiVersion": "v1", "metadata": {"name": "web-123", "namespace": "dev", "uid": "pod-uid", "resourceVersion": "40"}}),
        )
    } else {
        (
            200,
            json!({
                "kind": "Deployment",
                "apiVersion": "apps/v1",
                "metadata": {"name": "api", "namespace": "dev", "uid": "deployment-uid", "resourceVersion": "42"},
                "spec": {"replicas": 3}
            }),
        )
    };
    if is_create || is_created_pod {
        attach_create_provenance(&mut body, provenance);
    }
    Ok(Response::builder()
        .status(code)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap())
}

async fn spawn_write_mock() -> String {
    spawn_write_mock_with_observation().await.0
}

async fn spawn_counted_write_mock(writes: Arc<AtomicUsize>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => continue,
            };
            let writes = writes.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |request| {
                            let writes = writes.clone();
                            async move {
                                if request.method() != hyper::Method::GET {
                                    writes.fetch_add(1, Ordering::SeqCst);
                                }
                                write_mock_handler(request).await
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

async fn spawn_write_mock_with_observation() -> (String, CreateProvenance) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let provenance = CreateProvenance::default();
    let observed = provenance.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            let provenance = provenance.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ =
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            io,
                            service_fn(move |request| {
                                let provenance = provenance.clone();
                                async move {
                                    write_mock_handler_with_provenance(request, &provenance).await
                                }
                            }),
                        )
                        .await;
            });
        }
    });
    (format!("http://{addr}"), observed)
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
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, None)
            .with_listener_mode(ApiListenerMode::Policy),
    );

    let sink = RecordingSink::default();
    let deadline_unix = guard::env::now_unix().saturating_add(300);
    sink.deadline_unix.store(deadline_unix, Ordering::SeqCst);
    proxy.attach_gate(Arc::new(sink.clone()));
    proxy.attach_session_sink(Arc::new(LiveSessionSink));

    tokio::spawn(proxy.clone().serve_on(listener));

    let base = format!("https://{listen}");
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();

    // A create in a non-prod namespace is forwarded and a delete-revert is armed.
    let resp = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("live-session")
        .body(r#"{"metadata":{"name":"web-123"}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "create forwarded");
    let provisional_header = resp
        .headers()
        .get("x-guard-provisional")
        .and_then(|value| value.to_str().ok())
        .unwrap();
    assert!(provisional_header.starts_with("test-handle-0;"));
    assert!(provisional_header.contains(&format!("deadline_unix={deadline_unix}")));
    assert!(provisional_header.contains("seconds_remaining="));
    let warning = resp
        .headers()
        .get("warning")
        .and_then(|value| value.to_str().ok())
        .unwrap();
    assert!(
        warning.contains(&guard::gating::provisional::operator_confirm_command(
            "test-handle-0"
        ))
    );
    assert!(warning.contains(&format!("deadline_unix={deadline_unix}")));
    assert!(warning.contains("seconds_remaining="));

    // A patch on a named object snapshots the prior state and arms a restore.
    let observed = client
        .get(format!(
            "{base}/apis/apps/v1/namespaces/dev/deployments/api"
        ))
        .bearer_auth("live-session")
        .send()
        .await
        .unwrap();
    assert_eq!(observed.status(), 200, "deployment observation forwarded");
    let resp = client
        .patch(format!(
            "{base}/apis/apps/v1/namespaces/dev/deployments/api"
        ))
        .bearer_auth("live-session")
        .header("content-type", "application/merge-patch+json")
        .body(r#"{"spec":{"replicas":5}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "patch forwarded");
    let provisional_header = resp
        .headers()
        .get("x-guard-provisional")
        .and_then(|value| value.to_str().ok())
        .unwrap();
    assert!(provisional_header.starts_with("test-handle-1;"));
    assert!(provisional_header.contains(&format!("deadline_unix={deadline_unix}")));
    assert!(provisional_header.contains("seconds_remaining="));

    // Both response headers prove the reverts were durable before success was
    // returned; the sink records the same handles for lifecycle assertions.
    assert_eq!(sink.calls.lock().unwrap().len(), 2);

    let calls = sink.calls.lock().unwrap();
    assert!(calls.iter().all(|call| {
        call.session_fingerprint.as_deref() == Some("session-fingerprint")
            && call.upstream_target == mock_base
            && call.upstream_identity.len() == 64
    }));
    let resource_uids = sink.resource_uids.lock().unwrap();
    assert!(resource_uids.first().is_some_and(Option::is_some));
    assert!(resource_uids.get(1).is_some_and(Option::is_none));

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
    let reflected_authorization = req
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
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
        .header("x-reflected-authorization", &reflected_authorization)
        .header(
            "location",
            format!("https://attacker.invalid/collect?auth={reflected_authorization}"),
        )
        .header(
            "link",
            "</api/v1/namespaces/dev/pods?limit=50&continue=next>; rel=\"next\"",
        )
        .header("x-ratelimit-limit", "60")
        .header("x-ratelimit-remaining", "42")
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
async fn proxy_denies_subresource_and_identity_override_headers() {
    let mock_base = spawn_header_echo_upstream().await;
    let kubeconfig = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n  - name: c\n    cluster: {{server: \"{mock_base}\"}}\ncontexts:\n  - name: ctx\n    context: {{cluster: c, user: u}}\nusers:\n  - name: u\n    user: {{}}\n"
    );
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(include_str!("../examples/api-policy.yaml")).expect("policy");
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(ApiProxy::new(listen, tls, upstream, policy, None));
    let session_sink = RecordingSessionSink::default();
    proxy.attach_session_sink(Arc::new(session_sink.clone()));

    tokio::spawn(proxy.clone().serve_on(listener));

    let base = format!("https://{listen}");
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

    // 2. A request carrying identity headers is rejected instead of silently
    // changing the question by evaluating it as the proxy identity.
    let impersonate_resp = client
        .get(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("live-session")
        .header("Impersonate-User", "system:masters")
        .header("Impersonate-Group", "system:masters")
        .send()
        .await
        .unwrap();
    assert_eq!(
        impersonate_resp.status(),
        403,
        "Kubernetes impersonation headers must be rejected"
    );
    let v: Value = impersonate_resp.json().await.unwrap();
    assert!(v["message"].as_str().unwrap().contains("not supported"));

    let remote_user_resp = client
        .get(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("live-session")
        .header("X-Remote-User", "admin")
        .header("X-Remote-Group", "system:masters")
        .send()
        .await
        .unwrap();
    assert_eq!(
        remote_user_resp.status(),
        403,
        "front-proxy identity headers must be rejected"
    );
    let v: Value = remote_user_resp.json().await.unwrap();
    assert!(v["message"].as_str().unwrap().contains("not supported"));
    let restricted_resp = client
        .get(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("restricted-session")
        .header("Impersonate-User", "system:masters")
        .send()
        .await
        .unwrap();
    assert_eq!(restricted_resp.status(), 403);
    let v: Value = restricted_resp.json().await.unwrap();
    assert!(v["message"].as_str().unwrap().contains("not supported"));
    let events = session_sink.events.lock().unwrap();
    assert_eq!(events.len(), 3);
    assert!(events
        .iter()
        .all(|event| !event.allowed && event.status == 403));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guard_session_bearer_is_validated_and_never_forwarded() {
    let mock_base = spawn_header_echo_upstream().await;
    let kubeconfig = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n  - name: c\n    cluster: {{server: \"{mock_base}\"}}\ncontexts:\n  - name: ctx\n    context: {{cluster: c, user: u}}\nusers:\n  - name: u\n    user: {{token: upstream-only}}\n"
    );
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(include_str!("../examples/api-policy.yaml")).unwrap();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(ApiProxy::new(listen, tls, upstream, policy, None));
    proxy.attach_session_sink(Arc::new(LiveSessionSink));
    tokio::spawn(proxy.clone().serve_on(listener));
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let base = format!("https://{listen}");

    let response = client
        .get(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("live-session")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("set-cookie"));
    assert!(!response.headers().contains_key("authorization"));
    assert!(!response.headers().contains_key("www-authenticate"));
    assert_eq!(
        response
            .headers()
            .get("link")
            .and_then(|value| value.to_str().ok()),
        Some("</api/v1/namespaces/dev/pods?limit=50&continue=next>; rel=\"next\"")
    );
    assert_eq!(response.headers().get("x-ratelimit-limit").unwrap(), "60");
    assert_eq!(
        response.headers().get("x-ratelimit-remaining").unwrap(),
        "42"
    );
    let body: Value = response.json().await.unwrap();
    assert_eq!(
        body["receivedHeaders"]["authorization"].as_str(),
        Some("[REDACTED]"),
        "the upstream credential must be injected but redacted from the response"
    );
    assert!(!body.to_string().contains("live-session"));
    assert!(!body.to_string().contains("upstream-only"));

    let invalid = client
        .get(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("expired-session")
        .send()
        .await
        .unwrap();
    assert_eq!(
        invalid.status(),
        403,
        "unknown or expired sessions fail closed"
    );

    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(include_str!("../examples/api-policy.yaml")).unwrap();
    let (restricted_listener, restricted_listen) = reserve_listener().await;
    let restricted_proxy = Arc::new(
        ApiProxy::new(restricted_listen, tls, upstream, policy, None)
            .with_endpoint_context("cluster-a", "cluster-a/token"),
    );
    restricted_proxy.attach_session_sink(Arc::new(RestrictedCredentialSessionSink));
    tokio::spawn(restricted_proxy.serve_on(restricted_listener));
    let restricted_client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let restricted = restricted_client
        .get(format!(
            "https://{restricted_listen}/api/v1/namespaces/dev/pods"
        ))
        .bearer_auth("restricted-session")
        .send()
        .await
        .unwrap();
    assert_eq!(restricted.status(), 403);
    assert!(restricted.text().await.unwrap().contains("not entitled"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readonly_listener_requires_session_override_and_keeps_protocol_denies() {
    let mock_base = spawn_mock_upstream().await;
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(&mock_base), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml("default: allow\n").unwrap();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, None)
            .with_listener_mode(ApiListenerMode::Readonly),
    );
    let judge = RecordingJudge::new(vec![judge_allow(Some(1), Some(Reversibility::Reversible))]);
    proxy.attach_judge(Arc::new(judge.clone())).await;
    proxy.attach_session_sink(Arc::new(LiveSessionSink));
    tokio::spawn(proxy.clone().serve_on(listener));
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let base = format!("https://{listen}");

    let unscoped = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(unscoped.status(), 403);

    let scoped = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("live-session")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(scoped.status(), 200);
    {
        let summaries = judge.summaries.lock().unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(
            summaries[0].session_intent.as_deref(),
            Some("manage development pods")
        );
    }

    let hard_deny = client
        .post(format!("{base}/api/v1/namespaces/dev/pods/web/exec"))
        .bearer_auth("live-session")
        .send()
        .await
        .unwrap();
    assert_eq!(hard_deny.status(), 403);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issued_session_modes_enforce_api_boundary_without_prompt_bypass() {
    let mock_base = spawn_mock_upstream().await;
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(&mock_base), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(
        "default: allow\nrules:\n  - verbs: [get]\n    resources: [configmaps]\n    namespaces: [dev]\n    action: evaluate\n  - verbs: [delete]\n    resources: [pods]\n    namespaces: [dev]\n    action: deny\n",
    )
    .unwrap();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, None)
            .with_listener_mode(ApiListenerMode::Readonly),
    );
    let judge = ModeCoverageJudge::default();
    proxy.attach_judge(Arc::new(judge.clone())).await;
    proxy.attach_session_sink(Arc::new(ModeSessionSink));
    tokio::spawn(proxy.serve_on(listener));
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let base = format!("https://{listen}");

    let policy_only = client
        .get(format!("{base}/api/v1/namespaces/dev/configmaps/cm"))
        .bearer_auth("policy-only")
        .send()
        .await
        .unwrap();
    assert_eq!(policy_only.status(), 403);
    assert_eq!(judge.judge_calls.load(Ordering::SeqCst), 0);

    for token in ["policy-only", "readonly"] {
        let response = client
            .post(format!("{base}/api/v1/namespaces/dev/pods"))
            .bearer_auth(token)
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            403,
            "{token} prompt must not authorize a write"
        );
    }
    assert_eq!(judge.judge_calls.load(Ordering::SeqCst), 0);

    let covered = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("readonly-authorized")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        covered.status(),
        200,
        "exact typed session coverage authorizes the write"
    );
    assert_eq!(judge.judge_calls.load(Ordering::SeqCst), 0);

    let evaluated = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("evaluator")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(evaluated.status(), 200);
    assert_eq!(judge.judge_calls.load(Ordering::SeqCst), 1);

    let explicit_deny = client
        .delete(format!("{base}/api/v1/namespaces/dev/pods/web"))
        .bearer_auth("readonly-authorized")
        .send()
        .await
        .unwrap();
    assert_eq!(
        explicit_deny.status(),
        403,
        "operator policy deny stays absolute"
    );
    assert_eq!(judge.judge_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_expansion_is_revalidated_immediately_before_forward() {
    let mock_base = spawn_write_mock().await;
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(&mock_base), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml("default: allow\n").unwrap();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, None)
            .with_listener_mode(ApiListenerMode::Readonly),
    );
    proxy
        .attach_judge(Arc::new(RecordingJudge::new(vec![judge_allow(
            Some(1),
            Some(Reversibility::Reversible),
        )])))
        .await;
    proxy.attach_session_sink(Arc::new(ChangingSessionSink {
        resolutions: AtomicUsize::new(0),
    }));
    tokio::spawn(proxy.clone().serve_on(listener));

    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    assert_eq!(
        client
            .get(format!(
                "https://{listen}/apis/apps/v1/namespaces/dev/deployments/api"
            ))
            .bearer_auth("live-then-edited")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let response = client
        .patch(format!(
            "https://{listen}/apis/apps/v1/namespaces/dev/deployments/api"
        ))
        .bearer_auth("live-then-edited")
        .header("content-type", "application/merge-patch+json")
        .body(r#"{"metadata":{"labels":{"checked":"true"}}}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 403);
    assert!(response
        .text()
        .await
        .unwrap()
        .contains("session authority changed"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hot_reloaded_explicit_deny_is_rechecked_after_evaluator_delay() {
    let writes = Arc::new(AtomicUsize::new(0));
    let mock_base = spawn_counted_write_mock(writes.clone()).await;
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(&mock_base), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let temp = tempfile::tempdir().unwrap();
    let policy_path = temp.path().join("api-policy.yaml");
    let evaluate_policy = "default: deny\nrules:\n  - verbs: [get]\n    resources: [deployments]\n    namespaces: [dev]\n    action: allow\n  - verbs: [patch]\n    resources: [deployments]\n    namespaces: [dev]\n    action: evaluate\n";
    std::fs::write(&policy_path, evaluate_policy).unwrap();
    let policy = ApiPolicy::load_file(&policy_path).unwrap();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, Some(policy_path.clone()))
            .with_policy_reload_interval(Duration::from_millis(50)),
    );
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    proxy
        .attach_judge(Arc::new(BlockingJudge {
            started: started.clone(),
            release: release.clone(),
        }))
        .await;
    proxy.attach_session_sink(Arc::new(LiveSessionSink));
    tokio::spawn(proxy.clone().serve_on(listener));
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    assert_eq!(
        client
            .get(format!(
                "https://{listen}/apis/apps/v1/namespaces/dev/deployments/api"
            ))
            .bearer_auth("live-session")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let request = tokio::spawn(async move {
        client
            .patch(format!(
                "https://{listen}/apis/apps/v1/namespaces/dev/deployments/api"
            ))
            .bearer_auth("live-session")
            .body("{}")
            .send()
            .await
            .unwrap()
    });
    started.notified().await;
    let deny_policy = "default: deny\nrules:\n  - verbs: [patch]\n    resources: [deployments]\n    namespaces: [dev]\n    action: deny\n";
    std::fs::write(&policy_path, deny_policy).unwrap();
    wait_for_policy_reload(&proxy, deny_policy).await;
    release.notify_one();

    let response = request.await.unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(
        writes.load(Ordering::SeqCst),
        0,
        "the stale evaluator allow must not reach the upstream"
    );
}

async fn spawn_blocking_snapshot_mock(
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    writes: Arc<AtomicUsize>,
) -> String {
    let gets = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let started = started.clone();
            let release = release.clone();
            let writes = writes.clone();
            let gets = gets.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let started = started.clone();
                    let release = release.clone();
                    let writes = writes.clone();
                    let gets = gets.clone();
                    async move {
                        if req.method() == hyper::Method::GET {
                            if gets.fetch_add(1, Ordering::SeqCst) == 1 {
                                started.notify_one();
                                release.notified().await;
                            }
                        } else {
                            writes.fetch_add(1, Ordering::SeqCst);
                        }
                        write_mock_handler(req).await
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_allow_revalidates_session_after_delayed_snapshot() {
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let writes = Arc::new(AtomicUsize::new(0));
    let mock_base =
        spawn_blocking_snapshot_mock(started.clone(), release.clone(), writes.clone()).await;
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(&mock_base), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(
        "default: deny\nrules:\n  - verbs: [get]\n    resources: [deployments]\n    namespaces: [dev]\n    action: allow\n  - verbs: [patch]\n    resources: [deployments]\n    namespaces: [dev]\n    action: allow\n",
    )
    .unwrap();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, None)
            .with_listener_mode(ApiListenerMode::Policy),
    );
    proxy.attach_gate(Arc::new(RecordingSink::default()));
    let remaining = Arc::new(AtomicUsize::new(3));
    proxy.attach_session_sink(Arc::new(BudgetSessionSink {
        remaining_resolutions: remaining.clone(),
    }));
    tokio::spawn(proxy.serve_on(listener));
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    assert_eq!(
        client
            .get(format!(
                "https://{listen}/apis/apps/v1/namespaces/dev/deployments/api"
            ))
            .bearer_auth("budget-session")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let request = tokio::spawn(async move {
        client
            .patch(format!(
                "https://{listen}/apis/apps/v1/namespaces/dev/deployments/api"
            ))
            .bearer_auth("budget-session")
            .body("{}")
            .send()
            .await
            .unwrap()
    });
    started.notified().await;
    remaining.store(0, Ordering::SeqCst);
    release.notify_one();

    assert_eq!(request.await.unwrap().status(), 403);
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}

async fn assert_direct_allow_reload_fails_closed(next_action: &str, next_intent: &str) {
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let writes = Arc::new(AtomicUsize::new(0));
    let mock_base =
        spawn_blocking_snapshot_mock(started.clone(), release.clone(), writes.clone()).await;
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(&mock_base), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let temp = tempfile::tempdir().unwrap();
    let policy_path = temp.path().join("api-policy.yaml");
    std::fs::write(
        &policy_path,
        "intent: initial task intent\ndefault: deny\nrules:\n  - verbs: [get]\n    resources: [deployments]\n    namespaces: [dev]\n    action: allow\n  - verbs: [patch]\n    resources: [deployments]\n    namespaces: [dev]\n    action: allow\n",
    )
    .unwrap();
    let policy = ApiPolicy::load_file(&policy_path).unwrap();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, Some(policy_path.clone()))
            .with_listener_mode(ApiListenerMode::Policy)
            .with_policy_reload_interval(Duration::from_millis(50)),
    );
    proxy.attach_gate(Arc::new(RecordingSink::default()));
    proxy.attach_session_sink(Arc::new(LiveSessionSink));
    tokio::spawn(proxy.clone().serve_on(listener));
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    assert_eq!(
        client
            .get(format!(
                "https://{listen}/apis/apps/v1/namespaces/dev/deployments/api"
            ))
            .bearer_auth("live-session")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let request = tokio::spawn(async move {
        client
            .patch(format!(
                "https://{listen}/apis/apps/v1/namespaces/dev/deployments/api"
            ))
            .bearer_auth("live-session")
            .body("{}")
            .send()
            .await
            .unwrap()
    });
    started.notified().await;
    let next_policy = format!(
        "intent: {next_intent}\ndefault: deny\nrules:\n  - verbs: [patch]\n    resources: [deployments]\n    namespaces: [dev]\n    action: {next_action}\n"
    );
    std::fs::write(&policy_path, &next_policy).unwrap();
    wait_for_policy_reload(&proxy, &next_policy).await;
    release.notify_one();

    assert_eq!(request.await.unwrap().status(), 403);
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_allow_fails_closed_for_every_hot_authority_transition() {
    for (action, intent) in [
        ("hold", "initial task intent"),
        ("evaluate", "initial task intent"),
        ("deny", "initial task intent"),
        ("allow", "changed evaluator intent"),
    ] {
        assert_direct_allow_reload_fails_closed(action, intent).await;
    }
}

/// A `SelfSubjectAccessReview` (`kubectl auth can-i`) is forwarded with the same
/// single upstream credential the proxy injects on every request, so the
/// self-check reflects the identity that actually performs writes rather than a
/// separate or stale one. The header-echo upstream reports the Authorization it
/// received, and the proxy redacts that reflected credential before returning
/// the review response.
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
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, None)
            .with_listener_mode(ApiListenerMode::Policy),
    );
    proxy.attach_session_sink(Arc::new(LiveSessionSink));

    tokio::spawn(proxy.clone().serve_on(listener));

    let base = format!("https://{listen}");
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
        .bearer_auth("live-session")
        .header("content-type", "application/json")
        .body(review.to_string())
        .send()
        .await
        .expect("self access review");
    assert_eq!(resp.status(), 200, "the review is forwarded");
    assert!(
        resp.headers().get("x-reflected-authorization").is_none(),
        "arbitrary upstream response headers are not forwarded"
    );
    assert!(
        resp.headers().get("location").is_none(),
        "cross-origin credential-bearing redirects are dropped"
    );
    let v: Value = resp.json().await.unwrap();
    let received = v["receivedHeaders"].as_object().expect("headers");
    assert_eq!(
        received.get("authorization").and_then(Value::as_str),
        Some("[REDACTED]"),
        "the upstream credential must be injected but never reflected to the client: {received:?}"
    );
}

/// Mock apiserver for the provenance test: a POST returns a created Pod named
/// `check-pod`; a DELETE returns a success Status (the object removed).
async fn create_delete_mock_handler(
    req: Request<Incoming>,
    provenance: CreateProvenance,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (method, _) = observe_create_provenance(req, &provenance).await;
    let (code, mut body) = match method {
        hyper::Method::POST => (201, created_pod_object()),
        hyper::Method::GET => (200, created_pod_object()),
        hyper::Method::DELETE => (
            200,
            json!({"kind": "Status", "apiVersion": "v1", "status": "Success"}),
        ),
        _ => (
            200,
            json!({"kind": "Status", "apiVersion": "v1", "status": "Success"}),
        ),
    };
    if matches!(method, hyper::Method::POST | hyper::Method::GET) {
        attach_create_provenance(&mut body, &provenance);
    }
    Ok(Response::builder()
        .status(code)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap())
}

fn created_pod_object() -> Value {
    json!({
        "kind": "Pod",
        "apiVersion": "v1",
        "metadata": {
            "name": "check-pod",
            "namespace": "dev",
            "uid": "check-pod-uid",
            "resourceVersion": "7"
        },
        "spec": {"containers": []}
    })
}

async fn spawn_create_delete_mock() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let provenance = CreateProvenance::default();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            let provenance = provenance.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |request| {
                            create_delete_mock_handler(request, provenance.clone())
                        }),
                    )
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

async fn spawn_failing_create_delete_mock(outcomes: VecDeque<Option<u16>>) -> String {
    let outcomes = Arc::new(std::sync::Mutex::new(outcomes));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let provenance = CreateProvenance::default();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => continue,
            };
            let outcomes = outcomes.clone();
            let provenance = provenance.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req: Request<Incoming>| {
                    let outcomes = outcomes.clone();
                    let provenance = provenance.clone();
                    async move {
                        let (method, _) = observe_create_provenance(req, &provenance).await;
                        if method == hyper::Method::POST {
                            let mut body = created_pod_object();
                            attach_create_provenance(&mut body, &provenance);
                            return Ok::<_, std::io::Error>(
                                Response::builder()
                                    .status(201)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(body.to_string())))
                                    .unwrap(),
                            );
                        }
                        if method == hyper::Method::DELETE {
                            let outcome = outcomes.lock().unwrap().pop_front().unwrap_or(Some(200));
                            let Some(status) = outcome else {
                                return Err(std::io::Error::other("simulated upstream disconnect"));
                            };
                            return Ok(Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(
                                    json!({"kind":"Status","status": if status < 300 {"Success"} else {"Failure"}}).to_string(),
                                )))
                                .unwrap());
                        }
                        let mut body = created_pod_object();
                        attach_create_provenance(&mut body, &provenance);
                        Ok(Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(body.to_string())))
                            .unwrap())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

async fn spawn_truncated_cleanup_mock() -> String {
    type MockBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let provenance = CreateProvenance::default();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let provenance = provenance.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let provenance = provenance.clone();
                    async move {
                        let (method, _) = observe_create_provenance(req, &provenance).await;
                        let response: Response<MockBody> = if method == hyper::Method::POST {
                            let mut body = created_pod_object();
                            attach_create_provenance(&mut body, &provenance);
                            let body = body.to_string();
                            Response::builder()
                                .status(201)
                                .header("content-type", "application/json")
                                .body(
                                    Full::new(Bytes::from(body))
                                        .map_err(|never| match never {})
                                        .boxed(),
                                )
                                .unwrap()
                        } else if method == hyper::Method::DELETE {
                            let frames = futures::stream::iter([
                                Ok(Frame::data(Bytes::from_static(b"{"))),
                                Err(std::io::Error::other("simulated body disconnect")),
                            ]);
                            Response::builder()
                                .status(200)
                                .header("content-type", "application/json")
                                .body(StreamBody::new(frames).boxed())
                                .unwrap()
                        } else {
                            let mut body = created_pod_object();
                            attach_create_provenance(&mut body, &provenance);
                            Response::builder()
                                .status(200)
                                .header("content-type", "application/json")
                                .body(
                                    Full::new(Bytes::from(body.to_string()))
                                        .map_err(|never| match never {})
                                        .boxed(),
                                )
                                .unwrap()
                        };
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

async fn spawn_stalled_cleanup_body_mock() -> String {
    type MockBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let provenance = CreateProvenance::default();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let provenance = provenance.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let provenance = provenance.clone();
                    async move {
                        let (method, _) = observe_create_provenance(req, &provenance).await;
                        let response: Response<MockBody> = if method == hyper::Method::DELETE {
                            let frames =
                                futures::stream::pending::<Result<Frame<Bytes>, std::io::Error>>();
                            Response::builder()
                                .status(200)
                                .header("content-type", "application/json")
                                .body(StreamBody::new(frames).boxed())
                                .unwrap()
                        } else {
                            let status = if method == hyper::Method::POST {
                                201
                            } else {
                                200
                            };
                            let mut body = created_pod_object();
                            attach_create_provenance(&mut body, &provenance);
                            Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .body(
                                    Full::new(Bytes::from(body.to_string()))
                                        .map_err(|never| match never {})
                                        .boxed(),
                                )
                                .unwrap()
                        };
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

async fn start_provenance_proxy(
    mock_base: String,
    session_sink: Option<Arc<dyn ApiSessionSink>>,
) -> (SingleConnectionClient, RecordingSink) {
    start_provenance_proxy_with_body_timeout(mock_base, session_sink, Duration::from_secs(10)).await
}

async fn start_provenance_proxy_with_body_timeout(
    mock_base: String,
    session_sink: Option<Arc<dyn ApiSessionSink>>,
    body_timeout: Duration,
) -> (SingleConnectionClient, RecordingSink) {
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(&mock_base), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(include_str!("../examples/api-policy.yaml")).unwrap();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, None)
            .with_listener_mode(ApiListenerMode::Policy)
            .with_upstream_body_timeout(body_timeout),
    );
    let sink = RecordingSink::default();
    proxy.attach_gate(Arc::new(sink.clone()));
    proxy.attach_session_sink(session_sink.unwrap_or_else(|| Arc::new(LiveSessionSink)));
    tokio::spawn(proxy.serve_on(listener));
    let client = SingleConnectionClient::connect(listen, &ca_pem).await;
    (client, sink)
}

struct SingleConnectionClient {
    sender: hyper::client::conn::http2::SendRequest<Full<Bytes>>,
    authority: String,
}

impl SingleConnectionClient {
    async fn connect(listen: std::net::SocketAddr, ca_pem: &str) -> Self {
        let ca_der = base64::engine::general_purpose::STANDARD
            .decode(
                ca_pem
                    .lines()
                    .filter(|line| !line.starts_with("-----"))
                    .collect::<String>(),
            )
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(pki_types::CertificateDer::from(ca_der)).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let tcp = tokio::net::TcpStream::connect(listen).await.unwrap();
        let server_name = pki_types::ServerName::try_from("127.0.0.1")
            .unwrap()
            .to_owned();
        let tls_stream = connector.connect(server_name, tcp).await.unwrap();
        let (sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls_stream))
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Self {
            sender,
            authority: listen.to_string(),
        }
    }

    async fn request(
        &mut self,
        method: hyper::Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<&str>,
    ) -> hyper::StatusCode {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("https://{}{}", self.authority, path));
        if let Some(bearer) = bearer {
            builder = builder.header("authorization", format!("Bearer {bearer}"));
        }
        let request = builder
            .body(Full::new(Bytes::from(body.unwrap_or_default().to_string())))
            .unwrap();
        let response = self.sender.send_request(request).await.unwrap();
        let status = response.status();
        response.into_body().collect().await.unwrap();
        status
    }
}

/// A delete of a resource guard itself created earlier in the session is
/// contained cleanup (e.g. a Helm post-install hook removing its own check
/// resource): it is allowed and its now-moot auto-revert is resolved, rather
/// than being held like an unrecorded destructive delete. A delete of a
/// resource with no creation record keeps the strict policy handling (hold).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_allows_contained_delete_of_created_resource() {
    let (mut client, sink) = start_provenance_proxy(spawn_create_delete_mock().await, None).await;

    // This test's assertions depend on all four requests landing on the same
    // proxy connection because provenance is connection-scoped. The dedicated
    // HTTP/2 client owns one TLS connection and drains every response body.

    // A delete with no creation record is held for operator approval (strict).
    let status = client
        .request(
            hyper::Method::DELETE,
            "/api/v1/namespaces/dev/pods/other-pod",
            Some("live-session"),
            None,
        )
        .await;
    assert_eq!(status, 403, "delete of an unrecorded resource stays held");

    // Create a resource through the proxy; guard records its provenance.
    let status = client
        .request(
            hyper::Method::POST,
            "/api/v1/namespaces/dev/pods",
            Some("live-session"),
            Some(r#"{"metadata":{"name":"check-pod"}}"#),
        )
        .await;
    assert_eq!(status, 201, "create forwarded");
    assert_eq!(sink.calls.lock().unwrap().len(), 1);

    // Deleting that same resource is now contained cleanup: allowed and forwarded.
    let status = client
        .request(
            hyper::Method::DELETE,
            "/api/v1/namespaces/dev/pods/check-pod",
            Some("live-session"),
            None,
        )
        .await;
    assert_eq!(
        status, 200,
        "delete of a guard-created resource is contained and allowed"
    );

    // The now-moot auto-revert for the create was resolved.
    assert_eq!(sink.resolved.lock().unwrap().len(), 1);
    assert_eq!(
        sink.calls.lock().unwrap().len(),
        1,
        "contained delete forwards without arming a delete-restore revert"
    );

    // Provenance is single-use: a second delete of the same name has no record
    // and falls back to the strict hold.
    let status = client
        .request(
            hyper::Method::DELETE,
            "/api/v1/namespaces/dev/pods/check-pod",
            Some("live-session"),
            None,
        )
        .await;
    assert_eq!(
        status, 403,
        "provenance is consumed; a repeat delete is held again"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn contained_delete_retains_revert_on_transport_4xx_and_5xx_failures() {
    for (first, expected) in [(Some(404), 404), (Some(503), 503), (None, 502)] {
        let mock = spawn_failing_create_delete_mock(VecDeque::from([first, Some(200)])).await;
        let (mut client, sink) = start_provenance_proxy(mock, None).await;

        assert_eq!(
            client
                .request(
                    hyper::Method::POST,
                    "/api/v1/namespaces/dev/pods",
                    Some("live-session"),
                    Some(r#"{"metadata":{"name":"check-pod"}}"#),
                )
                .await,
            201
        );

        let status = client
            .request(
                hyper::Method::DELETE,
                "/api/v1/namespaces/dev/pods/check-pod",
                Some("live-session"),
                None,
            )
            .await;
        assert_eq!(status.as_u16(), expected);
        assert!(
            sink.resolved.lock().unwrap().is_empty(),
            "failed cleanup must retain its armed revert"
        );

        if first.is_some() {
            assert_eq!(
                client
                    .request(
                        hyper::Method::DELETE,
                        "/api/v1/namespaces/dev/pods/check-pod",
                        Some("live-session"),
                        None,
                    )
                    .await,
                200
            );
            assert_eq!(
                sink.resolved.lock().unwrap().len(),
                1,
                "the retained revert resolves only after a later 2xx delete"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn contained_delete_retains_revert_when_session_expires_before_forward() {
    let remaining = Arc::new(AtomicUsize::new(2));
    let session_sink = BudgetSessionSink {
        remaining_resolutions: remaining.clone(),
    };
    let (mut client, sink) = start_provenance_proxy(
        spawn_create_delete_mock().await,
        Some(Arc::new(session_sink)),
    )
    .await;

    assert_eq!(
        client
            .request(
                hyper::Method::POST,
                "/api/v1/namespaces/dev/pods",
                Some("budget-session"),
                Some(r#"{"metadata":{"name":"check-pod"}}"#),
            )
            .await,
        201
    );

    remaining.store(1, Ordering::SeqCst);
    assert_eq!(
        client
            .request(
                hyper::Method::DELETE,
                "/api/v1/namespaces/dev/pods/check-pod",
                Some("budget-session"),
                None,
            )
            .await,
        403
    );
    assert!(sink.resolved.lock().unwrap().is_empty());

    remaining.store(2, Ordering::SeqCst);
    assert_eq!(
        client
            .request(
                hyper::Method::DELETE,
                "/api/v1/namespaces/dev/pods/check-pod",
                Some("budget-session"),
                None,
            )
            .await,
        200
    );
    assert_eq!(sink.resolved.lock().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn contained_delete_retains_revert_when_a_2xx_body_disconnects() {
    let (mut client, sink) =
        start_provenance_proxy(spawn_truncated_cleanup_mock().await, None).await;

    assert_eq!(
        client
            .request(
                hyper::Method::POST,
                "/api/v1/namespaces/dev/pods",
                Some("live-session"),
                Some(r#"{"metadata":{"name":"check-pod"}}"#),
            )
            .await,
        201
    );

    assert_eq!(
        client
            .request(
                hyper::Method::DELETE,
                "/api/v1/namespaces/dev/pods/check-pod",
                Some("live-session"),
                None,
            )
            .await,
        502
    );
    assert!(
        sink.resolved.lock().unwrap().is_empty(),
        "a truncated 2xx cleanup response must retain its revert"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn contained_delete_body_stall_is_bounded_and_retains_revert() {
    let (mut client, sink) = start_provenance_proxy_with_body_timeout(
        spawn_stalled_cleanup_body_mock().await,
        None,
        Duration::from_millis(150),
    )
    .await;

    assert_eq!(
        client
            .request(
                hyper::Method::POST,
                "/api/v1/namespaces/dev/pods",
                Some("live-session"),
                Some(r#"{"metadata":{"name":"check-pod"}}"#),
            )
            .await,
        201
    );

    let status = tokio::time::timeout(
        Duration::from_secs(2),
        client.request(
            hyper::Method::DELETE,
            "/api/v1/namespaces/dev/pods/check-pod",
            Some("live-session"),
            None,
        ),
    )
    .await
    .expect("contained cleanup body has a finite timeout");
    assert_eq!(status, 504);
    assert!(sink.resolved.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn created_provenance_never_overrides_an_explicit_policy_deny() {
    let mock_base = spawn_create_delete_mock().await;
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(&mock_base), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(
        "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: allow\n  - verbs: [delete]\n    resources: [pods]\n    namespaces: [dev]\n    action: deny\n",
    )
    .unwrap();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, None)
            .with_listener_mode(ApiListenerMode::Policy),
    );
    let sink = RecordingSink::default();
    proxy.attach_gate(Arc::new(sink.clone()));
    proxy.attach_session_sink(Arc::new(LiveSessionSink));
    tokio::spawn(proxy.clone().serve_on(listener));

    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let base = format!("https://{listen}");
    let created = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .bearer_auth("live-session")
        .body(r#"{"metadata":{"name":"check-pod"}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    created.bytes().await.unwrap();
    let denied = client
        .delete(format!("{base}/api/v1/namespaces/dev/pods/check-pod"))
        .bearer_auth("live-session")
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    assert!(sink.resolved.lock().unwrap().is_empty());
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
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(ApiProxy::new(listen, tls, upstream, policy, None));

    tokio::spawn(proxy.clone().serve_on(listener));

    let base = format!("https://{listen}");
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
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, None)
            .with_listener_mode(ApiListenerMode::Policy),
    );

    let sink = RecordingSink::default();
    proxy.attach_gate(Arc::new(sink.clone()));
    proxy.attach_session_sink(Arc::new(LiveSessionSink));

    tokio::spawn(proxy.clone().serve_on(listener));

    let base = format!("https://{listen}");
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();

    // Eviction cannot carry Guard's object preconditions, so the concurrency
    // floor rejects it even though policy would otherwise allow it.
    let resp = client
        .post(format!(
            "{base}/api/v1/namespaces/dev/pods/critical-0/eviction"
        ))
        .bearer_auth("live-session")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        409,
        "an eviction that cannot carry object preconditions fails closed"
    );
    // No auto-revert was armed for the rejected subresource write, so no
    // provenance exists.
    assert_eq!(
        sink.calls.lock().unwrap().len(),
        0,
        "a subresource write arms no auto-revert and seeds no provenance"
    );

    // Deleting the evicted pod must stay held: the eviction did not launder it.
    let resp = client
        .delete(format!("{base}/api/v1/namespaces/dev/pods/critical-0"))
        .bearer_auth("live-session")
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

/// Regression test: a filtered Helm release-storage Secret must fail explicitly.
/// Helm skips release records whose `data.release` payload cannot be decoded,
/// so a successful response with that field removed can look like an
/// authoritative empty release inventory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_rejects_helm_release_secret_instead_of_returning_false_empty_state() {
    let mock_base = spawn_helm_release_mock().await;
    let kubeconfig = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n  - name: c\n    cluster: {{server: \"{mock_base}\"}}\ncontexts:\n  - name: ctx\n    context: {{cluster: c, user: u}}\nusers:\n  - name: u\n    user: {{}}\n"
    );
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(include_str!("../examples/api-policy.yaml")).expect("policy");
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(ApiProxy::new(listen, tls, upstream, policy, None));

    tokio::spawn(proxy.clone().serve_on(listener));

    let base = format!("https://{listen}");
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
    assert_eq!(resp.status(), 403);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["status"], "Failure");
    assert_eq!(v["reason"], "Forbidden");
    assert!(v["message"].as_str().unwrap().contains("typed Helm verb"));
    assert!(!v.to_string().contains("SDRzSUFB"));
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

    async fn mark_revert_dispatching(&self, _handle: &str) -> bool {
        false
    }

    async fn resolve(&self, _handle: &str) -> bool {
        false
    }

    async fn authorize_cleanup(
        &self,
        _handle: &str,
        _resource_uid: &str,
        _create_provenance: &str,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        reject_test_cleanup(handoff).await
    }

    async fn mark_revert_forwarded(&self, _handle: &str, _resource_uid: Option<&str>) -> bool {
        false
    }

    async fn mark_revert_indeterminate(
        &self,
        _handle: &str,
        _reason: &str,
        _resource_uid: Option<&str>,
    ) -> bool {
        false
    }

    async fn cancel_staged_revert(&self, _handle: &str) -> bool {
        false
    }

    async fn mark_revert_rejected(&self, _handle: &str, _reason: &str) -> bool {
        false
    }

    async fn hold_request(
        &self,
        _snapshot: &ApiHoldSnapshot,
        _reason: &str,
        _session_context: Option<&ApiSessionContext>,
    ) -> guard::proxy::HoldDecision {
        guard::proxy::HoldDecision::Approved {
            handle: "test-approved".to_string(),
        }
    }
}

#[derive(Clone)]
struct DenyingSink {
    reason: &'static str,
}

#[async_trait::async_trait]
impl guard::proxy::GateSink for DenyingSink {
    async fn arm_revert(&self, _mutation: guard::proxy::ApiMutation) -> Option<String> {
        None
    }

    async fn mark_revert_dispatching(&self, _handle: &str) -> bool {
        false
    }

    async fn resolve(&self, _handle: &str) -> bool {
        false
    }

    async fn authorize_cleanup(
        &self,
        _handle: &str,
        _resource_uid: &str,
        _create_provenance: &str,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        reject_test_cleanup(handoff).await
    }

    async fn mark_revert_forwarded(&self, _handle: &str, _resource_uid: Option<&str>) -> bool {
        false
    }

    async fn mark_revert_indeterminate(
        &self,
        _handle: &str,
        _reason: &str,
        _resource_uid: Option<&str>,
    ) -> bool {
        false
    }

    async fn cancel_staged_revert(&self, _handle: &str) -> bool {
        false
    }

    async fn mark_revert_rejected(&self, _handle: &str, _reason: &str) -> bool {
        false
    }

    async fn hold_request(
        &self,
        _snapshot: &ApiHoldSnapshot,
        _reason: &str,
        _session_context: Option<&ApiSessionContext>,
    ) -> guard::proxy::HoldDecision {
        guard::proxy::HoldDecision::Denied {
            reason: self.reason.to_string(),
            handle: Some("approval-test-ref".to_string()),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_matches_create_body_metadata_predicates() {
    let mock_base = spawn_mock_upstream().await;
    let kubeconfig = kubeconfig_for(&mock_base);
    let policy = ApiPolicy::from_yaml(
        r#"
default: deny
rules:
  - verbs: [create]
    resources: [jobs]
    namespaces: [dev]
    names: ["*-admission*"]
    annotations:
      "helm.sh/hook": "pre-*"
    action: allow
  - verbs: [create]
    resources: [jobs]
    namespaces: [dev]
    action: hold
"#,
    )
    .expect("policy");
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, None)
            .with_listener_mode(ApiListenerMode::Policy),
    );
    proxy.attach_session_sink(Arc::new(LiveSessionSink));
    tokio::spawn(proxy.clone().serve_on(listener));

    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let endpoint = format!("https://{listen}/apis/batch/v1/namespaces/dev/jobs");
    let response = client
        .post(&endpoint)
        .bearer_auth("live-session")
        .json(&json!({
            "metadata": {
                "name": "chart-admission-create",
                "annotations": {"helm.sh/hook": "pre-install,pre-upgrade"}
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "matching hook create is forwarded");

    let response = client
        .post(endpoint)
        .bearer_auth("live-session")
        .json(&json!({"metadata": {"name": "chart-admission-create"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        403,
        "missing annotation falls through to the hold rule"
    );
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
  - verbs: [get]
    resources: [pods]
    namespaces: [dev]
    action: allow
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
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(ApiProxy::new(listen, tls, upstream, policy, None));
    proxy.attach_session_sink(Arc::new(LiveSessionSink));
    tokio::spawn(proxy.clone().serve_on(listener));

    let base = format!("https://{listen}");
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    assert_eq!(
        client
            .get(format!("{base}/api/v1/namespaces/dev/pods/web-0"))
            .bearer_auth("live-session")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let resp = client
        .delete(format!("{base}/api/v1/namespaces/dev/pods/web-0"))
        .bearer_auth("live-session")
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
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(ApiProxy::new(listen, tls, upstream, policy, None));
    proxy.attach_gate(Arc::new(ApprovingSink));
    let session_sink = RecordingSessionSink::default();
    proxy.attach_session_sink(Arc::new(session_sink.clone()));
    tokio::spawn(proxy.clone().serve_on(listener));

    let base = format!("https://{listen}");
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    assert_eq!(
        client
            .get(format!("{base}/api/v1/namespaces/dev/pods/web-0"))
            .bearer_auth("live-session")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let resp = client
        .delete(format!("{base}/api/v1/namespaces/dev/pods/web-0"))
        .bearer_auth("live-session")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "an approved hold is forwarded upstream");
    {
        let events = session_sink.events.lock().unwrap();
        let held = events.iter().filter(|event| event.held).collect::<Vec<_>>();
        assert_eq!(held.len(), 1, "the held request is recorded once");
        assert!(held[0].allowed, "the operator-approved hold was allowed");
    }

    for reason in ["operator denied", "approval expired"] {
        let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");
        let tls = ProxyTls::generate().expect("tls");
        let ca_pem = tls.ca_pem().to_string();
        let policy = ApiPolicy::from_yaml(policy_yaml).expect("policy");
        let (listener, listen) = reserve_listener().await;
        let proxy = Arc::new(ApiProxy::new(listen, tls, upstream, policy, None));
        proxy.attach_gate(Arc::new(DenyingSink { reason }));
        let denied_session = RecordingSessionSink::default();
        proxy.attach_session_sink(Arc::new(denied_session.clone()));
        tokio::spawn(proxy.clone().serve_on(listener));

        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
            .build()
            .unwrap();
        let response = client
            .delete(format!("https://{listen}/api/v1/namespaces/dev/pods/web-0"))
            .bearer_auth("live-session")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403, "{reason} must fail closed");
        assert_eq!(
            response
                .headers()
                .get("x-guard-approval")
                .and_then(|value| value.to_str().ok()),
            Some("approval-test-ref"),
        );
        let body = response.text().await.unwrap();
        assert!(body.contains("approval-test-ref"), "body: {body}");
        assert!(
            body.contains("guard approval show approval-test-ref"),
            "body: {body}"
        );
        let events = denied_session.events.lock().unwrap();
        assert_eq!(events.len(), 1, "{reason} is recorded once");
        assert!(events[0].held, "{reason} remains a hold in history");
        assert!(
            !events[0].allowed,
            "{reason} must not be recorded as allowed"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_request_captures_complete_body_before_approval_and_stalls_fail_closed() {
    use sha2::{Digest, Sha256};

    let (mock_base, observed_create) = spawn_write_mock_with_observation().await;
    let upstream =
        Upstream::from_kubeconfig_str(&kubeconfig_for(&mock_base), None).expect("upstream");
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(
        "default: deny\nrules:\n  - verbs: [create]\n    resources: [pods]\n    namespaces: [dev]\n    action: hold\n",
    )
    .unwrap();
    let (listener, listen) = reserve_listener().await;
    let proxy = Arc::new(
        ApiProxy::new(listen, tls, upstream, policy, None)
            .with_request_body_timeout(Duration::from_millis(250)),
    );
    let sink = SnapshotSink::default();
    proxy.attach_gate(Arc::new(sink.clone()));
    proxy.attach_session_sink(Arc::new(LiveSessionSink));
    tokio::spawn(proxy.serve_on(listener));
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let base = format!("https://{listen}");

    let waiting_for_tail = Arc::new(tokio::sync::Semaphore::new(0));
    let release_tail = Arc::new(tokio::sync::Semaphore::new(0));
    let stream = futures::stream::unfold(
        (0_u8, waiting_for_tail.clone(), release_tail.clone()),
        |(step, waiting, release)| async move {
            match step {
                0 => Some((
                    Ok::<_, std::io::Error>(Bytes::from_static(
                        br#"{"metadata":{"name":"held-pod"},"spec":"#,
                    )),
                    (1, waiting, release),
                )),
                1 => {
                    waiting.add_permits(1);
                    release.acquire().await.ok()?.forget();
                    Some((
                        Ok(Bytes::from_static(br#"{"replicas":2}}"#)),
                        (2, waiting, release),
                    ))
                }
                _ => None,
            }
        },
    );
    let request = tokio::spawn({
        let client = client.clone();
        let base = base.clone();
        async move {
            client
                .post(format!("{base}/api/v1/namespaces/dev/pods"))
                .bearer_auth("live-session")
                .body(reqwest::Body::wrap_stream(stream))
                .send()
                .await
                .unwrap()
        }
    });
    waiting_for_tail.acquire().await.unwrap().forget();
    assert!(
        sink.snapshots.lock().unwrap().is_empty(),
        "approval must not be requested while request bytes remain unread"
    );
    release_tail.add_permits(1);
    assert_eq!(request.await.unwrap().status(), 201);
    let marker = observed_create
        .lock()
        .unwrap()
        .provenance
        .clone()
        .expect("forwarded create carries canonical provenance");
    let mut approved_body = json!({
        "metadata": {
            "name": "held-pod",
            "annotations": {}
        },
        "spec": {"replicas": 2}
    });
    approved_body["metadata"]["annotations"][CREATE_PROVENANCE_ANNOTATION] = Value::String(marker);
    let body = serde_json::to_vec(&approved_body).unwrap();
    let expected_digest = Sha256::digest(&body)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    {
        let snapshots = sink.snapshots.lock().unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].body_sha256, expected_digest);
        assert_eq!(
            snapshots[0].body_sha256,
            observed_create
                .lock()
                .unwrap()
                .body_sha256
                .clone()
                .expect("upstream observed the approved body")
        );
        assert!(snapshots[0]
            .redacted_body_shape
            .contains(CREATE_PROVENANCE_ANNOTATION));
    }

    let before = sink.snapshots.lock().unwrap().len();
    let (stalled_tx, stalled_rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1);
    let stalled_stream = futures::stream::unfold(stalled_rx, |mut receiver| async move {
        receiver.recv().await.map(|item| (item, receiver))
    });
    let stalled_request = tokio::spawn(async move {
        client
            .post(format!("{base}/api/v1/namespaces/dev/pods"))
            .bearer_auth("live-session")
            .body(reqwest::Body::wrap_stream(stalled_stream))
            .send()
            .await
            .unwrap()
    });
    stalled_tx
        .send(Ok(Bytes::from_static(br#"{"spec":"#)))
        .await
        .unwrap();
    let stalled_response = stalled_request.await.unwrap();
    assert_eq!(stalled_response.status(), 408);
    assert_eq!(sink.snapshots.lock().unwrap().len(), before);
    drop(stalled_tx);
}

/// Gate sink that counts hold requests and approves each, so a test can assert
/// how many requests were escalated to the queue.
#[derive(Clone, Default)]
struct CountingSink {
    holds: Arc<std::sync::Mutex<u32>>,
}

#[derive(Clone, Default)]
struct SnapshotSink {
    snapshots: Arc<std::sync::Mutex<Vec<ApiHoldSnapshot>>>,
}

#[derive(Clone)]
struct BlockingSnapshotSink {
    state: SnapshotSink,
    reached: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}

impl Default for BlockingSnapshotSink {
    fn default() -> Self {
        Self {
            state: SnapshotSink::default(),
            reached: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        }
    }
}

#[async_trait::async_trait]
impl GateSink for BlockingSnapshotSink {
    async fn arm_revert(&self, mutation: guard::proxy::ApiMutation) -> Option<String> {
        self.state.arm_revert(mutation).await
    }

    async fn mark_revert_dispatching(&self, handle: &str) -> bool {
        self.state.mark_revert_dispatching(handle).await
    }

    async fn resolve(&self, handle: &str) -> bool {
        self.state.resolve(handle).await
    }

    async fn authorize_cleanup(
        &self,
        handle: &str,
        resource_uid: &str,
        create_provenance: &str,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        self.state
            .authorize_cleanup(handle, resource_uid, create_provenance, handoff)
            .await
    }

    async fn mark_revert_forwarded(&self, handle: &str, resource_uid: Option<&str>) -> bool {
        self.state.mark_revert_forwarded(handle, resource_uid).await
    }

    async fn mark_revert_indeterminate(
        &self,
        handle: &str,
        reason: &str,
        resource_uid: Option<&str>,
    ) -> bool {
        self.state
            .mark_revert_indeterminate(handle, reason, resource_uid)
            .await
    }

    async fn cancel_staged_revert(&self, handle: &str) -> bool {
        self.state.cancel_staged_revert(handle).await
    }

    async fn mark_revert_rejected(&self, handle: &str, reason: &str) -> bool {
        self.state.mark_revert_rejected(handle, reason).await
    }

    async fn hold_request(
        &self,
        snapshot: &ApiHoldSnapshot,
        _reason: &str,
        _session_context: Option<&ApiSessionContext>,
    ) -> guard::proxy::HoldDecision {
        self.state.snapshots.lock().unwrap().push(snapshot.clone());
        self.reached.add_permits(1);
        self.release.acquire().await.unwrap().forget();
        guard::proxy::HoldDecision::Approved {
            handle: "snapshot-approved".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl GateSink for SnapshotSink {
    async fn arm_revert(&self, _mutation: guard::proxy::ApiMutation) -> Option<String> {
        None
    }

    async fn mark_revert_dispatching(&self, _handle: &str) -> bool {
        false
    }

    async fn resolve(&self, _handle: &str) -> bool {
        false
    }

    async fn authorize_cleanup(
        &self,
        _handle: &str,
        _resource_uid: &str,
        _create_provenance: &str,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        reject_test_cleanup(handoff).await
    }

    async fn mark_revert_forwarded(&self, _handle: &str, _resource_uid: Option<&str>) -> bool {
        false
    }

    async fn mark_revert_indeterminate(
        &self,
        _handle: &str,
        _reason: &str,
        _resource_uid: Option<&str>,
    ) -> bool {
        false
    }

    async fn cancel_staged_revert(&self, _handle: &str) -> bool {
        false
    }

    async fn mark_revert_rejected(&self, _handle: &str, _reason: &str) -> bool {
        false
    }

    async fn hold_request(
        &self,
        snapshot: &ApiHoldSnapshot,
        _reason: &str,
        _session_context: Option<&ApiSessionContext>,
    ) -> guard::proxy::HoldDecision {
        self.snapshots.lock().unwrap().push(snapshot.clone());
        guard::proxy::HoldDecision::Approved {
            handle: "snapshot-approved".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl guard::proxy::GateSink for CountingSink {
    async fn arm_revert(&self, _mutation: guard::proxy::ApiMutation) -> Option<String> {
        None
    }

    async fn mark_revert_dispatching(&self, _handle: &str) -> bool {
        false
    }

    async fn resolve(&self, _handle: &str) -> bool {
        false
    }

    async fn authorize_cleanup(
        &self,
        _handle: &str,
        _resource_uid: &str,
        _create_provenance: &str,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        reject_test_cleanup(handoff).await
    }

    async fn mark_revert_forwarded(&self, _handle: &str, _resource_uid: Option<&str>) -> bool {
        false
    }

    async fn mark_revert_indeterminate(
        &self,
        _handle: &str,
        _reason: &str,
        _resource_uid: Option<&str>,
    ) -> bool {
        false
    }

    async fn cancel_staged_revert(&self, _handle: &str) -> bool {
        false
    }

    async fn mark_revert_rejected(&self, _handle: &str, _reason: &str) -> bool {
        false
    }

    async fn hold_request(
        &self,
        _snapshot: &ApiHoldSnapshot,
        _reason: &str,
        _session_context: Option<&ApiSessionContext>,
    ) -> guard::proxy::HoldDecision {
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
    let (listener, listen) = reserve_listener().await;
    // Threshold 2: the first two occurrences of a shape are escalated.
    let proxy =
        Arc::new(ApiProxy::new(listen, tls, upstream, policy, None).with_rarity_escalation(2));
    let sink = CountingSink::default();
    proxy.attach_gate(Arc::new(sink.clone()));
    tokio::spawn(proxy.clone().serve_on(listener));

    let base = format!("https://{listen}");
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

    assert_eq!(*sink.holds.lock().unwrap(), 3);
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
  - verbs: [get]
    resources: [deployments]
    namespaces: [dev]
    action: allow
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
    assert_eq!(
        client
            .get(format!(
                "{base}/apis/apps/v1/namespaces/dev/deployments/api"
            ))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
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
    assert_eq!(sink.calls.lock().unwrap().len(), 1);

    let judge = RecordingJudge::new(vec![judge_allow(Some(4), Some(Reversibility::Recoverable))]);
    let (base, client) = start_proxy_with(
        spawn_write_mock().await,
        policy,
        Some(Arc::new(judge)),
        None,
        0,
    )
    .await;
    assert_eq!(
        client
            .get(format!(
                "{base}/apis/apps/v1/namespaces/dev/deployments/api"
            ))
            .bearer_auth("live-session")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let resp = client
        .patch(format!(
            "{base}/apis/apps/v1/namespaces/dev/deployments/api"
        ))
        .header("content-type", "application/merge-patch+json")
        .bearer_auth("live-session")
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
        .bearer_auth("live-session")
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
async fn evaluator_is_not_called_when_final_guard_cannot_be_materialized() {
    let policy = r#"
default: deny
rules:
  - verbs: [get]
    resources: [deployments]
    namespaces: [dev]
    action: allow
  - verbs: [patch]
    resources: [deployments]
    namespaces: [dev]
    action: evaluate
"#;
    let gets = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let writes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (mock_base, _) = spawn_flaky_snapshot_mock(gets.clone(), writes.clone()).await;
    let judge = RecordingJudge::new(vec![judge_allow(Some(5), Some(Reversibility::Recoverable))]);
    let observed_judge = judge.clone();
    let sink = RecordingSink::default();
    let (base, client) = start_proxy_with(
        mock_base,
        policy,
        Some(Arc::new(judge)),
        Some(Arc::new(sink)),
        0,
    )
    .await;
    assert_eq!(
        client
            .get(format!(
                "{base}/apis/apps/v1/namespaces/dev/deployments/api"
            ))
            .bearer_auth("live-session")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let resp = client
        .patch(format!(
            "{base}/apis/apps/v1/namespaces/dev/deployments/api"
        ))
        .header("content-type", "application/merge-patch+json")
        .bearer_auth("live-session")
        .body(r#"{"spec":{"replicas":9}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        409,
        "a final guard that cannot be materialized must fail before evaluation"
    );
    assert!(observed_judge.summaries.lock().unwrap().is_empty());
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

    async fn mark_revert_dispatching(&self, _handle: &str) -> bool {
        false
    }

    async fn resolve(&self, _handle: &str) -> bool {
        false
    }

    async fn authorize_cleanup(
        &self,
        _handle: &str,
        _resource_uid: &str,
        _create_provenance: &str,
        handoff: &mut dyn ApiForwardHandoff,
    ) -> Result<(), String> {
        reject_test_cleanup(handoff).await
    }

    async fn mark_revert_forwarded(&self, _handle: &str, _resource_uid: Option<&str>) -> bool {
        false
    }

    async fn mark_revert_indeterminate(
        &self,
        _handle: &str,
        _reason: &str,
        _resource_uid: Option<&str>,
    ) -> bool {
        false
    }

    async fn mark_revert_rejected(&self, _handle: &str, _reason: &str) -> bool {
        false
    }

    async fn cancel_staged_revert(&self, _handle: &str) -> bool {
        false
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_evaluate_holds_when_sink_cannot_arm() {
    let policy = r#"
default: deny
rules:
  - verbs: [get]
    resources: [deployments]
    namespaces: [dev]
    action: allow
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
    assert_eq!(
        client
            .get(format!(
                "{base}/apis/apps/v1/namespaces/dev/deployments/api"
            ))
            .bearer_auth("live-session")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let resp = client
        .patch(format!(
            "{base}/apis/apps/v1/namespaces/dev/deployments/api"
        ))
        .header("content-type", "application/merge-patch+json")
        .bearer_auth("live-session")
        .body(r#"{"spec":{"replicas":9}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "a contained write must be held when the sink cannot arm a revert"
    );
    assert_eq!(
        armed.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no revert arming should be attempted for a held write"
    );
    // The pre-judge constructibility GET and the pre-approval guard
    // materialization GET ran. No post-approval fetch or write occurs.
    assert_eq!(gets.load(std::sync::atomic::Ordering::SeqCst), 2);
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
  - verbs: [get]
    resources: [deployments]
    namespaces: [dev]
    action: allow
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
    assert_eq!(
        client
            .get(format!(
                "{base}/apis/apps/v1/namespaces/dev/deployments/api"
            ))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
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
    // The caller's observation and one pre-evaluator arbitration fetch are the
    // only reads. The prepared snapshot and final bytes are reused at handoff.
    assert_eq!(gets.load(std::sync::atomic::Ordering::SeqCst), 2);
}
