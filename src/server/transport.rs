use super::*;

#[derive(Clone)]
pub struct Server {
    config: ServerConfig,
}

impl Server {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        socket_path: Option<PathBuf>,
        tcp_port: Option<u16>,
        evaluator: Evaluator,
        secrets: SecretManager,
        redact: bool,
        auth_token: Option<String>,
        admin_token: Option<String>,
        socket_group: Option<String>,
        allowed_uids: Option<Vec<u32>>,
        shim_dir: Option<PathBuf>,
        dry_run: bool,
        tool_registry: ToolRegistry,
        redact_secrets: Vec<String>,
        preflight: bool,
        sessions: SessionRegistry,
        session_store: Option<SessionStore>,
        exec_as_caller: bool,
        state_db_path: Option<PathBuf>,
    ) -> Self {
        let config = ServerConfig::new(
            socket_path,
            tcp_port,
            evaluator,
            secrets,
            redact,
            auth_token,
            admin_token,
            socket_group,
            allowed_uids,
            shim_dir,
            dry_run,
            tool_registry,
            redact_secrets,
            preflight,
            sessions,
            session_store,
            exec_as_caller,
            state_db_path,
        );
        Self { config }
    }

    /// Enable consequence gating. Must be called before `run`.
    pub fn set_gate(&mut self, gate: GateMode) {
        self.config.gate = gate;
    }

    /// Install the operator-defined verb catalog. Must be called before `run`.
    pub fn set_verbs(&mut self, catalog: VerbCatalog) {
        self.config.verbs = Arc::new(RwLock::new(catalog));
    }

    /// Install the operator-defined session-grant profiles. Must be called
    /// before `run`.
    pub fn set_profiles(&mut self, catalog: ProfileCatalog) {
        self.config.profiles = catalog;
    }

    /// Restrict which binaries may execute. `None` imposes no restriction (the
    /// default); an empty list denies everything. Must be called before `run`.
    pub fn set_allowed_binaries(&mut self, allowed: Option<Vec<String>>) {
        self.config.allowed_binaries = allowed;
    }

    /// Set the operator-declared extra child-env passthrough list (see
    /// [`ServerConfig::extra_child_env`]). Must be called before `run`.
    pub fn set_extra_child_env(&mut self, vars: Vec<String>) {
        self.config.extra_child_env = vars;
    }

    /// Attach a Kubernetes API proxy to run alongside the gate socket. Must be
    /// called before `run`.
    pub fn set_kube_proxy(&mut self, proxy: Arc<guard::proxy::ApiProxy>) {
        self.config.kube_proxy = Some(proxy);
    }

    /// Load persisted provisional/approval state and apply startup recovery:
    /// no revert ever runs unattended at boot. Past-deadline or interrupted
    /// provisionals become `needs_operator_decision`; interrupted approvals
    /// become `exec_failed`. Both are surfaced via a high-severity audit line.
    async fn startup_gating(&self) {
        let Some(store) = &self.config.session_store else {
            tracing::info!(
                "Consequence gating enabled (no state-db: provisional/approval state is process-local and not recovered across restart)"
            );
            return;
        };

        match store.load_provisionals().await {
            Ok(rows) => {
                let (reg, moved) = ProvisionalRegistry::from_rows(rows);
                if !moved.is_empty() {
                    tracing::warn!(
                        "[AUDIT] STARTUP_RECOVERY provisionals_needing_decision={} handles={:?} (no revert runs unattended at boot)",
                        moved.len(),
                        moved
                    );
                    for h in &moved {
                        if let Some(p) = reg.get(h) {
                            if let Err(e) = store.save_provisional(p.clone()).await {
                                tracing::warn!(
                                    "failed to persist recovered provisional {}: {}",
                                    h,
                                    e
                                );
                            }
                        }
                    }
                }
                *self.config.provisional.write().await = reg;
            }
            Err(e) => tracing::error!("failed to load provisional state: {}", e),
        }

        match store.load_approvals().await {
            Ok(rows) => {
                let now = now_unix();
                let (mut reg, recovered) = ApprovalRegistry::from_rows(rows, now);
                if !recovered.is_empty() {
                    tracing::warn!(
                        "[AUDIT] STARTUP_RECOVERY approvals_exec_failed={} handles={:?} (exec interrupted by restart)",
                        recovered.len(),
                        recovered
                    );
                    for h in &recovered {
                        if let Some(a) = reg.get(h) {
                            if let Err(e) = store.save_approval(a.clone()).await {
                                tracing::warn!("failed to persist recovered approval {}: {}", h, e);
                            }
                        }
                    }
                }
                // A kube-proxy hold cannot survive a restart: the parked HTTP
                // request died with the old process, so a still-pending row
                // would offer the operator an approval that releases nothing.
                let orphaned: Vec<String> = reg
                    .list()
                    .into_iter()
                    .filter(|a| {
                        a.status == ApprovalStatus::Pending
                            && a.snapshot.binary == KUBE_PROXY_SENTINEL_BINARY
                    })
                    .map(|a| a.handle)
                    .collect();
                for h in &orphaned {
                    reg.set_exec_failed(
                        h,
                        now,
                        "daemon restarted; the held API request is gone".to_string(),
                    );
                    if let Some(a) = reg.get(h) {
                        if let Err(e) = store.save_approval(a.clone()).await {
                            tracing::warn!("failed to persist retired proxy hold {}: {}", h, e);
                        }
                    }
                }
                if !orphaned.is_empty() {
                    tracing::warn!(
                        "[AUDIT] STARTUP_RECOVERY kube_proxy_holds_retired={} handles={:?}",
                        orphaned.len(),
                        orphaned
                    );
                }
                *self.config.approvals.write().await = reg;
            }
            Err(e) => tracing::error!("failed to load approval state: {}", e),
        }
    }

    /// Load persisted read grants at startup. Any grant already past its TTL is
    /// revoked immediately (a read grant only removes access, so this is always
    /// safe to do unattended, unlike a provisional revert); a grant still within
    /// its TTL is re-armed by loading it Active so the sweeper fires at its
    /// deadline.
    #[cfg(unix)]
    async fn startup_read_grants(&self) {
        let Some(store) = &self.config.session_store else {
            return;
        };
        let rows = match store.load_read_grants().await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!("failed to load read-grant state: {}", e);
                return;
            }
        };
        let reg = GrantReadRegistry::from_rows(rows);
        let now = now_unix();
        let mut surviving = GrantReadRegistry::new();
        for grant in reg.list() {
            if grant.status == ReadGrantStatus::Active && now >= grant.expires_unix {
                match revoke_read_grant_acls(&grant).await {
                    Ok(()) => {
                        tracing::warn!(
                            "[AUDIT] READ_GRANT_REVOKED handle={} path=\"{}\" source=startup-expired",
                            grant.handle,
                            grant.target_path
                        );
                        delete_read_grant_row(&self.config, &grant.target_path).await;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "[AUDIT] READ_GRANT_REVOKE_FAILED handle={} path=\"{}\" source=startup-expired detail=\"{}\"",
                            grant.handle,
                            grant.target_path,
                            e
                        );
                        surviving.insert(grant);
                    }
                }
            } else {
                surviving.insert(grant);
            }
        }
        *self.config.read_grants.write().await = surviving;
    }

    pub async fn run(&self) -> Result<()> {
        tracing::info!("Server::run() called");

        // Consequence gating: load persisted state (with boot-safe recovery).
        if self.config.gate.is_on() {
            tracing::info!("Consequence gating: {}", self.config.gate);
            self.startup_gating().await;
        }
        // Reconcile persisted read grants (revoke expired, re-arm live).
        #[cfg(unix)]
        self.startup_read_grants().await;

        // The single sweeper drives both consequence-gate reverts (gate-on only)
        // and read-grant expiries (Unix, gate-independent), so it runs whenever
        // either is live. Without this a read grant could outlive its TTL simply
        // because the daemon runs without consequence gating.
        if self.config.gate.is_on() || cfg!(unix) {
            let config = self.config.clone();
            tokio::spawn(async move { gating_sweeper(config).await });
        }

        let mut futures = Vec::new();

        if let Some(ref socket_path) = self.config.socket_path {
            tracing::info!("Starting local listener on {}", socket_path.display());
            let path = socket_path.clone();
            let config = self.config.clone();
            futures.push(tokio::spawn(async move {
                Self::run_local_static(&path, &config).await
            }));
        }

        if let Some(port) = self.config.tcp_port {
            tracing::info!("Starting TCP listener on port {}", port);
            let config = self.config.clone();
            futures.push(tokio::spawn(async move {
                Self::run_tcp_static(port, &config).await
            }));
        }

        if let Some(ref proxy) = self.config.kube_proxy {
            // The auto-revert envelope needs the consequence sweeper, which only
            // runs under `--gate consequence`. Without it the proxy still gates
            // (allow/deny/hold/redact) but forwards recoverable writes unwrapped.
            if self.config.gate.is_on() {
                let snapshot_dir = self
                    .config
                    .state_db_path
                    .as_ref()
                    .and_then(|p| p.parent())
                    .map(|d| d.join("kube-proxy-reverts"))
                    .unwrap_or_else(|| std::env::temp_dir().join("guard-kube-proxy-reverts"));
                if let Err(e) = std::fs::create_dir_all(&snapshot_dir) {
                    tracing::warn!(
                        "could not create kube-proxy revert dir {}: {}",
                        snapshot_dir.display(),
                        e
                    );
                }
                proxy.attach_gate(Arc::new(DaemonGateSink {
                    config: self.config.clone(),
                    kubeconfig: proxy.real_kubeconfig().to_path_buf(),
                    snapshot_dir,
                    window_secs: DEFAULT_CONFIRM_WITHIN_SECS,
                }));
            } else {
                tracing::info!(
                    "kube-proxy: --gate consequence not set; recoverable writes forwarded without auto-revert and policy 'hold' rules deny fail-closed (no approval queue)"
                );
            }
            tracing::info!("Starting kube-proxy listener on {}", proxy.listen());
            let proxy = proxy.clone();
            futures.push(tokio::spawn(async move { proxy.serve().await }));
        }

        if futures.is_empty() {
            anyhow::bail!("no socket path or TCP port specified");
        }

        // A listener loop only returns on a fatal error (e.g. it could not bind);
        // surface it as an error return rather than exiting silently. This makes
        // the process exit non-zero, so the Windows service reports a failure and
        // the SCM restart action engages instead of the daemon sitting STOPPED
        // after a bind failure while having briefly reported RUNNING.
        let mut listener_error: Option<anyhow::Error> = None;
        for result in futures::future::join_all(futures).await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::error!("listener exited with error: {:#}", e);
                    listener_error.get_or_insert(e);
                }
                Err(e) => {
                    tracing::error!("listener task panicked: {}", e);
                    listener_error
                        .get_or_insert_with(|| anyhow::anyhow!("listener task panicked: {}", e));
                }
            }
        }

        match listener_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Platform dispatch for the local listener: UNIX domain socket on Unix,
    /// named pipe on Windows.
    async fn run_local_static(socket_path: &Path, config: &ServerConfig) -> Result<()> {
        #[cfg(unix)]
        {
            Self::run_unix_static(socket_path, config).await
        }
        #[cfg(windows)]
        {
            Self::run_pipe_static(socket_path, config).await
        }
    }

    #[cfg(windows)]
    async fn run_pipe_static(socket_path: &Path, config: &ServerConfig) -> Result<()> {
        let pipe_name = winplat::pipe_name(socket_path);
        tracing::info!("guard server listening on named pipe {}", pipe_name);

        let mut server = winplat::create_pipe_server(&pipe_name, true)?;

        loop {
            // Wait for a client to connect to the current instance, then hand it
            // off and immediately stand up the next instance for the next client.
            server
                .connect()
                .await
                .context("named pipe connect failed")?;
            let connected = server;
            server = winplat::create_pipe_server(&pipe_name, false)?;

            let config = config.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_client_pipe(connected, &config).await {
                    tracing::error!("client handler error: {}", e);
                }
            });
        }
    }

    #[cfg(unix)]
    async fn run_unix_static(socket_path: &Path, config: &ServerConfig) -> Result<()> {
        if let Some(parent) = socket_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .context("failed to create socket directory")?;
        }

        if socket_path.exists() {
            tokio::fs::remove_file(socket_path).await?;
        }

        let listener = UnixListener::bind(socket_path).context("failed to bind UNIX socket")?;
        Self::chmod_path(socket_path, 0o666).await?;

        tracing::info!("guard server listening on {}", socket_path.display());

        if let Some(ref group) = config.socket_group {
            Self::chown_to_group(socket_path, group).await?;
            if let Some(parent) = socket_path.parent() {
                Self::chmod_path(parent, 0o755).await?;
            }
        }

        loop {
            match listener.accept().await {
                Ok((stream, _peer_addr)) => {
                    let config = config.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_client_unix(stream, &config).await {
                            tracing::error!("client handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("accept error: {}", e);
                }
            }
        }
    }

    async fn run_tcp_static(port: u16, config: &ServerConfig) -> Result<()> {
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr)
            .await
            .context("failed to bind TCP socket")?;

        tracing::info!("guard server listening on tcp://{}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let config = config.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_client_tcp(stream, &config).await {
                            tracing::error!("client handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("accept error: {}", e);
                }
            }
        }
    }

    #[cfg(unix)]
    async fn chown_to_group(path: &Path, group: &str) -> Result<()> {
        let output = Command::new("chgrp").arg(group).arg(path).output().await?;

        if !output.status.success() {
            bail!(
                "failed to change group of {} to {}: {}",
                path.display(),
                group,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    #[cfg(unix)]
    async fn chmod_path(path: &std::path::Path, mode: u32) -> Result<()> {
        let permissions = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, permissions)
            .with_context(|| format!("failed to chmod {} to {:o}", path.display(), mode))?;
        Ok(())
    }
}

/// Windows-only helpers: named-pipe name normalization and peer-SID resolution.
/// The SID is the Windows analog of a Unix peer UID — the kernel-verified
/// identity of the process on the other end of the local pipe.
#[cfg(windows)]
pub(super) mod winplat {
    use anyhow::{bail, Context, Result};
    use std::os::windows::io::AsRawHandle;
    use tokio::net::windows::named_pipe::NamedPipeServer;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, RevertToSelf, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Pipes::{CreateNamedPipeW, ImpersonateNamedPipeClient};
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
    };

    // Named pipe creation flags (avoid extra feature imports for the constants).
    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008; // byte type/readmode/wait = 0
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
    const PIPE_BUF: u32 = 65536;

    /// Create a named-pipe server instance with an explicit security descriptor
    /// so local authenticated users can connect to the gate. A pipe's security
    /// must be set at creation time (the server handle has no WRITE_DAC), so we
    /// call CreateNamedPipeW directly and wrap the handle into tokio.
    ///
    /// Connect access is NOT the trust boundary: the gate enforces policy on
    /// every request and never exposes the brokered credentials. The boundary is
    /// the daemon's account isolation. Tighten the trustee set (currently
    /// Administrators/SYSTEM/Authenticated Users) for a multi-user host.
    pub fn create_pipe_server(pipe_name: &str, first: bool) -> Result<NamedPipeServer> {
        let wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
        // The daemon's own account gets full control so it can create the
        // additional pipe instances each accepted client needs
        // (FILE_CREATE_PIPE_INSTANCE). A non-elevated daemon runs as a plain
        // Authenticated User, so without this it can create the first instance
        // but is denied the second (the AU ACE below excludes create-instance).
        // Administrators/SYSTEM also get full control. Authenticated Users get
        // only FILE_GENERIC_READ|FILE_GENERIC_WRITE (0x0012019b) so they can
        // CONNECT but NOT stand up rogue instances. Tighten AU to a specific
        // agent SID for a multi-user host.
        let owner_sid =
            unsafe { process_user_sid() }.context("resolve daemon SID for pipe DACL")?;
        let sddl: Vec<u16> =
            format!("D:(A;;GA;;;{owner_sid})(A;;GA;;;BA)(A;;GA;;;SY)(A;;0x0012019b;;;AU)\0")
                .encode_utf16()
                .collect();
        unsafe {
            let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut psd,
                std::ptr::null_mut(),
            ) == 0
            {
                bail!(
                    "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: psd,
                bInheritHandle: 0,
            };
            let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
            if first {
                open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
            }
            let handle = CreateNamedPipeW(
                wide.as_ptr(),
                open_mode,
                PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUF,
                PIPE_BUF,
                0,
                &sa,
            );
            LocalFree(psd as _);
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                bail!(
                    "CreateNamedPipeW failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            NamedPipeServer::from_raw_handle(handle as _)
                .context("NamedPipeServer::from_raw_handle failed")
        }
    }

    /// Normalize a configured path/name into a `\\.\pipe\<name>` pipe name so the
    /// same `--socket` flag works on Windows.
    pub fn pipe_name(path: &std::path::Path) -> String {
        let s = path.to_string_lossy().to_string();
        if s.starts_with(r"\\.\pipe\") || s.starts_with(r"\\?\pipe\") {
            s
        } else {
            let base = path.file_name().and_then(|f| f.to_str()).unwrap_or("guard");
            format!(r"\\.\pipe\{}", base)
        }
    }

    /// SID string of the daemon's own process token. Used to grant the daemon
    /// full control of the pipe DACL so it can create additional instances.
    pub(crate) unsafe fn process_user_sid() -> Result<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            bail!(
                "OpenProcessToken failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let result = sid_string_from_token(token);
        CloseHandle(token);
        result
    }

    /// Resolve the SID string of the connected pipe client by briefly
    /// impersonating it and reading the impersonation token's user.
    pub fn client_sid(server: &NamedPipeServer) -> Result<String> {
        let pipe = server.as_raw_handle() as HANDLE;
        unsafe {
            if ImpersonateNamedPipeClient(pipe) == 0 {
                bail!(
                    "ImpersonateNamedPipeClient failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let outcome = sid_from_current_thread();
            // Always drop impersonation. A failed revert would leave this pooled
            // tokio worker thread impersonating the lower-privilege client for
            // subsequent tasks (policy eval, credential reads), so a failure here
            // is unrecoverable for the process: abort rather than risk running
            // privileged work under the client's token.
            if RevertToSelf() == 0 {
                tracing::error!(
                    "RevertToSelf failed after named-pipe impersonation ({}); aborting",
                    std::io::Error::last_os_error()
                );
                std::process::abort();
            }
            outcome
        }
    }

    unsafe fn sid_from_current_thread() -> Result<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) == 0 {
            bail!(
                "OpenThreadToken failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let result = sid_string_from_token(token);
        CloseHandle(token);
        result
    }

    unsafe fn sid_string_from_token(token: HANDLE) -> Result<String> {
        let mut len: u32 = 0;
        // First call sizes the buffer (it is expected to "fail" with the length).
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        if len == 0 {
            bail!("GetTokenInformation returned a zero length");
        }
        let mut buf = vec![0u8; len as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            len,
            &mut len,
        ) == 0
        {
            bail!(
                "GetTokenInformation failed: {}",
                std::io::Error::last_os_error()
            );
        }
        // buf is a Vec<u8> (alignment 1); forming a &TOKEN_USER to it would be UB
        // because TOKEN_USER's embedded PSID forces 8-byte alignment. Read the SID
        // pointer out with an unaligned read instead of taking a reference.
        let sid = core::ptr::read_unaligned(core::ptr::addr_of!(
            (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid
        ));
        let mut wide: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut wide) == 0 {
            bail!(
                "ConvertSidToStringSidW failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let s = widestring_to_string(wide);
        LocalFree(wide as _);
        Ok(s)
    }

    unsafe fn widestring_to_string(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

#[cfg(unix)]
async fn handle_client_unix(stream: UnixStream, config: &ServerConfig) -> Result<()> {
    let uid = stream
        .peer_cred()
        .context("failed to read peer credentials")?
        .uid();
    tracing::info!("handle_client_unix: peer uid = {}", uid);

    if let Err(e) = config.validate_uid(uid) {
        tracing::warn!("uid {} rejected: {}", uid, e);
        return Err(e);
    }

    serve_connection(stream, CallerIdentity::Unix { uid }, config).await
}

#[cfg(windows)]
async fn handle_client_pipe(stream: NamedPipeServer, config: &ServerConfig) -> Result<()> {
    let caller = match winplat::client_sid(&stream) {
        Ok(sid) => {
            tracing::info!("named pipe client sid = {}", sid);
            CallerIdentity::Windows { sid }
        }
        Err(e) => {
            // Fail closed: a local pipe peer whose SID we cannot resolve is not
            // trustworthy for per-identity state (secret namespaces, pending-op
            // caps). Drop the connection rather than admit a shared synthetic
            // identity that multiple degraded callers would collapse onto.
            tracing::warn!(
                "could not resolve pipe client SID ({}); rejecting connection",
                e
            );
            return Err(e);
        }
    };
    serve_connection(stream, caller, config).await
}

/// Drive the request/response protocol for one connected client, independent of
/// the underlying transport (UNIX socket or Windows named pipe).
async fn serve_connection<S>(stream: S, caller: CallerIdentity, config: &ServerConfig) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    tracing::info!("serve_connection: waiting for request...");
    while let Ok(Some(line)) = lines.next_line().await {
        if line.len() > MAX_REQUEST_BYTES {
            tracing::warn!("request too large ({} bytes), dropping", line.len());
            continue;
        }
        tracing::debug!("serve_connection: received request (raw)");
        let incoming: IncomingMessage = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = ExecuteResponse {
                    allowed: false,
                    reason: format!("invalid request: {}", e),
                    exit_code: None,
                    stdout: None,
                    stderr: None,
                    status: None,
                    handle: None,
                    coverage: None,
                };
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
        };

        let request = match incoming {
            IncomingMessage::Admin { admin, .. } => {
                let resp = handle_admin_request(config, &caller, admin).await;
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
            IncomingMessage::Grant { grant } => {
                let result = handle_grant_request(config, &caller, grant).await;
                let resp = result.into_response();
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
            IncomingMessage::Execute(req) => *req,
        };

        if let Err(_e) = config.validate_token(request.auth_token.as_deref()) {
            config.log_audit_policy(
                &caller,
                &request.binary,
                &request.args,
                false,
                "invalid auth token",
            );
            let resp = ExecuteResponse {
                allowed: false,
                reason: "invalid auth token".to_string(),
                exit_code: None,
                stdout: None,
                stderr: None,
                status: None,
                handle: None,
                coverage: None,
            };
            writer
                .write_all(serde_json::to_string(&resp)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
            continue;
        }

        let result = if request.stream {
            execute_command_streaming(request.clone(), config, &caller, &mut writer).await
        } else {
            execute_command(request.clone(), config, &caller).await
        };
        emit_exec_audit_events(config, &caller, &request.binary, &request.args, &result);

        let resp = result.into_response();
        if request.stream {
            write_stream_message(
                &mut writer,
                &ExecuteStreamMessage::Result { response: resp },
            )
            .await?;
        } else {
            writer
                .write_all(serde_json::to_string(&resp)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
        }
    }

    Ok(())
}

/// Emit POLICY and (optionally) EXEC_FAILED audit events for a single
/// request, mirroring what the execute handlers emit inline. Test-only:
/// the audit-format tests assert on both events through one entry point.
#[cfg(test)]
pub(super) fn emit_audit_events(
    config: &ServerConfig,
    caller: &CallerIdentity,
    binary: &str,
    args: &[String],
    result: &ExecuteResult,
) {
    // Always emit the policy decision — this is the event historical
    // grep patterns (`[AUDIT] ALLOWED` / `[AUDIT] DENIED`) key on.
    config.log_audit_policy(
        caller,
        binary,
        args,
        result.policy_allowed(),
        result.policy_reason(),
    );

    // If the policy allowed but exec failed, emit a second event so the
    // audit stream can distinguish "LLM denied" from "LLM approved but
    // exec failed". Ignored by legacy grep patterns.
    if let ExecOutcome::Failed { reason, .. } = &result.exec {
        config.log_audit_exec_failed(caller, binary, args, reason);
    }
}

fn emit_exec_audit_events(
    config: &ServerConfig,
    caller: &CallerIdentity,
    binary: &str,
    args: &[String],
    result: &ExecuteResult,
) {
    if let ExecOutcome::Failed { reason, .. } = &result.exec {
        config.log_audit_exec_failed(caller, binary, args, reason);
    }
}

/// Connect to the local guard daemon: UNIX domain socket on Unix, named pipe on
/// Windows. Returns a stream that implements `AsyncRead + AsyncWrite`.
#[cfg(unix)]
pub(super) async fn connect_local(path: &std::path::Path) -> Result<UnixStream> {
    UnixStream::connect(path)
        .await
        .context("failed to connect to guard server")
}

#[cfg(windows)]
pub(super) async fn connect_local(
    path: &std::path::Path,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;
    let name = winplat::pipe_name(path);
    ClientOptions::new()
        .open(&name)
        .context("failed to connect to guard server")
}

async fn handle_client_tcp(stream: tokio::net::TcpStream, config: &ServerConfig) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        if line.len() > MAX_REQUEST_BYTES {
            tracing::warn!("request too large ({} bytes), dropping", line.len());
            continue;
        }
        let incoming: IncomingMessage = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = ExecuteResponse {
                    allowed: false,
                    reason: format!("invalid request: {}", e),
                    exit_code: None,
                    stdout: None,
                    stderr: None,
                    status: None,
                    handle: None,
                    coverage: None,
                };
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
        };

        let request = match incoming {
            IncomingMessage::Admin { admin, admin_token } => {
                let caller = if matches!(admin, AdminRequest::Ping) {
                    CallerIdentity::Tcp {
                        token: "<tcp>".to_string(),
                    }
                } else if let Err(e) = config.validate_admin_token(admin_token.as_deref()) {
                    let resp = AdminResponse::Error {
                        message: format!("admin RPC refused: {}", e),
                    };
                    writer
                        .write_all(serde_json::to_string(&resp)?.as_bytes())
                        .await?;
                    writer.write_all(b"\n").await?;
                    continue;
                } else {
                    CallerIdentity::TcpAdmin {
                        token: admin_token.unwrap_or_else(|| "<missing>".to_string()),
                    }
                };
                let resp = handle_admin_request(config, &caller, admin).await;
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
            IncomingMessage::Grant { grant } => {
                // Read grants apply a POSIX ACL for a kernel-verified local uid;
                // a bearer-token TCP caller carries no such identity, so it can
                // never be the grant principal. Refuse rather than guess.
                let reason = format!(
                    "read grants require a local Unix socket caller: '{}' cannot be requested over TCP",
                    grant.path()
                );
                let resp = ExecuteResponse {
                    allowed: false,
                    reason,
                    exit_code: None,
                    stdout: None,
                    stderr: None,
                    status: None,
                    handle: None,
                    coverage: None,
                };
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
            IncomingMessage::Execute(req) => *req,
        };

        if let Err(_e) = config.validate_token(request.auth_token.as_deref()) {
            let caller = CallerIdentity::Unknown;
            config.log_audit_policy(
                &caller,
                &request.binary,
                &request.args,
                false,
                "invalid auth token",
            );
            let resp = ExecuteResponse {
                allowed: false,
                reason: "invalid auth token".to_string(),
                exit_code: None,
                stdout: None,
                stderr: None,
                status: None,
                handle: None,
                coverage: None,
            };
            writer
                .write_all(serde_json::to_string(&resp)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
            continue;
        }

        let caller = CallerIdentity::Tcp {
            token: request
                .auth_token
                .clone()
                .unwrap_or_else(|| "<none>".to_string()),
        };
        let result = if request.stream {
            execute_command_streaming(request.clone(), config, &caller, &mut writer).await
        } else {
            execute_command(request.clone(), config, &caller).await
        };
        emit_exec_audit_events(config, &caller, &request.binary, &request.args, &result);

        let resp = result.into_response();
        if request.stream {
            write_stream_message(
                &mut writer,
                &ExecuteStreamMessage::Result { response: resp },
            )
            .await?;
        } else {
            writer
                .write_all(serde_json::to_string(&resp)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
        }
    }

    Ok(())
}

pub(super) async fn write_stream_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &ExecuteStreamMessage,
) -> Result<()> {
    writer
        .write_all(serde_json::to_string(message)?.as_bytes())
        .await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

pub(super) async fn write_policy_decision<W: AsyncWrite + Unpin>(
    stream_output: bool,
    writer: &mut W,
    allowed: bool,
    reason: &str,
) -> Result<()> {
    if stream_output {
        write_stream_message(
            writer,
            &ExecuteStreamMessage::PolicyDecision {
                allowed,
                reason: reason.to_string(),
            },
        )
        .await?;
    }
    Ok(())
}
