# Agent integration

Guard keeps the agent-facing surface close to ordinary shell and API tooling.
The daemon remains the only policy and credential boundary; integrations do not
reimplement evaluation.

## Generic shims

Install wrappers for tools an agent already knows:

```bash
guard shim ssh kubectl helm ansible ansible-playbook
guard shim --list
guard shim --remove helm
```

A shim preserves argv and the caller's working directory, then invokes
`guard run`. Any executable name can be shimmed. The listed tools are examples,
not first-class authorization types. Guard avoids re-entering the top-level shim
while leaving nested shims available to child processes.

Add the shim directory ahead of the real tools in the agent's `PATH`. The agent
cannot bypass Guard if it also lacks remote credentials and direct upstream
reachability.

## Guard-owned execution context

An authenticated caller controls the command argv and a canonicalized working
directory. The daemon executes approved work with:

- its configured operating-system identity, unless `--exec-as-caller` is set;
- a clean environment plus built-in safe values;
- operator-selected `GUARD_CHILD_ENV` values;
- Guard's SSH configuration and agent socket;
- approved secret and secret-file bindings.

Caller-controlled `SSH_AUTH_SOCK`, SSH configuration, or credential environment
does not replace this context. This keeps remote access brokered even when an
agent asks to run `ssh`, Ansible, or another SSH-using tool.

Guard preserves tool semantics. It runs in the caller's working directory and
does not copy, stage, rewrite, or interpret playbooks, charts, inventories, or
other input files. File-driven tools remain denied by the default evaluator
posture unless a matching verb or short-lived grant authorizes the requested
region.

On Unix, the transparent read-grant pipeline can temporarily add an ACL when the
daemon account cannot read one named caller file. Credential-shaped paths,
multi-hardlink files, symlink swaps, and traversal outside the file owner's home
fail closed. The ACL is inode-pinned, TTL-scoped, audited, persisted for cleanup,
and removed by startup or periodic reconciliation. Windows keeps native file
ACLs unchanged and returns access denied.

`--exec-as-caller` is an alternate Unix filesystem-identity model for a root
daemon. It cannot be combined with TCP, the API proxy, or secret-file delivery.
It also moves more local filesystem authority to the caller, so it is not the
default credential-broker model.

## Secrets

Store secrets in the daemon backend, then name them at execution time:

```bash
guard secrets add DEPLOY_TOKEN
guard run --secret DEPLOY_TOKEN deploy-tool status
guard run --secret API_TOKEN=DEPLOY_TOKEN api-client status
guard run --secret-file ANSIBLE_VAULT_PASSWORD_FILE=ansible-vault-password \
  ansible-playbook --check site.yml
```

Secret values never enter the request, command line, evaluator prompt, audit
record, hold row, or session history. A hold stores a salted value hash and
revalidates it before approval. Child output is redacted by exact values and
credential-shaped patterns.

## Structured CLI output

Human `guard run` streams the child process. `guard run --json` returns one
machine-readable result containing child stdout, stderr, exit status, decision
source, matched verb cells, and escalation guidance. `--explain` renders those
details on stderr for a successful human run; default success remains quiet.
Denied and held results render guidance without requiring the flag. Read commands such as
`guard status --json`, `guard session status --json`, and `guard verb list
--json` support automation without parsing prose.

Guard-origin denial, hold, and operational failures use distinct outcomes from
an executed child's exit status. A successful human command does not print verb
matching noise. Denied and held commands print the matching coverage and the
next bounded action on stderr.

## MCP

Expose the same daemon through MCP over stdio:

```bash
guard config set-server ~/.guard/guard.sock
guard mcp serve
```

The MCP server executes commands and provides requester-scoped verb, approval,
and session operations through the normal daemon protocol. Structured and human
tool results carry the stable decision source, matched cells, and guidance. It
does not create a parallel policy path.

HTTP MCP is available for a local single-tenant runtime and requires a bearer:

```bash
export GUARD_MCP_TOKEN="..."
guard mcp serve --http 127.0.0.1:7333
```

Every HTTP MCP caller appears to the daemon as the MCP process principal. Keep
the listener inside the same trusted boundary and use the stdio transport when
per-process network identity is unnecessary.

## In-process API clients

Helm, Terraform providers, k9s, and SDKs can perform API operations without
spawning a command for each request. Point these clients at Guard's brokered
endpoint so policy applies at the request boundary. The API client carries a
Guard session bearer while the daemon retains the upstream credential. See
[API proxy](api-proxy.md).
