# System-prompt append: local tool knowledge

Copyable evaluator prompt supplement for deployment-specific systemd context.
Load with
`guard server start --dry-run --exec-user guard-exec --system-prompt-append <path>` or
`GUARD_PROMPT_APPEND=<path>`; the daemon appends the whole file to the mode
prompt without replacing it, so everything in this file, including this
paragraph, becomes evaluator context. Keep the content factual and tool-scoped;
the worked style and the typed-verb alternative are documented in
[docs/configuration.md](../docs/configuration.md).

Local systemd policy:

- `systemctl status api.service` and `systemctl status worker.service` inspect
  deployment services without changing them.
- `systemctl restart api.service` and `systemctl restart worker.service` mutate
  process state and require the applicable consequence controls.
- Treat every other local unit as outside this deployment's intended scope.

Prompt additions refine evaluator context for supported executable profiles.
They do not authorize an executable that Guard's profile registry rejects.
