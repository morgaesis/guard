# System-prompt append: local tool knowledge

Copyable evaluator prompt supplement for an in-house tool the compiled prompts
do not know. Load with `guard server start --system-prompt-append <path>` or
`GUARD_PROMPT_APPEND=<path>`; the daemon appends the whole file to the mode
prompt without replacing it, so everything in this file, including this
paragraph, becomes evaluator context. Keep the content factual and tool-scoped;
the worked style and the typed-verb alternative are documented in
[docs/configuration.md](../docs/configuration.md).

Local tool: servicectl

- `servicectl list` enumerates configured services and does not mutate anything.
- `servicectl status [SERVICE]` and `servicectl info SERVICE` read service
  state and configuration and do not mutate anything.
- `servicectl logs SERVICE` prints recent log lines; `--since DURATION` and
  `--limit N` bound the read. Read-only.
- `servicectl restart SERVICE`, `servicectl scale SERVICE COUNT`, and
  `servicectl config set SERVICE KEY VALUE` mutate the named service: they
  change processes, replica counts, and persisted configuration. Treat each as
  an opaque mutation.
- Reject unknown subcommands, shell fragments, stdin-driven input, and service
  names that are not visible as one argv element.
