# mcp-firewall

A local security proxy that sits between an MCP client and its MCP servers.
It tracks the provenance of every value flowing through an agent session and
blocks tool calls that violate a declared policy before they execute.

Think of it as a reference monitor for agent tool calls: **deterministic
information-flow control, not an LLM judge.**

> **This is a research/demo project. All "attacks" in this repo are inert
> text fixtures used to test the defence.** The demo runs entirely offline
> against local mock MCP servers. No real credentials, no real network
> egress, and no third-party services are involved anywhere in the default
> path. See [Safety & scope](#safety--scope) below.

## Status

Phase 1 of 5 is complete: a method-agnostic stdio proxy shim with an
append-only audit log, wired end-to-end against three local mock MCP
servers. Labelling, the policy engine, static detectors, the benchmark
harness, and the dashboard land in later phases (tracked below).

- [x] Phase 1 — proxy shim, audit log, CLI
- [ ] Phase 2 — labels, taint propagation, policy engine, DENY path
- [ ] Phase 3 — static detectors (rug pull, shadowing, tool poisoning)
- [ ] Phase 4 — benchmark harness and results
- [ ] Phase 5 — read-only dashboard

## Threat model, in plain language

An MCP-based agent calls tools across multiple servers with different trust
levels — e.g. a trusted local docs server, and an untrusted inbox server
whose content originates from other people. If the agent reads untrusted
content and later uses it (directly, or after paraphrasing) as an argument
to a sensitive tool call — like the recipient of an outgoing message, or a
file path — an attacker who controls that untrusted content can steer the
agent's actions without ever touching the model weights or the prompt. This
is *indirect prompt injection*. Related attack classes this project targets:

- **Tool poisoning** — a tool description contains hidden imperative
  instructions aimed at the agent, not the user.
- **Tool shadowing** — two servers register a tool with the same (or
  confusable) name, and the wrong one gets called.
- **Rug pull** — a tool's schema silently changes after the user already
  approved the original version.
- **Cross-server exfiltration / confused deputy** — data read from one
  server is used to construct a call to a completely different server that
  was never meant to see it.

mcp-firewall's answer is not "ask a model whether this looks suspicious."
It labels every tool result with where it came from and how much it should
be trusted, propagates that label into anything derived from it, and
mechanically refuses a tool call if a labelled value reaches a sink a
policy forbids. That decision is deterministic and auditable.

## Architecture

```
MCP client (Claude Desktop, Cursor, etc.)
        |
        |  stdio, JSON-RPC 2.0
        v
  mcp-firewall run  --server <name> -- <real server command>
        |
        | inspects only tools/call and tools/list;
        | every other method is forwarded verbatim, ids untouched
        v
   real MCP server (spawned as a subprocess)
```

Each configured downstream server gets its own `mcp-firewall run` process,
mirroring how a real MCP host already spawns one process per server entry
in its config. All instances share one local audit database.

```
mcp_firewall/
  proxy.py      MCP protocol shim (stdio). Method-agnostic: parses only
                tools/call and tools/list, forwards everything else
                (including unknown/future methods, notifications, progress,
                cancellation) byte-for-byte with ids preserved.
  labels.py      [phase 2] Label model {source_server, trust_level, is_secret}
                and propagation.
  policy.py      [phase 2] Loads policy.yaml, evaluates rules, ALLOW/DENY.
  detectors.py   [phase 3] Static checks on tool metadata.
  audit.py       SQLite append-only log of every tools/call and tools/list:
                args, result, verdict, reason.
  cli.py         `mcp-firewall run|demo|report`

demo/
  servers/       Three small mock MCP servers, all local, all inert:
                  docs_server   (trusted, reads demo/sandbox/* only)
                  inbox_server  (UNTRUSTED, returns canned emails from fixtures)
                  mailer_server (the sink; appends to a local log file --
                                 there is no network code in this file at all)
  agent.py       The scripted "client" that drives the demo. See the
                 worst-case-agent note below before reading any firewall-off
                 number produced by it.
  mcp_client.py  A small synchronous stdio JSON-RPC client used by agent.py.
  fixtures/      Benign (and, later, attack-scenario) fixtures as plain text.
  sandbox/       fake_secrets.txt (a fake canary, CANARY-DO-NOT-PANIC-0001)
                 and a couple of dummy documents.

tests/
  fixtures/echo_server.py   Trivial stdio JSON-RPC responder used only to
                             test that the proxy forwards arbitrary methods.
  fixtures/sdk_server.py    A real server built with the official `mcp` SDK
                             (dev/test-only dependency), used to prove the
                             proxy also works against genuine SDK traffic,
                             not just our own hand-rolled mock protocol.
```

### Why the proxy doesn't use the `mcp` SDK at runtime

The proxy operates purely at the JSON-RPC framing level: it never needs to
understand what a given method *means* to do its job, only whether it's
`tools/call` or `tools/list`. Depending on the SDK at runtime would also
mean tracking its release cadence just to stay a transparent pass-through.
The `mcp` package is still used, but only as a **dev/test dependency**, to
build a real SDK-based server (`tests/fixtures/sdk_server.py`) so there is
an integration test proving the proxy works against genuine SDK wire
traffic and not just our own mock protocol.

### A note on the scripted demo agent

`demo/agent.py`, run with the default `--backend scripted`, is a
deterministic, **worst-case compliant** agent: starting from the phase that
adds attack scenarios, it will follow any imperative instruction it finds
in tool output, including text from the untrusted `inbox_server`, with no
judgement of its own. That's intentional — it exists to show the firewall
stops the bad outcome even when the layer above it does exactly what an
attacker's text tells it to.

**Firewall-off "attack success" measured with the scripted agent is true by
construction**, not an empirical claim about how a real model behaves — it
only confirms a fixture would work if nothing were policing it. The
optional `--backend ollama` path runs the same scenarios against a locally
run open model and is reported as a **separate table** in the benchmark
results (added in Phase 4); the two are never combined into one number.

## Running the demo

Two commands, fully offline, no API keys:

```bash
python -m venv .venv && .venv/Scripts/pip install -e ".[dev]"   # Windows
# source .venv/bin/activate && pip install -e ".[dev]"          # macOS/Linux

mcp-firewall demo
```

This spawns the three mock servers, each wrapped by its own proxy process,
runs a benign scripted task against each, and writes everything to
`audit.db`. Inspect the run with:

```bash
mcp-firewall report --audit-db audit.db
```

## Testing

```bash
pytest
```

Tests are hermetic: no network access, no real MCP servers beyond the local
mock/test fixtures, and no model calls.

## Benchmark results

Not yet available — the benchmark harness lands in Phase 4. This section
will contain two tables: attack success rate and benign-task completion /
false-positive rate, each before/after enabling the firewall, with the
scripted-agent and ollama-backend results kept separate per the note above.

## Safety & scope

- All attack fixtures are inert plain-text strings in `demo/fixtures/` —
  never executed, never sent anywhere. See `demo/fixtures/README.md`.
- The "secret" an attack scenario tries to steal is a fake canary string,
  `CANARY-DO-NOT-PANIC-0001`, in `demo/sandbox/fake_secrets.txt`. It is not
  a real credential.
- The exfiltration "sink" (`mailer_server`) has no network code at all — it
  appends to a local log file. Nothing is ever emailed, uploaded, or sent
  anywhere.
- The mock docs tool rejects any path outside `demo/sandbox/`, independent
  of the firewall's own policy engine.
- The demo runs fully offline against local subprocesses. Any local HTTP
  server this project adds (the Phase 5 dashboard) binds to `127.0.0.1`
  only, never `0.0.0.0`.
- Nothing in this repo touches your real MCP client configuration, shell
  config, SSH config, or anything outside this repository.
