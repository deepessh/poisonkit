# CLI Attack Matrix

A black-box evaluation of **tool-metadata poisoning** against three real
product CLI coding agents: **Codex CLI**, **GitHub Copilot CLI**, and
**Claude Code**. Six attacks deliver payloads through tool metadata
(descriptions, parameter schemas, tool identity); a seventh,
**rag-poison**, poisons tool *output* as a comparison against the adjacent
indirect-injection surface.

## What was tested

Three phases, more than 200 runs in total:

1. **Fixed-model harness comparison** — one shared model
   (`deepseek/deepseek-v4-flash-0731`) routed into all three CLIs, isolating
   harness behavior: system prompts, tool rendering, agent loops, permission
   handling.
2. **Vendor-aligned models** — each CLI on its vendor-family model
   (`openai/gpt-5.3-codex`, `openai/gpt-5.4`, `anthropic/claude-sonnet-4.6`),
   served through OpenRouter rather than vendor endpoints.
3. **Frontier-model sensitivity** — GPT-6 family (`openai/gpt-6-luna`,
   `openai/gpt-6-sol`), `anthropic/claude-sonnet-5`, and a targeted
   `anthropic/claude-opus-5.5` probe, all via OpenRouter.

Verdicts are **PWN** (the attack's predefined success condition was met),
**RESIST** (fixture engaged, attack failed), and **INCONCLUSIVE** (fixture
never engaged or the run was unusable — never counted as resistance).

## Core finding

Tool-metadata poisoning is an **interaction problem**: security depends on
the model, the agent harness, and where malicious instructions enter the
tool interface — not on any one of them alone. Full results, methodology,
and limitations are in the findings report:

- [`report/Poisonkit CLI Attack Matrix — Public Findings Report.pdf`](report/Poisonkit%20CLI%20Attack%20Matrix%20—%20Public%20Findings%20Report.pdf)
- [`report/Poisonkit CLI Attack Matrix — Public Findings Report.docx`](report/Poisonkit%20CLI%20Attack%20Matrix%20—%20Public%20Findings%20Report.docx)

## Reproduce it

Prerequisites: Python 3.10+, the three CLIs installed
(`codex`, `copilot`, `claude`), and an OpenRouter API key.

```bash
export OPENROUTER_API_KEY=<your key>

# one cell, three repetitions:
python3 drivers/run_matrix.py \
  --cli codex --model deepseek/deepseek-v4-flash-0731 \
  --attacks param-poison --runs 3 --out ./matrix-results

# full matrix on one model:
python3 drivers/run_matrix.py \
  --cli codex --cli copilot --cli claude \
  --model deepseek/deepseek-v4-flash-0731 --out ./matrix-results
```

How it works:

- `drivers/cli_drivers.py` — headless per-CLI drivers. Each CLI is pointed
  at a local proxy instead of its default endpoint; runs execute in
  disposable temp dirs with approval prompts bypassed for unattended
  evaluation. No temperature, top-p, seed, or reasoning-effort parameters
  are set — every CLI runs its own defaults.
- `drivers/or_proxy.py` — localhost forward proxy (`/v1/*` for
  OpenAI-compatible CLIs, `/api/*` for Claude Code's Anthropic protocol)
  that attaches the OpenRouter credential per request. The raw key never
  touches CLI env vars, config files, or disk.
- `drivers/run_matrix.py` — batch runner: benign smoke gate per combo,
  three (configurable) repetitions per attack, two-phase rug-pull, per-cell
  transcripts + sink logs + `results.jsonl`, verdicts via
  `classify_verdict`.
- `fixtures/pk_mcp_fixture.py` — the poisoned MCP fixture server (stdio
  JSON-RPC, stdlib only). One attack per invocation, selected by
  `PK_ATTACK`; `PK_RUG_PHASE=1|2` selects the rug-pull phase. All canaries
  are synthetic and harmless; sinks are append-only temp logs.

## Caveats (see the report's Limitations for the full list)

- Models were served through OpenRouter, not vendor endpoints — these are
  vendor-*aligned* configurations, not native product configurations.
- OpenRouter provider routing was not pinned; provider-level variation may
  contribute to run-to-run differences.
- Fractions describe observed runs in this test environment, not estimates
  of real-world attack probability.
- Approval/re-approval UX is unobservable in headless runs.
