# contract-review

A multi-chain smart contract review server, exposed over the Model Context Protocol (MCP).
Point an MCP-capable assistant at it, give it a deployed address or a repository, and it runs a
pinned, sandboxed static analysis of the code, hands the leads to the assistant for review, and
renders a branded PDF report.

Live connector: `https://mcp.soken.dev/mcp` (Streamable HTTP). Product site: [soken.dev](https://soken.dev).

## What it does

1. **Pin** the exact code under review (verified on-chain source, a git commit, or uploaded files).
2. **Build** it in an isolated, no-network container for its chain.
3. **Analyze** with the chain's static tooling plus our own rule sets; every tool reports
   `ok`, `degraded` or `not_run` with a reason. Nothing is ever silently dropped.
4. **Map** the codebase (units, call graph, trust boundaries) so the reviewer reads what matters.
5. **Review**: the assistant works the leads, writes findings, and the server challenges them
   against the code before they are accepted.
6. **Report**: a finalized review renders to a PDF with severity KPIs, architecture figure and
   per-finding cards; the owner can publish it to the public showcase with explicit consent.

## Supported chains and analyzers

| Family | Chains | Analysis engines |
|---|---|---|
| EVM | Ethereum, Base, Arbitrum, Optimism, BSC, Polygon, HyperEVM, Arc, Robinhood | Slither, Aderyn (offline), semantic mapper |
| TRON | TRON | Slither-based (shared EVM compiler path) |
| Vyper | EVM Vyper contracts | Slither (best effort), advisories |
| Solana | SPL / Anchor programs, Token-2022 | clippy, cargo-audit (RustSec), soken-solana-rules |
| Move | Aptos, Sui | stock lints, Move Prover (formal verification, spec-gated), soken-move-rules |
| Starknet | Cairo | scarb lint, Caracal, soken-cairo-rules |
| TON | FunC, Tact, Tolk | Misti (Tact), soken-ton-rules |

Severity is normalized through one rubric (`contract/rubric/`) so a finding means the same thing
on every chain.

## Tools

18 MCP tools, all prefixed `review_`:

`review_start` · `review_status` · `review_get_guide` · `review_read_code` · `review_search_code` ·
`review_contract_map` · `review_leads` · `review_facts` · `review_dismiss_lead` ·
`review_submit_finding` · `review_withdraw_finding` · `review_challenge` ·
`review_answer_challenge` · `review_set_section` · `review_finalize` · `review_report` ·
`review_delete_job` · `review_publish`

The full tool contract (input and output schemas, error catalog) lives in `contract/`.

## Security model

- Every build and analysis step runs in a sandboxed container with no network access; external
  dependencies are fetched by the supervisor beforehand and pinned by digest.
- Analyzers fail closed. A tool that did not run says so; it never reports "no findings".
- Report links are signed and time-limited. Publishing a report requires the owner's manage key
  and an explicit, logged consent; the publish worker pushes only the server-rendered PDF.
- Analyzer output is treated as untrusted text and parsed in the supervisor, never executed.

## Development

```bash
uv sync --locked
uv run ruff check src tests
uv run pytest -q
```

Database-backed tests start a Postgres 16 container when Docker is available and skip otherwise.
Sandbox images are built from `docker/<name>/Dockerfile` and pinned by digest in `images.lock.json`.

## Layout

```
contract/     tool contract, error catalog, severity rubric and checklists
docker/       sandbox image definitions (one directory per image)
migrations/   Postgres schema
scripts/      image planning, e2e drivers, operations helpers
slither_plugins/  custom Slither detectors
src/soken_review/
  adapters/   per-chain fetch, build, analyze and verification
  engine/     severity, challenge and text gates
  mapping/    codebase map and facts
  report/     report assembly and the PDF kit
  tools/      the MCP tool handlers
  worker/     the step supervisor and the publish worker
tests/
```

## License

All rights reserved. The source is published for transparency and review; it is not licensed
for reuse, redistribution or derivative works without written permission.
