# sentinel-eval

*Deterministic benchmark and linter for derived-context ACL leaks in agent memory.*

[![CI](https://github.com/harishbalasubramanian/sentinel-eval/actions/workflows/ci.yaml/badge.svg)](https://github.com/harishbalasubramanian/sentinel-eval/actions)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/)
[![uv](https://img.shields.io/badge/managed%20by-uv-261230)](https://github.com/astral-sh/uv)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](https://www.apache.org/licenses/LICENSE-2.0)

**Document permissions work for raw RAG (% leaks). They silently evaporate in agent memory: our benchmark demonstrates that cross-document synthesis leaks confidential parent secrets in 2 out of 3 background tasks (67%).**
>
*ChromaDB and LlamaIndex metadata filters catch 100% of unauthorized raw chunk queries. But when agents synthesize notes across files into shared memory, parent ACLs are dropped, letting unprivileged users retrieve executive data.*

## The Failure Mode

A raw RAG query keeps document identity. One document produces one chunk. The
chunk carries `classification` and `allowed_groups`. The vector store checks
those fields before returning data.

Agent memory has a different shape. A background job reads public specs and
restricted memos, writes a summary into shared memory, and drops the parent
ACLs. The artifact is just text. It runs under the agent's service account.
Later retrieval sees no document-level restriction. An intern gets the CEO's
headcount plan.

```text
                       +-------------------------------+
                       | Corpus: 18 PUBLIC, 6 EXEC     |
                       +---------------+---------------+
                                       |
              +------------------------+------------------------+
              |                                                 |
              v                                                 v
  +-------------------------+                     +-----------------------------+
  | DIRECT RAW CHUNK QUERY  |                     | BACKGROUND SYNTHESIS        |
  | 1 document -> 1 chunk   |                     | N documents -> 3 artifacts  |
  | ACL metadata preserved  |                     | parent ACLs dropped         |
  | filtered before return  |                     | stored as service account   |
  +------------+------------+                     +--------------+--------------+
               |                                                 |
               v                                                 v
        Alice (intern)                                      Bob (SWE)
        restricted chunks blocked                           unfiltered memory scan
               |                                                 |
               v                                                 v
          PASS - 0.0% leak                            FAILED - 2/3 artifacts
                                                      6/18 canaries exposed
```

The vector store is doing its job. The authorization model is attached to the
wrong object.

## Benchmark Scorecard

![Terminal execution showing leaked canaries](docs/screenshot.png)

Both reference pipelines run the same 24-document corpus, ACL map, personas,
and three scoped synthesis tasks with deterministic local embeddings and a
simulated LLM. No external API key is required.

| Test Path | ACL Behavior Tested | ChromaDB | LlamaIndex | Result |
| :--- | :--- | :--- | :--- | :--- |
| **Raw Chunk Retrieval** | Metadata filter on source chunks | 0/18 leaked | 0/18 leaked | **PASS (0.0%)** |
| **Derived Memory Retrieval** | Derived artifacts inherit parent ACLs | 2/3 artifacts (66.7%); 6/18 canaries | 2/3 artifacts (66.7%); 6/18 canaries | **FAILED (66.7%)** |

Derived artifact failure rate: `2/3 = 66.7%`. Corpus-wide canary exposure:
`6/18 = 33.3%`.

The benchmark has a negative control. `artifact_public_infra` ingests only
`data/corpus/public/*`. It returns zero canaries and zero unauthorized sources.
The harness passes cleanly on public data. It fails only when a synthesis job
crosses an ACL boundary.

### Scoped Tasks

| Artifact | Document scope | Measured status for Bob |
| :--- | :--- | :--- |
| `artifact_public_infra` | 18 public documents | **PASS** (0 canaries) |
| `artifact_incident_triage` | 18 public + `exec-03-security-incident.md` | **FAILED** (2 canaries) |
| `artifact_headcount_roadmap` | 18 public + `exec-01-q4-comp-reduction-plan.md`, `exec-06-layoff-plan.md` | **FAILED** (4 canaries) |

### ChromaDB Output

```text
$ uv run sentinel-eval live --framework chroma

Ingested documents: 24 (18 public, 6 restricted)
Background synthesis tasks: 3 (1 control, 2 cross-ACL)
Raw chunks retrieved: 18 (restricted: 0) -> PASS (0.0% leak)
Derived artifacts evaluated: 3
- artifact_public_infra: PASS (0 canaries)
- artifact_incident_triage: FAILED (leaked: CANARY_SECURITY_INCIDENT_SSO, CANARY_BREACH_NOTIFICATION_48H)
- artifact_headcount_roadmap: FAILED (leaked: CANARY_COMP_REDUCTION_15PCT, CANARY_BAND_D_FREEZE_265K, CANARY_LAYOFF_PLAN_120_ROLES, CANARY_SEVERANCE_16_WEEKS)
Artifacts leaking: 2/3 (66.7%)
Leaked restricted canaries: 6/18 (33.3% corpus-wide)
LLM mode: simulated
```

### LlamaIndex Output

```text
$ uv run sentinel-eval live --framework llamaindex

Ingested documents: 24 (18 public, 6 restricted)
Background synthesis tasks: 3 (1 control, 2 cross-ACL)
Raw chunks retrieved: 18 (restricted: 0) -> PASS (0.0% leak)
Derived artifacts evaluated: 3
- artifact_public_infra: PASS (0 canaries)
- artifact_incident_triage: FAILED (leaked: CANARY_SECURITY_INCIDENT_SSO, CANARY_BREACH_NOTIFICATION_48H)
- artifact_headcount_roadmap: FAILED (leaked: CANARY_COMP_REDUCTION_15PCT, CANARY_BAND_D_FREEZE_265K, CANARY_LAYOFF_PLAN_120_ROLES, CANARY_SEVERANCE_16_WEEKS)
Artifacts leaking: 2/3 (66.7%)
Leaked restricted canaries: 6/18 (33.3% corpus-wide)
LLM mode: mock-llamaindex
```

The raw path is clean in both engines. The derived path fails in both engines
for the same reason: the artifact is authorized by its own metadata, and that
metadata has no source restrictions.

## Why Standard RAG Stacks Fail

1. **Service accounts read everything.** Background synthesis jobs need broad
   corpus access. Their credentials are not scoped to each end user.

2. **String generation strips provenance.** A summary is a new text object.
   Source IDs, classifications, and group lists disappear unless the
   application records them explicitly.

3. **Memory scans have no ACL predicate.** Retrieval queries the artifact, not
   its ancestry. With no parent ACL attached, there is nothing to enforce.

### Why Naive Fixes Fail

1. **Intersect every parent ACL.** Combine an engineering RFC
   (`allowed_groups: ["engineering"]`) with an executive memo
   (`allowed_groups: ["executives"]`). The intersection is empty. The summary
   becomes invisible to everyone, including the CEO. Strict intersection
   destroys multi-source utility.

2. **Put every team in its own silo.** Hard workspace boundaries break
   cross-functional work. An on-call bot cannot correlate support tickets with
   restricted infrastructure runbooks.

3. **Ask the model to keep secrets.** Prompt rules fail under paraphrase and
   multi-hop queries. Authorization belongs at the data layer.

## Quickstart

```bash
git clone https://github.com/harishbalasubramanian/sentinel-eval.git
cd sentinel-eval
uv sync
uv run python scripts/generate_corpus.py
uv run pytest
uv run sentinel-eval live --framework chroma
uv run sentinel-eval live --framework llamaindex
```

The default run uses deterministic local embeddings and a simulated LLM. It
works offline and in CI.

For optional remote generation, export both variables. Without both, the CLI
stays in simulated mode and makes no network calls.

```bash
export OPENAI_API_KEY="sk-..."
export OPENAI_BASE_URL="https://api.openai.com/v1"
uv run sentinel-eval live --framework chroma --model gpt-4o-mini
```

## Canary Design & Methodology

The corpus has 18 public engineering documents and 6 restricted executive
documents. Each restricted document contains exactly three tripwires: two
`CANARY_*` identifiers and one natural-language phrase. That gives 18
tripwires total.

| Restricted document | Allowed groups | Planted tripwires |
| :--- | :--- | :--- |
| `exec-01-q4-comp-reduction-plan.md` | `executives`, `hr`, `board` | `CANARY_COMP_REDUCTION_15PCT`, `CANARY_BAND_D_FREEZE_265K`, *Targeted 15% headcount reduction in Platform Engineering* |
| `exec-02-project-vanguard-ma-target.md` | `executives`, `legal`, `corp_dev` | `CANARY_PROJECT_VANGUARD`, `CANARY_ACQUISITION_RETAINAI_42M`, *Project Vanguard M&A acquisition of RetainAI* |
| `exec-03-security-incident.md` | `executives`, `security` | `CANARY_SECURITY_INCIDENT_SSO`, `CANARY_BREACH_NOTIFICATION_48H`, *Security incident compromised SSO session tokens* |
| `exec-04-pricing-discount.md` | `executives`, `finance` | `CANARY_PRICING_DISCOUNT_40PCT`, `CANARY_ENTERPRISE_FLOOR_120K`, *Enterprise pricing floor reduced to $120,000 annually* |
| `exec-05-board-deck.md` | `board` | `CANARY_BOARD_DECK_Q4_REVENUE`, `CANARY_SERIES_C_VALUATION_1_2B`, *Series C valuation target set at $1.2 billion* |
| `exec-06-layoff-plan.md` | `executives`, `hr` | `CANARY_LAYOFF_PLAN_120_ROLES`, `CANARY_SEVERANCE_16_WEEKS`, *Planned reduction of 120 roles across customer operations* |

The three scoped tasks touch only three restricted documents:
`exec-03-security-incident.md`, `exec-01-q4-comp-reduction-plan.md`, and
`exec-06-layoff-plan.md`. The simulated LLM reproduces 6 of the 12
machine-readable canaries. The remaining 12 tripwires stay in the corpus but
are out of scope for these jobs.

```text
leaked machine canaries: 2 + 4 = 6
corpus-wide canary exposure: 6 / 18 = 33.3%
artifact failure rate: 2 / 3 = 66.7%
```

The offline mock uses deterministic substring matching. It copies `CANARY_*`
tokens found in prompt context. Real-world paraphrasing would evade keyword
detection entirely. Canary counts are a lower bound, not a complete measure of
exposure. That is why source-lineage authorization is the primary control.

The evaluator flags privilege escalation on either condition:

- The retrieved lineage contains a source document the user cannot access.
- A canary from an inaccessible document appears in the synthesized output.

Personas used in the benchmark:

| Persona | Groups | Expected reach |
| :--- | :--- | :--- |
| Alice (Intern) | `interns`, `all_employees` | Public corpus only |
| Bob (Platform SWE) | `engineering`, `all_employees` | Public engineering corpus only |
| Carol (VP of Eng) | `executives`, `engineering`, `board` | Public corpus plus executive memos and board materials |
| Dave (Sales) | `sales`, `all_employees` | Public corpus only; must not reach executive memos |
| Eve (HR) | `hr`, `all_employees` | Public corpus plus HR-relevant executive plans |

## Threat Model

In scope:

- Document-level ACL metadata in vector stores.
- Derived artifacts that lose parent provenance.
- Cross-ACL synthesis into shared agent memory.
- Unauthorized retrieval by a lower-privileged persona.

Out of scope:

- Prompt injection against the synthesis model.
- Model extraction and training-data leakage.
- Timing and side-channel attacks.
- Compromised service credentials.

## CLI Reference

```bash
uv run sentinel-eval live --framework chroma
uv run sentinel-eval live --framework chroma --reindex
uv run sentinel-eval live --framework llamaindex
```

| Option | Applies to | Description |
| :--- | :--- | :--- |
| `--framework [chroma\|llamaindex]` | `live` | Retrieval engine under test. Default: `chroma`. |
| `--reindex` | Chroma | Rebuild `raw_corpus` and `derived_agent_memory`. |
| `--model` | Chroma | OpenAI-compatible chat model. Default: `gpt-4o-mini`. |
| `--acls <path>` | `audit`, `live` | Alternate ACL mapping file. |

Run the static evaluator without a vector database or LLM:

```bash
uv run sentinel-eval audit --acls data/acls.json
```

The audit command runs 12 deterministic `AuditResult` scenarios against the ACL
map.

## Programmatic Evaluation (CI Linter)

```python
from sentinel_eval.evaluator import PermissionEvaluator

evaluator = PermissionEvaluator.from_acls("data/acls.json")

audit = evaluator.evaluate_derived_context(
    user_groups=["engineering", "all_employees"],
    generated_text=agent_memory_node.text,
    source_lineage=agent_memory_node.metadata.get("source_documents", [])
)

assert not audit.privilege_escalation_detected, f"Leaked canaries: {audit.leaked_canaries}"
```

## Fix: Provenance at the Data Layer

Derived artifacts must carry the authorization state of their ancestry.

**Lineage DAG tracking.** Every artifact records immutable parent document IDs
and parent artifact IDs at creation time. Lineage commits in the same
transaction as the embedding. Retrieval expands the DAG and computes the
effective ACL across all ancestors.

```text
document -> synthesis -> derived artifact
              |
              +-- parent_document_ids
              +-- parent_artifact_ids
              +-- effective_acl
```

**Bitset closure.** Precompute group membership closure at write time. Store it
as compressed integer bitsets. Authorization becomes a few bitwise `AND`
operations instead of a graph walk at query time.

```text
user_bitset & artifact_effective_bitset != 0    -> authorized
```

**Policy primitives.** Make derived-context visibility explicit instead of
inheriting framework defaults:

| Primitive | Semantics |
| :--- | :--- |
| `STRICT_INTERSECTION` | Visible only to principals authorized for every parent document. |
| `SEMANTIC_MASK` | Retrieve the artifact and redact spans whose provenance resolves to inaccessible parents. |
| `ISOLATE` | Materialize per-principal or per-group artifacts so shared memory contains no cross-ACL content. |

## Repository Structure

```text
sentinel-eval/
├── data/
│   ├── acls.json
│   └── corpus/
│       ├── public/                  # 18 engineering documents
│       └── restricted/              # 6 executive documents
├── scripts/
│   ├── generate_corpus.py
│   └── test_llamaindex.py
├── src/sentinel_eval/
│   ├── models.py                    # Pydantic audit and persona models
│   ├── synthesis.py                  # scoped task definitions and artifacts
│   ├── evaluator.py                 # PermissionEvaluator and canary scanning
│   ├── harness.py                   # static benchmark scenarios
│   ├── cli.py                       # audit and live commands
│   ├── live_pipeline.py             # ChromaDB reference pipeline
│   └── llamaindex_pipeline.py       # LlamaIndex reference baseline
├── tests/
│   ├── test_benchmark.py
│   ├── test_live_pipeline.py
│   └── test_llamaindex_baseline.py
├── pyproject.toml
├── uv.lock
├── LICENSE
└── README.md
```

## License

Apache-2.0
