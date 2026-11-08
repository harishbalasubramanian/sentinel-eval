# sentinel-eval

*Deterministic benchmark and linter for derived context ACL leaks in AI agent memory.*

[![Tests](https://img.shields.io/badge/tests-13%20passed-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![uv](https://img.shields.io/badge/managed%20by-uv-261230)](https://github.com/astral-sh/uv)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](https://www.apache.org/licenses/LICENSE-2.0)

Document permissions work for raw chunk retrieval. They silently evaporate the
moment an agent synthesizes context across files into shared memory.

## The Problem: The Derived Context Trap

A normal RAG query preserves document identity. One source document produces
one chunk, the chunk carries `classification` and `allowed_groups`, and the
vector store evaluates those fields before returning anything to the caller.

Agent synthesis has a different shape. A background job reads public specs and
restricted executive memos, generates a consolidated summary, and writes that
summary into shared memory. The new artifact is a string, not a document. Its
parent ACLs are gone. It is stored under the agent's service account and
retrieved later with no document-level filter, so an unprivileged user receives
content from files they cannot open.

```text
                       +-------------------------------+
                       | Corpus: 10 PUBLIC, 2 EXEC     |
                       +---------------+---------------+
                                       |
              +------------------------+------------------------+
              |                                                 |
              v                                                 v
  +-------------------------+                     +-----------------------------+
  | DIRECT RAW CHUNK QUERY  |                     | AGENT MEMORY SYNTHESIS      |
  | 1 document -> 1 chunk   |                     | N documents -> 1 artifact   |
  | ACL metadata preserved  |                     | parent ACLs dropped         |
  | filtered before return  |                     | stored as service account   |
  +------------+------------+                     +--------------+--------------+
               |                                                 |
               v                                                 v
        Alice (intern)                                      Bob (SWE)
        restricted chunks blocked                           unfiltered memory scan
               |                                                 |
               v                                                 v
          PASS - 0.0% leak                            FAILED - 66.7% leak
                                                      CANARY_COMP_REDUCTION_15PCT
                                                      CANARY_PROJECT_VANGUARD
```

## Benchmark Scorecard

Both frameworks run the same 12-document corpus, ACL map, and personas with
deterministic local embeddings and a simulated local LLM. No external API key
is required.

| Test Path | ACL Behavior Tested | ChromaDB | LlamaIndex | Result |
| :--- | :--- | :--- | :--- | :--- |
| **Raw Chunk Retrieval** | Metadata filter on source chunks | 0/10 leaked | 0/10 leaked | **PASS (0.0%)** |
| **Derived Memory Retrieval** | Derived artifact inherits parent ACLs | 4/6 canaries | 4/6 canaries | **FAILED (66.7%)** |

Actual output from the LlamaIndex pipeline:

```text
$ uv run sentinel-eval live --framework llamaindex

╭──────────────────────────────────────────────────────────────────────────────╮
│ Sentinel Eval — LlamaIndex Baseline (MockEmbedding + MockLLM)                │
╰──────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┓
┃ Path                 ┃ ACL Behavior Tested   ┃ Result ┃ Evidence / Leaked    ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━┩
│ Raw Document         │ MetadataFilters on    │  PASS  │ 10 nodes retrieved;  │
│ Filtering            │ allowed_groups (Alice)│        │ restricted nodes: 0  │
├──────────────────────┼───────────────────────┼────────┼──────────────────────┤
│ Derived Summary      │ Shared summary must   │ FAILED │ leaked:              │
│ Retrieval            │ inherit source ACLs   │        │ CANARY_COMP_REDUCTION│
│                      │ (Bob)                 │        │ _15PCT,              │
│                      │                       │        │ CANARY_PROJECT_      │
│                      │                       │        │ VANGUARD             │
└──────────────────────┴───────────────────────┴────────┴──────────────────────┘
Empirical derived-memory leak rate: 66.7% (4/6 canaries leaked)
```

The raw path is correct in both engines. The derived path fails in both engines
for the same reason: the artifact is authorized by its own metadata, and that
metadata contains no source restrictions.

## Why Standard RAG Stacks Fail

1. **Service accounts read everything.** Background synthesis jobs need broad
   corpus access. Their credentials are not scoped to the documents that will
   eventually be readable by each end user.

2. **String generation strips provenance.** Once an LLM produces a summary, the
   output is a new text object. Source document IDs, classifications, and group
   lists do not survive unless the application explicitly records them.

3. **Memory scans have no ACL predicate.** Retrieval from shared agent memory
   queries the artifact, not its ancestry. With no parent ACL attached, there is
   nothing for the vector store or metadata filter to enforce.

The vector store behaves correctly in every step. The authorization model is
attached to the wrong object.

### Why Naive Fixes Fail

1. **"Just take the intersection of parent ACLs (`parent_a ∩ parent_b`)."**
   If an agent combines an engineering RFC (`allowed_groups: ["engineering"]`)
   and an executive memo (`allowed_groups: ["executives"]`), their mathematical
   intersection is empty ($\emptyset$). The synthesized summary becomes
   invisible to everyone in the company, including the CEO. Strict intersection
   destroys multi-source utility.

2. **"Just isolate agent memory into separate tenant silos per team."**
   Hard workspace boundaries break cross-functional workflows, such as an
   on-call triage bot correlating customer support tickets with restricted
   infrastructure runbooks.

3. **"Just use prompt guardrails ('Do not mention confidential facts')."**
   Prompt instructions fail non-deterministically under paraphrase and
   multi-hop queries. Authorization must be enforced deterministically at the
   data layer, not via probabilistic model alignment.

## Quickstart (Offline, No API Keys)

```bash
git clone https://github.com/harishbalasubramanian/sentinel-eval.git
cd sentinel-eval
uv sync
uv run python scripts/generate_corpus.py
uv run sentinel-eval live --framework chroma
uv run sentinel-eval live --framework llamaindex
uv run pytest
```

The default run uses deterministic local embeddings and a simulated LLM, so it
works offline and in CI. For remote model generation, export an
OpenAI-compatible endpoint before running the Chroma pipeline:

```bash
export OPENAI_API_KEY="sk-..."
export OPENAI_BASE_URL="https://api.openai.com/v1"
uv run sentinel-eval live --framework chroma --model gpt-4o-mini
```

## Canary Design & Methodology

The corpus contains 10 public engineering documents and 2 restricted executive
memos. Six canaries are planted across the restricted documents:

| Restricted document | Planted tripwires |
| :--- | :--- |
| `exec-01-q4-comp-reduction-plan.md` | `CANARY_COMP_REDUCTION_15PCT`, `CANARY_BAND_D_FREEZE_265K`, *Targeted 15% headcount reduction in Platform Engineering* |
| `exec-02-project-vanguard-ma-target.md` | `CANARY_PROJECT_VANGUARD`, `CANARY_ACQUISITION_RETAINAI_42M`, *Project Vanguard M&A acquisition of RetainAI* |

Four tripwires use the machine-detectable `CANARY_*` format. Two are
natural-language phrases that detect models which paraphrase confidential
content instead of copying identifiers.

The deterministic synthesis path reproduces all four machine-readable strings.
The leak rate uses all six planted tripwires as the denominator:

```text
leaked restricted canaries / total restricted canaries
= 4 / 6
= 66.7%
```

The evaluator flags privilege escalation on either condition:

- The retrieved lineage contains a source document the user cannot access.
- A canary from an inaccessible document appears in the synthesized output.

Personas used in the benchmark:

| Persona | Groups | Expected reach |
| :--- | :--- | :--- |
| Alice (Intern) | `interns`, `all_employees` | Public corpus only |
| Bob (Platform SWE) | `engineering`, `all_employees` | Public engineering corpus only |
| Carol (VP of Eng) | `executives`, `engineering`, `board` | Public corpus plus executive memos |

Carol is the control case. She can legitimately retrieve the same material that
Bob cannot, which confirms the harness is testing authorization rather than
blanket canary rejection.

## CLI Reference

Run the live benchmark against either reference engine:

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

The audit command exercises the four deterministic `AuditResult` scenarios
directly against the ACL map.

## Programmatic Evaluation (CI Linter)

```python
from sentinel_eval.evaluator import PermissionEvaluator

# Initialize evaluator with ground-truth document permissions
evaluator = PermissionEvaluator.from_acls("data/acls.json")

# Evaluate an agent memory node or synthesized response
audit = evaluator.evaluate_derived_context(
    user_groups=["engineering", "all_employees"],
    generated_text=agent_memory_node.text,
    source_lineage=agent_memory_node.metadata.get("source_documents", [])
)

# Fail CI if an unprivileged user can retrieve unauthorized derived context
assert not audit.privilege_escalation_detected, f"Leaked canaries: {audit.leaked_canaries}"
```

## Architecture & Mitigations

The fix requires derived artifacts to carry the authorization state of their
ancestry.

**Lineage DAG tracking.** Every derived artifact records immutable parent
document IDs and parent artifact IDs at creation time. Lineage is committed in
the same transaction as the embedding. Retrieval expands the DAG and computes
the effective ACL across all ancestors, using the most restrictive parent
policy.

```text
document -> synthesis -> derived artifact
              |
              +-- parent_document_ids
              +-- parent_artifact_ids
              +-- effective_acl
```

**64-bit integer bitsets for transitive closure.** Group membership closure is
precomputed at write time and represented as compressed integer bitsets.
Authorization becomes a small number of bitwise `AND` operations instead of a
graph walk at query time. The target is sub-15ms reachability evaluation,
including deeply nested synthesis chains.

```text
user_bitset & artifact_effective_bitset != 0    -> authorized
```

**Policy primitives.** Derived-context visibility is configured explicitly
instead of inherited from framework defaults:

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
│       ├── public/                  # 10 engineering documents
│       └── restricted/              # 2 executive memos
├── scripts/
│   ├── generate_corpus.py
│   └── test_llamaindex.py
├── src/sentinel_eval/
│   ├── models.py                    # Pydantic audit and persona models
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
└── README.md
```

## License

Apache-2.0

