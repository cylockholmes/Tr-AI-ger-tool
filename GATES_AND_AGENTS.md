# Gates and agents

A reference for the nine agents in `triage.py` and every gate that can change a verdict.
The README explains the pipeline. This page lists, in one place, who does what and what
can stop a finding from becoming Confirmed.

**One rule governs all of it:** models read and judge, code verifies and decides what is
allowed through. Every gate can only move a verdict **toward Needs Review**. Nothing
downstream can promote a finding.

## Agents

Three agents are language models. Six are deterministic code.

| Agent | Kind | Job | Sees | Produces | May not |
|---|---|---|---|---|---|
| **Registrar** | code | Parses the CSV, extracts provenance facts and dataset-wide context | Raw rows | Evidence packet, facts, context | Judge anything |
| **Scout** | model (Assessor A) | First independent assessment | Packet, facts, context, category rubric | Checklist, verdict, confidence, quoted evidence, report fields | See the Skeptic's answer |
| **Skeptic** | model (Assessor B) | Blind second review, told to try to refute both "real" and "false positive" | Same inputs as Scout | Its own checklist, verdict and quotes | See the Scout's answer |
| **Arbiter** | model | Decides only when Scout and Skeptic disagree on the label or differ by 1.5+ CVSS points | Packet, facts, rubric, both assessments including checklists | Final verdict | Average the two, or defer to the more confident one |
| **Warden** | code | Runs every gate below | Every verdict | A possibly downgraded verdict with a plain-language reason | Raise a verdict |
| **Scorekeeper** | code | Computes the CVSS 3.1 score from the vector, harmonises vectors across identical scenarios, assigns priority | Confirmed findings | Score, severity, priority tier | Accept a model's arithmetic |
| **Cartographer** | code | Correlates confirmed findings in one environment into attack chains | Results | `attack_chains.json` | Change a classification |
| **Editor** | code | Plain-language cleanup of client-facing text | Model-written text | Cleaned text | Add or remove facts |
| **Publisher** | code | Writes the CSV and both reports | Final results | Output files | Include anything not in the results |

The roster lives in `AGENTS` in `triage.py` and is written to `out/run_summary.json`.

## Gates

All gates are run by the Warden. The first group runs per finding in `apply_gates`. The
consistency gate runs afterwards across the whole file.

| # | Gate | Applies to | Downgrades to Needs Review when | Code |
|---|---|---|---|---|
| 1 | **Quote verification** | Every verdict | A cited quote is not a verbatim substring of an evidence field (whitespace and case are normalised). Rejected quotes are discarded and noted | `verify_citations`, `locate_quote` |
| 2 | **Identifier-only quotes** | Every verdict | A quote has fewer than 16 characters of content beyond the row's request or finding ID | `locate_quote` |
| 3 | **Boundary observed** | Confirmed, False Positive | The reviewers do not both say the decisive boundary was observed (crossed for Confirmed, enforced for False Positive) | `apply_gates` |
| 4 | **Minimum citations** | Confirmed | Fewer than 2 quotes survive verification | `apply_gates` |
| 5 | **Runtime evidence** | Confirmed | No verified quote comes from a runtime field (observation, validation test, request, response, HTTP exchange, logs, trace) | `RUNTIME_FIELDS` |
| 6 | **Capture behind the narrative** | Confirmed | The only runtime support is the analyst's own description of a test, with no captured request, response, log or trace | `NARRATIVE_RUNTIME_FIELDS` |
| 7 | **Claims are not proof** | False Positive | Every verified quote comes from owner comments or compensating-control claims | `CLAIM_FIELDS` |
| 8 | **Revision provenance** | False Positive | The source excerpt is not tied to the running revision (release bot says the image differs, or the revision does not match the manifest) and no runtime quote shows the control in place | `extract_facts` |
| 9 | **Guided checklist** | Confirmed, False Positive | See [below](#the-guided-checklist-gate) | `verify_checklist`, `checklist_reason` |
| 10 | **Confidence floor** | Confirmed, False Positive | Confidence is below 0.6. On agreement it is the lower of the two reviewers' values; the Arbiter is capped at 0.85 | `MIN_DECISIVE_CONFIDENCE` |
| 11 | **Consistency gate** | Whole file | Rows with the same scenario and evidence profile were classified differently. Every decisive verdict in that group moves to Needs Review | `consistency_gate` |
| 12 | **Failure routing** | Every verdict | A model call fails, times out or returns output that fails the schema. The row gets confidence 0 | `_failed`, `validate` |

A downgraded finding keeps its original class in `gated_from` and the reason in
`gate_notes`, so a reviewer can see exactly what was held back and why.

### The guided checklist gate

Added from two public methods: ZeroFalse's per-CWE micro-rubrics and the Vulnhalla
guided-question approach used by VulnHunterX.

**Rubrics.** `RUBRICS` has an entry for each of the 14 categories in the input data:
Injection, Authorization, Authentication, Path Traversal, File Upload, Browser Security,
OAuth, Code Execution, Secret Detection, Cryptography, Server-Side Request Forgery,
Information Exposure, Account Recovery and Concurrency. Each entry holds:

- the **decisive boundary** for the category;
- **look-alikes** that are often mistaken for the opposite, such as `%s` placeholders
  versus string-built SQL, test-mode keys versus live ones, or MD5 for a cache key
  versus MD5 for a password;
- **three checks**, each phrased so that "yes" means the vulnerable condition is shown.

A rubric says what kind of observation counts. It never says how to decide a finding.

**Answering.** Before classifying, each reviewer answers every check with `yes`, `no` or
`unknown`. A yes or no needs a verbatim quote from the packet. An unknown carries no quote.

**Checking.** Code re-verifies every checklist quote exactly as it does citations. A yes or
no whose quote is not found counts as unbacked.

| Verdict | Needs |
|---|---|
| Confirmed | Every check answered yes and backed |
| False Positive | At least one check answered no and backed |
| Needs Review | Nothing. It is never gated |

**Agreement.** When Scout and Skeptic agree on the label, a check keeps its answer only if
both gave the same one. A split check becomes unknown, so a disagreement between reviewers
on a decisive check prevents Confirmed. When the Arbiter decides, its own checklist is used.

**Scope.** A row whose category has no rubric is not checklist-gated.

## What the gates do not prove

They prove a quote exists and sits in an evidence field of the right kind. They do not
prove the quote means what the reviewer says it means. That is why Confirmed also needs two
independent reviews, a runtime capture and consistency across identical evidence, and why
the analyst report still lists every Needs Review with the specific evidence that would
settle it.

## Checking it yourself

```bash
python3 triage.py --self-test
```

The 58 offline tests include the gates above: fabricated quotes, claim-only evidence,
unobserved boundaries, low confidence, source-only dismissals, split equivalent rows, and
the guided checklist (unanswered check, a check answered no, fabricated checklist quote,
merged checklists, categories without a rubric).

A 30-finding sample was run with both `claude-opus-5-5` and `claude-sonnet-5-5`. Both
produced the same verdicts as the previous full run on those rows (8 Confirmed, 10 False
Positive, 12 Needs Review), and the checklist gate downgraded nothing. That is a small
sample of the first rows, so treat it as a regression check, not a measure of how many
false Confirmed the gate would catch.
