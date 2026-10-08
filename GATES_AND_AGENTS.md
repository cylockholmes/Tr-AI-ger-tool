# Gates and agents

A reference for the ten agents in `triage.py` and every gate that can change a verdict or the text a client reads.
The [README](README.md) explains how to run the tool. This page answers two questions in one place: who does what,
and what can stop a finding from becoming Confirmed.

**One rule governs all of it:** models read and judge; code verifies and decides what is allowed through. Every gate
can only move a verdict **toward Needs Review**. Nothing downstream can promote a finding.

## Agents

Four agents use a language model. Six are deterministic code.

| Agent | Kind | Job | Sees | Produces | May not |
|---|---|---|---|---|---|
| **Registrar** | code + 1 model call | Parses any CSV, maps its columns onto pipeline roles, extracts provenance facts and dataset-wide counts | The file; for unplaced columns, their names and a few sample values | Rows on canonical keys, `column_map.json`, evidence packet, facts | Judge a finding |
| **Scout** | model (review A) | First independent assessment | Packet, facts, dataset counts, category rubric | Checklist, verdict, confidence, quoted evidence, CVSS vector, title, impact, fix | See the Skeptic's answer |
| **Skeptic** | model (review B) | Blind second review, briefed to try to refute both "real" and "false positive" | Same inputs as the Scout | Its own checklist, verdict, quotes and vector | See the Scout's answer |
| **Arbiter** | model | Decides when the two reviews disagree on the outcome; casts a third CVSS vote when both confirm but score any metric differently | Packet, facts, rubric, both reviews | Verdict, vector, report fields | Average the reviews, or defer to the more confident one |
| **Warden** | code | Runs every gate below | Every verdict | A possibly downgraded verdict with a plain-language reason | Raise a verdict |
| **Editor** | code | Plain-language cleanup of client-facing text: jargon, spelling, punctuation, attacker wording that matches the vector | Model-written text | Cleaned text | Add or remove facts |
| **Scorekeeper** | code | Combines the reviews' vectors per metric, computes the CVSS 3.1 score, aligns findings with identical evidence, assigns fix order | Confirmed findings | Vector, score, severity, priority tier | Accept a model's arithmetic |
| **Cartographer** | code | Correlates confirmed findings in one environment into attack chains | Results | `attack_chains.json` | Change a classification |
| **Fact-checker** | model + code | Checks every claim in each confirmed issue's client-facing title and impact against that finding's evidence | Lead finding's row, vector and client text | Passed, revised or flagged text; `fact_check.json` | Change a verdict, score or fix; pass text it could not check |
| **Publisher** | code | Writes the CSVs and the reports | Final results | Output files | Include anything not in the results |

The roster lives in `AGENTS` in `triage.py` and is written to `run_summary.json` on every run.

## Verdict gates

The Warden runs gates 1 to 11 per finding in `apply_gates`. The consistency gate runs afterwards across the whole
file. Field kinds come from the column mapping (README, "Input"): a column mapped as `capture` counts as a captured
observation, `claim` as an assertion, `label` as an untrusted scanner label.

| # | Gate | Applies to | Downgrades to Needs Review when | Code |
|---|---|---|---|---|
| 1 | **Quote verification** | Every verdict | A cited quote is not a verbatim substring of a quotable field (whitespace and case normalised). Rejected quotes are discarded and noted. The verdict only moves if too few good quotes remain (gates 4 to 6) | `verify_citations`, `locate_quote` |
| 2 | **Identifier-only quotes** | Every verdict | A quote has fewer than 16 characters of content beyond the row's own request or finding ID. Discarded like gate 1 | `locate_quote`, `quote_problem` |
| 3 | **Labels are not evidence** | Every verdict | A quote comes only from scanner labels (severity, rule, title, IDs, dates). Discarded like gate 1 | `quotable_fields`, `quote_problem` |
| 4 | **Minimum citations** | Confirmed | Fewer than 2 quotes survive verification | `apply_gates` |
| 5 | **Runtime evidence** | Confirmed | No verified quote comes from runtime evidence (a capture or a test account) | `is_runtime` |
| 6 | **Capture behind the narrative** | Confirmed | The only runtime support is someone's description of a test, with no captured request, response, tool output, log or trace | `is_capture` |
| 7 | **Claims are not proof** | False Positive | Every verified quote comes from owner comments, tickets or claimed controls | `is_claim` |
| 8 | **Revision provenance** | False Positive | The source excerpt is not tied to the running revision and no runtime quote shows the control in place | `extract_facts` |
| 9 | **Boundary observed** | Confirmed, False Positive | The reviews do not both say the decisive boundary was observed | `apply_gates` |
| 10 | **Guided checklist** | Confirmed, False Positive | See [below](#the-guided-checklist-gate) | `verify_checklist`, `checklist_reason` |
| 11 | **Confidence floor** | Confirmed, False Positive | Confidence is below 0.6. On agreement it is the lower of the two reviews; the Arbiter is capped at 0.85 | `MIN_DECISIVE_CONFIDENCE` |
| 12 | **Consistency gate** | Whole file | Rows with the same scenario and evidence profile were classified differently. Every decisive verdict in the group moves to Needs Review | `consistency_gate` |
| 13 | **Failure routing** | Every verdict | A model call fails, times out or returns output that fails the schema. The row gets confidence 0 | `_failed`, `validate` |

A downgraded finding keeps its original class in `gated_from` and the reason in `gate_notes`, and its reasoning in the
CSV says what evidence would decide it.

### The guided checklist gate

Adapted from two public methods: ZeroFalse's per-CWE micro-rubrics and the Vulnhalla guided-question approach used by
VulnHunterX.

**Rubrics.** `RUBRICS` covers 14 flaw categories: Injection, Authorization, Authentication, Path Traversal, File
Upload, Browser Security, OAuth, Code Execution, Secret Detection, Cryptography, Server-Side Request Forgery,
Information Exposure, Account Recovery and Concurrency. A finding's rubric is found from its category by name, else by
keyword (`SQL Injection`, `CWE-89`, `IDOR`, `XSS` and so on), and from its title when there is no category. Each rubric
holds:

- the **decisive boundary** for the category;
- **look-alikes** often mistaken for the opposite, such as `%s` placeholders versus string-built SQL, test-mode keys
  versus live ones, or MD5 for a cache key versus MD5 for a password;
- **three checks**, each phrased so that "yes" means the vulnerable condition is shown.

A rubric says what kind of observation counts. It never says how to decide a finding.

**Answering.** Before classifying, each review answers every check `yes`, `no` or `unknown`. A yes or no needs a
verbatim quote; an unknown carries none. Code re-verifies every checklist quote exactly as it does citations.

| Verdict | Needs |
|---|---|
| Confirmed | Every check answered yes and backed |
| False Positive | At least one check answered no and backed |
| Needs Review | Nothing. It is never gated |

**Agreement.** When the reviews agree on the outcome, a check keeps its answer only if both gave the same one. A split
check becomes unknown, so a disagreement on a decisive check prevents Confirmed. When the Arbiter decides, its own
checklist is used. A finding no rubric fits is not checklist-gated.

## Proof that the gates run

A gate that never fires looks the same as a gate that is switched off. Three things separate the two.

- **Every gate runs on every finding.** `apply_gates` computes the condition of gates 1 to 11 for each finding, whatever
  its verdict, and stores a `gate_trace` on the result: for each gate, whether it applies to that verdict, whether its
  condition was met and whether it fired. Gate 12 runs across the whole file and gate 13 on every model failure.
- **Gate activity is reported.** The console, `run_summary.json` (`gate_activity`) and the "Gate activity" table in
  the analyst report list, per gate, how many findings it was evaluated on and how many it acted on.
- **A drill trips every gate before every run.** `gate_drill` feeds each gate the fault it exists to catch (a
  fabricated quote, an identifier-only quote, a quote copied from a scanner label, one citation, claims as the only
  support, narrative with no capture, a dismissal resting on an owner claim, source that is not the running revision,
  an unobserved boundary, an all-unknown checklist, confidence 0.55, split verdicts on identical evidence, a failed
  model call) and checks that the gate fired and the verdict became Needs Review. A clean control must fire nothing.
  The drill makes no model calls. It runs at the start of every run, its result is written to `gate_drill.json`, and
  if any gate fails to trip the run stops with exit code 4 before assessing a finding. `python3 triage.py --gate-drill`
  runs it alone.

**What the real runs show.** On the first 25 findings of the 350-row file, assessed with fresh model calls, no gate
downgraded any verdict. This also held when the sentences that restate the gate rules (the confidence floor, the
citation minimum, the checklist requirement) were removed from the models' prompt. The models' own judgment already
met every gate's condition: decisive verdicts carried confidence of 0.70 or more, at least four verified quotes, a
backed checklist and an observed boundary, and they sent weak cases to Needs Review themselves. Gates 9 and 10 compare
a model's answers with its own verdict, so they only fire if a model contradicts itself. Gates 1 to 3 fire on a
hallucinated quote, which did not occur. Only the consistency gate has fired on real data (2 findings in the 350-row
run). A zero in the activity table therefore means the evidence passed, and the drill shows the gate would have caught
a failure.

## Scoring rules

Owned by the Scorekeeper. None of them can change a verdict.

| Rule | What it does | Code |
|---|---|---|
| **Score from vector** | The CVSS 3.1 score is computed by code from the vector, never taken from a model | `base_score` |
| **Third vote on any split** | If two confirming reviews differ on any CVSS metric (or on severity band, or by 1.5+ points), the Arbiter votes too | `needs_adjudication` |
| **Per-metric vote** | Each metric takes the median of the confirming reviews' values; with an even count, the less severe. Order-independent. The reasoning comes from the closest review plus a sentence naming each split | `tiebreak_vector` |
| **Identical evidence, one vector** | Confirmed findings of the same scenario share the most common vector (ties to the lower score); the reasoning travels with it; originals are kept | `harmonise` |
| **Fix order** | CVSS score × environment weight; confidence is not an input | `priority`, `env_class` |

## Client-text checks

Owned by the Editor and the Fact-checker. They govern what a client reads, never the verdict.

| Check | What it does | Code |
|---|---|---|
| **Plain language** | Removes pipeline jargon and filler, converts to US spelling, fixes punctuation around paths and code, restores sentence capitals | `plain_text` |
| **Attacker matches the vector** | "Anyone who can reach…" becomes "any signed-in user…" for PR:L, or "an attacker…" when the account requirement was only assumed | `align_actor` |
| **Claims against evidence** | Every claim in the title and impact is marked supported, inference, not tested or unsupported. A supported claim must quote text that code finds in the row's evidence or record fields (asset, environment, owner, category, dates; never scanner severity or confidence) | `fact_check`, `verify_claims` |
| **One rewrite, then flag** | Unsupported claims get one rewrite that is checked again. Anything still unsupported, or any check that fails, is flagged on the console, in the analyst report and in `fact_check.json` | `fact_check` |
| **Leftover tells** | The rendered reports are scanned for jargon or AI filler that slipped through | `report_style_issues` |

## What the gates do not prove

They prove a quote exists and sits in an evidence field of the right kind. They do not prove the quote means what a
review says it means. That is why Confirmed also needs two independent reviews, a runtime capture, a passed checklist
and consistency across identical evidence, and why the analyst report lists every Needs Review with the evidence that
would settle it.

The Fact-checker catches claims the evidence does not state. It does not catch an inference that is reasonable but
wrong, so the analyst report shows every claim and its status.

## Checking it yourself

```bash
python3 triage.py --self-test
```

The 89 offline tests cover every gate and rule above, including fabricated quotes, claim-only evidence, unobserved
boundaries, low confidence, source-only dismissals, split equivalent rows, the checklist, the per-metric vote, the
Fact-checker and arbitrary CSV formats.

Validation with real model runs, on synthetic data:

- **Verdict stability.** One 25-finding sample was assessed three times with fresh model calls, with prompt changes in
  between. 24 of 25 verdicts were identical every time; the one that moved had a live secret whose public exposure was
  not observed at runtime, which both outcomes can defend.
- **Fact-checker and the reviews' brief.** On a random 20 previously confirmed findings, the share of findings whose
  client text needed correcting fell from 9 of 19 to 4 of 19 over three rounds of tightening the reviews' brief, with
  nothing left flagged for a person.
- **Foreign formats.** A semicolon-separated, Windows-1252 scanner export with no ID column, and a file with Spanish
  column names, both ran end to end into valid reports.

These are small samples. Treat them as regression checks, not as measured error rates.
