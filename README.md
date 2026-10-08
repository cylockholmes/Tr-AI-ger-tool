# Tr(AI)ger

Evidence-first triage for noisy security findings. Give it a CSV of scanner findings. It gives back a verdict for every row, an executive report and an analyst report.

Every finding ends up as one of three things, with a reason and a confidence:

- **Confirmed**: the row contains quoted evidence, including a captured runtime observation, that shows the vulnerable condition.
- **False Positive**: the row contains evidence, not an owner's say-so, that the condition is absent or unreachable on the running code.
- **Needs Review**: the deciding step was not observed, or the evidence conflicts. The output names the evidence that would settle it.

The rule behind all of it: **models read and judge, and code verifies and decides what is allowed through.** A model can propose Confirmed, but only evidence the code can check lets it stand.

## Run it

You need Python 3.9+ and the [Claude Code](https://claude.com/claude-code) CLI (`claude`) on your `PATH`, logged in. There are no pip packages.

```bash
python3 triage.py --csv findings.csv --client-name "Acme Corp"
python3 triage.py --csv findings.csv --limit 10 --out /tmp/try   # try a few first
python3 triage.py --self-test                                    # 89 offline tests, no model calls
```

Without `--csv` it lists the CSVs it finds and asks. Model answers are cached in `.cache/`, so an interrupted run resumes where it stopped. If the CLI reports a 401, log in again with `claude auth login`.

The input can be any CSV with any column names. The delimiter is detected, and each column is mapped to a role by name, then by common aliases, then by one model call for what is left. `--column-map map.json` overrides the mapping. The mapping is printed and saved as `column_map.json`.

A column's kind decides what it can prove: captured traffic, logs and traces are runtime evidence; a tester's narrative is a description of a test; source and config are static evidence; owner and ticket statements are **claims**; scanner scores, severities and IDs are **untrusted labels**. Nothing missing is invented. An existing verdict column is hidden from the model.

## How a verdict is made

1. **Two blind reviews.** The Scout and the Skeptic each answer a per-category checklist, give a verdict, quote their evidence and propose a CVSS vector. They never see each other's answer, and the Skeptic is told to argue against both outcomes.
2. **A third vote only on disagreement.** If they differ on the outcome or on any CVSS metric, the Arbiter decides from the evidence. It cannot average.
3. **Seven gates**, all code, all able to move a verdict only toward Needs Review:

| Gate | Moves a verdict to Needs Review when |
|---|---|
| Quote verification | A quote is not verbatim in the row, is just an identifier, or comes only from a scanner label. The bad quote is discarded |
| Sufficient evidence | Confirmed has fewer than 2 verified quotes, or none from a capture |
| Claims are not proof | A False Positive rests only on owner or ticket statements |
| Revision provenance | A False Positive rests on source that is not shown to be the running revision |
| Guided checklist | Confirmed lacks a backed "yes" on every check, or a False Positive lacks a backed "no". A quote from a claim does not back an answer |
| Consistency | Rows with identical evidence were classified differently |
| Failure routing | A model call failed. The row gets confidence 0 |

A model's own confidence and its own "boundary observed" flag are reported, but they are not gates. They describe the model's verdict, so a gate on them could only disagree with itself.

4. **Scoring in code.** The CVSS 3.1 score is computed from the vector, never taken from a model. If the reviews split on a metric, the median per metric is used (the less severe on a tie). Fix order is CVSS score times an environment weight (production 1.0, staging 0.6, sandbox 0.5, edit `ENV_WEIGHT` to change it). Confidence is kept out of the formula.
5. **Client text is checked.** The Editor removes jargon and matches attacker wording to the vector. The Fact-checker marks every claim in an issue's title and impact supported, inference, not tested or unsupported, and code checks each supporting quote is really in the row. Anything still unsupported is flagged for a person.

The full roster of agents and the detail of each gate are in [GATES_AND_AGENTS.md](GATES_AND_AGENTS.md).

## Do the gates actually fire?

A gate that never fires looks the same as one that is switched off, so the tool shows its work:

- Every per-finding gate is evaluated on every finding and recorded in its `gate_trace`.
- Each run starts with a **drill** that plants one fault per gate (a fabricated quote, claims as the only proof, a claim-backed checklist answer, split verdicts, a failed model call) and requires the gate to trip. No model calls are used. If any gate fails to trip, the run stops with exit code 4. `--gate-drill` runs it alone.
- The console, `run_summary.json` and the analyst report show how many findings each gate was evaluated on and how many it acted on.

On real data most gates fire rarely, because the models' own judgement already clears them. Across 240 reviews from the saved samples, none was downgraded by an earlier, larger gate set, which is why the two gates that only compared a model with its own verdict were removed. The tightened checklist gate does act: replaying saved reviews, it moves three findings (FLR-0043, FLR-0108, FLR-0102) from Confirmed to Needs Review, each because a decisive check rested only on an owner or ticket claim. Whether that is right for a given finding is a judgement call.

## What you get

| File | For | Contents |
|---|---|---|
| `client_report.html` and `.md` | Executives | Confirmed issues only, in business terms: CVSS vector and score, impact, ordered fix with a retest step, owners, every affected system |
| `findings_report.html` | Analysts | Everything: each confirmed issue with evidence, every Needs Review with the test that would settle it, every False Positive with its reason, attack chains, gate activity, a searchable appendix |
| `classified_findings.csv` | Everyone | Verdict, reasoning, confidence, priority, CVSS and gate notes per finding |
| `<input name>-filled.csv` | Everyone | Your input with `candidate_classification` and `candidate_reasoning` filled in |
| `assessments.jsonl` | Reviewers | The full audit trail: every review, quotes, checklists, gate trace |
| `gate_drill.json`, `fact_check.json`, `column_map.json`, `attack_chains.json`, `audit.json`, `run_summary.json` | Reviewers | Gate drill, claim checks, column mapping, chains, consistency audit, run statistics |

Both reports are self-contained HTML with no external requests. They say plainly that they triage existing findings from supplied evidence and are not a penetration test.

## Options

| Flag | Purpose |
|---|---|
| `--csv PATH` `--out DIR` | Input file and output directory (default `./out`) |
| `--client-name` `--company` `--tester` | Names for the reports (prompted if omitted; `''` leaves company and tester out) |
| `--column-map FILE` | Override the inferred column mapping |
| `--model` `--fallback-model` `--effort` | Default `claude-sonnet-5-5`, fallback `claude-opus-5-5`, effort `high` |
| `--workers N` `--timeout S` | Parallel findings (4) and per-call timeout (420 s) |
| `--ids A-1,A-2` `--limit N` | Assess only some findings |
| `--no-cache` `--skip-fact-check` | Ignore cached answers, skip the Fact-checker |
| `--rebuild-reports` | Rebuild reports from saved results with no model calls |
| `--gate-drill` `--self-test` | Run the gate drill or the test suite and exit |

Exit codes: `0` success, `2` input error, `3` some findings could not be assessed and went to Needs Review (re-run to retry), `4` gate drill failed, `130` interrupted. Cost is roughly $0.10 per finding on the default model.

## Limits

- **Bounded by the evidence.** No host is contacted. Thin exports land in Needs Review with the missing evidence named.
- **The gates check provenance, not meaning.** They prove a quote is real and from the right kind of evidence, not that it supports the claim made from it. That judgement is the models', so check a sample before sending anything.
- **CVSS vectors are model judgements.** The voting rule makes each result reproducible from the saved reviews, but a fresh run can vote differently on a debatable metric.
- **The Fact-checker catches unsupported claims, not wrong inferences.**
- **Provenance facts read particular formats** (`revision=<hex>` in source, `image-source-revision` in the manifest, a release-bot note, `X-Request-ID`). On other exports they come out empty and the models read provenance unaided.
- **Attack chains are correlations** unless the data links findings by a shared request, trace, session or object ID.
- **Editing any prompt invalidates the cache**, and the next run costs a full run.

```
triage.py             the whole tool: agents, gates, scoring, both reports, tests
README.md             this file
GATES_AND_AGENTS.md   every agent and every gate in one place
```
