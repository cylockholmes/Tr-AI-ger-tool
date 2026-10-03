#!/usr/bin/env python3
"""Tr(AI)ger: evidence-first triage for noisy security findings.

Usage:
  python3 triage.py                       # prompts you to pick a .csv
  python3 triage.py --csv findings.csv
  python3 triage.py --csv f.csv --model claude-sonnet-5-5 --out out-sonnet

Single-file triage pipeline (stdlib only, Python >= 3.9).
Requires the Claude Code CLI (`claude`) on PATH and logged in.
"""
from __future__ import annotations

import argparse
import collections
import copy
import concurrent.futures as cf
import csv
import datetime as dt
import hashlib
import html
import json
import math
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


# ============================================================================
# Policy constants (referenced by prompts, gates and the report)
# ============================================================================
CLASSIFICATIONS = ("Confirmed", "False Positive", "Needs Review")
MIN_QUOTE_CHARS = 16             # shorter citations are too generic to count as evidence
MIN_CITATIONS_CONFIRMED = 2
MIN_DECISIVE_CONFIDENCE = 0.6    # Confirmed / False Positive below this become Needs Review
NEEDS_REVIEW_CONFIDENCE_CAP = 0.5
ADJUDICATED_CONFIDENCE_CAP = 0.85
CVSS_DIVERGENCE = 1.5            # agreeing Confirmed verdicts this far apart are adjudicated
# Fix order = CVSS score weighted by how close the system is to production.
# Model-reported confidence is deliberately not part of it: Confirmed already
# requires a confidence floor, and a few hundredths of an uncalibrated number
# should not reorder a customer's remediation list.
ENV_WEIGHT = {"production": 1.0, "dr-canary": 0.85, "staging": 0.6, "sandbox": 0.5}
DEFAULT_ENV_WEIGHT = 0.7
TIER_CHASE = 7.0
TIER_LOOK = 3.0


# ---------------------------------------------------------------------------
# Agent roster. Three agents are language models; the rest are deterministic
# code stages. The README documents what each one sees, produces and may not do.
# ---------------------------------------------------------------------------
AGENTS = {
    "Registrar": "code: parses the CSV, extracts provenance facts and dataset-wide context",
    "Scout": "model, Assessor A: classifies the finding and proposes CVSS vector, impact and fix",
    "Skeptic": "model, Assessor B: blind second review that tries to refute both outcomes",
    "Arbiter": "model: decides only when Scout and Skeptic disagree",
    "Warden": "code: evidence gates and consistency gate; can only move a verdict toward Needs Review",
    "Scorekeeper": "code: computes CVSS 3.1 scores, harmonises vectors, assigns priority",
    "Cartographer": "code: correlates confirmed findings into attack chains",
    "Editor": "code: plain-language cleanup of every client-facing sentence",
    "Publisher": "code: writes the CSV, the analyst report and the client report",
}


# ============================================================================
# CSV input / output
# ============================================================================
# Always parsed with the csv module: fields contain quoted
# commas and embedded newlines, so line- or comma-splitting is wrong.
REQUIRED_COLUMNS = ("finding_id",)

# Columns that are never shown to the model: they are the answer slots.
HIDDEN_COLUMNS = ("candidate_classification", "candidate_reasoning")


class InputError(Exception):
    pass


def read_findings(path: Path) -> List[Dict[str, str]]:
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh, strict=True)
            if reader.fieldnames is None:
                raise InputError(f"{path}: empty file or no header row")
            missing = [c for c in REQUIRED_COLUMNS if c not in reader.fieldnames]
            if missing:
                raise InputError(f"{path}: missing required column(s): {', '.join(missing)}")
            rows = []
            for row in reader:
                if None in row:  # more cells than headers -> malformed row
                    raise InputError(f"{path}: record ending near line {reader.line_num} has extra cells")
                if None in row.values():  # fewer cells than headers -> truncated row
                    raise InputError(f"{path}: record ending near line {reader.line_num} has too few cells")
                row = {k: (v or "") for k, v in row.items()}
                if not row["finding_id"].strip():
                    raise InputError(f"{path}: record ending near line {reader.line_num} has no finding_id")
                rows.append(row)
    except UnicodeDecodeError as exc:
        raise InputError(f"{path}: not valid UTF-8 ({exc})") from exc
    except csv.Error as exc:
        raise InputError(f"{path}: not valid CSV ({exc})") from exc
    ids = [r["finding_id"] for r in rows]
    dupes = sorted(i for i, n in collections.Counter(ids).items() if n > 1)
    if dupes:
        raise InputError(f"{path}: duplicate finding_id(s): {', '.join(dupes[:10])}")
    if not rows:
        raise InputError(f"{path}: no findings")
    return rows


OUTPUT_COLUMNS = (
    "finding_id",
    "classification",
    "reasoning",
    "confidence",
    "priority_tier",
    "priority_score",
    "cvss_vector",
    "cvss_score",
    "cvss_severity",
    "decisive_boundary",
    "assessor_agreement",
    "gate_notes",
    "asset",
    "environment",
    "finding_title",
    "first_observed_utc",
    "scanner_source",
    "attack_chains",
)


def _csv_cell(value) -> str:
    """Neutralise spreadsheet formula injection in untrusted text."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def write_filled_input(path: Path, source_csv: Path, results: List[Dict[str, object]]) -> int:
    """Write a copy of the input CSV with every original column kept as supplied and
    the two answer columns (candidate_classification, candidate_reasoning) filled
    from the final verdicts. Rows keep the input order; rows that were not assessed
    (--ids / --limit) are left blank. Returns the number of rows filled."""
    rows = read_findings(source_csv)
    by_id = {str(r["finding_id"]): r for r in results}
    with open(source_csv, newline="", encoding="utf-8-sig") as fh:
        fields = list(csv.DictReader(fh).fieldnames or [])
    fields += [c for c in HIDDEN_COLUMNS if c not in fields]
    filled = 0
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            res = by_id.get(row["finding_id"])
            if res:
                row["candidate_classification"] = str(res["classification"])
                row["candidate_reasoning"] = _csv_cell(res.get("reasoning"))
                filled += 1
            w.writerow(row)
    return filled


def write_classified(path: Path, results: List[Dict[str, object]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=OUTPUT_COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in results:
            w.writerow({k: _csv_cell("; ".join(r.get("chains") or []) if k == "attack_chains" else r.get(k))
                        for k in OUTPUT_COLUMNS})


# ============================================================================
# CVSS 3.1 base score calculator (FIRST specification, section 7)
# ============================================================================
# The model proposes a vector; the score is always computed here so a model
# arithmetic slip can never reach the client report.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_VECTOR_RE = re.compile(
    r"^CVSS:3\.1/AV:(?P<AV>[NALP])/AC:(?P<AC>[LH])/PR:(?P<PR>[NLH])/UI:(?P<UI>[NR])"
    r"/S:(?P<S>[UC])/C:(?P<C>[HLN])/I:(?P<I>[HLN])/A:(?P<A>[HLN])$"
)


class CVSSError(ValueError):
    pass


def roundup(value: float) -> float:
    """Spec Appendix A roundup: smallest one-decimal number >= value,
    computed on integers to avoid floating-point artefacts."""
    as_int = int(round(value * 100000))
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def parse_vector(vector: str) -> Dict[str, str]:
    m = _VECTOR_RE.match((vector or "").strip())
    if not m:
        raise CVSSError(f"not a CVSS 3.1 base vector: {vector!r}")
    return m.groupdict()


def base_score(vector: str) -> float:
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"
    iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    if impact <= 0:
        return 0.0
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def cvss_severity_label(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def score_vector(vector: Optional[str]) -> Tuple[Optional[str], Optional[float], Optional[str]]:
    """Return (normalised vector, score, severity) or (None, None, None)."""
    if not vector:
        return None, None, None
    v = vector.strip()
    if not v.startswith("CVSS:"):
        v = "CVSS:3.1/" + v
    try:
        s = base_score(v)
    except CVSSError:
        return None, None, None
    return v, s, cvss_severity_label(s)


# ============================================================================
# Deterministic evidence pre-processing
# ============================================================================
# Nothing here decides a classification. It (1) renders a row into a labelled
# evidence packet for the model and (2) extracts provenance / correlation facts
# that are easy for code and error-prone for a reader: revision identifiers,
# request-ID correlation across HTTP, logs and traces, sampling and capture
# warnings. Facts are stated, never interpreted.
# Field groups. Order matters: it is the order the model reads the packet.
FIELD_ORDER = [
    ("Scanner metadata (UNTRUSTED labels)", [
        "finding_id", "scanner_source", "scanner_rule", "scanner_severity", "scanner_confidence",
        "finding_title", "category", "scanner_raw_output",
    ]),
    ("Asset", ["asset", "environment", "asset_owner", "first_observed_utc", "last_observed_utc", "request_id"]),
    ("Analyst observation and validation", ["observation", "validation_attempt"]),
    ("Runtime HTTP evidence", ["raw_request", "raw_response", "raw_http_exchange"]),
    ("Code and configuration", [
        "code_or_config_context", "source_code_excerpt", "conflicting_revision_diff",
        "deployment_manifest_excerpt", "adjacent_code_noise",
    ]),
    ("Identity / network context", ["identity_network_context"]),
    ("Claims and contradictions", ["claimed_compensating_controls", "contradictory_evidence", "ticket_comment_thread"]),
    ("Runtime telemetry (sampled, mixed request IDs)", ["mixed_service_logs", "distributed_trace_excerpt"]),
    ("Evidence quality", ["evidence_collection_warnings", "evidence_gaps"]),
]

# Fields whose content is a direct runtime observation of the target.
RUNTIME_FIELDS = frozenset({
    "observation", "validation_attempt", "raw_request", "raw_response", "raw_http_exchange",
    "mixed_service_logs", "distributed_trace_excerpt",
})
# Analyst narrative describing a test, as opposed to the captured traffic itself.
NARRATIVE_RUNTIME_FIELDS = frozenset({"observation", "validation_attempt"})
# Fields that only carry assertions by interested parties.
CLAIM_FIELDS = frozenset({"claimed_compensating_controls", "ticket_comment_thread"})
# Scanner labels and identifiers are shown to the model but are never evidence.
METADATA_FIELDS = frozenset(FIELD_ORDER[0][1] + FIELD_ORDER[1][1])


def quotable_fields(row: Dict[str, str]) -> List[str]:
    return [k for k in row if k not in HIDDEN_COLUMNS and k not in METADATA_FIELDS]


def render_packet(row: Dict[str, str]) -> str:
    known = {f for _, fields in FIELD_ORDER for f in fields}
    groups = FIELD_ORDER + [("Other fields", [f for f in row if f not in known and f not in HIDDEN_COLUMNS])]
    out = []
    for heading, fields in groups:
        block = [f"<field name=\"{f}\">\n{row[f]}\n</field>" for f in fields if f in row]
        if block:
            out.append(f"## {heading}\n" + "\n".join(block))
    return "\n\n".join(out)


def _parse_utc(value: str) -> Optional[dt.datetime]:
    try:
        return dt.datetime.strptime((value or "").strip(), "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def time_sort_key(row: Dict[str, str]) -> tuple:
    """Chronological processing order; rows without timestamps go last."""
    far = dt.datetime.max
    return (_parse_utc(row.get("first_observed_utc", "")) or far,
            _parse_utc(row.get("last_observed_utc", "")) or far, row.get("finding_id", ""))


def extract_facts(row: Dict[str, str]) -> Dict[str, object]:
    rid = row.get("request_id", "").strip()
    facts: Dict[str, object] = {"row_request_id": rid}

    src = re.search(r"revision=([0-9a-f]{6,40})", row.get("source_code_excerpt", ""))
    man = re.search(r"image-source-revision:\s*'?([0-9a-f]{6,40})", row.get("deployment_manifest_excerpt", ""))
    facts["source_attachment_revision"] = src.group(1) if src else None
    facts["manifest_image_source_revision"] = man.group(1) if man else None
    if src and man:
        facts["source_revision_matches_manifest"] = src.group(1) == man.group(1)
    digest = re.search(r"@sha256:([0-9a-f]{12})", row.get("deployment_manifest_excerpt", ""))
    facts["manifest_image_digest_prefix"] = digest.group(1) if digest else None
    collected = re.search(r"evidence-collected-at:\s*'?([0-9T:\-Z]+)", row.get("deployment_manifest_excerpt", ""))
    facts["manifest_collected_at"] = collected.group(1) if collected else None

    diff = row.get("conflicting_revision_diff", "")
    age = re.search(r"snapshot collected (\d+) days before runtime", diff)
    facts["source_snapshot_age_days"] = int(age.group(1)) if age else None
    owner_claim = re.search(r"owner states this revision deployed to (\w+)", diff)
    facts["owner_claimed_deploy_slot"] = owner_claim.group(1) if owner_claim else None
    facts["image_digest_absent_from_ticket"] = "image digest was not present" in diff

    thread = row.get("ticket_comment_thread", "")
    rb = re.search(r"candidate image differs from source attachment=(\w+)", thread)
    facts["release_bot_image_differs_from_source"] = (rb.group(1) == "true") if rb else None
    ret = re.search(r"log retention for this path is ([^;]+);", thread)
    facts["log_retention"] = ret.group(1).strip() if ret else None

    http = row.get("raw_http_exchange", "")
    xr = re.search(r"X-Request-ID:\s*(\S+)", http)
    facts["http_request_id_matches_row"] = (xr.group(1) == rid) if xr else None
    cw = re.search(r"# capture_warning=(\S+)", http)
    facts["http_capture_warning"] = cw.group(1) if cw else None
    xc = re.search(r"X-Cache:\s*(\S+)", http)
    facts["http_x_cache"] = xc.group(1) if xc else None

    log_events = []
    other_ids = set()
    for line in row.get("mixed_service_logs", "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("request_id") == rid:
            log_events.append({k: ev[k] for k in ("level", "msg", "service", "sampled", "route_rev") if k in ev})
        elif ev.get("request_id"):
            other_ids.add(ev["request_id"])
    facts["log_events_for_row_request_id"] = log_events
    facts["log_unrelated_request_ids"] = sorted(other_ids)

    spans = []
    for line in row.get("distributed_trace_excerpt", "").splitlines():
        m = re.search(r"span=(\S+).*?status=(\S+)\s+request_id=(\S+)", line)
        if m:
            spans.append({"span": m.group(1), "status": m.group(2),
                          "request_id": "ROW" if m.group(3) == rid else m.group(3)})
    facts["trace_spans"] = spans
    samp = re.search(r"trace_sampling=(\S+)", row.get("distributed_trace_excerpt", ""))
    facts["trace_sampling"] = samp.group(1) if samp else None

    facts["evidence_collection_warnings"] = row.get("evidence_collection_warnings", "")


    first, last = _parse_utc(row.get("first_observed_utc", "")), _parse_utc(row.get("last_observed_utc", ""))
    collected_at = _parse_utc(facts["manifest_collected_at"] or "")
    if first and last:
        facts["observation_window_days"] = round((last - first).total_seconds() / 86400, 1)
        if collected_at:
            if collected_at < first:
                facts["manifest_collected"] = f"{(first - collected_at).days} days BEFORE the finding was first observed"
            elif collected_at > last:
                facts["manifest_collected"] = f"{(collected_at - last).days} days AFTER the finding was last observed"
            else:
                facts["manifest_collected"] = "within the observation window"
    return facts


_ROUTING_SPANS = ("edge.receive", "policy.evaluate")
# The facts that make two rows of the same scenario evidentially equivalent.
# Scanner type and environment are deliberately excluded: the data shows the
# scanner varies independently of the evidence, and environment affects
# impact, not whether the vulnerability is real.
EVIDENCE_PROFILE_FACTS = ("http_x_cache", "http_capture_warning", "evidence_collection_warnings",
                          "release_bot_image_differs_from_source", "trace_sampling")


def scenario_key(r: Dict[str, str]) -> tuple:
    """Rows generated from the same scenario share title, observation and validation text."""
    return (r.get("finding_title", ""), r.get("observation", ""), r.get("validation_attempt", ""))


def _side_effect_spans(facts: Dict[str, object]) -> Tuple[str, ...]:
    """Spans other than edge routing, policy evaluation and the handler itself."""
    return tuple(sorted({s["span"] for s in facts.get("trace_spans", [])
                         if s["span"] not in _ROUTING_SPANS and not s["span"].endswith(".handler")}))


def dataset_context(rows: List[Dict[str, str]]) -> Dict[str, str]:
    """Cross-row observations computed over the whole input file. A property
    that every row shares, or that varies independently of the scenario,
    cannot distinguish one finding from another - but read row by row it looks
    like evidence. Each entry is emitted only if the data actually shows it."""
    ctx: Dict[str, str] = {}
    http_days, log_days = collections.Counter(), collections.Counter()
    for r in rows:
        d = re.search(r"<\s*Date:\s*(\d{4}-\d{2}-\d{2})", r.get("raw_http_exchange", ""))
        t = re.search(r'"ts":\s*"(\d{4}-\d{2}-\d{2})', r.get("mixed_service_logs", ""))
        if d and t:
            http_days[d.group(1)] += 1
            log_days[t.group(1)] += 1
    if len(rows) > 1 and len(http_days) == 1 and len(log_days) == 1 and sum(http_days.values()) == len(rows):
        (hd, _), (ld, _) = http_days.most_common(1)[0], log_days.most_common(1)[0]
        if hd != ld:
            ctx["capture_vs_log_date_offset"] = (
                f"All {len(rows)} findings have HTTP captures dated {hd} and service logs and traces dated {ld}.")
    spans_by_scenario: Dict[tuple, set] = {}
    size = collections.Counter()
    for r in rows:
        key = scenario_key(r)
        size[key] += 1
        spans_by_scenario.setdefault(key, set()).add(_side_effect_spans(extract_facts(r)))
    repeated = [k for k, n in size.items() if n > 1]
    multi = [k for k in repeated if len(spans_by_scenario[k]) > 1]
    if repeated and len(multi) / len(repeated) >= 0.5:
        ctx["generic_side_effect_spans"] = (
            f"In {len(multi)} of {len(repeated)} scenarios that occur more than once, findings with identical "
            "observation and validation text carry different generic downstream spans (e.g. db.query, "
            "queue.publish, cache.lookup, http.egress).")
    header_sets = collections.Counter(
        tuple(sorted(set(re.findall(r"^>\s*([A-Za-z-]+):", r.get("raw_http_exchange", ""), re.M)) - {"Authorization"}))
        for r in rows)
    with_auth = sum(1 for r in rows if re.search(r"(?im)^>.*\bauthorization:", r.get("raw_http_exchange", "")))
    common, n_common = header_sets.most_common(1)[0] if header_sets else ((), 0)
    if len(rows) > 1 and n_common / len(rows) >= 0.9:
        ctx["captured_request_headers"] = (
            f"{n_common} of {len(rows)} request captures list the same header set ({', '.join(common)}); "
            f"a credential header appears in {with_auth}.")
    scanners_by_scenario: Dict[tuple, set] = {}
    for r in rows:
        scanners_by_scenario.setdefault(scenario_key(r), set()).add(r.get("scanner_source", "").strip())
    mixed = [k for k in repeated if len(scanners_by_scenario[k]) > 1]
    if repeated and len(mixed) / len(repeated) >= 0.5:
        ctx["scanner_vs_scenario"] = (
            f"In {len(mixed)} of {len(repeated)} repeated scenarios, the same observed evidence was reported by "
            "different scanners.")

    # X-Cache on the capture: does it vary with the scenario, and does the trace show the origin handled it anyway?
    cache_by_scenario: Dict[tuple, set] = {}
    hits = handled = 0
    for r in rows:
        f = extract_facts(r)
        cache_by_scenario.setdefault(scenario_key(r), set()).add(f.get("http_x_cache"))
        if f.get("http_x_cache") == "HIT":
            hits += 1
            handled += any(sp["span"].endswith(".handler") and sp["request_id"] == "ROW"
                           for sp in f.get("trace_spans", []))
    varied = [k for k in repeated if len(cache_by_scenario[k]) > 1]
    if hits and repeated and len(varied) / len(repeated) >= 0.5 and handled / hits >= 0.75:
        ctx["capture_cache_header"] = (
            f"The X-Cache value on captures differs between findings with identical evidence in {len(varied)} of "
            f"{len(repeated)} repeated scenarios, and in {handled} of {hits} captures marked HIT the trace shows "
            "the origin handler processing that same request ID.")
    return ctx


def render_facts(facts: Dict[str, object]) -> str:
    return json.dumps(facts, indent=1)


_WS = re.compile(r"\s+")


def normalise(text: str) -> str:
    return _WS.sub(" ", (text or "")).strip().lower()


def locate_quote(row: Dict[str, str], quote: str) -> List[str]:
    """Return the evidence fields that contain `quote` (whitespace-normalised,
    case-insensitive). A quote must carry at least MIN_QUOTE_CHARS of content
    beyond the row's own identifiers: quoting a request ID proves nothing."""
    q = normalise(quote)
    content = q
    for ident in (row.get("request_id"), row.get("finding_id")):
        if ident:
            content = content.replace(normalise(ident), "")
    if len(content.strip(" :=-\"'")) < MIN_QUOTE_CHARS:
        return []
    return [f for f in quotable_fields(row) if q in normalise(row[f])]


# ============================================================================
# Prompts and output schemas
# ============================================================================
# Process (adapted from Assay's confirmation model):
#   * classifier  - first independent assessment
#   * verifier    - second independent assessment, blind to the first, framed
#                   adversarially (Assay's "re-test with a different sentinel":
#                   a finding that only one framing can support is not confirmed)
#   * adjudicator - only when the two disagree; sees both and the evidence
# Every role must cite verbatim evidence; the code then verifies each quote
# against the row (Assay's "mandatory evidence attachment").

_QUOTE = {
    "type": "object",
    "properties": {
        "field": {"type": "string", "description": "Column name the quote was copied from."},
        "quote": {"type": "string", "description": f"Exact verbatim substring of that field, {MIN_QUOTE_CHARS}-200 characters."},
        "supports": {"type": "string", "description": "What this quote proves or disproves, in one short clause."},
    },
    "required": ["field", "quote", "supports"],
    "additionalProperties": False,
}

_CHECK = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "description": "The check id exactly as listed in the category rubric."},
        "answer": {"type": "string", "enum": ["yes", "no", "unknown"],
                   "description": "yes = the packet shows the vulnerable condition; no = the packet shows it absent; "
                                  "unknown = the packet does not show either."},
        "field": {"type": "string", "description": "Column name the quote was copied from; empty when unknown."},
        "quote": {"type": "string", "description": f"Exact verbatim substring, {MIN_QUOTE_CHARS}-200 characters; "
                                                   "empty when the answer is unknown."},
    },
    "required": ["id", "answer", "field", "quote"],
    "additionalProperties": False,
}

ASSESSMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "checklist": {
            "type": "array",
            "description": "One entry per check in the category rubric, answered before the classification. "
                           "Empty only when the packet carries no rubric.",
            "items": _CHECK,
            "maxItems": 8,
        },
        "decisive_boundary": {
            "type": "string",
            "description": "The single security boundary or side effect whose observation decides this finding "
                           "(e.g. 'canary file outside export dir returned to caller').",
        },
        "boundary_observed": {
            "type": "boolean",
            "description": "True only if supplied evidence directly observes that boundary being crossed "
                           "(for Confirmed) or being enforced on the deployed path (for False Positive).",
        },
        "provenance": {
            "type": "string",
            "description": "Which revision/image each key piece of evidence describes and whether they can be "
                           "treated as one fact.",
        },
        "compensating_controls": {
            "type": "string",
            "description": "Each claimed control and whether evidence shows it exists AND covers this path.",
        },
        "classification": {"type": "string", "enum": list(CLASSIFICATIONS)},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "reasoning": {
            "type": "string",
            "description": "2-4 sentences, evidence-based, naming the decisive evidence and why alternatives fail.",
        },
        "evidence": {"type": "array", "items": _QUOTE, "minItems": 1, "maxItems": 8},
        "missing_evidence": {
            "type": "string",
            "description": "For Needs Review: the specific observation that would decide it. Otherwise empty.",
        },
        "report": {
            "type": "object",
            "description": "Required when classification is Confirmed; otherwise fill with empty strings.",
            "properties": {
                "client_title": {"type": "string"},
                "cvss_vector": {"type": "string", "description": "CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_"},
                "cvss_rationale": {"type": "string", "description": "One clause per metric choice, from evidence."},
                "business_impact": {"type": "string", "description": "Plain language for a non-technical executive."},
                "recommended_fix": {"type": "string"},
            },
            "required": ["client_title", "cvss_vector", "cvss_rationale", "business_impact", "recommended_fix"],
            "additionalProperties": False,
        },
    },
    "required": [
        "checklist", "decisive_boundary", "boundary_observed", "provenance", "compensating_controls", "classification",
        "confidence", "reasoning", "evidence", "missing_evidence", "report",
    ],
    "additionalProperties": False,
}

ADJUDICATION_SCHEMA = copy.deepcopy(ASSESSMENT_SCHEMA)
ADJUDICATION_SCHEMA["properties"]["adjudication_note"] = {
    "type": "string",
    "description": "Which assessor's argument failed and the specific evidence that breaks it.",
}
ADJUDICATION_SCHEMA["required"].append("adjudication_note")


# ---------------------------------------------------------------------------
# Category rubrics and guided checklists
# ---------------------------------------------------------------------------
# Adapted from ZeroFalse (per-CWE micro-rubrics: what the vulnerable pattern needs, and which safe-looking or
# dangerous-looking idioms are often mistaken for the opposite) and Vulnhalla / VulnHunterX (evidence-anchored
# yes/no questions answered before the verdict). A rubric tells the model what KIND of observation counts for this
# category. It never says how a particular finding should be decided. Each check is phrased so that "yes" means the
# vulnerable condition is shown; the checklist gate in apply_gates uses that to hold Confirmed and False Positive
# to the same quoted evidence the model was asked to look for.
RUBRICS: Dict[str, Dict[str, object]] = {
    "Injection": {
        "boundary": "Attacker-controlled text becomes part of the query or command text that the service executes.",
        "lookalikes": "Percent or question-mark placeholders, and driver-level parameter binding, are not injection. "
                      "String formatting that builds the statement text is. A template engine is not a shell until "
                      "its output reaches a process-execution call.",
        "checks": [
            ("input_in_statement", "Does attacker-controlled input become part of the statement or command text, "
                                   "rather than a bound parameter?"),
            ("effect_observed", "Does a capture, log or trace show the executed text or its result changed by the input?"),
            ("no_binding_on_path", "Is there no sign of parameter binding, escaping or an allowlist on the running path?"),
        ],
    },
    "Authorization": {
        "boundary": "A caller reads or changes something that belongs to another tenant, organisation or role.",
        "lookalikes": "Hiding a parameter in the UI is not a control. A claimed downstream ownership check counts only "
                      "when code, config or a test shows it runs on this path.",
        "checks": [
            ("cross_boundary_caller", "Was the request made by a principal from a different tenant, organisation or role "
                                      "than the data or action it touched?"),
            ("foreign_result", "Did the response or side effect belong to the other tenant, organisation or role?"),
            ("no_check_on_path", "Is no ownership or tenant check shown running before the operation on the deployed path?"),
        ],
    },
    "Authentication": {
        "boundary": "The service accepts a credential it should reject, or reveals which identities exist.",
        "lookalikes": "A token that decodes is not a token that was verified. Identical status codes with different "
                      "bodies or timing can still enumerate users; a generic message with identical behaviour cannot.",
        "checks": [
            ("bad_credential_or_probe", "Was a forged, unsigned, expired or absent credential, or a probe with a known "
                                        "and an unknown identity, actually sent?"),
            ("accepted_or_distinguishable", "Did the service grant access, or answer the two probes in an observably "
                                            "different way?"),
            ("no_check_on_path", "Is no signature check, uniform response or rate control shown on the deployed path?"),
        ],
    },
    "Path Traversal": {
        "boundary": "A file name or path supplied by the caller reaches a file operation outside the intended directory.",
        "lookalikes": "Rejecting '..' only on the raw string is weaker than resolving the path and comparing it to the "
                      "base directory. A canary file outside the base directory that was read or written is direct proof.",
        "checks": [
            ("traversal_input_sent", "Was a name or path with traversal segments or an absolute path sent?"),
            ("outside_base_reached", "Does the evidence show a file outside the intended directory read or written?"),
            ("no_resolution_check", "Is no path resolution against the base directory shown on the running path?"),
        ],
    },
    "File Upload": {
        "boundary": "Names inside an uploaded archive or file decide where the service writes on disk.",
        "lookalikes": "Extraction that resolves each member path and checks it stays under the target directory is safe. "
                      "Checking only the archive's own name is not.",
        "checks": [
            ("hostile_member_sent", "Did the test upload an archive or file whose member names escape the target?"),
            ("outside_write_observed", "Does the evidence show a file written outside the upload directory?"),
            ("no_member_check", "Is no per-member path check shown on the running path?"),
        ],
    },
    "Browser Security": {
        "boundary": "A web page from an untrusted origin can read credentialed responses from this service.",
        "lookalikes": "A wildcard origin without credentials, an allowlist of known origins, and public non-sensitive "
                      "responses are not a credentialed cross-origin read.",
        "checks": [
            ("untrusted_origin_reflected", "Does the response allow an attacker-chosen Origin that the test supplied?"),
            ("credentials_allowed", "Does the same response allow credentials?"),
            ("sensitive_response", "Does the credentialed response carry data or state an attacker would want?"),
        ],
    },
    "OAuth": {
        "boundary": "The authorisation flow sends a code or token to a location the attacker chose.",
        "lookalikes": "Exact-match registered redirect URIs are safe. Prefix, substring or host-only matching is not. "
                      "A redirect that was only built, but not issued, shows intent rather than effect.",
        "checks": [
            ("attacker_redirect_sent", "Was an unregistered or attacker-controlled redirect target sent?"),
            ("redirect_issued", "Does the evidence show the service issuing a redirect to that target with a code or token?"),
            ("no_exact_match", "Is no exact-match check against registered redirect URIs shown on the path?"),
        ],
    },
    "Code Execution": {
        "boundary": "Caller-supplied text is evaluated as code in the service process.",
        "lookalikes": "Literal-only parsers such as ast.literal_eval or JSON parsing do not execute input. An eval-family "
                      "call on a constant or on a value the caller cannot influence is not exploitable.",
        "checks": [
            ("input_reaches_eval", "Does caller input reach an eval-family or equivalent call?"),
            ("execution_observed", "Does the evidence show the input being executed (output, side effect, changed result)?"),
            ("no_sandbox", "Is no sandbox, allowlist or literal-only parsing shown on the running path?"),
        ],
    },
    "Secret Detection": {
        "boundary": "A working credential is readable by someone who should not have it.",
        "lookalikes": "Test-mode keys, documented example values, placeholders and keys that are public by design "
                      "(publishable keys) are not live secrets. A matching format alone proves nothing.",
        "checks": [
            ("value_is_live", "Does the evidence show the value is a live credential, not a test, example or "
                              "public-by-design key?"),
            ("client_accessible", "Is the value in something a client or unauthenticated user can obtain?"),
            ("accepted_by_provider", "Does the evidence show the credential being accepted, or not revoked?"),
        ],
    },
    "Cryptography": {
        "boundary": "A weak primitive protects a value whose secrecy or integrity an attacker benefits from breaking.",
        "lookalikes": "MD5 for cache keys, ETags or file checksums is not a vulnerability. MD5 for passwords, tokens or "
                      "signatures is. A weak hash wrapped in HMAC or a slow password hash is a different question.",
        "checks": [
            ("security_sensitive_use", "Is the primitive used on a password, token, signature or other security-sensitive value?"),
            ("attacker_gains", "Does the evidence show how an attacker could gain from the weakness "
                               "(stored values, attacker-controlled input, comparison oracle)?"),
            ("no_stronger_wrapper", "Is no stronger construction shown protecting the same value on the path?"),
        ],
    },
    "Server-Side Request Forgery": {
        "boundary": "The service makes a request, on the caller's behalf, to a destination the caller should not reach.",
        "lookalikes": "Storing a URL is not fetching it. A fetch that is validated against an allowlist after DNS "
                      "resolution is a control. Reaching only public hosts is not an internal-service boundary.",
        "checks": [
            ("internal_target_sent", "Was an internal, loopback or metadata address supplied?"),
            ("request_made", "Does the evidence show the service making the request, or returning its result?"),
            ("no_egress_control", "Is no allowlist, post-resolution check or egress block shown on the path?"),
        ],
    },
    "Information Exposure": {
        "boundary": "A caller who should not see internal detail receives it, or gains an interactive debug surface.",
        "lookalikes": "A generic error page is not exposure. Stack traces with paths, configuration values, or an "
                      "interactive console reachable without credentials are.",
        "checks": [
            ("detail_returned", "Does a captured response contain internal detail or a debug console?"),
            ("detail_sensitive", "Is that detail something an attacker can use (paths, secrets, interactive access)?"),
            ("reachable_by_low_privilege", "Was it reached without privileged credentials, on the assessed environment?"),
        ],
    },
    "Account Recovery": {
        "boundary": "A reset token can be guessed, reused or applied to an account the caller does not control.",
        "lookalikes": "A token that looks short is not predictable unless the evidence shows the pattern or a second "
                      "use. Expiry and single-use enforcement are the controls to look for.",
        "checks": [
            ("token_weakness_shown", "Does the evidence show a predictable pattern, or the same token used twice?"),
            ("takeover_effect", "Did the weakness lead to a password change or account access?"),
            ("no_expiry_or_single_use", "Is no expiry or single-use enforcement shown on the path?"),
        ],
    },
    "Concurrency": {
        "boundary": "Parallel requests get past a limit that serial requests respect.",
        "lookalikes": "A lock, transaction, atomic counter or unique constraint on the same record is a control. "
                      "Many requests that were all rejected prove the limit held.",
        "checks": [
            ("parallel_requests_sent", "Were requests sent in parallel against the same limit?"),
            ("over_limit_succeeded", "Does the evidence show more successes than the limit allows?"),
            ("no_atomic_enforcement", "Is no atomic enforcement shown on the path?"),
        ],
    },
}


def rubric_for(category: str) -> Optional[Dict[str, object]]:
    return RUBRICS.get((category or "").strip())


def render_rubric(category: str) -> str:
    r = rubric_for(category)
    if not r:
        return ""
    checks = "\n".join(f"- {cid}: {text}" for cid, text in r["checks"])
    return (f"Decisive boundary for this category: {r['boundary']}\n"
            f"Look-alikes that are often mistaken for the opposite: {r['lookalikes']}\n"
            f"Checklist (answer every id, in the `checklist` field, before you classify):\n{checks}")


_COMMON_RULES_TEMPLATE = """
# Ground rules (non-negotiable)
- All targets and evidence are synthetic. Use ONLY facts present in the evidence packet. Never add facts.
- Scanner severity, confidence, rule names and titles are unreliable labels, not evidence.
- A compensating-control claim (from an owner, a ticket, or the claimed_compensating_controls field) is NOT proof
  that the control exists or covers the relevant path. It counts only if code, config, trace, or a runtime test in
  the packet independently demonstrates it on the relevant path.
- "UI does not expose this parameter" is never a control; UI reachability is not server-side authorization.
- Logs are sampled and mixed with unrelated request IDs. Absence of a log line or span is NOT evidence that an action
  did not happen. Only events carrying the finding's own request_id belong to this test.
- Source attachments, deployment manifests, owner comments and runtime observations may describe DIFFERENT
  revisions. Resolve provenance before combining them:
    * A runtime observation against the asset (HTTP exchange, validation attempt, trace with the row's request_id)
      describes what is actually running, whatever any attachment says.
    * A source excerpt only describes the running service if its revision is tied to the deployed image. If the
      release bot says the candidate image differs from the source attachment, or the snapshot is stale, or the
      revision does not match the manifest, source-only reasoning (in EITHER direction) is weak.
    * An owner statement that a revision is deployed is a claim, not attestation.
- Lines marked as adjacent / unrelated / noise, and diff hunks unrelated to the scanner's code path, are distractors.
- Evidence-collection warnings (truncated body, unavailable attachment, unattested source, proxy-rewritten headers)
  matter only when the decisive evidence depends on the affected artefact. Say so when they do.
- A manifest's image-source-revision annotation is a label, not attestation; the deployed image is identified by its
  digest. Never call a revision hash "the deployed image".
- An artefact that was not supplied (network policy, RLS definition, worker code) is unknown, not absent. Do not
  state that a control does not exist unless the evidence says so.
- Time matters for provenance: if the deployment manifest was collected before the finding was first observed or
  after it was last observed (facts: manifest_collected), it may not describe the image that was running when the
  evidence was captured.
- dataset_context (in the facts block) reports counts that code observed across the whole input file. It states
  what the data shows, not what it means. When an entry is present, apply these method rules:
  (1) A property shared by every finding, or one that differs between findings with identical evidence, cannot
  tell this finding from any other. Do not cite it as a reason for your classification in either direction.
  (2) Where captures list a fixed header set, a missing credential header is not evidence that no credential was
  needed. Choose CVSS PR from what the evidence says the test required (for example a valid tenant token, a
  dispatcher role, a public login form).
  (3) A generic downstream span (db.query, queue.publish, cache.lookup, http.egress) counts only when the packet
  ties it to the sensitive operation itself, for example a span or log that names the provider dispatch, file
  read or tenant record.
  (4) The scanner that raised a finding is not evidence, and nothing in the data says what analysis a scanner
  performed. Do not reason from a scanner's name or assumed tool type.
  (5) The X-Cache value matters only when the observation or validation text itself makes caching part of the
  finding (for example CDN cache keys, or responses that differ by cache state).
- Distinguish authentication (who you are), authorization (what you may touch), exploitability (can the boundary
  actually be crossed on the deployed path) and impact (what crossing it yields).

# Classification standard
- Confirmed: the packet directly observes the vulnerable behaviour or its security-relevant effect on the assessed
  target (e.g. data from another tenant returned, canary outside a boundary read, side effect executed, forged token
  accepted), provenance does not undermine that observation, and no demonstrated control blocks the path. A plausible
  code smell alone is never Confirmed.
- False Positive: the packet affirmatively demonstrates the vulnerable condition is absent or unreachable on the
  deployed path (e.g. runtime rejection before the sensitive operation, parameter binding proven on the running
  revision, the flagged value is non-sensitive by design). An owner's word or the absence of logs is not enough.
- Needs Review: the decisive boundary is not observable, evidence is inconclusive or contradictory in a way the
  packet cannot resolve, or the case rests on an unverified claim. This is the correct, professional answer when
  evidence is insufficient - do not force a confident answer either way.

# Confidence calibration
- 0.85-0.97: decisive runtime observation, provenance consistent, no unresolved contradiction.
- 0.65-0.85: strong evidence with a minor residual gap that cannot change the outcome.
- 0.40-0.65: use mainly for Needs Review - how sure you are that the evidence is genuinely insufficient.
- Never exceed 0.97. If you would rate a Confirmed or False Positive below {min_conf}, it is Needs Review.

# Category checklist
- When the message includes a category rubric, answer every check in `checklist` BEFORE you classify. "yes" means
  the packet itself shows the vulnerable condition, "no" means the packet itself shows it absent, "unknown" means
  the packet shows neither. Support every yes and every no with a verbatim quote from the packet; leave field and
  quote empty for unknown. Never answer yes from the scanner title or a claim.
- The rubric describes what kind of observation counts. It is not evidence and it does not decide the finding.
  Confirmed needs every check answered yes with a quote. False Positive needs at least one check answered no with
  a quote that shows the condition absent on the deployed path.

# Evidence citations
- Provide {min_cites}-6 citations. Each `quote` must be copied EXACTLY (verbatim substring, {min_chars}-200 chars) from
  the named field. Citations are machine-verified against the packet; fabricated or paraphrased quotes cause automatic
  downgrade. Scanner labels and identifiers ({metadata}) are not evidence and do not count;
  a quote must say something beyond the request ID.
- For Confirmed, at least one citation must come from a runtime field ({runtime}).
- For False Positive, at least one citation must come from something other than claims/ticket comments, and if the
  release bot reports that the image differs from the source attachment, at least one must come from a runtime field.

# Writing style (applies to every sentence you write, including reasoning)
- Write like an experienced penetration tester writing for the client: plain, direct, specific. Past tense for what
  was tested ("the test sent", "the service returned"). Short sentences. One idea per sentence.
- Describe evidence by what it is: "the captured response", "the validation test", "the service logs", "the trace",
  "the deployment manifest", "the source excerpt", "the ticket thread", "the owner". Never use internal labels:
  no "packet", "row", "field", "facts block", "dataset_context", "assessor", "hypothesis", "schema", and no
  underscore_names such as request_id or validation_attempt (write "request ID", "validation test").
- Do not use em dashes or en dashes. Do not use: notably, importantly, crucially, it is worth noting, overall,
  in summary, ultimately, delve, robust, leverage, comprehensive, seamless, underscores, highlights, landscape,
  "not just X but Y", "this is not X, it is Y", rhetorical questions, or a closing sentence that restates the verdict.
- No filler and no hedging stacks. Say what was shown, what was not, and why that decides it.
- Never mention yourself, a model, AI, instructions, or these rules.

# Client report fields (only for Confirmed; otherwise empty strings)
- cvss_vector: CVSS 3.1 base vector for THIS asset and environment. CVSS rates the vulnerability, not the tester's
  restraint: score C/I/A for what the DEMONSTRATED primitive gives an attacker (e.g. attacker input executed by a
  code-evaluating function is code execution in that process, even if the test only ran a harmless probe; a forged
  token accepted as admin grants that role's access even if the test only read a summary). Lower C/I/A only when the
  packet shows an actual limit on the primitive (sandboxing, an allowlist, read-only access, a narrow data scope).
  Do not score impact the packet gives no basis for. Pick AV/PR/UI from what the test actually required; pick S:C
  only when the impact lands outside the vulnerable component's security authority. The demonstrated-vs-reachable
  distinction belongs in business_impact, not in a lowered vector.
- business_impact: 2-3 plain-language sentences for an executive at a fleet-management company: who could do what,
  to whose data or vehicles, and why it matters. No jargon. Separate what was DEMONSTRATED from what the packet shows
  is REACHABLE (e.g. "the test read a planted canary file; the same access reaches customer exports stored on that
  host"). Never claim access to data or systems the packet does not mention.
- recommended_fix: concrete, specific to the code/config shown; primary fix first, then defence in depth; include
  how to verify the fix.
""".format(
    min_conf=MIN_DECISIVE_CONFIDENCE, min_cites=MIN_CITATIONS_CONFIRMED, min_chars=MIN_QUOTE_CHARS,
    metadata=", ".join(sorted(METADATA_FIELDS)), runtime=", ".join(sorted(RUNTIME_FIELDS)))
_COMMON_RULES = _COMMON_RULES_TEMPLATE

CLASSIFIER_SYSTEM = (
    "You are a senior application-security adjudicator triaging one raw scanner finding for the client. "
    "Your job is to decide what the evidence actually proves.\n"
    "Work in this order: (1) state the decisive boundary for this finding type; (2) list which evidence observes that "
    "boundary and which revision/image it describes; (3) test each claimed control against evidence; (4) classify.\n"
    + _COMMON_RULES
)

VERIFIER_SYSTEM = (
    "You are an independent, sceptical second assessor re-testing a scanner finding for the client. "
    "Another assessor has already looked at it; you do not see their answer. Assume they "
    "may have been fooled in EITHER direction: by a dramatic-looking but unproven exploit narrative, or by reassuring "
    "owner claims and absent logs.\n"
    "Before classifying, actively try to refute both hypotheses: build the strongest case that it is real and the "
    "strongest case that it is a false positive, and see which survives contact with the runtime evidence and the "
    "provenance facts. If neither survives cleanly, the answer is Needs Review.\n"
    + _COMMON_RULES
)

ADJUDICATOR_SYSTEM = (
    "You are the final adjudicator for a security finding on which two independent assessors disagreed. "
    "You are given the evidence packet, deterministic provenance facts, and both assessments. Do not average them "
    "and do not defer to the more confident one. Re-read the evidence, identify the exact point of disagreement, and "
    "determine which reading the packet actually supports. When the disagreement is itself caused by a boundary the "
    "packet cannot observe, the correct answer is Needs Review. Explain in adjudication_note which argument failed "
    "and on what evidence.\n"
    + _COMMON_RULES
)


def _rubric_block(rubric: str) -> str:
    return f"<category_rubric>\n{rubric}\n</category_rubric>\n\n" if rubric else ""


def user_message(packet: str, facts: str, rubric: str = "") -> str:
    return (
        "Classify the following finding. The deterministic facts block was extracted by code from the same packet "
        "(revision identifiers, request-ID correlation, sampling); it restates the packet and adds nothing new. "
        "Its dataset_context entry, if present, was computed by code across ALL findings in the input file.\n\n"
        f"<deterministic_facts>\n{facts}\n</deterministic_facts>\n\n"
        f"{_rubric_block(rubric)}"
        f"<evidence_packet>\n{packet}\n</evidence_packet>\n\n"
        "Return only the JSON object required by the schema."
    )


def adjudication_message(packet: str, facts: str, first: dict, second: dict, rubric: str = "") -> str:
    def strip(a: dict) -> dict:
        return {k: a.get(k) for k in (
            "classification", "confidence", "checklist", "decisive_boundary", "boundary_observed", "provenance",
            "compensating_controls", "reasoning", "evidence", "missing_evidence",
        )} | ({"cvss_vector": a.get("report", {}).get("cvss_vector")} if a.get("classification") == "Confirmed" else {})
    return (
        "Two independent assessors disagreed on this finding.\n\n"
        f"<assessor_A>\n{json.dumps(strip(first), indent=1)}\n</assessor_A>\n\n"
        f"<assessor_B>\n{json.dumps(strip(second), indent=1)}\n</assessor_B>\n\n"
        f"<deterministic_facts>\n{facts}\n</deterministic_facts>\n\n"
        f"{_rubric_block(rubric)}"
        f"<evidence_packet>\n{packet}\n</evidence_packet>\n\n"
        "Return only the JSON object required by the schema."
    )


# ============================================================================
# Claude Code CLI backend
# ============================================================================
# Headless, following Assay's claude-cli pattern:
# prompt over stdin, isolated empty working directory, no tools, no MCP, no
# session persistence, JSON envelope with structured output. Unlike Assay, the
# returned object is validated against the schema before it is accepted.
class LLMError(Exception):
    pass


@dataclass
class CallStats:
    calls: int = 0
    cache_hits: int = 0
    failures: int = 0
    cost_usd: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, **kw):
        with self.lock:
            for k, v in kw.items():
                setattr(self, k, getattr(self, k) + v)


def validate(obj, schema, path="$") -> List[str]:
    """Minimal JSON-schema validator for the subset used in the schemas below."""
    errs: List[str] = []
    t = schema.get("type")
    if t == "object":
        if not isinstance(obj, dict):
            return [f"{path}: expected object"]
        for k in schema.get("required", []):
            if k not in obj:
                errs.append(f"{path}.{k}: missing")
        props = schema.get("properties", {})
        for k, sub in props.items():
            if k in obj:
                errs += validate(obj[k], sub, f"{path}.{k}")
        if schema.get("additionalProperties") is False:
            errs += [f"{path}.{k}: unexpected property" for k in obj if k not in props]
    elif t == "array":
        if not isinstance(obj, list):
            return [f"{path}: expected array"]
        if len(obj) < schema.get("minItems", 0):
            errs.append(f"{path}: fewer than {schema['minItems']} items")
        if len(obj) > schema.get("maxItems", len(obj)):
            errs.append(f"{path}: more than {schema['maxItems']} items")
        for i, item in enumerate(obj):
            errs += validate(item, schema.get("items", {}), f"{path}[{i}]")
    elif t == "string":
        if not isinstance(obj, str):
            errs.append(f"{path}: expected string")
        elif "enum" in schema and obj not in schema["enum"]:
            errs.append(f"{path}: {obj!r} not in {schema['enum']}")
    elif t == "number":
        if isinstance(obj, bool) or not isinstance(obj, (int, float)):
            errs.append(f"{path}: expected number")
        elif not (schema.get("minimum", float("-inf")) <= obj <= schema.get("maximum", float("inf"))):
            errs.append(f"{path}: {obj} out of range")
    elif t == "boolean":
        if not isinstance(obj, bool):
            errs.append(f"{path}: expected boolean")
    return errs


def _extract_json(text: str):
    text = (text or "").strip()
    try:
        return json.loads(text)
    except ValueError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except ValueError:
            pass
    raise LLMError("model output is not JSON")


class ModelDenied(LLMError):
    """The model refused the request permanently (unknown model, no access,
    permission denied). Retrying the same model is pointless."""


# A denial must be about the model itself. Generic words ("permission denied" on a
# local file, "temporarily unavailable", HTTP 400 for an over-long prompt) are
# transient or per-request failures and must never disable a model for the run.
_DENIED_RE = re.compile(r"not_found_error|permission_error|"
                        r"model[^.\n]{0,80}(?:not found|does not exist|not available to|no access|not supported)|"
                        r"(?:invalid|unknown|unsupported) model", re.I)
_DENIED_STATUS = {403, 404}


class ClaudeCLI:
    """`models` is an ordered fallback chain, e.g. ["claude-opus-5-5", "claude-opus-4-8"].
    Per call: try each model in order. A permanent denial moves straight to the
    next model and disables the denied one for the rest of the run; transient
    failures (timeouts, unparsable or schema-invalid output) are retried with
    backoff before falling back. The model that actually answered is recorded
    on the output as `_model`."""

    def __init__(self, models, effort: Optional[str] = "high", binary: str = "claude",
                 timeout: int = 420, retries: int = 3, cache_dir: Optional[Path] = None,
                 stats: Optional[CallStats] = None):
        self.models = [models] if isinstance(models, str) else list(models)
        if not self.models:
            raise ValueError("at least one model required")
        self.effort = effort
        self.binary = shutil.which(binary) or binary
        self.timeout = timeout
        self.retries = retries
        self.cache_dir = cache_dir
        self.stats = stats or CallStats()
        self.disabled: Dict[str, str] = {}
        self.used: collections.Counter = collections.Counter()
        self._lock = threading.Lock()

    @property
    def model(self) -> str:
        return " -> ".join(self.models)

    def check_available(self) -> None:
        if not shutil.which(self.binary):
            raise LLMError(f"claude CLI not found ({self.binary}); install Claude Code or pass --claude-bin")

    def _argv(self, model: str, system: str, schema: dict) -> List[str]:
        argv = [self.binary, "--print", "--model", model]
        if self.effort:
            argv += ["--effort", self.effort]
        argv += [
            "--output-format", "json",
            "--json-schema", json.dumps(schema),
            "--system-prompt", system,
            "--restricted", "--tools", "", "--strict-mcp-config",
            "--disable-slash-commands", "--setting-sources", "",
            "--no-session-persistence",
        ]
        return argv

    def _cache_path(self, stage: str, key: str) -> Optional[Path]:
        if not self.cache_dir:
            return None
        return self.cache_dir / stage / f"{key}.json"

    def cache_key(self, model: str, system: str, schema: dict, message: str) -> str:
        h = hashlib.sha256()
        for part in (model, str(self.effort), system, json.dumps(schema, sort_keys=True), message):
            h.update(part.encode())
            h.update(b"\x00")
        return h.hexdigest()[:32]

    def complete(self, stage: str, system: str, schema: dict, message: str) -> dict:
        # A cached answer from any model in the chain (preferred order) is reused.
        for model in self.models:
            cp = self._cache_path(stage, self.cache_key(model, system, schema, message))
            if cp and cp.exists():
                try:
                    cached = json.loads(cp.read_text(encoding="utf-8"))
                    if not validate(cached["output"], schema):
                        self.stats.add(cache_hits=1)
                        return self._answered(model, cached["output"])
                except (ValueError, KeyError, TypeError):
                    pass
        errors: List[str] = []
        for model in self.models:
            with self._lock:
                if model in self.disabled:
                    errors.append(f"{model}: disabled earlier ({self.disabled[model]})")
                    continue
            try:
                out = self._complete_with(model, stage, system, schema, message)
            except ModelDenied as exc:
                with self._lock:
                    if model not in self.disabled:
                        self.disabled[model] = str(exc)[:200]
                        print(f"[fallback] {model} denied ({str(exc)[:160]}); using next model for the rest of the run",
                              file=sys.stderr)
                errors.append(f"{model}: {exc}")
                continue
            except LLMError as exc:
                if model != self.models[-1]:
                    print(f"[fallback] {stage}: {model} failed ({str(exc)[:160]}); trying next model", file=sys.stderr)
                errors.append(f"{model}: {exc}")
                continue
            return self._answered(model, out)
        self.stats.add(failures=1)
        raise LLMError(f"{stage}: all models failed: " + " | ".join(errors))

    def _answered(self, model: str, out: dict) -> dict:
        with self._lock:
            self.used[model] += 1
        return {**out, "_model": model}

    def _complete_with(self, model: str, stage: str, system: str, schema: dict, message: str) -> dict:
        cp = self._cache_path(stage, self.cache_key(model, system, schema, message))
        last: Exception = LLMError("no attempt made")
        for attempt in range(1, self.retries + 1):
            try:
                out, cost = self._call_once(model, system, schema, message)
                self.stats.add(cost_usd=cost)
                errs = validate(out, schema)
                if errs:
                    raise LLMError("schema violation: " + "; ".join(errs[:5]))
                self.stats.add(calls=1)
                if cp:
                    cp.parent.mkdir(parents=True, exist_ok=True)
                    tmp = cp.with_suffix(".tmp")
                    tmp.write_text(json.dumps({"model": model, "stage": stage, "cost_usd": cost,
                                               "output": out}, indent=1), encoding="utf-8")
                    tmp.replace(cp)
                return out
            except ModelDenied:
                self.stats.add(calls=1)
                raise
            except (LLMError, subprocess.TimeoutExpired, OSError) as exc:
                last = exc
                self.stats.add(calls=1)
                if attempt < self.retries:
                    time.sleep(min(60, 5 * 2 ** (attempt - 1)))
        raise LLMError(f"failed after {self.retries} attempts: {last}")

    def _call_once(self, model: str, system: str, schema: dict, message: str):
        with tempfile.TemporaryDirectory(prefix="triage-") as sandbox:
            proc = subprocess.run(
                self._argv(model, system, schema), input=message, capture_output=True, text=True,
                timeout=self.timeout, cwd=sandbox,
            )
        if not proc.stdout.strip():
            msg = proc.stderr.strip()[:300]
            if _DENIED_RE.search(msg):
                raise ModelDenied(f"exit {proc.returncode}: {msg}")
            raise LLMError(f"empty CLI output (exit {proc.returncode}): {msg}")
        try:
            env = json.loads(proc.stdout)
        except ValueError:
            raise LLMError(f"CLI did not return a JSON envelope: {proc.stdout[:300]}")
        if not isinstance(env, dict):
            raise LLMError(f"CLI envelope is not an object: {proc.stdout[:300]}")
        if env.get("is_error"):
            msg = str(env.get("result"))[:300]
            if env.get("api_error_status") in _DENIED_STATUS or _DENIED_RE.search(msg):
                raise ModelDenied(f"status {env.get('api_error_status')}: {msg}")
            raise LLMError(f"CLI error (status {env.get('api_error_status')}): {msg}")
        try:
            cost = float(env.get("total_cost_usd") or 0.0)
        except (TypeError, ValueError):
            cost = 0.0
        usage = env.get("modelUsage") if isinstance(env.get("modelUsage"), dict) else {}
        served = [m for m, u in usage.items() if isinstance(u, dict) and u.get("outputTokens")]
        if served and not any(model in m or m in model for m in served):
            raise LLMError(f"requested {model} but CLI served {served}")
        out = env.get("structured_output")
        if out is None:
            out = _extract_json(str(env.get("result", "")))
        if not isinstance(out, dict):
            raise LLMError("structured output is not an object")
        return out, cost


class FakeLLM:
    """Test double: `responder(stage, message) -> dict` or raise."""

    def __init__(self, responder: Callable[[str, str], dict]):
        self.responder = responder
        self.stats = CallStats()
        self.model = "fake"

    def check_available(self) -> None:
        pass

    def complete(self, stage: str, system: str, schema: dict, message: str) -> dict:
        self.stats.add(calls=1)
        out = self.responder(stage, message)
        errs = validate(out, schema)
        if errs:
            raise LLMError("schema violation: " + "; ".join(errs))
        return out


# ============================================================================
# Deterministic evidence gates
# ============================================================================
# Applied after the model has spoken. These are the guarantee that missing, fabricated or claim-only evidence never
# silently becomes Confirmed (or a confident False Positive): a gate can only
# move a verdict TOWARDS Needs Review, never away from it.
def verify_citations(row: Dict[str, str], citations: List[dict]) -> Tuple[List[dict], List[dict]]:
    verified, rejected = [], []
    for c in citations or []:
        fields = locate_quote(row, c.get("quote", ""))
        if fields:
            claimed = c.get("field")
            located = claimed if claimed in fields else fields[0]
            verified.append({**c, "field": located, "located_in": fields})
        else:
            rejected.append(c)
    return verified, rejected


def verify_checklist(row: Dict[str, str], checklist: List[dict]) -> List[dict]:
    """One entry per rubric check, in rubric order. An answer of yes or no only counts as `backed` when its quote
    is found verbatim in the row; a missing or repeated check id is treated as unknown."""
    rubric = rubric_for(row.get("category", ""))
    if not rubric:
        return []
    given: Dict[str, dict] = {}
    for c in checklist or []:
        given.setdefault(c.get("id"), c)
    out = []
    for cid, text in rubric["checks"]:
        c = given.get(cid) or {}
        answer = c.get("answer") if c.get("answer") in ("yes", "no") else "unknown"
        fields = locate_quote(row, c.get("quote", "")) if answer != "unknown" else []
        out.append({"id": cid, "check": text, "answer": answer, "quote": c.get("quote", "") if fields else "",
                    "field": (c.get("field") if c.get("field") in fields else fields[0]) if fields else "",
                    "backed": bool(fields)})
    return out


def merge_checklists(row: Dict[str, str], first: List[dict], second: List[dict]) -> List[dict]:
    """Two agreeing assessors: a check keeps its answer only when both gave it; otherwise it is unknown."""
    a = {c["id"]: c for c in verify_checklist(row, first)}
    b = {c["id"]: c for c in verify_checklist(row, second)}
    out = []
    for cid, ca in a.items():
        cb = b[cid]
        if ca["answer"] == cb["answer"] and ca["answer"] != "unknown":
            pick = ca if ca["backed"] else cb
            out.append({"id": cid, "answer": ca["answer"], "field": pick["field"], "quote": pick["quote"]})
        else:
            out.append({"id": cid, "answer": "unknown", "field": "", "quote": ""})
    return out


def checklist_reason(category: str, cls: str, checks: List[dict]) -> Optional[str]:
    """Why the guided checklist does not support `cls`, or None. Rows whose category has no rubric are not gated."""
    if not checks:
        return None
    if cls == "Confirmed":
        missing = [c for c in checks if not (c["answer"] == "yes" and c["backed"])]
        if missing:
            return (f"{len(missing)} of {len(checks)} checks for {category.lower()} findings have no quoted evidence "
                    f"showing the vulnerable condition")
    elif cls == "False Positive":
        if not any(c["answer"] == "no" and c["backed"] for c in checks):
            return f"no check for {category.lower()} findings has quoted evidence showing the condition is absent"
    return None


def apply_gates(row: Dict[str, str], assessment: dict, extra_citations: List[dict] = ()) -> dict:
    """Return a new dict with classification/confidence possibly downgraded and
    `gate_notes`, `gate_reasons`, `gated_from`, `verified_evidence`,
    `rejected_evidence` populated."""
    a = dict(assessment)
    verified, rejected = verify_citations(row, list(a.get("evidence", [])) + list(extra_citations))
    # Both assessors often cite the same text, or a fragment of a sentence the other cited in full.
    # Keep the longest form of each; order follows the first citation.
    texts = [normalise(v["quote"]) for v in verified]
    verified = [v for i, (v, t) in enumerate(zip(verified, texts))
                if not any((t in u and (t != u or j < i)) for j, u in enumerate(texts) if j != i)]
    notes: List[str] = []
    if rejected:
        notes.append(f"{len(rejected)} cited quote(s) not found verbatim in the row and were discarded")

    cls = a.get("classification")
    conf = float(a.get("confidence", 0.0))
    cited = {v["field"] for v in verified}
    has_runtime = bool(cited & RUNTIME_FIELDS)
    has_capture = bool(cited & (RUNTIME_FIELDS - NARRATIVE_RUNTIME_FIELDS))  # request, response, exchange, log or trace
    facts = extract_facts(row)
    reasons: List[str] = []

    if cls == "Confirmed":
        if not a.get("boundary_observed"):
            reasons.append("the evidence does not show the security boundary actually being crossed")
        if len(verified) < MIN_CITATIONS_CONFIRMED:
            reasons.append(f"too little of the cited evidence could be found in the source data "
                           f"({len(verified)} of the {MIN_CITATIONS_CONFIRMED} items required)")
        if not has_runtime:
            reasons.append("none of the supporting evidence comes from testing the running service")
        elif not has_capture:
            reasons.append("the supporting evidence is the analyst's description of the test, with no captured request, "
                           "response, log or trace behind it")
    elif cls == "False Positive":
        if not a.get("boundary_observed"):
            reasons.append("the evidence does not show the control actually blocking the attack")
        if not (cited - CLAIM_FIELDS):
            reasons.append("the case for dismissal rests only on owner or ticket statements")
        if (facts.get("release_bot_image_differs_from_source") or facts.get("source_revision_matches_manifest") is False) \
                and not has_runtime:
            reasons.append("the reviewed source is not shown to be the running revision, "
                           "and no test of the running service shows the control in place")
    elif cls != "Needs Review":
        reasons.append(f"unknown classification {cls!r}")
    checks = verify_checklist(row, a.get("checklist", []))
    why = checklist_reason(row.get("category", ""), cls, checks)
    if why:
        reasons.append(why)
    if cls in ("Confirmed", "False Positive") and conf < MIN_DECISIVE_CONFIDENCE:
        reasons.append("the evidence is not strong enough to decide it either way")

    if reasons:
        notes.append(f"downgraded {cls} -> Needs Review: " + "; ".join(reasons))
        a["gated_from"] = cls
        a["classification"] = "Needs Review"
        conf = min(conf, NEEDS_REVIEW_CONFIDENCE_CAP)
    a["confidence"] = round(max(0.0, min(1.0, conf)), 2)
    a["verified_checklist"] = checks
    a["verified_evidence"] = verified
    a["rejected_evidence"] = rejected
    a["gate_notes"] = notes
    a["gate_reasons"] = reasons
    return a


# ============================================================================
# Per-finding pipeline, prioritisation, audit
# ============================================================================
# classify -> verify (blind) -> adjudicate on disagreement -> deterministic
# gates -> priority.


def priority(score: Optional[float], environment: str):
    if score is None:
        return None, ""
    p = round(score * ENV_WEIGHT.get(environment.strip().lower(), DEFAULT_ENV_WEIGHT), 2)
    tier = "CHASE" if p >= TIER_CHASE else "LOOK" if p >= TIER_LOOK else "NOTE"
    return p, tier


def _cvss_of(a: dict):
    return score_vector((a.get("report") or {}).get("cvss_vector"))


def needs_adjudication(a: dict, b: dict) -> Optional[str]:
    if a["classification"] != b["classification"]:
        return f"classification: A={a['classification']} vs B={b['classification']}"
    if a["classification"] == "Confirmed":
        _, sa, _ = _cvss_of(a)
        _, sb, _ = _cvss_of(b)
        if sa is None or sb is None:
            return "Confirmed without a valid CVSS vector from both assessors"
        if abs(sa - sb) >= CVSS_DIVERGENCE:
            return f"CVSS divergence: A={sa} vs B={sb}"
    return None


_UNSCORED = {"cvss_vector": None, "cvss_score": None, "cvss_severity": None,
             "priority_score": None, "priority_tier": ""}


def _base_result(row: Dict[str, str]) -> Dict[str, object]:
    base = {k: row.get(k, "") for k in ("finding_id", "asset", "environment", "finding_title", "category",
                                        "asset_owner", "scanner_source", "first_observed_utc")}
    return base


def assess_row(row: Dict[str, str], llm, context: Optional[Dict[str, str]] = None) -> Dict[str, object]:
    packet = render_packet(row)
    facts_obj = extract_facts(row)
    facts = render_facts({**facts_obj, "dataset_context": context} if context else facts_obj)
    rubric = render_rubric(row.get("category", ""))
    msg = user_message(packet, facts, rubric)
    base = {**_base_result(row), "facts": facts_obj}
    try:
        a = llm.complete("classify", CLASSIFIER_SYSTEM, ASSESSMENT_SCHEMA, msg)
    except LLMError as exc:
        return _failed(base, str(exc))
    try:
        b = llm.complete("verify", VERIFIER_SYSTEM, ASSESSMENT_SCHEMA, msg)
    except LLMError as exc:
        return _failed(base, f"verifier failed: {exc}", A=a)

    reason = needs_adjudication(a, b)
    extra: List[dict] = []
    if reason is None:
        # Agreement: the assessment with more verifiable evidence is primary; both
        # assessors' citations are pooled for the gate. Confidence is the LOWER of
        # the two, and the boundary counts as observed only if both say so.
        n_verified = lambda x: len(verify_citations(row, x.get("evidence", []))[0])
        primary, other = (a, b) if n_verified(a) >= n_verified(b) else (b, a)
        if primary["classification"] == "Confirmed" and _cvss_of(primary)[0] is None:
            primary, other = other, primary
        final = dict(primary)
        final["confidence"] = min(float(a["confidence"]), float(b["confidence"]))
        final["boundary_observed"] = bool(a.get("boundary_observed")) and bool(b.get("boundary_observed"))
        final["checklist"] = merge_checklists(row, a.get("checklist", []), b.get("checklist", []))
        extra = other.get("evidence", [])
        agreement, adjudicated = f"agree ({a['classification']})", False
    else:
        try:
            c = llm.complete("adjudicate", ADJUDICATOR_SYSTEM, ADJUDICATION_SCHEMA,
                             adjudication_message(packet, facts, a, b, rubric))
        except LLMError as exc:
            return _failed(base, f"assessors disagreed ({reason}) and adjudication failed: {exc}", A=a, B=b)
        final = dict(c)
        final["confidence"] = min(float(c["confidence"]), ADJUDICATED_CONFIDENCE_CAP)
        agreement, adjudicated = f"adjudicated [{reason}] -> {c['classification']}", True

    gated = apply_gates(row, final, extra)
    notes = list(gated["gate_notes"])
    reasoning = gated.get("reasoning", "").strip()
    missing = gated.get("missing_evidence", "")
    if gated.get("gated_from"):
        # The CSV `reasoning` must explain the final class, so the gate outcome is stated there too.
        verdict = {"Confirmed": "confirm this finding", "False Positive": "close this finding"}.get(
            gated["gated_from"], "decide this finding")
        reasoning = (f"Not enough verifiable evidence to {verdict}: {'; '.join(gated['gate_reasons'])}. "
                     f"Analysis: {reasoning}")
        missing = missing or "Evidence that addresses the following: " + "; ".join(gated["gate_reasons"]) + "."

    out = dict(base)
    out.update({
        "classification": gated["classification"],
        "confidence": gated["confidence"],
        "reasoning": reasoning,
        "decisive_boundary": gated.get("decisive_boundary", ""),
        "boundary_observed": gated.get("boundary_observed"),
        "provenance": gated.get("provenance", ""),
        "compensating_controls": gated.get("compensating_controls", ""),
        "missing_evidence": missing,
        "checklist": gated["verified_checklist"],
        "evidence": gated["verified_evidence"],
        "rejected_evidence": gated["rejected_evidence"],
        "assessor_agreement": agreement,
        "adjudicated": adjudicated,
        "gated_from": gated.get("gated_from"),
        "error": None,
        "adjudication_note": gated.get("adjudication_note", ""),
        "assessments": {"A": a, "B": b, **({"adjudicator": c} if adjudicated else {})},
        "models_used": sorted({x["_model"] for x in (a, b, final) if x.get("_model")}),
        **_UNSCORED,
    })

    if out["classification"] == "Confirmed":
        rep = gated.get("report") or {}
        vec, score, sev = _cvss_of(gated)
        out.update({
            "client_title": rep.get("client_title") or row.get("finding_title", ""),
            "cvss_vector": vec, "cvss_score": score, "cvss_severity": sev,
            "cvss_rationale": rep.get("cvss_rationale", ""),
            "business_impact": rep.get("business_impact", ""),
            "recommended_fix": rep.get("recommended_fix", ""),
        })
        if vec is None:
            notes.append("CVSS vector invalid; finding unscored")
        out["priority_score"], out["priority_tier"] = priority(score, out["environment"])
    out["gate_notes"] = " | ".join(notes)
    return polish_result(out)


def _failed(base: dict, error: str, **assessments) -> Dict[str, object]:
    out = dict(base)
    out.update({
        "classification": "Needs Review",
        "confidence": 0.0,
        "reasoning": f"Automated assessment could not complete; routed to human review. ({error[:300]})",
        "decisive_boundary": "", "missing_evidence": "Automated assessment failed; manual review required.",
        "evidence": [], "rejected_evidence": [], "assessor_agreement": "error", "adjudicated": False,
        "gated_from": None, "gate_notes": "pipeline error -> Needs Review", "error": error,
        "assessments": assessments, **_UNSCORED,
    })
    return out


def run(rows: List[Dict[str, str]], llm, workers: int = 4,
        progress: Optional[Callable[[int, int, dict], None]] = None,
        context: Optional[Dict[str, str]] = None) -> List[Dict[str, object]]:
    results: Dict[str, dict] = {}
    pool = cf.ThreadPoolExecutor(max_workers=max(1, workers))
    try:
        futs = {pool.submit(assess_row, r, llm, context): r for r in rows}
        for done, fut in enumerate(cf.as_completed(futs), 1):
            r = futs[fut]
            try:
                res = fut.result()
            except Exception as exc:  # defensive: never lose a row
                res = _failed(_base_result(r), f"unexpected {type(exc).__name__}: {exc}")
                print(f"[warn] {r['finding_id']}: {exc}", file=sys.stderr)
            results[r["finding_id"]] = res
            if progress:
                progress(done, len(rows), res)
    except KeyboardInterrupt:
        # Don't keep paying for queued rows; finished calls are already cached for a resume.
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    pool.shutdown(wait=True)
    return [results[r["finding_id"]] for r in rows]


def equivalence_key(row: Dict[str, str], facts: Dict[str, object]) -> tuple:
    return scenario_key(row) + tuple(str(facts.get(k)) for k in EVIDENCE_PROFILE_FACTS)


def consistency_gate(rows: List[Dict[str, str]], results: List[Dict[str, object]]) -> List[Dict[str, object]]:
    """Rows with the same scenario AND the same evidence profile carry the same
    evidence. If independent assessments still classified them differently,
    the evidence is not robustly decisive, so every decisive verdict in that
    group is routed to Needs Review. Like the other gates it only ever moves
    a verdict towards Needs Review. Mutates `results`; returns the actions."""
    by_id = {r["finding_id"]: r for r in rows}
    groups: Dict[tuple, List[dict]] = {}
    for res in results:
        if res.get("error"):
            continue
        row = by_id[res["finding_id"]]
        groups.setdefault(equivalence_key(row, res.get("facts") or extract_facts(row)), []).append(res)
    actions = []
    for members in groups.values():
        verdicts = {m["classification"] for m in members}
        if len(verdicts) < 2:
            continue
        tally = dict(collections.Counter(m["classification"] for m in members))
        peers = ", ".join(f"{m['finding_id']}={m['classification']}" for m in members)
        for m in members:
            if m["classification"] == "Needs Review":
                continue
            note = (f"consistency gate: rows with identical evidence were classified differently ({peers}); "
                    f"downgraded {m['classification']} -> Needs Review")
            actions.append({"finding_id": m["finding_id"], "from": m["classification"], "group": tally})
            m["gated_from"] = m["gated_from"] or m["classification"]
            others = ", ".join(x["finding_id"] for x in members if x is not m)
            plural = "," in others
            m["reasoning"] = (f"Held for review: {others} {'carry' if plural else 'carries'} the same evidence and "
                              f"{'were' if plural else 'was'} assessed differently, so "
                              f"this evidence does not settle the question on its own. Analysis: {m['reasoning']}")
            m["missing_evidence"] = m.get("missing_evidence") or (
                f"A cleaner test of the deciding point. {others} {'have' if ',' in others else 'has'} the same evidence "
                f"and {'were' if ',' in others else 'was'} judged differently, so the existing captures cannot settle it.")
            m["gate_notes"] = (m["gate_notes"] + " | " if m.get("gate_notes") else "") + note
            m["classification"] = "Needs Review"
            m["confidence"] = min(float(m["confidence"]), NEEDS_REVIEW_CONFIDENCE_CAP)
            m.update(_UNSCORED)
            polish_result(m)
    return actions


# ---------------------------------------------------------------------------
# Client-facing language
# ---------------------------------------------------------------------------
# The prompt asks for a plain consultant's voice; this pass guarantees it. It
# maps internal labels to plain words and strips stock filler, and
# `style_issues` is used by the audit and tests to prove none survive.
FIELD_WORDS = {
    "raw_http_exchange": "captured HTTP exchange", "raw_request": "captured request", "raw_response": "captured response",
    "validation_attempt": "validation test", "observation": "analyst observation", "mixed_service_logs": "service logs",
    "distributed_trace_excerpt": "trace", "source_code_excerpt": "source excerpt", "code_or_config_context": "code context",
    "conflicting_revision_diff": "revision diff", "deployment_manifest_excerpt": "deployment manifest",
    "identity_network_context": "identity and network context", "claimed_compensating_controls": "claimed controls",
    "contradictory_evidence": "contradictory evidence", "ticket_comment_thread": "ticket thread",
    "adjacent_code_noise": "adjacent code", "evidence_collection_warnings": "collection warnings",
    "evidence_gaps": "evidence gaps", "scanner_raw_output": "scanner output", "release_bot_image_differs_from_source":
    "release bot's image-mismatch flag", "manifest_collected": "manifest collection time",
    "dataset_context": "dataset-wide context", "boundary_observed": "observed boundary", "request_id": "request ID",
    "finding_id": "finding ID", "first_observed_utc": "first observation", "last_observed_utc": "last observation",
    "trace_sampling": "trace sampling", "http_x_cache": "cache status", "log_retention": "log retention",
}
_PHRASES = [
    (r"\b(?:the )?row'?s own request[ _]id\b", "the test's request ID"),
    (r"\b(?:the )?row'?s request[ _]id\b", "the test's request ID"),
    (r"\b(?:the )?finding'?s own request[ _]id\b", "the test's request ID"),
    (r"\b(?:the )?evidence packet\b", "the evidence"), (r"\bthe packet\b", "the evidence"),
    (r"\bpacket\b", "evidence"), (r"\bthis row\b(?!-)", "this finding"), (r"\bthe row\b(?!-)", "this finding"),
    (r"\bthe facts block\b", "the collected facts"), (r"\bdeterministic facts\b", "collected facts"),
    (r"\bAssessor A'?s\b", "the first review's"), (r"\bAssessor B'?s\b", "the second review's"),
    (r"\bAssessor A\b", "the first review"), (r"\bAssessor B\b", "the second review"),
    (r"\b[Bb]oth assessors\b", "both reviews"), (r"\b[Aa]ssessors?\b", "review"),
]
_PLAIN_WORDS = {"robust": "strong", "robustly": "firmly", "leverage": "use", "leveraged": "used", "leverages": "uses",
                "comprehensive": "full", "seamless": "smooth", "seamlessly": "smoothly", "underscores": "shows",
                "underscore": "show", "delve": "look", "landscape": "environment"}
_FILLER = r"(?:Notably|Importantly|Crucially|Overall|In summary|Ultimately|Additionally|Furthermore|Moreover|It is worth noting that|It's worth noting that|Note that)"
AI_TELLS = re.compile(
    r"[\u2014\u2013]|\b(?:delve|robust|leverage[sd]?|comprehensive|seamless(?:ly)?|underscores?|landscape|"
    r"notably|importantly|crucially|it'?s worth noting|it is worth noting|in summary|as an ai|language model)\b|"
    r"\b(?:packet|assessor)s?\b|\bfacts block\b|"
    + r"\b(?:" + "|".join(sorted((k for k in FIELD_WORDS if "_" in k), key=len, reverse=True)) + r")\b", re.I)


def plain_text(text: str) -> str:
    if not text:
        return text
    t = str(text)
    t = re.sub(r"\s*[\u2014]\s*", ", ", t)                       # em dash -> comma
    t = re.sub(r"(?<=\w)\s*\u2013\s*(?=\w)", "-", t)              # en dash between words -> hyphen
    t = re.sub(r"\s*\u2013\s*", ", ", t)
    for pat, rep in _PHRASES:
        t = re.sub(pat, rep, t, flags=re.I)
    for name in sorted((k for k in FIELD_WORDS if "_" in k), key=len, reverse=True):
        t = re.sub(rf"`?\b{name}\b`?", FIELD_WORDS[name], t)
    t = re.sub(rf"(^|(?<=[.!?]\s)){_FILLER},?\s+(\w)", lambda m: m.group(1) + m.group(2).upper(), t)
    t = re.sub(rf",?\s*\b{_FILLER},\s*", ", ", t, flags=re.I)
    for word, plain in _PLAIN_WORDS.items():
        t = re.sub(rf"\b{word}\b", lambda m, p=plain: p.capitalize() if m.group(0)[0].isupper() else p, t, flags=re.I)
    t = re.sub(r",\s*,", ",", t)
    t = re.sub(r"\s+([,.;:])", r"\1", t)
    return re.sub(r"[ \t]{2,}", " ", t).strip()


def style_issues(text: str) -> List[str]:
    """Tells that should never appear in client-facing text. Code identifiers that are
    legitimately part of evidence (inside quotes/backticks) are excluded by callers."""
    return sorted({m.group(0) for m in AI_TELLS.finditer(text or "")})


def report_style_issues(page: str) -> List[str]:
    """Scan the rendered report's own prose. Verbatim evidence (code blocks) and
    the source data's own titles/identifiers are data, not our writing, so they
    are removed before scanning."""
    t = re.sub(r"(?is)<(style|script|code|pre)\b.*?</\1>", " ", page)
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    return style_issues(html.unescape(t))


CLIENT_TEXT_FIELDS = ("reasoning", "missing_evidence", "decisive_boundary", "provenance", "compensating_controls",
                      "client_title", "cvss_rationale", "business_impact", "recommended_fix", "adjudication_note")


def polish_result(r: Dict[str, object]) -> Dict[str, object]:
    for k in CLIENT_TEXT_FIELDS:
        if isinstance(r.get(k), str):
            r[k] = plain_text(r[k])
    for ev in r.get("evidence") or []:
        ev["supports"] = plain_text(ev.get("supports", ""))
    return r


# ---------------------------------------------------------------------------
# Attack-chain correlation (Assay-style deterministic rules)
# ---------------------------------------------------------------------------
# The dataset links no two findings by request, trace, session or object ID, so
# a chain is a CORRELATION: findings in the same environment whose types form a
# known attack progression. Chains never change a classification; they inform
# priority and tell the client which open items to investigate first.
_STEP = {
    "enumeration": ("Authentication", "enumerate"),
    "debug_exposure": ("Information Exposure", "debug"),
    "reset_token": ("Account Recovery", "reset token"),
    "oauth_redirect": ("OAuth", "redirect"),
    "token_forgery": ("Authentication", "without cryptographic verification"),
    "cors_credentialed": ("Browser Security", "cross-origin"),
    "cross_tenant_command": ("Authorization", "vehicle command"),
    "cross_tenant_report": ("Authorization", "another organization"),
    # Titles can't tell an identifier-injection write from a sort-parameter question,
    # so all SQL findings count as injection, not as a tenant-boundary step.
    "sql_injection": ("Injection", "sql"),
    "code_execution": ("Code Execution", "eval"),
    "shell_injection": ("Injection", "shell command"),
    "path_traversal": ("Path Traversal", "export directory"),
    "archive_write": ("File Upload", "archive"),
    "ssrf": ("Server-Side Request Forgery", "internal services"),
    "secret_exposure": ("Secret Detection", "payment key"),
}
_IDENTITY = ("reset_token", "oauth_redirect", "token_forgery", "cors_credentialed")
_TENANT = ("cross_tenant_command", "cross_tenant_report")
_EXECUTION = ("code_execution", "shell_injection", "sql_injection", "path_traversal", "archive_write")
CHAIN_RULES = [
    {"id": "account-takeover", "name": "Account discovery to account takeover",
     "stages": [("Find valid accounts", ("enumeration",)), ("Take over the session or credential", _IDENTITY)],
     "why": "Enumeration supplies confirmed targets for a token-forgery, token-leak or reset-token weakness."},
    {"id": "identity-to-tenant", "name": "Stolen or forged identity used across the tenant boundary",
     "stages": [("Obtain or forge an identity", _IDENTITY), ("Act on another tenant's data or vehicles", _TENANT)],
     "why": "A forged or leaked identity is what lets an outsider reach an object- or tenant-level "
            "authorization gap."},
    {"id": "recon-to-execution", "name": "Error disclosure guiding code or query injection",
     "stages": [("Learn internals from errors", ("debug_exposure",)), ("Inject code or queries", _EXECUTION)],
     "why": "Stack traces and debug output shorten the path to a working injection payload."},
    {"id": "execution-to-secrets", "name": "Server-side execution or file read reaching secrets",
     "stages": [("Run code or read files on a server", _EXECUTION),
                ("Use exposed secrets or internal services", ("secret_exposure", "ssrf"))],
     "why": "Server-side execution or file access is the usual route to credentials and internal services."},
]


def chain_step(result: Dict[str, object]) -> Optional[str]:
    cat, title = result.get("category", ""), (result.get("finding_title") or "").lower()
    for step, (c, keyword) in _STEP.items():
        if cat == c and keyword in title:
            return step
    return None


def correlate_chains(results: List[Dict[str, object]]) -> List[Dict[str, object]]:
    """One chain per (rule, environment) whose every stage has a Confirmed or
    Needs Review finding and at least one stage has a Confirmed finding. The
    chain is 'confirmed' if every stage has a Confirmed member, otherwise
    'contingent' on the listed Needs Review items. Stage members are ordered
    by first observation; `observed_in_attack_order` says whether the earliest
    finding of each stage was seen no later than the earliest of the next.
    Annotates member results with `chains`; returns the chain records."""
    by_env: Dict[str, List[dict]] = {}
    for r in results:
        if r["classification"] in ("Confirmed", "Needs Review") and not r.get("error") and chain_step(r):
            by_env.setdefault(r["environment"].strip().lower(), []).append(r)
    chains = []
    for rule in CHAIN_RULES:
        for env, members in sorted(by_env.items()):
            stages = [(label, sorted((m for m in members if chain_step(m) in steps),
                                     key=lambda m: (m.get("first_observed_utc", ""), m["finding_id"])))
                      for label, steps in rule["stages"]]
            if not all(found for _, found in stages):
                continue
            confirmed = [any(m["classification"] == "Confirmed" for m in found) for _, found in stages]
            if not any(confirmed):
                continue
            # A step with confirmed findings lists only those; a step without any lists the
            # findings under review that would complete the chain.
            stages = [(label, [m for m in found if m["classification"] == "Confirmed"] if ok else found)
                      for (label, found), ok in zip(stages, confirmed)]
            firsts = [min(m.get("first_observed_utc", "") for m in found) for _, found in stages]
            chain = {
                "chain_id": f"{rule['id']}:{env}", "name": rule["name"], "environment": env, "why": rule["why"],
                "status": "confirmed" if all(confirmed) else "contingent",
                "observed_in_attack_order": all(a <= b for a, b in zip(firsts, firsts[1:])),
                "stages": [{"stage": label, "findings": [
                    {"finding_id": m["finding_id"], "classification": m["classification"], "asset": m["asset"],
                     "title": m["finding_title"], "first_observed_utc": m.get("first_observed_utc", ""),
                     "cvss_score": m.get("cvss_score")} for m in found]} for label, found in stages],
                "pending_review": sorted({m["finding_id"] for _, found in stages for m in found
                                          if m["classification"] == "Needs Review"}),
            }
            chains.append(chain)
            for _, found in stages:
                for m in found:
                    m.setdefault("chains", []).append(chain["chain_id"])
    return chains


def harmonise(rows: List[Dict[str, str]], results: List[Dict[str, object]]) -> List[Dict[str, object]]:
    """Identical evidence should read identically in the report.
    - CVSS: Confirmed findings of the same scenario share one base vector, the one
      most of them were given (ties go to the lower score). Environment is not a
      base-score input, so it does not split the group.
    - Confidence: findings with identical evidence and the same verdict share the
      lowest confidence any of them received.
    Mutates `results`, keeps the original values, and returns the changes."""
    by_id = {r["finding_id"]: r for r in rows}
    changes = []
    scenarios: Dict[tuple, List[dict]] = {}
    for res in results:
        if res["classification"] == "Confirmed" and res.get("cvss_vector"):
            scenarios.setdefault(scenario_key(by_id[res["finding_id"]]), []).append(res)
    for members in scenarios.values():
        votes = collections.Counter(m["cvss_vector"] for m in members)
        if len(votes) < 2:
            continue
        top = max(votes.values())
        chosen = min((v for v, n in votes.items() if n == top), key=base_score)
        for m in members:
            if m["cvss_vector"] != chosen:
                changes.append({"finding_id": m["finding_id"], "field": "cvss_vector",
                                "from": m["cvss_vector"], "to": chosen})
                m["cvss_vector_original"] = m["cvss_vector"]
                m["cvss_vector"], m["cvss_score"], m["cvss_severity"] = score_vector(chosen)
                m["gate_notes"] = (m["gate_notes"] + " | " if m.get("gate_notes") else "") + \
                    f"CVSS aligned with {len(members) - 1} other finding(s) carrying identical evidence"
    groups: Dict[tuple, List[dict]] = {}
    for res in results:
        if not res.get("error"):
            row = by_id[res["finding_id"]]
            groups.setdefault(equivalence_key(row, res.get("facts") or extract_facts(row)) +
                              (res["classification"],), []).append(res)
    for members in groups.values():
        low = min(float(m["confidence"]) for m in members)
        for m in members:
            if float(m["confidence"]) != low:
                changes.append({"finding_id": m["finding_id"], "field": "confidence", "from": m["confidence"], "to": low})
                m["confidence_original"], m["confidence"] = m["confidence"], low
    for res in results:
        if res["classification"] == "Confirmed":
            res["priority_score"], res["priority_tier"] = priority(res.get("cvss_score"), res["environment"])
    return changes


def consistency_audit(rows: List[Dict[str, str]], results: List[Dict[str, object]]) -> Dict[str, object]:
    """Self-check: rows generated from the same scenario (same title + analyst
    observation + validation attempt) should normally land in the same class.
    A split is not automatically wrong - per-row provenance can legitimately
    differ - but every minority row is listed for human spot-check together
    with the provenance facts that differ."""
    by_id = {r["finding_id"]: r for r in results}
    groups: Dict[tuple, List[str]] = {}
    for r in rows:
        groups.setdefault(scenario_key(r), []).append(r["finding_id"])
    splits = []
    for (title, obs, _), ids in groups.items():
        cls = {i: by_id[i]["classification"] for i in ids if i in by_id}
        tally = collections.Counter(cls.values())
        if len(tally) > 1:
            majority = tally.most_common(1)[0][0]
            splits.append({
                "finding_title": title, "observation": obs[:160], "tally": dict(tally), "majority": majority,
                "minority": [{"finding_id": i, "classification": c, "confidence": by_id[i]["confidence"],
                              "release_bot_image_differs": by_id[i].get("facts", {}).get("release_bot_image_differs_from_source"),
                              "warnings": by_id[i].get("facts", {}).get("evidence_collection_warnings"),
                              "reasoning": by_id[i]["reasoning"]}
                             for i, c in cls.items() if c != majority],
            })
    return {"scenario_groups": len(groups), "split_groups": len(splits),
            "minority_rows": sum(len(s["minority"]) for s in splits), "splits": splits}


# ============================================================================
# Client HTML report
# ============================================================================
# Client-ready, self-contained HTML report (no external assets).
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}
FIELD_LABELS = {
    "observation": "Analyst observation", "validation_attempt": "Validation test", "raw_request": "HTTP request",
    "raw_response": "HTTP response", "raw_http_exchange": "HTTP exchange", "mixed_service_logs": "Service logs",
    "distributed_trace_excerpt": "Distributed trace", "source_code_excerpt": "Source code",
    "code_or_config_context": "Code / config", "deployment_manifest_excerpt": "Deployment manifest",
    "conflicting_revision_diff": "Revision diff", "identity_network_context": "Identity / network context",
    "contradictory_evidence": "Contradictory evidence", "claimed_compensating_controls": "Claimed controls",
    "ticket_comment_thread": "Ticket thread", "evidence_gaps": "Evidence gaps",
    "evidence_collection_warnings": "Collection warnings",
}


def e(x) -> str:
    return html.escape("" if x is None else str(x), quote=True)


# URLs, API paths, file names, function calls and code identifiers in prose are
# set as code, the way a consultant formats them in a written report.
_CODE_TOKEN = re.compile(
    r"https?://[^\s<>\"']+[^\s<>\"'.,;:)]"
    r"|(?<![\w/])/(?:[\w.~%-]+/)+[\w.~%-]*(?:\?[^\s<>\"']*[^\s<>\"'.,;:)])?"
    r"|\b[\w/]+\.(?:py|yaml|yml|json|txt)\b"
    r"|\b[A-Za-z_][\w.]*\([^()\s]{0,40}\)"
    r"|\b[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+\b")


def prose(x) -> str:
    """Escape model-written prose and set code-like tokens in <code>."""
    out, last = [], 0
    text = "" if x is None else str(x)
    for m in _CODE_TOKEN.finditer(text):
        out.append(e(text[last:m.start()]))
        out.append(f"<code>{e(m.group(0))}</code>")
        last = m.end()
    out.append(e(text[last:]))
    return "".join(out)


def _sev_badge(sev) -> str:
    return f'<span class="sev sev-{e((sev or "none").lower())}">{e({"Medium": "Moderate"}.get(sev, sev or "Unscored"))}</span>'


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _raised_by(r: dict) -> str:
    return r.get("scanner_source") or "unknown scanner"


def _agreement_text(r: dict) -> str:
    if r.get("error"):
        return "automated assessment failed"
    if r.get("adjudicated"):
        return "the two independent reviews disagreed; a third review decided"
    return "two independent assessments agreed"


def _cls_badge(c: str) -> str:
    slug = {"Confirmed": "conf", "False Positive": "fp", "Needs Review": "nr"}.get(c, "nr")
    return f'<span class="cls cls-{slug}">{e(c)}</span>'


def _priority_key(r):
    return (-(r.get("priority_score") or 0), SEV_ORDER.get(r.get("cvss_severity"), 5), r["finding_id"])


def _title_key(r):
    return (r["finding_title"], r["finding_id"])


def _group_by_title(rows: List[dict], key) -> Dict[str, List[dict]]:
    """Group rows by finding title; groups and members follow `key` order."""
    groups: Dict[str, List[dict]] = {}
    for r in sorted(rows, key=key):
        groups.setdefault(r["finding_title"], []).append(r)
    return groups


# ---------------------------------------------------------------------------
# Report building blocks
# ---------------------------------------------------------------------------
TIER_LABEL = {"CHASE": "Fix now", "LOOK": "Plan a fix", "NOTE": "Backlog"}
SEV_COLOR = {"Critical": "var(--crit)", "High": "var(--high)", "Medium": "var(--med)", "Low": "var(--low)"}
ENV_ORDER = ("production", "dr-canary", "staging", "sandbox")
ENV_NICE = {"production": "Production", "dr-canary": "DR canary", "staging": "Staging", "sandbox": "Sandbox"}
# Short names for the issue types, used for headings and charts. Types without an
# entry fall back to the wording of the finding itself.
ISSUE_LABEL = {
    "token_forgery": "Forged login tokens accepted", "shell_injection": "Command injection",
    "code_execution": "Remote code execution", "sql_injection": "SQL injection",
    "path_traversal": "File read through path traversal", "archive_write": "File write through archive upload",
    "ssrf": "Server-side request forgery", "secret_exposure": "Secret key exposed publicly",
    "reset_token": "Predictable password-reset tokens", "enumeration": "Account enumeration at login",
    "oauth_redirect": "Open redirect after login", "cors_credentialed": "Any website can read user data",
    "debug_exposure": "Debug console exposed", "cross_tenant_command": "Vehicle commands across customers",
    "cross_tenant_report": "Reports readable across customers",
}
CVSS_METRICS = {
    "AV": ("Attack vector", {"N": "Network", "A": "Adjacent network", "L": "Local", "P": "Physical"}),
    "AC": ("Complexity", {"L": "Low", "H": "High"}),
    "PR": ("Privileges needed", {"N": "None", "L": "Low", "H": "High"}),
    "UI": ("User action", {"N": "None", "R": "Required"}),
    "S": ("Scope", {"U": "Unchanged", "C": "Changed"}),
    "C": ("Confidentiality", {"N": "None", "L": "Low", "H": "High"}),
    "I": ("Integrity", {"N": "None", "L": "Low", "H": "High"}),
    "A": ("Availability", {"N": "None", "L": "Low", "H": "High"}),
}


def issue_key(r: dict) -> str:
    return chain_step(r) or "other:" + str(r.get("category") or "uncategorised")


_TITLE_HOST = re.compile(r"\s+on\s+[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:example|internal)\b|\s+in production\b", re.I)


def _date_window(days: List[str], default: str = "the observation period") -> str:
    """'July 1, 2026 to October 11, 2026' from ISO dates; unparseable values are skipped."""
    good = []
    for d in days:
        try:
            good.append(dt.date.fromisoformat(d[:10]))
        except ValueError:
            continue
    if not good:
        return default
    fmt = lambda d: d.strftime("%B %d, %Y").replace(" 0", " ")
    return f"{fmt(min(good))} to {fmt(max(good))}"


def display_title(r: dict) -> str:
    """Heading for an issue. The model words each title from one example, so a host name
    or 'in production' in it would be wrong for the other systems listed under it."""
    t = r.get("client_title") or r.get("finding_title") or ""
    t = _TITLE_HOST.sub("", t)
    return re.sub(r"\s+([,;])", r"\1", re.sub(r"\benabled (exposes)", r"\1", t)).strip()


def issue_label(key: str, lead: dict) -> str:
    if key in ISSUE_LABEL:
        return ISSUE_LABEL[key]
    return (lead.get("client_title") or lead.get("finding_title") or "Other").split(" (")[0]


def _group_by_issue(rows: List[dict], key=_priority_key) -> Dict[str, List[dict]]:
    groups: Dict[str, List[dict]] = {}
    for r in sorted(rows, key=key):
        groups.setdefault(issue_key(r), []).append(r)
    return groups


def _sentences(text) -> List[str]:
    # Not after "...", "= ?" or ".." (SQL placeholders and ellipses inside code samples).
    return [s.strip() for s in re.split(r"(?<=[.!?])(?<!\.\.\.)(?<!= \?)\s+(?=[A-Z0-9])", str(text or "").strip()) if s.strip()]


_HARDEN = re.compile(r"^(as (further |additional )?(defence|defense|protection)|for (extra )?defence|"
                     r"as defence|alternatively|also,? (add|limit|run|move|turn))", re.I)
_VERIFY = re.compile(r"^(to verify|verify|to confirm|confirm that|check that)", re.I)


def split_fix(text) -> Tuple[List[str], List[str], List[str]]:
    """Split the recommended-fix paragraph into what to change, extra hardening and how to verify."""
    steps, harden, verify = [], [], []
    state = steps
    for s in _sentences(text):
        if _VERIFY.match(s):
            state = verify
        elif _HARDEN.match(s) and state is steps:
            state = harden
        state.append(s)
    return steps, harden, verify


def _list(items: List[str], cls: str = "") -> str:
    return f"<ul class='{cls}'>" + "".join(f"<li>{prose(i)}</li>" for i in items) + "</ul>" if items else ""


def _trim(s, n: int = 240) -> str:
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    return s if len(s) <= n else s[: n - 1].rstrip() + "..."


def _sev_of(score) -> str:
    if score is None:
        return "None"
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low" if score > 0 else "None"


def _worst(rows: List[dict]) -> dict:
    return min(rows, key=lambda r: (SEV_ORDER.get(r.get("cvss_severity"), 5), -(r.get("cvss_score") or 0)))


def _donut(parts: List[Tuple[str, int, str]], center: str, sub: str) -> str:
    total = sum(n for _, n, _ in parts) or 1
    r, c = 52, 2 * math.pi * 52
    off, arcs = 0.0, []
    for label, n, color in parts:
        ln = c * n / total
        arcs.append(f"<circle r='{r}' cx='80' cy='80' fill='none' stroke='{color}' stroke-width='22' "
                    f"stroke-dasharray='{ln:.2f} {c - ln:.2f}' stroke-dashoffset='{-off:.2f}' transform='rotate(-90 80 80)'>"
                    f"<title>{e(label)}: {n}</title></circle>")
        off += ln
    legend = "".join(f"<li><i style='background:{col}'></i><b>{n}</b> {e(lab)}</li>" for lab, n, col in parts)
    return (f"<div class='donut'><svg viewBox='0 0 160 160' role='img' aria-label='Findings by classification'>{''.join(arcs)}"
            f"<text x='80' y='78' text-anchor='middle' class='dn'>{e(center)}</text>"
            f"<text x='80' y='96' text-anchor='middle' class='ds'>{e(sub)}</text></svg><ul class='legend'>{legend}</ul></div>")


def _stack_bar(parts: List[Tuple[str, int, str]]) -> str:
    total = sum(n for _, n, _ in parts) or 1
    segs = "".join(f"<span style='width:{100 * n / total:.2f}%;background:{col}' title='{e(lab)}: {n}'>{n if n / total > .06 else ''}</span>"
                   for lab, n, col in parts if n)
    legend = "".join(f"<li><i style='background:{col}'></i>{e(lab)} <b>{n}</b></li>" for lab, n, col in parts)
    return f"<div class='stack'>{segs}</div><ul class='legend row'>{legend}</ul>"


def _bar_rows(items: List[Tuple[str, int, str, str]], scale: int) -> str:
    """items: (label, value, color, href). Horizontal bars, one per row."""
    scale = scale or 1
    rows = []
    for label, n, color, href in items:
        name = f"<a href='{e(href)}'>{e(label)}</a>" if href else e(label)
        rows.append(f"<div class='brow'><span class='bl'>{name}</span><span class='bt'><span class='bf' "
                    f"style='width:{max(100 * n / scale, 2):.1f}%;background:{color}'></span></span><b class='bv'>{n}</b></div>")
    return "<div class='bars'>" + "".join(rows) + "</div>"


def _heatmap(confirmed: List[dict]) -> str:
    sevs = ("Critical", "High", "Medium", "Low")
    cnt = collections.Counter((r["environment"].strip().lower(), r.get("cvss_severity")) for r in confirmed)
    envs = [x for x in ENV_ORDER if any(cnt[(x, s)] for s in sevs)] + sorted(
        {r["environment"].strip().lower() for r in confirmed} - set(ENV_ORDER))
    peak = max(cnt.values(), default=1)
    head = "".join(f"<th>{s}</th>" for s in sevs) + "<th>Total</th>"
    body = []
    for env in envs:
        cells = []
        for s in sevs:
            n = cnt[(env, s)]
            alpha = 0 if not n else .18 + .72 * n / peak
            cells.append(f"<td class='hm' style='--c:{SEV_COLOR[s]};--a:{alpha:.2f}'>{n or ''}</td>")
        tot = sum(cnt[(env, s)] for s in sevs)
        body.append(f"<tr><th scope='row'>{e(env)}</th>{''.join(cells)}<td class='tot'>{tot}</td></tr>")
    return f"<table class='heat'><thead><tr><th></th>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def _score_meter(score) -> str:
    if score is None:
        return ""
    pos = max(0.0, min(float(score), 10.0)) * 10
    return (f"<div class='meter' role='img' aria-label='CVSS score {e(score)} out of 10'><span class='ms'></span>"
            f"<span class='mk' style='left:{pos:.1f}%'><b>{e(score)}</b></span></div>"
            f"<div class='mlab'><span>0</span><span>Low</span><span>Medium</span><span>High</span><span>Critical</span><span>10</span></div>")


def _cvss_chips(vector) -> str:
    parts = dict(p.split(":", 1) for p in str(vector or "").split("/")[1:] if ":" in p)
    chips = []
    for k, (name, vals) in CVSS_METRICS.items():
        v = parts.get(k)
        if v is None:
            continue
        hot = (k in "CIA" and v == "H") or (k == "AV" and v == "N") or (k in ("AC", "UI", "PR") and v in ("L", "N"))
        chips.append(f"<li class='{'hot' if hot else ''}'><span>{name}</span><b>{e(vals.get(v, v))}</b></li>")
    return "<ul class='chips'>" + "".join(chips) + "</ul>" if chips else ""


def _env_chips(rows: List[dict]) -> str:
    cnt = collections.Counter(r["environment"].strip().lower() for r in rows)
    order = [x for x in ENV_ORDER if x in cnt] + sorted(set(cnt) - set(ENV_ORDER))
    return "".join(f"<span class='env env-{e(x)}'>{e(x)} {cnt[x]}</span>" for x in order)


def _tier_badge(tier) -> str:
    return f"<span class='tier tier-{e((tier or '').lower())}'>{e(TIER_LABEL.get(tier, tier))}</span>" if tier else ""


def _evidence_points(ev: List[dict], limit: int = 4) -> str:
    if not ev:
        return "<p class='muted'>No verifiable citations.</p>"
    items = []
    for c in ev[:limit]:
        items.append(f"<li><b>{prose(c.get('supports', ''))}</b><span class='src'>{e(FIELD_LABELS.get(c['field'], c['field']))}</span>"
                     f"<code class='quote'>{e(_trim(c['quote'], 300))}</code></li>")
    more = ""
    if len(ev) > limit:
        more = ("<details class='more'><summary>" + f"{len(ev) - limit} more evidence item{'s' if len(ev) - limit != 1 else ''}</summary>"
                "<ul class='proof'>" + "".join(
                    f"<li><b>{prose(c.get('supports', ''))}</b><span class='src'>{e(FIELD_LABELS.get(c['field'], c['field']))}</span>"
                    f"<code class='quote'>{e(_trim(c['quote'], 300))}</code></li>" for c in ev[limit:]) + "</ul></details>")
    return f"<ul class='proof'>{''.join(items)}</ul>{more}"


def _impact_block(text) -> str:
    sents = _sentences(text)
    if not sents:
        return ""
    lead, rest = sents[0], " ".join(sents[1:])
    return f"<p class='lead'>{prose(lead)}</p>" + (f"<p>{prose(rest)}</p>" if rest else "")


def _fix_block(text) -> str:
    steps, harden, verify = split_fix(text)
    out = ""
    if steps:
        out += "<h5>What to change</h5><ol class='steps'>" + "".join(f"<li>{prose(s)}</li>" for s in steps) + "</ol>"
    if harden:
        out += "<h5>Extra hardening</h5>" + _list(harden)
    if verify:
        out += "<h5>How to check the fix worked</h5>" + _list(verify)
    return out


def _technical_details(r: dict) -> str:
    return f"""<details class="tech"><summary>Technical details: scoring, provenance and controls</summary>
    <p><strong>Finding ID.</strong> {e(r['finding_id'])} &middot; raised by {e(r.get('scanner_source') or 'unknown scanner')} &middot; first observed {e((r.get('first_observed_utc') or '')[:10])} &middot; asset owner: {e(r.get('asset_owner'))}</p>
    <p><strong>CVSS 3.1 vector.</strong> <code>{e(r.get('cvss_vector') or 'unscored')}</code></p>
    <p><strong>Why this score.</strong> {prose(r.get('cvss_rationale'))}</p>
    <p><strong>What the evidence shows.</strong> {prose(r.get('reasoning'))}</p>
    <p><strong>Which code revision was running.</strong> {prose(r.get('provenance'))}</p>
    <p><strong>Claimed protections.</strong> {prose(r.get('compensating_controls'))}</p>
    <p><strong>Assessment confidence.</strong> {e(r['confidence'])} &middot; {e(_agreement_text(r))}</p>
  </details>"""


def _hero_card(r: dict, anchor: str, rank: int, siblings: int) -> str:
    sev = r.get("cvss_severity") or "None"
    same = (f"<p class='note'>The same issue was also confirmed on {siblings} other asset{'s' if siblings != 1 else ''}. "
            f"See <a href='#issue-{e(issue_key(r))}'>all instances</a>.</p>") if siblings else ""
    chains = (f"<p class='note'>Part of an attack chain: {e(', '.join(sorted({c.split(':')[0].replace('-', ' ') for c in r['chains']})))}. <a href='#chains'>See chains</a>.</p>"
              if r.get("chains") else "")
    return f"""
<article class="hero sev-b-{e(sev.lower())}" id="{e(anchor)}">
  <div class="hero-top">
    <div class="rank">{rank}</div>
    <div class="hero-title"><div class="eyebrow">{e(r.get('category'))} &middot; {e(r['finding_id'])}</div>
      <h3>{e(display_title(r))}</h3>
      <div class="where"><span class="env env-{e(r['environment'].strip().lower())}">{e(r['environment'])}</span> <code>{e(r['asset'])}</code>
        {_tier_badge(r.get('priority_tier'))}</div></div>
    <div class="hero-score">{_sev_badge(sev)}<div class="big">{e(r.get('cvss_score') if r.get('cvss_score') is not None else '-')}</div><div class="muted">CVSS 3.1</div></div>
  </div>
  {_score_meter(r.get('cvss_score'))}
  <div class="cols">
    <section><h4>What we found and why it matters</h4>{_impact_block(r.get('business_impact'))}{same}{chains}</section>
    <section><h4>How we know</h4>{_evidence_points(r.get('evidence', []))}</section>
  </div>
  <section class="fixbox"><h4>How to fix it</h4>{_fix_block(r.get('recommended_fix'))}</section>
  <h4>Severity breakdown</h4>{_cvss_chips(r.get('cvss_vector'))}
  {_technical_details(r)}
</article>"""


def _instance_detail(r: dict) -> str:
    return (f"<details class='inst-d' id='f-{e(r['finding_id'])}'><summary>Evidence for {e(r['finding_id'])} "
            f"<span class='muted'>{e(r['asset'])} ({e(r['environment'])})</span></summary>"
            f"{_evidence_points(r.get('evidence', []), 3)}{_technical_details(r)}</details>")


def _issue_block(i: int, key: str, rows: List[dict]) -> str:
    lead = rows[0]
    worst = _worst(rows)
    label = issue_label(key, lead)
    prod = sum(1 for r in rows if r["environment"].strip().lower() == "production")
    inst_rows = "".join(
        f"<tr><td><a href='#f-{e(r['finding_id'])}'>{e(r['finding_id'])}</a></td><td><code>{e(r['asset'])}</code></td>"
        f"<td><span class='env env-{e(r['environment'].strip().lower())}'>{e(r['environment'])}</span></td>"
        f"<td>{_sev_badge(r.get('cvss_severity'))} {e(r.get('cvss_score'))}</td><td>{_tier_badge(r.get('priority_tier'))}</td>"
        f"<td>{e(r['confidence'])}</td></tr>" for r in rows)
    sents = _sentences(lead.get("business_impact"))
    return f"""
<details class="issue" id="issue-{e(key)}">
  <summary><span class="inum">{i}</span>
    <span class="it"><b>{e(label)}</b><small>{prose(sents[0]) if sents else ''}</small></span>
    <span class="ic"><b>{len(rows)}</b><small>instance{'s' if len(rows) != 1 else ''}</small></span>
    <span class="iw">{_env_chips(rows)}{f"<small>{prod} in production</small>" if prod else ""}</span>
    <span class="is">{_sev_badge(worst.get('cvss_severity'))}<small>up to {e(worst.get('cvss_score'))}</small></span></summary>
  <div class="issue-body">
    <div class="cols"><section><h4>Impact</h4>{_impact_block(lead.get('business_impact'))}</section>
      <section class="fixbox"><h4>Recommended fix</h4>{_fix_block(lead.get('recommended_fix'))}</section></div>
    <h4>Where it was confirmed</h4>
    <div class="tablewrap"><table class="inst"><thead><tr><th>ID</th><th>Asset</th><th>Environment</th><th>Severity</th><th>Priority</th><th>Confidence</th></tr></thead><tbody>{inst_rows}</tbody></table></div>
    {''.join(_instance_detail(r) for r in rows)}
  </div>
</details>"""


def _chains_html(chains: List[dict]) -> str:
    if not chains:
        return "<p class='muted'>No combination of confirmed findings in a single environment forms a known attack progression.</p>"
    order = sorted(chains, key=lambda c: (c["status"] != "confirmed", c["environment"] != "production", c["chain_id"]))
    cards = []
    for c in order:
        boxes = []
        for st in c["stages"]:
            fs = st["findings"]
            ids = ", ".join(f["finding_id"] for f in fs[:5]) + (f" +{len(fs) - 5} more" if len(fs) > 5 else "")
            titles = sorted({f["title"] for f in fs})
            blurb = _trim(titles[0], 70) + (f" (+{len(titles) - 1} related)" if len(titles) > 1 else "")
            scores = [f["cvss_score"] for f in fs if f.get("cvss_score") is not None]
            state = "ok" if all(f["classification"] == "Confirmed" for f in fs) else "open"
            boxes.append(f"<div class='stage stage-{state}'><div class='sl'>{e(st['stage'])}</div>"
                         f"<div class='sn'>{len(fs)} finding{'s' if len(fs) != 1 else ''}"
                         f"{' &middot; CVSS up to ' + e(max(scores)) if scores else ''}</div>"
                         f"<div class='sb'>{e(blurb)}</div><div class='si'>{e(ids)}</div>"
                         f"<div class='sstate'>{'Confirmed' if state == 'ok' else 'Still under review'}</div></div>")
        status = ("Every step confirmed" if c["status"] == "confirmed" else
                  f"Depends on {e(', '.join(c['pending_review'][:6]))}{' and more' if len(c['pending_review']) > 6 else ''}, still under review")
        cards.append(f"<article class='chain'><header><h3>{e(c['name'])}</h3><span class='env env-{e(c['environment'])}'>{e(c['environment'])}</span>"
                     f"<span class='tier tier-{'chase' if c['status'] == 'confirmed' else 'look'}'>{status if c['status'] != 'confirmed' else 'All steps confirmed'}</span></header>"
                     f"<div class='flow'>{'<span class=arrow>&rarr;</span>'.join(boxes)}</div>"
                     f"<p class='muted'>{e(c['why'])}</p></article>")
    return "".join(cards)


def _needs_review_html(nr: List[dict]) -> str:
    out = []
    for key, rows in sorted(_group_by_issue(nr, _title_key).items(), key=lambda kv: -len(kv[1])):
        lead = rows[0]
        label = issue_label(key, lead)
        asked = _trim(lead.get("missing_evidence"), 330)
        trs = "".join(f"<tr><td>{e(r['finding_id'])}</td><td><code>{e(r['asset'])}</code></td><td>{e(r['environment'])}</td>"
                      f"<td>{prose(r['reasoning'])}</td><td>{prose(r.get('missing_evidence'))}</td></tr>" for r in rows)
        out.append(f"<details class='nrg'><summary><b>{e(label)}</b><span class='count'>{len(rows)}</span>"
                   f"<small>{prose(asked)}</small></summary><div class='tablewrap'><table class='inst'><thead><tr><th>ID</th><th>Asset</th><th>Env</th>"
                   f"<th>Why it is undecided</th><th>What would decide it</th></tr></thead><tbody>{trs}</tbody></table></div></details>")
    return "".join(out)


# ---------------------------------------------------------------------------
# Findings report in the structure of a professional penetration-test report
# (cover, confidentiality, assessment overview, severity ratings, scope,
# executive summary with attack summary, strengths and weaknesses, technical findings).
# ---------------------------------------------------------------------------
SEV_DISPLAY = {"Medium": "Moderate"}
SEV_DEFS = [
    ("Critical", "9.0-10.0", "Exploitation is straightforward and usually results in system-level compromise or exposure across customers. Form a plan of action and fix immediately."),
    ("High", "7.0-8.9", "Exploitation is more difficult but could cause elevated privileges and potentially a loss of data or downtime. Form a plan of action and fix as soon as possible."),
    ("Moderate", "4.0-6.9", "Weaknesses exist but are harder to exploit or need extra steps such as user interaction. Fix after high-priority issues are resolved."),
    ("Low", "0.1-3.9", "Not directly exploitable but would reduce the attack surface. Fix during the next maintenance window."),
    ("Informational", "N/A", "No confirmed vulnerability. Items where the evidence could not decide the question, findings shown to be false alarms, and controls that held up."),
]
_VECTOR_WORDS = {"N": "Remote (network)", "A": "Adjacent (internal network)", "L": "Local", "P": "Physical"}


def _vector_word(vec) -> str:
    m = re.search(r"AV:([NALP])", str(vec or ""))
    return _VECTOR_WORDS.get(m.group(1), "Not scored") if m else "Not scored"


def _sev_cell(sev) -> str:
    return f"<td class='sevcell sc-{e((sev or 'none').lower())}'>{e(SEV_DISPLAY.get(sev, sev or 'Unscored'))}</td>"


def _figures(ev: List[dict], counter: List[int], limit: int = 6) -> str:
    out = []
    for c in ev[:limit]:
        counter[0] += 1
        out.append(f"<figure><pre>{e(_trim(c['quote'], 420))}</pre><figcaption>Figure {counter[0]}: {prose(c.get('supports', ''))} "
                   f"<span class='src'>({e(FIELD_LABELS.get(c['field'], c['field']))})</span></figcaption></figure>")
    return "".join(out)


def _remediation(r: dict) -> str:
    steps, harden, verify = split_fix(r.get("recommended_fix"))
    items = [(s) for s in steps] + [("Defence in depth: " + s) if not s.lower().startswith(("as ", "for ")) else s for s in harden]
    li = "".join(f"<li><b>Item {i}:</b> {prose(s)}</li>" for i, s in enumerate(items, 1))
    retest = _list(verify) if verify else ""
    return (f"<table class='kv'><tr><th>Who:</th><td>{e(r.get('asset_owner') or 'Asset owner')}</td></tr>"
            f"<tr><th>Vector:</th><td>{e(_vector_word(r.get('cvss_vector')))}</td></tr>"
            f"<tr><th>Action:</th><td><ul class='items'>{li}</ul></td></tr>"
            + (f"<tr><th>Retest:</th><td>{retest}</td></tr>" if retest else "") + "</table>")


def _tcm_finding(code: str, anchor: str, title: str, lead: dict, rows: List[dict], counter: List[int],
                 badge: str = "", extra_instances: str = "") -> str:
    sev = lead.get("cvss_severity")
    systems = "".join(f"<li><code>{e(r['asset'])}</code> ({e(r['environment'])}) <a href='#f-{e(r['finding_id'])}'>{e(r['finding_id'])}</a></li>" for r in rows)
    impact = _impact_block(lead.get("business_impact"))
    chains = (f"<p class='note'>This finding is part of an attack chain ({e(', '.join(sorted({c.split(':')[0].replace('-', ' ') for c in lead['chains']}))) }). "
              f"See <a href='#attack-summary'>Attack Summary</a>.</p>") if lead.get("chains") else ""
    return f"""
<section class="finding" id="{e(anchor)}">
  <h3><span class="fcode">{e(code)}</span> {e(title)} <span class="sevtag sc-{e((sev or 'none').lower())}">{e(SEV_DISPLAY.get(sev, sev or 'Unscored'))}</span>{badge}</h3>
  <table class="kv">
    <tr><th>Description:</th><td>{prose(lead.get('decisive_boundary'))}</td></tr>
    <tr><th>Impact:</th><td><b>{e(SEV_DISPLAY.get(sev, sev or 'Unscored'))}</b> &middot; CVSS 3.1 score {e(lead.get('cvss_score') if lead.get('cvss_score') is not None else 'n/a')} {_tier_badge(lead.get('priority_tier'))}{impact}{chains}</td></tr>
    <tr><th>System{'s' if len(rows) != 1 else ''}:</th><td><ul class="plain">{systems}</ul></td></tr>
    <tr><th>References:</th><td>CVSS 3.1 vector <code>{e(lead.get('cvss_vector') or 'unscored')}</code>{_cvss_chips(lead.get('cvss_vector'))}
      <p class="muted">{prose(lead.get('cvss_rationale'))}</p></td></tr>
  </table>
  <h4>Exploitation Proof of Concept</h4>
  <p>{prose(lead.get('reasoning'))}</p>
  {_figures(lead.get('evidence', []), counter)}
  <h4>Remediation</h4>
  {_remediation(lead)}
  {extra_instances}
</section>"""


def _instances_table(rows: List[dict]) -> str:
    trs = "".join(f"<tr><td><a href='#f-{e(r['finding_id'])}'>{e(r['finding_id'])}</a></td><td><code>{e(r['asset'])}</code></td><td>{e(r['environment'])}</td>"
                  f"{_sev_cell(r.get('cvss_severity'))}<td>{e(r.get('cvss_score'))}</td><td>{e(TIER_LABEL.get(r.get('priority_tier'), ''))}</td><td>{e(r['confidence'])}</td></tr>"
                  for r in rows)
    return ("<h4>Where this was confirmed</h4><table class='grid'><thead><tr><th>ID</th><th>System</th><th>Environment</th><th>Severity</th><th>CVSS</th><th>Priority</th><th>Confidence</th></tr></thead>"
            f"<tbody>{trs}</tbody></table>")


def _instance_evidence(rows: List[dict], counter: List[int]) -> str:
    """Per-instance evidence, kept for traceability; shown on screen, left out of print."""
    return "".join(f"<details class='noprint' id='f-{e(r['finding_id'])}'><summary>Evidence for {e(r['finding_id'])} ({e(r['asset'])}, {e(r['environment'])})</summary>"
                   f"{_evidence_points(r.get('evidence', []), 3)}<p class='muted'>{prose(r.get('provenance'))}</p></details>" for r in rows)


def _attack_summary(chains: List[dict], by_id: Dict[str, dict]) -> str:
    seen, out = set(), []
    for c in sorted(chains, key=lambda c: (c["status"] != "confirmed", c["environment"] != "production", c["chain_id"])):
        rule = c["chain_id"].split(":")[0]
        if rule in seen:
            continue
        seen.add(rule)
        rows = []
        for i, st in enumerate(c["stages"], 1):
            fs = st["findings"]
            state = "confirmed" if all(f["classification"] == "Confirmed" for f in fs) else "still under review"
            kinds: Dict[str, List[dict]] = {}
            for f in fs:
                r = by_id.get(f["finding_id"])
                if r:
                    kinds.setdefault(issue_key(r), []).append(r)
            acts, recs = [], []
            for key, rs_ in sorted(kinds.items(), key=lambda kv: -len(kv[1])):
                lead = sorted(rs_, key=_priority_key)[0]
                label = issue_label(key, lead)
                acts.append(f"<li><b>{e(label)}</b> ({len(rs_)} finding{'s' if len(rs_) != 1 else ''}) <span class='muted'>"
                            f"{e(', '.join(r['finding_id'] for r in rs_[:3]))}{' and more' if len(rs_) > 3 else ''}</span></li>")
                steps, _, _ = split_fix(lead.get("recommended_fix"))
                recs.append(f"<li><b>{e(label)}:</b> {prose(_trim(steps[0], 200)) if steps else 'See the finding entry.'}</li>")
            rows.append(f"<tr><td class='c'>{i}</td><td><b>{e(st['stage'])}</b> ({state})<ul class='items'>{''.join(acts)}</ul></td>"
                        f"<td><ul class='items'>{''.join(recs)}</ul></td></tr>")
        n_env = sum(1 for x in chains if x["chain_id"].split(":")[0] == rule)
        out.append(f"<h4>{e(c['name'])} <span class='muted'>({e(c['environment'])}{f'; the same path exists in {n_env - 1} other environment(s)' if n_env > 1 else ''})</span></h4>"
                   f"<p>{e(c['why'])}</p><table class='grid steps'><thead><tr><th>Step</th><th>Action</th><th>Recommendation</th></tr></thead><tbody>{''.join(rows)}</tbody></table>")
    return "".join(out) or "<p class='muted'>No combination of confirmed findings in a single environment forms a known attack progression.</p>"


def build_report(results: List[dict], source_name: str, model: str, chains: List[dict] = (), client: str = "Client") -> str:
    cl = e(client)
    counts = collections.Counter(r["classification"] for r in results)
    confirmed = [r for r in results if r["classification"] == "Confirmed"]
    nr = [r for r in results if r["classification"] == "Needs Review"]
    fp = [r for r in results if r["classification"] == "False Positive"]
    by_id = {r["finding_id"]: r for r in results}
    groups = _group_by_issue(confirmed)
    ranked = sorted(groups.items(), key=lambda kv: (_priority_key(kv[1][0]), kv[0]))
    top = sorted(confirmed, key=_priority_key)[:3]
    tiers = collections.Counter(r.get("priority_tier") for r in confirmed)
    sev = collections.Counter(r.get("cvss_severity") for r in confirmed)
    prod = [r for r in confirmed if r["environment"].strip().lower() == "production"]
    prod_hi = sum(1 for r in prod if r.get("cvss_severity") in ("Critical", "High"))
    adjudicated = sum(1 for r in results if r.get("adjudicated"))
    gated = sum(1 for r in results if r.get("gated_from"))
    errors = sum(1 for r in results if r.get("error"))
    consistency = sum(1 for r in results if "consistency gate" in (r.get("gate_notes") or ""))
    evidence_gated = gated - consistency
    n_conf_chains = sum(1 for c in chains if c["status"] == "confirmed")
    seen = sorted(r.get("first_observed_utc", "")[:10] for r in results if r.get("first_observed_utc"))
    window = _date_window(seen)
    weights = ", ".join(f"{k} {v}" for k, v in ENV_WEIGHT.items())
    type_names = {k: issue_label(k, g[0]) for k, g in groups.items()}
    error_banner = (f"<div class='banner'><strong>{errors} finding(s) could not be assessed automatically</strong> "
                    f"and are listed as informational (needs review) pending manual assessment.</div>") if errors else ""
    counter = [0]

    # --- tables used by the front matter ---
    owners = collections.Counter(r.get("asset_owner") or "Not recorded" for r in results)
    owner_rows = "".join(f"<tr><td>{e(o)}</td><td>{n} findings</td><td>To be provided by {cl}</td></tr>" for o, n in sorted(owners.items()))
    env_assets: Dict[str, set] = {}
    for r in results:
        env_assets.setdefault(r["environment"].strip().lower(), set()).add(r["asset"])
    envs = [x for x in ENV_ORDER if x in env_assets] + sorted(set(env_assets) - set(ENV_ORDER))
    scope_rows = "".join(f"<tr><td>{e(ENV_NICE.get(x, x))}</td><td>{', '.join('<code>' + e(a) + '</code>' for a in sorted(env_assets[x]))}</td></tr>" for x in envs)
    sev_rows = "".join(f"<tr><td class='sevcell sc-{n.lower() if n != 'Moderate' else 'medium'}'>{n}</td><td>{rng}</td><td>{d}</td></tr>" for n, rng, d in SEV_DEFS)

    # --- executive summary ---
    worst_types = ", ".join(type_names[k] for k, _ in ranked[:3])
    exec_text = (f"The security tooling at {cl} produced {len(results)} raw findings between {window}. Each was evaluated against the evidence supplied "
                 f"(runtime requests and responses, traces, logs, source and deployment records, owner comments) and not against the scanner's own severity label. "
                 f"{counts['Confirmed']} findings are confirmed real, {counts['False Positive']} are false alarms, and {counts['Needs Review']} cannot be decided without more evidence. "
                 f"The confirmed findings fall into {len(groups)} issue types; the client report lists {len({client_issue_key(r) for r in confirmed})} distinct issues because it keeps two flaws of the same type apart when their scored scenarios differ. "
                 f"{_plural(len(prod), 'confirmed finding affects', 'confirmed findings affect')} production, {prod_hi} of them rated High or Critical. "
                 f"It is highly recommended that {cl} address {worst_types} first.")
    weak = "".join(f"<h4>{e(type_names[k])}</h4>{_impact_block(g[0].get('business_impact'))}" for k, g in ranked[:4])
    fp_groups = _group_by_issue(fp, _title_key)
    strengths = ""
    for k, g in sorted(fp_groups.items(), key=lambda kv: -len(kv[1]))[:4]:
        ss = _sentences(g[0].get("reasoning"))
        strengths += (f"<h4>{len(g)} reported {e(issue_label(k, g[0]).lower())} case{'s' if len(g) != 1 else ''} shown not exploitable</h4>"
                      f"<p>{prose(' '.join(ss[:3]))}</p>")
    sev_bars = _bar_rows([(SEV_DISPLAY.get(s, s), sev.get(s, 0), SEV_COLOR[s], "") for s in ("Critical", "High", "Medium", "Low")],
                         max(sev.values(), default=1))
    heat = _heatmap(confirmed).replace(">Medium<", ">Moderate<")
    type_bars = _bar_rows([(type_names[k], len(g), SEV_COLOR.get(_worst(g).get("cvss_severity"), "var(--accent)"), f"#issue-{k}")
                           for k, g in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))], max((len(g) for g in groups.values()), default=1))
    donut = _donut([("Confirmed", counts["Confirmed"], "var(--conf)"), ("Informational: needs review", counts["Needs Review"], "var(--nr)"),
                    ("Informational: false positive", counts["False Positive"], "var(--fp)")], str(len(results)), "findings")

    # --- technical findings ---
    priority_html = "".join(_tcm_finding(f"P-{i}", f"top-{i}", display_title(r), r, [r], counter,
                                         badge=" <span class='tier tier-chase'>Top priority</span>" if True else "")
                            for i, r in enumerate(top, 1)) or "<p>No findings met the confirmation standard.</p>"
    issue_html = []
    for i, (k, g) in enumerate(ranked, 1):
        lead = g[0]
        issue_html.append(_tcm_finding(f"F-{i:02d}", f"issue-{k}", type_names[k] + f": {display_title(lead)}",
                                       lead, g[:1] if len(g) == 1 else g, counter,
                                       extra_instances=_instances_table(g) + _instance_evidence(g, counter)))
    nr_html = _needs_review_html(nr)
    fp_html = ("<table class='grid'><thead><tr><th>ID</th><th>Title</th><th>System</th><th>Env</th><th>Why it is not exploitable as reported</th></tr></thead><tbody>"
               + "".join(f"<tr><td>{e(r['finding_id'])}</td><td>{e(r['finding_title'])}</td><td><code>{e(r['asset'])}</code></td><td>{e(r['environment'])}</td><td>{prose(r['reasoning'])}</td></tr>"
                         for r in sorted(fp, key=_title_key)) + "</tbody></table>") if fp else ""
    all_rows = "".join(
        f"<tr data-cls='{e(r['classification'])}'><td>{e(r['finding_id'])}</td><td>{e((r.get('first_observed_utc') or '')[:10])}</td>"
        f"<td>{e(r['finding_title'])}</td><td><code>{e(r['asset'])}</code></td><td>{e(r['environment'])}</td><td>{e(r.get('scanner_source'))}</td>"
        f"<td>{_cls_badge(r['classification'])}</td><td>{e(r['confidence'])}</td><td class='reason'>{prose(r['reasoning'])}</td></tr>" for r in results)

    toc = [("confidentiality", "Confidentiality Statement"), ("disclaimer", "Disclaimer"), ("contacts", "Contact Information"),
           ("overview", "Assessment Overview"), ("severity", "Finding Severity Ratings"), ("scope", "Scope"),
           ("exec", "Executive Summary"), ("attack-summary", "&nbsp;&nbsp;Attack Summary"), ("strengths", "&nbsp;&nbsp;Security Strengths"),
           ("weaknesses", "&nbsp;&nbsp;Security Weaknesses"), ("impact", "&nbsp;&nbsp;Vulnerabilities by Impact"),
           ("findings", "Technical Findings"), ("priority", "&nbsp;&nbsp;Top Priority Findings"), ("confirmed", "&nbsp;&nbsp;All Confirmed Findings by Issue Type"),
           ("informational", "Additional Reports and Scans (Informational)"), ("method", "Assessment Method and Limitations"), ("appendix", "Appendix: Every Finding")]
    toc_html = "".join(f"<li><a href='#{a}'>{t}</a></li>" for a, t in toc)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{cl} Security Assessment Findings Report</title>
<style>
:root{{--bg:#e9ebef;--paper:#fff;--ink:#1a1f2b;--muted:#5b6475;--line:#d6dae1;--accent:#13294b;--soft:#f1f4f8;--red:#b3261e;
--crit:#8c1230;--high:#c8431a;--med:#c28a14;--low:#3f7a4d;--conf:#b3261e;--fp:#5f8f6b;--nr:#c28a14}}
*{{box-sizing:border-box;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
body{{margin:0;background:var(--bg);color:var(--ink);font:14.5px/1.6 Calibri,"Segoe UI",-apple-system,Roboto,Arial,sans-serif}}
a{{color:#1f4e8c}} .doc{{max-width:930px;margin:24px auto;background:var(--paper);box-shadow:0 2px 14px rgba(0,0,0,.12)}}
.cover{{padding:120px 64px 90px;background:var(--accent);color:#fff;min-height:520px;display:flex;flex-direction:column;justify-content:center}}
.cover .co{{font-size:46px;font-weight:700;line-height:1.1}} .cover .tt{{font-size:30px;margin-top:6px;font-weight:300}}
.cover .rule{{width:90px;height:5px;background:var(--red);margin:26px 0}} .cover p{{margin:2px 0;font-size:16px;opacity:.92}}
.page{{padding:34px 64px 10px}} h2{{font-size:25px;color:var(--accent);border-bottom:3px solid var(--red);padding-bottom:5px;margin:34px 0 14px;scroll-margin-top:12px}}
h3{{font-size:19px;color:var(--accent);margin:26px 0 8px;scroll-margin-top:12px}} h4{{font-size:15.5px;color:var(--accent);margin:18px 0 6px}} p{{margin:5px 0 10px}}
.fcode{{font:600 13px ui-monospace,Menlo,monospace;background:var(--soft);padding:2px 7px;border-radius:5px;margin-right:4px}}
code{{font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;background:rgba(127,127,127,.13);padding:1px 5px;border-radius:4px;word-break:break-word}}
.muted{{color:var(--muted)}} .toc{{columns:2;column-gap:36px;list-style:none;padding:0}} .toc li{{padding:3px 0;border-bottom:1px dotted var(--line);break-inside:avoid}} .toc a{{text-decoration:none}}
table{{width:100%;border-collapse:collapse;font-size:13.5px}} th,td{{text-align:left;padding:7px 9px;border:1px solid var(--line);vertical-align:top}}
table.grid th,table.kv th{{background:var(--accent);color:#fff;font-weight:600}} table.kv th{{width:130px;white-space:nowrap}} table.kv{{margin:8px 0 14px}} table.kv th{{background:var(--soft);color:var(--accent)}}
td.c{{text-align:center;font-weight:700;width:46px}} .sevcell{{font-weight:700;color:#fff;text-align:center;white-space:nowrap}}
.sc-critical{{background:var(--crit)}} .sc-high{{background:var(--high)}} .sc-medium{{background:var(--med)}} .sc-low{{background:var(--low)}} .sc-none{{background:#777}}
.sevtag{{display:inline-block;font-size:12px;font-weight:700;padding:2px 10px;border-radius:999px;color:#fff;vertical-align:middle;margin-left:6px}}
.sev,.cls,.tier{{display:inline-block;font-size:12px;font-weight:700;padding:1px 9px;border-radius:999px;color:#fff;background:#777;white-space:nowrap}}
.sev-critical{{background:var(--crit)}} .sev-high{{background:var(--high)}} .sev-medium{{background:var(--med)}} .sev-low{{background:var(--low)}}
.cls-conf{{background:var(--conf)}} .cls-fp{{background:var(--fp)}} .cls-nr{{background:var(--nr)}}
.tier{{background:transparent;color:var(--ink);border:1px solid var(--line);font-weight:600}} .tier-chase{{border-color:var(--crit);color:var(--crit)}} .tier-look{{border-color:var(--med);color:var(--med)}}
.lead{{font-weight:600}} ul.items,ul.plain{{margin:0;padding-left:18px}} ul.plain{{list-style:none;padding:0}} ul.items li{{margin:5px 0}}
figure{{margin:12px 0;border:1px solid var(--line);border-radius:6px;overflow:hidden;break-inside:avoid}} figure pre{{margin:0;padding:10px 12px;background:#10151f;color:#e6edf7;white-space:pre-wrap;word-break:break-word;font:12px/1.5 ui-monospace,Menlo,monospace}}
figcaption{{padding:6px 12px;background:var(--soft);font-size:12.5px;color:var(--muted);font-style:italic}} .src{{font-style:normal;text-transform:uppercase;font-size:10.5px;letter-spacing:.05em}}
ul.chips{{list-style:none;padding:0;margin:8px 0 0;display:flex;flex-wrap:wrap;gap:6px}} .chips li{{border:1px solid var(--line);border-radius:6px;padding:3px 8px;font-size:11.5px;line-height:1.3}} .chips li span{{display:block;color:var(--muted)}} .chips li.hot{{border-color:var(--high);background:rgba(200,67,26,.07)}}
.note{{font-size:13px;background:var(--soft);padding:6px 10px;border-radius:6px}} .banner{{border:1px solid var(--crit);background:rgba(140,18,48,.07);padding:10px 14px;margin:12px 0}}
.callout{{border-left:5px solid var(--red);background:var(--soft);padding:12px 16px;margin:12px 0}}
.twocol{{display:grid;grid-template-columns:1fr 1fr;gap:22px}} .bars{{margin-top:4px}} .brow{{display:grid;grid-template-columns:minmax(140px,42%) 1fr 28px;gap:10px;align-items:center;margin:5px 0;font-size:13px}}
.bt{{height:14px;background:var(--line);border-radius:3px;overflow:hidden;display:block}} .bf{{display:block;height:100%}} .bv{{text-align:right}} .bl a{{color:var(--ink);text-decoration:none}}
.donut{{display:flex;align-items:center;gap:16px;flex-wrap:wrap}} .donut svg{{width:140px;height:140px}} .dn{{font:700 28px sans-serif;fill:var(--ink)}} .ds{{font:12px sans-serif;fill:var(--muted)}}
.legend{{list-style:none;padding:0;margin:0}} .legend li{{display:flex;align-items:center;gap:8px;margin:4px 0;font-size:13px}} .legend i{{width:12px;height:12px;border-radius:3px;display:inline-block}}
table.heat{{border-collapse:separate;border-spacing:3px}} table.heat th{{border:0;background:none;color:var(--muted);text-align:center;font-size:12px;padding:3px}} table.heat th[scope=row]{{text-align:left;color:var(--ink)}}
td.hm{{border:0;text-align:center;font-weight:700;border-radius:5px;height:30px;background:color-mix(in srgb,var(--c) calc(var(--a)*100%),transparent)}} td.tot{{border:0;text-align:center;font-weight:700}}
details{{margin:6px 0;font-size:13px}} summary{{cursor:pointer;color:#1f4e8c;font-weight:600}} ul.proof{{list-style:none;padding:0}} ul.proof li{{border-left:3px solid var(--accent);padding:3px 0 3px 10px;margin:8px 0}} ul.proof li b{{display:block}}
code.quote{{display:block;white-space:pre-wrap}} details.nrg{{border:1px solid var(--line);padding:8px 12px;border-radius:6px;margin:8px 0}} details.nrg summary small{{display:block;font-weight:400;color:var(--muted)}}
.count{{font-size:12px;background:var(--soft);padding:1px 8px;border-radius:999px;margin-left:6px}} .tablewrap{{overflow-x:auto}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}} .filters input{{flex:1;min-width:200px;padding:7px;border:1px solid var(--line);border-radius:6px}} .filters button{{padding:6px 12px;border:1px solid var(--line);border-radius:6px;background:#fff;cursor:pointer}} .filters button.on{{background:var(--accent);color:#fff}}
.foot{{padding:20px 64px 40px;color:var(--muted);font-size:12.5px;text-align:center}} td.reason{{min-width:300px}}
@media (max-width:760px){{.page{{padding:20px 18px}} .cover{{padding:60px 22px}} .twocol{{grid-template-columns:1fr}} .toc{{columns:1}} .cover .co{{font-size:32px}}}}
@media print{{body{{background:#fff}} .doc{{box-shadow:none;margin:0;max-width:none}} .noprint,.filters{{display:none}} .cover{{min-height:90vh;break-after:page}} .page{{padding:0 6px}}
 h2{{break-before:page;break-after:avoid}} h3,h4{{break-after:avoid}} .finding{{break-before:page}} table,figure,.callout{{break-inside:avoid}} tr{{break-inside:avoid}} @page{{margin:16mm 14mm}}}}
</style></head><body><div class="doc">
<header class="cover"><div class="co">{cl}</div><div class="tt">Security Assessment Findings Report</div><div class="rule"></div>
<p>Business Confidential</p><p>Evidence period: {e(window)}</p><p>Source data: {e(source_name)}</p><p>Version 1.0</p></header>
<div class="page">
{error_banner}
<h2 style="break-before:auto">Table of Contents</h2><ol class="toc" style="list-style:none">{toc_html}</ol>

<h2 id="confidentiality">Confidentiality Statement</h2>
<p>This document is the exclusive property of {cl} and the assessment team. It contains proprietary and confidential information. Duplication, redistribution, or use, in whole or in part, in any form, requires consent of both parties.</p>
<p>{cl} may share this document with auditors under non-disclosure agreements to demonstrate security assessment compliance.</p>

<h2 id="disclaimer">Disclaimer</h2>
<p>This assessment is a snapshot in time. The findings and recommendations reflect the evidence gathered during the observation period and not any changes made outside of it.</p>
<p>The assessment rests on the evidence supplied with each finding and did not include new testing against any system. It does not evaluate every security control. It prioritizes the weaknesses an attacker would exploit first. Similar assessments should be repeated on a regular schedule by internal or third-party reviewers to confirm that controls continue to hold.</p>

<h2 id="contacts">Contact Information</h2>
<table class="grid"><thead><tr><th>Asset owner team</th><th>Scope of findings</th><th>Contact</th></tr></thead><tbody>{owner_rows}</tbody></table>

<h2 id="overview">Assessment Overview</h2>
<p>For findings first observed between {e(window)}, {cl}'s scanning and testing produced {len(results)} raw findings. These were adjudicated to separate real, exploitable issues from false alarms and from questions the evidence cannot answer. Phases of the assessment:</p>
<ul><li><b>Planning:</b> The raw findings file was read as real CSV, preserving multiline fields, and every row was given exactly one outcome.</li>
<li><b>Discovery:</b> Request IDs, code revisions, identities and side-effect boundaries were correlated across requests, responses, logs, traces, source excerpts, manifests and owner comments.</li>
<li><b>Adjudication:</b> Each finding received two independent reviews, with a third on disagreement. Every quoted piece of evidence was checked to appear word for word in the source data.</li>
<li><b>Reporting:</b> Confirmed findings were scored with CVSS 3.1, prioritized by environment exposure, grouped into issue types and correlated into attack chains.</li></ul>
<h4>Assessment Components</h4>
<p><b>Evidence-based finding adjudication.</b> Each finding is decided on what the evidence shows about the security boundary, not on the scanner label. Compensating-control claims are treated as claims until shown to exist and to cover the path in question.</p>

<h2 id="severity">Finding Severity Ratings</h2>
<p>The following table defines levels of severity and the corresponding CVSS v3 score range used throughout this document.</p>
<table class="grid"><thead><tr><th>Severity</th><th>CVSS v3 Score Range</th><th>Definition</th></tr></thead><tbody>{sev_rows}</tbody></table>

<h2 id="scope">Scope</h2>
<table class="grid"><thead><tr><th>Environment</th><th>Systems with findings</th></tr></thead><tbody>{scope_rows}</tbody></table>
<h4>Scope Exclusions</h4><p>No host was contacted and no new attacks were run. Conclusions rest only on the evidence supplied.</p>
<h4>Client Allowances</h4><p>{cl} supplied the raw findings with attached evidence: requests, responses, logs, traces, code excerpts, deployment manifests and owner comments. No other access was provided.</p>

<h2 id="exec">Executive Summary</h2>
<p>{e(exec_text)}</p>
<div class="callout"><b>{e('Production exposure: ' + str(len(prod)) + ' confirmed findings, ' + str(prod_hi) + ' High or Critical.')}</b>
 {f"Findings in the same environment also combine into {_plural(n_conf_chains, 'fully confirmed attack chain', 'fully confirmed attack chains')}, described below." if n_conf_chains else ''}</div>

<h3 id="attack-summary">Attack Summary</h3>
<p>The following tables describe how confirmed findings in one environment combine, step by step. The evidence does not link them to a single recorded attack, so these show combined exposure, not an incident. A step marked still under review should be settled first.</p>
{_attack_summary(list(chains), by_id)}

<h3 id="strengths">Security Strengths</h3>
<p>Not every report was a real weakness. In these areas the evidence shows the protection worked as intended.</p>
{strengths or "<p class='muted'>None recorded.</p>"}

<h3 id="weaknesses">Security Weaknesses</h3>
<p>The four highest-priority weaknesses, in order. Each has a full entry under Technical Findings.</p>
{weak}

<h3 id="impact">Vulnerabilities by Impact</h3>
<p>The following charts illustrate the confirmed vulnerabilities by impact, environment and type.</p>
<div class="twocol"><div><h4>Confirmed findings by severity</h4>{sev_bars}<h4>Outcome of all {len(results)} findings</h4>{donut}</div>
<div><h4>By environment</h4>{heat}<h4>By issue type</h4>{type_bars}</div></div>

<h2 id="findings">Technical Findings</h2>
<h3 id="priority">Top Priority Findings</h3>
<p>The three confirmed findings with the highest priority. Priority is the CVSS score weighted by how close the system is to production ({e(weights)}).</p>
{priority_html}
<h3 id="confirmed">All Confirmed Findings by Issue Type</h3>
<p>{counts['Confirmed']} confirmed findings in {len(groups)} issue types, ordered by priority. Each entry shows one worked example and lists every system where the issue was confirmed.</p>
{''.join(issue_html)}

<h2 id="informational">Additional Reports and Scans (Informational)</h2>
<h3>Findings that need more evidence ({counts['Needs Review']})</h3>
<p>These are not dismissed. The deciding step was not observed, or the evidence conflicts in a way only more data can settle. Treat the follow-up in each group as the test plan.</p>
{nr_html or '<p>None.</p>'}
<h3>False positives ({len(fp)})</h3>
<p>The evidence shows the reported condition is absent or unreachable on the deployed path. These can be closed.</p>
<div class="tablewrap">{fp_html}</div>

<h2 id="method">Assessment Method and Limitations</h2>
<ul>
<li><b>Two independent reviews per finding.</b> The second review did not see the first and was set up to challenge both outcomes. {"Where they disagreed, or scored severity far apart, a third review decided; " + _plural(adjudicated, "finding needed", "findings needed") + " this." if adjudicated else "They agreed on every finding, so no tie-break was needed."}</li>
<li><b>Evidence must be checkable.</b> Confirmed needs at least {MIN_CITATIONS_CONFIRMED} verified citations including runtime evidence, and the deciding step must have been observed. {_plural(evidence_gated, "verdict was", "verdicts were") if evidence_gated else "No verdicts were"} downgraded to Needs Review by these checks.</li>
<li><b>Consistency check.</b> Findings with the same scenario and evidence must get the same answer. Where reviews still split, the decisive verdicts moved to Needs Review ({_plural(consistency, "finding", "findings")}).</li>
<li><b>Claims are not controls.</b> Owner statements, claimed protections and missing log entries are never treated as proof. Source, manifest and runtime records are matched by revision and date before being combined.</li>
<li><b>Scoring.</b> CVSS 3.1 vectors are chosen from the evidence and scores computed by the published formula. Priority = CVSS &times; environment weight. Fix now is 7.0 or above, Plan a fix 3.0 or above, Backlog below that. Model confidence is reported but does not change the order.</li>
<li><b>Limits.</b> Assessment uses only the supplied evidence. Reviews were carried out with automated analysis ({e(model)}) under the checks above. {_plural(errors, "finding", "findings") + " could not be reviewed and" if errors else "No findings failed review, and none"} {"is" if errors == 1 else "are"} listed as needs review for that reason.</li></ul>

<h2 id="appendix" class="noprint">Appendix: Every Finding</h2>
<div class="noprint"><div class="filters"><input id="q" placeholder="Filter by ID, system, title, reasoning..." aria-label="Filter findings">
<button data-f="" class="on">All</button><button data-f="Confirmed">Confirmed</button><button data-f="False Positive">False positive</button><button data-f="Needs Review">Needs review</button></div>
<div class="tablewrap"><table id="all" class="grid"><thead><tr><th>ID</th><th>First seen</th><th>Title</th><th>System</th><th>Env</th><th>Raised by</th><th>Outcome</th><th>Conf.</th><th>Reasoning</th></tr></thead>
<tbody>{all_rows}</tbody></table></div></div>
</div><div class="foot">{cl} Security Assessment Findings Report &middot; Business Confidential &middot; Version 1.0</div></div>
<script>
(function(){{var q=document.getElementById('q'),f='',rows=[].slice.call(document.querySelectorAll('#all tbody tr'));
function apply(){{var t=q.value.toLowerCase();rows.forEach(function(r){{var ok=(!f||r.dataset.cls===f)&&(!t||r.textContent.toLowerCase().indexOf(t)>-1);r.style.display=ok?'':'none';}});}}
q.addEventListener('input',apply);[].forEach.call(document.querySelectorAll('.filters button'),function(b){{b.addEventListener('click',function(){{
[].forEach.call(document.querySelectorAll('.filters button'),function(x){{x.classList.remove('on')}});b.classList.add('on');f=b.dataset.f;apply();}});}});
function openFor(h){{var t=h&&document.getElementById(h.slice(1));var o=t;while(o){{if(o.tagName==='DETAILS')o.open=true;o=o.parentElement;}}if(t)t.scrollIntoView();}}
window.addEventListener('hashchange',function(){{openFor(location.hash)}});openFor(location.hash);}})();
</script></body></html>"""


# ---------------------------------------------------------------------------
# Client report: confirmed findings only
# ---------------------------------------------------------------------------
# The analyst report above carries the whole adjudication (false positives, open
# questions, method). This one is for the customer: only findings that were
# confirmed, each with its CVSS 3.1 score, plain-language business impact and
# recommended fix, ordered by what to do first.
def _client_fix(text) -> str:
    steps, harden, verify = split_fix(text)
    out = ""
    if steps or harden:
        out += "<ol class='steps'>" + "".join(f"<li>{prose(s)}</li>" for s in steps + harden) + "</ol>"
    if verify:
        out += "<p class='verify'><b>How to check the fix worked.</b> " + prose(" ".join(verify)) + "</p>"
    return out


def client_issue_key(r: dict) -> tuple:
    """One client section per distinct flaw: same issue type and same scored scenario.
    CVSS vectors are aligned across identical scenarios, so the vector separates
    two different flaws that share a type (SQL injection in a lookup vs in an update)."""
    return (issue_key(r), r.get("cvss_vector") or "")


def _client_issue(n: int, rows: List[dict]) -> str:
    lead = rows[0]  # highest-priority instance
    sev = lead.get("cvss_severity") or "None"
    proof = [c.get("supports", "") for c in (lead.get("evidence") or []) if c.get("supports")][:3]
    why = ("<p class='why'><b>How it was confirmed.</b> " + " ".join(
        prose(p[:1].upper() + p[1:].rstrip(".") + ".") for p in proof) + "</p>") if proof else ""
    prod = sum(1 for r in rows if r["environment"].strip().lower() == "production")
    inst = "".join(
        f"<tr><td>{e(r['finding_id'])}</td><td><code>{e(r['asset'])}</code></td>"
        f"<td><span class='env env-{e(r['environment'].strip().lower())}'>{e(r['environment'])}</span></td>"
        f"<td>{e((r.get('first_observed_utc') or '')[:10])}</td><td>{e(TIER_LABEL.get(r.get('priority_tier'), ''))}</td></tr>"
        for r in sorted(rows, key=lambda r: (r["environment"].strip().lower() != "production", r["asset"], r["finding_id"])))
    note = ("" if len(rows) == 1 else
            f"<p class='why'>Impact and fix are described from the example on <code>{e(lead['asset'])}</code> ({e(lead['finding_id'])}). "
            f"The same flaw was confirmed on each system in the table above.</p>")
    return f"""
<article class="entry sc-b-{e(sev.lower())}" id="issue-{n}">
  <header><span class="num">{n}</span>
    <div><h3>{e(display_title(lead))}</h3>
      <div class="sub">{len(rows)} system{'s' if len(rows) != 1 else ''} affected{f', {prod} in production' if prod else ''}</div></div>
    <div class="score"><span class="sevtag sc-{e(sev.lower())}">{e(SEV_DISPLAY.get(sev, sev))}</span><b>{e(lead.get('cvss_score') if lead.get('cvss_score') is not None else 'n/a')}</b><small>CVSS 3.1</small></div></header>
  <p class="vec"><code>{e(lead.get('cvss_vector') or 'unscored')}</code></p>
  <div class="cols"><section><h4>Business impact</h4>{_impact_block(lead.get('business_impact'))}{why}</section>
  <section class="fix"><h4>Recommended fix</h4>{_client_fix(lead.get('recommended_fix'))}</section></div>
  <h4 style="margin-top:12px">Where this was found</h4>
  <table class="where"><thead><tr><th>Finding ID</th><th>Endpoint</th><th>Environment</th><th>First observed</th><th>Fix order</th></tr></thead><tbody>{inst}</tbody></table>
  {note}
</article>"""


def build_client_report(results: List[dict], source_name: str, chains: List[dict] = (), client: str = "Client") -> str:
    cl = e(client)
    confirmed = sorted((r for r in results if r["classification"] == "Confirmed"), key=_priority_key)
    sev = collections.Counter(r.get("cvss_severity") for r in confirmed)
    prod = [r for r in confirmed if r["environment"].strip().lower() == "production"]
    prod_hi = sum(1 for r in prod if r.get("cvss_severity") in ("Critical", "High"))
    n_fp = sum(1 for r in results if r["classification"] == "False Positive")
    n_nr = sum(1 for r in results if r["classification"] == "Needs Review")
    by_issue: Dict[tuple, List[dict]] = {}
    for r in confirmed:
        by_issue.setdefault(client_issue_key(r), []).append(r)

    def order(rows):  # worst severity first, then production exposure, then reach
        lead = rows[0]
        return (SEV_ORDER.get(lead.get("cvss_severity"), 5), -(lead.get("cvss_score") or 0),
                -sum(1 for r in rows if r["environment"].strip().lower() == "production"), -len(rows), lead["finding_id"])
    issues = sorted(by_issue.values(), key=order)
    number = {id(rows): i for i, rows in enumerate(issues, 1)}
    seen = sorted(r.get("first_observed_utc", "")[:10] for r in results if r.get("first_observed_utc"))
    window = _date_window(seen, "the review period")
    best_tier = lambda rows: min((r.get("priority_tier") or "NOTE" for r in rows), key={"CHASE": 0, "LOOK": 1, "NOTE": 2}.get)
    index_rows = "".join(
        f"<tr><td>{number[id(rows)]}</td><td><a href='#issue-{number[id(rows)]}'>{e(display_title(rows[0]))}</a></td>"
        f"{_sev_cell(rows[0].get('cvss_severity'))}<td class='n'>{e(rows[0].get('cvss_score'))}</td><td class='n'>{len(rows)}</td>"
        f"<td>{_env_chips(rows)}</td><td>{e(TIER_LABEL.get(best_tier(rows), ''))}</td></tr>" for rows in issues)
    body = ""
    for band, label in (("Critical", "Critical"), ("High", "High"), ("Medium", "Moderate"), ("Low", "Low")):
        rows_b = [rows for rows in issues if rows[0].get("cvss_severity") == band]
        if rows_b:
            n_find = sum(len(x) for x in rows_b)
            body += (f"<h2 id='sev-{band.lower()}'>{label} severity <span class='count'>{len(rows_b)} issue{'s' if len(rows_b) != 1 else ''}, "
                     f"{n_find} finding{'s' if n_find != 1 else ''}</span></h2>"
                     + "".join(_client_issue(number[id(rows)], rows) for rows in rows_b))
    first = "".join(
        f"<li><b><a href='#issue-{number[id(rows)]}'>{e(display_title(rows[0]))}</a></b> "
        f"<span class='muted'>({len(rows)} system{'s' if len(rows) != 1 else ''}, CVSS {e(rows[0].get('cvss_score'))})</span><br>"
        f"{prose(_trim((split_fix(rows[0].get('recommended_fix'))[0] or [''])[0], 230))}</li>" for rows in issues[:3])
    sev_bars = _bar_rows([(SEV_DISPLAY.get(s, s), sum(1 for rows in issues if rows[0].get('cvss_severity') == s), SEV_COLOR[s], "")
                          for s in ("Critical", "High", "Medium", "Low")], max(1, len(issues)))
    heat = _heatmap(confirmed).replace(">Medium<", ">Moderate<")
    sev_rows = "".join(f"<tr><td class='sevcell sc-{n.lower() if n != 'Moderate' else 'medium'}'>{n}</td><td>{rng}</td><td>{d}</td></tr>" for n, rng, d in SEV_DEFS[:4])
    prod_issues = sum(1 for rows in issues if any(r["environment"].strip().lower() == "production" for r in rows))
    prod_systems = len({r["asset"] for r in prod})
    lead_in = (f"Every one of the {len(issues)} issues is" if prod_issues == len(issues) else f"{prod_issues} of the {len(issues)} issues are")
    headline = (f"{lead_in} present in production: {len(prod)} findings on {prod_systems} production "
                f"system{'s' if prod_systems != 1 else ''}, {prod_hi} of them rated High or Critical." if prod
                else "None of the confirmed findings affects production.")
    n_issues = lambda sv: sum(1 for rows in issues if rows[0].get("cvss_severity") == sv)
    sev_table = "".join(
        f"<tr><td class='sevcell sc-{sv.lower()}'>{lab}</td><td class='n'>{n_issues(sv)}</td><td class='n'>{sev.get(sv, 0)}</td></tr>"
        for sv, lab in (("Critical", "Critical"), ("High", "High"), ("Medium", "Moderate"), ("Low", "Low")))
    sev_table += f"<tr class='tot'><td><b>Total</b></td><td class='n'>{len(issues)}</td><td class='n'>{len(confirmed)}</td></tr>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{cl} Confirmed Security Findings</title>
<style>
:root{{--bg:#eceef2;--paper:#fff;--ink:#1a1f2b;--muted:#5b6475;--line:#d9dde4;--accent:#13294b;--soft:#f1f4f8;--red:#b3261e;--crit:#8c1230;--high:#c8431a;--med:#c28a14;--low:#3f7a4d}}
*{{box-sizing:border-box;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 Calibri,"Segoe UI",-apple-system,Roboto,Arial,sans-serif}}
a{{color:#1f4e8c}} .doc{{max-width:960px;margin:24px auto;background:var(--paper);box-shadow:0 2px 14px rgba(0,0,0,.12)}}
.cover{{padding:110px 60px 80px;background:var(--accent);color:#fff}} .cover .co{{font-size:44px;font-weight:700}} .cover .tt{{font-size:28px;font-weight:300;margin-top:4px}}
.cover .rule{{width:90px;height:5px;background:var(--red);margin:24px 0}} .cover p{{margin:2px 0;opacity:.92}}
.page{{padding:20px 60px 30px}} h2{{font-size:24px;color:var(--accent);border-bottom:3px solid var(--red);padding-bottom:5px;margin:34px 0 10px;scroll-margin-top:12px}}
h3{{font-size:18px;margin:0}} h4{{font-size:12.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:4px 0 6px}} p{{margin:5px 0 9px}}
code{{font:12.5px/1.45 ui-monospace,Menlo,monospace;background:rgba(127,127,127,.13);padding:1px 5px;border-radius:4px;word-break:break-word}} .muted{{color:var(--muted)}}
.tiles{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:14px 0}} .tile{{border:1px solid var(--line);border-top:5px solid var(--c);border-radius:8px;padding:12px 14px}} .tile b{{display:block;font-size:30px;line-height:1.1}} .tile span{{color:var(--muted);font-size:13px}}
.callout{{border-left:5px solid var(--red);background:var(--soft);padding:12px 16px;margin:14px 0}} .callout .big{{font-size:19px;font-weight:700}}
.twocol{{display:grid;grid-template-columns:1fr 1fr;gap:24px}} .bars .brow{{display:grid;grid-template-columns:minmax(110px,40%) 1fr 26px;gap:8px;align-items:center;margin:5px 0;font-size:13px}}
.bt{{height:13px;background:var(--line);border-radius:3px;overflow:hidden;display:block}} .bf{{display:block;height:100%}} .bv{{text-align:right}} .bl a{{color:var(--ink);text-decoration:none}}
table{{width:100%;border-collapse:collapse;font-size:13px}} th,td{{text-align:left;padding:6px 8px;border:1px solid var(--line);vertical-align:top}} th{{background:var(--accent);color:#fff}} td.n{{text-align:center;font-weight:700}}
table.where th{{background:var(--soft);color:var(--accent)}} table.sevsum{{width:auto;min-width:360px;margin:6px 0 12px}} table.sevsum tr.tot td{{background:var(--soft)}}
.sevcell{{font-weight:700;color:#fff;text-align:center;white-space:nowrap}} .sc-critical{{background:var(--crit)}} .sc-high{{background:var(--high)}} .sc-medium{{background:var(--med)}} .sc-low{{background:var(--low)}} .sc-none{{background:#777}}
.sevtag{{display:inline-block;font-size:12px;font-weight:700;padding:2px 10px;border-radius:999px;color:#fff}}
.env{{display:inline-block;font-size:12px;font-weight:600;padding:1px 8px;border-radius:6px;background:var(--soft);border:1px solid var(--line);margin:1px 3px 1px 0;white-space:nowrap}} .env-production{{background:rgba(179,38,30,.12);border-color:var(--red)}}
table.heat{{border-collapse:separate;border-spacing:3px;width:auto}} table.heat th{{border:0;background:none;color:var(--muted);text-align:center;font-size:12px}} table.heat th[scope=row]{{text-align:left;color:var(--ink)}}
td.hm{{border:0;text-align:center;font-weight:700;border-radius:5px;min-width:56px;height:30px;background:color-mix(in srgb,var(--c) calc(var(--a)*100%),transparent)}} td.tot{{border:0;text-align:center;font-weight:700}}
.entry{{border:1px solid var(--line);border-left:6px solid var(--accent);border-radius:8px;padding:14px 18px;margin:16px 0}}
.sc-b-critical{{border-left-color:var(--crit)}} .sc-b-high{{border-left-color:var(--high)}} .sc-b-medium{{border-left-color:var(--med)}} .sc-b-low{{border-left-color:var(--low)}}
.entry header{{display:grid;grid-template-columns:36px 1fr auto;gap:12px;align-items:start}} .num{{background:var(--soft);border-radius:50%;width:32px;height:32px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px}}
.sub{{color:var(--muted);font-size:13px;margin-top:3px}} .score{{text-align:center}} .score b{{display:block;font-size:30px;line-height:1.1}} .score small{{color:var(--muted)}}
.vec{{margin:6px 0 0}} .cols{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:8px}} .lead{{font-weight:600}} .why{{font-size:13px;color:var(--muted)}}
.fix{{background:var(--soft);border-radius:8px;padding:8px 14px}} ol.steps{{margin:2px 0 6px;padding-left:20px}} ol.steps li{{margin:5px 0}} .verify{{font-size:13px}}
.count{{font-size:13px;font-weight:400;background:var(--soft);padding:1px 9px;border-radius:999px;color:var(--muted)}} .foot{{padding:16px 60px 36px;color:var(--muted);font-size:12.5px;text-align:center}}
@media (max-width:760px){{.page{{padding:16px 16px}} .cover{{padding:60px 20px}} .twocol,.cols{{grid-template-columns:1fr}} .tiles{{grid-template-columns:repeat(2,1fr)}} .entry header{{grid-template-columns:32px 1fr}} .score{{grid-column:1/-1;text-align:left}}}}
@media print{{body{{background:#fff}} .doc{{box-shadow:none;margin:0;max-width:none}} .cover{{min-height:90vh;break-after:page}} .page{{padding:0 4px}} h2{{break-before:page}} .entry{{break-inside:avoid}} @page{{margin:16mm 14mm}}}}
</style></head><body><div class="doc">
<header class="cover"><div class="co">{cl}</div><div class="tt">Confirmed Security Findings and Remediation Plan</div><div class="rule"></div>
<p>Confidential</p><p>Evidence period: {e(window)}</p></header>
<div class="page">
<h2 style="break-before:auto">Summary</h2>
<p>Your security tooling raised {len(results)} findings. Each was checked against the evidence behind it, and <b>{len(confirmed)}</b> are confirmed real.
Where the same flaw appears on several systems it is reported once, with every affected endpoint and finding ID listed under it. The {len(confirmed)} findings are therefore
<b>{len(issues)} distinct issues</b>. A <i>finding</i> is one flaw on one system. An <i>issue</i> is the same flaw wherever it occurs. Each issue has its score, business impact and fix.</p>
<p>The other {len(results) - len(confirmed)} findings are not in this report. {n_fp} were checked and are not exploitable as reported, so no action is needed. {n_nr} could not be decided from the evidence supplied: they are neither confirmed nor ruled out, and each needs one specific follow-up test before it can be settled.</p>
<div class="callout"><div class="big">{e(headline)}</div>Start with the three issues below.</div>
<table class="sevsum"><thead><tr><th>Severity</th><th>Distinct issues</th><th>Findings</th></tr></thead><tbody>{sev_table}</tbody></table>
<h4>Fix these first</h4><ol class="steps">{first}</ol>
<div class="twocol"><div><h4>Findings by environment and severity</h4>{heat}</div><div><h4>Distinct issues by severity</h4>{sev_bars}</div></div>

<h2 id="index">All issues at a glance</h2>
<table><thead><tr><th>#</th><th>Issue</th><th>Severity</th><th>CVSS</th><th>Systems</th><th>Environments</th><th>Fix order</th></tr></thead><tbody>{index_rows}</tbody></table>
<h4 style="margin-top:14px">How severity is rated (CVSS 3.1)</h4><table><thead><tr><th>Severity</th><th>Score</th><th>What it means</th></tr></thead><tbody>{sev_rows}</tbody></table>
<p class="muted">Issues are ordered by severity, then by how many production systems are affected, then by how many systems in total. Fix order combines the CVSS score with how close the system is to production (production counts fully, disaster-recovery next, then staging, then sandbox); it is shown for each affected system.</p>
{body}
<h2>About this report</h2>
<p>This is a snapshot in time based on the evidence gathered with each finding, from {e(window)}. No new testing was run against any system for this report. The {n_fp} findings shown not to be exploitable and the {n_nr} that need more evidence are not listed here. Repeat the review after fixes ship to confirm that the controls hold.</p>
</div><div class="foot">{cl} Confirmed Security Findings &middot; Confidential</div></div></body></html>"""


# ============================================================================
# Command line
# ============================================================================
DEFAULT_MODEL = "claude-opus-5-5"
DEFAULT_FALLBACK = "claude-opus-4-8"
HERE = Path(__file__).resolve().parent


def choose_csv() -> Path:
    candidates = sorted({p.resolve() for d in (Path.cwd(), HERE / "data") if d.is_dir() for p in d.glob("*.csv")})
    if candidates:
        print("CSV files found:")
        for i, p in enumerate(candidates, 1):
            print(f"  [{i}] {p}")
    while True:
        try:
            ans = input("Select a number or enter a path to a .csv file: ").strip().strip("'\"")
        except EOFError:
            sys.exit("no CSV selected")
        if ans.isdigit() and candidates and 1 <= int(ans) <= len(candidates):
            return candidates[int(ans) - 1]
        p = Path(ans).expanduser()
        if p.is_file() and p.suffix.lower() == ".csv":
            return p
        print(f"  not a .csv file: {ans!r}")


def rebuild_reports(out: Path, source_name: str, source_csv: Optional[Path] = None, client: Optional[str] = None) -> int:
    """Regenerate both HTML reports from saved results. No model calls."""
    try:
        results = [json.loads(line) for line in (out / "assessments.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        chains = json.loads((out / "attack_chains.json").read_text(encoding="utf-8"))
        summary = json.loads((out / "run_summary.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: cannot rebuild reports from {out}: {exc}", file=sys.stderr)
        return 2
    for r in results:  # fix order is derived from the saved CVSS score, so a policy change needs no model calls
        if r["classification"] == "Confirmed":
            r["priority_score"], r["priority_tier"] = priority(r.get("cvss_score"), r["environment"])
    write_classified(out / "classified_findings.csv", results)
    (out / "assessments.jsonl").write_text("".join(json.dumps(r, default=str) + "\n" for r in results), encoding="utf-8")
    used = summary.get("model_calls_answered") or {}
    model_desc = ", ".join(f"{m} ({n} calls)" for m, n in used.items()) or ", ".join(summary.get("model_chain", []))
    name = client or summary.get("client_name") or "Client"
    analyst = build_report(results, source_name, model_desc, chains, name)
    client_page = build_client_report(results, source_name, chains, name)
    (out / "findings_report.html").write_text(analyst, encoding="utf-8")
    (out / "client_report.html").write_text(client_page, encoding="utf-8")
    leftover = report_style_issues(analyst) + report_style_issues(client_page)
    if leftover:
        print(f"WARNING: report prose still contains: {', '.join(sorted(set(leftover)))}", file=sys.stderr)
    print(f"Rebuilt {out}/findings_report.html and {out}/client_report.html from {len(results)} saved assessments")
    if source_csv and source_csv.exists():
        try:
            n = write_filled_input(out / f"{source_csv.stem}-filled.csv", source_csv, results)
            print(f"Rebuilt {out}/{source_csv.stem}-filled.csv ({n} rows filled)")
        except (InputError, OSError) as exc:
            print(f"warning: could not rebuild the filled input CSV: {exc}", file=sys.stderr)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Classify scanner findings as Confirmed / False Positive / Needs Review.")
    ap.add_argument("--csv", type=Path, help="input findings CSV (prompted if omitted)")
    ap.add_argument("--out", type=Path, default=HERE / "out", help="output directory (default: ./out)")
    ap.add_argument("--model", default=DEFAULT_MODEL, help=f"primary Claude model id (default {DEFAULT_MODEL})")
    ap.add_argument("--fallback-model", default=DEFAULT_FALLBACK,
                    help=f"comma-separated fallback model ids if the primary fails or is denied "
                         f"(default {DEFAULT_FALLBACK}; '' for none)")
    ap.add_argument("--effort", default="high", help="claude --effort level (low/medium/high/xhigh/max; '' to omit)")
    ap.add_argument("--workers", type=int, default=4, help="parallel findings (default 4)")
    ap.add_argument("--timeout", type=int, default=420, help="per-call timeout seconds")
    ap.add_argument("--limit", type=int, help="only assess the first N findings")
    ap.add_argument("--ids", help="comma-separated finding_ids to assess")
    ap.add_argument("--claude-bin", default="claude")
    ap.add_argument("--client-name", help="name shown in the report headings (default: Client)")
    ap.add_argument("--no-cache", action="store_true", help="ignore cached model responses")
    ap.add_argument("--rebuild-reports", action="store_true",
                    help="rebuild both HTML reports from the saved out/assessments.jsonl; no model calls")
    ap.add_argument("--self-test", action="store_true", help="run the built-in test suite and exit")
    args = ap.parse_args(argv)
    if args.self_test:
        result = unittest.main(module=__name__, argv=[sys.argv[0]], exit=False, verbosity=2).result
        return 0 if result.wasSuccessful() else 1

    if args.rebuild_reports:
        return rebuild_reports(args.out, args.csv.name if args.csv else "findings CSV", args.csv, args.client_name)

    csv_path = args.csv or choose_csv()
    try:
        rows = read_findings(csv_path)
        context = dataset_context(rows)  # computed over the whole file, before any --ids/--limit filter
        rows.sort(key=time_sort_key)     # process and report in chronological order
    except (InputError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.ids:
        want = {i.strip() for i in args.ids.split(",") if i.strip()}
        unknown = want - {r["finding_id"] for r in rows}
        if unknown:
            print(f"warning: unknown finding_id(s) ignored: {', '.join(sorted(unknown))}", file=sys.stderr)
        rows = [r for r in rows if r["finding_id"] in want]
    if args.limit is not None:
        rows = rows[: max(0, args.limit)]
    if not rows:
        print("error: no findings selected", file=sys.stderr)
        return 2
    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    models = [args.model] + [m.strip() for m in (args.fallback_model or "").split(",") if m.strip() and m.strip() != args.model]
    llm = ClaudeCLI(models, effort=args.effort or None, binary=args.claude_bin, timeout=args.timeout,
                    cache_dir=None if args.no_cache else HERE / ".cache")
    try:
        llm.check_available()
    except LLMError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"Assessing {len(rows)} findings from {csv_path.name} with {llm.model} ({args.workers} workers)")
    t0 = time.time()
    tally = collections.Counter()

    def progress(done, total, res):
        tally[res["classification"]] += 1
        print(f"[{done:>4}/{total}] {res['finding_id']}  {res['classification']:<14} conf={res['confidence']:<4} "
              f"{res['assessor_agreement'][:60]}  | C={tally['Confirmed']} FP={tally['False Positive']} "
              f"NR={tally['Needs Review']}  ${llm.stats.cost_usd:.2f}", flush=True)

    try:
        results = run(rows, llm, workers=args.workers, progress=progress, context=context)
    except KeyboardInterrupt:
        print("\ninterrupted; completed model calls are cached - re-run the same command to resume", file=sys.stderr)
        return 130

    used = {m: n for m, n in llm.used.items() if n}
    model_desc = ", ".join(f"{m} ({n} calls)" for m, n in sorted(used.items(), key=lambda kv: -kv[1])) or llm.model
    gate_actions = consistency_gate(rows, results)
    for a in gate_actions:
        print(f"[consistency gate] {a['finding_id']}: {a['from']} -> Needs Review (group {a['group']})")
    harmonised = harmonise(rows, results)
    print(f"[harmonise] {sum(1 for c in harmonised if c['field'] == 'cvss_vector')} CVSS vector(s) and "
          f"{sum(1 for c in harmonised if c['field'] == 'confidence')} confidence value(s) aligned across identical evidence")
    chains = correlate_chains(results)
    for c in chains:
        print(f"[chain] {c['chain_id']} ({c['status']}): " + " -> ".join(
            "/".join(f["finding_id"] for f in st["findings"]) for st in c["stages"]))
    # Outputs are written only after the consistency gate and chain correlation have run.
    write_classified(out / "classified_findings.csv", results)
    filled_path = out / f"{csv_path.stem}-filled.csv"
    n_filled = write_filled_input(filled_path, csv_path, results)
    print(f"Filled candidate_classification and candidate_reasoning for {n_filled} rows in {filled_path}")
    with open(out / "assessments.jsonl", "w", encoding="utf-8") as fh:
        for r in results:
            fh.write(json.dumps(r, default=str) + "\n")
    (out / "attack_chains.json").write_text(json.dumps(chains, indent=1), encoding="utf-8")
    audit = consistency_audit(rows, results)
    audit["consistency_gate_actions"] = gate_actions
    audit["harmonised"] = harmonised
    (out / "audit.json").write_text(json.dumps(audit, indent=1, default=str), encoding="utf-8")
    errors = sum(1 for r in results if r.get("error"))
    stats = {"client_name": args.client_name or "Client", "agents": AGENTS, "model_chain": llm.models, "model_calls_answered": used, "models_disabled": llm.disabled,
             "effort": args.effort, "findings": len(results),
             "counts": dict(collections.Counter(r["classification"] for r in results)),
             "llm_calls": llm.stats.calls, "cache_hits": llm.stats.cache_hits, "failures": llm.stats.failures, "rows_failed": errors,
             "cost_usd_this_run": round(llm.stats.cost_usd, 2), "elapsed_s": round(time.time() - t0, 1),
             "consistency_audit": {k: audit[k] for k in ("scenario_groups", "split_groups", "minority_rows")}}
    (out / "run_summary.json").write_text(json.dumps(stats, indent=1), encoding="utf-8")
    page = build_report(results, csv_path.name, model_desc, chains, args.client_name or "Client")
    (out / "findings_report.html").write_text(page, encoding="utf-8")
    client_page = build_client_report(results, csv_path.name, chains, args.client_name or "Client")
    (out / "client_report.html").write_text(client_page, encoding="utf-8")
    leftover = report_style_issues(page)
    audit["report_style_issues"] = leftover
    (out / "audit.json").write_text(json.dumps(audit, indent=1, default=str), encoding="utf-8")
    if leftover:
        print(f"WARNING: report prose still contains: {', '.join(leftover)}", file=sys.stderr)
    print(json.dumps(stats, indent=1))
    print(f"Wrote {out}/: classified_findings.csv, findings_report.html, client_report.html, assessments.jsonl, attack_chains.json, audit.json, run_summary.json")
    for m, why in llm.disabled.items():
        print(f"NOTICE: {m} was unavailable ({why[:120]}); fallback model(s) answered instead - see run_summary.json",
              file=sys.stderr)
    if errors:
        print(f"WARNING: {errors} finding(s) could not be assessed and were routed to Needs Review. "
              f"Re-run the same command to retry them (successful calls are cached).", file=sys.stderr)
        return 3
    return 0




# ============================================================================
# Self-tests (python3 triage.py --self-test)
# ============================================================================
def _test_row(**kw):
    base = {
        "finding_id": "T-1", "asset": "api.example", "environment": "production", "finding_title": "IDOR",
        "category": "Authorization", "asset_owner": "Fleet API", "request_id": "req_abc",
        "observation": "Tenant B session retrieved tenant A vehicle record 4411 with full GPS history.",
        "validation_attempt": "Paired cross-tenant test returned HTTP 200 with the other tenant's data.",
        "raw_response": 'HTTP/1.1 200 | {"vehicle":4411,"org":"tenant-a"}',
        "claimed_compensating_controls": "Owner says a downstream ownership check exists.",
        "ticket_comment_thread": "[service-owner] please downgrade; UI does not expose this parameter",
        "evidence_gaps": "None material.",
        "candidate_classification": "", "candidate_reasoning": "",
    }
    base.update(kw)
    return base


CHECK_QUOTE = ("observation", "Tenant B session retrieved tenant A vehicle record 4411")


def _test_checklist(cls, category="Authorization", **override):
    """A checklist consistent with `cls`: every check yes (Confirmed), no (False Positive) or unknown (Needs Review).
    `override` maps a check id to an answer, or to a (answer, field, quote) tuple."""
    out = []
    for cid, _ in RUBRICS[category]["checks"]:
        answer = {"Confirmed": "yes", "False Positive": "no"}.get(cls, "unknown")
        field, quote = CHECK_QUOTE if answer != "unknown" else ("", "")
        o = override.get(cid)
        if isinstance(o, tuple):
            answer, field, quote = o
        elif o:
            answer = o
            field, quote = CHECK_QUOTE if o != "unknown" else ("", "")
        out.append({"id": cid, "answer": answer, "field": field, "quote": quote})
    return out


def _test_assessment(cls, quotes, conf=0.9, observed=True, vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                     checklist=None):
    return {
        "checklist": _test_checklist(cls) if checklist is None else checklist,
        "decisive_boundary": "cross-tenant read", "boundary_observed": observed, "provenance": "runtime",
        "compensating_controls": "claimed only", "classification": cls, "confidence": conf,
        "reasoning": "test", "evidence": [{"field": f, "quote": q, "supports": "x"} for f, q in quotes],
        "missing_evidence": "",
        "report": {"client_title": "t", "cvss_vector": vector if cls == "Confirmed" else "",
                   "cvss_rationale": "", "business_impact": "", "recommended_fix": ""},
    }


GOOD_QUOTES = [("observation", "Tenant B session retrieved tenant A vehicle record 4411"),
               ("raw_response", '{"vehicle":4411,"org":"tenant-a"}')]


def _synthetic_findings():
    """Four small findings: two scenarios, each reported twice by different scanners, with a fixed
    capture header set, a capture/log date offset, an unrelated request ID in the logs and a source
    revision that differs from the manifest."""
    rows = []
    for n, (title, obs, scanner) in enumerate([("IDOR", "Tenant B read tenant A record 1.", "ScannerA"),
                                               ("IDOR", "Tenant B read tenant A record 1.", "ScannerB"),
                                               ("SQLi", "A quote changed the executed SQL.", "ScannerA"),
                                               ("SQLi", "A quote changed the executed SQL.", "ScannerB")]):
        rid = f"req_row{n}"
        rows.append(_test_row(
            finding_id=f"S-{n}", finding_title=title, observation=obs, scanner_source=scanner, request_id=rid,
            first_observed_utc=f"2026-07-0{n + 1}T00:00:00Z", last_observed_utc=f"2026-07-0{n + 1}T12:00:00Z",
            raw_http_exchange=f"> GET /x\n> Host: a\n> Accept: */*\n> User-Agent: t\n> X-Request-ID: {rid}\n"
                              "< HTTP/1.1 200\n< Date: 2026-08-01T00:00:00Z\n< X-Cache: MISS\n",
            mixed_service_logs=json.dumps({"ts": "2026-08-11T00:00:01Z", "request_id": rid, "msg": "ok"}) + "\n"
                               + json.dumps({"ts": "2026-08-11T00:00:02Z", "request_id": "req_unrelated", "msg": "noise"}),
            source_code_excerpt="# attachment=a.py revision=aaaa11112222\nx = 1",
            deployment_manifest_excerpt="annotations:\n  org/image-source-revision: 'bbbb33334444'\n"
                                        "  org/evidence-collected-at: '2026-06-01T00:00:00Z'"))
    return rows


class TestCSVParsing(unittest.TestCase):
    def test_quoted_commas_and_newlines_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.csv"
            with open(p, "w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["finding_id", "observation"])
                w.writerow(["A-1", "line one, with comma\nline two, \"quoted\""])
                w.writerow(["A-2", "plain"])
            rows = read_findings(p)
            self.assertEqual([r["finding_id"] for r in rows], ["A-1", "A-2"])
            self.assertEqual(rows[0]["observation"], 'line one, with comma\nline two, "quoted"')

    def test_duplicate_ids_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.csv"
            p.write_text("finding_id,observation\nA,1\nA,2\n")
            with self.assertRaises(InputError):
                read_findings(p)


class TestEvidenceGates(unittest.TestCase):
    def test_confirmed_with_fabricated_evidence_becomes_needs_review(self):
        a = _test_assessment("Confirmed", [("raw_response", "HTTP/1.1 200 attacker downloaded /etc/shadow"),
                                     ("observation", "root shell obtained on the worker host")])
        g = apply_gates(_test_row(), a)
        self.assertEqual(g["classification"], "Needs Review")
        self.assertLessEqual(g["confidence"], 0.5)
        self.assertEqual(len(g["rejected_evidence"]), 2)

    def test_confirmed_without_runtime_evidence_becomes_needs_review(self):
        a = _test_assessment("Confirmed", [("claimed_compensating_controls", "Owner says a downstream ownership check exists"),
                                     ("ticket_comment_thread", "please downgrade; UI does not expose this parameter")])
        self.assertEqual(apply_gates(_test_row(), a)["classification"], "Needs Review")

    def test_confirmed_when_boundary_not_observed_becomes_needs_review(self):
        a = _test_assessment("Confirmed", GOOD_QUOTES, observed=False)
        self.assertEqual(apply_gates(_test_row(), a)["classification"], "Needs Review")

    def test_low_confidence_confirmed_becomes_needs_review(self):
        self.assertEqual(apply_gates(_test_row(), _test_assessment("Confirmed", GOOD_QUOTES, conf=0.55))["classification"],
                         "Needs Review")

    def test_well_evidenced_confirmed_survives(self):
        g = apply_gates(_test_row(), _test_assessment("Confirmed", GOOD_QUOTES))
        self.assertEqual(g["classification"], "Confirmed")
        self.assertEqual(len(g["verified_evidence"]), 2)

    def test_false_positive_resting_only_on_owner_claim_becomes_needs_review(self):
        a = _test_assessment("False Positive", [("claimed_compensating_controls", "Owner says a downstream ownership check exists")])
        self.assertEqual(apply_gates(_test_row(), a)["classification"], "Needs Review")

    def test_whitespace_differences_in_quotes_still_verify(self):
        a = _test_assessment("Confirmed", [("observation", "Tenant B   session\nretrieved tenant A vehicle"),
                                     ("raw_response", '{"vehicle":4411,"org":"tenant-a"}')])
        self.assertEqual(apply_gates(_test_row(), a)["classification"], "Confirmed")


class TestReviewRegressions(unittest.TestCase):
    def test_quoting_only_identifiers_cannot_confirm(self):
        r = _test_row(raw_http_exchange="> X-Request-ID: req_712f86a919b9\n< HTTP/1.1 200", request_id="req_712f86a919b9")
        a = _test_assessment("Confirmed", [("raw_http_exchange", "X-Request-ID: req_712f86a919b9"),
                                           ("finding_title", "IDOR"), ("request_id", "req_712f86a919b9")])
        self.assertEqual(apply_gates(r, a)["classification"], "Needs Review")

    def test_false_positive_on_source_only_with_image_mismatch_is_needs_review(self):
        r = _test_row(source_code_excerpt="cur.execute('SELECT id FROM fleets WHERE org_id = %s', (org_id,))",
                      ticket_comment_thread="[release-bot 11:41] candidate image differs from source attachment=true")
        a = _test_assessment("False Positive", [("source_code_excerpt", "SELECT id FROM fleets WHERE org_id = %s")])
        g = apply_gates(r, a)
        self.assertEqual(g["classification"], "Needs Review")
        self.assertEqual(g["gated_from"], "False Positive")
        r2 = dict(r, ticket_comment_thread="[release-bot 11:41] candidate image differs from source attachment=false")
        self.assertEqual(apply_gates(r2, a)["classification"], "False Positive")

    def test_confirmed_resting_on_analyst_narrative_alone_becomes_needs_review(self):
        row = _test_row(observation="Tenant B session retrieved tenant A vehicle record 4411",
                        validation_attempt="Two cross-tenant attempts returned tenant A rows in the seeded test")
        a = _test_assessment("Confirmed", [("observation", "Tenant B session retrieved tenant A vehicle record 4411"),
                                           ("validation_attempt", "Two cross-tenant attempts returned tenant A rows")])
        g = apply_gates(row, a)
        self.assertEqual(g["classification"], "Needs Review")
        self.assertIn("no captured request", " ".join(g["gate_reasons"]))

    def test_false_positive_on_source_only_when_revisions_differ_without_a_release_bot_note(self):
        row = _test_row(source_code_excerpt="# attachment=q.py revision=1111aaaa2222\ncur.execute('SELECT id FROM fleets WHERE org_id = %s', (org_id,))",
                        deployment_manifest_excerpt="annotations:\n  org/image-source-revision: '9999bbbb8888'")
        self.assertIs(extract_facts(row)["source_revision_matches_manifest"], False)
        a = _test_assessment("False Positive", [("source_code_excerpt", "SELECT id FROM fleets WHERE org_id = %s")])
        self.assertEqual(apply_gates(row, a)["classification"], "Needs Review")

    def test_denial_detection_is_narrow(self):
        transient = ["prompt is too long: 250000 tokens > 200000 maximum",
                     "EACCES: permission denied, open '/home/x/.claude.json'",
                     "The model is temporarily unavailable due to high load", "Service not available",
                     "Session not found"]
        for msg in transient:
            self.assertIsNone(_DENIED_RE.search(msg), msg)
        for msg in ["model: claude-opus-5-5 not found", "not_found_error: model", "invalid model name"]:
            self.assertIsNotNone(_DENIED_RE.search(msg), msg)
        self.assertNotIn(400, _DENIED_STATUS)

    def test_consistency_gate_routes_split_equivalent_rows_to_needs_review(self):
        base = [_test_row(), _test_row(finding_title="Other flaw", observation="A different observation entirely.")]
        twin_a, twin_b = dict(base[0], finding_id="EQ-1"), dict(base[0], finding_id="EQ-2", request_id="req_other")
        other = dict(base[1], finding_id="EQ-3")
        llm = FakeLLM(lambda s, m: _test_assessment("Needs Review", GOOD_QUOTES, conf=0.5))
        res = [assess_row(r, llm) for r in (twin_a, twin_b, other)]
        res[0].update(classification="False Positive", confidence=0.8)
        res[2].update(classification="Confirmed", confidence=0.9)  # no equivalent peer: untouched
        actions = consistency_gate([twin_a, twin_b, other], res)
        self.assertEqual([a["finding_id"] for a in actions], ["EQ-1"])
        self.assertEqual(res[0]["classification"], "Needs Review")
        self.assertLessEqual(res[0]["confidence"], NEEDS_REVIEW_CONFIDENCE_CAP)
        self.assertEqual(res[2]["classification"], "Confirmed")

    def test_rows_sort_chronologically_and_dataset_facts_cover_scanner_and_headers(self):
        rows = _synthetic_findings()
        ordered = sorted(reversed(rows), key=time_sort_key)
        self.assertLessEqual(ordered[0]["first_observed_utc"], ordered[-1]["first_observed_utc"])
        self.assertIn("manifest_collected", extract_facts(rows[0]))
        ctx = dataset_context(rows)
        self.assertIn("scanner_vs_scenario", ctx)
        self.assertIn("captured_request_headers", ctx)

    def test_harmonise_aligns_cvss_and_confidence_across_identical_evidence(self):
        base = _test_row()
        twins = [dict(base, finding_id=f"H-{i}", request_id=f"req_h{i}") for i in range(3)]
        vecs = ["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"]
        res = []
        for r, v, c in zip(twins, vecs, (0.9, 0.8, 0.85)):
            a = _test_assessment("Confirmed", GOOD_QUOTES, conf=c, vector=v)
            out = assess_row(r, FakeLLM(lambda s, m, a=a: a))
            out.update(classification="Confirmed", confidence=c, gate_notes="")
            out["cvss_vector"], out["cvss_score"], out["cvss_severity"] = score_vector(v)
            res.append(out)
        harmonise(twins, res)
        self.assertEqual({r["cvss_vector"] for r in res}, {vecs[0]})
        self.assertEqual(res[2]["cvss_vector_original"], vecs[2])
        self.assertEqual({r["confidence"] for r in res}, {0.8})

    def test_plain_text_leaves_row_level_security_alone(self):
        self.assertEqual(plain_text("No row-level security policy was shown for the row."),
                         "No row-level security policy was shown for this finding.")

    def test_chains_need_a_confirmed_step_and_never_change_classification(self):
        def res(fid, cat, title, cls, env="production", seen="2026-08-01T00:00:00Z"):
            return {"finding_id": fid, "category": cat, "finding_title": title, "classification": cls,
                    "environment": env, "asset": "a", "first_observed_utc": seen, "cvss_score": None}
        enum = res("C-1", "Authentication", "Authentication responses may enumerate registered users", "Confirmed")
        forge = res("C-2", "Authentication", "Bearer token accepted without cryptographic verification",
                    "Needs Review", seen="2026-08-05T00:00:00Z")
        other_env = res("C-3", "OAuth", "OAuth callback may redirect", "Confirmed", env="sandbox")
        fp = res("C-4", "OAuth", "OAuth callback may redirect", "False Positive")
        chains = correlate_chains([enum, forge, other_env, fp])
        self.assertEqual([c["chain_id"] for c in chains], ["account-takeover:production"])
        self.assertEqual(chains[0]["status"], "contingent")
        self.assertEqual(chains[0]["pending_review"], ["C-2"])
        self.assertTrue(chains[0]["observed_in_attack_order"])
        self.assertEqual(forge["classification"], "Needs Review")
        self.assertNotIn("chains", fp)
        enum["classification"] = forge["classification"] = "Needs Review"
        for r in (enum, forge):
            r.pop("chains", None)
        self.assertEqual(correlate_chains([enum, forge]), [])  # no confirmed step -> no chain

    def test_client_text_never_reads_like_pipeline_or_ai_output(self):
        jargon = ("The packet shows the row's request_id \u2014 notably \u2014 the validation_attempt; Assessor A's "
                  "view fails. Importantly, this is robust.")
        a = _test_assessment("Confirmed", GOOD_QUOTES)
        a["reasoning"] = a["report"]["business_impact"] = a["report"]["recommended_fix"] = jargon
        llm = FakeLLM(lambda s, m: a)
        res = [assess_row(_test_row(), llm)]
        for k in ("reasoning", "business_impact", "recommended_fix"):
            self.assertEqual(style_issues(res[0][k]), [], res[0][k])
        self.assertEqual(report_style_issues(build_report(res, "x.csv", "fake", correlate_chains(res))), [])

    def test_csv_formula_injection_neutralised(self):
        self.assertEqual(_csv_cell("=HYPERLINK(1)"), "'=HYPERLINK(1)")
        self.assertEqual(_csv_cell("plain"), "plain")
        self.assertEqual(_csv_cell(None), "")


class TestConsensus(unittest.TestCase):
    def _llm(self, by_stage):
        def responder(stage, msg):
            v = by_stage[stage]
            if isinstance(v, Exception):
                raise v
            return v
        return FakeLLM(responder)

    def test_contradictory_assessors_with_failed_adjudication_is_not_confirmed(self):
        llm = self._llm({"classify": _test_assessment("Confirmed", GOOD_QUOTES),
                         "verify": _test_assessment("False Positive", GOOD_QUOTES),
                         "adjudicate": LLMError("timeout")})
        res = assess_row(_test_row(), llm)
        self.assertEqual(res["classification"], "Needs Review")
        self.assertEqual(res["confidence"], 0.0)

    def test_disagreement_goes_to_adjudicator_and_confidence_is_capped(self):
        adj = _test_assessment("Confirmed", GOOD_QUOTES, conf=0.95)
        adj["adjudication_note"] = "B relied on owner claim"
        llm = self._llm({"classify": _test_assessment("Confirmed", GOOD_QUOTES),
                         "verify": _test_assessment("Needs Review", GOOD_QUOTES, conf=0.5), "adjudicate": adj})
        res = assess_row(_test_row(), llm)
        self.assertEqual(res["classification"], "Confirmed")
        self.assertLessEqual(res["confidence"], ADJUDICATED_CONFIDENCE_CAP)
        self.assertTrue(res["assessor_agreement"].startswith("adjudicated"))

    def test_llm_failure_routes_to_needs_review(self):
        llm = self._llm({"classify": LLMError("boom"), "verify": LLMError("boom")})
        res = assess_row(_test_row(), llm)
        self.assertEqual(res["classification"], "Needs Review")
        self.assertEqual(res["assessor_agreement"], "error")

    def test_agreement_confirmed_gets_cvss_and_priority(self):
        llm = self._llm({"classify": _test_assessment("Confirmed", GOOD_QUOTES),
                         "verify": _test_assessment("Confirmed", GOOD_QUOTES, conf=0.8)})
        res = assess_row(_test_row(), llm)
        self.assertEqual(res["cvss_score"], 6.5)
        self.assertEqual(res["confidence"], 0.8)        # lower of the two assessors
        self.assertEqual(res["priority_tier"], "LOOK")  # 6.5 * 1.0 = 6.5, below the 7.0 Fix-now line
        self.assertEqual(res["priority_score"], 6.5)    # confidence does not enter the score



class TestGuidedChecklist(unittest.TestCase):
    def test_every_dataset_category_has_a_rubric_with_a_bounded_checklist(self):
        cats = ["Injection", "Authorization", "Authentication", "Path Traversal", "Browser Security",
                "Server-Side Request Forgery", "File Upload", "OAuth", "Code Execution", "Secret Detection",
                "Cryptography", "Information Exposure", "Account Recovery", "Concurrency"]
        for c in cats:
            r = rubric_for(c)
            self.assertIsNotNone(r, c)
            ids = [cid for cid, _ in r["checks"]]
            self.assertTrue(2 <= len(ids) <= 8 and len(set(ids)) == len(ids), c)

    def test_rubric_and_checklist_instruction_reach_the_model_but_unknown_categories_get_none(self):
        self.assertIn("no_check_on_path", user_message("p", "f", render_rubric("Authorization")))
        self.assertNotIn("category_rubric", user_message("p", "f", render_rubric("Made-up category")))
        seen = []
        llm = FakeLLM(lambda stage, msg: seen.append(msg) or _test_assessment("Needs Review", GOOD_QUOTES, conf=0.5))
        assess_row(_test_row(), llm)
        self.assertTrue(all("<category_rubric>" in m for m in seen) and len(seen) == 2)

    def test_confirmed_with_an_unanswered_check_becomes_needs_review(self):
        a = _test_assessment("Confirmed", GOOD_QUOTES, checklist=_test_checklist("Confirmed", no_check_on_path="unknown"))
        g = apply_gates(_test_row(), a)
        self.assertEqual(g["classification"], "Needs Review")
        self.assertIn("1 of 3 checks", g["gate_notes"][-1])

    def test_confirmed_with_a_check_answered_no_becomes_needs_review(self):
        a = _test_assessment("Confirmed", GOOD_QUOTES, checklist=_test_checklist("Confirmed", foreign_result="no"))
        self.assertEqual(apply_gates(_test_row(), a)["classification"], "Needs Review")

    def test_confirmed_check_with_fabricated_quote_is_not_backed(self):
        bad = ("yes", "observation", "the attacker downloaded every vehicle record in the fleet")
        a = _test_assessment("Confirmed", GOOD_QUOTES, checklist=_test_checklist("Confirmed", foreign_result=bad))
        g = apply_gates(_test_row(), a)
        self.assertEqual(g["classification"], "Needs Review")
        self.assertFalse([c for c in g["verified_checklist"] if c["id"] == "foreign_result"][0]["backed"])

    def test_fully_backed_checklist_lets_confirmed_through(self):
        g = apply_gates(_test_row(), _test_assessment("Confirmed", GOOD_QUOTES))
        self.assertEqual(g["classification"], "Confirmed")
        self.assertTrue(all(c["backed"] for c in g["verified_checklist"]))

    def test_false_positive_needs_one_backed_no(self):
        quotes = [("validation_attempt", "Paired cross-tenant test returned HTTP 200 with the other tenant's data.")]
        none = _test_checklist("False Positive", cross_boundary_caller="unknown", foreign_result="unknown",
                               no_check_on_path="unknown")
        self.assertEqual(apply_gates(_test_row(), _test_assessment("False Positive", quotes, checklist=none))
                         ["classification"], "Needs Review")
        self.assertEqual(apply_gates(_test_row(), _test_assessment("False Positive", quotes))["classification"],
                         "False Positive")

    def test_row_without_a_rubric_is_not_checklist_gated(self):
        row = _test_row(category="Something New")
        a = _test_assessment("Confirmed", GOOD_QUOTES, checklist=[])
        self.assertEqual(apply_gates(row, a)["classification"], "Confirmed")

    def test_gate_never_raises_a_verdict(self):
        a = _test_assessment("Needs Review", GOOD_QUOTES, conf=0.5,
                             checklist=_test_checklist("Confirmed"))
        self.assertEqual(apply_gates(_test_row(), a)["classification"], "Needs Review")

    def test_agreeing_assessors_keep_only_checks_both_answered_the_same(self):
        x = _test_checklist("Confirmed")
        y = _test_checklist("Confirmed", foreign_result="no")
        merged = {c["id"]: c["answer"] for c in merge_checklists(_test_row(), x, y)}
        self.assertEqual(merged["foreign_result"], "unknown")
        self.assertEqual(merged["cross_boundary_caller"], "yes")

    def test_agreement_with_split_checklists_is_not_confirmed(self):
        llm = FakeLLM(lambda stage, msg: _test_assessment(
            "Confirmed", GOOD_QUOTES,
            checklist=_test_checklist("Confirmed", foreign_result="unknown" if stage == "verify" else None)))
        self.assertEqual(assess_row(_test_row(), llm)["classification"], "Needs Review")

    def test_schema_requires_a_checklist(self):
        a = _test_assessment("Confirmed", GOOD_QUOTES)
        del a["checklist"]
        self.assertTrue(validate(a, ASSESSMENT_SCHEMA))


class TestReviewFixes(unittest.TestCase):
    def test_filled_input_csv_keeps_every_column_and_fills_the_two_answer_columns(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            src, dst = Path(d) / "in.csv", Path(d) / "out.csv"
            src.write_text("finding_id,asset,candidate_classification,candidate_reasoning\n"
                           'A-1,"a,b\nc",,\nA-2,x,,\n', encoding="utf-8")
            n = write_filled_input(dst, src, [{"finding_id": "A-1", "classification": "Confirmed", "reasoning": "=bad"}])
            rows = list(csv.DictReader(open(dst, newline="", encoding="utf-8")))
            self.assertEqual(n, 1)
            self.assertEqual(rows[0]["asset"], "a,b\nc")            # raw field untouched, newline and comma kept
            self.assertEqual(rows[0]["candidate_classification"], "Confirmed")
            self.assertEqual(rows[0]["candidate_reasoning"], "'=bad")  # formula injection neutralised
            self.assertEqual(rows[1]["candidate_classification"], "")  # not assessed -> left blank

    def test_fix_text_does_not_split_sql_placeholders_or_ellipses(self):
        steps, _, _ = split_fix("Use UPDATE quotas SET used = used + 1 WHERE org_id = ? AND used < limit. "
                                "Or take a lock with SELECT... FOR UPDATE in the same transaction.")
        self.assertEqual(len(steps), 2)

    def test_priority_ignores_model_confidence(self):
        self.assertEqual(priority(9.1, "production"), (9.1, "CHASE"))
        self.assertEqual(priority(8.8, "staging")[1], "LOOK")
        self.assertEqual(priority(None, "production"), (None, ""))

    def test_issue_titles_drop_host_names_and_bad_dates_do_not_crash(self):
        t = display_title({"client_title": "Credentialed CORS trusts arbitrary origins on api.example.test, so any site can read data"})
        self.assertNotIn("example.test", t)
        self.assertNotIn(" ,", t)
        self.assertEqual(_date_window(["N/A", "2026-07-01", "2026-10-11"]), "July 1, 2026 to October 11, 2026")
        self.assertEqual(_date_window(["N/A"]), "the observation period")

    def test_truncated_or_malformed_csv_is_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            short, quote = Path(d) / "s.csv", Path(d) / "q.csv"
            short.write_text("finding_id,a,b\nX-1,1\n", encoding="utf-8")
            quote.write_text('finding_id,a\nX-1,"never closed\nX-2,2\n', encoding="utf-8")
            for f in (short, quote):
                with self.assertRaises(InputError):
                    read_findings(f)


class TestModelFallback(unittest.TestCase):
    def _cli(self, behaviour):
        cli = ClaudeCLI(["primary-model", "backup-model"], retries=2, cache_dir=None)
        calls = []

        def fake(model, system, schema, message):
            calls.append(model)
            r = behaviour(model, len(calls))
            if isinstance(r, Exception):
                raise r
            return r, 0.0
        cli._call_once = fake
        return cli, calls

    def test_denied_primary_falls_back_and_stays_disabled(self):
        ok = _test_assessment("Needs Review", GOOD_QUOTES, conf=0.5)
        cli, calls = self._cli(lambda m, n: ModelDenied("status 404: model not found") if m == "primary-model" else ok)
        out1 = cli.complete("classify", "s", ASSESSMENT_SCHEMA, "m1")
        out2 = cli.complete("classify", "s", ASSESSMENT_SCHEMA, "m2")
        self.assertEqual(out1["_model"], "backup-model")
        self.assertEqual(out2["_model"], "backup-model")
        self.assertEqual(calls, ["primary-model", "backup-model", "backup-model"])  # denied model not retried
        self.assertIn("primary-model", cli.disabled)

    def test_transient_primary_failure_retries_then_falls_back(self):
        ok = _test_assessment("Needs Review", GOOD_QUOTES, conf=0.5)
        cli, calls = self._cli(lambda m, n: LLMError("timeout") if m == "primary-model" else ok)
        with unittest.mock.patch("time.sleep"):
            out = cli.complete("classify", "s", ASSESSMENT_SCHEMA, "m")
        self.assertEqual(out["_model"], "backup-model")
        self.assertEqual(calls, ["primary-model", "primary-model", "backup-model"])
        self.assertNotIn("primary-model", cli.disabled)

    def test_primary_success_does_not_touch_backup(self):
        ok = _test_assessment("Needs Review", GOOD_QUOTES, conf=0.5)
        cli, calls = self._cli(lambda m, n: ok)
        self.assertEqual(cli.complete("classify", "s", ASSESSMENT_SCHEMA, "m")["_model"], "primary-model")
        self.assertEqual(calls, ["primary-model"])

    def test_all_models_failing_routes_row_to_needs_review(self):
        cli, _ = self._cli(lambda m, n: ModelDenied("permission denied"))
        res = assess_row(_test_row(), cli)
        self.assertEqual(res["classification"], "Needs Review")
        self.assertEqual(res["assessor_agreement"], "error")

    def test_schema_invalid_output_is_never_accepted(self):
        cli, _ = self._cli(lambda m, n: {"classification": "Confirmed"})
        with unittest.mock.patch("time.sleep"), self.assertRaises(LLMError):
            cli.complete("classify", "s", ASSESSMENT_SCHEMA, "m")


class TestCVSS(unittest.TestCase):
    def test_known_vectors(self):
        cases = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
        }
        for v, s in cases.items():
            self.assertEqual(base_score(v), s, v)

    def test_invalid_vector_is_unscored(self):
        self.assertEqual(score_vector("CVSS:3.0/AV:X"), (None, None, None))


class TestFactsAndReport(unittest.TestCase):
    def test_dataset_context_only_states_what_the_data_shows(self):
        rows = _synthetic_findings()
        ctx = dataset_context(rows)
        self.assertIn("capture_vs_log_date_offset", ctx)
        self.assertEqual(dataset_context(rows[:1]), {})
        for text in ctx.values():  # the notes report counts; interpretation lives in the rules prompt
            for phrase in ("artefact", "must not", "does not show", "neither proves", "Do not reason", "Treat the"):
                self.assertNotIn(phrase, text)
        shifted = [dict(rows[0]), dict(rows[1], raw_http_exchange=rows[1]["raw_http_exchange"].replace(
            "2026-08-01", "2026-08-11"))]
        self.assertNotIn("capture_vs_log_date_offset", dataset_context(shifted))

    def test_facts_correlate_request_ids_and_revisions(self):
        f = extract_facts(_synthetic_findings()[0])
        self.assertTrue(f["http_request_id_matches_row"])
        self.assertIn("req_unrelated", f["log_unrelated_request_ids"])
        self.assertEqual(f["source_attachment_revision"], "aaaa11112222")
        self.assertFalse(f["source_revision_matches_manifest"])

    def test_report_escapes_untrusted_text_and_csv_written(self):
        llm = FakeLLM(lambda s, m: _test_assessment("Confirmed", GOOD_QUOTES))
        r = _test_row(finding_title="<script>alert(1)</script>")
        res = [assess_row(r, llm)]
        page = build_report(res, "x.csv", "fake")
        self.assertNotIn("<script>alert(1)</script>", page)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "o.csv"
            write_classified(p, res)
            with open(p) as fh:
                out = list(csv.DictReader(fh))
            self.assertEqual(out[0]["classification"], "Confirmed")
            self.assertTrue(0 <= float(out[0]["confidence"]) <= 1)



class TestClientReport(unittest.TestCase):
    def _results(self):
        llm = FakeLLM(lambda s, m: _test_assessment("Confirmed", GOOD_QUOTES))
        return [assess_row(_test_row(), llm)]

    def test_client_report_has_only_confirmed_findings(self):
        conf = self._results()
        other = dict(conf[0], finding_id="TF-9999", classification="False Positive", finding_title="ALARM-ONLY-TITLE",
                     client_title="ALARM-ONLY-TITLE")
        nr = dict(conf[0], finding_id="TF-9998", classification="Needs Review", finding_title="UNDECIDED-TITLE", client_title="UNDECIDED-TITLE")
        page = build_client_report(conf + [other, nr], "x.csv")
        self.assertIn(conf[0]["finding_id"], page)
        self.assertNotIn("ALARM-ONLY-TITLE", page)
        self.assertNotIn("UNDECIDED-TITLE", page)
        self.assertNotIn("TF-9999", page)

    def test_client_report_carries_score_impact_and_fix(self):
        res = self._results()
        page = build_client_report(res, "x.csv")
        self.assertIn("CVSS 3.1", page)
        self.assertIn(res[0]["cvss_vector"], page)
        self.assertIn("Business impact", page)
        self.assertIn("Recommended fix", page)
        self.assertEqual(report_style_issues(page), [])

    def test_same_issue_on_many_endpoints_is_one_section_listing_every_instance(self):
        a = self._results()[0]
        b = dict(a, finding_id="TF-7002", asset="other.example.test", environment="staging")
        c = dict(a, finding_id="TF-7003", asset="third.example.test", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                 client_title="A different flaw of the same type")
        page = build_client_report([a, b, c], "x.csv")
        self.assertEqual(page.count('<article class="entry'), 2)  # a+b together, c apart
        for r in (a, b, c):
            self.assertEqual(page.count(f"<td>{r['finding_id']}</td>"), 1)  # each instance listed exactly once
        self.assertIn("other.example.test", page)

    def test_summary_issue_and_finding_counts_reconcile(self):
        a = self._results()[0]
        rows = [dict(a, finding_id=f"TF-6{i:03d}", asset=f"svc{i}.example.test") for i in range(4)]
        rows.append(dict(a, finding_id="TF-6900", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cvss_severity="Critical", cvss_score=9.8))
        page = build_client_report(rows, "x.csv")
        m = re.search(r"<tr class='tot'><td><b>Total</b></td><td class='n'>(\d+)</td><td class='n'>(\d+)</td>", page)
        self.assertEqual((m.group(1), m.group(2)), ("2", "5"))  # 2 distinct issues, 5 findings

    def test_every_confirmed_finding_appears_exactly_once(self):
        a = self._results()[0]
        rows = [dict(a, finding_id=f"TF-8{i:03d}", asset=f"svc{i}.example.test") for i in range(5)]
        page = build_client_report(rows, "x.csv")
        for r in rows:
            self.assertEqual(page.count(f"<td>{r['finding_id']}</td>"), 1)

    def test_client_report_escapes_untrusted_text(self):
        res = self._results()
        res[0]["client_title"] = "<script>alert(1)</script>"
        self.assertNotIn("<script>alert(1)</script>", build_client_report(res, "x.csv"))



if __name__ == "__main__":
    sys.exit(main())
