#!/usr/bin/env python3
"""Tr(AI)ger: evidence-first triage for noisy security findings.

Usage:
  python3 triage.py                       # prompts you to pick a .csv
  python3 triage.py --csv findings.csv
  python3 triage.py --csv f.csv --model claude-opus-5-5 --out out-opus

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
import io
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
from typing import Any, Callable, Dict, List, Optional, Protocol, Sequence, Tuple, Union


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
# Other spellings of the weighted environments, so "prod", "PRD" or "uat" weigh like their class. Display keeps the
# file's own wording.
ENV_ALIASES = {"prod": "production", "prd": "production", "live": "production", "production": "production",
               "dr": "dr-canary", "disaster-recovery": "dr-canary", "dr-canary": "dr-canary",
               "stage": "staging", "stg": "staging", "staging": "staging", "preprod": "staging", "pre-prod": "staging",
               "uat": "staging", "qa": "staging", "dev": "sandbox", "development": "sandbox", "test": "sandbox",
               "sandbox": "sandbox", "lab": "sandbox"}


def env_class(environment: str) -> str:
    """The weighted environment class for an environment label; unknown labels are returned lower-cased."""
    k = re.sub(r"[\s_]+", "-", (environment or "").strip().lower())
    return ENV_ALIASES.get(k, k)
TIER_CHASE = 7.0
TIER_LOOK = 3.0


# ---------------------------------------------------------------------------
# Agent roster. Three agents are language models; the rest are deterministic
# code stages. The README documents what each one sees, produces and may not do.
# ---------------------------------------------------------------------------
AGENTS = {
    "Registrar": "code (+ one model call for columns no rule recognises): parses any CSV, maps its columns onto "
                 "pipeline roles, extracts provenance facts and dataset-wide context",
    "Scout": "model, Assessor A: classifies the finding and proposes CVSS vector, impact and fix",
    "Skeptic": "model, Assessor B: blind second review that tries to refute both outcomes",
    "Arbiter": "model: decides when Scout and Skeptic disagree on the outcome; casts a third CVSS vote when they "
               "confirm but score any metric differently",
    "Warden": "code: evidence gates and consistency gate; can only move a verdict toward Needs Review",
    "Scorekeeper": "code: combines the reviews' vectors per metric, computes CVSS 3.1 scores, harmonises vectors, "
                   "assigns priority",
    "Cartographer": "code: correlates confirmed findings into attack chains",
    "Editor": "code: plain-language cleanup of every client-facing sentence",
    "Fact-checker": "model + code: checks every claim in each issue's client-facing text against its evidence; "
                    "code verifies the quotes; one rewrite, then anything unsupported is flagged for a person",
    "Publisher": "code: writes the CSVs, the analyst report and the client report (HTML and Markdown)",
}


# ============================================================================
# CSV input / output
# ============================================================================
# Always parsed with the csv module: fields contain quoted commas and embedded newlines, so line- or comma-splitting
# is wrong. Any CSV is accepted: the delimiter is sniffed, non-UTF-8 files fall back to Windows-1252, and the
# columns are mapped onto the pipeline's canonical roles (see "Column mapping" below).
REQUIRED_COLUMNS = ("finding_id",)

# Columns that are never shown to the model: they are the answer slots, and the source row number.
HIDDEN_COLUMNS = ("candidate_classification", "candidate_reasoning", "_row")


class InputError(Exception):
    pass


def load_csv(path: Path) -> Tuple[List[str], List[Dict[str, str]]]:
    """Parse any delimited text file into its header and rows, strictly.

    The delimiter (comma, semicolon, tab or pipe) is sniffed from the start of the file. UTF-8 (with or without a BOM)
    is tried first, then Windows-1252. Rows with more or fewer cells than the header are rejected rather than guessed.

    Raises:
        InputError: If the file is unreadable, empty, has no header, or has a malformed row.
    """
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise InputError(f"{path}: cannot read ({exc})") from exc
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise InputError(f"{path}: not valid UTF-8 or Windows-1252 text")
    if encoding != "utf-8-sig":
        print(f"notice: {path.name} is not UTF-8; read as Windows-1252", file=sys.stderr)
    try:
        delimiter = csv.Sniffer().sniff(text[:65536], delimiters=",;\t|").delimiter
    except csv.Error:
        delimiter = ","
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True)
        if not reader.fieldnames or not any(h.strip() for h in reader.fieldnames):
            raise InputError(f"{path}: empty file or no header row")
        headers = [h.strip() for h in reader.fieldnames]
        if len(set(headers)) != len(headers):
            raise InputError(f"{path}: repeated column name(s): "
                             + ", ".join(sorted(h for h, n in collections.Counter(headers).items() if n > 1)))
        reader.fieldnames = headers
        rows = []
        for row in reader:
            if None in row:  # more cells than headers -> malformed row
                raise InputError(f"{path}: record ending near line {reader.line_num} has extra cells")
            if None in row.values():  # fewer cells than headers -> truncated row
                raise InputError(f"{path}: record ending near line {reader.line_num} has too few cells")
            if any((v or "").strip() for v in row.values()):  # skip fully blank lines
                rows.append({k: (v or "") for k, v in row.items()})
    except csv.Error as exc:
        raise InputError(f"{path}: not valid CSV ({exc})") from exc
    if not rows:
        raise InputError(f"{path}: no findings")
    return headers, rows


# ---------------------------------------------------------------------------
# Column mapping
# ---------------------------------------------------------------------------
# The pipeline works on canonical column names. A file that already uses them maps onto itself. Other files are
# mapped by (1) exact canonical names, (2) common aliases, (3) optionally one model call for the columns still
# unplaced, and (4) a user-supplied --column-map JSON, which always wins. A column with no canonical role keeps its
# data under "<kind>.<name>", where the kind says what the evidence is worth to the gates:
#   capture   direct runtime capture: requests, responses, tool output, logs, traces      (runtime, can confirm)
#   observed  a person's account of a test that was run                                    (runtime narrative)
#   code      source, configuration, manifests
#   claim     assertions by interested parties: owner or ticket comments, claimed mitigations (never proof alone)
#   context   descriptions, network or identity context, references, recommendations
#   quality   notes on evidence gaps, sampling or collection problems
#   label     scanner labels: scores, severities, IDs, dates                               (shown, never quotable)
#   answer    an existing verdict or triage decision                                       (hidden from the model)
#   ignore    empty or irrelevant                                                           (hidden from the model)
FIELD_KINDS = ("capture", "observed", "code", "claim", "context", "quality", "label", "answer", "ignore")
CANONICAL_ALIASES: Dict[str, Tuple[str, ...]] = {
    "finding_id": ("id", "vuln_id", "vulnerability_id", "issue_id", "alert_id", "record_id", "ref", "reference", "uid", "uuid"),
    "finding_title": ("title", "name", "vulnerability", "vulnerability_name", "vuln_name", "issue", "issue_name",
                      "summary", "plugin_name", "check_name", "rule_name", "alert", "alert_name", "finding_name"),
    "category": ("type", "vuln_type", "vulnerability_type", "finding_type", "issue_type", "cwe", "family", "plugin_family"),
    "asset": ("host", "hostname", "target", "url", "uri", "endpoint", "ip", "ip_address", "resource", "component",
              "service", "application", "app", "system", "fqdn", "domain", "location", "affected_asset"),
    "environment": ("env", "stage", "tier", "zone", "network_zone"),
    "asset_owner": ("owner", "team", "owning_team", "assignee", "business_unit"),
    "scanner_source": ("scanner", "tool", "source_tool", "detected_by", "scanner_name", "engine", "detection_source"),
    "scanner_rule": ("rule", "rule_id", "plugin_id", "check_id", "template_id", "signature", "cve", "cve_id"),
    "scanner_severity": ("severity", "risk", "risk_rating", "risk_level", "criticality", "cvss", "cvss_score", "base_score"),
    "scanner_confidence": ("confidence", "certainty"),
    "first_observed_utc": ("first_seen", "first_observed", "first_detected", "discovered", "discovered_at", "detected_at",
                           "created", "created_at", "date", "timestamp", "found_at", "observed_at"),
    "last_observed_utc": ("last_seen", "last_observed", "last_detected", "updated", "updated_at"),
    "request_id": ("correlation_id", "x_request_id"),
    "raw_request": ("request", "http_request"),
    "raw_response": ("response", "http_response"),
    "raw_http_exchange": ("http_exchange", "http_transaction"),
    "validation_attempt": ("validation", "verification", "reproduction", "steps_to_reproduce", "repro_steps"),
    "mixed_service_logs": ("logs", "log", "service_logs", "log_excerpt"),
    "distributed_trace_excerpt": ("trace", "traces", "trace_excerpt"),
    "source_code_excerpt": ("code", "code_snippet", "snippet", "source_code"),
    "code_or_config_context": ("config", "configuration", "config_context"),
    "deployment_manifest_excerpt": ("manifest", "deployment_manifest"),
    "claimed_compensating_controls": ("compensating_controls", "mitigations", "mitigation", "controls"),
    "ticket_comment_thread": ("comments", "comment", "ticket_comments", "notes", "discussion"),
    "evidence_gaps": ("gaps", "known_gaps"),
}
# Columns that hold an existing verdict are hidden from the model so it cannot copy the answer.
ANSWER_ALIASES = ("status", "verdict", "triage_status", "triage", "resolution", "disposition", "false_positive",
                  "is_false_positive", "state")
# Common column names whose evidence kind is clear from the name alone.
KIND_ALIASES: Dict[str, Tuple[str, ...]] = {
    "capture": ("plugin_output", "output", "tool_output", "proof", "http_traffic", "request_response", "evidence_output",
                "captured_response", "response_body"),
    "observed": ("poc", "proof_of_concept", "test_result", "test_results", "exploitation", "exploit_result"),
    "claim": ("analyst_notes", "dev_notes", "developer_notes", "owner_notes", "owner_comment", "remarks",
              "justification", "risk_acceptance", "exception_reason"),
    "context": ("description", "synopsis", "solution", "remediation", "recommendation", "see_also", "references",
                "impact_description", "details"),
}
_KIND_PREFIX = re.compile(r"^(%s)\." % "|".join(FIELD_KINDS))


def _header_key(h: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", h.strip().lower()).strip("_")


def canonical_names() -> List[str]:
    return [f for _, fields in FIELD_ORDER for f in fields] + list(HIDDEN_COLUMNS[:2])


def heuristic_mapping(headers: Sequence[str]) -> Dict[str, Optional[str]]:
    """Source column -> canonical name or "<kind>.<name>", or None when no rule places it."""
    canon = canonical_names()
    out: Dict[str, Optional[str]] = {}
    taken: set = set()
    for h in headers:  # exact canonical names first, so they are never displaced by an alias
        if _header_key(h) in canon and _header_key(h) not in taken:
            out[h] = _header_key(h)
            taken.add(out[h])
    for h in headers:
        if h in out:
            continue
        k = _header_key(h)
        if k in ANSWER_ALIASES:
            out[h] = f"answer.{k}"
            continue
        kind = next((kd for kd, names in KIND_ALIASES.items() if k in names), None)
        if kind:
            out[h] = f"{kind}.{k}"
            continue
        role = next((c for c, aliases in CANONICAL_ALIASES.items() if k in aliases and c not in taken), None)
        out[h] = role
        if role:
            taken.add(role)
    return out


SCHEMA_MAP_SCHEMA = {
    "type": "object",
    "properties": {"columns": {"type": "array", "items": {
        "type": "object",
        "properties": {"column": {"type": "string"}, "role": {"type": "string"}},
        "required": ["column", "role"]}}},
    "required": ["columns"],
}
# What each canonical role means, for the model that places unrecognised columns. scanner_raw_output is not offered:
# it is a scanner label, and a tool's captured output for this instance is runtime evidence (kind "capture").
CANONICAL_HINTS = {
    "finding_id": "unique ID of the finding", "finding_title": "short name of the finding",
    "category": "vulnerability class or type", "asset": "affected host, URL, IP, service or component",
    "environment": "production, staging, dev and so on", "asset_owner": "owning team or person",
    "scanner_source": "the tool that reported it", "scanner_rule": "rule, plugin, check or CVE ID",
    "scanner_severity": "severity or risk rating given by the tool", "scanner_confidence": "the tool's confidence",
    "first_observed_utc": "date or time first found or reported", "last_observed_utc": "date or time last seen",
    "request_id": "request or correlation ID", "raw_request": "captured HTTP request",
    "raw_response": "captured HTTP response", "raw_http_exchange": "captured request and response together",
    "observation": "a tester's description of what they observed", "validation_attempt": "how the finding was verified",
    "mixed_service_logs": "log lines", "distributed_trace_excerpt": "trace spans",
    "source_code_excerpt": "source code", "code_or_config_context": "configuration or code context",
    "deployment_manifest_excerpt": "deployment manifest", "identity_network_context": "network or identity context",
    "claimed_compensating_controls": "claimed mitigations", "contradictory_evidence": "evidence against the finding",
    "ticket_comment_thread": "comments from owners or tickets", "evidence_gaps": "what was not tested",
    "evidence_collection_warnings": "problems collecting the evidence",
}
SCHEMA_MAP_SYSTEM = """You map the columns of a security-findings spreadsheet onto a triage pipeline's roles. Column names
may be in any language. For each column you are given, return one role. Either a canonical role, used at most once:
{canonical}
or one evidence kind:
  capture (raw captured requests, responses, tool or plugin output, logs, traces), observed (a person's account of a
  test that was run), code (source, configuration, manifests), claim (statements by owners, developers or tickets,
  claimed mitigations), context (descriptions, network or identity context, references, remediation advice),
  quality (notes on evidence gaps or collection problems), label (scanner labels: scores, severities, IDs, dates,
  counts), answer (an existing verdict or triage decision about the finding), ignore (empty or irrelevant).
Judge from the column name AND the sample values. Prefer a weaker kind when unsure: context over capture, label over
context, except that a tool's output showing what happened for THIS finding (its request, response or result) is
capture. Return every column you were given, spelled exactly."""


def model_mapping(headers: Sequence[str], rows: Sequence[Dict[str, str]], unplaced: Sequence[str],
                  taken: Sequence[str], llm: "LLMBackend") -> Dict[str, str]:
    """Ask the model to place the columns no rule could place. Code validates every answer: unknown columns are
    dropped, a canonical role already taken (or claimed twice) falls back to context, an unknown role to context."""
    free = [c for c in CANONICAL_HINTS if c not in taken]
    samples = []
    for h in unplaced:
        vals = [r[h].strip() for r in rows if r.get(h, "").strip()][:3]
        samples.append(f"<column name={json.dumps(h)}>\n" + "\n---\n".join(v[:240] for v in vals) + "\n</column>")
    canon = "\n".join(f"  {c}: {CANONICAL_HINTS[c]}" for c in free)
    out = llm.complete("schema", SCHEMA_MAP_SYSTEM.replace("{canonical}", canon), SCHEMA_MAP_SCHEMA,
                       "All columns: " + ", ".join(headers) + "\n\nColumns to place, with sample values:\n" + "\n".join(samples))
    placed: Dict[str, str] = {}
    used = set(taken)
    for item in out.get("columns", []):
        col, role = item.get("column"), (item.get("role") or "").strip().lower()
        if col not in unplaced or col in placed:
            continue
        if role in free and role not in used:
            placed[col], _ = role, used.add(role)
        elif role in FIELD_KINDS:
            placed[col] = f"{role}.{_header_key(col) or 'column'}"
        else:
            placed[col] = f"context.{_header_key(col) or 'column'}"
    return placed


def infer_mapping(headers: Sequence[str], rows: Sequence[Dict[str, str]], llm: Optional["LLMBackend"] = None,
                  override: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """The full source-column -> pipeline-key mapping. Rules first; the model only for what rules leave unplaced; the
    user's override last. Without a model, unplaced columns become context (quotable, never runtime proof)."""
    mapping = heuristic_mapping(headers)
    unplaced = [h for h, v in mapping.items() if v is None]
    if unplaced and llm is not None:
        try:
            mapping.update(model_mapping(headers, rows, unplaced, [v for v in mapping.values() if v], llm))
        except LLMError as exc:
            print(f"warning: column mapping by model failed ({exc}); unplaced columns are treated as context", file=sys.stderr)
    for h, v in list(mapping.items()):
        if v is None:
            mapping[h] = f"context.{_header_key(h) or 'column'}"
    for h, v in (override or {}).items():
        if h not in mapping:
            raise InputError(f"--column-map names a column the file does not have: {h!r}")
        if v not in canonical_names() and not _KIND_PREFIX.match(v):
            raise InputError(f"--column-map role for {h!r} must be a canonical column or '<kind>.<name>' with kind in "
                             f"{', '.join(FIELD_KINDS)}: got {v!r}")
        mapping[h] = v
    # Two columns on one key: the later one keeps its data as context.
    seen: set = set()
    for h in headers:
        if mapping[h] in seen:
            mapping[h] = f"context.{_header_key(h) or 'column'}"
        seen.add(mapping[h])
    return mapping


_DATE_FORMATS = ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d", "%Y/%m/%d %H:%M:%S",
                 "%Y/%m/%d", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%m/%d/%Y", "%d %b %Y", "%b %d, %Y", "%B %d, %Y",
                 "%d-%b-%Y", "%a, %d %b %Y %H:%M:%S")


def normalise_timestamp(value: str) -> str:
    """ISO 8601 UTC ('2026-07-01T13:00:00Z') for common date formats and epoch seconds; anything else unchanged.
    Ambiguous day/month dates are read as US month/day."""
    v = (value or "").strip()
    if not v:
        return ""
    try:
        d = dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        d = None
        if re.fullmatch(r"\d{10}(\.\d+)?", v):
            d = dt.datetime.fromtimestamp(float(v), tz=dt.timezone.utc)
        for fmt in _DATE_FORMATS:
            if d:
                break
            try:
                d = dt.datetime.strptime(re.sub(r"\s*(UTC|GMT|Z)$", "", v), fmt)
            except ValueError:
                continue
    if d is None:
        return v
    if d.tzinfo:
        d = d.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def apply_mapping(rows: Sequence[Dict[str, str]], mapping: Dict[str, str], source: str = "input") -> List[Dict[str, str]]:
    """Rename every row onto pipeline keys and fill what the reports need. Nothing is invented: a missing or
    non-unique ID becomes the row number (the original kept as a label), a missing title or asset becomes
    'Untitled finding' / 'Unspecified asset', and timestamps are normalised to ISO 8601 where their format is known.

    Raises:
        InputError: If an explicit finding_id column repeats an ID or leaves one blank.
    """
    out = []
    for i, raw in enumerate(rows, 1):
        row = {mapping[h]: v for h, v in raw.items()}
        row["_row"] = str(i)
        out.append(row)
    explicit = any(h == "finding_id" for h in mapping)  # the file's own finding_id column is a contract
    ids = [r.get("finding_id", "").strip() for r in out]
    blanks = [i for i, x in enumerate(ids, 1) if not x]
    dupes = sorted(x for x, n in collections.Counter(ids).items() if x and n > 1)
    if explicit and (blanks or dupes):
        if blanks:
            raise InputError(f"{source}: record {blanks[0]} has no finding_id")
        raise InputError(f"{source}: duplicate finding_id(s): {', '.join(dupes[:10])}")
    if "finding_id" not in mapping.values() or blanks or dupes:
        if "finding_id" in mapping.values():
            print(f"notice: the ID column is blank or repeated in {source}; findings are numbered by row "
                  f"(the original value is kept as label.source_id)", file=sys.stderr)
        width = max(4, len(str(len(out))))
        for r in out:
            if r.get("finding_id", "").strip():
                r["label.source_id"] = r["finding_id"]
            r["finding_id"] = f"ROW-{int(r['_row']):0{width}d}"
    for r in out:
        r["finding_id"] = r["finding_id"].strip()
        r.setdefault("finding_title", "")
        if not r["finding_title"].strip():
            r["finding_title"] = (r.get("category") or r.get("scanner_rule") or "Untitled finding").strip()
        if not (r.get("asset") or "").strip():
            r["asset"] = "Unspecified asset"
        if not (r.get("environment") or "").strip():
            r["environment"] = "unspecified"
        for k in ("first_observed_utc", "last_observed_utc"):
            if r.get(k):
                r[k] = normalise_timestamp(r[k])
    return out


def read_findings(path: Path, mapping: Optional[Dict[str, str]] = None, llm: Optional["LLMBackend"] = None,
                  override: Optional[Dict[str, str]] = None) -> List[Dict[str, str]]:
    """Read any findings CSV into one dict per row, keyed by pipeline column names.

    Args:
        path: The input file.
        mapping: A saved source-column mapping to reuse (a rebuild); inferred when omitted.
        llm: Optional model for placing columns no rule recognises.
        override: User mapping (--column-map) that wins over everything else.

    Returns:
        The rows in file order. Each carries "_row" (its 1-based position in the file).

    Raises:
        InputError: If the file cannot be parsed, or its own finding_id column is blank or repeated.
    """
    headers, raw = load_csv(path)
    if mapping is None or set(mapping) != set(headers):
        mapping = infer_mapping(headers, raw, llm, override)
    rows = apply_mapping(raw, mapping, str(path))
    read_findings.last_mapping = mapping  # type: ignore[attr-defined]
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


def _csv_cell(value: object) -> str:
    """Neutralise spreadsheet formula injection in untrusted text."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def write_filled_input(path: Path, source_csv: Path, results: List[Dict[str, object]],
                       rows: Optional[List[Dict[str, str]]] = None) -> int:
    """Write a copy of the input with every original column kept as supplied and the two answer columns
    (candidate_classification, candidate_reasoning) added or filled from the final verdicts. Rows keep the input
    order and are matched by position, so any input format works; rows not assessed (--ids / --limit) stay blank.
    Returns the number of rows filled."""
    headers, raw = load_csv(source_csv)
    rows = rows if rows is not None else read_findings(source_csv)
    pos = {r["finding_id"]: int(r["_row"]) for r in rows}
    by_row = {pos[str(r["finding_id"])]: r for r in results if str(r["finding_id"]) in pos}
    fields = headers + [c for c in HIDDEN_COLUMNS[:2] if c not in headers]
    filled = 0
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for i, row in enumerate(raw, 1):
            res = by_row.get(i)
            if res:
                row["candidate_classification"] = str(res["classification"])
                row["candidate_reasoning"] = _csv_cell(res.get("reasoning"))
                filled += 1
            w.writerow(row)
    return filled


def write_classified(path: Path, results: List[Dict[str, object]]) -> None:
    """Write the per-finding results as the classified CSV, neutralising spreadsheet formulas.

    Args:
        path: Destination file.
        results: Final per-finding results.
    """
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
    """Split a CVSS 3.1 base vector into its metrics.

    Args:
        vector: A vector such as "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".

    Returns:
        The metric abbreviations mapped to their values.

    Raises:
        CVSSError: If the text is not a CVSS 3.1 base vector.
    """
    m = _VECTOR_RE.match((vector or "").strip())
    if not m:
        raise CVSSError(f"not a CVSS 3.1 base vector: {vector!r}")
    return m.groupdict()


def base_score(vector: str) -> float:
    """Compute the CVSS 3.1 base score from a vector, following the FIRST specification.

    Args:
        vector: A CVSS 3.1 base vector.

    Returns:
        The score from 0.0 to 10.0.

    Raises:
        CVSSError: If the vector is invalid.
    """
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
    """Map a CVSS base score to its qualitative rating: None, Low, Medium, High or Critical."""
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


def field_kind(f: str) -> str:
    """The evidence kind of a pipeline key: a canonical column's kind, or the "<kind>." prefix of a mapped column."""
    if f in HIDDEN_COLUMNS:
        return "answer"
    if f in METADATA_FIELDS:
        return "label"
    if f in NARRATIVE_RUNTIME_FIELDS:
        return "observed"
    if f in RUNTIME_FIELDS:
        return "capture"
    if f in CLAIM_FIELDS:
        return "claim"
    m = _KIND_PREFIX.match(f)
    return m.group(1) if m else "context"


def is_runtime(f: str) -> bool:
    return field_kind(f) in ("capture", "observed")


def is_capture(f: str) -> bool:
    """A captured request, response, exchange, log, trace or tool output, as opposed to someone's account of a test."""
    return field_kind(f) == "capture"


def is_claim(f: str) -> bool:
    return field_kind(f) == "claim"


def quotable_fields(row: Dict[str, str]) -> List[str]:
    """List the row's columns that may be quoted as evidence, leaving out hidden answer columns and scanner labels."""
    return [k for k in row if field_kind(k) not in ("answer", "ignore", "label")]


def render_packet(row: Dict[str, str]) -> str:
    """Render a row as the labelled evidence packet the models read, grouped by kind of evidence."""
    known = {f for _, fields in FIELD_ORDER for f in fields}
    extra = [f for f in row if f not in known and field_kind(f) not in ("answer", "ignore")]
    kind_heading = {"label": "Other scanner labels (UNTRUSTED)", "capture": "Other runtime captures",
                    "observed": "Other test accounts", "code": "Other code and configuration",
                    "claim": "Other claims (assertions, not proof)", "quality": "Other evidence-quality notes",
                    "context": "Other context"}
    groups = FIELD_ORDER + [(kind_heading[k], [f for f in extra if field_kind(f) == k]) for k in kind_heading]
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
    """Extract provenance and correlation facts from a row without judging them.

    Covers revision identifiers, request-ID correlation across the HTTP exchange, logs and traces, sampling, and capture
    warnings. Facts are stated, never interpreted.

    Args:
        row: One finding.

    Returns:
        The facts, ready to render into the model's message.
    """
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
    """Render the facts block as indented JSON."""
    return json.dumps(facts, indent=1)


_WS = re.compile(r"\s+")


def normalise(text: str) -> str:
    """Lower-case text and collapse whitespace, the form in which quotes are compared with evidence."""
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

# The Fact-checker reads only what the client will read (title, impact, factual statements inside the fix) against
# the evidence of the finding the text was written from. It never touches a verdict or a score.
FACT_STATUSES = ("supported", "inference", "not_tested", "unsupported")
FACTCHECK_SCHEMA = {
    "type": "object",
    "properties": {
        "claims": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "field": {"type": "string", "enum": ["client_title", "business_impact", "recommended_fix"]},
                    "claim": {"type": "string", "description": "One atomic factual claim, in the text's own words."},
                    "status": {"type": "string", "enum": list(FACT_STATUSES)},
                    "quote": {"type": "string", "description": "For supported: verbatim text from the packet that "
                                                               "states the claim. Otherwise empty."},
                    "note": {"type": "string", "description": "For unsupported: what the packet actually says."},
                },
                "required": ["field", "claim", "status", "quote", "note"],
            },
        },
        "revised_title": {"type": "string", "description": "Only if the title has an unsupported claim; else empty."},
        "revised_impact": {"type": "string", "description": "Only if the impact has an unsupported claim; else empty."},
    },
    "required": ["claims", "revised_title", "revised_impact"],
}
FACTCHECK_SYSTEM = """You fact-check the client-facing text of a security report against the evidence packet of
the one finding it was written from. You do not judge whether the finding is real or how it is scored.

Split the title and the impact into atomic factual claims. In the recommended fix, check only statements of fact
about the system or the evidence (e.g. "the key was unrestricted"); skip advice. Give each claim one status:
- supported: the packet states it. Quote the packet verbatim (at least 16 characters, copied exactly) in `quote`.
- inference: it follows directly and generically from a demonstrated primitive without naming any data, system,
  person or consequence the packet does not mention (e.g. "code execution lets an attacker run commands as the
  service").
- not_tested: the text says something was not tested, not shown or not attempted, and the packet agrees.
- A claim framed as REACHABLE rather than demonstrated ("the same access could reach X") is supported when the packet
  itself states that X is accessible to the affected component (e.g. "worker shares a writable volume with report
  templates"); quote that statement. It is unsupported when X or its accessibility comes from nowhere in the packet.
- unsupported: anything else. In particular: data types, systems, scopes or attacker actions the packet does not
  name; follow-on movement, downtime, legal, contractual, regulatory or financial consequences; a test described as
  a real-world event; an effect the packet says was blocked or not attempted described as having happened; the
  access an attacker needs stated more loosely than the CVSS vector given; a statement that rests only on an owner
  comment, ticket thread or claimed control but is presented as established fact rather than attributed ("the owner
  states ...").

If any claim in the title or impact is unsupported, write revised_title and/or revised_impact that remove or
correct only those claims, keep every supported claim, use plain language for an executive, add nothing new, and
keep the impact to 2-3 sentences (a title is a noun phrase of at most 12 words). Otherwise leave them empty.
Never mention yourself, a model, AI or these rules."""


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


# Category wording differs between tools ("SQL Injection", "CWE-89", "IDOR"); these keywords find the rubric when
# the category is not one of the rubric names. First match wins, so the more specific patterns come first.
RUBRIC_KEYWORDS = [
    (r"ssrf|server.side request", "Server-Side Request Forgery"), (r"path traversal|directory traversal|lfi|cwe-22\b", "Path Traversal"),
    (r"upload|archive|zip.?slip", "File Upload"), (r"rce|remote code|code exec|eval|deseriali|cwe-(94|95|502)\b", "Code Execution"),
    (r"inject|sqli|cwe-(78|89)\b", "Injection"), (r"oauth|redirect|cwe-601\b", "OAuth"),
    (r"cors|xss|cross.site|csrf|clickjack|cwe-(79|352|942)\b", "Browser Security"),
    (r"secret|api key|credential.*(exposed|leak|hard)|hard.?coded|cwe-(798|540)\b", "Secret Detection"),
    (r"password reset|account recovery|reset token|cwe-640\b", "Account Recovery"),
    (r"idor|access control|authori[sz]|privilege|tenant|cwe-(639|862|863|284)\b", "Authorization"),
    (r"authenticat|login|session|jwt|token|enumerat|cwe-(287|347|204)\b", "Authentication"),
    (r"crypt|random|prng|cipher|tls|ssl|hash|cwe-(327|330|338)\b", "Cryptography"),
    (r"race|concurren|toctou|cwe-362\b", "Concurrency"),
    (r"disclos|exposure|debug|stack trace|verbose|information leak|cwe-(200|209|489)\b", "Information Exposure"),
]


def rubric_for(category: str) -> Optional[Dict[str, object]]:
    """Return the rubric for a finding category (by name, else by keyword), or None when no rubric fits."""
    c = (category or "").strip()
    if c in RUBRICS:
        return RUBRICS[c]
    for pattern, name in RUBRIC_KEYWORDS:
        if re.search(pattern, c, re.I):
            return RUBRICS[name]
    return None


def render_rubric(category: str) -> str:
    """Render a category's rubric as prompt text: decisive boundary, look-alikes and the checklist. Empty if there is none."""
    r = rubric_for(category)
    if not r:
        return ""
    checks = "\n".join(f"- {cid}: {text}" for cid, text in r["checks"])
    return (f"Decisive boundary for this category: {r['boundary']}\n"
            f"Look-alikes that are often mistaken for the opposite: {r['lookalikes']}\n"
            f"Checklist (answer every id, in the `checklist` field, before you classify):\n{checks}")


_COMMON_RULES = """
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
  downgrade. Scanner labels and identifiers ({metadata}, and any field named label.*) are not evidence and do not count;
  a quote must say something beyond the request ID.
- For Confirmed, at least one citation must come from a runtime field ({runtime}, or a field named capture.* or
  observed.*). Fields named claim.* are assertions, like owner comments.
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
  Do not score impact the packet gives no basis for. Pick AV/PR/UI from what the test actually required. Use PR:N
  only when the packet affirmatively shows no account is needed (a public artifact, a request stated to be
  unauthenticated, or a forged or absent credential that was accepted). A capture that simply shows no credential
  header is not that proof, because captures can omit or rewrite headers: use PR:L and say in cvss_rationale that
  the credential requirement was not shown. PR is the ATTACKER's privilege: when the attack is delivered through a
  victim's action (a crafted link, a malicious page), the victim's account belongs in UI:R, not in PR, and the test
  account used to play the victim does not make it PR:L. Pick S:C
  only when the impact lands outside the vulnerable component's security authority. The demonstrated-vs-reachable
  distinction belongs in business_impact, not in a lowered vector.
- client_title: a noun phrase of at most 12 words naming the flaw and the affected function (e.g. "SQL injection in
  vehicle lookup endpoint"). Not a sentence, no consequence clause, no host name.
- business_impact: 2-3 plain-language sentences for a non-technical executive: who could do what, to whose data or
  systems, and why it matters. No jargon. Name the attacker by the access the vector requires (PR:N "anyone who can
  reach ...", PR:L "any signed-in user ...", PR:H "an administrator ..."). Separate what was DEMONSTRATED from what
  the packet shows is REACHABLE (e.g. "the test read a planted canary file; the same access reaches customer exports
  stored on that host"). Use the packet's own words for data and scopes (say "customers and payment intents", not
  "billing records"). Never claim access to data, systems, follow-on movement, downtime, legal, contractual or
  regulatory consequences the packet does not mention. If the packet says an effect was blocked (e.g. by a safety
  interlock) or not attempted, say so rather than implying it happened. Describe the test as a test, never as a
  real-world event. Four rules that are easy to break:
  * Name a consequence only if the packet names it. No generic follow-ons the packet does not state (phishing,
    data theft, "customer data", altered reports); "report-source exports" stays "report-source exports".
  * Something stated only in an owner comment, ticket thread or claimed control is attributed ("the owner states
    ..."), never presented as established, and never the basis for how far the access reaches.
  * If PR:L was chosen only because the credential requirement was not shown, say that ("an attacker who can reach
    the search page; whether an account is needed was not shown"), not "any signed-in user".
  * Scope the attacker exactly as the packet does ("callers from the three namespaces the network policy permits",
    not "anyone on the network") and never hedge the vector ("an account, if one is required").
  * Not attempted means not tested: "no outbound callback was used" is not "the test showed no outbound traffic".
  * Never fill in how a result was obtained when the packet does not say ("the state was recovered", not "the
    state was recovered from job IDs"), and attribute to the owner only what an owner comment actually says.
- recommended_fix: concrete, specific to the code/config shown; primary fix first, then defense in depth; end with
  one sentence that starts "To verify," describing how to confirm the fix.
- Use US English spelling (organization, behavior, defense, authorized).
""".format(
    min_conf=MIN_DECISIVE_CONFIDENCE, min_cites=MIN_CITATIONS_CONFIRMED, min_chars=MIN_QUOTE_CHARS,
    metadata=", ".join(sorted(METADATA_FIELDS)), runtime=", ".join(sorted(RUNTIME_FIELDS)))

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
    """Build the message that asks a reviewer to classify one finding.

    Args:
        packet: The rendered evidence packet.
        facts: The rendered deterministic facts.
        rubric: The rendered category rubric, or an empty string.
    """
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
    """Build the message that asks the Arbiter to settle two disagreeing reviews.

    Args:
        packet: The rendered evidence packet.
        facts: The rendered deterministic facts.
        first: The first reviewer's assessment.
        second: The second reviewer's assessment.
        rubric: The rendered category rubric, or an empty string.
    """
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

    def add(self, **kw: float) -> None:
        """Add to the named counters, safely across worker threads."""
        with self.lock:
            for k, v in kw.items():
                setattr(self, k, getattr(self, k) + v)


def validate(obj: object, schema: dict, path: str = "$") -> List[str]:
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


def _extract_json(text: str) -> Any:
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


class LLMBackend(Protocol):
    """What the pipeline needs from a model backend: ClaudeCLI in production, FakeLLM in the tests."""

    stats: CallStats

    def complete(self, stage: str, system: str, schema: dict, message: str) -> dict:
        """Run one model call and return the schema-valid JSON object, or raise LLMError."""
        ...


class ClaudeCLI:
    """`models` is an ordered fallback chain, e.g. ["claude-opus-5-5", "claude-opus-4-8"].
    Per call: try each model in order. A permanent denial moves straight to the
    next model and disables the denied one for the rest of the run; transient
    failures (timeouts, unparsable or schema-invalid output) are retried with
    backoff before falling back. The model that actually answered is recorded
    on the output as `_model`."""

    def __init__(self, models: Union[str, Sequence[str]], effort: Optional[str] = "high", binary: str = "claude",
                 timeout: int = 420, retries: int = 3, cache_dir: Optional[Path] = None,
                 stats: Optional[CallStats] = None) -> None:
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
        """The model chain as text, primary first."""
        return " -> ".join(self.models)

    def check_available(self) -> None:
        """Raise LLMError if the claude binary is not on PATH."""
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
        """Hash of everything that determines a model answer: model, effort, prompts, schema and message."""
        h = hashlib.sha256()
        for part in (model, str(self.effort), system, json.dumps(schema, sort_keys=True), message):
            h.update(part.encode())
            h.update(b"\x00")
        return h.hexdigest()[:32]

    def complete(self, stage: str, system: str, schema: dict, message: str) -> dict:
        """Run one model call through the fallback chain, with caching, retries and schema validation.

        Args:
            stage: Pipeline stage name (classify, verify or adjudicate); selects the cache folder.
            system: System prompt.
            schema: JSON schema the answer must satisfy.
            message: User message.

        Returns:
            The schema-valid answer, tagged with the model that gave it.

        Raises:
            LLMError: If every model fails or denies the request.
        """
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

    def _call_once(self, model: str, system: str, schema: dict, message: str) -> Tuple[dict, float]:
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

    def __init__(self, responder: Callable[[str, str], dict]) -> None:
        self.responder = responder
        self.stats = CallStats()
        self.model = "fake"

    def check_available(self) -> None:
        """Always available."""
        pass

    def complete(self, stage: str, system: str, schema: dict, message: str) -> dict:
        """Return the responder's answer, rejecting it if it breaks the schema."""
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
    """Check that each cited quote appears verbatim in the row.

    Args:
        row: The finding the quotes were cited against.
        citations: Quotes with the field each claims to come from.

    Returns:
        The citations found, with the field they were located in, and the citations not found.
    """
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
    """One entry per rubric check, in rubric order. A yes or no only counts as `backed` when its quote is found
    verbatim in the row; a missing or repeated check id is treated as unknown."""
    rubric = rubric_for(row.get("category") or row.get("finding_title", ""))
    if not rubric:
        return []
    given: Dict[str, dict] = {}
    for c in checklist or []:
        given.setdefault(c.get("id"), c)
    out = []
    for cid, text in rubric["checks"]:
        c = given.get(cid) or {}
        answer = c.get("answer") if c.get("answer") in ("yes", "no") else "unknown"
        hit = next(iter(verify_citations(row, [c])[0]), {}) if answer != "unknown" else {}
        out.append({"id": cid, "check": text, "answer": answer, "backed": bool(hit),
                    "field": hit.get("field", ""), "quote": hit.get("quote", "")})
    return out


def merge_checklists(row: Dict[str, str], first: List[dict], second: List[dict]) -> List[dict]:
    """Two agreeing assessors: a check keeps its answer only when both gave it; otherwise it is unknown."""
    out = []
    for ca, cb in zip(verify_checklist(row, first), verify_checklist(row, second)):
        if ca["answer"] == cb["answer"] != "unknown":
            pick = ca if ca["backed"] else cb
            out.append({"id": ca["id"], "answer": ca["answer"], "field": pick["field"], "quote": pick["quote"]})
        else:
            out.append({"id": ca["id"], "answer": "unknown", "field": "", "quote": ""})
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
    has_runtime = any(is_runtime(f) for f in cited)
    has_capture = any(is_capture(f) for f in cited)  # request, response, exchange, log, trace or tool output
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
        if all(is_claim(f) for f in cited):
            reasons.append("the case for dismissal rests only on owner or ticket statements")
        if (facts.get("release_bot_image_differs_from_source") or facts.get("source_revision_matches_manifest") is False) \
                and not has_runtime:
            reasons.append("the reviewed source is not shown to be the running revision, "
                           "and no test of the running service shows the control in place")
    elif cls != "Needs Review":
        reasons.append(f"unknown classification {cls!r}")
    checks = verify_checklist(row, a.get("checklist", []))
    why = checklist_reason(row.get("category") or "this type of", cls, checks)
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


def priority(score: Optional[float], environment: str) -> Tuple[Optional[float], str]:
    """Weight a CVSS score by how close the system is to production and assign a fix tier.

    Args:
        score: The CVSS base score, or None if unscored.
        environment: The environment name, such as "production".

    Returns:
        The priority score and its tier (CHASE, LOOK or NOTE), or (None, "") if unscored.
    """
    if score is None:
        return None, ""
    p = round(score * ENV_WEIGHT.get(env_class(environment), DEFAULT_ENV_WEIGHT), 2)
    tier = "CHASE" if p >= TIER_CHASE else "LOOK" if p >= TIER_LOOK else "NOTE"
    return p, tier


def _cvss_of(a: dict) -> Tuple[Optional[str], Optional[float], Optional[str]]:
    return score_vector((a.get("report") or {}).get("cvss_vector"))


# Severity order of each CVSS 3.1 base metric's values, least severe first.
METRIC_ORDER = {"AV": "PLAN", "AC": "HL", "PR": "HLN", "UI": "RN", "S": "UC", "C": "NLH", "I": "NLH", "A": "NLH"}


def tiebreak_vector(reviews: Sequence[dict]) -> Tuple[Optional[dict], str]:
    """Combine the CVSS vectors of every review that confirmed the finding, deterministically.

    Each metric takes the median of the reviews' values in severity order; with an even number of reviews the less
    severe of the two middle values wins, so a higher rating needs agreement and no single review can raise the
    score alone. The report text (title, rationale, impact, fix) comes from the review whose vector is closest to the
    result, and one sentence is added naming each metric the reviews scored differently. The outcome does not depend
    on the order of the reviews.

    Returns:
        The report to use (None if no review has a valid vector) and the added note ("" when all vectors agree).
    """
    scored = [(r, parse_vector(score_vector((r.get("report") or {}).get("cvss_vector"))[0]))
              for r in reviews if score_vector((r.get("report") or {}).get("cvss_vector"))[0]]
    if not scored:
        return None, ""
    final, split = {}, []
    for m, order in METRIC_ORDER.items():
        values = sorted((v[m] for _, v in scored), key=order.index)
        final[m] = values[(len(values) - 1) // 2]
        if len(set(values)) > 1:
            split.append(f"{m} ({' vs '.join(sorted(set(values), key=order.index, reverse=True))}; scored {final[m]})")
    vector = "CVSS:3.1/" + "/".join(f"{m}:{final[m]}" for m in METRIC_ORDER)
    # Closest review first; ties broken by the review's own vector text so the choice is order-independent.
    closest = min(scored, key=lambda rv: (sum(rv[1][m] != final[m] for m in METRIC_ORDER), rv[0]["report"]["cvss_vector"]))[0]
    report = dict(closest["report"], cvss_vector=vector)
    note = ""
    if split:
        note = ("The reviews scored " + ", ".join(split) + " differently; where they disagree the score uses the middle "
                "value, or the less severe one when there is no middle, because a higher rating needs agreement.")
        report["cvss_rationale"] = (report.get("cvss_rationale", "").rstrip() + " " + note).strip()
    return report, note


def needs_adjudication(a: dict, b: dict) -> Optional[str]:
    """Decide whether two reviews of one finding need a third.

    Returns:
        The reason, or None if the reviews agree on the label and, for Confirmed, on every CVSS metric.
    """
    if a["classification"] != b["classification"]:
        return f"classification: A={a['classification']} vs B={b['classification']}"
    if a["classification"] == "Confirmed":
        _, sa, _ = _cvss_of(a)
        _, sb, _ = _cvss_of(b)
        if sa is None or sb is None:
            return "Confirmed without a valid CVSS vector from both assessors"
        if abs(sa - sb) >= CVSS_DIVERGENCE:
            return f"CVSS divergence: A={sa} vs B={sb}"
        if cvss_severity_label(sa) != cvss_severity_label(sb):
            return f"CVSS severity band differs: A={sa} ({cvss_severity_label(sa)}) vs B={sb} ({cvss_severity_label(sb)})"
        va, vb = parse_vector(_cvss_of(a)[0]), parse_vector(_cvss_of(b)[0])
        split = [m for m in METRIC_ORDER if va[m] != vb[m]]
        if split:  # a third vote, so the per-metric median in tiebreak_vector is a real majority
            return "CVSS metrics differ: " + ", ".join(f"{m} A={va[m]} B={vb[m]}" for m in split)
    return None


_UNSCORED = {"cvss_vector": None, "cvss_score": None, "cvss_severity": None,
             "priority_score": None, "priority_tier": ""}


def _base_result(row: Dict[str, str]) -> Dict[str, object]:
    base = {k: row.get(k, "") for k in ("finding_id", "asset", "environment", "finding_title", "category",
                                        "asset_owner", "scanner_source", "first_observed_utc", "last_observed_utc")}
    return base


def assess_row(row: Dict[str, str], llm: LLMBackend, context: Optional[Dict[str, str]] = None) -> Dict[str, object]:
    """Run the full pipeline for one finding: classify, verify blind, adjudicate on disagreement, then gate.

    Any model failure routes the finding to Needs Review with confidence 0 instead of raising.

    Args:
        row: The finding.
        llm: The model backend.
        context: Dataset-wide context computed across all rows, if any.

    Returns:
        The final result, including both reviews, the gate outcome and, for Confirmed, the CVSS score and priority.
    """
    packet = render_packet(row)
    facts_obj = extract_facts(row)
    facts = render_facts({**facts_obj, "dataset_context": context} if context else facts_obj)
    rubric = render_rubric(row.get("category") or row.get("finding_title", ""))
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
        def n_verified(x: dict) -> int:
            return len(verify_citations(row, x.get("evidence", []))[0])

        primary, other = (a, b) if n_verified(a) >= n_verified(b) else (b, a)
        if primary["classification"] == "Confirmed" and _cvss_of(primary)[0] is None:
            primary, other = other, primary
        final = dict(primary)
        final["confidence"] = min(float(a["confidence"]), float(b["confidence"]))
        final["boundary_observed"] = bool(a.get("boundary_observed")) and bool(b.get("boundary_observed"))
        final["checklist"] = merge_checklists(row, a.get("checklist", []), b.get("checklist", []))
        if final["classification"] == "Confirmed":
            report, _ = tiebreak_vector([a, b])
            if report:
                final["report"] = report
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
        if final["classification"] == "Confirmed":
            report, _ = tiebreak_vector([x for x in (a, b, c) if x.get("classification") == "Confirmed"])
            if report:
                final["report"] = report
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


def run(rows: List[Dict[str, str]], llm: LLMBackend, workers: int = 4,
        progress: Optional[Callable[[int, int, dict], None]] = None,
        context: Optional[Dict[str, str]] = None) -> List[Dict[str, object]]:
    """Assess every row in parallel.

    Args:
        rows: The findings to assess.
        llm: The model backend.
        workers: Number of findings assessed at once.
        progress: Called with (done, total, result) as each finding finishes.
        context: Dataset-wide context passed to every assessment.

    Returns:
        One result per row, in input order.
    """
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
    """Key under which two rows carry the same evidence: same scenario and same evidence-profile facts."""
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
# Generated prose is normalised to US spelling (the source data is US English); verbatim evidence is never rewritten.
_US_SPELLING = {
    "organisation": "organization", "organisations": "organizations", "organisational": "organizational",
    "behaviour": "behavior", "behaviours": "behaviors", "defence": "defense", "defences": "defenses",
    "artefact": "artifact", "artefacts": "artifacts", "honour": "honor", "honoured": "honored", "honours": "honors",
    "authorise": "authorize", "authorised": "authorized", "authorises": "authorizes", "authorisation": "authorization",
    "unauthorised": "unauthorized", "parameterise": "parameterize", "parameterised": "parameterized",
    "sanitise": "sanitize", "sanitised": "sanitized", "sanitisation": "sanitization", "normalise": "normalize",
    "normalised": "normalized", "serialise": "serialize", "serialised": "serialized", "deserialise": "deserialize",
    "deserialised": "deserialized", "prioritise": "prioritize", "prioritised": "prioritized", "minimise": "minimize",
    "recognise": "recognize", "recognised": "recognized", "analyse": "analyze", "analysed": "analyzed",
    "utilise": "use", "licence": "license", "centre": "center", "catalogue": "catalog", "favour": "favor",
}
_FILLER = r"(?:Notably|Importantly|Crucially|Overall|In summary|Ultimately|Additionally|Furthermore|Moreover|It is worth noting that|It's worth noting that|Note that)"
AI_TELLS = re.compile(
    r"[\u2014\u2013]|\b(?:delve|robust|leverage[sd]?|comprehensive|seamless(?:ly)?|underscores?|landscape|"
    r"notably|importantly|crucially|it'?s worth noting|it is worth noting|in summary|as an ai|language model)\b|"
    r"\b(?:packet|assessor)s?\b|\bfacts block\b|"
    + r"\b(?:" + "|".join(sorted((k for k in FIELD_WORDS if "_" in k), key=len, reverse=True)) + r")\b", re.I)


def _capitalise_sentences(t: str) -> str:
    """Capitalise a lowercase word that starts a sentence ('list. the evidence' -> 'list. The evidence'), but not
    after abbreviations such as e.g. or i.e., and not code (a word followed by '(', '.' or '_')."""
    def up(m: "re.Match[str]") -> str:
        before = t[max(0, m.start() - 6):m.start()].lower()
        if re.search(r"\b(e\.g|i\.e|etc|vs|approx|no)\.\s*$", before):
            return m.group(0)
        return m.group(0)[:-len(m.group(1))] + m.group(1)[:1].upper() + m.group(1)[1:]
    return re.sub(r"(?<=[a-z0-9)\"'][.!?]) +([a-z]+)(?![(._\w])", up, t)


def plain_text(text: str) -> str:
    """Rewrite model-written text into plain client-facing language: no dashes, filler phrases, internal field names or jargon."""
    if not text:
        return text
    t = str(text)
    t = re.sub(r"\s*[\u2014]\s*", ", ", t)                       # em dash -> comma
    t = re.sub(r"(?<=\w)\s*\u2013\s*(?=\w)", "-", t)              # en dash between words -> hyphen
    t = re.sub(r"\s*\u2013\s*", ", ", t)
    for pat, rep in _PHRASES:
        t = re.sub(pat, lambda m, r=rep: (r[:1].upper() + r[1:]) if m.group(0)[:1].isupper() else r, t, flags=re.I)
    for name in sorted((k for k in FIELD_WORDS if "_" in k), key=len, reverse=True):
        t = re.sub(rf"`?\b{name}\b`?", FIELD_WORDS[name], t)
    t = re.sub(rf"(^|(?<=[.!?]\s)){_FILLER},?\s+(\w)", lambda m: m.group(1) + m.group(2).upper(), t)
    t = re.sub(rf",?\s*\b{_FILLER},\s*", ", ", t, flags=re.I)
    for word, plain in _PLAIN_WORDS.items():
        t = re.sub(rf"\b{word}\b", lambda m, p=plain: p.capitalize() if m.group(0)[0].isupper() else p, t, flags=re.I)
    t = re.sub(r"\b(" + "|".join(_US_SPELLING) + r")\b",
               lambda m: (lambda us: us.capitalize() if m.group(0)[0].isupper() else us)(_US_SPELLING[m.group(0).lower()]),
               t, flags=re.I)
    t = re.sub(r",\s*,", ",", t)
    t = _capitalise_sentences(t)
    # Drop stray space before punctuation, but not before "../" or "..." (paths and code samples).
    t = re.sub(r"\s+([,;:]|\.(?![./\w]))", r"\1", t)
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


_ACTOR = {"L": "any signed-in user", "H": "a user with administrative privileges"}


_PR_ASSUMED = re.compile(r"PR:L[^.]*\b(not shown|was not shown|not stated|does not (show|state)|assum)", re.I)


def align_actor(text: str, vector: object, rationale: object = "") -> str:
    """'Anyone who can reach X' overstates a flaw whose CVSS vector requires an account (PR:L) or admin rights (PR:H);
    name the attacker the vector describes instead. When PR:L is only an assumption (the rationale says the
    credential requirement was not shown), the neutral 'an attacker' is used rather than claiming an account."""
    m = re.search(r"PR:([NLH])", str(vector or ""))
    who = _ACTOR.get(m.group(1)) if m else None
    if who and m.group(1) == "L" and _PR_ASSUMED.search(str(rationale or "")):
        who = "an attacker"
    if not who or not text:
        return text
    return re.sub(r"\b(anyone|anybody|any caller|any client|any attacker|an unauthenticated attacker|an outsider)\b(?= (who|with|that|can|could))",
                  lambda x: who.capitalize() if x.group(0)[0].isupper() else who, text, flags=re.I)


def polish_result(r: Dict[str, object]) -> Dict[str, object]:
    """Clean every client-facing text field of a result in place and return it."""
    for k in CLIENT_TEXT_FIELDS:
        if isinstance(r.get(k), str):
            r[k] = plain_text(r[k])
    r["business_impact"] = align_actor(r.get("business_impact") or "", r.get("cvss_vector"), r.get("cvss_rationale"))
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
    """Name the attack-progression step a result represents, or None if it fits no known step."""
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
        donor = min((m for m in members if m["cvss_vector"] == chosen), key=lambda m: m["finding_id"])
        for m in members:
            if m["cvss_vector"] != chosen:
                # The rationale must describe the vector shown, so it comes with the vector.
                m["cvss_rationale_original"], m["cvss_rationale"] = m.get("cvss_rationale"), donor.get("cvss_rationale")
                m["business_impact"] = align_actor(m.get("business_impact") or "", chosen, donor.get("cvss_rationale"))
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


# ---------------------------------------------------------------------------
# Fact-checker: client-facing claims against the evidence
# ---------------------------------------------------------------------------
def factcheck_message(row: Dict[str, str], r: dict, title: str, impact: str) -> str:
    return (f"<evidence_packet>\n{render_packet(row)}\n</evidence_packet>\n\n"
            f"<cvss_vector>{r.get('cvss_vector') or ''}</cvss_vector>\n"
            f"<client_title>{title}</client_title>\n<business_impact>{impact}</business_impact>\n"
            f"<recommended_fix>{r.get('recommended_fix') or ''}</recommended_fix>")


# Record facts a claim may rest on besides the evidence ("on the production service"). The scanner's own severity,
# confidence and rule are opinions, not facts, and stay excluded.
RECORD_FIELDS = ("asset", "environment", "asset_owner", "category", "first_observed_utc", "last_observed_utc")


def _in_record(row: Dict[str, str], quote: str) -> bool:
    q = normalise(quote)
    return bool(q) and any(q in normalise(row.get(f) or "") for f in RECORD_FIELDS)


def _strip_markup(quote: str) -> str:
    """Quotes copied from the packet sometimes carry its <field name="..."> wrapper; the value is what counts."""
    return re.sub(r"</?field\b[^>]*>", " ", quote or "").strip()


def verify_claims(row: Dict[str, str], claims: List[dict]) -> List[dict]:
    """Code check on the Fact-checker: a claim marked supported must quote text that is really in the row, either
    in the evidence or in the row's record fields. A missing or invented quote turns the claim into unsupported."""
    out = []
    for c in claims:
        c = dict(c)
        q = _strip_markup(c.get("quote", ""))
        if c["status"] == "supported" and not (locate_quote(row, q) or _in_record(row, q)):
            c["status"], c["note"] = "unsupported", ("quoted text not found in the evidence; " + c.get("note", "")).strip("; ")
        out.append(c)
    return out


def _unsupported(claims: List[dict], fields: Sequence[str] = ("client_title", "business_impact")) -> List[dict]:
    return [c for c in claims if c["status"] == "unsupported" and c["field"] in fields]


def fact_check(results: List[dict], rows: Dict[str, Dict[str, str]], llm: LLMBackend) -> List[dict]:
    """Check the text the client will read for every confirmed issue, written from the issue's lead finding.

    Unsupported claims in the title or impact get one rewrite, which is checked again. Text that still carries an
    unsupported claim is kept but flagged, so a person fixes it before the report goes out. A failed call is also
    flagged; nothing is ever passed unchecked. Unsupported statements inside the fix are reported, not rewritten.

    Returns:
        One record per issue: finding_id, status (passed, revised, flagged) and the claims.
    """
    log = []
    for group in issue_groups([r for r in results if r["classification"] == "Confirmed"]):
        lead = group[0]
        row = rows.get(lead["finding_id"])
        if row is None:
            continue
        title, impact = lead.get("client_title") or "", lead.get("business_impact") or ""
        record = {"finding_id": lead["finding_id"], "issue": display_title(lead), "status": "passed",
                  "original": {"client_title": title, "business_impact": impact}}
        try:
            first = llm.complete("factcheck", FACTCHECK_SYSTEM, FACTCHECK_SCHEMA, factcheck_message(row, lead, title, impact))
            claims = verify_claims(row, first["claims"])
            if _unsupported(claims):
                title = plain_text(first["revised_title"]) or title
                impact = align_actor(plain_text(first["revised_impact"]) or impact, lead.get("cvss_vector"), lead.get("cvss_rationale"))
                second = llm.complete("factcheck", FACTCHECK_SYSTEM, FACTCHECK_SCHEMA, factcheck_message(row, lead, title, impact))
                record["first_pass"] = claims
                claims = verify_claims(row, second["claims"])
                record["status"] = "flagged" if _unsupported(claims) else "revised"
                lead["client_title"], lead["business_impact"] = title, impact
        except LLMError as exc:
            claims, record["status"], record["error"] = [], "flagged", f"fact check failed: {exc}"
        record["claims"] = claims
        record["fix_unsupported"] = [c["claim"] for c in _unsupported(claims, ("recommended_fix",))]
        lead["fact_check"] = {k: record[k] for k in ("status", "claims", "fix_unsupported") if k in record}
        if record.get("error"):
            lead["fact_check"]["error"] = record["error"]
        log.append(record)
    return log


# ============================================================================
# Client HTML report
# ============================================================================
# Client-ready, self-contained HTML report (no external assets).
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}
FIELD_LABELS = {
    "observation": "Source observation", "validation_attempt": "Validation test", "raw_request": "HTTP request",
    "raw_response": "HTTP response", "raw_http_exchange": "HTTP exchange", "mixed_service_logs": "Service logs",
    "distributed_trace_excerpt": "Distributed trace", "source_code_excerpt": "Source code",
    "code_or_config_context": "Code / config", "deployment_manifest_excerpt": "Deployment manifest",
    "conflicting_revision_diff": "Revision diff", "identity_network_context": "Identity / network context",
    "contradictory_evidence": "Contradictory evidence", "claimed_compensating_controls": "Claimed controls",
    "ticket_comment_thread": "Ticket thread", "evidence_gaps": "Evidence gaps",
    "evidence_collection_warnings": "Collection warnings",
}


def field_label(f: str) -> str:
    """Human label for a pipeline key: 'capture.plugin_output' -> 'Plugin output'."""
    if f in FIELD_LABELS:
        return FIELD_LABELS[f]
    name = _KIND_PREFIX.sub("", f).replace("_", " ").strip()
    return (name[:1].upper() + name[1:]) or f


def e(x: object) -> str:
    """Escape a value for HTML. None becomes an empty string."""
    return html.escape("" if x is None else str(x), quote=True)


# URLs, API paths, file names, function calls and code identifiers in prose are
# set as code, the way a consultant formats them in a written report.
_CODE_TOKEN = re.compile(
    r"https?://[^\s<>\"']+[^\s<>\"'.,;:)]"
    r"|(?<![\w/.])(?:(?:\.\./)+|/)(?:[\w.~%-]+/)+(?:[\w.~%-]*[\w~%-])?(?:\?[^\s<>\"']*[^\s<>\"'.,;:)])?"
    r"|\b[\w/]+\.(?:py|yaml|yml|json|txt)\b"
    r"|\b[A-Za-z_][\w.]*\([^()\s]{0,40}\)"
    r"|\b[A-Za-z_]\w*(?:\.\w+)*\.\w*_\w*\b"
    r"|\b[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+\b")


def prose(x: object) -> str:
    """Escape model-written prose and set code-like tokens in <code>."""
    out, last = [], 0
    text = "" if x is None else str(x)
    for m in _CODE_TOKEN.finditer(text):
        out.append(e(text[last:m.start()]))
        out.append(f"<code>{e(m.group(0))}</code>")
        last = m.end()
    out.append(e(text[last:]))
    return "".join(out)


def _sev_badge(sev: Optional[str]) -> str:
    return f'<span class="sev sev-{e((sev or "none").lower())}">{e({"Medium": "Moderate"}.get(sev, sev or "Unscored"))}</span>'


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _cls_badge(c: str) -> str:
    slug = {"Confirmed": "conf", "False Positive": "fp", "Needs Review": "nr"}.get(c, "nr")
    return f'<span class="cls cls-{slug}">{e(c)}</span>'


def _priority_key(r: dict) -> tuple:
    return (-(r.get("priority_score") or 0), SEV_ORDER.get(r.get("cvss_severity"), 5), r["finding_id"])


def _title_key(r: dict) -> tuple:
    return (r["finding_title"], r["finding_id"])


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
# Standard weakness references per issue type: CWE IDs, and the OWASP Top 10 (2021) category only where that
# category's published CWE mapping contains the CWE.
ISSUE_REFS = {
    "secret_exposure": (("CWE-540", "Inclusion of Sensitive Information in Source Code"), ("CWE-798", "Use of Hard-coded Credentials")),
    "shell_injection": (("CWE-78", "OS Command Injection"),),
    "code_execution": (("CWE-95", "Eval Injection"),),
    "sql_injection": (("CWE-89", "SQL Injection"),),
    "token_forgery": (("CWE-347", "Improper Verification of Cryptographic Signature"),),
    "cross_tenant_command": (("CWE-639", "Authorization Bypass Through User-Controlled Key"),),
    "cross_tenant_report": (("CWE-639", "Authorization Bypass Through User-Controlled Key"),),
    "path_traversal": (("CWE-22", "Path Traversal"),),
    "archive_write": (("CWE-22", "Path Traversal"),),
    "reset_token": (("CWE-640", "Weak Password Recovery Mechanism for Forgotten Password"), ("CWE-330", "Use of Insufficiently Random Values")),
    "cors_credentialed": (("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"),),
    "oauth_redirect": (("CWE-601", "URL Redirection to Untrusted Site (Open Redirect)"),),
    "enumeration": (("CWE-204", "Observable Response Discrepancy"),),
    "ssrf": (("CWE-918", "Server-Side Request Forgery"),),
    "debug_exposure": (("CWE-489", "Active Debug Code"), ("CWE-215", "Insertion of Sensitive Information Into Debugging Code")),
}
OWASP_2021 = {
    "CWE-540": "A01:2021 Broken Access Control", "CWE-22": "A01:2021 Broken Access Control",
    "CWE-639": "A01:2021 Broken Access Control", "CWE-601": "A01:2021 Broken Access Control",
    "CWE-347": "A02:2021 Cryptographic Failures", "CWE-330": "A02:2021 Cryptographic Failures",
    "CWE-78": "A03:2021 Injection", "CWE-89": "A03:2021 Injection", "CWE-95": "A03:2021 Injection",
    "CWE-942": "A05:2021 Security Misconfiguration", "CWE-798": "A07:2021 Identification and Authentication Failures",
    "CWE-640": "A07:2021 Identification and Authentication Failures", "CWE-918": "A10:2021 Server-Side Request Forgery",
}


def references_html(key: str) -> str:
    """CWE links (and OWASP Top 10 categories) for an issue type; empty when the type has no mapping."""
    refs = ISSUE_REFS.get(key, ())
    items = [f"<a href='https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html'>{e(cwe)}</a> {e(name)}" for cwe, name in refs]
    owasp = sorted({OWASP_2021[c] for c, _ in refs if c in OWASP_2021})
    return "; ".join(items) + (f". OWASP Top 10: {e(', '.join(owasp))}" if owasp else "")


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
    """Attack-step type of a finding (e.g. sql_injection), else its category. Used for chains and labels."""
    return chain_step(r) or "other:" + str(r.get("category") or "uncategorized")


def flaw_key(r: dict) -> Tuple[str, str]:
    """One report section per distinct flaw: same attack-step type and same scanner finding title.
    Two SQL injections (a read-only lookup and an UPDATE identifier injection) share a type but not a title,
    endpoint, code or fix, so they stay separate."""
    return issue_key(r), r.get("finding_title") or ""


def flaw_anchor(key: Tuple[str, str]) -> str:
    return "issue-" + re.sub(r"[^a-z0-9]+", "-", f"{key[0]} {key[1]}".lower()).strip("-")


def issue_groups(confirmed: List[dict]) -> List[List[dict]]:
    """Confirmed findings grouped by flaw, each group led by its highest-priority finding. Groups are ordered by
    severity, then score, then production exposure, then reach, so both reports number the issues identically."""
    groups: Dict[Tuple[str, str], List[dict]] = {}
    for r in sorted(confirmed, key=_priority_key):
        groups.setdefault(flaw_key(r), []).append(r)

    def order(rows: List[dict]) -> tuple:
        lead = rows[0]
        return (SEV_ORDER.get(lead.get("cvss_severity"), 5), -(lead.get("cvss_score") or 0),
                -sum(1 for r in rows if _is_prod(r)), -len(rows), lead["finding_id"])
    return sorted(groups.values(), key=order)


def _is_prod(r: dict) -> bool:
    return env_class(r["environment"]) == "production"


def _systems(rows: List[dict]) -> int:
    """Distinct systems (host and environment) behind a set of findings. Several findings can be on one system."""
    return len({(r["asset"], r["environment"].strip().lower()) for r in rows})


def _reach(rows: List[dict]) -> str:
    """'7 findings on 3 systems' - findings and systems are different counts and both are stated."""
    return f"{_plural(len(rows), 'finding', 'findings')} on {_plural(_systems(rows), 'system', 'systems')}"


_TITLE_HOST = re.compile(r"\s+on\s+[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:example|internal)\b|\s+in production\b", re.I)


def _fmt_date(d: dt.date) -> str:
    return d.strftime("%B %d, %Y").replace(" 0", " ")


def _dates(days: List[str]) -> List[dt.date]:
    good = []
    for d in days:
        try:
            good.append(dt.date.fromisoformat((d or "")[:10]))
        except ValueError:
            continue
    return good


def _date_window(days: List[str], default: str = "the observation period") -> str:
    """'July 1, 2026 to October 11, 2026' from ISO dates; unparseable values are skipped."""
    good = _dates(days)
    return f"{_fmt_date(min(good))} to {_fmt_date(max(good))}" if good else default


def _observed(rows: List[dict], today: Optional[dt.date] = None) -> Tuple[str, str]:
    """The span the scanner observed these findings (first to last observation), and a note when the source
    timestamps run past the report date. Timestamps are reported as recorded, never corrected."""
    days = [r.get(k) or "" for r in rows for k in ("first_observed_utc", "last_observed_utc")]
    good, today = _dates(days), today or dt.date.today()
    late = sum(1 for r in rows if any(d > today for d in _dates([r.get("first_observed_utc") or "", r.get("last_observed_utc") or ""])))
    note = (f"{_plural(late, 'finding has', 'findings have')} source timestamps later than the report date "
            f"({_fmt_date(today)}); dates are reported as recorded in the source data.") if late else ""
    return (_date_window(days) if good else ""), note


def _observed_from(window: str) -> str:
    """', observed from July 1, 2026 to ...', or nothing when the source data records no dates."""
    return f", observed from {window}" if window else ""


def display_title(r: dict) -> str:
    """Heading for an issue. The model words each title from one example, so a host name
    or 'in production' in it would be wrong for the other systems listed under it."""
    t = r.get("client_title") or r.get("finding_title") or ""
    t = _TITLE_HOST.sub("", t)
    return re.sub(r"\s+([,;])", r"\1", re.sub(r"\benabled (exposes)", r"\1", t)).strip()


def issue_label(key: str, lead: dict) -> str:
    """Short plain name for an issue type, used in headings and charts."""
    if key in ISSUE_LABEL:
        return ISSUE_LABEL[key]
    return (lead.get("client_title") or lead.get("finding_title") or "Other").split(" (")[0]


def _group_by_issue(rows: List[dict], key: Callable[[dict], Any] = _priority_key) -> Dict[str, List[dict]]:
    groups: Dict[str, List[dict]] = {}
    for r in sorted(rows, key=key):
        groups.setdefault(issue_key(r), []).append(r)
    return groups


def _sentences(text: object) -> List[str]:
    # Not after "...", "= ?" or ".." (SQL placeholders and ellipses inside code samples).
    return [s.strip() for s in re.split(r"(?<=[.!?])(?<!\.\.\.)(?<!= \?)\s+(?=[A-Z0-9])", str(text or "").strip()) if s.strip()]


_HARDEN = re.compile(r"^(as (further |additional )?(defence|defense|protection)|for (extra )?defence|"
                     r"as defence|alternatively|also,? (add|limit|run|move|turn))", re.I)
# "Verify every token against the issuer key" is a fix step, not a retest, so bare "Verify" does not start verification.
_VERIFY = re.compile(r"^(to verify|verify (by|the fix|that the fix)|to confirm|confirm that|check that|retest)", re.I)


def split_fix(text: object) -> Tuple[List[str], List[str], List[str]]:
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


def _trim(s: object, n: int = 240) -> str:
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    return s if len(s) <= n else s[: n - 1].rstrip() + "..."


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


def _bar_rows(items: List[Tuple[str, int, str, str]], scale: int) -> str:
    """items: (label, value, color, href). Horizontal bars, one per row."""
    scale = scale or 1
    rows = []
    for label, n, color, href in items:
        name = f"<a href='{e(href)}'>{e(label)}</a>" if href else e(label)
        rows.append(f"<div class='brow'><span class='bl'>{name}</span><span class='bt'><span class='bf' "
                    f"style='width:{(max(100 * n / scale, 2) if n else 0):.1f}%;background:{color}'></span></span><b class='bv'>{n}</b></div>")
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


def _cvss_chips(vector: object) -> str:
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


def _tier_badge(tier: Optional[str]) -> str:
    return f"<span class='tier tier-{e((tier or '').lower())}'>{e(TIER_LABEL.get(tier, tier))}</span>" if tier else ""


def _evidence_points(ev: List[dict], limit: int = 4) -> str:
    if not ev:
        return "<p class='muted'>No verifiable citations.</p>"
    items = []
    for c in ev[:limit]:
        items.append(f"<li><b>{prose(c.get('supports', ''))}</b><span class='src'>{e(field_label(c['field']))}</span>"
                     f"<code class='quote'>{e(_trim(c['quote'], 300))}</code></li>")
    more = ""
    if len(ev) > limit:
        more = ("<details class='more'><summary>" + f"{len(ev) - limit} more evidence item{'s' if len(ev) - limit != 1 else ''}</summary>"
                "<ul class='proof'>" + "".join(
                    f"<li><b>{prose(c.get('supports', ''))}</b><span class='src'>{e(field_label(c['field']))}</span>"
                    f"<code class='quote'>{e(_trim(c['quote'], 300))}</code></li>" for c in ev[limit:]) + "</ul></details>")
    return f"<ul class='proof'>{''.join(items)}</ul>{more}"


def _impact_block(text: object) -> str:
    sents = _sentences(text)
    if not sents:
        return ""
    lead, rest = sents[0], " ".join(sents[1:])
    return f"<p class='lead'>{prose(lead)}</p>" + (f"<p>{prose(rest)}</p>" if rest else "")


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
    ("Critical", "9.0-10.0", "CVSS 3.1 Critical. Serious compromise is possible with few preconditions. Form a plan of action and fix immediately."),
    ("High", "7.0-8.9", "CVSS 3.1 High. A confirmed flaw with significant impact on confidentiality, integrity or availability. Fix as soon as possible."),
    ("Moderate", "4.0-6.9", "CVSS 3.1 Medium. Impact is limited or exploitation needs extra conditions such as an account or user interaction. Fix after Critical and High issues."),
    ("Low", "0.1-3.9", "CVSS 3.1 Low. Minor impact. Fix during the next maintenance window."),
    ("Informational", "N/A", "No confirmed vulnerability. Items where the evidence could not decide the question, findings shown to be false alarms, and controls that held up."),
]
_VECTOR_WORDS = {"N": "Remote (network)", "A": "Adjacent (internal network)", "L": "Local", "P": "Physical"}


def _vector_word(vec: object) -> str:
    m = re.search(r"AV:([NALP])", str(vec or ""))
    return _VECTOR_WORDS.get(m.group(1), "Not scored") if m else "Not scored"


def _sev_cell(sev: Optional[str]) -> str:
    return f"<td class='sevcell sc-{e((sev or 'none').lower())}'>{e(SEV_DISPLAY.get(sev, sev or 'Unscored'))}</td>"


def _figures(ev: List[dict], counter: List[int], limit: int = 6) -> str:
    out = []
    for c in ev[:limit]:
        counter[0] += 1
        out.append(f"<figure><pre>{e(_trim(c['quote'], 420))}</pre><figcaption>Figure {counter[0]}: {prose(c.get('supports', ''))} "
                   f"<span class='src'>({e(field_label(c['field']))})</span></figcaption></figure>")
    return "".join(out)


def _owners(rows: List[dict]) -> str:
    return ", ".join(sorted({r.get("asset_owner") for r in rows if r.get("asset_owner")})) or "Asset owner (not recorded)"


def _remediation(r: dict, rows: Sequence[dict] = ()) -> str:
    steps, harden, verify = split_fix(r.get("recommended_fix"))
    items = list(steps) + [("Defense in depth: " + s) if not s.lower().startswith(("as ", "for ")) else s for s in harden]
    li = "".join(f"<li><b>Item {i}:</b> {prose(s)}</li>" for i, s in enumerate(items, 1))
    retest = _list(verify) if verify else ""
    return (f"<table class='kv remed'><tr><th>Who:</th><td>{e(_owners(list(rows) or [r]))}</td></tr>"
            f"<tr><th>Vector:</th><td>{e(_vector_word(r.get('cvss_vector')))}</td></tr>"
            f"<tr><th>Action:</th><td><ul class='items'>{li}</ul></td></tr>"
            + (f"<tr><th>Retest:</th><td>{retest}</td></tr>" if retest else "") + "</table>")


def _tcm_finding(code: str, anchor: str, title: str, lead: dict, rows: List[dict], counter: List[int],
                 badge: str = "", extra_instances: str = "") -> str:
    sev = lead.get("cvss_severity")
    refs = references_html(issue_key(lead))
    tools = ", ".join(sorted({r.get("scanner_source") or "not recorded" for r in rows}))
    fc = lead.get("fact_check") or {}
    bad = [c for c in fc.get("claims", []) if c["status"] == "unsupported"]
    fc_row = (f"<tr><th>Fact check:</th><td><b>{e(fc['status'].capitalize())}</b>"
              + (f" &middot; {e(fc['error'])}" if fc.get("error") else "")
              + ("".join(f"<br>Unsupported: {e(c['claim'])} <span class='muted'>({e(c.get('note') or '')})</span>" for c in bad))
              + ("".join(f"<br>Fix statement not in evidence: {e(x)}" for x in fc.get("fix_unsupported", [])))
              + "</td></tr>") if fc else ""
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
    <tr><th>Risk:</th><td>CVSS 3.1 vector <code>{e(lead.get('cvss_vector') or 'unscored')}</code>{_cvss_chips(lead.get('cvss_vector'))}
      <p class="muted">{prose(lead.get('cvss_rationale'))}</p></td></tr>
    <tr><th>Detected by:</th><td>{e(tools)} <span class="muted">(scanner named in the source data)</span></td></tr>
    {f"<tr><th>References:</th><td>{refs}</td></tr>" if refs else ""}
    {fc_row}
  </table>
  <h4>Evidence and Analysis (from source records)</h4>
  <p>{prose(lead.get('reasoning'))}</p>
  {_figures(lead.get('evidence', []), counter)}
  <h4>Remediation</h4>
  {_remediation(lead, rows)}
  {extra_instances}
</section>"""


def _instances_table(rows: List[dict]) -> str:
    trs = "".join(f"<tr><td><a href='#f-{e(r['finding_id'])}'>{e(r['finding_id'])}</a></td><td><code>{e(r['asset'])}</code></td><td>{e(r['environment'])}</td>"
                  f"<td>{e(r.get('asset_owner') or '')}</td>{_sev_cell(r.get('cvss_severity'))}<td>{e(r.get('cvss_score'))}</td><td>{e(TIER_LABEL.get(r.get('priority_tier'), ''))}</td><td>{e(r['confidence'])}</td></tr>"
                  for r in rows)
    return (f"<h4>Where this was confirmed ({e(_reach(rows))})</h4><table class='grid'><thead><tr><th>ID</th><th>System</th><th>Environment</th><th>Owner</th><th>Severity</th><th>CVSS</th><th>Priority</th><th>Confidence</th></tr></thead>"
            f"<tbody>{trs}</tbody></table>")


def _instance_evidence(rows: List[dict], counter: List[int]) -> str:
    """Per-instance evidence, kept for traceability; collapsed on screen, opened for print."""
    return "".join(f"<details class='inst-ev' id='f-{e(r['finding_id'])}'><summary>Evidence for {e(r['finding_id'])} ({e(r['asset'])}, {e(r['environment'])})</summary>"
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
        others = sorted({x["environment"] for x in chains if x["chain_id"].split(":")[0] == rule and x is not c and x["status"] == "confirmed"})
        also = f"; also fully confirmed in {', '.join(others)}" if others else ""
        out.append(f"<h4>{e(c['name'])} <span class='muted'>({e(c['environment'])}{e(also)})</span></h4>"
                   f"<p>{e(c['why'])}</p><table class='grid steps'><thead><tr><th>Step</th><th>Action</th><th>Recommendation</th></tr></thead><tbody>{''.join(rows)}</tbody></table>")
    return "".join(out) or "<p class='muted'>No combination of confirmed findings in a single environment forms a known attack progression.</p>"


# ---------------------------------------------------------------------------
# Report design
# ---------------------------------------------------------------------------
# Both reports share one visual system: a deep teal ground with pale aqua text, hairline rules, an amber signal
# colour for High and "Fix now", coral for Critical, and a mint panel for the fix. Headings are tight uppercase
# grotesque, labels and evidence are monospace, and evidence sits in terminal-style panels. The cover carries a faint
# contour texture. Only locally installed fonts are used, so the page is self-contained and makes no network
# requests. Printing switches to a light palette.
FONT_LINKS = ""  # no web fonts: a confidential report must open offline and must not call third parties

REPORT_BASE_CSS = """
:root{--paper:#061A1E;--sheet:#0A2229;--panel:#0F333B;--ink:#CAE2E4;--strong:#EAF5F6;--muted:#93ABAE;
--line:rgba(202,226,228,.14);--line2:rgba(202,226,228,.08);--soft:rgba(202,226,228,.06);--amber:#F0B429;--mint:#E6FFEC;
--green:#30A46C;--code:#15181A;--code-ink:#CAE2E4;--on-fill:#061A1E;
--crit:#FF7A66;--high:#F0B429;--med:#9CC9CE;--low:#30A46C;--conf:#FF7A66;--fp:#30A46C;--nr:#9CC9CE;--accent:#9CC9CE;
--display:"Archivo","SF Pro Display","Helvetica Neue","Segoe UI",system-ui,sans-serif;
--body:"Archivo","SF Pro Text","Helvetica Neue","Segoe UI",system-ui,sans-serif;
--mono:"DM Mono","SF Mono",ui-monospace,Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;color:var(--ink);background:var(--paper);font:15px/1.65 var(--body)}
a{color:var(--mint);text-decoration-color:rgba(230,255,236,.4);text-underline-offset:3px} a:hover{color:var(--amber)}
.doc{max-width:1120px;margin:0 auto}
.cover{position:relative;overflow:hidden;border-bottom:1px solid var(--line);background:linear-gradient(180deg,#0A2229 0%,var(--paper) 100%)}
.cover .topo{position:absolute;inset:0;width:100%;height:100%}
.cover .in{position:relative;padding:72px 40px 56px;display:flex;flex-direction:column;gap:40px}
.cover .kicker{font:500 12px var(--mono);letter-spacing:.16em;text-transform:uppercase;color:var(--muted)}
.cover h1{margin:0;font:600 clamp(40px,7vw,68px)/1 var(--display);letter-spacing:-.035em;text-transform:uppercase;color:var(--strong)}
.cover .tt{margin:6px 0 0;font:600 clamp(40px,7vw,68px)/1 var(--display);letter-spacing:-.035em;text-transform:uppercase;color:rgba(202,226,228,.45)}
.cover .meta{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));column-gap:24px}
.cover .meta div{padding:14px 0 12px;border-top:1px solid var(--line);color:var(--strong)}
.cover .meta span{display:block;font:500 11px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-bottom:4px}
.page{padding:56px 40px 24px;counter-reset:sec}
h2{display:flex;align-items:baseline;gap:16px;margin:64px 0 20px;font:600 30px/1.1 var(--display);letter-spacing:-.02em;text-transform:uppercase;color:var(--strong);scroll-margin-top:14px;counter-increment:sec}
h2::before{content:counter(sec,decimal-leading-zero);font:500 12px var(--mono);letter-spacing:0;color:var(--amber)}
h3{font:600 22px/1.2 var(--display);letter-spacing:-.015em;color:var(--strong);margin:32px 0 10px;scroll-margin-top:14px}
h4{font:500 11.5px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin:22px 0 8px}
p{margin:6px 0 12px}
code{font:12.5px/1.5 var(--mono);background:var(--soft);color:var(--strong);padding:1px 5px;border-radius:3px;word-break:break-word}
.muted{color:var(--muted)} .lead{font-size:17px;color:var(--strong)}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line2);vertical-align:top}
th{font:500 11px var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--line)}
table.grid th{background:transparent}
.sevcell{font:600 11.5px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--on-fill);text-align:center;white-space:nowrap}
.sc-critical{background:var(--crit)} .sc-high{background:var(--high)} .sc-medium{background:var(--med)} .sc-low{background:var(--low)} .sc-none{background:var(--muted)}
.sevtag,.sev,.cls,.tier{display:inline-block;font:600 11px var(--mono);letter-spacing:.08em;text-transform:uppercase;padding:3px 8px;border-radius:3px;color:var(--on-fill);background:var(--muted);white-space:nowrap}
.sevtag{vertical-align:middle;margin-left:6px}
.sev-critical{background:var(--crit)} .sev-high{background:var(--high)} .sev-medium{background:var(--med)} .sev-low{background:var(--low)}
.cls-conf{background:var(--conf)} .cls-fp{background:var(--fp)} .cls-nr{background:var(--nr)}
.callout{margin:18px 0;padding:18px 22px;background:var(--panel);border:1px solid var(--line);border-radius:6px;color:var(--ink)}
.callout b,.callout .big{font:600 20px/1.25 var(--display);color:var(--amber);display:block;margin-bottom:4px}
.twocol{display:grid;grid-template-columns:1.25fr .75fr;gap:32px}
.brow{display:grid;grid-template-columns:minmax(120px,42%) 1fr 32px;gap:12px;align-items:center;margin:8px 0;font-size:13px}
.bt{height:8px;background:var(--soft);border-radius:4px;display:block} .bf{display:block;height:100%;border-radius:4px} .bv{text-align:right;font-family:var(--mono)} .bl a{text-decoration:none}
.donut{display:flex;align-items:center;gap:18px;flex-wrap:wrap} .donut svg{width:140px;height:140px}
.dn{font:600 28px var(--display);fill:var(--strong)} .ds{font:11px var(--mono);fill:var(--muted)}
.legend{list-style:none;padding:0;margin:0} .legend li{display:flex;align-items:center;gap:8px;margin:5px 0;font-size:13px} .legend i{width:10px;height:10px;border-radius:2px;display:inline-block}
table.heat{border-collapse:separate;border-spacing:3px;width:auto} table.heat th{border:0;text-align:center;padding:3px}
table.heat th[scope=row]{text-align:left;color:var(--ink)}
td.hm{border:0;text-align:center;font:600 13px var(--mono);min-width:52px;height:30px;border-radius:3px;color:var(--strong);background:color-mix(in srgb,var(--c) calc(var(--a)*100%),transparent)}
td.tot{border:0;text-align:center;font-weight:600}
.count{font:500 11px var(--mono);letter-spacing:.04em;background:var(--mint);color:var(--on-fill);padding:2px 9px;border-radius:3px;margin-left:8px;vertical-align:middle;white-space:nowrap}
h2 .count{font-size:11px;letter-spacing:.04em;text-transform:none}
.foot{padding:24px 40px 40px;color:var(--muted);font:12px var(--mono);letter-spacing:.06em;border-top:1px solid var(--line);text-align:center}
figure{margin:14px 0;background:var(--code);border:1px solid var(--line2);border-radius:6px;overflow:hidden;break-inside:avoid}
figure pre{margin:0;padding:14px 16px;color:var(--code-ink);white-space:pre-wrap;word-break:break-word;font:12.5px/1.6 var(--mono);border-left:3px solid var(--amber)}
figcaption{padding:8px 16px;border-top:1px solid var(--line2);font:12px var(--mono);color:var(--muted)} .src{text-transform:uppercase;font-size:10.5px;letter-spacing:.1em;color:var(--amber)}
.printonly{display:none}
@media (max-width:860px){.page{padding:28px 16px}.cover .in{padding:48px 16px 36px}.twocol{grid-template-columns:1fr}.foot{padding:18px 16px}
}
@media print{
 :root{--paper:#fff;--sheet:#fff;--panel:#F2F6F6;--ink:#1D2B2E;--strong:#0A2229;--muted:#4F6265;--line:#C9D6D7;--line2:#E1E8E9;
  --soft:#EEF3F3;--code:#F4F6F6;--code-ink:#0A2229;--amber:#9A6A00;--mint:#E6FFEC;--high:#E3A21A;--med:#7FB3B9}
 *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
 .cover{background:#0A2229;min-height:92vh;break-after:page;--strong:#EAF5F6;--muted:#93ABAE;--line:rgba(202,226,228,.2);--amber:#F0B429}
 .cover h1,.cover .meta div{color:#EAF5F6} .cover .tt{color:rgba(202,226,228,.5)}
 .page{padding:0 6px} h2{break-before:page;break-after:avoid} h3,h4{break-after:avoid}
 table,figure,.callout{break-inside:avoid} tr{break-inside:avoid} .noprint{display:none} .printonly{display:inline}
 @page{margin:16mm 14mm}}
"""

ANALYST_CSS = """
.toc{columns:2;column-gap:40px;list-style:none;padding:0;counter-reset:toc;font:13px var(--mono)}
.toc li{padding:7px 0;border-bottom:1px solid var(--line2);break-inside:avoid} .toc a{text-decoration:none;color:var(--ink)} .toc a:hover{color:var(--amber)}
.fcode{font:500 12.5px var(--mono);background:var(--mint);color:var(--on-fill);padding:3px 9px;border-radius:3px;margin-right:6px;vertical-align:middle}
section.finding{border-top:1px solid var(--line);padding-top:8px;margin-top:40px}
section.finding h3{font-size:24px;text-transform:uppercase;letter-spacing:-.02em}
table.kv{margin:10px 0 16px;border:1px solid var(--line);border-radius:6px;border-collapse:separate;border-spacing:0;overflow:hidden}
table.kv th{width:150px;white-space:nowrap;background:var(--panel);color:var(--muted);border-bottom:1px solid var(--line2)}
table.kv td{border-bottom:1px solid var(--line2)} table.kv tr:last-child th,table.kv tr:last-child td{border-bottom:0}
table.kv.remed{background:var(--mint);color:#0A2229;border-color:transparent}
table.kv.remed th{background:rgba(10,34,41,.08);color:#0F333B} table.kv.remed td{border-color:rgba(10,34,41,.12)}
table.kv.remed code{background:rgba(10,34,41,.08);color:#0A2229} table.kv.remed a{color:#0F333B}
td.c{text-align:center;font-weight:600;width:46px;font-family:var(--mono);color:var(--amber)}
.tier{background:transparent;color:var(--ink);border:1px solid var(--line);font-weight:500} .tier-chase{border-color:var(--amber);color:var(--amber)} .tier-look{border-color:var(--med);color:var(--med)}
ul.items,ul.plain{margin:0;padding-left:18px} ul.plain{list-style:none;padding:0} ul.items li{margin:6px 0}
ul.chips{list-style:none;padding:0;margin:10px 0 0;display:flex;flex-wrap:wrap;gap:6px}
.chips li{border:1px solid var(--line);border-radius:3px;padding:3px 8px;font:11.5px/1.3 var(--mono)} .chips li span{display:block;color:var(--muted)} .chips li.hot{border-color:rgba(240,180,41,.55);color:var(--amber)}
.note{font-size:13px;background:var(--soft);border-radius:4px;padding:7px 11px} .banner{border:1px solid var(--crit);background:rgba(255,122,102,.08);border-radius:6px;padding:12px 16px;margin:14px 0}
.bars{margin-top:4px}
details{margin:6px 0;font-size:13px} summary{cursor:pointer;font-weight:600;color:var(--strong)}
ul.proof{list-style:none;padding:0} ul.proof li{border-left:3px solid var(--amber);padding:3px 0 3px 12px;margin:10px 0} ul.proof li b{display:block;color:var(--strong)}
code.quote{display:block;white-space:pre-wrap;background:var(--code);padding:8px 10px;margin-top:4px}
details.nrg{border:1px solid var(--line);border-radius:6px;padding:10px 16px;margin:10px 0;background:var(--sheet)} details.nrg summary small{display:block;font-weight:400;color:var(--muted)}
.tablewrap{overflow-x:auto} td.reason{min-width:300px}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
.filters input{flex:1;min-width:200px;padding:10px;border:1px solid var(--line);border-radius:4px;background:var(--sheet);color:var(--strong);font:13px var(--mono)}
.filters button{padding:9px 14px;min-height:40px;border:1px solid var(--line);border-radius:4px;background:transparent;color:var(--ink);cursor:pointer;font:500 12px var(--mono)}
.filters button.on{background:var(--mint);color:var(--on-fill);border-color:var(--mint)}
@media (max-width:860px){.toc{columns:1}}
@media print{.filters{display:none}.finding{break-before:page}}
"""

CLIENT_CSS = """
.posture{display:grid;grid-template-columns:auto 1fr;gap:4px 28px;align-items:center;background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:22px 26px;margin:8px 0 20px}
.posture .plabel{grid-column:1/-1;font:500 11px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.posture b{font:600 clamp(32px,5vw,46px)/1 var(--display);letter-spacing:-.03em;text-transform:uppercase;color:var(--c)} .posture p{margin:0;font-size:15px}
ul.brief{padding-left:20px;margin:6px 0 10px} ul.brief li{margin:8px 0} ul.brief li.lead{font-size:16px}
table.sevsum{width:auto;min-width:360px;margin:8px 0 14px;border:1px solid var(--line);border-radius:6px;border-collapse:separate;border-spacing:0;overflow:hidden}
table.sevsum tr.tot td{background:var(--soft);font-weight:600} td.n{text-align:center;font-weight:600;font-family:var(--mono)}
.env{display:inline-block;font:500 11.5px var(--mono);padding:2px 8px;border:1px solid var(--line);border-radius:3px;margin:1px 4px 1px 0;white-space:nowrap;color:var(--ink)}
.env-production{color:var(--amber);border-color:rgba(240,180,41,.5)}
.bars .brow{grid-template-columns:minmax(110px,40%) 1fr 30px}
ol.steps{margin:4px 0 8px;padding-left:22px} ol.steps li{margin:7px 0}
.entry{background:var(--sheet);border:1px solid var(--line);border-radius:8px;margin:26px 0;overflow:hidden}
.entry header{display:grid;grid-template-columns:auto 1fr auto;gap:18px;align-items:start;padding:26px 30px;border-bottom:1px solid var(--line)}
.num{font:500 13px var(--mono);color:var(--amber);padding-top:8px}
.entry h3{margin:0;font-size:26px;line-height:1.15}
.sub{color:var(--muted);font:12.5px/1.5 var(--mono);margin-top:6px}
.score{text-align:right} .score b{display:block;font:600 52px/1 var(--display);letter-spacing:-.03em;color:var(--strong);margin-top:6px}
.sc-b-critical .score b{color:var(--crit)} .sc-b-high .score b{color:var(--high)} .sc-b-medium .score b{color:var(--med)} .sc-b-low .score b{color:var(--low)}
.score small{font:11px var(--mono);color:var(--muted);letter-spacing:.12em;text-transform:uppercase}
.vec{margin:0;padding:12px 30px 0;font:12px var(--mono);color:var(--muted)} .vec code{background:transparent;padding:0;color:var(--muted)}
.cols{display:grid;grid-template-columns:1.5fr 1fr;gap:0;margin-top:6px}
.cols>section{padding:16px 30px 24px}
.why{font-size:13px;color:var(--muted)}
.fix{background:var(--mint);color:#0A2229} .fix h4{color:#0F333B} .fix code{background:rgba(10,34,41,.08);color:#0A2229} .fix a{color:#0F333B}
.verify{font-size:13.5px;border-top:1px solid rgba(10,34,41,.18);padding-top:10px}
.entry>h4{padding:0 30px} .entry>table.where{margin:0 30px 8px;width:calc(100% - 60px)} .entry>.why{padding:0 30px 20px}
.idbtn{white-space:nowrap;font:500 12.5px var(--mono);background:var(--mint);color:var(--on-fill);border:0;border-radius:3px;padding:6px 10px;min-height:32px;cursor:pointer}
.idbtn::before{content:"+ "} .idbtn[aria-expanded="true"]::before{content:"\\2212 "} .idbtn:hover,.idbtn:focus-visible{background:var(--amber)}
table.where td{overflow-wrap:anywhere}
tr.evrow>td{background:var(--paper);padding:16px 18px;border-left:3px solid var(--amber)}
.proof .pmeta{display:flex;flex-wrap:wrap;gap:6px 22px;font:12px var(--mono);color:var(--muted)} .proof .pmeta b{color:var(--strong)}
.proof figure{margin:12px 0 4px}
.proof figcaption{border-top:0;border-bottom:1px solid var(--line2);font:500 11px var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.proof pre{margin:0;padding:14px 16px;max-height:360px;overflow:auto;color:var(--code-ink);white-space:pre-wrap;word-break:break-word;font:12.5px/1.6 var(--mono)}
.proof mark{background:rgba(240,180,41,.25);color:var(--amber);padding:0 2px;border-radius:2px}
ul.shows{margin:4px 0 12px;padding-left:20px;font-size:13px}
@media print{tr.evrow[hidden]{display:none}.proof pre{max-height:none}.entry{break-inside:auto}.entry header{break-after:avoid}
 .proof mark{background:#FCE8B2;color:#0A2229}}
@media (max-width:860px){.cols{grid-template-columns:1fr}.entry header{grid-template-columns:auto 1fr;padding:18px}.score{grid-column:1/-1;text-align:left}
 .cols>section{padding:14px 18px}.vec{padding:10px 18px 0}.entry>h4{padding:0 18px}.entry>table.where{margin:0 18px 8px;width:calc(100% - 36px)}.entry>.why{padding:0 18px 16px}}
"""

_TOPO = ('<svg class="topo" aria-hidden="true" viewBox="0 0 1280 560" preserveAspectRatio="xMidYMid slice">'
         '<g fill="none" stroke="rgba(202,226,228,0.07)" stroke-width="1">'
         + "".join(f'<path d="M-40 {420 + d} C 180 {330 + d}, 300 {470 + d}, 520 {380 + d} S 860 {260 + d}, 1080 {340 + d} S 1320 {300 + d}, 1360 {260 + d}"></path>'
                   for d in (0, 30, 60))
         + "".join(f'<path d="M-40 {120 + d} C 140 {60 + d}, 320 {180 + d}, 560 {110 + d} S 900 {40 + d}, 1120 {120 + d} S 1300 {90 + d}, 1360 {60 + d}"></path>'
                   for d in (0, 30))
         + '<path d="M880 260 C 940 200, 1060 210, 1080 270 S 990 350, 930 320 S 850 300, 880 260"></path>'
           '<path d="M850 262 C 920 170, 1100 180, 1115 272 S 1000 385, 920 352 S 815 310, 850 262"></path>'
           '<path d="M820 264 C 900 140, 1140 150, 1150 274 S 1010 420, 905 384 S 780 318, 820 264"></path></g></svg>')


def prepared_by(company: str = "", tester: str = "") -> str:
    """'Jane Doe, Acme Security'; whichever parts were given, or '' when neither was."""
    return ", ".join(x for x in (tester.strip(), company.strip()) if x)


def _team_html(client: str, company: str, tester: str) -> str:
    """Contact table for the assessment team and the client. Only names the user supplied are shown;
    contact details are never invented."""
    rows = []
    if tester or company:
        rows.append(f"<tr><td>{e(company or 'Not provided')}</td><td>{e(tester or 'Not provided')}</td><td>Report author</td><td>Not provided</td></tr>")
    rows.append(f"<tr><td>{e(client)}</td><td>To be provided by {e(client)}</td><td>Client security contact</td><td>Not provided</td></tr>")
    return ("<table class='grid'><thead><tr><th>Organization</th><th>Name</th><th>Role</th><th>Contact</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")


def _cover(client_html: str, title: str, meta: List[Tuple[str, str]], kicker: str) -> str:
    """The report cover: client name as the page's h1, the report title, and a row of labelled facts."""
    facts = "".join(f"<div><span>{e(k)}</span>{e(v)}</div>" for k, v in meta)
    return (f'<header class="cover">{_TOPO}<div class="in"><div class="kicker">{e(kicker)}</div>'
            f'<div><h1>{client_html}</h1><p class="tt">{e(title)}</p></div>'
            f'<div class="meta">{facts}</div></div></header>')


def build_report(results: List[dict], source_name: str, model: str, chains: List[dict] = (), client: str = "Client",
                 company: str = "", tester: str = "") -> str:
    """Render the technical report for internal analysts and engineers.

    It carries every verdict, including false positives and findings that need more evidence, with the evidence,
    CVSS reasoning, method and a searchable appendix.

    Args:
        results: Final per-finding results.
        source_name: Name of the input file.
        model: Description of the models that answered.
        chains: Attack chains correlated from the confirmed findings.
        client: Client name shown in headings.
        company: The reporting company (shown as author when given).
        tester: The assessor's name (shown as author when given).

    Returns:
        A self-contained HTML page.
    """
    cl = e(client)
    author = prepared_by(company, tester)
    co = e(company) if company else "the assessment team"
    counts = collections.Counter(r["classification"] for r in results)
    confirmed = [r for r in results if r["classification"] == "Confirmed"]
    nr = [r for r in results if r["classification"] == "Needs Review"]
    fp = [r for r in results if r["classification"] == "False Positive"]
    by_id = {r["finding_id"]: r for r in results}
    issues = issue_groups(confirmed)
    top = issues[:3]
    tiers = collections.Counter(r.get("priority_tier") for r in confirmed)
    sev = collections.Counter(r.get("cvss_severity") for r in confirmed)
    prod = [r for r in confirmed if env_class(r["environment"]) == "production"]
    prod_hi = sum(1 for r in prod if r.get("cvss_severity") in ("Critical", "High"))
    adjudicated = sum(1 for r in results if r.get("adjudicated"))
    gated = sum(1 for r in results if r.get("gated_from"))
    errors = sum(1 for r in results if r.get("error"))
    consistency = sum(1 for r in results if "consistency gate" in (r.get("gate_notes") or ""))
    evidence_gated = gated - consistency
    n_conf_chains = sum(1 for c in chains if c["status"] == "confirmed")
    window, date_note = _observed(results)
    report_date = _fmt_date(dt.date.today())
    weights = ", ".join(f"{k} {v}" for k, v in ENV_WEIGHT.items())
    def name(g: List[dict]) -> str:
        """'SQL injection: SQL injection in vehicle lookup', without repeating a label the title already starts with."""
        label, title = issue_label(issue_key(g[0]), g[0]), display_title(g[0])
        return title if title.lower().startswith(label.lower()[:12]) else f"{label}: {title}"
    error_banner = (f"<div class='banner'><strong>{errors} finding(s) could not be assessed automatically</strong> "
                    f"and are listed as informational (needs review) pending manual assessment.</div>") if errors else ""
    flagged = [r["finding_id"] for r in confirmed if (r.get("fact_check") or {}).get("status") == "flagged"]
    if flagged:
        error_banner += (f"<div class='banner'><strong>Client text held for review:</strong> the impact or title for "
                         f"{_plural(len(flagged), 'issue', 'issues')} ({e(', '.join(flagged))}) still carries a claim the "
                         f"evidence does not support. Correct it before the executive report is sent.</div>")
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
    first_names = [display_title(g[0]) for g in top]
    first_text = (", ".join(first_names[:-1]) + " and " + first_names[-1]) if len(first_names) > 1 else "".join(first_names)
    exec_text = (f"{cl}'s security tooling produced {_plural(len(results), 'raw finding', 'raw findings')}{_observed_from(window)}. Each was evaluated against the evidence supplied "
                 f"with it (runtime requests and responses, traces, logs, source and deployment records, owner comments), not against the scanner's own severity label. "
                 f"Of these, {counts['Confirmed']} {'is' if counts['Confirmed'] == 1 else 'are'} confirmed, {counts['False Positive']} "
                 f"{'is a false positive' if counts['False Positive'] == 1 else 'are false positives'}, and {counts['Needs Review']} "
                 f"cannot be decided without more evidence. "
                 f"The confirmed findings are {_plural(len(issues), 'distinct issue', 'distinct issues')}. "
                 f"{_plural(len(prod), 'confirmed finding is', 'confirmed findings are')} in production, {prod_hi} of them rated High or Critical. "
                 + (f"Fix these first: {first_text}." if first_text else ""))
    weak = "".join(f"<h4>{e(name(g))}</h4>{_impact_block(g[0].get('business_impact'))}" for g in top)
    fp_groups: Dict[Tuple[str, str], List[dict]] = {}
    for r in sorted(fp, key=_title_key):
        fp_groups.setdefault(flaw_key(r), []).append(r)
    strengths = ""
    for k, g in sorted(fp_groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:4]:
        ss = _sentences(g[0].get("reasoning"))
        strengths += (f"<h4>{e(g[0]['finding_title'])}: {_plural(len(g), 'finding', 'findings')} closed as false positives</h4>"
                      f"<p><b>Example {e(g[0]['finding_id'])}.</b> {prose(' '.join(ss[:2]))}</p>")
    sev_bars = _bar_rows([(SEV_DISPLAY.get(s, s), sev.get(s, 0), SEV_COLOR[s], "") for s in ("Critical", "High", "Medium", "Low")],
                         max(sev.values(), default=1))
    heat = _heatmap(confirmed).replace(">Medium<", ">Moderate<")
    type_bars = _bar_rows([(issue_label(issue_key(g[0]), g[0]), len(g), SEV_COLOR.get(_worst(g).get("cvss_severity"), "var(--accent)"), f"#{flaw_anchor(flaw_key(g[0]))}")
                           for g in sorted(issues, key=lambda g: -len(g))], max((len(g) for g in issues), default=1))
    donut = _donut([("Confirmed", counts["Confirmed"], "var(--conf)"), ("Informational: needs review", counts["Needs Review"], "var(--nr)"),
                    ("Informational: false positive", counts["False Positive"], "var(--fp)")], str(len(results)), "findings")

    # --- technical findings ---
    priority_html = "".join(
        f"<li><a href='#{flaw_anchor(flaw_key(g[0]))}'><b>F-{i:02d}</b> {e(display_title(g[0]))}</a> "
        f"<span class='sevtag sc-{e((g[0].get('cvss_severity') or 'none').lower())}'>{e(SEV_DISPLAY.get(g[0].get('cvss_severity'), g[0].get('cvss_severity') or ''))}</span> "
        f"CVSS {e(g[0].get('cvss_score'))}, {e(_reach(g))}, {sum(1 for r in g if _is_prod(r))} in production.</li>"
        for i, g in enumerate(top, 1))
    priority_html = f"<ol class='items'>{priority_html}</ol>" if priority_html else "<p>No findings met the confirmation standard.</p>"
    issue_html = []
    for i, g in enumerate(issues, 1):
        issue_html.append(_tcm_finding(f"F-{i:02d}", flaw_anchor(flaw_key(g[0])), name(g), g[0], g, counter,
                                       extra_instances=_instances_table(g) + _instance_evidence(g, counter)))
    nr_html = _needs_review_html(nr)
    fp_html = ("<table class='grid'><thead><tr><th>ID</th><th>Title</th><th>System</th><th>Env</th><th>Why it is not exploitable as reported</th></tr></thead><tbody>"
               + "".join(f"<tr><td>{e(r['finding_id'])}</td><td>{e(r['finding_title'])}</td><td><code>{e(r['asset'])}</code></td><td>{e(r['environment'])}</td><td>{prose(r['reasoning'])}</td></tr>"
                         for r in sorted(fp, key=_title_key)) + "</tbody></table>") if fp else ""
    all_rows = "".join(
        f"<tr data-cls='{e(r['classification'])}'><td>{e(r['finding_id'])}</td><td>{e((r.get('first_observed_utc') or '')[:10])}</td>"
        f"<td>{e(r['finding_title'])}</td><td><code>{e(r['asset'])}</code></td><td>{e(r['environment'])}</td><td>{e(r.get('scanner_source'))}</td>"
        f"<td>{_cls_badge(r['classification'])}</td><td>{e(r['confidence'])}</td><td class='reason'>{prose(r['reasoning'])}</td></tr>" for r in results)

    toc = [("audience", "How to Use This Report"), ("confidentiality", "Confidentiality Statement"), ("disclaimer", "Disclaimer"), ("contacts", "Contact Information"),
           ("overview", "Assessment Overview"), ("severity", "Finding Severity Ratings"), ("scope", "Scope"),
           ("exec", "Assessment Summary"), ("attack-summary", "&nbsp;&nbsp;Attack Summary"), ("strengths", "&nbsp;&nbsp;Security Strengths"),
           ("weaknesses", "&nbsp;&nbsp;Security Weaknesses"), ("impact", "&nbsp;&nbsp;Vulnerabilities by Impact"),
           ("findings", "Technical Findings"), ("priority", "&nbsp;&nbsp;Top Priority Issues"), ("confirmed", "&nbsp;&nbsp;All Confirmed Issues"),
           ("informational", "Additional Reports and Scans (Informational)"), ("method", "Assessment Method and Limitations"), ("appendix", "Appendix: Every Finding")]
    toc_html = "".join(f"<li{' class=noprint' if a == 'appendix' else ''}><a href='#{a}'>{t}</a></li>" for a, t in toc)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{cl} Technical Assessment Report (Analyst Edition)</title>
{FONT_LINKS}<style>{REPORT_BASE_CSS}{ANALYST_CSS}</style></head><body><div class="doc">
{_cover(cl, "Technical Assessment Report", [("Edition", "Analyst, for the internal security team"), ("Prepared for", client)] + ([("Prepared by", author)] if author else []) + [("Classification", "Business Confidential"), ("Report date", report_date), ("Findings observed", window or "Not recorded in the source data"), ("Source data", source_name), ("Version", "1.0")], "Analyst edition")}
<div class="page">
{error_banner}
<h2 style="break-before:auto">Table of Contents</h2><ol class="toc" style="list-style:none">{toc_html}</ol>

<h2 id="audience">How to Use This Report</h2>
<p>This is the technical record of the assessment. It is written for the analysts and engineers who verify findings, reproduce them and ship the fixes. Every finding in the source data has a decision here, including the false positives and the findings that need more evidence, each with its reason.</p>
<p>Each confirmed finding carries its CVSS 3.1 vector with a reason for every metric, the exact evidence it rests on, how the flaw was reproduced and an ordered fix. The companion executive report carries only the confirmed issues, in business terms, for the people who fund and own the risk.</p>
<table class="kv"><tbody><tr><th>Start with</th><td>Top Priority Issues. Read each entry's evidence figures before the conclusion, then check the CVSS reasoning against your own view of the system.</td></tr>
<tr><th>Then</th><td>All Confirmed Issues, which lists every affected finding once per issue.</td></tr>
<tr><th>Open questions</th><td>Findings that need more evidence. Treat the follow-up under each one as your test plan.</td></tr>
<tr><th>Any single row</th><td>The appendix filters all findings by outcome and by text.</td></tr></tbody></table>

<h2 id="confidentiality">Confidentiality Statement</h2>
<p>This document is the exclusive property of {cl} and {co}. It contains proprietary and confidential information. Duplication, redistribution, or use, in whole or in part, in any form, requires consent of both {cl} and {co}.</p>
<p>This document is an evidence-based triage of existing scanner findings. It is not a penetration test report and should not be presented as one.</p>

<h2 id="disclaimer">Disclaimer</h2>
<p>This assessment is a snapshot in time. The findings and recommendations reflect the evidence supplied with each finding{e(_observed_from(window))}, and not any changes made outside of it.{(" " + e(date_note)) if date_note else ""}</p>
<p>The assessment rests on the evidence supplied with each finding and did not include new testing against any system. It does not evaluate every security control. It prioritizes the weaknesses an attacker would exploit first. Similar assessments should be repeated on a regular schedule by internal or third-party reviewers to confirm that controls continue to hold.</p>

<h2 id="contacts">Contact Information</h2>
{_team_html(client, company, tester)}
<h4>Asset owner teams named in the findings</h4>
<table class="grid"><thead><tr><th>Asset owner team</th><th>Scope of findings</th><th>Contact</th></tr></thead><tbody>{owner_rows}</tbody></table>

<h2 id="overview">Assessment Overview</h2>
<p>{cl}'s scanning and testing produced {_plural(len(results), 'raw finding', 'raw findings')}{e(_observed_from(window))}. This assessment triaged them: each was decided from the evidence attached to it, to separate real, exploitable issues from false positives and from questions the evidence cannot answer. No system was tested as part of this work. Phases:</p>
<ul><li><b>Ingestion:</b> The findings file was parsed as CSV, preserving multiline fields. Every row receives exactly one outcome.</li>
<li><b>Evidence correlation:</b> Request IDs, code revisions, identities and side-effect boundaries were matched across the requests, responses, logs, traces, source excerpts, manifests and owner comments supplied with each finding.</li>
<li><b>Automated adjudication with checks:</b> Each finding received two independent automated reviews by an AI model ({e(model)}), with a third when they disagreed. Code then checked that every quoted piece of evidence appears word for word in the source data and applied the evidence gates described under Assessment Method and Limitations.</li>
<li><b>Reporting:</b> Confirmed findings were scored with CVSS 3.1, prioritized by environment, grouped into distinct issues and correlated into attack chains.</li></ul>
<h4>Assessment Components</h4>
<p><b>Evidence-based finding adjudication.</b> Each finding is decided on what the evidence shows about the security boundary, not on the scanner label. Compensating-control claims are treated as claims until shown to exist and to cover the path in question.</p>

<h2 id="severity">Finding Severity Ratings</h2>
<p>The following table defines the severity levels and the corresponding CVSS 3.1 score ranges used throughout this document. "Moderate" is used for the CVSS 3.1 "Medium" rating.</p>
<table class="grid"><thead><tr><th>Severity</th><th>CVSS 3.1 Score Range</th><th>Definition</th></tr></thead><tbody>{sev_rows}</tbody></table>

<h2 id="scope">Scope</h2>
<table class="grid"><thead><tr><th>Environment</th><th>Systems with findings</th></tr></thead><tbody>{scope_rows}</tbody></table>
<h4>Scope Exclusions</h4><p>No host was contacted and no new attacks were run. Conclusions rest only on the evidence supplied.</p>
<h4>Client Allowances</h4><p>Input was one findings file ({e(source_name)}, {len(results)} rows) with the evidence attached to each row: requests, responses, logs, traces, code excerpts, deployment manifests and owner comments. No system access was provided or used.</p>

<h2 id="exec">Assessment Summary</h2>
<p>{e(exec_text)}</p>{f"<p class='muted'>{e(date_note)}</p>" if date_note else ""}
<div class="callout"><b>{e('Production exposure: ' + str(len(prod)) + ' confirmed findings, ' + str(prod_hi) + ' High or Critical.')}</b>
 {f"Findings in the same environment also combine into {_plural(n_conf_chains, 'fully confirmed attack chain', 'fully confirmed attack chains')}, described below." if n_conf_chains else ''}</div>

<h3 id="attack-summary">Attack Summary</h3>
<p>The following tables describe how confirmed findings in one environment combine, step by step. The evidence does not link them to a single recorded attack, so these show combined exposure, not an incident. A step marked still under review should be settled first.</p>
{_attack_summary(list(chains), by_id)}

<h3 id="strengths">Security Strengths (Controls Verified in Source Evidence)</h3>
<p>The largest groups of findings closed as false positives, with one worked example each. In each case the evidence shows the reported condition is absent or unreachable on the deployed path.</p>
{strengths or "<p class='muted'>None recorded.</p>"}

<h3 id="weaknesses">Security Weaknesses</h3>
<p>The three highest-priority issues, in order. Each has a full entry under Technical Findings.</p>
{weak}

<h3 id="impact">Vulnerabilities by Impact</h3>
<p>The following charts illustrate the confirmed vulnerabilities by impact, environment and type.</p>
<div class="twocol"><div><h4>Confirmed findings by severity</h4>{sev_bars}<h4>Outcome of all {len(results)} findings</h4>{donut}</div>
<div><h4>By environment</h4>{heat}<h4>By issue type</h4>{type_bars}</div></div>

<h2 id="findings">Technical Findings</h2>
<h3 id="priority">Top Priority Issues</h3>
<p>The three issues to fix first: highest severity, then score, then production exposure. Each links to its full entry below. Per-system fix order is the CVSS score weighted by environment ({e(weights)}).</p>
{priority_html}
<h3 id="confirmed">All Confirmed Issues</h3>
<p>{counts['Confirmed']} confirmed findings in {len(issues)} distinct issues, ordered by severity. The numbering (F-01 onward) matches the executive report. Each entry shows one worked example and lists every finding where the issue was confirmed.</p>
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
<li><b>Two independent reviews per finding.</b> The second review did not see the first and was set up to challenge both outcomes. {"Where they disagreed on the outcome or on any CVSS metric, a third review voted; " + _plural(adjudicated, "finding needed", "findings needed") + " this." if adjudicated else "The two reviews reached the same outcome on every finding, so no third review was needed."}</li>
<li><b>Evidence must be checkable.</b> Confirmed needs at least {MIN_CITATIONS_CONFIRMED} verified citations including runtime evidence, and the deciding step must have been observed. {_plural(evidence_gated, "verdict was", "verdicts were") if evidence_gated else "No verdicts were"} downgraded to Needs Review by these checks.</li>
<li><b>Consistency check.</b> Findings with the same scenario and evidence must get the same answer. Where findings with identical evidence received different verdicts, the decisive ones were moved to Needs Review ({_plural(consistency, "finding", "findings")}).</li>
<li><b>Claims are not controls.</b> Owner statements, claimed protections and missing log entries are never treated as proof. Source, manifest and runtime records are matched by revision and date before being combined.</li>
<li><b>Scoring.</b> CVSS 3.1 vectors are chosen from the evidence and scores computed by the published formula. Priority = CVSS &times; environment weight. Fix now is 7.0 or above, Plan a fix 3.0 or above, Backlog below that. Model confidence is reported but does not change the order.</li>
<li><b>Limits.</b> Assessment uses only the supplied evidence. Reviews were carried out by AI models (models and call counts: {e(model)}) under the code checks above; a person remains responsible for every outcome. {_plural(errors, "finding", "findings") + " could not be reviewed and" if errors else "No findings failed review, and none"} {"is" if errors == 1 else "are"} listed as needs review for that reason.</li></ul>

<h2 id="appendix" class="noprint">Appendix: Every Finding (on-screen only)</h2>
<div class="noprint"><div class="filters"><input id="q" placeholder="Filter by ID, system, title, reasoning..." aria-label="Filter findings">
<button data-f="" class="on">All</button><button data-f="Confirmed">Confirmed</button><button data-f="False Positive">False positive</button><button data-f="Needs Review">Needs review</button></div>
<div class="tablewrap"><table id="all" class="grid"><thead><tr><th>ID</th><th>First seen</th><th>Title</th><th>System</th><th>Env</th><th>Raised by</th><th>Outcome</th><th>Conf.</th><th>Reasoning</th></tr></thead>
<tbody>{all_rows}</tbody></table></div></div>
</div><div class="foot">{cl} Technical Assessment Report &middot; Analyst Edition{(" &middot; Prepared by " + e(author)) if author else ""} &middot; Business Confidential &middot; Version 1.0</div></div>
<script>
(function(){{var q=document.getElementById('q'),f='',rows=[].slice.call(document.querySelectorAll('#all tbody tr'));
function apply(){{var t=q.value.toLowerCase();rows.forEach(function(r){{var ok=(!f||r.dataset.cls===f)&&(!t||r.textContent.toLowerCase().indexOf(t)>-1);r.style.display=ok?'':'none';}});}}
q.addEventListener('input',apply);[].forEach.call(document.querySelectorAll('.filters button'),function(b){{b.addEventListener('click',function(){{
[].forEach.call(document.querySelectorAll('.filters button'),function(x){{x.classList.remove('on')}});b.classList.add('on');f=b.dataset.f;apply();}});}});
function openFor(h){{var t=h&&document.getElementById(h.slice(1));var o=t;while(o){{if(o.tagName==='DETAILS')o.open=true;o=o.parentElement;}}if(t)t.scrollIntoView();}}
window.addEventListener('hashchange',function(){{openFor(location.hash)}});openFor(location.hash);
window.addEventListener('beforeprint',function(){{[].forEach.call(document.querySelectorAll('details'),function(d){{d.open=true}})}});}})();
</script></body></html>"""


# ---------------------------------------------------------------------------
# Client report: confirmed findings only
# ---------------------------------------------------------------------------
# The analyst report above carries the whole adjudication (false positives, open
# questions, method). This one is for the customer: only findings that were
# confirmed, each with its CVSS 3.1 score, plain-language business impact and
# recommended fix, ordered by what to do first.
def _client_fix(text: object) -> str:
    steps, harden, verify = split_fix(text)
    out = ""
    if steps or harden:
        out += "<ol class='steps'>" + "".join(f"<li>{prose(s)}</li>" for s in steps + harden) + "</ol>"
    if verify:
        out += "<p class='verify'><b>How to check the fix worked.</b> " + prose(" ".join(verify)) + "</p>"
    return out


# ---------------------------------------------------------------------------
# Audiences
# ---------------------------------------------------------------------------
# Two reports, one set of verdicts. The technical report is the working record for the analysts and engineers
# who verify, reproduce and fix. The executive report is the briefing for the people who fund and own the risk:
# confirmed issues only, in business terms, with decisions to take. Both are written the way a senior penetration
# tester would write for that reader.
RISK_POSTURE = {  # key: (label, colour variable, one-sentence meaning)
    "critical": ("Critical", "--crit", "A confirmed flaw rated Critical is live in production. Fix it before anything else."),
    "high": ("High", "--high", "Confirmed flaws rated High are live in production. Fix them in the current planning cycle."),
    "moderate": ("Moderate", "--med", "Confirmed flaws are live in production, none rated High or Critical. Fix them on a planned schedule."),
    "contained": ("Contained", "--low", "Confirmed flaws exist, but only outside production. Fix them before the same code ships."),
    "none": ("No confirmed findings", "--low", "No finding met the standard for confirmation. Items that need more evidence are not cleared."),
}


def risk_posture(confirmed: List[dict]) -> str:
    """Posture from the worst confirmed severity in production, in plain rules a reader can check."""
    prod = {r.get("cvss_severity") for r in confirmed if env_class(r["environment"]) == "production"}
    for sev, key in (("Critical", "critical"), ("High", "high")):
        if sev in prod:
            return key
    return "moderate" if prod else "contained" if confirmed else "none"


PROOF_JS = """
(function(){
function set(btn,open){var row=document.getElementById(btn.getAttribute('aria-controls'));if(!row)return;
row.hidden=!open;btn.setAttribute('aria-expanded',open?'true':'false');}
[].forEach.call(document.querySelectorAll('.idbtn'),function(b){b.addEventListener('click',function(){set(b,b.getAttribute('aria-expanded')!=='true');});});
function fromHash(){var id=location.hash.slice(1);if(!id)return;var b=document.querySelector('.idbtn[aria-controls="'+id+'"]');
if(b){set(b,true);b.scrollIntoView({block:'center'});}}
window.addEventListener('hashchange',fromHash);fromHash();})();
"""


PROOF_MAX_CHARS = 8000   # a captured field longer than this is cut, keeping the cited quotes in view


def _highlight(text: str, quotes: List[str]) -> str:
    """HTML-escape `text`, wrapping each cited quote in <mark>. Quotes are matched the way the evidence check
    matched them: whitespace-insensitive and case-insensitive."""
    spans: List[Tuple[int, int]] = []
    for q in quotes:
        words = q.split()
        if not words:
            continue
        m = re.search(r"\s+".join(re.escape(w) for w in words), text, re.I)
        if m:
            spans.append(m.span())
    out, pos = [], 0
    for a, b in sorted(spans):
        if a < pos:
            continue
        out += [e(text[pos:a]), f"<mark>{e(text[a:b])}</mark>"]
        pos = b
    return "".join(out) + e(text[pos:])


def _proof_html(r: dict, row: Optional[Dict[str, str]]) -> str:
    """The evidence behind one confirmed finding: the full text of every captured record it cites, with the
    quoted lines highlighted. Without the source row, only the quoted lines are shown."""
    by_field: Dict[str, List[dict]] = {}
    for c in r.get("evidence") or []:
        by_field.setdefault(c["field"], []).append(c)
    blocks = []
    for field, cites in by_field.items():
        quotes = [c["quote"] for c in cites]
        full = (row or {}).get(field) or ""
        shown = full if len(full) <= PROOF_MAX_CHARS else full[:PROOF_MAX_CHARS] + "\n[... cut for length]"
        body = _highlight(shown, quotes) if shown else "\n\n".join(e(q) for q in quotes)
        points = "".join(f"<li>{prose(c.get('supports', ''))}</li>" for c in cites if c.get("supports"))
        blocks.append(f"<figure><figcaption>{e(field_label(field))}</figcaption><pre>{body}</pre></figure>"
                      + (f"<ul class='shows'>{points}</ul>" if points else ""))
    facts = [("System", r["asset"]), ("Environment", r["environment"]),
             ("First observed", (r.get("first_observed_utc") or "")[:10]), ("Request ID", (row or {}).get("request_id", ""))]
    meta = "".join(f"<span><b>{e(k)}</b> {e(v)}</span>" for k, v in facts if v)
    records = "".join(blocks) or "<p class='muted'>No evidence was recorded.</p>"
    return (f"<div class='proof'><div class='pmeta'>{meta}</div>"
            f"<h4>What the evidence shows</h4><p>{prose(r.get('reasoning', ''))}</p>"
            f"<h4>The records it rests on</h4>{records}</div>")


def _client_issue(n: int, rows: List[dict], source: Optional[Dict[str, Dict[str, str]]] = None) -> str:
    lead = rows[0]  # highest-priority instance
    sev = lead.get("cvss_severity") or "None"
    refs = references_html(issue_key(lead))
    proof = [c.get("supports", "") for c in (lead.get("evidence") or []) if c.get("supports")][:3]
    why = ("<p class='why'><b>How it was confirmed.</b> " + " ".join(
        prose(p[:1].upper() + p[1:].rstrip(".") + ".") for p in proof) + "</p>") if proof else ""
    prod = sum(1 for r in rows if env_class(r["environment"]) == "production")
    inst = "".join(
        f"<tr><td><button type='button' class='idbtn' aria-expanded='false' aria-controls='ev-{e(r['finding_id'])}'>{e(r['finding_id'])}</button></td>"
        f"<td><code>{e(r['asset'])}</code></td>"
        f"<td><span class='env env-{e(r['environment'].strip().lower())}'>{e(r['environment'])}</span></td>"
        f"<td>{e((r.get('first_observed_utc') or '')[:10])}</td><td>{e(TIER_LABEL.get(r.get('priority_tier'), ''))}</td></tr>"
        f"<tr class='evrow' id='ev-{e(r['finding_id'])}' hidden><td colspan='5'>{_proof_html(r, (source or {}).get(r['finding_id']))}</td></tr>"
        for r in sorted(rows, key=lambda r: (env_class(r["environment"]) != "production", r["asset"], r["finding_id"])))
    note = ("" if len(rows) == 1 else
            f"<p class='why'>Impact and fix are described from the example on <code>{e(lead['asset'])}</code> ({e(lead['finding_id'])}). "
            f"The same flaw was confirmed for each finding in the table above.</p>")
    return f"""
<article class="entry sc-b-{e(sev.lower())}" id="issue-{n}">
  <header><span class="num">{n}</span>
    <div><h3>{e(display_title(lead))}</h3>
      <div class="sub">{e(_reach(rows))}{f', {_plural(prod, "finding", "findings")} in production' if prod else ''} &middot; Owner: {e(_owners(rows))} &middot; Technical report F-{n:02d}</div></div>
    <div class="score"><span class="sevtag sc-{e(sev.lower())}">{e(SEV_DISPLAY.get(sev, sev))}</span><b>{e(lead.get('cvss_score') if lead.get('cvss_score') is not None else 'n/a')}</b><small>CVSS 3.1</small></div></header>
  <p class="vec"><code>{e(lead.get('cvss_vector') or 'unscored')}</code>{f" <span class='muted'>&middot; {refs}</span>" if refs else ""}</p>
  <div class="cols"><section><h4>Business impact</h4>{_impact_block(lead.get('business_impact'))}{why}</section>
  <section class="fix"><h4>Recommended fix</h4>{_client_fix(lead.get('recommended_fix'))}</section></div>
  <h4 style="margin-top:12px">Where this was found <span class="muted noprint">(select a finding ID to see the evidence)</span><span class="muted printonly">(evidence for each finding ID: technical report F-{n:02d})</span></h4>
  <table class="where"><thead><tr><th>Finding ID</th><th>System</th><th>Environment</th><th>Scanner first observed</th><th>Fix order</th></tr></thead><tbody>{inst}</tbody></table>
  {note}
</article>"""


def build_client_report(results: List[dict], source_name: str, chains: List[dict] = (), client: str = "Client",
                        source_rows: Optional[Dict[str, Dict[str, str]]] = None, company: str = "", tester: str = "") -> str:
    """Render the executive report for leadership and risk owners.

    It carries confirmed findings only, in business terms: a risk posture, what leadership needs to know, decisions
    requested and, for each issue, score, impact, fix and the evidence behind every finding ID.

    Args:
        results: Final per-finding results.
        source_name: Name of the input file.
        chains: Attack chains correlated from the confirmed findings.
        client: Client name shown in headings.
        source_rows: The input rows by finding_id, so evidence can be shown in full. Without them only the quoted
            lines are shown.
        company: The reporting company (shown as author when given).
        tester: The assessor's name (shown as author when given).

    Returns:
        A self-contained HTML page.
    """
    cl = e(client)
    author = prepared_by(company, tester)
    confirmed = sorted((r for r in results if r["classification"] == "Confirmed"), key=_priority_key)
    sev = collections.Counter(r.get("cvss_severity") for r in confirmed)
    prod = [r for r in confirmed if env_class(r["environment"]) == "production"]
    prod_hi = sum(1 for r in prod if r.get("cvss_severity") in ("Critical", "High"))
    n_fp = sum(1 for r in results if r["classification"] == "False Positive")
    n_nr = sum(1 for r in results if r["classification"] == "Needs Review")
    issues = issue_groups(confirmed)
    number = {id(rows): i for i, rows in enumerate(issues, 1)}
    window, date_note = _observed(confirmed)
    report_date = _fmt_date(dt.date.today())
    def best_tier(rows: List[dict]) -> str:
        """The most urgent fix tier among an issue's findings."""
        return min((r.get("priority_tier") or "NOTE" for r in rows), key={"CHASE": 0, "LOOK": 1, "NOTE": 2}.get)

    index_rows = "".join(
        f"<tr><td>{number[id(rows)]}</td><td><a href='#issue-{number[id(rows)]}'>{e(display_title(rows[0]))}</a></td>"
        f"{_sev_cell(rows[0].get('cvss_severity'))}<td class='n'>{e(rows[0].get('cvss_score'))}</td><td class='n'>{len(rows)}</td><td class='n'>{_systems(rows)}</td>"
        f"<td>{_env_chips(rows)}</td><td>{e(TIER_LABEL.get(best_tier(rows), ''))}</td></tr>" for rows in issues)
    body = ""
    for band, label in (("Critical", "Critical"), ("High", "High"), ("Medium", "Moderate"), ("Low", "Low")):
        rows_b = [rows for rows in issues if rows[0].get("cvss_severity") == band]
        if rows_b:
            n_find = sum(len(x) for x in rows_b)
            body += (f"<h2 id='sev-{band.lower()}'>{label} severity <span class='count'>{len(rows_b)} issue{'s' if len(rows_b) != 1 else ''}, "
                     f"{n_find} finding{'s' if n_find != 1 else ''}</span></h2>"
                     + "".join(_client_issue(number[id(rows)], rows, source_rows) for rows in rows_b))
    first = "".join(
        f"<li><b><a href='#issue-{number[id(rows)]}'>{e(display_title(rows[0]))}</a></b> "
        f"<span class='muted'>({e(_reach(rows))}, CVSS {e(rows[0].get('cvss_score'))})</span><br>"
        f"{prose(_trim((split_fix(rows[0].get('recommended_fix'))[0] or [''])[0], 230))}</li>" for rows in issues[:3])
    sev_bars = _bar_rows([(SEV_DISPLAY.get(s, s), sum(1 for rows in issues if rows[0].get('cvss_severity') == s), SEV_COLOR[s], "")
                          for s in ("Critical", "High", "Medium", "Low")], max(1, len(issues)))
    heat = _heatmap(confirmed).replace(">Medium<", ">Moderate<")
    sev_rows = "".join(f"<tr><td class='sevcell sc-{n.lower() if n != 'Moderate' else 'medium'}'>{n}</td><td>{rng}</td><td>{d}</td></tr>" for n, rng, d in SEV_DEFS[:4])
    prod_issues = sum(1 for rows in issues if any(env_class(r["environment"]) == "production" for r in rows))
    prod_systems = len({r["asset"] for r in prod})
    lead_in = (f"Every one of the {len(issues)} issues is" if prod_issues == len(issues) else f"{prod_issues} of the {len(issues)} issues are")
    headline = (f"{lead_in} present in production: {len(prod)} findings on {prod_systems} production "
                f"system{'s' if prod_systems != 1 else ''}, {prod_hi} of them rated High or Critical." if prod
                else "None of the confirmed findings affects production.")
    def n_issues(severity: str) -> int:
        return sum(1 for rows in issues if rows[0].get("cvss_severity") == severity)

    sev_table = "".join(
        f"<tr><td class='sevcell sc-{sv.lower()}'>{lab}</td><td class='n'>{n_issues(sv)}</td><td class='n'>{sev.get(sv, 0)}</td></tr>"
        for sv, lab in (("Critical", "Critical"), ("High", "High"), ("Medium", "Moderate"), ("Low", "Low")))
    sev_table += f"<tr class='tot'><td><b>Total</b></td><td class='n'>{len(issues)}</td><td class='n'>{len(confirmed)}</td></tr>"
    posture_label, posture_color, posture_text = RISK_POSTURE[risk_posture(confirmed)]
    n_now = sum(1 for rows in issues if best_tier(rows) == "CHASE")
    risks = "".join(
        f"<li><b>{e(display_title(rows[0]))}.</b> {prose((_sentences(rows[0].get('business_impact')) or [''])[0])}</li>" for rows in issues[:3])
    brief = (f"<li class='lead'>{e(headline)}</li>"
             + (f"<li>{_plural(n_now, 'issue is', 'issues are')} marked <b>Fix now</b>: the most severe, closest to production.</li>" if n_now else "")
             + risks)
    owners = sorted({r.get("asset_owner") for r in confirmed if r.get("asset_owner")})
    asks = ([f"Approve immediate work on the {n_now} issue{'s' if n_now != 1 else ''} marked Fix now."] if n_now else []) + (
        [f"Confirm an owner for every issue. Teams named in the records: {e(', '.join(owners))}."] if owners else []) + (
        [f"Schedule follow-up testing for the {n_nr} finding{'s' if n_nr != 1 else ''} the evidence could not decide. The technical report names the test that would settle each one."] if n_nr else []) + [
        "Schedule a retest once the fixes ship, to confirm each one holds."]
    decisions = "".join(f"<li>{d}</li>" for d in asks)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{cl} Executive Security Report</title>
{FONT_LINKS}<style>{REPORT_BASE_CSS}{CLIENT_CSS}</style></head><body><div class="doc">
{_cover(cl, "Executive Security Report", [("Edition", "Executive, for leadership and risk owners"), ("Prepared for", client)] + ([("Prepared by", author)] if author else []) + [("Classification", "Business Confidential"), ("Report date", report_date), ("Findings observed", window or "Not recorded in the source data"), ("Source data", source_name), ("Version", "1.0")], "Executive edition")}
<div class="page">
<h2 style="break-before:auto">Executive brief</h2>
<div class="posture" style="--c:var({posture_color})"><span class="plabel">Risk posture</span><b>{e(posture_label)}</b><p>{e(posture_text)}</p></div>
<h4>What leadership needs to know</h4>
<ul class="brief">{brief}</ul>
<h4>Decisions requested</h4>
<ol class="steps">{decisions}</ol>
<table class="sevsum"><thead><tr><th>Severity</th><th>Distinct issues</th><th>Findings</th></tr></thead><tbody>{sev_table}</tbody></table>
<h4>Fix these first</h4><ol class="steps">{first}</ol>
<p class="muted">Engineers: each issue below lists its CVSS vector, the fix steps and, behind each finding ID, the evidence that proves it. The companion technical report holds the full adjudication.</p>

<h2>About these numbers</h2>
<p>Your security tooling raised {len(results)} findings. Each was checked against the evidence behind it, and <b>{len(confirmed)}</b> are confirmed real.
Where the same flaw was reported more than once it is described once, with every affected system and finding ID listed under it. The {len(confirmed)} findings are therefore
<b>{len(issues)} distinct issues</b>. A <i>finding</i> is one scanner record; some systems carry several records of the same flaw. An <i>issue</i> is the same flaw wherever it occurs.</p>
<p>This report triages findings that {cl}'s tooling had already raised, using the evidence recorded with each one. It is not a penetration test: no system was tested for this report, and nothing here goes beyond what that evidence shows.{(" " + e(date_note)) if date_note else ""}</p>
<p>The other {len(results) - len(confirmed)} findings are not in this report. {n_fp} were checked and are not exploitable as reported, so no action is needed. {n_nr} could not be decided from the evidence supplied: they are neither confirmed nor ruled out, and each needs one specific follow-up test before it can be settled.</p>
<div class="twocol"><div><h4>Findings by environment and severity</h4>{heat}</div><div><h4>Distinct issues by severity</h4>{sev_bars}</div></div>

<h2 id="index">All issues at a glance</h2>
<table><thead><tr><th>#</th><th>Issue</th><th>Severity</th><th>CVSS</th><th>Findings</th><th>Systems</th><th>Environments</th><th>Fix order</th></tr></thead><tbody>{index_rows}</tbody></table>
<h4 style="margin-top:14px">How severity is rated (CVSS 3.1; "Moderate" is the CVSS "Medium" rating)</h4><table><thead><tr><th>Severity</th><th>Score</th><th>What it means</th></tr></thead><tbody>{sev_rows}</tbody></table>
<p class="muted">Issues are ordered by severity, then score, then how many findings are in production, then how many findings in total. Issue numbers match the F-numbers in the technical report. Fix order combines the CVSS score with how close the system is to production (production counts fully, disaster-recovery next, then staging, then sandbox); it is shown for each affected system.</p>
{body}
<h2>About this report</h2>
<p>This is a snapshot in time based on the evidence recorded with each confirmed finding{e(_observed_from(window))}. No new testing was run against any system for this report.{(" Prepared by " + e(author) + " for " + cl + ".") if author else ""} The {n_fp} findings shown not to be exploitable and the {n_nr} that need more evidence are not listed here. Repeat the review after fixes ship to confirm that the controls hold.</p>
</div><div class="foot">{cl} Executive Security Report{(" &middot; Prepared by " + e(author)) if author else ""} &middot; Business Confidential &middot; Version 1.0 &middot; {e(report_date)}</div></div>
<noscript><style>.evrow[hidden]{{display:table-row}}</style></noscript>
<script>{PROOF_JS}</script></body></html>"""


def _md(text: object) -> str:
    """One line of prose for Markdown (pipes are escaped only where a table needs it)."""
    return re.sub(r"\s+", " ", str(text or "")).strip()


def build_client_markdown(results: List[dict], source_name: str, client: str = "Client", company: str = "", tester: str = "") -> str:
    """The client report as Markdown: the three highest-priority issues first, then every other confirmed issue.
    Each carries title, affected assets, CVSS 3.1 vector and score, impact, fix and the verbatim evidence quotes."""
    confirmed = [r for r in results if r["classification"] == "Confirmed"]
    issues = issue_groups(confirmed)
    window, date_note = _observed(confirmed)
    counts = collections.Counter(r["classification"] for r in results)
    author = prepared_by(company, tester)
    out = [f"# {client}: Confirmed Security Findings", "",
           f"Prepared for {client}" + (f" by {author}" if author else ""), "",
           f"Business Confidential · Version 1.0 · Report date {_fmt_date(dt.date.today())} · Source data: {source_name}", "",
           "## Summary", "",
           f"{_plural(len(results), 'scanner finding was', 'scanner findings were')} triaged against the evidence recorded with "
           f"each one: {counts['Confirmed']} confirmed, {counts['False Positive']} false positive{'s' if counts['False Positive'] != 1 else ''} "
           f"and {counts['Needs Review']} needing more evidence before {'it' if counts['Needs Review'] == 1 else 'they'} can be decided. "
           f"The confirmed findings are {_plural(len(issues), 'distinct issue', 'distinct issues')}{_observed_from(window)}. This is a triage of "
           f"existing findings, not a penetration test; no system was tested for this report." + (f" {date_note}" if date_note else ""), "",
           "| # | Issue | Severity | CVSS | Findings | Systems |", "|---|---|---|---|---|---|"]
    for i, g in enumerate(issues, 1):
        sev = g[0].get("cvss_severity")
        out.append(f"| F-{i:02d} | {_md(display_title(g[0])).replace('|', chr(92) + '|')} | {SEV_DISPLAY.get(sev, sev)} | {g[0].get('cvss_score')} | {len(g)} | {_systems(g)} |")
    for i, g in enumerate(issues, 1):
        if i == 1:
            out += ["", "## Top 3 priority issues"]
        elif i == 4:
            out += ["", "## All other confirmed issues"]
        lead, sev = g[0], g[0].get("cvss_severity")
        steps, harden, verify = split_fix(lead.get("recommended_fix"))
        refs = re.sub(r"<[^>]+>", "", references_html(issue_key(lead)))
        out += ["", f"### F-{i:02d} {_md(display_title(lead))} ({SEV_DISPLAY.get(sev, sev)})", "",
                f"- **CVSS 3.1:** {lead.get('cvss_score')} `{lead.get('cvss_vector')}`",
                f"- **Affected ({_reach(g)}):** " + "; ".join(f"`{r['asset']}` ({r['environment']}, {r['finding_id']})" for r in g),
                f"- **Owner:** {_owners(g)}"] + ([f"- **References:** {html.unescape(refs)}"] if refs else []) + [
                "", "**Impact.** " + _md(lead.get("business_impact")), "", "**Recommended fix.**", ""]
        out += [f"{n}. {_md(s)}" for n, s in enumerate(steps + harden, 1)]
        if verify:
            out += ["", "**How to check the fix worked.** " + _md(" ".join(verify))]
        out += ["", f"**Evidence** (verbatim from the source record for {lead['finding_id']}):", ""]
        for c in (lead.get("evidence") or [])[:4]:
            out.append(f"- {field_label(c['field'])}: `{_md(_trim(c['quote'], 300)).replace('`', '')}`"
                       + (f" ({_md(c.get('supports'))})" if c.get("supports") else ""))
        if len(g) > 1:
            out += ["", f"Impact and fix are described from {lead['finding_id']}; the same flaw was confirmed for every finding listed above."]
    return "\n".join(out) + "\n"


# ============================================================================
# Command line
# ============================================================================
DEFAULT_MODEL = "claude-sonnet-5-5"
DEFAULT_FALLBACK = "claude-opus-5-5"
HERE = Path(__file__).resolve().parent


def choose_csv() -> Path:
    """Ask the user to pick a CSV from the current and data directories, or to type a path.

    Raises:
        SystemExit: If input ends before a file is chosen.
    """
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


def ask(label: str, given: Optional[str], default: str = "") -> str:
    """A value from the command line, else asked for interactively, else the default (non-interactive runs)."""
    if given is not None:
        return given.strip()
    if not sys.stdin.isatty():
        return default
    try:
        ans = input(f"{label}{f' [{default}]' if default else ' (Enter to leave out)'}: ").strip()
    except EOFError:
        return default
    return ans or default


def report_parties(args: argparse.Namespace, saved: Optional[dict] = None) -> Tuple[str, str, str]:
    """Client company, reporting company and assessor name for the reports. Flags win, then prompts; a rebuild
    offers the values saved with the run as defaults. Blank author fields are left out of the reports."""
    saved = saved or {}
    return (ask("Client company name", args.client_name, saved.get("client_name") or "Client") or "Client",
            ask("Reporting company name", args.company, saved.get("reporting_company", "")),
            ask("Pentester / assessor name", args.tester, saved.get("assessor_name", "")))


def rebuild_reports(out: Path, source_name: str, source_csv: Optional[Path] = None,
                    parties: Optional[Callable[[dict], Tuple[str, str, str]]] = None) -> int:
    """Regenerate both HTML reports from saved results. No model calls."""
    try:
        results = [json.loads(line) for line in (out / "assessments.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        chains = json.loads((out / "attack_chains.json").read_text(encoding="utf-8"))
        summary = json.loads((out / "run_summary.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: cannot rebuild reports from {out}: {exc}", file=sys.stderr)
        return 2
    for r in results:  # fix order is derived from the saved CVSS score, so a policy change needs no model calls
        polish_result(r)  # re-apply the current editorial rules to saved prose (idempotent)
        if r["classification"] == "Confirmed":
            r["priority_score"], r["priority_tier"] = priority(r.get("cvss_score"), r["environment"])
    write_classified(out / "classified_findings.csv", results)
    (out / "assessments.jsonl").write_text("".join(json.dumps(r, default=str) + "\n" for r in results), encoding="utf-8")
    used = summary.get("model_calls_answered") or {}
    model_desc = ", ".join(f"{m} ({n} calls)" for m, n in used.items()) or ", ".join(summary.get("model_chain", []))
    name, company, tester = parties(summary) if parties else (summary.get("client_name") or "Client",
                                                               summary.get("reporting_company", ""), summary.get("assessor_name", ""))
    summary.update(client_name=name, reporting_company=company, assessor_name=tester)
    (out / "run_summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    source_rows: Optional[Dict[str, Dict[str, str]]] = None
    if source_csv:
        try:
            saved = out / "column_map.json"
            mapping = json.loads(saved.read_text(encoding="utf-8")) if saved.exists() else None
            source_rows = {r["finding_id"]: r for r in read_findings(source_csv, mapping=mapping)}
        except (OSError, InputError) as exc:
            print(f"warning: the client report will show quoted lines only; could not read {source_csv}: {exc}", file=sys.stderr)
    for r in results:  # results saved before last_observed_utc was recorded
        if not r.get("last_observed_utc") and source_rows and r["finding_id"] in source_rows:
            r["last_observed_utc"] = source_rows[r["finding_id"]].get("last_observed_utc", "")
    analyst = build_report(results, source_name, model_desc, chains, name, company, tester)
    client_page = build_client_report(results, source_name, chains, name, source_rows, company, tester)
    (out / "findings_report.html").write_text(analyst, encoding="utf-8")
    (out / "client_report.html").write_text(client_page, encoding="utf-8")
    (out / "client_report.md").write_text(build_client_markdown(results, source_name, name, company, tester), encoding="utf-8")
    leftover = report_style_issues(analyst) + report_style_issues(client_page)
    if leftover:
        print(f"WARNING: report prose still contains: {', '.join(sorted(set(leftover)))}", file=sys.stderr)
    print(f"Rebuilt {out}/findings_report.html, client_report.html and client_report.md from {len(results)} saved assessments")
    if source_csv and source_csv.exists():
        try:
            n = write_filled_input(out / f"{source_csv.stem}-filled.csv", source_csv, results,
                                   list(source_rows.values()) if source_rows else None)
            print(f"Rebuilt {out}/{source_csv.stem}-filled.csv ({n} rows filled)")
        except (InputError, OSError) as exc:
            print(f"warning: could not rebuild the filled input CSV: {exc}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Define the command-line options."""
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
    ap.add_argument("--client-name", help="client company name for the reports (prompted if omitted; default: Client)")
    ap.add_argument("--company", help="reporting company name (prompted if omitted; '' to leave out)")
    ap.add_argument("--tester", help="pentester / assessor name (prompted if omitted; '' to leave out)")
    ap.add_argument("--no-cache", action="store_true", help="ignore cached model responses")
    ap.add_argument("--skip-fact-check", action="store_true", help="do not fact-check the client-facing text")
    ap.add_argument("--column-map", type=Path, help="JSON object mapping source columns to roles; overrides the inferred mapping")
    ap.add_argument("--rebuild-reports", action="store_true",
                    help="rebuild both HTML reports from the saved out/assessments.jsonl; no model calls")
    ap.add_argument("--self-test", action="store_true", help="run the built-in test suite and exit")
    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Command-line entry point.

    Args:
        argv: Arguments to parse; defaults to sys.argv.

    Returns:
        Exit code: 0 success, 2 input error, 3 some findings could not be assessed, 130 interrupted.
    """
    args = build_parser().parse_args(argv)
    if args.self_test:
        result = unittest.main(module=__name__, argv=[sys.argv[0]], exit=False, verbosity=2).result
        return 0 if result.wasSuccessful() else 1

    if args.rebuild_reports:
        return rebuild_reports(args.out, args.csv.name if args.csv else "findings CSV", args.csv,
                               lambda saved: report_parties(args, saved))

    csv_path = args.csv or choose_csv()
    models = [args.model] + [m.strip() for m in (args.fallback_model or "").split(",") if m.strip() and m.strip() != args.model]
    llm = ClaudeCLI(models, effort=args.effort or None, binary=args.claude_bin, timeout=args.timeout,
                    cache_dir=None if args.no_cache else HERE / ".cache")
    try:
        llm.check_available()
    except LLMError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        override = json.loads(args.column_map.read_text(encoding="utf-8")) if args.column_map else None
        if override is not None and not (isinstance(override, dict) and all(isinstance(v, str) for v in override.values())):
            raise InputError(f"{args.column_map}: expected a JSON object of source column -> role")
        rows = read_findings(csv_path, llm=llm, override=override)
        mapping = read_findings.last_mapping  # type: ignore[attr-defined]
        all_rows = list(rows)
        context = dataset_context(rows)  # computed over the whole file, before any --ids/--limit filter
        rows.sort(key=time_sort_key)     # process and report in chronological order
    except (InputError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("Column mapping (source column -> role):")
    for src, dst in mapping.items():
        print(f"  {src!r:<34} -> {dst}")
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
    client, company, tester = report_parties(args)  # asked before the long run, not after it
    out = args.out
    out.mkdir(parents=True, exist_ok=True)


    print(f"Assessing {len(rows)} findings from {csv_path.name} with {llm.model} ({args.workers} workers)")
    t0 = time.time()
    tally = collections.Counter()

    def progress(done: int, total: int, res: dict) -> None:
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
    facts_log: List[dict] = []
    if not args.skip_fact_check:
        facts_log = fact_check(results, {r["finding_id"]: r for r in rows}, llm)
        for f in facts_log:
            bad = [c["claim"] for c in f["claims"] if c["status"] == "unsupported"]
            print(f"[fact-check] {f['finding_id']} {f['status']}" + (f": {'; '.join(bad)[:200]}" if bad else "")
                  + (f" ({f['error'][:120]})" if f.get("error") else ""))
        (out / "fact_check.json").write_text(json.dumps(facts_log, indent=1), encoding="utf-8")
    # Outputs are written only after the consistency gate and chain correlation have run.
    write_classified(out / "classified_findings.csv", results)
    filled_path = out / f"{csv_path.stem}-filled.csv"
    n_filled = write_filled_input(filled_path, csv_path, results, all_rows)
    (out / "column_map.json").write_text(json.dumps(mapping, indent=1), encoding="utf-8")
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
    stats = {"client_name": client, "reporting_company": company, "assessor_name": tester, "agents": AGENTS, "model_chain": llm.models, "model_calls_answered": used, "models_disabled": llm.disabled,
             "effort": args.effort, "findings": len(results),
             "counts": dict(collections.Counter(r["classification"] for r in results)),
             "llm_calls": llm.stats.calls, "cache_hits": llm.stats.cache_hits, "failures": llm.stats.failures, "rows_failed": errors,
             "cost_usd_this_run": round(llm.stats.cost_usd, 2), "elapsed_s": round(time.time() - t0, 1),
             "consistency_audit": {k: audit[k] for k in ("scenario_groups", "split_groups", "minority_rows")},
             "fact_check": dict(collections.Counter(f["status"] for f in facts_log)) if facts_log else "skipped"}
    (out / "run_summary.json").write_text(json.dumps(stats, indent=1), encoding="utf-8")
    page = build_report(results, csv_path.name, model_desc, chains, client, company, tester)
    (out / "findings_report.html").write_text(page, encoding="utf-8")
    client_page = build_client_report(results, csv_path.name, chains, client, {r["finding_id"]: r for r in rows}, company, tester)
    (out / "client_report.html").write_text(client_page, encoding="utf-8")
    (out / "client_report.md").write_text(build_client_markdown(results, csv_path.name, client, company, tester), encoding="utf-8")
    leftover = report_style_issues(page) + report_style_issues(client_page)
    audit["report_style_issues"] = leftover
    (out / "audit.json").write_text(json.dumps(audit, indent=1, default=str), encoding="utf-8")
    if leftover:
        print(f"WARNING: report prose still contains: {', '.join(leftover)}", file=sys.stderr)
    print(json.dumps(stats, indent=1))
    print(f"Wrote {out}/: classified_findings.csv, findings_report.html, client_report.html, client_report.md, assessments.jsonl, attack_chains.json, audit.json, run_summary.json")
    for m, why in llm.disabled.items():
        print(f"NOTICE: {m} was unavailable ({why[:120]}); fallback model(s) answered instead - see run_summary.json",
              file=sys.stderr)
    flagged = [f["finding_id"] for f in facts_log if f["status"] == "flagged"]
    if flagged:
        print(f"WARNING: client-facing text for {len(flagged)} issue(s) still has claims the evidence does not support "
              f"({', '.join(flagged)}). Fix them before sending; see fact_check.json and the analyst report.", file=sys.stderr)
    if errors:
        print(f"WARNING: {errors} finding(s) could not be assessed and were routed to Needs Review. "
              f"Re-run the same command to retry them (successful calls are cached).", file=sys.stderr)
        return 3
    return 0


# ============================================================================
# Self-tests (python3 triage.py --self-test)
# ============================================================================
def _test_row(**kw: Any) -> Dict[str, str]:
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


GOOD_QUOTES = [("observation", "Tenant B session retrieved tenant A vehicle record 4411"),
               ("raw_response", '{"vehicle":4411,"org":"tenant-a"}')]
CHECK_QUOTE = GOOD_QUOTES[0]


def _test_checklist(cls: str, category: str = "Authorization", **override: Any) -> List[dict]:
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


def _test_assessment(cls: str, quotes: List[Tuple[str, str]], conf: float = 0.9, observed: bool = True,
                     vector: str = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                     checklist: Optional[List[dict]] = None) -> dict:
    return {
        "checklist": _test_checklist(cls) if checklist is None else checklist,
        "decisive_boundary": "cross-tenant read", "boundary_observed": observed, "provenance": "runtime",
        "compensating_controls": "claimed only", "classification": cls, "confidence": conf,
        "reasoning": "test", "evidence": [{"field": f, "quote": q, "supports": "x"} for f, q in quotes],
        "missing_evidence": "",
        "report": {"client_title": "t", "cvss_vector": vector if cls == "Confirmed" else "",
                   "cvss_rationale": "", "business_impact": "", "recommended_fix": ""},
    }


def _synthetic_findings() -> List[Dict[str, str]]:
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
            out["cvss_rationale"] = f"AV:{v.split('AV:')[1][0]} because ..."
            res.append(out)
        harmonise(twins, res)
        self.assertEqual({r["cvss_vector"] for r in res}, {vecs[0]})
        self.assertEqual(res[2]["cvss_vector_original"], vecs[2])
        self.assertEqual(res[2]["cvss_rationale"], "AV:N because ...")   # the rationale travels with the vector
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

    def test_cvss_tiebreak_is_per_metric_median_and_order_independent(self):
        def rv(vec, title):
            return {"classification": "Confirmed", "report": {"cvss_vector": vec, "client_title": title,
                                                              "cvss_rationale": "r.", "business_impact": "", "recommended_fix": ""}}
        hi = rv("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "hi")   # 8.1
        lo = rv("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", "lo")   # 6.5
        two, note = tiebreak_vector([hi, lo])
        self.assertEqual(two["cvss_vector"], lo["report"]["cvss_vector"])  # two reviews: the less severe value
        self.assertIn("C (H vs N; scored N)", note)
        self.assertEqual(tiebreak_vector([lo, hi])[0], two)                 # order does not matter
        three, _ = tiebreak_vector([hi, lo, rv(hi["report"]["cvss_vector"], "adj")])
        self.assertEqual(three["cvss_vector"], hi["report"]["cvss_vector"])  # two of three agree: their value
        same, note2 = tiebreak_vector([hi, rv(hi["report"]["cvss_vector"], "b")])
        self.assertEqual((same["cvss_vector"], note2), (hi["report"]["cvss_vector"], ""))
        self.assertEqual(tiebreak_vector([{"classification": "Confirmed", "report": {"cvss_vector": "junk"}}]), (None, ""))

    def test_scores_in_different_severity_bands_are_adjudicated(self):
        conf = {"classification": "Confirmed"}
        high = dict(conf, report={"cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"})      # 8.1 High
        critical = dict(conf, report={"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"})  # 9.1 Critical
        self.assertIn("severity band", needs_adjudication(high, critical) or "")
        self.assertIsNone(needs_adjudication(high, dict(high)))
        same_band = dict(conf, report={"cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"})  # 8.3 High
        self.assertIn("A A=N B=L", needs_adjudication(high, same_band) or "")  # any metric split gets a third vote

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
            self.assertTrue(len(ids) >= 2 and len(set(ids)) == len(ids), c)

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
        with tempfile.TemporaryDirectory() as d:
            src, dst = Path(d) / "in.csv", Path(d) / "out.csv"
            src.write_text("finding_id,asset,candidate_classification,candidate_reasoning\n"
                           'A-1,"a,b\nc",,\nA-2,x,,\n', encoding="utf-8")
            n = write_filled_input(dst, src, [{"finding_id": "A-1", "classification": "Confirmed", "reasoning": "=bad"}])
            with open(dst, newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
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
        self.assertEqual(_observed([{"first_observed_utc": "N/A"}])[0], "")   # no dates: nothing claimed
        self.assertEqual(plain_text("Done. The packet does not show it."), "Done. The evidence does not show it.")
        self.assertEqual(plain_text("Two accounts. the evidence ends, e.g. here. eval(x) stays."), "Two accounts. The evidence ends, e.g. here. eval(x) stays.")

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


class TestAnyCSV(unittest.TestCase):
    """Any delimited file, any column names, any data: the pipeline maps it and still produces valid reports."""

    HEADERS = ["Host", "Plugin Name", "Risk", "Plugin Output", "Analyst Notes", "Status", "Env", "Discovered"]
    DATA = [["10.0.0.5", "SQL Injection in /search", "High",
             'GET /search?q=1%27%20OR%201=1--\nHTTP/1.1 200 OK\n{"rows": 4021, "note": "all customers returned"}',
             "Dev team says WAF blocks this; not verified", "Open", "prod", "03/15/2026 14:02"],
            ["10.0.0.9", "Missing HSTS header", "Low", "Strict-Transport-Security header not present", "Caf\u00e9 team owns this",
             "Open", "staging", "2026-03-16"],
            ["10.0.0.5", "Outdated jQuery 1.8", "Medium", "", "Version string seen only", "Accepted risk", "prod", "1773700000"]]

    def _write(self, d: str, delimiter: str = ";", encoding: str = "cp1252") -> Path:
        path = Path(d) / "export.csv"
        with open(path, "w", newline="", encoding=encoding) as fh:
            csv.writer(fh, delimiter=delimiter).writerows([self.HEADERS] + self.DATA)
        return path

    def test_scanner_export_is_mapped_without_a_model(self):
        with tempfile.TemporaryDirectory() as d:
            rows = read_findings(self._write(d))
        m = read_findings.last_mapping
        self.assertEqual((m["Host"], m["Plugin Name"], m["Risk"], m["Env"]), ("asset", "finding_title", "scanner_severity", "environment"))
        self.assertEqual((m["Plugin Output"], m["Analyst Notes"], m["Status"]), ("capture.plugin_output", "claim.analyst_notes", "answer.status"))
        self.assertEqual([r["finding_id"] for r in rows], ["ROW-0001", "ROW-0002", "ROW-0003"])  # no ID column: numbered
        self.assertEqual(rows[0]["first_observed_utc"], "2026-03-15T14:02:00Z")
        self.assertTrue(rows[2]["first_observed_utc"].startswith("2026-03-16T"))           # epoch seconds
        self.assertIn("Caf\u00e9", rows[1]["claim.analyst_notes"])                         # Windows-1252 decoded
        self.assertNotIn("Accepted risk", render_packet(rows[2]))                           # an existing verdict is hidden
        self.assertEqual(priority(9.0, "prod"), priority(9.0, "production"))

    def test_capture_columns_can_confirm_and_claim_columns_cannot(self):
        with tempfile.TemporaryDirectory() as d:
            row = read_findings(self._write(d, ",", "utf-8"))[0]
        q1, q2 = 'GET /search?q=1%27%20OR%201=1--', '"note": "all customers returned"'
        checks = [{"id": cid, "answer": "yes", "field": "capture.plugin_output", "quote": q2} for cid, _ in RUBRICS["Injection"]["checks"]]
        ok = apply_gates(row, _test_assessment("Confirmed", [("capture.plugin_output", q1), ("capture.plugin_output", q2)], checklist=checks))
        self.assertEqual(ok["classification"], "Confirmed")
        claim_only = apply_gates(row, _test_assessment("Confirmed", [("claim.analyst_notes", "Dev team says WAF blocks this")], checklist=checks))
        self.assertEqual(claim_only["classification"], "Needs Review")

    def test_model_column_mapping_is_validated_by_code(self):
        headers = ["Ref", "Weird Col", "Other", "Ghost"]
        rows = [{"Ref": "A", "Weird Col": "x", "Other": "y", "Ghost": ""}]
        answer = {"columns": [{"column": "Weird Col", "role": "asset"}, {"column": "Other", "role": "asset"},
                              {"column": "Ghost", "role": "made_up_role"}, {"column": "Not A Column", "role": "capture"}]}
        m = infer_mapping(headers, rows, FakeLLM(lambda s, msg: answer))
        self.assertEqual(m["Ref"], "finding_id")                       # alias rule, never re-asked
        self.assertEqual(m["Weird Col"], "asset")
        self.assertEqual(m["Other"], "context.other")                  # a canonical role is used at most once
        self.assertEqual(m["Ghost"], "context.ghost")                  # an unknown role falls back to context
        self.assertNotIn("Not A Column", m)

    def test_column_map_override_wins_and_is_checked(self):
        m = infer_mapping(["Host", "Blob"], [{"Host": "h", "Blob": "b"}], override={"Blob": "capture.blob"})
        self.assertEqual(m["Blob"], "capture.blob")
        with self.assertRaises(InputError):
            infer_mapping(["Host"], [{"Host": "h"}], override={"Host": "not_a_role"})

    def test_any_csv_produces_valid_reports_and_filled_copy(self):
        q1, q2 = 'GET /search?q=1%27%20OR%201=1--', '"note": "all customers returned"'
        def responder(stage, msg):
            if "ROW-0001" in msg:
                checks = [{"id": cid, "answer": "yes", "field": "capture.plugin_output", "quote": q2} for cid, _ in RUBRICS["Injection"]["checks"]]
                return _test_assessment("Confirmed", [("capture.plugin_output", q1), ("capture.plugin_output", q2)],
                                        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", checklist=checks)
            return _test_assessment("Needs Review", [], conf=0.5, observed=False, checklist=[])
        with tempfile.TemporaryDirectory() as d:
            src = self._write(d)
            rows = read_findings(src)
            results = run(rows, FakeLLM(responder), workers=1)
            pages = (build_report(results, src.name, "fake", correlate_chains(results), "Acme"),
                     build_client_report(results, src.name, (), "Acme", {r["finding_id"]: r for r in rows}),
                     build_client_markdown(results, src.name, "Acme"))
            n = write_filled_input(Path(d) / "filled.csv", src, results, rows)
            with open(Path(d) / "filled.csv", newline="", encoding="utf-8") as fh:
                filled = list(csv.DictReader(fh))
        self.assertEqual([r["classification"] for r in results], ["Confirmed", "Needs Review", "Needs Review"])
        for page in pages:
            self.assertIn("10.0.0.5", page)
            self.assertNotRegex(page, r"<td>None</td>|<code>None</code>|\bNone \u00b7|: None\b")  # no empty value printed as None
        self.assertEqual(report_style_issues(pages[0]) + report_style_issues(pages[1]), [])
        self.assertEqual((n, list(filled[0])[:len(self.HEADERS)]), (3, self.HEADERS))     # original columns kept
        self.assertEqual(filled[0]["candidate_classification"], "Confirmed")


class TestFactChecker(unittest.TestCase):
    """The Fact-checker may only narrow client text; it never invents, never touches verdicts or scores."""

    def _setup(self, answers):
        row = _test_row()
        res = assess_row(row, FakeLLM(lambda s, m: _test_assessment("Confirmed", GOOD_QUOTES)))
        res["business_impact"] = "Tenant B read tenant A's vehicle record. This exposes every customer's billing history."
        calls = iter(answers)
        llm = FakeLLM(lambda s, m: next(calls))
        return row, res, llm

    @staticmethod
    def _answer(status, quote="", impact=""):
        return {"claims": [{"field": "business_impact", "claim": "c", "status": status, "quote": quote, "note": ""}],
                "revised_title": "", "revised_impact": impact}

    def test_supported_claim_with_real_quote_passes_unchanged(self):
        row, res, llm = self._setup([self._answer("supported", GOOD_QUOTES[0][1])])
        before = res["business_impact"]
        log = fact_check([res], {row["finding_id"]: row}, llm)
        self.assertEqual(log[0]["status"], "passed")
        self.assertEqual(res["business_impact"], before)

    def test_record_facts_such_as_environment_count_as_support(self):
        row, _, _ = self._setup([])
        self.assertEqual(verify_claims(row, self._answer("supported", row["environment"])["claims"])[0]["status"], "supported")
        self.assertEqual(verify_claims(row, self._answer("supported", "Critical")["claims"])[0]["status"], "unsupported")

    def test_quote_copied_with_packet_markup_still_counts(self):
        row, _, _ = self._setup([])
        q = f'<field name="environment">\n{row["environment"]}'
        self.assertEqual(verify_claims(row, self._answer("supported", q)["claims"])[0]["status"], "supported")

    def test_supported_label_with_invented_quote_counts_as_unsupported(self):
        row, res, _ = self._setup([])
        claims = verify_claims(row, self._answer("supported", "every customer's billing history is exposed")["claims"])
        self.assertEqual(claims[0]["status"], "unsupported")

    def test_unsupported_claim_is_rewritten_and_rechecked(self):
        fixed = "Tenant B read tenant A's vehicle record."
        row, res, llm = self._setup([self._answer("unsupported", impact=fixed), self._answer("supported", GOOD_QUOTES[0][1])])
        verdict, score = res["classification"], res["cvss_score"]
        log = fact_check([res], {row["finding_id"]: row}, llm)
        self.assertEqual(log[0]["status"], "revised")
        self.assertEqual(res["business_impact"], fixed)
        self.assertEqual((res["classification"], res["cvss_score"]), (verdict, score))

    def test_claim_still_unsupported_after_rewrite_is_flagged_for_a_person(self):
        row, res, llm = self._setup([self._answer("unsupported", impact="Still says billing."), self._answer("unsupported")])
        log = fact_check([res], {row["finding_id"]: row}, llm)
        self.assertEqual(log[0]["status"], "flagged")
        self.assertIn("held for review", build_report([res], "x.csv", "fake"))

    def test_failed_fact_check_is_flagged_never_passed(self):
        row, res, _ = self._setup([])
        def boom(stage, message):
            raise LLMError("timeout")
        log = fact_check([res], {row["finding_id"]: row}, FakeLLM(boom))
        self.assertEqual(log[0]["status"], "flagged")


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
                 finding_title=a["finding_title"] + " (lookup)", client_title="A different flaw of the same type")
        page = build_client_report([a, b, c], "x.csv")
        self.assertEqual(page.count('<article class="entry'), 2)  # a+b together, c apart
        # The technical report numbers the same issues the same way.
        self.assertEqual(len(re.findall(r'<span class="fcode">F-\d+</span>', build_report([a, b, c], "x.csv", "fake"))), 2)
        for r in (a, b, c):
            self.assertEqual(page.count(f">{r['finding_id']}</button>"), 1)  # each instance listed exactly once
        self.assertIn("other.example.test", page)

    def test_summary_issue_and_finding_counts_reconcile(self):
        a = self._results()[0]
        rows = [dict(a, finding_id=f"TF-6{i:03d}", asset=f"svc{i}.example.test") for i in range(4)]
        rows.append(dict(a, finding_id="TF-6900", finding_title="Another flaw", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                         cvss_severity="Critical", cvss_score=9.8))
        page = build_client_report(rows, "x.csv")
        m = re.search(r"<tr class='tot'><td><b>Total</b></td><td class='n'>(\d+)</td><td class='n'>(\d+)</td>", page)
        self.assertEqual((m.group(1), m.group(2)), ("2", "5"))  # 2 distinct issues, 5 findings

    def test_findings_and_systems_are_counted_separately(self):
        a = self._results()[0]
        rows = [dict(a, finding_id=f"TF-5{i:03d}") for i in range(3)]  # three records of one flaw on one system
        page = build_client_report(rows, "x.csv")
        self.assertIn("3 findings on 1 system", page)
        self.assertNotIn("3 systems", page)

    def test_fix_steps_starting_with_verify_are_not_mistaken_for_the_retest(self):
        steps, _, verify = split_fix("Verify every token against the issuer key. Pin the algorithm. To verify, replay the forged token.")
        self.assertEqual(len(steps), 2)
        self.assertEqual(verify, ["To verify, replay the forged token."])

    def test_editing_keeps_paths_and_uses_us_spelling(self):
        out = plain_text("Repeat with a ../quarantine/x.txt member . The organisation behaviour was authorised.")
        self.assertIn(" ../quarantine/x.txt member.", out)
        self.assertIn("organization behavior was authorized", out)
        self.assertIn("<code>/tmp/fl_probe</code>.", prose("wrote /tmp/fl_probe."))

    def test_impact_names_the_attacker_the_vector_requires(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
        self.assertEqual(align_actor("Anyone who can reach the endpoint can run code.", v),
                         "Any signed-in user who can reach the endpoint can run code.")
        self.assertEqual(align_actor("Anyone who can reach it.", v.replace("PR:L", "PR:N")), "Anyone who can reach it.")
        self.assertEqual(align_actor("Any caller who can reach it.", v), "Any signed-in user who can reach it.")
        self.assertEqual(align_actor("Anyone who can reach it.", v, "PR:L because the credential requirement was not shown."),
                         "An attacker who can reach it.")

    def test_reports_make_no_network_requests(self):
        res = self._results()
        for page in (build_client_report(res, "x.csv"), build_report(res, "x.csv", "fake")):
            self.assertNotRegex(page, r"<link[^>]+https?://|<script[^>]+src=|@import")

    def test_reports_carry_client_reporting_company_and_assessor(self):
        res = self._results()
        pages = (build_report(res, "x.csv", "fake", (), "Acme Fleet", "Northwind Security", "Jordan Lee"),
                 build_client_report(res, "x.csv", (), "Acme Fleet", None, "Northwind Security", "Jordan Lee"),
                 build_client_markdown(res, "x.csv", "Acme Fleet", "Northwind Security", "Jordan Lee"))
        for page in pages:
            self.assertIn("Acme Fleet", page)
            self.assertIn("Jordan Lee, Northwind Security", page)
        bare = build_report(res, "x.csv", "fake", (), "Acme Fleet")
        self.assertNotIn("Prepared by", bare)  # nothing is invented when the author is not given

    def test_markdown_report_has_every_required_field(self):
        res = self._results()
        md = build_client_markdown(res, "x.csv")
        for needle in ("## Top 3 priority issues", res[0]["cvss_vector"], str(res[0]["cvss_score"]), res[0]["asset"],
                       "**Impact.**", "**Recommended fix.**", "**Evidence**"):
            self.assertIn(needle, md)

    def test_every_confirmed_finding_appears_exactly_once(self):
        a = self._results()[0]
        rows = [dict(a, finding_id=f"TF-8{i:03d}", asset=f"svc{i}.example.test") for i in range(5)]
        page = build_client_report(rows, "x.csv")
        for r in rows:
            self.assertEqual(page.count(f">{r['finding_id']}</button>"), 1)

    def test_finding_id_opens_the_full_cited_record_with_the_quote_highlighted(self):
        res = self._results()
        row = _test_row(raw_response='HTTP/1.1 200 OK\nX-Trace: 1\n{"vehicle":4411,"org":"tenant-a"}\nend of capture')
        page = build_client_report(res, "x.csv", source_rows={"T-1": row})
        self.assertRegex(page, r"<button type='button' class='idbtn' aria-expanded='false' aria-controls='ev-T-1'>T-1</button>")
        self.assertIn("<tr class='evrow' id='ev-T-1' hidden>", page)
        self.assertIn("end of capture", page)                          # the whole record, not only the quote
        self.assertIn("<mark>{&quot;vehicle&quot;:4411,&quot;org&quot;:&quot;tenant-a&quot;}</mark>", page)
        self.assertEqual(report_style_issues(page), [])

    def test_evidence_without_source_rows_shows_the_quoted_lines_and_escapes_them(self):
        res = self._results()
        res[0]["evidence"][0]["quote"] = "<img src=x onerror=alert(1)> tenant record"
        page = build_client_report(res, "x.csv")
        self.assertNotIn("<img src=x", page)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt; tenant record", page)

    def test_highlight_matches_across_whitespace_and_case_and_never_breaks_markup(self):
        out = _highlight("a <b>\nTenant   B read</b> z", ["tenant b READ"])
        self.assertEqual(out, "a &lt;b&gt;\n<mark>Tenant   B read</mark>&lt;/b&gt; z")

    def test_risk_posture_follows_the_worst_confirmed_severity_in_production(self):
        mk = lambda sev, env: {"cvss_severity": sev, "environment": env}
        self.assertEqual(risk_posture([mk("Critical", "production"), mk("Low", "production")]), "critical")
        self.assertEqual(risk_posture([mk("High", "production"), mk("Critical", "staging")]), "high")
        self.assertEqual(risk_posture([mk("Medium", "production")]), "moderate")
        self.assertEqual(risk_posture([mk("Critical", "staging")]), "contained")
        self.assertEqual(risk_posture([]), "none")

    def test_executive_edition_leads_with_posture_and_decisions_and_the_analyst_edition_says_who_it_is_for(self):
        res = self._results()
        page = build_client_report(res, "x.csv")
        for text in ("Executive brief", "Risk posture", "What leadership needs to know", "Decisions requested", "Executive edition"):
            self.assertIn(text, page)
        self.assertEqual(report_style_issues(page), [])
        analyst = build_report(res, "x.csv", "fake")
        self.assertIn("How to Use This Report", analyst)
        self.assertIn("Analyst edition", analyst)
        self.assertNotIn("Executive Summary", analyst)

    def test_client_report_escapes_untrusted_text(self):
        res = self._results()
        res[0]["client_title"] = "<script>alert(1)</script>"
        self.assertNotIn("<script>alert(1)</script>", build_client_report(res, "x.csv"))


if __name__ == "__main__":
    sys.exit(main())
