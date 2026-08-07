#!/usr/bin/env python3
"""Hardened, overlay-bound PID-non-scoring manual attack8 scorer.

This version leaves the v1 scorer and v2 overlay wrapper unchanged.  It adds
closed-manifest verification, path-plus-byte evidence contracts, authoritative
overlay scope checks, transactional create-only publication, fail-closed
finalization, final input/output provenance, and a deterministic local
negative-test harness.  It never calls an external API.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import ntpath
import os
import shutil
import sys
import tempfile
import unicodedata
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, Iterable

try:
    from . import codex_manual_attack8_scoring as base
    from . import codex_manual_attack8_scoring_v2_pid_non_scoring as v2
except ImportError:  # Direct script execution.
    import codex_manual_attack8_scoring as base
    import codex_manual_attack8_scoring_v2_pid_non_scoring as v2


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = Path(__file__).resolve()
BASE_SCORER = Path(base.__file__).resolve()
SCHEMA_VERSION = "codex_manual_action_claim_review_v4_pid_non_scoring_hardened"
MANIFEST_SCHEMA_VERSION = "codex_manual_queue_manifest_v4_pid_non_scoring_hardened"
SELF_VALIDATION_SCHEMA_VERSION = "codex_manual_queue_self_validation_v4"
BUNDLE_COMPLETION_SCHEMA_VERSION = "codex_manual_queue_bundle_completion_v4"
FINALIZATION_SCHEMA_VERSION = "codex_manual_finalization_manifest_v4"
SYNTHETIC_SCHEMA_VERSION = "codex_manual_hardened_synthetic_validation_v4"
SYNTHETIC_MANIFEST_SCHEMA_VERSION = (
    "codex_manual_hardened_synthetic_validation_manifest_v4"
)
INCOMPLETE_EXIT_CODE = 3
EXPECTED_SLOT_KINDS = frozenset({"subject", "operation", "object"})
CONTRACT_KEYS = (
    *base.CONTRACT_KEYS,
    "run_json",
    "gold_json",
    "review_policy_overlay_path",
    "review_policy_overlay_sha256",
    "effective_review_policy_sha256",
)
FROZEN_SOURCE_KEYS = tuple(
    key for key in base.CONTRACT_KEYS if key != "schema_version"
)
MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "created_at_utc",
        "score_root",
        "source_prepare_manifest",
        "source_prepare_manifest_sha256",
        "source_queue",
        "source_queue_sha256",
        "validation_steps",
        "validation_steps_sha256",
        "review_policy_overlay_path",
        "review_policy_overlay_sha256",
        "effective_review_policy_sha256",
        "queue",
        "queue_sha256",
        "review_template",
        "review_template_sha256",
        "review_template_row_count",
        "wrapper_path",
        "wrapper_sha256",
        "base_scorer_path",
        "base_scorer_sha256",
        "run_root",
        "gold_root",
        "eligible_count",
        "models",
        "stage_counts",
        "denominators",
        "canonical_slot_kinds",
        "semantic_aliases",
        "pid_identity_scored",
        "hidden_alert_mapping_scored",
        "strict_pid_sentence_effective",
        "source_artifacts_modified",
        "external_api_calls",
        "non_overwrite_policy",
        "transactional_publication",
    }
)
PATH_HASH_BINDINGS = {
    "source_prepare_manifest_sha256": "source_prepare_manifest",
    "source_queue_sha256": "source_queue",
    "validation_steps_sha256": "validation_steps",
    "review_policy_overlay_sha256": "review_policy_overlay_path",
    "queue_sha256": "queue",
    "review_template_sha256": "review_template",
    "wrapper_sha256": "wrapper_path",
    "base_scorer_sha256": "base_scorer_path",
}


class IncompleteFinalization(ValueError):
    """A valid review set that is not a complete 48-row formal result."""


@dataclass(frozen=True)
class ReviewSnapshot:
    """One immutable, single-read reviewer input and its validated decisions."""

    role: str
    source_path: Path
    source_path_repo_relative: str
    raw_bytes: bytes
    raw_sha256: str
    reviewer_id: str
    rows_by_queue: dict[str, dict[str, Any]]

    @property
    def decision_set_sha256(self) -> str:
        return base.canonical_hash(
            {
                queue_id: row["decision_sha256"]
                for queue_id, row in sorted(self.rows_by_queue.items())
            }
        )


def repo_relative(path: Path, *, label: str = "artifact") -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError as exc:
        raise ValueError(f"{label} must be inside repository root: {path}") from exc


def declared_path(value: Any, *, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} path is missing or empty")
    candidate = Path(value)
    resolved = (candidate if candidate.is_absolute() else ROOT / candidate).resolve()
    repo_relative(resolved, label=label)
    return resolved


def require_child(path: Path, root: Path, *, label: str) -> None:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} is outside expected root {root}: {path}") from exc


def validate_safe_basename(value: Any, *, label: str) -> str:
    """Return a conservative cross-platform artifact basename.

    The name is validated using both POSIX and Windows path rules even when the
    current host is Windows. Compatibility Unicode is checked after NFKC
    normalization so full-width separators and dot segments cannot bypass the
    policy.
    """

    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty basename")
    if len(value) > 240:
        raise ValueError(f"{label} is too long")
    normalized = unicodedata.normalize("NFKC", value)
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"{label} contains a control character")
    if any(separator in value or separator in normalized for separator in ("/", "\\")):
        raise ValueError(f"{label} contains a path separator")
    if value in {".", ".."} or normalized in {".", ".."}:
        raise ValueError(f"{label} is a dot segment")
    if PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute():
        raise ValueError(f"{label} must not be absolute")
    if ntpath.splitdrive(value)[0] or ntpath.splitdrive(normalized)[0]:
        raise ValueError(f"{label} contains a drive or UNC component")
    if Path(value).name != value or PureWindowsPath(value).name != value:
        raise ValueError(f"{label} is not a basename")
    if any(
        character in '<>:"|?*'
        for candidate in (value, normalized)
        for character in candidate
    ):
        raise ValueError(f"{label} contains a Windows-reserved character")
    if value.endswith((" ", ".")) or normalized.endswith((" ", ".")):
        raise ValueError(f"{label} has a Windows-ambiguous suffix")
    device_stem = normalized.split(".", 1)[0].rstrip(" .").casefold()
    reserved = {"con", "prn", "aux", "nul", "clock$"}
    reserved.update(f"com{index}" for index in range(1, 10))
    reserved.update(f"lpt{index}" for index in range(1, 10))
    if device_stem in reserved:
        raise ValueError(f"{label} is a Windows-reserved device name")
    return value


def stage_destination(stage: Path, name: Any, *, label: str) -> Path:
    """Resolve a safe basename and prove the destination is beneath stage."""

    safe_name = validate_safe_basename(name, label=label)
    destination = stage / safe_name
    require_child(destination, stage, label=f"{label} destination")
    if destination.parent.resolve() != stage.resolve():
        raise ValueError(f"{label} destination is not directly beneath stage")
    return destination


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def jsonl_text(rows: Iterable[dict[str, Any]]) -> str:
    return "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)


def write_text_exclusive(path: Path, text: str) -> None:
    base.filesystem_path(path.parent).mkdir(parents=True, exist_ok=True)
    with base.filesystem_path(path).open(
        "x", encoding="utf-8", newline="\n"
    ) as handle:
        handle.write(text)


def write_bytes_exclusive(path: Path, content: bytes) -> None:
    base.filesystem_path(path.parent).mkdir(parents=True, exist_ok=True)
    with base.filesystem_path(path).open("xb") as handle:
        handle.write(content)


def write_json_exclusive(path: Path, value: Any) -> None:
    write_text_exclusive(path, json_text(value))


def write_jsonl_exclusive(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    write_text_exclusive(path, jsonl_text(rows))


def atomic_publish_directory(
    target: Path,
    writer: Callable[[Path], None],
) -> None:
    """Build a complete directory privately, then publish it with one rename."""
    target = target.resolve()
    repo_relative(target, label="publication target")
    base.filesystem_path(target.parent).mkdir(parents=True, exist_ok=True)
    if base.filesystem_path(target).exists():
        raise FileExistsError(f"Refusing to overwrite existing artifact bundle: {target}")
    stage = target.parent / f".v4stg-{uuid.uuid4().hex[:12]}"
    base.filesystem_path(stage).mkdir(exist_ok=False)
    try:
        writer(stage)
        os.rename(base.filesystem_path(stage), base.filesystem_path(target))
    except BaseException:
        if base.filesystem_path(stage).exists():
            require_child(stage, target.parent, label="staging cleanup target")
            shutil.rmtree(base.filesystem_path(stage))
        raise


def contract_body(row: dict[str, Any]) -> dict[str, Any]:
    return {key: row[key] for key in CONTRACT_KEYS}


def effective_review_policy(overlay_path: str, overlay_sha256: str) -> dict[str, Any]:
    policy = v2.effective_review_policy(overlay_path, overlay_sha256)
    policy["binding_schema_version"] = (
        "formal_review_policy_overlay_binding_v4_pid_non_scoring_hardened"
    )
    return policy


def validate_overlay_authoritative(
    path: Path,
    *,
    source_queue: Path,
    expected_count: int,
    required_path: Path | None = None,
) -> tuple[dict[str, Any], str, str]:
    resolved = path.resolve()
    if required_path is not None and resolved != required_path.resolve():
        raise ValueError(
            f"Overlay is not the authoritative source-root artifact: {resolved}"
        )
    overlay = base.read_json(resolved)
    if not isinstance(overlay, dict):
        raise ValueError("Policy overlay is not a JSON object")
    errors: list[str] = []
    if overlay.get("schema_version") != "formal_review_policy_overlay_v1":
        errors.append("unexpected overlay schema_version")
    if overlay.get("status") != "authoritative_for_versioned_re_review_only":
        errors.append("overlay status is not authoritative_for_versioned_re_review_only")

    scope = overlay.get("scope")
    if not isinstance(scope, dict):
        errors.append("overlay scope is missing")
        scope = {}
    expected_source_rel = repo_relative(source_queue, label="source queue")
    expected_score_root_rel = repo_relative(source_queue.parent, label="source score root")
    if scope.get("score_root") != expected_score_root_rel:
        errors.append("overlay scope.score_root mismatch")
    if scope.get("source_queue") != expected_source_rel:
        errors.append("overlay scope.source_queue mismatch")
    live_source_sha = base.sha256_file(source_queue)
    if scope.get("source_queue_sha256") != live_source_sha:
        errors.append("overlay scope.source_queue_sha256 mismatch")
    if scope.get("queue_row_count") != expected_count:
        errors.append("overlay scope.queue_row_count mismatch")
    for key in ("external_api_calls", "source_queue_modified", "source_reviews_modified"):
        if scope.get(key) is not False:
            errors.append(f"overlay scope.{key} must be false")

    terminology = overlay.get("terminology_resolution")
    aliases = terminology.get("semantic_aliases") if isinstance(terminology, dict) else None
    if not isinstance(terminology, dict) or terminology.get("status") != "pass":
        errors.append("overlay terminology resolution is not pass")
    if aliases != {"action": "operation"}:
        errors.append("overlay does not bind action=operation")

    pid = overlay.get("pid_resolution")
    if not isinstance(pid, dict) or pid.get("pid_identity_scored") is not False:
        errors.append("overlay does not set pid_identity_scored=false")
    if not isinstance(pid, dict) or pid.get("superseded_queue_text") != v2.STRICT_PID_TEXT:
        errors.append("overlay does not identify the superseded strict PID sentence")
    if not isinstance(pid, dict) or not str(pid.get("status") or "").startswith(
        "authoritative_policy_resolved"
    ):
        errors.append("overlay PID resolution is not authoritative")

    existing = overlay.get("existing_review_effect")
    required = existing.get("required_resolution") if isinstance(existing, dict) else None
    if not isinstance(existing, dict) or existing.get("retroactive_adoption_allowed") is not False:
        errors.append("overlay must prohibit retroactive adoption")
    if not isinstance(required, dict):
        errors.append("overlay required_resolution is missing")
    else:
        if required.get("scope") != "all 48 model/stage/instance rows":
            errors.append("overlay required_resolution.scope mismatch")
        if "two new independent Codex reviews" not in str(required.get("reviews") or ""):
            errors.append("overlay does not require two new independent reviews")
        if "third review" not in str(required.get("adjudication") or ""):
            errors.append("overlay does not require item-level third review")

    evidence = overlay.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        errors.append("overlay evidence list is missing")
    else:
        seen: set[str] = set()
        for index, item in enumerate(evidence, 1):
            if not isinstance(item, dict):
                errors.append(f"overlay evidence {index} is not an object")
                continue
            evidence_path_text = item.get("path")
            if not isinstance(evidence_path_text, str) or not evidence_path_text:
                errors.append(f"overlay evidence {index} path is missing")
                continue
            if evidence_path_text in seen:
                errors.append(f"duplicate overlay evidence path: {evidence_path_text}")
            seen.add(evidence_path_text)
            try:
                evidence_path = declared_path(
                    evidence_path_text, label=f"overlay evidence {index}"
                )
                if base.sha256_file(evidence_path) != item.get("sha256"):
                    errors.append(f"overlay evidence {index} SHA-256 mismatch")
            except (ValueError, FileNotFoundError) as exc:
                errors.append(str(exc))
    if errors:
        raise ValueError(f"Invalid authoritative formal review policy overlay: {errors}")
    return overlay, repo_relative(resolved, label="policy overlay"), base.sha256_file(resolved)


def validate_queue_rows(
    rows: list[dict[str, Any]],
    *,
    overlay_path: str,
    overlay_sha256: str,
    run_root: Path,
    gold_root: Path,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    expected_policy = effective_review_policy(overlay_path, overlay_sha256)
    expected_policy_sha256 = base.canonical_hash(expected_policy)
    for index, row in enumerate(rows, 1):
        missing = [
            key
            for key in (*CONTRACT_KEYS, "queue_id", "contract_sha256", "review_policy")
            if key not in row
        ]
        if missing:
            raise ValueError(f"Queue row {index} is missing fields: {missing}")
        if row["schema_version"] != SCHEMA_VERSION:
            raise ValueError(f"Queue schema mismatch at row {index}")
        for path_key, expected_root in (("run_json", run_root), ("gold_json", gold_root)):
            resolved = declared_path(row[path_key], label=f"row {index} {path_key}")
            if row[path_key] != repo_relative(resolved, label=path_key):
                raise ValueError(f"Queue {path_key} is not canonical repository-relative at row {index}")
            require_child(resolved, expected_root, label=f"row {index} {path_key}")
        if row["review_policy_overlay_path"] != overlay_path:
            raise ValueError(f"Overlay path mismatch at row {index}")
        if row["review_policy_overlay_sha256"] != overlay_sha256:
            raise ValueError(f"Overlay SHA-256 mismatch at row {index}")
        if row["effective_review_policy_sha256"] != expected_policy_sha256:
            raise ValueError(f"Effective policy SHA-256 mismatch at row {index}")
        if row["review_policy"] != expected_policy:
            raise ValueError(f"Effective review policy mismatch at row {index}")
        if row["review_policy"].get("pid_identity_scored") is not False:
            raise ValueError(f"PID is not explicitly non-scoring at row {index}")
        if row["review_policy"].get("alert_mapping_scored") is not False:
            raise ValueError(f"Hidden alert mapping is not non-scoring at row {index}")
        if row["review_policy"].get("semantic_aliases") != {"action": "operation"}:
            raise ValueError(f"Action/operation alias mismatch at row {index}")
        if v2.STRICT_PID_TEXT in str(row["review_policy"].get("match_semantics") or ""):
            raise ValueError(f"Strict PID sentence remains effective at row {index}")
        expected_hash = base.canonical_hash(contract_body(row))
        if row["contract_sha256"] != expected_hash:
            raise ValueError(f"Queue contract hash mismatch at row {index}")
        expected_id = (
            f"{row['model']}/{row['stage']}/{row['instance_id']}/"
            f"{expected_hash[:16]}"
        )
        if row["queue_id"] != expected_id:
            raise ValueError(f"Queue ID mismatch at row {index}")
        if row.get("candidate_output") is not None:
            if base.candidate_slots(row["candidate_output"]) != row["candidate_slots"]:
                raise ValueError(f"Candidate slot extraction mismatch at row {index}")
        gold_ids = [item["item_id"] for item in row["gold_items"]]
        pair_ids = [item["pair_id"] for item in row["order_pairs"]]
        slot_ids = [item["slot_id"] for item in row["candidate_slots"]]
        if len(gold_ids) != len(set(gold_ids)):
            raise ValueError(f"Duplicate Gold item ID at row {index}")
        if len(pair_ids) != len(set(pair_ids)):
            raise ValueError(f"Duplicate order-pair ID at row {index}")
        if len(slot_ids) != len(set(slot_ids)):
            raise ValueError(f"Duplicate candidate-slot ID at row {index}")
        if len(gold_ids) != row["maxima"]["gold_required_item_count"]:
            raise ValueError(f"Gold denominator mismatch at row {index}")
        if len(pair_ids) != row["maxima"]["gold_order_pair_count"]:
            raise ValueError(f"Order denominator mismatch at row {index}")
        if not {item["kind"] for item in row["candidate_slots"]} <= EXPECTED_SLOT_KINDS:
            raise ValueError(f"Non-canonical candidate slot kind at row {index}")
        if row["queue_id"] in result:
            raise ValueError(f"Duplicate queue ID: {row['queue_id']}")
        result[row["queue_id"]] = row
    return result


def review_template(row: dict[str, Any]) -> dict[str, Any]:
    template = v2.review_template(row)
    template["schema_version"] = SCHEMA_VERSION
    return template


def expected_formal_denominators(rows: list[dict[str, Any]], expected_count: int) -> dict[str, Any]:
    summary = v2.denominator_summary(rows)
    if expected_count == 48:
        expected_groups = {
            f"{model}/{stage}"
            for model in ("gpt-4.1-mini", "gpt-5.4-mini")
            for stage in base.STAGES
        }
        if set(summary["by_model_stage"]) != expected_groups:
            raise ValueError("Unexpected formal model/stage denominator groups")
        expected_values = {
            "case_count": 8,
            "gold_action_required_item_count": 129,
            "critical_evidence_count": 43,
            "gold_order_pair_count": 35,
        }
        for group, values in summary["by_model_stage"].items():
            for name, expected in expected_values.items():
                if values[name] != expected:
                    raise ValueError(
                        f"Formal denominator mismatch for {group}/{name}: "
                        f"{values[name]} != {expected}"
                    )
    return summary


def remap_declared_artifact(
    declared: Path,
    *,
    publication_root: Path,
    artifact_root: Path,
) -> Path:
    require_child(declared, publication_root, label="declared bundle artifact")
    return artifact_root / declared.relative_to(publication_root)


def verify_bundle_paths(
    queue_path: Path,
    manifest_path: Path,
    overlay_file: Path,
    *,
    expected_count: int,
    publication_root: Path | None = None,
) -> dict[str, Any]:
    queue_path = queue_path.resolve()
    manifest_path = manifest_path.resolve()
    artifact_root = queue_path.parent
    manifest = base.read_json(manifest_path)
    if not isinstance(manifest, dict):
        raise ValueError("Bound manifest is not a JSON object")
    if set(manifest) != MANIFEST_FIELDS:
        missing = sorted(MANIFEST_FIELDS - set(manifest))
        extra = sorted(set(manifest) - MANIFEST_FIELDS)
        raise ValueError(f"Manifest is not the closed v4 contract; missing={missing}, extra={extra}")
    if manifest["schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise ValueError("Bound manifest schema mismatch")
    try:
        datetime.fromisoformat(str(manifest["created_at_utc"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Manifest created_at_utc is invalid") from exc

    declared_root = declared_path(manifest["score_root"], label="manifest score_root")
    expected_publication_root = (
        publication_root.resolve() if publication_root is not None else artifact_root
    )
    if declared_root != expected_publication_root:
        raise ValueError("Manifest score_root mismatch")
    declared_queue = declared_path(manifest["queue"], label="manifest queue")
    declared_template = declared_path(
        manifest["review_template"], label="manifest review_template"
    )
    actual_queue = remap_declared_artifact(
        declared_queue,
        publication_root=declared_root,
        artifact_root=artifact_root,
    )
    actual_template = remap_declared_artifact(
        declared_template,
        publication_root=declared_root,
        artifact_root=artifact_root,
    )
    if actual_queue.resolve() != queue_path:
        raise ValueError("Manifest queue path mismatch")
    if manifest["queue_sha256"] != base.sha256_file(actual_queue):
        raise ValueError("Manifest queue SHA-256 mismatch")
    if manifest["review_template_sha256"] != base.sha256_file(actual_template):
        raise ValueError("Manifest review-template SHA-256 mismatch")

    source_queue = declared_path(manifest["source_queue"], label="source queue")
    source_manifest_path = declared_path(
        manifest["source_prepare_manifest"], label="source prepare manifest"
    )
    validation_steps = declared_path(
        manifest["validation_steps"], label="validation steps"
    )
    required_overlay = source_queue.parent / "formal_review_policy_overlay_v1.json"
    _, overlay_path, overlay_sha256 = validate_overlay_authoritative(
        overlay_file,
        source_queue=source_queue,
        expected_count=expected_count,
        required_path=required_overlay,
    )

    path_hash_actuals = {
        "source_prepare_manifest_sha256": source_manifest_path,
        "source_queue_sha256": source_queue,
        "validation_steps_sha256": validation_steps,
        "review_policy_overlay_sha256": overlay_file.resolve(),
        "queue_sha256": actual_queue,
        "review_template_sha256": actual_template,
        "wrapper_sha256": WRAPPER,
        "base_scorer_sha256": BASE_SCORER,
    }
    declared_hash_fields = {key for key in manifest if key.endswith("_sha256")}
    expected_hash_fields = set(PATH_HASH_BINDINGS) | {"effective_review_policy_sha256"}
    if declared_hash_fields != expected_hash_fields:
        raise ValueError("Manifest declared SHA-256 field set mismatch")
    for hash_key, actual_path in path_hash_actuals.items():
        path_key = PATH_HASH_BINDINGS[hash_key]
        declared = declared_path(manifest[path_key], label=path_key)
        expected_declared = (
            declared_queue
            if path_key == "queue"
            else declared_template
            if path_key == "review_template"
            else actual_path.resolve()
        )
        if declared != expected_declared:
            raise ValueError(f"Manifest {path_key} path mismatch")
        if manifest[hash_key] != base.sha256_file(actual_path):
            raise ValueError(f"Manifest {hash_key} mismatch")

    source_rows = base.read_jsonl(source_queue)
    base.validate_queue_rows(source_rows)
    source_manifest = base.read_json(source_manifest_path)
    if Path(str(source_manifest.get("queue"))).resolve() != source_queue:
        raise ValueError("Source prepare manifest queue path mismatch")
    if source_manifest.get("queue_sha256") != base.sha256_file(source_queue):
        raise ValueError("Source prepare manifest queue SHA-256 mismatch")
    if source_manifest.get("eligible_count") != len(source_rows):
        raise ValueError("Source prepare manifest eligible_count mismatch")
    if Path(str(source_manifest.get("validation_steps"))).resolve() != validation_steps:
        raise ValueError("Source prepare manifest validation_steps path mismatch")

    run_root = declared_path(manifest["run_root"], label="run root")
    gold_root = declared_path(manifest["gold_root"], label="Gold root")
    if run_root != source_queue.parent.parent / "runs":
        raise ValueError("Manifest run_root is not the frozen result run root")
    if gold_root != ROOT / "data/current_experiment/gold":
        raise ValueError("Manifest gold_root is not the repository Gold root")
    rows = base.read_jsonl(actual_queue)
    queue = validate_queue_rows(
        rows,
        overlay_path=overlay_path,
        overlay_sha256=overlay_sha256,
        run_root=run_root,
        gold_root=gold_root,
    )
    if len(rows) != expected_count or manifest["eligible_count"] != expected_count:
        raise ValueError("Bound queue or manifest eligible_count mismatch")
    if len(source_rows) != len(rows):
        raise ValueError("Source and bound queue row counts differ")

    source_queue_sha = base.sha256_file(source_queue)
    for index, (source, bound) in enumerate(zip(source_rows, rows), 1):
        if (source["model"], source["stage"], source["instance_id"]) != (
            bound["model"],
            bound["stage"],
            bound["instance_id"],
        ):
            raise ValueError(f"Source/bound order or identity mismatch at row {index}")
        for key in FROZEN_SOURCE_KEYS:
            if source[key] != bound[key]:
                raise ValueError(f"Frozen field changed at row {index}: {key}")
        expected_run = repo_relative(Path(source["run_json"]), label="source run")
        expected_gold = repo_relative(Path(source["gold_json"]), label="source Gold")
        if bound["run_json"] != expected_run:
            raise ValueError(f"Frozen run_json path changed at row {index}")
        if bound["gold_json"] != expected_gold:
            raise ValueError(f"Frozen gold_json path changed at row {index}")
        if bound.get("source_queue_id") != source["queue_id"]:
            raise ValueError(f"Source queue ID provenance mismatch at row {index}")
        if bound.get("source_contract_sha256") != source["contract_sha256"]:
            raise ValueError(f"Source contract provenance mismatch at row {index}")
        if bound.get("source_queue_sha256") != source_queue_sha:
            raise ValueError(f"Source queue provenance mismatch at row {index}")
        if base.sha256_file(declared_path(bound["run_json"], label="run JSON")) != bound["run_sha256"]:
            raise ValueError(f"Run file SHA-256 mismatch at row {index}")
        if base.sha256_file(declared_path(bound["gold_json"], label="Gold JSON")) != bound["gold_sha256"]:
            raise ValueError(f"Gold file SHA-256 mismatch at row {index}")
        if bound["validation_steps_sha256"] != base.sha256_file(validation_steps):
            raise ValueError(f"Validation-steps SHA-256 mismatch at row {index}")

    expected_template_rows = [review_template(row) for row in rows]
    actual_template_rows = base.read_jsonl(actual_template)
    if actual_template_rows != expected_template_rows:
        raise ValueError("Review-template row order or generated content mismatch")
    if manifest["review_template_row_count"] != len(actual_template_rows):
        raise ValueError("Manifest review_template_row_count mismatch")

    denominators = expected_formal_denominators(rows, expected_count)
    exact_claims = {
        "models": sorted({row["model"] for row in rows}),
        "stage_counts": dict(Counter(row["stage"] for row in rows)),
        "denominators": denominators,
        "canonical_slot_kinds": ["subject", "operation", "object"],
        "semantic_aliases": {"action": "operation"},
        "pid_identity_scored": False,
        "hidden_alert_mapping_scored": False,
        "strict_pid_sentence_effective": False,
        "source_artifacts_modified": False,
        "external_api_calls": False,
        "non_overwrite_policy": True,
        "transactional_publication": True,
    }
    for key, expected in exact_claims.items():
        if manifest[key] != expected:
            raise ValueError(f"Manifest {key} claim mismatch")
    expected_policy_hash = base.canonical_hash(
        effective_review_policy(overlay_path, overlay_sha256)
    )
    if manifest["effective_review_policy_sha256"] != expected_policy_hash:
        raise ValueError("Manifest effective_review_policy_sha256 mismatch")

    content_counts = {
        "gold_items": sum(len(row["gold_items"]) for row in rows),
        "order_pairs": sum(len(row["order_pairs"]) for row in rows),
        "candidate_slots": sum(len(row["candidate_slots"]) for row in rows),
    }
    return {
        "schema_version": SELF_VALIDATION_SCHEMA_VERSION,
        "status": "pass",
        "queue_row_count": len(rows),
        "queue_sha256": base.sha256_file(actual_queue),
        "manifest_sha256": base.sha256_file(manifest_path),
        "review_template_sha256": base.sha256_file(actual_template),
        "overlay_path": overlay_path,
        "overlay_sha256": overlay_sha256,
        "source_queue_sha256": source_queue_sha,
        "run_file_paths_and_hashes_verified": len(rows),
        "gold_file_paths_and_hashes_verified": len(rows),
        "manifest_closed_contract_verified": True,
        "all_declared_hashes_verified": True,
        "denominators": denominators,
        "content_counts": content_counts,
        "pid_identity_scored": False,
        "hidden_alert_mapping_scored": False,
        "action_aliases_operation": True,
        "external_api_calls": False,
    }


def verify_bundle_attestations(
    score_root: Path,
    manifest_path: Path,
    report: dict[str, Any],
) -> None:
    self_path = score_root / "queue_self_validation_v4.json"
    completion_path = score_root / "queue_bundle_completion_manifest_v4.json"
    self_report = base.read_json(self_path)
    completion = base.read_json(completion_path)
    if self_report != report:
        raise ValueError("Stored queue self-validation does not equal live verification")
    expected_completion = {
        "schema_version": BUNDLE_COMPLETION_SCHEMA_VERSION,
        "complete": True,
        "queue_manifest": repo_relative(manifest_path.resolve(), label="queue manifest"),
        "queue_manifest_sha256": report["manifest_sha256"],
        "queue_self_validation": repo_relative(self_path, label="self-validation"),
        "queue_self_validation_sha256": base.sha256_file(self_path),
        "wrapper_sha256": base.sha256_file(WRAPPER),
        "external_api_calls": False,
    }
    if completion != expected_completion:
        raise ValueError("Queue bundle completion manifest mismatch")


def bind_overlay(args: argparse.Namespace) -> None:
    queue_name = validate_safe_basename(args.queue_name, label="queue-name")
    template_name = validate_safe_basename(args.template_name, label="template-name")
    manifest_name = validate_safe_basename(args.manifest_name, label="manifest-name")
    if len({queue_name, template_name, manifest_name}) != 3:
        raise ValueError("queue-name, template-name, and manifest-name must be distinct")
    source_queue = args.source_queue.resolve()
    source_manifest_path = args.source_manifest.resolve()
    score_root = args.score_root.resolve()
    source_rows = base.read_jsonl(source_queue)
    base.validate_queue_rows(source_rows)
    if len(source_rows) != args.expected_count:
        raise ValueError(
            f"Source queue has {len(source_rows)} rows, expected {args.expected_count}"
        )
    source_manifest = base.read_json(source_manifest_path)
    if Path(str(source_manifest.get("queue"))).resolve() != source_queue:
        raise ValueError("Source manifest queue path mismatch")
    if source_manifest.get("queue_sha256") != base.sha256_file(source_queue):
        raise ValueError("Source manifest queue SHA-256 mismatch")
    if source_manifest.get("eligible_count") != len(source_rows):
        raise ValueError("Source manifest eligible_count mismatch")
    validation_steps = Path(str(source_manifest["validation_steps"])).resolve()
    required_overlay = source_queue.parent / "formal_review_policy_overlay_v1.json"
    _, overlay_path, overlay_sha = validate_overlay_authoritative(
        args.overlay,
        source_queue=source_queue,
        expected_count=args.expected_count,
        required_path=required_overlay,
    )
    run_root = source_queue.parent.parent / "runs"
    gold_root = ROOT / "data/current_experiment/gold"
    policy = effective_review_policy(overlay_path, overlay_sha)
    policy_sha = base.canonical_hash(policy)
    source_queue_sha = base.sha256_file(source_queue)
    bound_rows: list[dict[str, Any]] = []
    for source in source_rows:
        run_json = Path(source["run_json"]).resolve()
        gold_json = Path(source["gold_json"]).resolve()
        require_child(run_json, run_root, label="source run JSON")
        require_child(gold_json, gold_root, label="source Gold JSON")
        contract = {
            **{key: source[key] for key in base.CONTRACT_KEYS},
            "schema_version": SCHEMA_VERSION,
            "run_json": repo_relative(run_json, label="run JSON"),
            "gold_json": repo_relative(gold_json, label="Gold JSON"),
            "review_policy_overlay_path": overlay_path,
            "review_policy_overlay_sha256": overlay_sha,
            "effective_review_policy_sha256": policy_sha,
        }
        contract_sha = base.canonical_hash(contract)
        bound_rows.append(
            {
                **source,
                **contract,
                "queue_id": (
                    f"{source['model']}/{source['stage']}/{source['instance_id']}/"
                    f"{contract_sha[:16]}"
                ),
                "contract_sha256": contract_sha,
                "source_queue_id": source["queue_id"],
                "source_contract_sha256": source["contract_sha256"],
                "source_queue_sha256": source_queue_sha,
                "review_policy": policy,
            }
        )

    def writer(stage: Path) -> None:
        queue_path = stage_destination(stage, queue_name, label="queue-name")
        template_path = stage_destination(stage, template_name, label="template-name")
        manifest_path = stage_destination(stage, manifest_name, label="manifest-name")
        write_jsonl_exclusive(queue_path, bound_rows)
        write_jsonl_exclusive(template_path, (review_template(row) for row in bound_rows))
        manifest = {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "created_at_utc": base.utc_now(),
            "score_root": repo_relative(score_root, label="score root"),
            "source_prepare_manifest": repo_relative(
                source_manifest_path, label="source prepare manifest"
            ),
            "source_prepare_manifest_sha256": base.sha256_file(source_manifest_path),
            "source_queue": repo_relative(source_queue, label="source queue"),
            "source_queue_sha256": source_queue_sha,
            "validation_steps": repo_relative(validation_steps, label="validation steps"),
            "validation_steps_sha256": base.sha256_file(validation_steps),
            "review_policy_overlay_path": overlay_path,
            "review_policy_overlay_sha256": overlay_sha,
            "effective_review_policy_sha256": policy_sha,
            "queue": repo_relative(score_root / queue_name, label="queue"),
            "queue_sha256": base.sha256_file(queue_path),
            "review_template": repo_relative(
                score_root / template_name, label="review template"
            ),
            "review_template_sha256": base.sha256_file(template_path),
            "review_template_row_count": len(bound_rows),
            "wrapper_path": repo_relative(WRAPPER, label="wrapper"),
            "wrapper_sha256": base.sha256_file(WRAPPER),
            "base_scorer_path": repo_relative(BASE_SCORER, label="base scorer"),
            "base_scorer_sha256": base.sha256_file(BASE_SCORER),
            "run_root": repo_relative(run_root, label="run root"),
            "gold_root": repo_relative(gold_root, label="Gold root"),
            "eligible_count": len(bound_rows),
            "models": sorted({row["model"] for row in bound_rows}),
            "stage_counts": dict(Counter(row["stage"] for row in bound_rows)),
            "denominators": expected_formal_denominators(
                bound_rows, args.expected_count
            ),
            "canonical_slot_kinds": ["subject", "operation", "object"],
            "semantic_aliases": {"action": "operation"},
            "pid_identity_scored": False,
            "hidden_alert_mapping_scored": False,
            "strict_pid_sentence_effective": False,
            "source_artifacts_modified": False,
            "external_api_calls": False,
            "non_overwrite_policy": True,
            "transactional_publication": True,
        }
        write_json_exclusive(manifest_path, manifest)
        report = verify_bundle_paths(
            queue_path,
            manifest_path,
            args.overlay.resolve(),
            expected_count=args.expected_count,
            publication_root=score_root,
        )
        self_path = stage_destination(
            stage, "queue_self_validation_v4.json", label="queue self-validation"
        )
        write_json_exclusive(self_path, report)
        completion = {
            "schema_version": BUNDLE_COMPLETION_SCHEMA_VERSION,
            "complete": True,
            "queue_manifest": repo_relative(score_root / manifest_name),
            "queue_manifest_sha256": report["manifest_sha256"],
            "queue_self_validation": repo_relative(
                score_root / self_path.name, label="self-validation"
            ),
            "queue_self_validation_sha256": base.sha256_file(self_path),
            "wrapper_sha256": base.sha256_file(WRAPPER),
            "external_api_calls": False,
        }
        write_json_exclusive(
            stage_destination(
                stage,
                "queue_bundle_completion_manifest_v4.json",
                label="queue bundle completion manifest",
            ),
            completion,
        )

    atomic_publish_directory(score_root, writer)
    print(
        f"Bound {len(bound_rows)} hardened rows; "
        f"score_root={score_root}; queue_sha256="
        f"{base.sha256_file(score_root / queue_name)}"
    )


def verify_queue(args: argparse.Namespace) -> None:
    report = verify_bundle_paths(
        args.queue.resolve(),
        args.manifest.resolve(),
        args.overlay.resolve(),
        expected_count=args.expected_count,
    )
    verify_bundle_attestations(
        args.queue.resolve().parent,
        args.manifest.resolve(),
        report,
    )
    if args.report:
        write_json_exclusive(args.report.resolve(), report)
    print(
        f"PASS: {report['queue_row_count']} hardened rows; "
        f"queue_sha256={report['queue_sha256']}; "
        f"manifest_sha256={report['manifest_sha256']}"
    )


def validate_review_row(
    row: dict[str, Any],
    queue_row: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[str]]:
    adapted = dict(row)
    adapted["schema_version"] = v2.SCHEMA_VERSION
    normalized, errors = v2.validate_review_row(adapted, queue_row)
    if normalized is None or errors:
        return None, errors
    normalized["schema_version"] = SCHEMA_VERSION
    normalized["decision_sha256"] = base.canonical_hash(
        base.decision_fingerprint(normalized)
    )
    return normalized, []


def jsonl_rows_from_bytes(raw_bytes: bytes, *, source: Path) -> list[dict[str, Any]]:
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{source} is not valid UTF-8") from exc
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{source}:{line_number}: JSONL row is not an object")
        rows.append(value)
    return rows


def read_review_snapshot(
    path: Path,
    queue: dict[str, dict[str, Any]],
    *,
    allow_subset: bool,
    role: str,
) -> ReviewSnapshot:
    """Single-read, validate, hash, and retain one exact reviewer input."""

    path = path.resolve()
    path_relative = repo_relative(path, label=f"{role} input")
    with base.filesystem_path(path).open("rb") as handle:
        raw_bytes = handle.read()
    raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    rows = jsonl_rows_from_bytes(raw_bytes, source=path)
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        queue_id = str(row.get("queue_id") or "")
        if queue_id in result:
            raise ValueError(f"Duplicate queue_id in {path}: {queue_id}")
        if queue_id not in queue:
            raise ValueError(f"Unknown queue_id in {path}: {queue_id}")
        normalized, errors = validate_review_row(row, queue[queue_id])
        if normalized is None:
            raise ValueError(f"{path} is invalid for {queue_id}: {errors}")
        expected_hash = base.canonical_hash(base.decision_fingerprint(normalized))
        if row.get("decision_sha256") != expected_hash:
            raise ValueError(f"decision_sha256 mismatch in {path}: {queue_id}")
        result[queue_id] = normalized
    if not allow_subset and set(result) != set(queue):
        raise ValueError(f"{path} queue ID set does not match the full queue")
    reviewer_ids = sorted({row["reviewer_id"] for row in result.values()})
    if len(reviewer_ids) != 1:
        raise ValueError(
            f"{role} input must contain exactly one reviewer_id: {reviewer_ids}"
        )
    return ReviewSnapshot(
        role=role,
        source_path=path,
        source_path_repo_relative=path_relative,
        raw_bytes=raw_bytes,
        raw_sha256=raw_sha256,
        reviewer_id=reviewer_ids[0],
        rows_by_queue=result,
    )


def validated_review_map(
    path: Path,
    queue: dict[str, dict[str, Any]],
    *,
    allow_subset: bool,
) -> dict[str, dict[str, Any]]:
    """Compatibility helper; formal publication uses retained ReviewSnapshot."""

    return read_review_snapshot(
        path,
        queue,
        allow_subset=allow_subset,
        role="review",
    ).rows_by_queue


def load_verified_queue(args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, Any]]:
    report = verify_bundle_paths(
        args.queue.resolve(),
        args.manifest.resolve(),
        args.overlay.resolve(),
        expected_count=args.expected_count,
    )
    manifest = base.read_json(args.manifest.resolve())
    rows = base.read_jsonl(args.queue.resolve())
    queue = validate_queue_rows(
        rows,
        overlay_path=manifest["review_policy_overlay_path"],
        overlay_sha256=manifest["review_policy_overlay_sha256"],
        run_root=declared_path(manifest["run_root"], label="run root"),
        gold_root=declared_path(manifest["gold_root"], label="Gold root"),
    )
    return rows, queue, report


def validate_reviews(args: argparse.Namespace) -> None:
    _, queue, report = load_verified_queue(args)
    snapshot = read_review_snapshot(
        args.reviewer_jsonl.resolve(),
        queue,
        allow_subset=args.review_name == "review3",
        role=args.review_name,
    )
    review_map = snapshot.rows_by_queue
    if args.review_name != "review3" and len(review_map) != args.expected_count:
        raise ValueError("Base review must cover all formal rows")
    target = (
        args.score_root.resolve()
        / "validated_reviews_v4_pid_non_scoring_hardened"
        / args.review_name
    )

    def writer(stage: Path) -> None:
        output = stage_destination(stage, "review.jsonl", label="validated review")
        retained_input = stage_destination(
            stage,
            f"{args.review_name}_input_snapshot.jsonl",
            label="retained input snapshot",
        )
        write_bytes_exclusive(retained_input, snapshot.raw_bytes)
        ordered = [review_map[key] for key in queue if key in review_map]
        write_jsonl_exclusive(output, ordered)
        write_json_exclusive(
            stage_destination(
                stage, "validation_manifest.json", label="validation manifest"
            ),
            {
                "schema_version": "codex_manual_review_validation_manifest_v4",
                "valid": True,
                "review_name": args.review_name,
                "reviewer_id": snapshot.reviewer_id,
                "input_review": snapshot.source_path_repo_relative,
                "input_review_sha256": snapshot.raw_sha256,
                "retained_input_snapshot": repo_relative(
                    target / retained_input.name, label="retained input snapshot"
                ),
                "retained_input_snapshot_sha256": hashlib.sha256(
                    snapshot.raw_bytes
                ).hexdigest(),
                "validated_review": repo_relative(
                    target / "review.jsonl", label="validated review"
                ),
                "validated_review_sha256": base.sha256_file(output),
                "queue_manifest_sha256": report["manifest_sha256"],
                "row_count": len(ordered),
                "external_api_calls": False,
                "transactional_publication": True,
            },
        )

    atomic_publish_directory(target, writer)
    print(f"Validated {len(review_map)} hardened rows atomically: {target}")


def build_finalization(
    queue_rows: list[dict[str, Any]],
    queue: dict[str, dict[str, Any]],
    review1: dict[str, dict[str, Any]],
    review2: dict[str, dict[str, Any]],
    review3: dict[str, dict[str, Any]],
    *,
    overlay_path: str,
    overlay_sha256: str,
    expected_count: int,
) -> dict[str, Any]:
    reviewer_sets = [
        {row["reviewer_id"] for row in review1.values()},
        {row["reviewer_id"] for row in review2.values()},
    ]
    if any(len(ids) != 1 for ids in reviewer_sets):
        raise ValueError("Each base review must have one reviewer_id")
    if next(iter(reviewer_sets[0])) == next(iter(reviewer_sets[1])):
        raise ValueError("review1 and review2 must have different reviewer IDs")
    review3_ids = {row["reviewer_id"] for row in review3.values()}
    if review3 and len(review3_ids) != 1:
        raise ValueError(
            f"review3 must have exactly one reviewer_id: {sorted(review3_ids)}"
        )
    if review3 and next(iter(review3_ids)) in {
        next(iter(reviewer_sets[0])),
        next(iter(reviewer_sets[1])),
    }:
        raise ValueError("review3 reviewer must be independent from both base reviewers")
    comparisons: list[dict[str, Any]] = []
    adopted: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    adjudicated: list[dict[str, Any]] = []
    for queue_id, queue_row in queue.items():
        first, second = review1[queue_id], review2[queue_id]
        exact = base.decision_fingerprint(first) == base.decision_fingerprint(second)
        comparison = {
            "queue_id": queue_id,
            "model": queue_row["model"],
            "stage": queue_row["stage"],
            "instance_id": queue_row["instance_id"],
            "review_policy_overlay_path": overlay_path,
            "review_policy_overlay_sha256": overlay_sha256,
            "review1_reviewer_id": first["reviewer_id"],
            "review2_reviewer_id": second["reviewer_id"],
            "review1_decision_sha256": first["decision_sha256"],
            "review2_decision_sha256": second["decision_sha256"],
            "item_level_exact_match": exact,
            "adopted": False,
            "adoption_route": None,
        }
        selected: dict[str, Any] | None = first if exact else None
        conservative_count = 0
        if exact:
            comparison["adopted"] = True
            comparison["adoption_route"] = "exact_two_review_match"
        elif queue_id in review3:
            third = review3[queue_id]
            if third["reviewer_id"] in {
                first["reviewer_id"],
                second["reviewer_id"],
            }:
                raise ValueError(f"Third reviewer is not independent for {queue_id}")
            selected, conservative_count = base.adjudicate_reviews(first, second, third)
            selected["schema_version"] = SCHEMA_VERSION
            selected["review_policy_overlay_path"] = overlay_path
            selected["review_policy_overlay_sha256"] = overlay_sha256
            comparison.update(
                {
                    "adopted": True,
                    "adoption_route": "third_review_2_of_3",
                    "review3_reviewer_id": third["reviewer_id"],
                    "review3_decision_sha256": third["decision_sha256"],
                    "conservative_fallback_item_count": conservative_count,
                }
            )
        if selected is None:
            conflicts.append(
                {
                    **comparison,
                    "reason": "item_level_mismatch_requires_independent_review3",
                }
            )
        else:
            decisions = base.decision_fingerprint(selected)
            adopted_row = {
                **comparison,
                "totals": base.totals_from_review(selected, queue_row),
                "adopted_decisions": decisions,
                "adopted_decision_sha256": base.canonical_hash(decisions),
                "contract_sha256": queue_row["contract_sha256"],
                "run_sha256": queue_row["run_sha256"],
                "gold_sha256": queue_row["gold_sha256"],
                "queue_contract": contract_body(queue_row),
            }
            adopted.append(adopted_row)
            if comparison["adoption_route"] == "third_review_2_of_3":
                adjudicated.append(adopted_row)
        comparisons.append(comparison)
    if conflicts or len(adopted) < expected_count or len(queue) != expected_count:
        raise IncompleteFinalization(
            f"Formal finalization incomplete: adopted={len(adopted)}/"
            f"{expected_count}, conflicts={len(conflicts)}"
        )
    aggregate = base.aggregate(adopted)
    aggregate.update(
        {
            "schema_version": SCHEMA_VERSION,
            "review_policy_overlay_path": overlay_path,
            "review_policy_overlay_sha256": overlay_sha256,
            "pid_identity_scored": False,
            "hidden_alert_mapping_scored": False,
            "expected_queue_count": expected_count,
            "adopted_run_count": len(adopted),
            "excluded_conflict_count": 0,
            "complete": True,
        }
    )
    return {
        "comparisons": comparisons,
        "adopted": adopted,
        "adjudicated": adjudicated,
        "aggregate": aggregate,
        "queue_rows": queue_rows,
    }


def publish_finalization(
    target: Path,
    data: dict[str, Any],
    *,
    review_snapshots: tuple[ReviewSnapshot, ...],
    bundle_manifest: dict[str, Any],
    args: argparse.Namespace,
    report: dict[str, Any],
) -> None:
    expected_roles = ["review1", "review2"] + (
        ["review3"] if args.review3 else []
    )
    if [snapshot.role for snapshot in review_snapshots] != expected_roles:
        raise ValueError("Review snapshot roles do not match finalization inputs")
    if len({snapshot.reviewer_id for snapshot in review_snapshots[:2]}) != 2:
        raise ValueError("Base review snapshots must have independent reviewer IDs")
    if len(review_snapshots) == 3:
        if review_snapshots[2].reviewer_id in {
            review_snapshots[0].reviewer_id,
            review_snapshots[1].reviewer_id,
        }:
            raise ValueError("review3 snapshot reviewer is not independent")

    def writer(stage: Path) -> None:
        outputs = {
            "comparisons.jsonl": jsonl_text(data["comparisons"]),
            "adopted_reviews.jsonl": jsonl_text(data["adopted"]),
            "resolved_by_third_review.jsonl": jsonl_text(data["adjudicated"]),
            "formal_aggregate.json": json_text(data["aggregate"]),
        }
        for name, text in outputs.items():
            write_text_exclusive(
                stage_destination(stage, name, label=f"formal output {name}"),
                text,
            )
        output_files = [
            {
                "path": name,
                "sha256": base.sha256_file(
                    stage_destination(stage, name, label=f"formal output {name}")
                ),
            }
            for name in sorted(outputs)
        ]
        review_inputs: list[dict[str, Any]] = []
        for snapshot in review_snapshots:
            snapshot_name = f"{snapshot.role}_input_snapshot.jsonl"
            snapshot_path = stage_destination(
                stage,
                snapshot_name,
                label=f"{snapshot.role} retained input snapshot",
            )
            write_bytes_exclusive(snapshot_path, snapshot.raw_bytes)
            retained_sha256 = base.sha256_file(snapshot_path)
            if retained_sha256 != snapshot.raw_sha256:
                raise AssertionError(
                    f"{snapshot.role} retained snapshot bytes changed during staging"
                )
            review_inputs.append(
                {
                    "role": snapshot.role,
                    "path": snapshot.source_path_repo_relative,
                    "sha256": snapshot.raw_sha256,
                    "retained_snapshot": repo_relative(
                        target / snapshot_name,
                        label=f"{snapshot.role} retained input snapshot",
                    ),
                    "retained_snapshot_sha256": retained_sha256,
                    "reviewer_id": snapshot.reviewer_id,
                    "validated_row_count": len(snapshot.rows_by_queue),
                    "validated_decision_set_sha256": snapshot.decision_set_sha256,
                }
            )
        finalization_manifest = {
            "schema_version": FINALIZATION_SCHEMA_VERSION,
            "created_at_utc": base.utc_now(),
            "complete": True,
            "adopted_run_count": len(data["adopted"]),
            "expected_queue_count": args.expected_count,
            "conflict_count": 0,
            "adjudicated_count": len(data["adjudicated"]),
            "wrapper_path": repo_relative(WRAPPER, label="wrapper"),
            "wrapper_sha256": base.sha256_file(WRAPPER),
            "base_scorer_path": repo_relative(BASE_SCORER, label="base scorer"),
            "base_scorer_sha256": base.sha256_file(BASE_SCORER),
            "queue": bundle_manifest["queue"],
            "queue_sha256": report["queue_sha256"],
            "queue_manifest": repo_relative(args.manifest.resolve(), label="queue manifest"),
            "queue_manifest_sha256": report["manifest_sha256"],
            "review_template": bundle_manifest["review_template"],
            "review_template_sha256": report["review_template_sha256"],
            "review_policy_overlay_path": bundle_manifest[
                "review_policy_overlay_path"
            ],
            "review_policy_overlay_sha256": bundle_manifest[
                "review_policy_overlay_sha256"
            ],
            "review_inputs": review_inputs,
            "review3_reviewer_id": (
                review_snapshots[2].reviewer_id
                if len(review_snapshots) == 3
                else None
            ),
            "review3_adjudication_bindings": [
                {
                    "queue_id": row["queue_id"],
                    "reviewer_id": row["review3_reviewer_id"],
                    "decision_sha256": row["review3_decision_sha256"],
                }
                for row in data["adjudicated"]
            ],
            "output_files": output_files,
            "pid_identity_scored": False,
            "hidden_alert_mapping_scored": False,
            "external_api_calls": False,
            "transactional_publication": True,
        }
        write_json_exclusive(
            stage_destination(
                stage, "finalization_manifest.json", label="finalization manifest"
            ),
            finalization_manifest,
        )

    atomic_publish_directory(target, writer)


def finalize(args: argparse.Namespace) -> None:
    queue_rows, queue, report = load_verified_queue(args)
    review1_snapshot = read_review_snapshot(
        args.review1.resolve(), queue, allow_subset=False, role="review1"
    )
    review2_snapshot = read_review_snapshot(
        args.review2.resolve(), queue, allow_subset=False, role="review2"
    )
    review3_snapshot = (
        read_review_snapshot(
            args.review3.resolve(), queue, allow_subset=True, role="review3"
        )
        if args.review3
        else None
    )
    review1 = review1_snapshot.rows_by_queue
    review2 = review2_snapshot.rows_by_queue
    review3 = review3_snapshot.rows_by_queue if review3_snapshot else {}
    manifest = base.read_json(args.manifest.resolve())
    data = build_finalization(
        queue_rows,
        queue,
        review1,
        review2,
        review3,
        overlay_path=manifest["review_policy_overlay_path"],
        overlay_sha256=manifest["review_policy_overlay_sha256"],
        expected_count=args.expected_count,
    )
    target = args.score_root.resolve() / "formal_outputs_v4_pid_non_scoring_hardened"
    snapshots = (review1_snapshot, review2_snapshot) + (
        (review3_snapshot,) if review3_snapshot else ()
    )
    publish_finalization(
        target,
        data,
        review_snapshots=snapshots,
        bundle_manifest=manifest,
        args=args,
        report=report,
    )
    print(
        f"Formal hardened scoring complete: {len(data['adopted'])}/"
        f"{args.expected_count}; output={target}"
    )


def synthetic_review_rows(
    queue_rows: list[dict[str, Any]],
    reviewer_id: str,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for queue_row in queue_rows:
        row = review_template(queue_row)
        row["reviewer_id"] = reviewer_id
        for item in row["gold_items"]:
            item["score"] = 0
            item["reason_ja"] = "synthetic deterministic zero"
        for pair in row["order_pairs"]:
            pair["score"] = 0
            pair["reason_ja"] = "synthetic deterministic zero"
        for slot in row["candidate_slots"]:
            slot["include_in_denominator"] = 1
            slot["aligned_gold_step_id"] = None
            slot["matched_gold_item_id"] = None
            slot["is_true_positive"] = 0
            slot["false_positive_type"] = "unsupported"
            slot["reason_ja"] = "synthetic deterministic zero"
        normalized, errors = validate_review_row(row, queue_row)
        if normalized is None:
            raise AssertionError(errors)
        result.append(normalized)
    return result


def run_self_test(args: argparse.Namespace) -> None:
    queue_rows, queue, report = load_verified_queue(args)
    score_root = args.score_root.resolve()
    output_name = validate_safe_basename(args.output_name, label="output-name")
    manifest_live = base.read_json(args.manifest.resolve())
    test_results: list[dict[str, Any]] = []

    def passed(test_id: str, finding: str, detail: str) -> None:
        test_results.append(
            {"test_id": test_id, "finding": finding, "status": "PASS", "detail": detail}
        )

    def expect_reject(
        test_id: str,
        finding: str,
        callback: Callable[[], None],
        detail: str,
    ) -> None:
        try:
            callback()
        except (ValueError, FileNotFoundError, FileExistsError, json.JSONDecodeError):
            passed(test_id, finding, detail)
            return
        raise AssertionError(f"{test_id} unexpectedly accepted tampering")

    with tempfile.TemporaryDirectory(prefix=".v4t-", dir=ROOT) as temp_name:
        temp_root = Path(temp_name)
        clone = temp_root / "bundle"
        base.filesystem_path(clone).mkdir()
        queue_clone = clone / args.queue.name
        template_clone = clone / Path(manifest_live["review_template"]).name
        shutil.copyfile(
            base.filesystem_path(args.queue.resolve()),
            base.filesystem_path(queue_clone),
        )
        shutil.copyfile(
            base.filesystem_path(
                declared_path(manifest_live["review_template"], label="review template")
            ),
            base.filesystem_path(template_clone),
        )
        baseline_manifest = dict(manifest_live)
        baseline_manifest["score_root"] = repo_relative(clone)
        baseline_manifest["queue"] = repo_relative(queue_clone)
        baseline_manifest["review_template"] = repo_relative(template_clone)
        manifest_clone = clone / args.manifest.name
        write_json_exclusive(manifest_clone, baseline_manifest)
        verify_bundle_paths(
            queue_clone,
            manifest_clone,
            args.overlay.resolve(),
            expected_count=args.expected_count,
        )
        passed("BASELINE", "CQ-001..CQ-007", "cloned closed bundle verifies")

        def manifest_case(name: str, mutate: Callable[[dict[str, Any]], None]) -> None:
            candidate = dict(baseline_manifest)
            mutate(candidate)
            candidate_path = temp_root / f"{name}.json"
            write_json_exclusive(candidate_path, candidate)
            expect_reject(
                name,
                "CQ-001",
                lambda: verify_bundle_paths(
                    queue_clone,
                    candidate_path,
                    args.overlay.resolve(),
                    expected_count=args.expected_count,
                ),
                "closed manifest tamper rejected",
            )

        manifest_case("CQ001_TEMPLATE_PATH", lambda item: item.__setitem__("review_template", repo_relative(temp_root / "missing.jsonl")))
        manifest_case("CQ001_TEMPLATE_HASH", lambda item: item.__setitem__("review_template_sha256", "0" * 64))
        manifest_case("CQ001_QUEUE_PATH", lambda item: item.__setitem__("queue", repo_relative(temp_root / "missing_queue.jsonl")))
        manifest_case("CQ001_QUEUE_HASH", lambda item: item.__setitem__("queue_sha256", "0" * 64))
        manifest_case("CQ001_MODELS", lambda item: item.__setitem__("models", ["wrong"]))
        manifest_case("CQ001_STAGE_COUNTS", lambda item: item.__setitem__("stage_counts", {"stage1": 48}))
        manifest_case("CQ001_SCORE_ROOT", lambda item: item.__setitem__("score_root", repo_relative(temp_root)))
        manifest_case("CQ001_FLAGS", lambda item: item.update({"source_artifacts_modified": True, "external_api_calls": True, "non_overwrite_policy": False}))
        manifest_case("CQ001_DECLARED_HASH", lambda item: item.__setitem__("wrapper_sha256", "0" * 64))

        template_bad = clone / "template_bad.jsonl"
        bad_templates = base.read_jsonl(template_clone)
        bad_templates[0]["reviewer_id"] = "tampered"
        write_jsonl_exclusive(template_bad, bad_templates)
        candidate = dict(baseline_manifest)
        candidate["review_template"] = repo_relative(template_bad)
        candidate["review_template_sha256"] = base.sha256_file(template_bad)
        candidate_path = temp_root / "CQ001_TEMPLATE_CONTENT.json"
        write_json_exclusive(candidate_path, candidate)
        expect_reject(
            "CQ001_TEMPLATE_CONTENT",
            "CQ-001",
            lambda: verify_bundle_paths(
                queue_clone,
                candidate_path,
                args.overlay.resolve(),
                expected_count=args.expected_count,
            ),
            "hash-consistent wrong generated template rejected",
        )

        relocated = temp_root / "relocated_run.json"
        first_run = declared_path(queue_rows[0]["run_json"], label="run JSON")
        shutil.copyfile(
            base.filesystem_path(first_run), base.filesystem_path(relocated)
        )
        changed_rows = json.loads(json.dumps(queue_rows, ensure_ascii=False))
        changed_rows[0]["run_json"] = repo_relative(relocated)
        changed_contract = contract_body(changed_rows[0])
        changed_rows[0]["contract_sha256"] = base.canonical_hash(changed_contract)
        changed_rows[0]["queue_id"] = (
            f"{changed_rows[0]['model']}/{changed_rows[0]['stage']}/"
            f"{changed_rows[0]['instance_id']}/"
            f"{changed_rows[0]['contract_sha256'][:16]}"
        )
        relocated_queue = temp_root / "relocated_queue.jsonl"
        relocated_template = temp_root / "relocated_template.jsonl"
        write_jsonl_exclusive(relocated_queue, changed_rows)
        write_jsonl_exclusive(
            relocated_template, (review_template(row) for row in changed_rows)
        )
        relocated_manifest = dict(baseline_manifest)
        relocated_manifest.update(
            {
                "score_root": repo_relative(temp_root),
                "queue": repo_relative(relocated_queue),
                "queue_sha256": base.sha256_file(relocated_queue),
                "review_template": repo_relative(relocated_template),
                "review_template_sha256": base.sha256_file(relocated_template),
            }
        )
        relocated_manifest_path = temp_root / "relocated_manifest.json"
        write_json_exclusive(relocated_manifest_path, relocated_manifest)
        expect_reject(
            "CQ002_SAME_BYTES_DIFFERENT_PATH",
            "CQ-002",
            lambda: verify_bundle_paths(
                relocated_queue,
                relocated_manifest_path,
                args.overlay.resolve(),
                expected_count=args.expected_count,
            ),
            "same run bytes at a different path rejected by frozen path contract",
        )

        overlay_live = base.read_json(args.overlay.resolve())
        for test_id, mutator in (
            ("CQ003_STATUS", lambda item: item.__setitem__("status", "draft")),
            (
                "CQ003_SCOPE",
                lambda item: item["scope"].update(
                    {"source_queue_sha256": "0" * 64, "queue_row_count": 1}
                ),
            ),
            (
                "CQ003_EVIDENCE",
                lambda item: item["evidence"][0].__setitem__("sha256", "0" * 64),
            ),
        ):
            overlay_copy = json.loads(json.dumps(overlay_live, ensure_ascii=False))
            mutator(overlay_copy)
            overlay_path = temp_root / f"{test_id}.json"
            write_json_exclusive(overlay_path, overlay_copy)
            expect_reject(
                test_id,
                "CQ-003",
                lambda p=overlay_path: validate_overlay_authoritative(
                    p,
                    source_queue=declared_path(
                        manifest_live["source_queue"], label="source queue"
                    ),
                    expected_count=args.expected_count,
                    required_path=p,
                ),
                "non-authoritative overlay status/scope/evidence rejected",
            )

        review1_rows = synthetic_review_rows(queue_rows, "synthetic-reviewer-1")
        review2_rows = synthetic_review_rows(queue_rows, "synthetic-reviewer-2")
        review1_path = temp_root / "review1.jsonl"
        review2_path = temp_root / "review2.jsonl"
        write_jsonl_exclusive(review1_path, review1_rows)
        write_jsonl_exclusive(review2_path, review2_rows)
        review1_snapshot = read_review_snapshot(
            review1_path, queue, allow_subset=False, role="review1"
        )
        review2_snapshot = read_review_snapshot(
            review2_path, queue, allow_subset=False, role="review2"
        )
        review1 = review1_snapshot.rows_by_queue
        review2 = review2_snapshot.rows_by_queue
        mismatch_rows = json.loads(json.dumps(review2_rows, ensure_ascii=False))
        mismatch_rows[0]["gold_items"][0]["score"] = 1
        mismatch_rows[0]["decision_sha256"] = base.canonical_hash(
            base.decision_fingerprint(mismatch_rows[0])
        )
        mismatch_path = temp_root / "review2_mismatch.jsonl"
        write_jsonl_exclusive(mismatch_path, mismatch_rows)
        mismatch_snapshot = read_review_snapshot(
            mismatch_path, queue, allow_subset=False, role="review2"
        )
        mismatch = mismatch_snapshot.rows_by_queue
        incomplete_target = temp_root / "incomplete_formal_outputs"
        expect_reject(
            "CQ004_INCOMPLETE_NON_SUCCESS",
            "CQ-004",
            lambda: build_finalization(
                queue_rows,
                queue,
                review1,
                mismatch,
                {},
                overlay_path=manifest_live["review_policy_overlay_path"],
                overlay_sha256=manifest_live["review_policy_overlay_sha256"],
                expected_count=args.expected_count,
            ),
            "one unresolved conflict raises IncompleteFinalization/exit 3 before output",
        )
        if incomplete_target.exists():
            raise AssertionError("incomplete finalization published output")

        complete = build_finalization(
            queue_rows,
            queue,
            review1,
            review2,
            {},
            overlay_path=manifest_live["review_policy_overlay_path"],
            overlay_sha256=manifest_live["review_policy_overlay_sha256"],
            expected_count=args.expected_count,
        )
        synthetic_args = argparse.Namespace(
            review1=review1_path,
            review2=review2_path,
            review3=None,
            manifest=args.manifest,
            expected_count=args.expected_count,
        )
        collision_target = temp_root / "collision"
        base.filesystem_path(collision_target).mkdir()
        write_text_exclusive(collision_target / "sentinel.txt", "preserve\n")
        expect_reject(
            "CQ005_COLLISION_ATOMIC",
            "CQ-005",
            lambda: publish_finalization(
                collision_target,
                complete,
                review_snapshots=(review1_snapshot, review2_snapshot),
                bundle_manifest=manifest_live,
                args=synthetic_args,
                report=report,
            ),
            "pre-existing target rejects publication without partial output",
        )
        if sorted(
            path.name for path in base.filesystem_path(collision_target).iterdir()
        ) != ["sentinel.txt"]:
            raise AssertionError("collision target was partially modified")

        success_target = temp_root / "success"
        publish_finalization(
            success_target,
            complete,
            review_snapshots=(review1_snapshot, review2_snapshot),
            bundle_manifest=manifest_live,
            args=synthetic_args,
            report=report,
        )
        final_manifest = base.read_json(success_target / "finalization_manifest.json")
        review_hashes = [item["sha256"] for item in final_manifest["review_inputs"]]
        if review_hashes != [
            review1_snapshot.raw_sha256,
            review2_snapshot.raw_sha256,
        ]:
            raise AssertionError("finalization manifest lacks exact review input hashes")
        passed(
            "CQ006_REVIEW_INPUT_HASHES",
            "CQ-006",
            "finalization manifest binds both review files and every output",
        )
        passed(
            "CQ007_REPRODUCIBLE_FULL_PIPELINE",
            "CQ-007",
            "deterministic 48x2 reviews validate and complete the full pipeline",
        )

        mutation_source = temp_root / "review1_mutating.jsonl"
        write_bytes_exclusive(mutation_source, review1_snapshot.raw_bytes)
        immutable_snapshot = read_review_snapshot(
            mutation_source,
            queue,
            allow_subset=False,
            role="review1",
        )
        replacement = temp_root / "review1_replacement.tmp"
        write_bytes_exclusive(replacement, b'{"invalid_replacement":\n')
        os.replace(
            base.filesystem_path(replacement),
            base.filesystem_path(mutation_source),
        )
        mutation_target = temp_root / "mutation_safe"
        publish_finalization(
            mutation_target,
            complete,
            review_snapshots=(immutable_snapshot, review2_snapshot),
            bundle_manifest=manifest_live,
            args=synthetic_args,
            report=report,
        )
        mutation_manifest = base.read_json(
            mutation_target / "finalization_manifest.json"
        )
        retained_review1 = mutation_target / "review1_input_snapshot.jsonl"
        if mutation_manifest["review_inputs"][0]["sha256"] != immutable_snapshot.raw_sha256:
            raise AssertionError("CQ-008 manifest did not retain the validated input hash")
        if base.sha256_file(retained_review1) != immutable_snapshot.raw_sha256:
            raise AssertionError("CQ-008 retained snapshot bytes do not match validated bytes")
        retained = read_review_snapshot(
            retained_review1,
            queue,
            allow_subset=False,
            role="review1",
        )
        if retained.decision_set_sha256 != immutable_snapshot.decision_set_sha256:
            raise AssertionError("CQ-008 retained decisions differ from adopted decisions")
        if base.sha256_file(mutation_source) == immutable_snapshot.raw_sha256:
            raise AssertionError("CQ-008 mutation test did not replace the source input")
        passed(
            "CQ008_SINGLE_READ_IMMUTABLE_REVIEW",
            "CQ-008",
            "source replacement after validation cannot change decisions or provenance; exact retained bytes validate",
        )

        bad_names = [
            "../escaped.jsonl",
            "..\\escaped.jsonl",
            "sub/path.jsonl",
            "sub\\path.jsonl",
            "/absolute.jsonl",
            "C:\\absolute.jsonl",
            "C:drive-relative.jsonl",
            "\\\\server\\share.jsonl",
            ".",
            "..",
            "\uff0e\uff0e",
            "fullwidth\uff0fslash.jsonl",
            "NUL.jsonl",
            "trailing.",
            "trailing ",
            "control\u0001.jsonl",
            "",
        ]
        for index, bad_name in enumerate(bad_names, 1):
            before = sorted(
                str(path.relative_to(temp_root))
                for path in temp_root.rglob("*")
            )
            bad_target = temp_root / f"cq009_reject_{index:02d}"
            bad_args = argparse.Namespace(
                source_queue=declared_path(
                    manifest_live["source_queue"], label="source queue"
                ),
                source_manifest=declared_path(
                    manifest_live["source_prepare_manifest"],
                    label="source prepare manifest",
                ),
                overlay=args.overlay.resolve(),
                score_root=bad_target,
                expected_count=args.expected_count,
                queue_name=bad_name,
                template_name="safe_template.jsonl",
                manifest_name="safe_manifest.json",
            )
            expect_reject(
                f"CQ009_BAD_BASENAME_{index:02d}",
                "CQ-009",
                lambda bad_args=bad_args: bind_overlay(bad_args),
                f"unsafe basename rejected before staging: {bad_name!r}",
            )
            after = sorted(
                str(path.relative_to(temp_root))
                for path in temp_root.rglob("*")
            )
            if after != before or bad_target.exists():
                raise AssertionError(
                    f"CQ-009 unsafe name left an escaped or partial artifact: {bad_name!r}"
                )
        for safe_unicode in ("レビュー_queue.jsonl", "évidence.jsonl", "safe-name_01.json"):
            if validate_safe_basename(safe_unicode, label="safe Unicode") != safe_unicode:
                raise AssertionError("CQ-009 safe Unicode basename was altered")
        stage_probe = temp_root / "stage_probe"
        base.filesystem_path(stage_probe).mkdir()
        expect_reject(
            "CQ009_STAGE_DESTINATION_ESCAPE",
            "CQ-009",
            lambda: stage_destination(
                stage_probe, "../escape.json", label="stage destination probe"
            ),
            "beneath-stage enforcement rejects an escaping destination",
        )
        if (temp_root / "escape.json").exists():
            raise AssertionError("CQ-009 stage destination probe escaped")

        two_conflict_rows = json.loads(json.dumps(review2_rows, ensure_ascii=False))
        for index in (0, 1):
            two_conflict_rows[index]["gold_items"][0]["score"] = 1
            two_conflict_rows[index]["decision_sha256"] = base.canonical_hash(
                base.decision_fingerprint(two_conflict_rows[index])
            )
        two_conflict_path = temp_root / "review2_two_conflicts.jsonl"
        write_jsonl_exclusive(two_conflict_path, two_conflict_rows)
        two_conflict_snapshot = read_review_snapshot(
            two_conflict_path,
            queue,
            allow_subset=False,
            role="review2",
        )
        third_rows: list[dict[str, Any]] = []
        for index in (0, 1):
            third = json.loads(json.dumps(review1_rows[index], ensure_ascii=False))
            third["reviewer_id"] = "synthetic-reviewer-3"
            third["decision_sha256"] = base.canonical_hash(
                base.decision_fingerprint(third)
            )
            third_rows.append(third)
        mixed_third_rows = json.loads(json.dumps(third_rows, ensure_ascii=False))
        mixed_third_rows[1]["reviewer_id"] = "synthetic-reviewer-4"
        mixed_third_rows[1]["decision_sha256"] = base.canonical_hash(
            base.decision_fingerprint(mixed_third_rows[1])
        )
        mixed_third_path = temp_root / "review3_mixed_reviewer.jsonl"
        write_jsonl_exclusive(mixed_third_path, mixed_third_rows)
        expect_reject(
            "CQ010_MIXED_REVIEW3_REJECTED",
            "CQ-010",
            lambda: read_review_snapshot(
                mixed_third_path,
                queue,
                allow_subset=True,
                role="review3",
            ),
            "review3 input with multiple reviewer IDs is rejected",
        )
        third_path = temp_root / "review3_single_reviewer.jsonl"
        write_jsonl_exclusive(third_path, third_rows)
        third_snapshot = read_review_snapshot(
            third_path,
            queue,
            allow_subset=True,
            role="review3",
        )
        adjudicated = build_finalization(
            queue_rows,
            queue,
            review1,
            two_conflict_snapshot.rows_by_queue,
            third_snapshot.rows_by_queue,
            overlay_path=manifest_live["review_policy_overlay_path"],
            overlay_sha256=manifest_live["review_policy_overlay_sha256"],
            expected_count=args.expected_count,
        )
        adjudication_args = argparse.Namespace(
            review1=review1_path,
            review2=two_conflict_path,
            review3=third_path,
            manifest=args.manifest,
            expected_count=args.expected_count,
        )
        adjudication_target = temp_root / "adjudication_binding"
        publish_finalization(
            adjudication_target,
            adjudicated,
            review_snapshots=(
                review1_snapshot,
                two_conflict_snapshot,
                third_snapshot,
            ),
            bundle_manifest=manifest_live,
            args=adjudication_args,
            report=report,
        )
        adjudication_manifest = base.read_json(
            adjudication_target / "finalization_manifest.json"
        )
        bindings = adjudication_manifest["review3_adjudication_bindings"]
        if (
            adjudication_manifest["review3_reviewer_id"] != "synthetic-reviewer-3"
            or len(bindings) != 2
            or {item["reviewer_id"] for item in bindings}
            != {"synthetic-reviewer-3"}
        ):
            raise AssertionError("CQ-010 review3 identity is not bound per adjudication")
        passed(
            "CQ010_SINGLE_REVIEW3_BOUND",
            "CQ-010",
            "exactly one independent review3 identity is bound in every adjudication and the final manifest",
        )

        stable = {
            "review1_sha256": review1_snapshot.raw_sha256,
            "review2_sha256": review2_snapshot.raw_sha256,
            "formal_aggregate_sha256": base.sha256_file(
                success_target / "formal_aggregate.json"
            ),
        }

    output_target = score_root / output_name
    replay_command = (
        "python src/clouseau_process_time/"
        "codex_manual_attack8_scoring_v4_pid_non_scoring_hardened.py self-test "
        f"--queue {repo_relative(args.queue.resolve())} "
        f"--manifest {repo_relative(args.manifest.resolve())} "
        f"--overlay {repo_relative(args.overlay.resolve())} "
        f"--score-root {repo_relative(score_root)} --expected-count {args.expected_count} "
        "--output-name REPLACE_WITH_NEW_CREATE_ONLY_NAME"
    )
    synthetic_report = {
        "schema_version": SYNTHETIC_SCHEMA_VERSION,
        "status": "PASS",
        "replay_command": replay_command,
        "queue_sha256": report["queue_sha256"],
        "queue_manifest_sha256": report["manifest_sha256"],
        "review_template_sha256": report["review_template_sha256"],
        "overlay_sha256": report["overlay_sha256"],
        "wrapper_sha256": base.sha256_file(WRAPPER),
        "base_scorer_sha256": base.sha256_file(BASE_SCORER),
        "synthetic_review_count": 2,
        "rows_per_review": args.expected_count,
        "stable_output_hashes": stable,
        "tests": test_results,
        "finding_coverage": {
            finding: sum(1 for item in test_results if item["finding"] == finding)
            for finding in (f"CQ-{index:03d}" for index in range(1, 11))
        },
        "incomplete_cli_exit_code": INCOMPLETE_EXIT_CODE,
        "external_api_calls": False,
    }

    def writer(stage: Path) -> None:
        report_path = stage_destination(
            stage,
            "synthetic_validation_report.json",
            label="synthetic validation report",
        )
        write_json_exclusive(report_path, synthetic_report)
        write_json_exclusive(
            stage_destination(
                stage,
                "synthetic_validation_manifest.json",
                label="synthetic validation manifest",
            ),
            {
                "schema_version": SYNTHETIC_MANIFEST_SCHEMA_VERSION,
                "complete": True,
                "status": "PASS",
                "queue_manifest": repo_relative(args.manifest.resolve()),
                "queue_manifest_sha256": report["manifest_sha256"],
                "synthetic_validation_report": repo_relative(
                    output_target / report_path.name
                ),
                "synthetic_validation_report_sha256": base.sha256_file(report_path),
                "wrapper_sha256": base.sha256_file(WRAPPER),
                "external_api_calls": False,
                "transactional_publication": True,
            },
        )

    atomic_publish_directory(output_target, writer)
    print(
        f"PASS: hardened negative tests and synthetic "
        f"{args.expected_count}x2 pipeline; report={output_target}"
    )


def add_bundle_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--overlay", type=Path, required=True)
    parser.add_argument("--expected-count", type=int, default=48)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)

    bind = sub.add_parser("bind-overlay")
    bind.add_argument("--source-queue", type=Path, required=True)
    bind.add_argument("--source-manifest", type=Path, required=True)
    bind.add_argument("--overlay", type=Path, required=True)
    bind.add_argument("--score-root", type=Path, required=True)
    bind.add_argument("--expected-count", type=int, default=48)
    bind.add_argument(
        "--queue-name",
        default="review_queue_v4_pid_non_scoring_hardened.jsonl",
    )
    bind.add_argument(
        "--template-name",
        default="review_template_v4_pid_non_scoring_hardened.jsonl",
    )
    bind.add_argument(
        "--manifest-name",
        default="queue_manifest_v4_pid_non_scoring_hardened.json",
    )
    bind.set_defaults(func=bind_overlay)

    verify = sub.add_parser("verify-queue")
    add_bundle_arguments(verify)
    verify.add_argument("--report", type=Path, default=None)
    verify.set_defaults(func=verify_queue)

    validate = sub.add_parser("validate-review")
    add_bundle_arguments(validate)
    validate.add_argument("--reviewer-jsonl", type=Path, required=True)
    validate.add_argument(
        "--review-name", choices=("review1", "review2", "review3"), required=True
    )
    validate.add_argument("--score-root", type=Path, required=True)
    validate.set_defaults(func=validate_reviews)

    finish = sub.add_parser("finalize")
    add_bundle_arguments(finish)
    finish.add_argument("--review1", type=Path, required=True)
    finish.add_argument("--review2", type=Path, required=True)
    finish.add_argument("--review3", type=Path, default=None)
    finish.add_argument("--score-root", type=Path, required=True)
    finish.set_defaults(func=finalize)

    self_test = sub.add_parser("self-test")
    add_bundle_arguments(self_test)
    self_test.add_argument("--score-root", type=Path, required=True)
    self_test.add_argument(
        "--output-name", default="synthetic_self_validation_v4"
    )
    self_test.set_defaults(func=run_self_test)
    return result


def main() -> None:
    args = parser().parse_args()
    try:
        args.func(args)
    except IncompleteFinalization as exc:
        print(f"INCOMPLETE: {exc}", file=sys.stderr)
        raise SystemExit(INCOMPLETE_EXIT_CODE) from exc
    except (
        ValueError,
        FileNotFoundError,
        FileExistsError,
        json.JSONDecodeError,
        AssertionError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
