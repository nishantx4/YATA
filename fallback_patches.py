from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from red_agent import VulnerabilityFinding


def generate_patch(target_root: Path, finding: VulnerabilityFinding):
    from blue_agent import BlueAgent, PatchResult

    target_root = target_root.resolve()
    temp_root = Path(tempfile.mkdtemp(prefix="yata_patched_"))
    patched_root = temp_root / target_root.name
    shutil.copytree(
        target_root,
        patched_root,
        ignore=shutil.ignore_patterns(".yata", ".git", ".venv", "__pycache__")
    )

    # Reuse BlueAgent's own (vulnerability_type, language)-keyed registry so
    # the deterministic fallback path can never drift out of sync with the
    # LLM-assisted path over which strategy handles a given finding.
    language = getattr(finding, "language", "python")
    strategy = BlueAgent().strategies.get((finding.vulnerability_type, language))
    if strategy is None:
        raise ValueError(f"No patch strategy registered for {finding.vulnerability_type} ({language})")

    relative_file = Path(str(finding.metadata.get("relative_file", Path(finding.affected_file).name)))
    patched_copy_file = patched_root / relative_file
    original_source = patched_copy_file.read_text(encoding="utf-8")
    patched_source = strategy.apply_source(original_source, finding)
    patched_copy_file.write_text(patched_source, encoding="utf-8")

    changed_files = [str(relative_file)]
    changed_files.extend(strategy.apply_auxiliary_updates(patched_root, finding))

    mitigation, defense = strategy.fallback_guidance()
    patch_text = strategy.build_summary(original_source, patched_source)

    return PatchResult(
        patched_root=patched_root,
        patched_file=patched_copy_file,
        changed_files=changed_files,
        patch_text=patch_text,
        used_llm=False,
        mitigation_explanation=mitigation,
        defense_strategy=defense,
    )
