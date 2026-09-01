<<<<<<< HEAD
# Author: Avinash Krishna — Team AVV Elites (SIH26153)
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
"""
src/rag/knowledge_base.py

Loads the local MITRE ATT&CK knowledge base used by the RAG explainability
layer (retriever.py, copilot.py). Ships with a curated, hand-verified subset
(attck_knowledge_base.json) covering the techniques most visible in network
traffic across this project's five kill-chain stages — enough to make the
analyst-facing explanations concrete and grounded without requiring any
download at demo time (the spec requires the core system to run fully
offline, with zero outbound network calls).

sync_from_stix() is provided as a documented upgrade path: a team with
internet access can regenerate a much larger knowledge base from MITRE's
official STIX corpus before a real deployment, without touching any other
file in src/rag/ or src/explain/ — both are written against the KnowledgeBase
interface below, not against the JSON file directly.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from src.utils import PROJECT_ROOT, get_logger

logger = get_logger(__name__)


@dataclass
class KBEntry:
    id: str
    name: str
    attck_tactic: str
    project_stage: str
    summary: str
    network_signature: str
    mitigation: str

    def to_document(self) -> str:
        """Flattened text used as the retrieval unit — every field concatenated
        so BM25 can match on technique name, tactic, or the specific network
        behaviour described, whichever term the analyst's context uses."""
        return (
            f"{self.name} ({self.id}). Tactic: {self.attck_tactic}. "
            f"{self.summary} Typical network signature: {self.network_signature} "
            f"Mitigation: {self.mitigation}"
        )


class KnowledgeBase:
    def __init__(self, entries: list[KBEntry]):
        self.entries = entries

    @classmethod
    def load(cls, path: str | Path | None = None) -> "KnowledgeBase":
        path = Path(path) if path else PROJECT_ROOT / "src" / "rag" / "attck_knowledge_base.json"
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        entries = [KBEntry(**e) for e in raw["entries"]]
        logger.info(f"Loaded {len(entries)} ATT&CK knowledge-base entries from {path.name}")
        return cls(entries)

    def by_stage(self, project_stage: str) -> list[KBEntry]:
        return [e for e in self.entries if e.project_stage == project_stage]

    def by_id(self, technique_id: str) -> KBEntry | None:
        return next((e for e in self.entries if e.id == technique_id), None)

    def documents(self) -> list[str]:
        return [e.to_document() for e in self.entries]


def sync_from_stix(stix_bundle_path: str | Path, out_path: str | Path) -> None:
    """OPTIONAL, requires internet access and is NOT part of the offline demo
    path. Parses a MITRE ATT&CK Enterprise STIX 2.1 bundle (download from
    github.com/mitre-attack/attack-stix-data — enterprise-attack/enterprise-attack.json)
    and regenerates a full-coverage knowledge base in the same schema as
    attck_knowledge_base.json. Run this once, offline-of-the-demo, on a
    machine with internet access; the resulting JSON is then used exactly
    like the bundled seed file with zero code changes elsewhere.
    """
    with open(stix_bundle_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    tactic_shortname_to_stage = {
        "reconnaissance": "Reconnaissance",
        "initial-access": "Initial Access",
        "lateral-movement": "Lateral Movement",
        "command-and-control": "Command and Control",
        "exfiltration": "Exfiltration",
    }

    entries = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        phase_names = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]
        matching_stage = next((tactic_shortname_to_stage[p] for p in phase_names if p in tactic_shortname_to_stage), None)
        if matching_stage is None:
            continue
        ext_id = next(
            (r["external_id"] for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ext_id:
            continue
        entries.append({
            "id": ext_id,
            "name": obj.get("name", ""),
            "attck_tactic": ", ".join(phase_names),
            "project_stage": matching_stage,
            "summary": (obj.get("description", "").split("\n")[0])[:400],
            "network_signature": "See official technique page for detection guidance.",
            "mitigation": "See official technique page for linked mitigations.",
        })

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"_meta": {"source": "regenerated from official STIX corpus"}, "entries": entries}, f, indent=2)
    logger.info(f"Synced {len(entries)} techniques from STIX bundle -> {out_path}")
