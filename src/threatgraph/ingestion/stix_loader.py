"""Download, cache, and parse the official MITRE Enterprise ATT&CK STIX bundle.

Caching: the raw bundle is written to data/cache/enterprise-attack-<version>.json
on first download. Subsequent runs reuse the cached copy unless --refresh is
passed, so repeated pipeline runs do not re-download ~50MB of STIX each time.
"""
from __future__ import annotations

import hashlib
import json
import ssl
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from schemas import Entity, EntityType, ProvenanceRecord

from threatgraph.config import ATTACK_STIX_SHA256, ATTACK_STIX_URL, ATTACK_STIX_VERSION, CACHE_DIR

STIX_TYPE_TO_ENTITY_TYPE = {
    "intrusion-set": EntityType.THREAT_GROUP,
    "attack-pattern": EntityType.TECHNIQUE,
    "malware": EntityType.SOFTWARE,
    "tool": EntityType.SOFTWARE,
    "course-of-action": EntityType.MITIGATION,
    "campaign": EntityType.CAMPAIGN,
}

DOCUMENT_ID = f"mitre-attack-enterprise-v{ATTACK_STIX_VERSION}"


def _attack_id(obj: dict) -> Optional[str]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def _is_active(obj: dict) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def bundle_sha256(bundle: dict) -> str:
    """SHA-256 of the bundle's canonical JSON, independent of formatting."""
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _verify(bundle: dict, origin: str) -> dict:
    digest = bundle_sha256(bundle)
    if digest != ATTACK_STIX_SHA256:
        raise ValueError(
            f"ATT&CK STIX bundle from {origin} does not match the pinned v{ATTACK_STIX_VERSION} "
            f"content hash (expected {ATTACK_STIX_SHA256}, got {digest}). Results would not be "
            "reproducible. Delete the cached file and re-run with --refresh, or update "
            "ATTACK_STIX_SHA256 in threatgraph/config.py if you are deliberately changing versions."
        )
    return bundle


def fetch_bundle(refresh: bool = False) -> dict:
    """Return the raw STIX bundle dict, using the on-disk cache when possible.
    Either source is verified against the pinned content hash."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = CACHE_DIR / f"enterprise-attack-{ATTACK_STIX_VERSION}.json"
    if cache_path.exists() and not refresh:
        return _verify(json.loads(cache_path.read_text(encoding="utf-8")), str(cache_path))

    # certifi's CA bundle (pinned in requirements.lock) instead of the OS
    # store: python.org builds on macOS ship without system CA certificates,
    # which otherwise fails this download with CERTIFICATE_VERIFY_FAILED.
    try:
        import certifi
        context = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        context = ssl.create_default_context()
    with urllib.request.urlopen(ATTACK_STIX_URL, context=context) as response:
        bundle = _verify(json.load(response), ATTACK_STIX_URL)
    cache_path.write_text(json.dumps(bundle), encoding="utf-8")
    return bundle


@dataclass
class ParsedEntity:
    entity: Entity
    description: str
    stix_id: str
    provenance: ProvenanceRecord


@dataclass
class ParsedRelationship:
    source_stix_id: str
    target_stix_id: str
    predicate: str
    stix_relationship_id: str
    description: str = ""
    # STIX timestamps of the relationship object (ISO-8601), kept as edge
    # provenance so every graph fact records when MITRE asserted/updated it.
    created: str = ""
    modified: str = ""


@dataclass
class ParsedBundle:
    entities: dict[str, ParsedEntity] = field(default_factory=dict)  # keyed by stix_id
    relationships: list[ParsedRelationship] = field(default_factory=list)
    document_id: str = DOCUMENT_ID


def parse_bundle(bundle: dict) -> ParsedBundle:
    """Parse the raw STIX bundle into entities (with descriptions/aliases/attack_id)
    and relationships, preserving source-document provenance on every record."""
    objects = {o["id"]: o for o in bundle["objects"] if _is_active(o)}
    retrieved_at = datetime.now(timezone.utc).isoformat()

    parsed = ParsedBundle()
    for stix_id, obj in objects.items():
        entity_type = STIX_TYPE_TO_ENTITY_TYPE.get(obj.get("type"))
        if entity_type is None:
            continue
        aliases = [a for a in obj.get("aliases", obj.get("x_mitre_aliases", [])) if a != obj.get("name")]
        provenance = ProvenanceRecord(
            document_id=parsed.document_id,
            source_type="mitre_attack_stix",
            source_url=ATTACK_STIX_URL,
            stix_id=stix_id,
            retrieved_at=retrieved_at,
        )
        entity = Entity(
            name=obj.get("name", ""),
            entity_type=entity_type,
            attack_id=_attack_id(obj),
            aliases=aliases,
            confidence_score=1.0,  # ground-truth STIX data, not LLM-extracted
        )
        if entity.attack_id is None:
            continue
        parsed.entities[stix_id] = ParsedEntity(
            entity=entity,
            description=obj.get("description", ""),
            stix_id=stix_id,
            provenance=provenance,
        )

    for obj in bundle["objects"]:
        if obj.get("type") != "relationship" or not _is_active(obj):
            continue
        src, tgt = obj.get("source_ref"), obj.get("target_ref")
        if src not in parsed.entities or tgt not in parsed.entities:
            continue
        rel_type = obj.get("relationship_type")
        src_type = parsed.entities[src].entity.entity_type
        tgt_type = parsed.entities[tgt].entity.entity_type

        predicate = None
        if rel_type == "uses" and src_type in (EntityType.THREAT_GROUP, EntityType.SOFTWARE) and tgt_type in (
            EntityType.TECHNIQUE, EntityType.SOFTWARE,
        ):
            predicate = "USES"
        elif rel_type == "mitigates" and src_type == EntityType.MITIGATION and tgt_type == EntityType.TECHNIQUE:
            predicate = "MITIGATES"
        elif rel_type == "attributed-to" and src_type == EntityType.CAMPAIGN and tgt_type == EntityType.THREAT_GROUP:
            predicate = "ATTRIBUTED_TO"
        if predicate is None:
            continue

        parsed.relationships.append(ParsedRelationship(
            source_stix_id=src,
            target_stix_id=tgt,
            predicate=predicate,
            stix_relationship_id=obj["id"],
            description=obj.get("description", ""),
            created=obj.get("created", ""),
            modified=obj.get("modified", ""),
        ))

    return parsed


def load_parsed_bundle(refresh: bool = False) -> ParsedBundle:
    return parse_bundle(fetch_bundle(refresh=refresh))


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Download/parse MITRE ATT&CK STIX and report summary stats.")
    p.add_argument("--refresh", action="store_true", help="Re-download even if a cached copy exists.")
    args = p.parse_args()

    pb = load_parsed_bundle(refresh=args.refresh)
    by_type: dict[str, int] = {}
    for pe in pb.entities.values():
        by_type[pe.entity.entity_type.value] = by_type.get(pe.entity.entity_type.value, 0) + 1
    print(f"Parsed {len(pb.entities)} active entities, {len(pb.relationships)} relationships.")
    for k, v in sorted(by_type.items()):
        print(f"  {k}: {v}")
