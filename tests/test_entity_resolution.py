from dataclasses import dataclass

from schemas import Entity, EntityType, ProvenanceRecord

from threatgraph.entity_resolution import EntityResolver, normalize
from threatgraph.ingestion.stix_loader import ParsedEntity

PROV = ProvenanceRecord(document_id="doc1", source_type="mitre_attack_stix")


def _parsed(name, etype, attack_id, aliases=None):
    return ParsedEntity(
        entity=Entity(name=name, entity_type=etype, attack_id=attack_id,
                      aliases=aliases or [], confidence_score=1.0),
        description="", stix_id=f"stix--{attack_id}", provenance=PROV,
    )


def _resolver():
    canonical = {
        "s1": _parsed("APT29", EntityType.THREAT_GROUP, "G0016", aliases=["Cozy Bear", "The Dukes"]),
        "s2": _parsed("Process Injection", EntityType.TECHNIQUE, "T1055"),
    }
    return EntityResolver(canonical)


def test_resolve_by_attack_id():
    r = _resolver().resolve("Whatever Name", EntityType.THREAT_GROUP, attack_id="G0016")
    assert r.matched and r.canonical_name == "APT29" and r.method == "attack_id"


def test_resolve_by_alias_case_insensitive():
    r = _resolver().resolve("cozy bear", EntityType.THREAT_GROUP)
    assert r.matched and r.canonical_name == "APT29" and r.method == "alias"


def test_resolve_by_normalized_name():
    r = _resolver().resolve("process-injection", EntityType.TECHNIQUE)
    assert r.matched and r.canonical_name == "Process Injection" and r.method == "normalized_name"


def test_no_match_returns_unmatched():
    r = _resolver().resolve("Totally Unknown Group", EntityType.THREAT_GROUP)
    assert not r.matched


def test_normalize_folds_punctuation():
    assert normalize("APT-29!!") == normalize("apt 29")
