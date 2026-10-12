import pytest
from pydantic import ValidationError

from schemas import Entity, EntityType, ExtractionResult, Predicate, Relationship


def _entity(name, etype, attack_id=None):
    return {"name": name, "entity_type": etype, "attack_id": attack_id,
            "aliases": [], "confidence_score": 0.9}


def test_valid_extraction_result():
    result = ExtractionResult.model_validate({
        "entities": [
            _entity("APT29", "ThreatGroup", "G0016"),
            _entity("Process Injection", "Technique", "T1055"),
        ],
        "relationships": [
            {"source": "APT29", "predicate": "USES", "target": "Process Injection",
             "evidence_text": "APT29 uses Process Injection.", "confidence_score": 0.9},
        ],
    })
    assert result.relationships[0].predicate == Predicate.USES


def test_rejects_disallowed_triple_shape():
    with pytest.raises(ValidationError):
        ExtractionResult.model_validate({
            "entities": [
                _entity("APT29", "ThreatGroup", "G0016"),
                _entity("Mimikatz", "Software", "S0002"),
            ],
            "relationships": [
                # Software USES ThreatGroup is not in ALLOWED_TRIPLES.
                {"source": "Mimikatz", "predicate": "USES", "target": "APT29",
                 "evidence_text": "irrelevant", "confidence_score": 0.9},
            ],
        })


def test_rejects_mismatched_attack_id_prefix():
    with pytest.raises(ValidationError):
        Entity.model_validate(_entity("APT29", "ThreatGroup", "T0016"))


def test_rejects_undeclared_entity_reference():
    with pytest.raises(ValidationError):
        ExtractionResult.model_validate({
            "entities": [_entity("APT29", "ThreatGroup", "G0016")],
            "relationships": [
                {"source": "APT29", "predicate": "USES", "target": "Ghost Entity",
                 "evidence_text": "x", "confidence_score": 0.5},
            ],
        })


def test_confidence_out_of_range_rejected():
    with pytest.raises(ValidationError):
        Entity.model_validate(_entity("APT29", "ThreatGroup", "G0016") | {"confidence_score": 1.5})


def test_lenient_extraction_salvages_valid_relationships():
    from threatgraph.extraction.extractor import _validate_leniently

    raw = {
        "entities": [
            _entity("APT29", "ThreatGroup", "G0016"),
            _entity("Process Injection", "Technique", "T1055"),
            _entity("Mimikatz", "Software", "S0002"),
        ],
        "relationships": [
            {"source": "APT29", "predicate": "USES", "target": "Process Injection",
             "evidence_text": "valid", "confidence_score": 0.9},
            # Disallowed shape: Software-USES->ThreatGroup is not in ALLOWED_TRIPLES.
            {"source": "Mimikatz", "predicate": "USES", "target": "APT29",
             "evidence_text": "invalid shape", "confidence_score": 0.9},
        ],
    }
    result, rejected = _validate_leniently(raw)
    assert len(result.entities) == 3
    assert len(result.relationships) == 1
    assert result.relationships[0].source == "APT29"
    assert len(rejected) == 1
    assert rejected[0]["kind"] == "relationship"
