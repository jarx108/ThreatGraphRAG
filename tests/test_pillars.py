"""Tests for the rubric-pillar features: NED over free text, question
analysis, deterministic answer metrics, the GDS Cypher script, the Ollama
provider and the bounded extraction schema. None of them need Neo4j or an LLM."""
import json

import pytest
from schemas import Entity, EntityType, ProvenanceRecord

from threatgraph.entity_resolution import EntityResolver
from threatgraph.eval import answer_metrics
from threatgraph.graph import analytics
from threatgraph.ingestion.stix_loader import ParsedEntity
from threatgraph.rag.graphrag import asked_entity_type, format_analytics

PROV = ProvenanceRecord(document_id="doc1", source_type="mitre_attack_stix")


def _pe(name, etype, attack_id, aliases=()):
    return ParsedEntity(entity=Entity(name=name, entity_type=etype, attack_id=attack_id,
                                      aliases=list(aliases), confidence_score=1.0),
                        description="", stix_id=f"stix--{attack_id}", provenance=PROV)


@pytest.fixture
def resolver():
    return EntityResolver({p.stix_id: p for p in [
        _pe("APT29", EntityType.THREAT_GROUP, "G0016", ["Cozy Bear", "NOBELIUM"]),
        _pe("APT28", EntityType.THREAT_GROUP, "G0007", ["Fancy Bear"]),
        _pe("Mimikatz", EntityType.SOFTWARE, "S0002"),
        _pe("RTM", EntityType.THREAT_GROUP, "G0048"),
        _pe("at", EntityType.SOFTWARE, "S0110"),
        _pe("Spearphishing Attachment", EntityType.TECHNIQUE, "T1566.001"),
        _pe("Carbanak", EntityType.THREAT_GROUP, "G0008"),
        _pe("Carbanak", EntityType.SOFTWARE, "S0030"),
    ]})


# --- NED -------------------------------------------------------------------

def test_find_mentions_links_aliases_ids_and_names(resolver):
    text = "Does Cozy Bear (G0007?) use Mimikatz like fancy bear?"
    got = {(m.text, m.attack_id, m.method) for m in resolver.find_mentions(text)}
    assert ("Cozy Bear", "G0016", "alias") in got
    assert ("G0007", "G0007", "attack_id") in got
    assert ("Mimikatz", "S0002", "name") in got
    assert ("fancy bear", "G0007", "alias") in got


def test_find_mentions_prefers_longest_match_and_handles_plurals(resolver):
    ms = resolver.find_mentions("They send spearphishing attachments.")
    assert [(m.text, m.attack_id) for m in ms] == [("spearphishing attachments", "T1566.001")]


def test_find_mentions_ignores_short_words_unless_written_as_acronym(resolver):
    assert resolver.find_mentions("look at the rtm logs") == []
    assert [m.attack_id for m in resolver.find_mentions("The RTM group")] == ["G0048"]


def test_find_mentions_ambiguous_name_is_deterministic(resolver):
    # Same canonical name for a group and a software: the group wins, every time.
    assert [m.attack_id for m in resolver.find_mentions("Carbanak")] == ["G0008"]


# --- question analysis -------------------------------------------------------

@pytest.mark.parametrize("question,expected", [
    ("Which mitigations address the ATT&CK technique Phishing (T1566) used by Axiom (G0001)?", "Mitigation"),
    ("Which ATT&CK techniques does PoisonIvy (S0012), software used by Axiom (G0001), implement?", "Technique"),
    ("For PoisonIvy (S0012), software used by Axiom (G0001), which mitigations address each technique?", "Mitigation"),
    ("What software does APT29 use?", "Software"),
    ("Which groups use Mimikatz?", "ThreatGroup"),
    ("Tell me about APT29.", None),
])
def test_asked_entity_type(question, expected):
    assert asked_entity_type(question) == expected


def test_format_analytics_is_empty_without_gds_properties():
    assert format_analytics({"seeds": [], "coverage": []}) == ""


# --- answer metrics ----------------------------------------------------------

ITEM = {"expected_answer": {
    "threat_group": {"name": "Axiom", "attack_id": "G0001"},
    "technique": {"name": "Valid Accounts", "attack_id": "T1078"},
    "mitigations": [{"name": "A", "attack_id": "M1013"}, {"name": "B", "attack_id": "M1015"}],
}}


def _run(answer, facts=(), chunks=()):
    return {"answer": answer, "graph_facts": list(facts), "retrieved_chunks": list(chunks),
            "total_latency_seconds": 1.5}


def test_gold_excludes_entities_named_in_the_question():
    assert answer_metrics.gold_ids(ITEM) == {"M1013", "M1015"}


def test_score_perfect_traceable_answer():
    facts = [{"src_id": "M1013", "tgt_id": "T1078", "stix_relationship_id": "relationship--1"},
             {"src_id": "M1015", "tgt_id": "T1078", "stix_relationship_id": "relationship--2"}]
    s = answer_metrics.score(_run("Axiom (G0001) uses T1078; mitigate with M1013 and M1015.", facts), ITEM)
    assert s["accuracy"] == 1.0 and s["precision"] == 1.0 and s["fully_correct"] == 1.0
    assert s["hallucination"] == 0.25  # G0001 is cited but not in the retrieved evidence
    assert s["traceable"] == 0.75


def test_score_partial_and_wrong_answer():
    chunks = [{"entity_attack_id": "M1013", "text": "M1099 is unrelated"}]
    s = answer_metrics.score(_run("Use M1013 and M1099. Also M1050.", chunks=chunks), ITEM)
    assert s["accuracy"] == 0.5
    assert s["precision"] == pytest.approx(1 / 3)
    assert s["fully_correct"] == 0.0
    assert s["unsupported"] == ["M1050"]
    assert s["missing"] == ["M1015"]


def test_score_error_and_summary():
    s = answer_metrics.score({"error": "boom", "answer": ""}, ITEM)
    assert s["accuracy"] is None
    summary = answer_metrics.summarize([s, answer_metrics.score(_run("M1013 M1015"), ITEM)])
    assert summary["accuracy"] == {"mean": 1.0, "std": None, "n": 1}


# --- GDS script, Ollama provider, extraction schema ---------------------------

def test_gds_cypher_script_has_every_step():
    stmts = analytics.load_statements()
    for name in analytics.ALGORITHM_STEPS + analytics.READ_STEPS:
        assert stmts.get(name), name
    assert "gds.pageRank.write" in stmts["pagerank"] and "concurrency: 1" in stmts["louvain"]
    assert all("@name" not in s for s in stmts.values())


def test_ollama_provider_sends_seed_schema_and_context(monkeypatch):
    import urllib.request

    from threatgraph.rag import llm_provider

    sent = {}

    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self):
            return json.dumps({"message": {"content": "{}"}, "prompt_eval_count": 7, "eval_count": 3}).encode()

    def fake_urlopen(req, timeout):
        sent.update(json.loads(req.data))
        return Resp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    p = llm_provider.LLMProvider.__new__(llm_provider.LLMProvider)
    p.model, p.provider, p._client = "llama3.1:8b", "ollama", None
    r = p.complete("sys", "user", max_tokens=50, json_schema={"type": "object"})
    assert (r.text, r.input_tokens, r.output_tokens) == ("{}", 7, 3)
    assert sent["format"] == {"type": "object"}
    assert sent["options"]["seed"] == llm_provider.LLM.seed
    assert sent["options"]["temperature"] == llm_provider.LLM.temperature
    assert sent["options"]["num_ctx"] == llm_provider.LLM.ollama_num_ctx


def test_extraction_schema_is_bounded_but_entity_model_is_not():
    from threatgraph.extraction.extractor import EXTRACTION_JSON_SCHEMA as schema
    assert schema["properties"]["relationships"]["maxItems"] == 25
    assert schema["$defs"]["Entity"]["properties"]["aliases"]["maxItems"] == 10
    # Constrained decoding emits only required keys; the strict validator needs all five.
    assert set(schema["$defs"]["Entity"]["required"]) == {"name", "entity_type", "attack_id", "aliases",
                                                           "confidence_score"}
    # MITRE's own entities may have many aliases; the shared model must accept them.
    Entity(name="X", entity_type=EntityType.THREAT_GROUP, aliases=[f"a{i}" for i in range(20)], confidence_score=1)
