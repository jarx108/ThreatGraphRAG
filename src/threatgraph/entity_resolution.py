"""Resolve LLM-extracted entity mentions against the canonical ATT&CK entity set.

Used when ingesting free text (e.g. CISA advisories) through the extraction
pipeline: extracted mentions like "Cozy Bear" or "apt29" must resolve to the
single canonical ThreatGroup node (name="APT29", attack_id="G0016") instead
of creating duplicate graph nodes. Resolution is attempted in order of
decreasing precision and stops at the first match:

  1. Exact ATT&CK identifier match (e.g. "G0016").
  2. Known-alias match (case-insensitive, from STIX `aliases`/`x_mitre_aliases`).
  3. Normalized canonical-name match (lowercased, punctuation/whitespace folded).
  4. Embedding cosine-similarity match above a configurable threshold, as a
     last resort for near-miss spellings/paraphrases with no alias record.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from schemas import Entity, EntityType

from threatgraph.ingestion.stix_loader import ParsedEntity

_PUNCT_RE = re.compile(r"[^\w]+|_")


def normalize(name: str) -> str:
    return _PUNCT_RE.sub(" ", name.lower()).strip()


# Names/aliases that are ordinary English words or too short to be safe
# mention triggers when scanning free text (e.g. the Software "at" or "Net").
# They still resolve when the extractor tags them explicitly; this only
# stops find_mentions() from linking every "net" or "page" in a question.
_MIN_MENTION_CHARS = 4
_STOP_MENTIONS = {
    "data", "group", "groups", "software", "technique", "techniques", "mitigation", "mitigations",
    "attack", "tool", "tools", "user", "users", "page", "file", "files", "network", "system",
    "process", "account", "accounts", "command", "service", "services", "remote", "proxy",
    "windows", "linux", "macos", "cloud", "email", "web", "audit", "training", "encryption",
}


@dataclass
class Mention:
    """An entity mention found in free text and linked to a canonical node."""
    text: str
    start: int
    end: int
    attack_id: str
    canonical_name: str
    entity_type: str
    method: str  # "attack_id" | "name" | "alias"


@dataclass
class ResolutionResult:
    matched: bool
    attack_id: Optional[str] = None
    canonical_name: Optional[str] = None
    method: Optional[str] = None  # "attack_id" | "alias" | "normalized_name" | "semantic" | None
    similarity: Optional[float] = None


class EntityResolver:
    """Index of canonical ATT&CK entities, built once from a ParsedBundle,
    used to resolve many extracted mentions without re-scanning the bundle."""

    def __init__(self, canonical_entities: dict[str, ParsedEntity], embedder=None,
                 semantic_threshold: float = 0.85):
        self._by_attack_id: dict[str, Entity] = {}
        self._by_alias: dict[tuple[EntityType, str], Entity] = {}
        self._by_norm_name: dict[tuple[EntityType, str], Entity] = {}
        self._embedder = embedder
        self._semantic_threshold = semantic_threshold
        self._embedding_cache: dict[str, list[float]] = {}

        # normalized surface form -> [(entity, "name"|"alias")], for find_mentions()
        self._surface: dict[str, list[tuple[Entity, str]]] = {}
        for pe in canonical_entities.values():
            e = pe.entity
            if not e.attack_id:
                continue
            self._by_attack_id[e.attack_id.upper()] = e
            self._by_norm_name[(e.entity_type, normalize(e.name))] = e
            self._surface.setdefault(normalize(e.name), []).append((e, "name"))
            for alias in e.aliases:
                self._by_alias[(e.entity_type, alias.lower().strip())] = e
                if normalize(alias) != normalize(e.name):
                    self._surface.setdefault(normalize(alias), []).append((e, "alias"))
        self._max_ngram = max((len(k.split()) for k in self._surface), default=1)

    def find_mentions(self, text: str) -> list[Mention]:
        """Named Entity Disambiguation over free text: find ATT&CK IDs and
        entity names/aliases (longest match first, word-boundary aligned)
        and link each to its canonical node. A surface form shared by
        several entities (e.g. a group and a software both called "X") is
        disambiguated by preferring the canonical-name owner, then the
        ThreatGroup, then the lowest ATT&CK ID, so the choice is
        deterministic."""
        mentions: list[Mention] = []
        taken: list[tuple[int, int]] = []

        def free(a: int, b: int) -> bool:
            return all(b <= s0 or a >= e0 for s0, e0 in taken)

        for m in re.finditer(r"\b([GTSMC]\d{4}(?:\.\d{3})?)\b", text):
            e = self._by_attack_id.get(m.group(1).upper())
            if e:
                mentions.append(Mention(m.group(1), m.start(), m.end(), e.attack_id, e.name,
                                        e.entity_type.value, "attack_id"))
                taken.append((m.start(), m.end()))

        tokens = [(t.group(0), t.start(), t.end()) for t in re.finditer(r"[^\W_](?:[\w.\-$]*[\w$])?", text)]
        for n in range(min(self._max_ngram, len(tokens)), 0, -1):
            for i in range(len(tokens) - n + 1):
                a, b = tokens[i][1], tokens[i + n - 1][2]
                if not free(a, b):
                    continue
                surface = text[a:b]
                key = normalize(surface)
                if key not in self._surface and key.endswith("s") and key[:-1] in self._surface:
                    key = key[:-1]  # simple plural: "spearphishing attachments"
                # Short names count only as written acronyms ("RTM", "WCE"), never "rtm"/"at".
                too_short = len(key) < _MIN_MENTION_CHARS and not (len(key) >= 3 and surface.isupper())
                if too_short or key in _STOP_MENTIONS or key not in self._surface:
                    continue
                cands = sorted(self._surface[key], key=lambda c: (
                    c[1] != "name", c[0].entity_type != EntityType.THREAT_GROUP, c[0].attack_id))
                e, how = cands[0]
                mentions.append(Mention(surface, a, b, e.attack_id, e.name, e.entity_type.value, how))
                taken.append((a, b))
        return sorted(mentions, key=lambda m: m.start)

    def resolve(self, mention_name: str, entity_type: EntityType,
                attack_id: Optional[str] = None) -> ResolutionResult:
        if attack_id and attack_id.upper() in self._by_attack_id:
            e = self._by_attack_id[attack_id.upper()]
            return ResolutionResult(True, e.attack_id, e.name, "attack_id")

        alias_key = (entity_type, mention_name.lower().strip())
        if alias_key in self._by_alias:
            e = self._by_alias[alias_key]
            return ResolutionResult(True, e.attack_id, e.name, "alias")

        norm_key = (entity_type, normalize(mention_name))
        if norm_key in self._by_norm_name:
            e = self._by_norm_name[norm_key]
            return ResolutionResult(True, e.attack_id, e.name, "normalized_name")

        if self._embedder is not None:
            best = self._semantic_match(mention_name, entity_type)
            if best is not None:
                return best

        return ResolutionResult(False)

    def _semantic_match(self, mention_name: str, entity_type: EntityType) -> Optional[ResolutionResult]:
        import numpy as np

        candidates = [e for (t, _), e in self._by_norm_name.items() if t == entity_type]
        if not candidates:
            return None
        mention_vec = np.array(self._embedder.embed_one(mention_name))
        best_entity, best_sim = None, -1.0
        for e in candidates:
            if e.attack_id not in self._embedding_cache:
                self._embedding_cache[e.attack_id] = self._embedder.embed_one(e.name)
            cand_vec = np.array(self._embedding_cache[e.attack_id])
            denom = (np.linalg.norm(mention_vec) * np.linalg.norm(cand_vec)) or 1e-9
            sim = float(np.dot(mention_vec, cand_vec) / denom)
            if sim > best_sim:
                best_entity, best_sim = e, sim
        if best_entity is not None and best_sim >= self._semantic_threshold:
            return ResolutionResult(True, best_entity.attack_id, best_entity.name, "semantic", best_sim)
        return None
