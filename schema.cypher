// ThreatGraph - Neo4j schema checkpoint
// CS 6338 Knowledge Engineering
// Neo4j 5.x+

// ---- Uniqueness constraints ----
CREATE CONSTRAINT threat_group_attack_id IF NOT EXISTS
FOR (n:ThreatGroup) REQUIRE n.attack_id IS UNIQUE;

CREATE CONSTRAINT technique_attack_id IF NOT EXISTS
FOR (n:Technique) REQUIRE n.attack_id IS UNIQUE;

CREATE CONSTRAINT software_attack_id IF NOT EXISTS
FOR (n:Software) REQUIRE n.attack_id IS UNIQUE;

CREATE CONSTRAINT campaign_attack_id IF NOT EXISTS
FOR (n:Campaign) REQUIRE n.attack_id IS UNIQUE;

CREATE CONSTRAINT mitigation_attack_id IF NOT EXISTS
FOR (n:Mitigation) REQUIRE n.attack_id IS UNIQUE;

CREATE CONSTRAINT vulnerability_cve_id IF NOT EXISTS
FOR (n:Vulnerability) REQUIRE n.cve_id IS UNIQUE;

CREATE CONSTRAINT document_id IF NOT EXISTS
FOR (n:Document) REQUIRE n.document_id IS UNIQUE;

CREATE CONSTRAINT chunk_id IF NOT EXISTS
FOR (n:Chunk) REQUIRE n.chunk_id IS UNIQUE;

// ---- Lookup indexes ----
CREATE INDEX threat_group_name IF NOT EXISTS FOR (n:ThreatGroup) ON (n.name);
CREATE INDEX technique_name IF NOT EXISTS FOR (n:Technique) ON (n.name);
CREATE INDEX software_name IF NOT EXISTS FOR (n:Software) ON (n.name);
CREATE INDEX mitigation_name IF NOT EXISTS FOR (n:Mitigation) ON (n.name);
CREATE INDEX campaign_name IF NOT EXISTS FOR (n:Campaign) ON (n.name);

// The chunk_embedding vector index is created dynamically by
// src/threatgraph/graph/schema_init.py using the dimensions of whatever
// embedding model is configured (EMBEDDING_MODEL / EMBEDDING_DIM env vars),
// since this static file cannot know that value in advance. Default: 384
// dims for sentence-transformers/all-MiniLM-L6-v2.

// Intended relationship vocabulary:
// (:ThreatGroup)-[:USES]->(:Technique)
// (:ThreatGroup)-[:USES]->(:Software)
// (:Software)-[:USES]->(:Technique)
// (:Mitigation)-[:MITIGATES]->(:Technique)
// (:Campaign)-[:ATTRIBUTED_TO]->(:ThreatGroup)
// (:ThreatGroup|Software)-[:EXPLOITS]->(:Vulnerability)
// (:ThreatGroup|Technique|Software|Campaign|Mitigation|Vulnerability)-[:MENTIONED_IN]->(:Document)
