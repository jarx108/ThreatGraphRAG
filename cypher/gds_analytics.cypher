// ThreatGraph - Graph Data Science analytics (Neo4j GDS 2.x / 2026.x)
//
// Runnable on its own:   cypher-shell -u neo4j -p <pw> -f cypher/gds_analytics.cypher
// or via Python:         python -m threatgraph.graph.analytics
// (the Python module executes these exact statements, split on the
//  "// @name" markers, and records their results in results/graph_analytics.json).
//
// Only MITRE-asserted CTI edges (r.source = 'mitre_attack_stix') are
// projected; LLM-extracted edges and the Chunk/Document provenance layer are
// excluded so the analytics describe the verified knowledge graph.
// Algorithms run with concurrency 1 so results are deterministic run to run.

// @name drop_projection
CALL gds.graph.drop('threatgraph', false) YIELD graphName
RETURN graphName;

// @name project
MATCH (s)-[r:USES|MITIGATES|ATTRIBUTED_TO]->(t)
WHERE r.source = 'mitre_attack_stix'
WITH gds.graph.project(
  'threatgraph', s, t,
  {sourceNodeLabels: labels(s), targetNodeLabels: labels(t), relationshipType: type(r)},
  {undirectedRelationshipTypes: ['*']}
) AS g
RETURN g.graphName AS graph, g.nodeCount AS nodes, g.relationshipCount AS relationships;

// @name pagerank
CALL gds.pageRank.write('threatgraph', {
  writeProperty: 'pagerank', maxIterations: 50, dampingFactor: 0.85, concurrency: 1
})
YIELD nodePropertiesWritten, ranIterations, didConverge
RETURN nodePropertiesWritten, ranIterations, didConverge;

// @name louvain
CALL gds.louvain.write('threatgraph', {writeProperty: 'community', concurrency: 1})
YIELD communityCount, modularity, ranLevels
RETURN communityCount, modularity, ranLevels;

// @name wcc
CALL gds.wcc.write('threatgraph', {writeProperty: 'component', concurrency: 1})
YIELD componentCount, componentDistribution
RETURN componentCount, componentDistribution.max AS largestComponent;

// @name degree
CALL gds.degree.write('threatgraph', {writeProperty: 'degree', concurrency: 1})
YIELD nodePropertiesWritten, centralityDistribution
RETURN nodePropertiesWritten, centralityDistribution.mean AS meanDegree, centralityDistribution.max AS maxDegree;

// @name drop_after
CALL gds.graph.drop('threatgraph', false) YIELD graphName
RETURN graphName;

// ---------------------------------------------------------------------------
// Read-back queries over the written properties
// ---------------------------------------------------------------------------

// @name top_pagerank
MATCH (n) WHERE n.pagerank IS NOT NULL
WITH labels(n)[0] AS label, n ORDER BY n.pagerank DESC, n.attack_id
WITH label, collect({attack_id: n.attack_id, name: n.name, pagerank: n.pagerank, degree: n.degree})[0..10] AS top
RETURN label, top ORDER BY label;

// @name communities
MATCH (n) WHERE n.community IS NOT NULL
WITH n.community AS community, n ORDER BY n.pagerank DESC, n.attack_id
WITH community, count(*) AS size,
     collect({attack_id: n.attack_id, name: n.name, label: labels(n)[0]}) AS members
RETURN community, size,
       size([m IN members WHERE m.label = 'ThreatGroup']) AS groups,
       size([m IN members WHERE m.label = 'Software']) AS software,
       size([m IN members WHERE m.label = 'Technique']) AS techniques,
       size([m IN members WHERE m.label = 'Mitigation']) AS mitigations,
       size([m IN members WHERE m.label = 'Campaign']) AS campaigns,
       members[0..8] AS top_members
ORDER BY size DESC, community LIMIT 12;

// @name label_counts
MATCH (n) WHERE n.pagerank IS NOT NULL
RETURN labels(n)[0] AS label, count(*) AS nodes, avg(n.degree) AS avg_degree ORDER BY label;

// Path calculation: which mitigations cover the most of a group's techniques
// (counts Group-USES->Technique<-MITIGATES-Mitigation paths; the same signal
// GraphRAG adds to its prompt). Example group: APT29 (G0016).
// @name mitigation_coverage_example
MATCH (g:ThreatGroup {attack_id: 'G0016'})-[u:USES]->(t:Technique)<-[m:MITIGATES]-(mit:Mitigation)
WHERE u.source = 'mitre_attack_stix' AND m.source = 'mitre_attack_stix'
WITH g, mit, count(DISTINCT t) AS covered
MATCH (g)-[u2:USES]->(t2:Technique) WHERE u2.source = 'mitre_attack_stix'
WITH g, mit, covered, count(DISTINCT t2) AS total
RETURN g.name AS group_name, mit.attack_id AS attack_id, mit.name AS mitigation, covered, total
ORDER BY covered DESC, attack_id LIMIT 10;

// Path calculation: shortest connection between two threat groups.
// @name shortest_path_example
MATCH (a:ThreatGroup {attack_id: 'G0016'}), (b:ThreatGroup {attack_id: 'G0007'})
MATCH p = shortestPath((a)-[:USES|MITIGATES|ATTRIBUTED_TO*..4]-(b))
RETURN [n IN nodes(p) | coalesce(n.attack_id, '') + ' ' + coalesce(n.name, '')] AS path, length(p) AS hops;
