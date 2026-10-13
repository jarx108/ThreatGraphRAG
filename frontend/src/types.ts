// Shapes returned by the ThreatGraph API (src/threatgraph/api/pillars.py).

export type SystemKey = "baseline" | "threatgraph";

export interface BenchmarkQuestion {
  id: string;
  question: string;
  category?: string;
  required_hops?: number;
}

export interface Summary { mean: number | null; std: number | null; n: number }
export type SummaryMap = Record<string, Summary>;

export interface Overview {
  attack_version: string;
  llm: { provider: string; model: string };
  embedding: string;
  nodes: { label: string; n: number }[];
  edges_by_source: { source: string; n: number }[];
  headline: {
    benchmark: Record<SystemKey, SummaryMap> | null;
    n_questions?: number;
    ned_accuracy: number | null;
    ned_baseline_accuracy: number | null;
    communities: number | null;
  };
}

export interface Ingestion {
  attack_version: string;
  labels: { label: string; n: number; keys: string[] }[];
  relationships: { src: string; rel: string; tgt: string; source: string; n: number }[];
  stix_edge_example: Record<string, string | number | null> | null;
  stix_mapping: { stix_type: string; label: string }[];
  text_ingestion: {
    documents_processed: number;
    triples_resolved: number;
    edges_written: number;
    edges_verified_by_stix: number;
    verified_share: number | null;
    mean_confidence: number | null;
    by_predicate: Record<string, number>;
    ned_methods: Record<string, number>;
    model: string | null;
  } | null;
  llm_edge_examples: {
    subject: string; predicate: string; object: string; confidence: number; verified: boolean;
    model: string; evidence_text: string; source_document: string; subject_ned: string; object_ned: string;
  }[];
}

export interface RankedNode { attack_id: string; name: string; pagerank: number; degree: number }
export interface Community {
  community: number; size: number; groups: number; software: number; techniques: number;
  mitigations: number; campaigns: number; top_members: { attack_id: string; name: string; label: string }[];
}
export interface Analytics {
  available: boolean;
  computed_at?: string;
  gds_version?: string;
  projection?: { nodes: number; relationships: number; relationship_types: string[]; source_filter: string };
  topology?: { density: number; mean_degree: number; max_degree: number; components: number;
               largest_component: number; largest_component_share: number };
  pagerank?: { iterations: number; converged: boolean; top_by_label: Record<string, RankedNode[]> };
  louvain?: { communities: number; modularity: number; levels: number; largest: Community[] };
  examples?: {
    mitigation_coverage_G0016: { group_name: string; attack_id: string; mitigation: string; covered: number; total: number }[];
    shortest_path_G0016_G0007: { path: string[]; hops: number }[];
  };
}

export interface NedTally { n: number; accuracy: number | null; wrong_link: number; unlinked: number }
export interface NedEval {
  n_cases: number; n_entities: number; ambiguous_aliases_excluded: number; template: string;
  baseline_exact_name: Record<string, NedTally>;
  threatgraph_ned: Record<string, NedTally>;
}

export interface ExtractionNed {
  extraction: {
    model: string;
    sample_size_requested: number;
    sample_size_succeeded: number;
    computed_at: string | null;
    metrics: { precision: number; recall: number; f1: number; true_positives: number; false_positives: number;
               false_negatives: number; n_gold: number; n_predicted: number };
    false_positive_breakdown?: { n_genuine_fact_outside_sample: number; n_hallucinated: number; adjusted_precision: number };
  } | null;
  ned: NedEval | null;
  samples: { attack_id: string; name: string; text: string }[];
  model: string;
  provider: string;
}

export interface ExtractResult {
  entities: { mention: string; type: string; llm_attack_id: string | null; confidence: number; resolved: boolean;
              attack_id: string | null; canonical_name: string | null; method: string | null; similarity: number | null }[];
  relationships: { source: string; predicate: string; target: string; source_id: string | null; target_id: string | null;
                   confidence: number; evidence_text: string; verified: boolean | null }[];
  rejected: { kind: string; error: string }[];
  latency_seconds: number;
  cached: boolean;
  model: string;
  schema_enforced: boolean;
}

export interface Mention { text: string; start: number; end: number; attack_id: string; canonical_name: string;
                           entity_type: string; method: string }

export interface GraphFact {
  src_id: string; src_name: string; src_type: string; predicate: string;
  tgt_id: string; tgt_name: string; tgt_type: string;
  source?: string | null; stix_relationship_id?: string | null; modified?: string | null; confidence?: number | null;
}
export interface Chunk { chunk_id: string; entity_attack_id: string | null; entity_name: string | null; text: string; score: number }

export interface Scores {
  accuracy: number | null; precision: number | null; f1: number | null; fully_correct: number | null;
  hallucination: number | null; traceable: number | null; total_latency_seconds: number | null;
  cited: string[]; gold: string[]; correct: string[]; missing: string[]; unsupported: string[];
}

export interface RunView {
  system: SystemKey;
  answer: string;
  error: string | null;
  retrieval_latency_seconds: number;
  generation_latency_seconds: number;
  total_latency_seconds: number;
  generation_cached: boolean;
  retrieved_chunks: Chunk[];
  graph_facts: GraphFact[];
  linked_entities: { mention: string; attack_id: string; name: string; type: string; method: string }[];
  target_type: string | null;
  analytics: {
    seeds?: { attack_id: string; name: string; label: string; pagerank: number; rank: number; of_label: number;
              degree: number; community: number; community_size: number }[];
    coverage?: { attack_id: string; name: string; covered: number; total: number }[];
  };
  scores: Scores | null;
}

export interface AskResult { question: string; benchmark_id: string | null; gold: string[] | null; runs: Record<SystemKey, RunView> }

export interface BenchmarkResult {
  available: boolean;
  running: { id: string; done: number; total: number } | null;
  id?: string;
  finished_at?: string;
  n_questions?: number;
  metrics?: { key: string; label: string; higher_is_better: boolean }[];
  summary?: Record<SystemKey, SummaryMap>;
  by_category?: Record<string, Record<SystemKey, SummaryMap>>;
  rows?: { question_id: string; question: string; category: string; hops: number; scores: Partial<Record<SystemKey, Scores>> }[];
  config?: { llm: string; top_k_chunks: number; max_graph_facts: number };
}
