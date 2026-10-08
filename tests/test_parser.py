import json
import unittest
from scripts.parse_extraction import parse_extraction, ExtractionValidationError

VALID = {
    "entities": [
        {"name":"APT29","entity_type":"ThreatGroup","attack_id":"G0016",
         "aliases":[],"confidence_score":0.99},
        {"name":"Process Injection","entity_type":"Technique","attack_id":"T1055",
         "aliases":[],"confidence_score":0.99}
    ],
    "relationships": [
        {"source":"APT29","predicate":"USES","target":"Process Injection",
         "evidence_text":"APT29 uses Process Injection.","confidence_score":0.95}
    ]
}

class ParserTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(parse_extraction(json.dumps(VALID))["relationships"][0]["predicate"], "USES")

    def test_malformed_json(self):
        with self.assertRaises(ExtractionValidationError):
            parse_extraction("{not-json}")

    def test_bad_predicate(self):
        x = json.loads(json.dumps(VALID))
        x["relationships"][0]["predicate"] = "INVENTED"
        with self.assertRaises(ExtractionValidationError):
            parse_extraction(json.dumps(x))

    def test_out_of_range_confidence(self):
        x = json.loads(json.dumps(VALID))
        x["entities"][0]["confidence_score"] = 1.2
        with self.assertRaises(ExtractionValidationError):
            parse_extraction(json.dumps(x))

if __name__ == "__main__":
    unittest.main()
