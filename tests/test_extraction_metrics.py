from threatgraph.eval.extraction_metrics import classify_false_positives, score_extractions


def test_perfect_match():
    gold = {("G0016", "USES", "T1055")}
    m = score_extractions(gold, set(gold))
    assert m.precision == 1.0 and m.recall == 1.0 and m.f1 == 1.0
    assert m.true_positives == 1 and m.false_positives == 0 and m.false_negatives == 0


def test_no_overlap():
    gold = {("G0016", "USES", "T1055")}
    predicted = {("G9999", "USES", "T9999")}
    m = score_extractions(gold, predicted)
    assert m.precision == 0.0 and m.recall == 0.0 and m.f1 == 0.0
    assert m.false_positives == 1 and m.false_negatives == 1


def test_empty_predicted_scores_zero_not_crash():
    gold = {("G0016", "USES", "T1055")}
    m = score_extractions(gold, set())
    assert m.precision == 0.0 and m.recall == 0.0 and m.n_predicted == 0


def test_classify_false_positives_separates_real_from_hallucinated():
    # G0016 (APT29) USES S0154 (Cobalt Strike) is a real STIX relationship
    # that is very unlikely to be one of the 60 sampled gold triples at any
    # given time; a fabricated pair almost certainly is not a real edge.
    fps = [("G0016", "USES", "S0154"), ("G9999", "USES", "T9999")]
    breakdown = classify_false_positives(fps, true_positives=1, n_predicted=3)
    assert breakdown.n_total == 2
    assert breakdown.n_genuine_fact_outside_sample + breakdown.n_hallucinated == 2
    assert ("G9999", "USES", "T9999") in breakdown.hallucinated_triples
    assert breakdown.adjusted_precision >= 1 / 3


def test_partial_overlap_f1():
    gold = {("G1", "USES", "T1"), ("G1", "USES", "T2"), ("G1", "USES", "T3"), ("G1", "USES", "T4")}
    predicted = {("G1", "USES", "T1"), ("G1", "USES", "T2"), ("G1", "USES", "T9")}
    m = score_extractions(gold, predicted)
    assert m.true_positives == 2
    assert m.precision == 2 / 3
    assert m.recall == 2 / 4
    assert round(m.f1, 4) == round(2 * (2 / 3) * (1 / 2) / ((2 / 3) + (1 / 2)), 4)
