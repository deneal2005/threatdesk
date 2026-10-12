import evaluate
from evaluate import Row, format_report, metrics


def test_metrics_and_report_formatting():
    rows = [Row(2, "https://a.example", "scam", verdict="High risk", score=80, signals=["scam_list_hit"]),
            Row(3, "https://b.example", "scam", verdict="No strong signals", score=10, signals=["urgency"]),
            Row(4, "https://c.example", "legit", verdict="Medium risk", score=45),
            Row(5, "https://d.example", "legit", verdict="Insufficient data"),
            Row(6, "https://e.example", "scam", error="ConnectError: boom")]
    m = metrics(rows)
    assert (m["tp"], m["fn"], m["fp"], m["tn"], m["errors"], m["insufficient"]) == (1, 1, 1, 1, 1, 1)
    assert m["precision"] == 0.5 and m["recall"] == 0.5
    text = format_report(rows, m)
    assert "precision 50%  recall 50%" in text and "Misses:" in text and "b.example: No strong signals 10 urgency" in text


def test_empty_missing_and_bad_testset(tmp_path, capsys):
    assert evaluate.main([str(tmp_path / "nope.csv")]) == 2
    empty = tmp_path / "empty.csv"
    empty.write_text("url,label,brand_optional\n")
    assert evaluate.main([str(empty)]) == 2
    bad = tmp_path / "bad.csv"
    bad.write_text("url,label,brand_optional\nhttps://x.example,maybe,\n")
    assert evaluate.main([str(bad)]) == 2
    assert "line 2" in capsys.readouterr().err
