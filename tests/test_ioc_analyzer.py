from ioc_analyzer import analyze_text

def test_ioc_extraction():
    r=analyze_text("Urgent verify https://paypa1-security.example/verify 185.10.20.30 Invoice.zip")
    assert "https://paypa1-security.example/verify" in r["iocs"]["urls"]
    assert "185.10.20.30" in r["iocs"]["ips"]
    assert "Invoice.zip" in r["iocs"]["attachments"]
    assert r["risk_score"] > 0
