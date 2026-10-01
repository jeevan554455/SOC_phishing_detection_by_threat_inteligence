import os
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
from ioc_analyzer import analyze_text, enrich_with_virustotal

load_dotenv()
app = Flask(__name__)

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/analyze")
def analyze():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "Paste an email, alert, URL, or log snippet."}), 400

    result = analyze_text(text)

    if os.getenv("VIRUSTOTAL_API_KEY"):
        try:
            result["virustotal"] = enrich_with_virustotal(
                result["iocs"], os.getenv("VIRUSTOTAL_API_KEY")
            )
        except Exception as exc:
            result["virustotal"] = {"status": "error", "message": str(exc)}
    else:
        result["virustotal"] = {
            "status": "not_configured",
            "message": "VirusTotal is disabled. Add your own key to .env to enable it."
        }
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
