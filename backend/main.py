"""
FastAPI backend: /predict (cascade model), /report (community flag),
/stats (dashboard numbers). SQLite for storage -- zero setup needed.
Run: uvicorn main:app --reload
"""
import sqlite3
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from feature_extractor import extract_lexical_features, _tld_extractor
from feature_extractor import generate_reasons

app = FastAPI(title="Phishing Detector API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

stage1_model = joblib.load("models/stage1_model.pkl")
stage2_model = joblib.load("models/stage2_model.pkl")
lexical_features = joblib.load("models/lexical_features.pkl")
CONFIDENCE_THRESHOLD = 0.90

# ---- tiny SQLite setup ----
conn = sqlite3.connect("phishing.db", check_same_thread=False)
conn.execute("""CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, verdict TEXT,
    confidence REAL, stage_used TEXT, ts TEXT)""")
conn.execute("""CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT, reason TEXT, ts TEXT)""")
conn.commit()


class URLRequest(BaseModel):
    url: str


class ReportRequest(BaseModel):
    domain: str
    reason: str = "user reported"


# NOTE: atlassian.net removed -- it hosts customer subdomains, so a phishing page on
# evil.atlassian.net would have skipped the model. Same risk exists for google.com
# (docs/sites.google.com); mention it as a limitation in the report.
ALLOWLIST_DOMAINS = {
    'google.com', 'youtube.com', 'github.com', 'chatgpt.com', 'openai.com',
    'wikipedia.org', 'amazon.com', 'amazon.in', 'microsoft.com', 'apple.com',
    'facebook.com', 'instagram.com', 'linkedin.com', 'twitter.com', 'x.com',
    'geeksforgeeks.org', 'stackoverflow.com', 'netflix.com', 'reddit.com',
}

# ---- explainability: human-readable names of the 56 features ----
FRIENDLY = {
    "length_url": "URL length", "length_hostname": "hostname length", "ip": "IP address used as host",
    "nb_dots": "number of dots", "nb_hyphens": "number of hyphens", "nb_at": "'@' symbols",
    "nb_qm": "'?' characters", "nb_and": "'&' characters", "nb_or": "'|' characters", "nb_eq": "'=' characters",
    "nb_underscore": "underscores", "nb_tilde": "'~' characters", "nb_percent": "'%' characters",
    "nb_slash": "number of slashes", "nb_star": "'*' characters", "nb_colon": "':' characters",
    "nb_comma": "commas", "nb_semicolon": "semicolons", "nb_dollar": "'$' characters", "nb_space": "spaces",
    "nb_com": "'com' occurrences", "nb_dslash": "'//' inside the path", "http_in_path": "'http' inside the path",
    "https_token": "'https' token inside the URL", "ratio_digits_url": "share of digits in the URL",
    "ratio_digits_host": "share of digits in the hostname", "punycode": "punycode (look-alike characters)",
    "port": "non-standard port", "tld_in_path": "TLD text inside the path",
    "tld_in_subdomain": "TLD text inside the subdomain", "abnormal_subdomain": "abnormal subdomain pattern",
    "nb_subdomains": "number of subdomains", "prefix_suffix": "hyphen inside the domain name",
    "random_domain": "random-looking domain name", "shortening_service": "URL shortening service",
    "path_extension": "file extension in the path", "nb_redirection": "redirection markers ('//')",
    "nb_external_redirection": "external redirections", "length_words_raw": "number of words in the URL",
    "char_repeat": "repeated characters", "shortest_words_raw": "shortest word length (URL)",
    "shortest_word_host": "shortest word length (host)", "shortest_word_path": "shortest word length (path)",
    "longest_words_raw": "longest word length (URL)", "longest_word_host": "longest word length (host)",
    "longest_word_path": "longest word length (path)", "avg_words_raw": "average word length (URL)",
    "avg_word_host": "average word length (host)", "avg_word_path": "average word length (path)",
    "phish_hints": "phishing keywords (login, secure, verify...)",
    "domain_in_brand": "domain name matches a known brand", "brand_in_subdomain": "brand name in the subdomain",
    "brand_in_path": "brand name in the path", "suspicious_tld": "suspicious top-level domain",
    "statistical_report": "match with reported phishing hosts", "word_vowel_ratio": "vowel ratio of words in the URL",
}


def explain(model, row_df, label, top_k=3):
    """Top features that pushed the verdict (XGBoost contributions). Never breaks /predict."""
    try:
        contribs = model.get_booster().predict(xgb.DMatrix(row_df), pred_contribs=True)[0][:-1]
        names = list(row_df.columns)
        phishing = label == "phishing"
        order = np.argsort(contribs)[::-1] if phishing else np.argsort(contribs)
        out = []
        for i in order[:top_k]:
            if (phishing and contribs[i] <= 0) or (not phishing and contribs[i] >= 0):
                break
            value = row_df.iloc[0, i]
            value = round(float(value), 2) if isinstance(value, (float, np.floating)) else int(value)
            prefix = "Higher risk" if phishing else "Lower risk"
            out.append(f"{prefix}: {FRIENDLY.get(names[i], names[i])} ({value})")
        return out
    except Exception:
        return []


@app.post("/predict")

def predict(req: URLRequest):
    ext = _tld_extractor(req.url)
    base_domain = f"{ext.domain}.{ext.suffix}"
    reasons = []

    if base_domain in ALLOWLIST_DOMAINS:
        label = "legitimate"
        confidence = 0.99
        stage_used = "allowlist"

        reasons = [
            "The domain is present in the trusted allowlist"
        ]

    else:
        raw = extract_lexical_features(req.url)

        # Generate human-readable explanations
        reasons = generate_reasons(raw, req.url)

        lex_row = pd.DataFrame(
            [[raw.get(f, 0) for f in lexical_features]],
            columns=lexical_features
        )

        proba1 = stage1_model.predict_proba(lex_row)[0][1]

        confident = (
            proba1 >= CONFIDENCE_THRESHOLD
            or proba1 <= (1 - CONFIDENCE_THRESHOLD)
        )

        if confident:
            verdict_proba = proba1
            stage_used = "stage1_fast"
        else:
            verdict_proba = stage2_model.predict_proba(lex_row)[0][1]
            stage_used = "stage2_deep"

        label = "phishing" if verdict_proba >= 0.5 else "legitimate"

        confidence = float(
            verdict_proba if label == "phishing"
            else 1 - verdict_proba
        )

        reasons = explain(stage1_model, lex_row, label)

    # Save prediction in database
    conn.execute(
        "INSERT INTO logs (url, verdict, confidence, stage_used, ts) VALUES (?,?,?,?,?)",
        (req.url, label, confidence, stage_used, datetime.utcnow().isoformat())
    )
    conn.commit()

    # Return prediction result
    return {
        "url": req.url,
        "verdict": label,
        "confidence": round(confidence, 4),
        "stage_used": stage_used,
        "reasons": reasons
    }

@app.post("/report")
def report(req: ReportRequest):
    conn.execute("INSERT INTO reports (domain, reason, ts) VALUES (?,?,?)",
                 (req.domain, req.reason, datetime.utcnow().isoformat()))
    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM reports WHERE domain=?", (req.domain,)).fetchone()[0]
    return {"domain": req.domain, "total_reports": count, "blocklisted": count >= 3}


@app.get("/stats")
def stats():
    total = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    phishing = conn.execute("SELECT COUNT(*) FROM logs WHERE verdict='phishing'").fetchone()[0]
    recent = conn.execute("SELECT url, verdict, confidence, ts FROM logs ORDER BY id DESC LIMIT 10").fetchall()
    top_reports = conn.execute("""SELECT domain, COUNT(*) c FROM reports
                                   GROUP BY domain ORDER BY c DESC LIMIT 5""").fetchall()
    return {
        "total_scans": total,
        "phishing_blocked": phishing,
        "recent": [{"url": r[0], "verdict": r[1], "confidence": r[2], "ts": r[3]} for r in recent],
        "top_reported": [{"domain": r[0], "count": r[1]} for r in top_reports],
    }


@app.get("/")
def root():
    return {"status": "running"}