# URL phishing-detection workflow

```mermaid
flowchart TD
    A["User submits URL in web scanner<br/>or opens an HTTP(S) page in the extension"] --> B["Client sends POST /predict<br/>{ url } to local FastAPI backend"]
    B --> C["Extract registered domain and suffix<br/>using tldextract"]
    C --> D{"Exact base domain<br/>in trusted allowlist?"}

    D -- Yes --> E["Return legitimate<br/>confidence 0.99<br/>stage: allowlist"]
    D -- No --> F["Extract lexical URL features<br/>length, host, path, symbols,<br/>keywords, TLD, etc."]
    F --> G["Generate human-readable reasons<br/>(explanation only; not model input)"]
    F --> H["Build model input row<br/>in lexical_features.pkl column order"]
    H --> I["Stage 1 model<br/>calculate phishing probability p1"]
    I --> J{"Confident?<br/>p1 ≥ 0.90 or p1 ≤ 0.10"}

    J -- Yes --> K["Use Stage 1 probability<br/>stage: stage1_fast"]
    J -- No --> L["Stage 2 model<br/>calculate phishing probability p2<br/>stage: stage2_deep"]

    K --> M{"Selected probability ≥ 0.50?"}
    L --> M
    M -- Yes --> N["Verdict: phishing<br/>confidence = selected probability"]
    M -- No --> O["Verdict: legitimate<br/>confidence = 1 − selected probability"]

    N --> P["Save scan to SQLite logs"]
    O --> P
    P --> Q["Return URL, verdict, confidence,<br/>stage_used, and reasons"]
    E --> Q

    Q --> R{"Which client?"}
    R -- Web frontend --> S["Show verdict and confidence;<br/>user can report the scanned domain"]
    R -- Extension popup --> T["Show verdict, confidence,<br/>reasons, and report action"]
    R -- Extension background --> U["Set extension badge;<br/>show page warning if phishing"]

    S -. "Report as suspected phishing" .-> V["POST /report<br/>{ domain, reason }"]
    T -. "Report as suspected phishing" .-> V
    V --> W["Stores community report and returns<br/>domain and report count"]
    W -.-> X["Shown in dashboard top-reported domains;<br/>does not currently feed into /predict"]
```

## Decision details

- The trusted-domain check happens before feature extraction and model inference. It matches the extracted `domain.suffix` string against the allowlist.
- The feature extractor normalizes a trailing slash for feature calculation, then creates lexical signals from the URL. The model uses those feature values in the order saved in `lexical_features.pkl`.
- Stage 1 handles confident predictions. Only uncertain predictions—where the Stage 1 phishing probability is strictly between `0.10` and `0.90`—are sent to Stage 2.
- The final phishing/legitimate cutoff is `0.50`. Confidence is the probability of the returned class.
- Human-readable reasons are generated from URL features for explanation; they do not change the model verdict.
- Users can report a scanned domain from either the web scanner or extension, regardless of the predicted verdict. Successful reports are stored in SQLite and shown in the dashboard's top-reported domains; they do not currently feed into `/predict`.
- The backend currently writes model-path scans to SQLite, but the allowlist branch returns before that logging code.
