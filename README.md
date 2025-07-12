**🛡️ PhishGuard – A Dynamic Phishing URL Detector**

PhishGuard is an intelligent, client-side security tool that analyzes URLs to detect potential phishing threats in real-time. It leverages a hybrid approach, combining a live threat intelligence feed from the **VirusTotal API** with a robust set of **local, static analysis rules** to provide a multi-layered defense against malicious links.

 <img width="1413" height="883" alt="image" src="https://github.com/user-attachments/assets/6994d9cf-1db6-49b1-af17-c1fb5490b07d" />

---

##  Core Features

*   **Dynamic Threat Intelligence:** Connects directly to the VirusTotal API to check URLs against a database of over 70 antivirus scanners and URL blocklist services.
*   **Hybrid Analysis Engine:** If a URL is unknown to VirusTotal, PhishGuard uses its own static rule-based engine as a fallback to catch zero-day threats.
*   **Professional Two-Step Verification:** Mimics real-world security tools by first checking the reputation of the entire **domain** and then analyzing the **specific URL**, ensuring higher accuracy.
*   **Comprehensive Static Rules:** Detects common phishing patterns including:
    *   **Punycode Attacks (`xn--`):** Catches domains impersonating brands with non-ASCII characters.
    *   **Leetspeak (`g00gle.com`):** Flags common character substitutions.
    *   **Suspicious Keywords:** Scans for high-risk keywords like `login`, `secure`, `verify`, etc.
*   **Privacy-Focused:** All analysis happens in the browser. User-entered URLs are sent directly to the VirusTotal API.
*   **Modern & Responsive UI:** Clean, intuitive interface with clear "Safe," "Suspicious," and "Danger" verdicts, including explanations for why a URL was flagged.

---

## ⚙️ How It Works

PhishGuard follows a professional, multi-step verification process to determine the safety of a URL:

1.  **Whitelist Check:** The URL is first checked against a local whitelist of trusted domains. If a match is found, it is immediately flagged as **Safe** and no further checks are performed.
2.  **Domain Reputation Check:** The tool extracts the main domain from the URL (e.g., `example.com`) and queries the VirusTotal API for its reputation. If the domain itself is flagged as malicious by security vendors, the URL is immediately marked as **Danger**.
3.  **Full URL Reputation Check:** If the domain is clean, the *entire* specific URL is then sent to VirusTotal. This catches cases where a single malicious page is hosted on an otherwise legitimate domain. If flagged, it's marked as **Danger**.
4.  **Static Analysis Fallback:** If the URL and its domain are completely unknown to VirusTotal (a potential zero-day threat), PhishGuard's local static analysis engine scans the URL for suspicious patterns (Punycode, misspellings, keywords). The result is then marked as **Suspicious** or **Danger** based on the rules triggered.
5.  **Final Verdict:** The user is presented with a clear, color-coded result and an explanation of the findings.

This hierarchical approach ensures both speed (from whitelisting) and high accuracy (from the API and static rules), providing a robust defense against a wide range of threats.

---

## 🔬 Known Limitations

This project is a powerful demonstration of front-end and API integration skills, but it's important to understand its boundaries:

*   **URL Redirects:** The tool does not currently follow URL redirects (e.g., from `bit.ly` or `t.co`). It analyzes the shortener link itself, not its final destination. Resolving redirects safely requires a server-side component to bypass browser CORS (Cross-Origin Resource Sharing) security policies.
*   **API Rate Limiting:** This version uses a free VirusTotal API key, which is limited to 4 requests per minute. This is more than enough for personal use and testing, but would require a premium key for a commercial-scale application.

This project successfully demonstrates a deep understanding of these concepts and provides a strong foundation for a full-stack security application.
