document.addEventListener("DOMContentLoaded", () => {
  // --- 1. PASTE YOUR VIRUSTOTAL API KEY HERE ---
  const VT_API_KEY =
    "f2d3b77e0fc8fcc3e4adefdaa179a89feb6575c2166363b2f8f7be22770076e3";

  // --- Element References & Whitelist ---
  const urlInput = document.getElementById("urlInput");
  const checkButton = document.getElementById("checkButton");
  const resultContainer = document.getElementById("resultContainer");
  const loadingSpinner = document.getElementById("loadingSpinner");
  const placeholderText = document.getElementById("placeholderText");
  const WHITELIST = new Set([
    "google.com",
    "youtube.com",
    "github.com",
    "wikipedia.org",
  ]);

  // --- Event Listeners ---
  checkButton.addEventListener("click", handleCheck);
  urlInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") handleCheck();
  });

  // --- Main Handler ---
  async function handleCheck() {
    const urlString = urlInput.value.trim();
    if (!urlString) return;

    showLoading(true);
    clearResults();

    // --- THE CORRECT LOGIC FLOW ---
    try {
      // 1. Check our own whitelist first for instant results on trusted sites.
      const urlForWhitelist = new URL(normalizeUrl(urlString));
      const mainDomain = urlForWhitelist.hostname
        .split(".")
        .slice(-2)
        .join(".");
      if (WHITELIST.has(mainDomain)) {
        displayResult({
          status: "safe",
          message: "This domain is on the whitelist and is trusted.",
        });
        return; // Stop further checks
      }

      // 2. Query VirusTotal API
      const vtResult = await queryVirusTotal(urlString);

      // 3. Analyze the API response
      if (vtResult.isMalicious) {
        // If VT says it's bad, we're done. Verdict is DANGER.
        displayResult({
          status: "danger",
          message: `High risk! Flagged as malicious by VirusTotal.`,
          issues: [
            {
              rule: "Live Threat Database",
              description: `Flagged by ${vtResult.maliciousCount} security vendors.`,
            },
          ],
        });
      } else if (vtResult.wasFound) {
        // If VT knows about it and it's clean, we're done. Verdict is SAFE.
        displayResult({
          status: "safe",
          message: "Considered safe by VirusTotal.",
        });
      } else {
        // If VT has NEVER seen it (404 Not Found), fall back to our static analysis.
        const staticAnalysis = analyzeStatically(urlString);
        displayResult(staticAnalysis);
      }
    } catch (error) {
      console.error("Critical Error:", error.message);
      // If the API key is wrong or VT is down, show a clear error.
      displayResult({
        status: "error",
        message: `API Error: ${error.message}. Could not contact scan service.`,
      });
    } finally {
      showLoading(false);
    }
  }

  // --- API Function ---
  async function queryVirusTotal(urlToScan) {
    // We can't scan a local file path
    if (urlToScan.startsWith("file:")) {
      return { wasFound: false, isMalicious: false, maliciousCount: 0 };
    }
    const encodedUrl = btoa(urlToScan).replace(/=/g, "");
    const apiUrl = `https://www.virustotal.com/api/v3/urls/${encodedUrl}`;

    const response = await fetch(apiUrl, {
      headers: { "x-apikey": VT_API_KEY },
    });

    if (response.status === 404) {
      // This is NOT an error. It's a valid response meaning the URL is unknown.
      return { wasFound: false, isMalicious: false, maliciousCount: 0 };
    }
    if (response.status === 401) {
      throw new Error("Invalid API Key. Please check your key in script.js.");
    }
    if (!response.ok) {
      throw new Error(`API responded with status: ${response.status}`);
    }

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;
    const maliciousCount = stats.malicious + stats.suspicious;

    return {
      wasFound: true,
      isMalicious: maliciousCount > 0,
      maliciousCount: maliciousCount,
    };
  }

  // --- Static Analysis (Our fallback for unknown URLs) ---
  function analyzeStatically(urlString) {
    try {
      const url = new URL(normalizeUrl(urlString));
      const hostname = url.hostname.toLowerCase();
      const issues = [];

      if (hostname.includes("xn--")) {
        issues.push({ rule: "Punycode Domain", level: "danger" });
      }
      if (/(g00gle|micros0ft|paypa1|faceb00k)/.test(hostname)) {
        issues.push({ rule: "Potential Misspelling", level: "danger" });
      }
      if (
        ["login", "secure", "account", "password", "verify"].some((k) =>
          (hostname + url.pathname).includes(k)
        )
      ) {
        issues.push({ rule: "Suspicious Keyword", level: "suspicious" });
      }

      if (issues.some((i) => i.level === "danger"))
        return {
          status: "danger",
          message: "High risk! Failed static analysis of an unknown URL.",
          issues,
        };
      if (issues.length > 0)
        return {
          status: "suspicious",
          message:
            "Potentially unsafe. This unknown URL has suspicious traits.",
          issues,
        };

      // If an unknown URL passes static checks, it's *still* suspicious because we don't know its reputation.
      return {
        status: "suspicious",
        message:
          "URL is unknown to VirusTotal and has no obvious static flaws. Proceed with caution.",
        issues: [],
      };
    } catch (e) {
      return { status: "error", message: "Invalid URL format." };
    }
  }

  // --- UI Helpers --- (These are simplified and correct)
  function showLoading(isLoading) {
    loadingSpinner.style.display = isLoading ? "block" : "none";
    if (isLoading) placeholderText.style.display = "none";
  }

  function clearResults() {
    resultContainer.innerHTML = "";
    resultContainer.appendChild(loadingSpinner); // Keep the spinner element
    resultContainer.appendChild(placeholderText); // Keep the placeholder element
  }

  function displayResult(analysis) {
    clearResults();
    placeholderText.style.display = "none"; // Always hide placeholder when showing a result

    let headerClass = "",
      icon = "",
      message = analysis.message;

    switch (analysis.status) {
      case "safe":
        headerClass = "safe";
        icon = "✅";
        break;
      case "suspicious":
        headerClass = "suspicious";
        icon = "⚠️";
        break;
      case "danger":
        headerClass = "danger";
        icon = "🚨";
        break;
      case "error":
        headerClass = "danger";
        icon = "🚨";
        break;
    }

    const header = document.createElement("div");
    header.className = `result-header ${headerClass}`;
    header.innerHTML = `<span>${icon}</span> ${message}`;
    resultContainer.appendChild(header);

    if (analysis.issues && analysis.issues.length > 0) {
      const list = document.createElement("ul");
      list.className = "result-details";
      analysis.issues.forEach((issue) => {
        const item = document.createElement("li");
        item.innerHTML = `<strong>${issue.rule}</strong>: ${
          issue.description || "Detected"
        }`;
        list.appendChild(item);
      });
      resultContainer.appendChild(list);
    }
  }

  function normalizeUrl(urlString) {
    if (!/^https?:\/\//i.test(urlString)) return `https://${urlString}`;
    return urlString;
  }
});
