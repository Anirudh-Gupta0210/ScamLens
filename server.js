const express = require("express");
const dotenv = require("dotenv");
const net = require("node:net");

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 3000;

const allowedOrigins = new Set([
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "https://anirudh-gupta0210.github.io"
]);

app.use((req, res, next) => {
    const origin = req.headers.origin;

    if (origin && allowedOrigins.has(origin)) {
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Vary", "Origin");
    }

    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
        return res.sendStatus(204);
    }

    next();
});

app.use(express.json({ limit: "10kb" }));

app.get("/api/health", (req, res) => {
    res.json({
        status: "success",
        message: "ScamLens backend is running!"
    });
});

const knownShorteners = new Set([
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "shorturl.at",
    "ow.ly",
    "buff.ly",
    "rb.gy",
    "cutt.ly",
    "lnkd.in",
    "rebrand.ly",
    "soo.gd"
]);

const shoppingBrandDomains = {
    amazon: ["amazon.com", "amazon.in"],
    flipkart: ["flipkart.com"],
    myntra: ["myntra.com"],
    ajio: ["ajio.com"],
    meesho: ["meesho.com"],
    nike: ["nike.com"],
    adidas: ["adidas.com"],
    puma: ["puma.com"],
    apple: ["apple.com"],
    samsung: ["samsung.com"]
};

const shoppingBaitWords = [
    "outlet", "clearance", "discount", "deal", "deals",
    "sale", "offer", "offers", "cheap", "freegift", "gift"
];

const urgencyWords = [
    "urgent", "limited-time", "limitedtime", "flash-sale",
    "flashsale", "act-now", "actnow", "expires-today",
    "expirestoday", "last-chance", "lastchance"
];

const paymentWords = [
    "payment", "checkout", "billing", "wallet", "upi",
    "refund", "verify-account", "verifyaccount"
];

function isIpAddress(hostname) {
    return net.isIP(hostname) !== 0;
}

function getRiskLabel(score) {
    if (score >= 50) return "Higher risk signals";
    if (score >= 25) return "Use caution";
    return "Fewer warning signals";
}

function analyseUrl(parsedUrl) {
    let score = 0;
    const findings = [];

    const hostname = parsedUrl.hostname.toLowerCase();
    const fullUrl = parsedUrl.href;

    function addFinding(points, message) {
        score += points;
        findings.push({ points, message });
    }

    if (parsedUrl.protocol === "http:") {
        addFinding(
            10,
            "This URL uses HTTP rather than HTTPS. The connection is not encrypted."
        );
    }

    if (parsedUrl.username || parsedUrl.password) {
        addFinding(
            25,
            "The URL contains embedded credentials, which can disguise its destination."
        );
    }

    if (isIpAddress(hostname)) {
        addFinding(
            25,
            "The website uses an IP address instead of a typical domain name."
        );
    }

    if (
        hostname.startsWith("xn--") ||
        hostname.split(".").some(label => label.startsWith("xn--"))
    ) {
        addFinding(
            20,
            "The hostname contains punycode, which can be used in lookalike-domain attacks."
        );
    }

    if (knownShorteners.has(hostname)) {
        addFinding(
            15,
            "This is a URL-shortening service, so the final destination is not visible in the link."
        );
    }

    if (hostname.split(".").length >= 5) {
        addFinding(
            10,
            "The hostname has an unusually large number of subdomains."
        );
    }

    if (fullUrl.length > 200) {
        addFinding(
            15,
            "The URL is unusually long and may be difficult to inspect."
        );
    } else if (fullUrl.length > 120) {
        addFinding(
            10,
            "The URL is longer than usual and deserves closer inspection."
        );
    }

    if (hostname.includes("-")) {
        addFinding(
            5,
            "The hostname contains a hyphen. This is not proof of fraud, but should be considered with other signals."
        );
    }

    if (parsedUrl.port && !["80", "443"].includes(parsedUrl.port)) {
        addFinding(
            10,
            "The URL uses a non-standard web port."
        );
    }

    score = Math.min(score, 100);

    if (findings.length === 0) {
        findings.push({
            points: 0,
            message:
                "These basic checks did not identify the warning patterns tested. This does not mean the site is verified or safe."
        });
    }

    return {
        score,
        riskLabel: getRiskLabel(score),
        findings
    };
}

// Approximate registered-domain extraction.
// This is not a complete Public Suffix List implementation.
function getApproximateRegisteredDomain(hostname) {
    const labels = hostname
        .toLowerCase()
        .replace(/\.$/, "")
        .split(".");

    if (labels.length <= 2) {
        return labels.join(".");
    }

    const multiLabelSuffixes = new Set([
        "co.in", "com.in", "net.in", "org.in", "gov.in",
        "ac.in", "co.uk", "org.uk", "com.au", "co.nz"
    ]);

    const suffix = labels.slice(-2).join(".");

    if (multiLabelSuffixes.has(suffix)) {
        return labels.slice(-3).join(".");
    }

    return labels.slice(-2).join(".");
}

function editDistance(a, b) {
    const row = Array.from(
        { length: b.length + 1 },
        (_, i) => i
    );

    for (let i = 1; i <= a.length; i++) {
        let diagonal = row[0];
        row[0] = i;

        for (let j = 1; j <= b.length; j++) {
            const old = row[j];
            const cost = a[i - 1] === b[j - 1] ? 0 : 1;

            row[j] = Math.min(
                row[j] + 1,
                row[j - 1] + 1,
                diagonal + cost
            );

            diagonal = old;
        }
    }

    return row[b.length];
}

function normalizeLookalikeLabel(label) {
    const substitutions = {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t"
    };

    return label.replace(/[013457]/g, digit => substitutions[digit]);
}

function analyseShoppingUrl(parsedUrl) {
    const hostname = parsedUrl.hostname
        .toLowerCase()
        .replace(/\.$/, "");

    const registeredDomain =
        getApproximateRegisteredDomain(hostname);

    const registeredLabel = registeredDomain.split(".")[0];
    const labels = hostname.split(".");
    const signals = [];

    let score = 0;

    function addSignal(points, message) {
        score += points;
        signals.push({ points, message });
    }

    // Brand impersonation and lookalike detection.
    for (const [brand, officialDomains] of Object.entries(
        shoppingBrandDomains
    )) {
        const isOfficialDomain = officialDomains.some(domain =>
            hostname === domain || hostname.endsWith("." + domain)
        );

        if (isOfficialDomain) {
            continue;
        }

        const matchingLabel = labels.find(label => {
            const normalized = normalizeLookalikeLabel(label);

            return (
                normalized === brand ||
                normalized.includes(brand)
            );
        });

        if (matchingLabel) {
            const normalized =
                normalizeLookalikeLabel(matchingLabel);

            if (normalized === brand) {
                addSignal(
                    25,
                    `The hostname label "${matchingLabel}" resembles the brand "${brand}", but the registered domain is "${registeredDomain}". Verify the official website.`
                );
            } else {
                addSignal(
                    20,
                    `The hostname label "${matchingLabel}" contains the brand "${brand}", but the registered domain is "${registeredDomain}". Verify the seller independently.`
                );
            }

            break;
        }

        const closeMatch = labels.some(label => {
            if (label.length < 4) return false;

            const normalized = normalizeLookalikeLabel(label);

            return (
                normalized !== brand &&
                editDistance(normalized, brand) <=
                    (brand.length >= 8 ? 2 : 1)
            );
        });

        if (closeMatch) {
            addSignal(
                20,
                `A hostname label resembles the brand "${brand}". Check the exact registered domain before trusting the link.`
            );

            break;
        }

        if (
            registeredLabel.includes(brand) &&
            registeredLabel !== brand
        ) {
            addSignal(
                15,
                `The registered domain "${registeredDomain}" includes "${brand}" in a longer label. This does not establish brand ownership.`
            );

            break;
        }
    }

    // Multiple sale-related words in the registered domain.
    const baitCount = shoppingBaitWords.filter(word =>
        registeredLabel.includes(word)
    ).length;

    if (baitCount >= 2) {
        addSignal(
            5,
            "The registered domain combines multiple sale-related terms. This is a weak signal and can also occur on legitimate stores."
        );
    }

    // Urgency and flash-sale wording in the URL path/query.
    let decodedPathAndQuery = parsedUrl.pathname + parsedUrl.search;

    try {
        decodedPathAndQuery = decodeURIComponent(decodedPathAndQuery);
    } catch {
        // Keep the encoded form when percent-encoding is malformed.
    }

    const pathAndQuery = decodedPathAndQuery
        .toLowerCase()
        .replace(/[_\s]+/g, "-");

    const urgencyMatches = urgencyWords.filter(word =>
        pathAndQuery.includes(word)
    );

    if (urgencyMatches.length >= 2) {
        addSignal(
            8,
            "The URL combines multiple urgency or flash-sale phrases. Check the offer independently before paying."
        );
    }

    // Suspicious combinations of payment-related URL terms.
    const paymentMatches = paymentWords.filter(word =>
        pathAndQuery.includes(word)
    );

    const hasSensitivePaymentCombination =
        paymentMatches.includes("upi") &&
        (
            paymentMatches.includes("verify-account") ||
            paymentMatches.includes("verifyaccount") ||
            paymentMatches.includes("refund")
        );

    if (hasSensitivePaymentCombination) {
        addSignal(
            10,
            "The URL combines payment-related wording with account verification or refund wording. Do not share a UPI PIN or OTP."
        );
    }

    // Several discount signals together.
    const discountMatches = [
        /(?:\b|[-_])\d{2,3}[-_]?percent(?:\b|[-_])/i,
        /(?:\b|[-_])\d{2,3}off(?:\b|[-_])/i,
        /free[-_]?gift/i,
        /mega[-_]?sale/i
    ].filter(pattern =>
        pattern.test(hostname + parsedUrl.pathname + parsedUrl.search)
    ).length;

    if (discountMatches >= 2) {
        addSignal(
            5,
            "The URL combines several unusually promotional terms. Compare the offer with the seller's official store."
        );
    }

    return {
        registeredDomain,
        score: Math.min(score, 40),
        signals
    };
}

// URLhaus checks URLs associated with malware distribution.
// ScamLens does not open the submitted website.
async function checkUrlhaus(url) {
    const authKey = process.env.URLHAUS_AUTH_KEY;

    if (!authKey || !authKey.trim()) {
        return {
            status: "not_configured",
            provider: "URLhaus",
            message: "URLhaus is not configured. Local URL checks still ran."
        };
    }

    try {
        const response = await fetch(
            "https://urlhaus-api.abuse.ch/v1/url/",
            {
                method: "POST",
                headers: {
                    "Auth-Key": authKey.trim(),
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body: new URLSearchParams({ url }),
                signal: AbortSignal.timeout(8000)
            }
        );

        if (!response.ok) {
            console.error("URLhaus returned HTTP status:", response.status);

            return {
                status: "unavailable",
                provider: "URLhaus",
                message: "URLhaus could not complete the reputation check."
            };
        }

        const data = await response.json();

        if (data.query_status === "ok") {
            return {
                status: "listed",
                provider: "URLhaus",
                threat: data.threat || "Malware-related activity",
                urlStatus: data.url_status || "unknown",
                dateAdded: data.date_added || null,
                tags: Array.isArray(data.tags) ? data.tags : [],
                message:
                    "URLhaus lists this URL in its database of URLs associated with malware distribution."
            };
        }

        if (data.query_status === "no_results") {
            return {
                status: "not_listed",
                provider: "URLhaus",
                message:
                    "URLhaus did not find this URL in its database. This does not guarantee the website is safe."
            };
        }

        return {
            status: "unavailable",
            provider: "URLhaus",
            message: "URLhaus returned an unexpected response."
        };
    } catch (error) {
        console.error(
            "URLhaus check failed:",
            error.name || error.message
        );

        return {
            status: "unavailable",
            provider: "URLhaus",
            message:
                "URLhaus could not be reached. The local URL checks still ran."
        };
    }
}

// VirusTotal checks an existing URL report only.
// ScamLens does not submit new URLs for analysis.
async function checkVirusTotal(url) {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;

    if (!apiKey || !apiKey.trim()) {
        return {
            status: "not_configured",
            provider: "VirusTotal",
            message: "VirusTotal is not configured."
        };
    }

    try {
        const urlId = Buffer.from(url).toString("base64url");

        const response = await fetch(
            `https://www.virustotal.com/api/v3/urls/${urlId}`,
            {
                method: "GET",
                headers: {
                    "x-apikey": apiKey.trim()
                },
                signal: AbortSignal.timeout(8000)
            }
        );

        if (response.status === 404) {
            return {
                status: "no_report",
                provider: "VirusTotal",
                message: "VirusTotal has no existing report for this URL."
            };
        }

        if (response.status === 429) {
            return {
                status: "unavailable",
                provider: "VirusTotal",
                message: "VirusTotal rate limit reached. Try again later."
            };
        }

        if (!response.ok) {
            console.error(
                "VirusTotal returned HTTP status:",
                response.status
            );

            return {
                status: "unavailable",
                provider: "VirusTotal",
                message:
                    "VirusTotal could not complete the reputation check."
            };
        }

        const data = await response.json();
        const attributes = data?.data?.attributes;
        const stats = attributes?.last_analysis_stats;

        if (!stats || typeof stats !== "object") {
            return {
                status: "no_report",
                provider: "VirusTotal",
                message:
                    "VirusTotal has no usable existing analysis for this URL."
            };
        }

        const malicious = Number(stats.malicious) || 0;
        const suspicious = Number(stats.suspicious) || 0;

        return {
            status:
                malicious > 0
                    ? "malicious"
                    : suspicious > 0
                        ? "suspicious"
                        : "analyzed",
            provider: "VirusTotal",
            malicious,
            suspicious,
            harmless: Number(stats.harmless) || 0,
            undetected: Number(stats.undetected) || 0,
            lastAnalysisDate: attributes.last_analysis_date
                ? new Date(
                    attributes.last_analysis_date * 1000
                ).toISOString()
                : null,
            message: malicious > 0
                ? `VirusTotal reports ${malicious} malicious engine detection(s) for this URL.`
                : suspicious > 0
                    ? `VirusTotal reports ${suspicious} suspicious engine detection(s) for this URL.`
                    : "VirusTotal reported no malicious or suspicious detections in its last analysis. This does not guarantee safety."
        };
    } catch (error) {
        console.error(
            "VirusTotal check failed:",
            error.name || "Unknown error"
        );

        return {
            status: "unavailable",
            provider: "VirusTotal",
            message: "VirusTotal could not be reached."
        };
    }
}

app.post("/api/scan", async (req, res) => {
    const submittedUrl = req.body?.url;

    if (typeof submittedUrl !== "string" || !submittedUrl.trim()) {
        return res.status(400).json({
            status: "error",
            message: "Please provide a URL to scan."
        });
    }

    if (submittedUrl.length > 2048) {
        return res.status(400).json({
            status: "error",
            message: "The URL is too long. Please enter a URL under 2,048 characters."
        });
    }

    let parsedUrl;

    try {
        parsedUrl = new URL(submittedUrl.trim());
    } catch {
        return res.status(400).json({
            status: "error",
            message: "Please enter a valid URL, including https:// or http://."
        });
    }

    if (
        !["http:", "https:"].includes(parsedUrl.protocol) ||
        !parsedUrl.hostname ||
        !parsedUrl.hostname.includes(".")
    ) {
        return res.status(400).json({
            status: "error",
            message: "Please enter a valid HTTP or HTTPS website URL."
        });
    }

    // Run local checks and reputation checks.
    const urlAnalysis = analyseUrl(parsedUrl);
    const shoppingAnalysis = analyseShoppingUrl(parsedUrl);

    const [reputation, virusTotal] = await Promise.all([
        checkUrlhaus(parsedUrl.href),
        checkVirusTotal(parsedUrl.href)
    ]);

    const findings = [
        ...urlAnalysis.findings,
        ...shoppingAnalysis.signals
    ];

    // Local signals have a maximum contribution of 60 points.
    const localScore = Math.min(
        urlAnalysis.score + shoppingAnalysis.score,
        60
    );

    let reputationScore = 0;

    // URLhaus: a known malware-related listing is a strong signal.
    if (reputation.status === "listed") {
        reputationScore = Math.max(reputationScore, 60);

        findings.push({
            points: 60,
            message:
                "URLhaus lists this URL as associated with malware distribution."
        });
    } else if (reputation.status === "not_listed") {
        findings.push({
            points: 0,
            message:
                "URLhaus found no listing. This does not prove the website is safe."
        });
    } else {
        findings.push({
            points: 0,
            message:
                "URLhaus could not provide a complete reputation result."
        });
    }

    // VirusTotal detections provide evidence, not a probability.
    if (virusTotal.status === "malicious") {
        const maliciousCount = Number(virusTotal.malicious) || 0;

        const vtRisk = maliciousCount >= 5
            ? 50
            : maliciousCount >= 3
                ? 40
                : 30;

        reputationScore = Math.max(reputationScore, vtRisk);

        findings.push({
            points: vtRisk,
            message:
                `VirusTotal reports ${maliciousCount} malicious detection(s).`
        });
    } else if (virusTotal.status === "suspicious") {
        reputationScore = Math.max(reputationScore, 15);

        findings.push({
            points: 15,
            message:
                `VirusTotal reports ${Number(virusTotal.suspicious) || 0} suspicious detection(s).`
        });
    } else if (virusTotal.status === "analyzed") {
        findings.push({
            points: 0,
            message:
                "VirusTotal reported no malicious or suspicious detections in its existing analysis. This does not guarantee safety."
        });
    } else {
        findings.push({
            points: 0,
            message:
                "VirusTotal did not provide a usable existing analysis. No safety assumption was made."
        });
    }

    // Combine local and reputation evidence.
    const score = Math.min(
        localScore + reputationScore,
        100
    );

    const riskLabel = score >= 70
        ? "High Risk"
        : score >= 40
            ? "Medium Risk"
            : score >= 20
                ? "Use Caution"
                : "Fewer Warning Signals";

    const recommendations = (
        reputation.status === "listed" ||
        virusTotal.status === "malicious"
    )
        ? [
            "Do not open this link or enter credentials or payment details.",
            "Verify the seller or sender using an independently obtained official contact method."
        ]
        : virusTotal.status === "suspicious" || score >= 40
            ? [
                "Pause and verify the exact registered domain independently.",
                "Do not enter passwords, OTPs, UPI PINs, or payment details until verified."
            ]
            : score >= 20
                ? [
                    "Review the warning signals and verify the website through an official source before buying."
                ]
                : [
                    "No major warning signals were identified by the checks available for this scan.",
                    "This is not proof of safety; verify the seller and payment method before buying."
                ];

    return res.json({
        status: "success",
        url: parsedUrl.href,
        score,
        riskLabel,
        recommendations,
        findings: findings.map(finding => finding.message),
        findingDetails: findings,

        shoppingAnalysis: {
            registeredDomain: shoppingAnalysis.registeredDomain,
            score: shoppingAnalysis.score,
            signals: shoppingAnalysis.signals,
            note:
                "Shopping-domain and URL-pattern checks are heuristic, not proof of fraud."
        },

        reputation,
        virusTotal,

        disclaimer:
            "This is a preliminary risk assessment, not a verified fraud verdict or probability of fraud. Shopping-domain checks are heuristic and may flag legitimate sites. URLhaus focuses on URLs associated with malware distribution and does not detect every phishing or shopping scam. A URL not listed by URLhaus, or one with no VirusTotal detections, is not guaranteed to be safe. VirusTotal results reflect an existing third-party analysis and may be unavailable or outdated. ScamLens does not visit or submit the URL for a new scan."
    });
});

// Handle invalid JSON and unexpected server errors.
app.use((err, req, res, next) => {
    if (err instanceof SyntaxError && "body" in err) {
        return res.status(400).json({
            status: "error",
            message: "The request body must contain valid JSON."
        });
    }

    console.error("ScamLens server error:", err.message);

    return res.status(500).json({
        status: "error",
        message: "An unexpected server error occurred."
    });
});

app.listen(PORT, () => {
    console.log(
        `ScamLens backend running at http://localhost:${PORT}`
    );
});