const express = require("express");
const dotenv = require("dotenv");
const net = require("node:net");
const dns = require("node:dns").promises;
const path = require("node:path");

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
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") {
        return res.sendStatus(204);
    }

    next();
});

app.use(express.json({ limit: "10kb" }));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/style.css", (req, res) => {
    res.sendFile(path.join(__dirname, "style.css"));
});

app.get("/firebase.js", (req, res) => {
    res.sendFile(path.join(__dirname, "firebase.js"));
});

app.get("/api/health", (req, res) => {
    res.json({
        status: "success",
        message: "ScamLens backend is running!"
    });
});

const knownShorteners = new Set([
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "shorturl.at", "ow.ly", "buff.ly", "rb.gy",
    "cutt.ly", "lnkd.in", "rebrand.ly", "soo.gd"
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
        addFinding(10, "The URL uses a non-standard web port.");
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
        "0": "o", "1": "i", "3": "e",
        "4": "a", "5": "s", "7": "t"
    };

    return label.replace(
        /[013457]/g,
        digit => substitutions[digit]
    );
}

function analyseShoppingUrl(parsedUrl) {
    const hostname = parsedUrl.hostname.toLowerCase().replace(/\.$/, "");
    const registeredDomain = getApproximateRegisteredDomain(hostname);
    const registeredLabel = registeredDomain.split(".")[0];
    const labels = hostname.split(".");
    const signals = [];
    let score = 0;

    function addSignal(points, message) {
        score += points;
        signals.push({ points, message });
    }

    for (const [brand, officialDomains] of Object.entries(shoppingBrandDomains)) {
        const isOfficialDomain = officialDomains.some(domain =>
            hostname === domain || hostname.endsWith("." + domain)
        );

        if (isOfficialDomain) continue;
                const matchingLabel = labels.find(label => {
            const normalized = normalizeLookalikeLabel(label);
            return normalized === brand || normalized.includes(brand);
        });

        if (matchingLabel) {
            addSignal(
                25,
                `The hostname label "${matchingLabel}" resembles the brand "${brand}", but the registered domain is "${registeredDomain}". Verify the official website.`
            );
            break;
        }

        const closeMatch = labels.some(label => {
            if (label.length < 4) return false;

            const normalized = normalizeLookalikeLabel(label);

            return normalized !== brand &&
                editDistance(normalized, brand) <= (brand.length >= 8 ? 2 : 1);
        });

        if (closeMatch) {
            addSignal(
                20,
                `A hostname label resembles the brand "${brand}". Check the exact registered domain before trusting the link.`
            );
            break;
        }

        if (registeredLabel.includes(brand) && registeredLabel !== brand) {
            addSignal(
                15,
                `The registered domain "${registeredDomain}" includes "${brand}" in a longer label. This does not establish brand ownership.`
            );
            break;
        }
    }

    const baitCount = shoppingBaitWords.filter(word =>
        registeredLabel.includes(word)
    ).length;

    if (baitCount >= 2) {
        addSignal(
            5,
            "The registered domain combines multiple sale-related terms. This is a weak signal and can also occur on legitimate stores."
        );
    }

    let decodedPathAndQuery = parsedUrl.pathname + parsedUrl.search;

    try {
        decodedPathAndQuery = decodeURIComponent(decodedPathAndQuery);
    } catch {
        // Keep the encoded form if decoding fails.
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

    const paymentMatches = paymentWords.filter(word =>
        pathAndQuery.includes(word)
    );

    if (
        paymentMatches.includes("upi") &&
        (
            paymentMatches.includes("verify-account") ||
            paymentMatches.includes("verifyaccount") ||
            paymentMatches.includes("refund")
        )
    ) {
        addSignal(
            10,
            "The URL combines payment-related wording with account verification or refund wording. Do not share a UPI PIN or OTP."
        );
    }

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

async function checkUrlhaus(url) {
    const authKey = process.env.URLHAUS_AUTH_KEY;

    if (!authKey || !authKey.trim()) {
        return {
            status: "not_configured",
            provider: "URLhaus",
            message: "URLhaus is not configured."
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
        console.error("URLhaus check failed:", error.message);

        return {
            status: "unavailable",
            provider: "URLhaus",
            message: "URLhaus could not be reached."
        };
    }
}

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
                headers: { "x-apikey": apiKey.trim() },
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
            return {
                status: "unavailable",
                provider: "VirusTotal",
                message: "VirusTotal could not complete the reputation check."
            };
        }

        const data = await response.json();
        const attributes = data?.data?.attributes;
        const stats = attributes?.last_analysis_stats;

        if (!stats || typeof stats !== "object") {
            return {
                status: "no_report",
                provider: "VirusTotal",
                message: "VirusTotal has no usable existing analysis for this URL."
            };
        }

        const malicious = Number(stats.malicious) || 0;
        const suspicious = Number(stats.suspicious) || 0;

        return {
            status: malicious > 0
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
                ? new Date(attributes.last_analysis_date * 1000).toISOString()
                : null,
            message: malicious > 0
                ? `VirusTotal reports ${malicious} malicious engine detection(s) for this URL.`
                : suspicious > 0
                    ? `VirusTotal reports ${suspicious} suspicious detection(s) for this URL.`
                    : "VirusTotal reported no malicious or suspicious detections in its last analysis. This does not guarantee safety."
        };
    } catch (error) {
        console.error("VirusTotal check failed:", error.message);

        return {
            status: "unavailable",
            provider: "VirusTotal",
            message: "VirusTotal could not be reached."
        };
    }
}
function isPublicIp(address) {
    const family = net.isIP(address);

    if (family === 4) {
        const [a, b] = address.split(".").map(Number);

        if (
            a === 0 ||
            a === 10 ||
            a === 127 ||
            (a === 100 && b >= 64 && b <= 127) ||
            (a === 169 && b === 254) ||
            (a === 172 && b >= 16 && b <= 31) ||
            (a === 192 && b === 168) ||
            (a === 192 && b === 0) ||
            (a === 198 && (b === 18 || b === 19)) ||
            a >= 224
        ) {
            return false;
        }

        return true;
    }

    if (family === 6) {
        const normalized = address.toLowerCase();

        if (
            normalized === "::" ||
            normalized === "::1" ||
            normalized.startsWith("fc") ||
            normalized.startsWith("fd") ||
            normalized.startsWith("fe8") ||
            normalized.startsWith("fe9") ||
            normalized.startsWith("fea") ||
            normalized.startsWith("feb") ||
            normalized.startsWith("ff")
        ) {
            return false;
        }

        return true;
    }

    return false;
}

async function hostnameHasOnlyPublicAddresses(hostname) {
    const cleanHost = hostname.toLowerCase().replace(/^\[|\]$/g, "");

    if (
        cleanHost === "localhost" ||
        cleanHost.endsWith(".localhost") ||
        cleanHost.endsWith(".local") ||
        cleanHost.endsWith(".internal")
    ) {
        return false;
    }

    if (net.isIP(cleanHost)) {
        return isPublicIp(cleanHost);
    }

    const records = await dns.lookup(cleanHost, {
        all: true,
        verbatim: true
    });

    return records.length > 0 &&
        records.every(record => isPublicIp(record.address));
}

// Look up the registration event using RDAP.
async function checkDomainAge(hostname) {
    const registeredDomain = getApproximateRegisteredDomain(hostname);
    const tld = registeredDomain.split(".").pop().toLowerCase();

    let endpoints = [];

    if (tld === "in") {
        endpoints = [
            `https://rdap.nixiregistry.in/rdap/domain/${encodeURIComponent(registeredDomain)}`,
            `https://rdap.org/domain/${encodeURIComponent(registeredDomain)}`
        ];
    } else if (tld === "com") {
        endpoints = [
            `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(registeredDomain)}`,
            `https://rdap.org/domain/${encodeURIComponent(registeredDomain)}`
        ];
    } else {
        endpoints = [
            `https://rdap.org/domain/${encodeURIComponent(registeredDomain)}`
        ];
    }

    const errors = [];

    for (const endpoint of endpoints) {
        try {
            const response = await fetch(endpoint, {
                headers: {
                    Accept: "application/rdap+json, application/json",
                    "User-Agent": "ScamLens/1.0"
                },
                signal: AbortSignal.timeout(10000)
            });

            if (!response.ok) {
                errors.push(`HTTP ${response.status}`);
                continue;
            }

            const data = await response.json();
            const events = Array.isArray(data.events) ? data.events : [];

            const registrationEvent = events.find(event =>
                ["registration", "registered"].includes(
                    String(event.eventAction || "").toLowerCase()
                )
            );

            if (!registrationEvent?.eventDate) {
                errors.push("registration date not provided");
                continue;
            }

            const registrationTime = Date.parse(registrationEvent.eventDate);

            if (
                !Number.isFinite(registrationTime) ||
                registrationTime > Date.now()
            ) {
                errors.push("invalid registration date");
                continue;
            }

            const ageDays = Math.floor(
                (Date.now() - registrationTime) / 86400000
            );

            return {
                status: "checked",
                registrationDate: new Date(registrationTime).toISOString(),
                ageDays,
                message:
                    `Domain is approximately ${ageDays} days old based on its RDAP registration date.`
            };
        } catch (error) {
            errors.push(
                error.cause?.code || error.message || "request failed"
            );

            console.warn(
                `RDAP lookup failed for ${endpoint}:`,
                error.message
            );
        }
    }

    return {
        status: "unavailable",
        registrationDate: null,
        ageDays: null,
        message: errors.length
            ? `Domain registration age could not be checked (${errors.join("; ")}).`
            : "Domain registration age could not be checked."
    };
}

// Check a limited HTTP redirect chain using HEAD requests.
// Destinations resolving to private/local IPs are blocked.
async function checkRedirectChain(startUrl) {
    const maxRedirects = 5;
    const redirects = [];
    let currentUrl = new URL(startUrl);

    try {
        for (let hop = 0; hop <= maxRedirects; hop++) {
            if (!["http:", "https:"].includes(currentUrl.protocol)) {
                return {
                    status: "blocked",
                    redirectCount: redirects.length,
                    finalUrl: null,
                    redirects,
                    message: "An unsupported redirect protocol was blocked."
                };
            }

            if (currentUrl.username || currentUrl.password) {
                return {
                    status: "blocked",
                    redirectCount: redirects.length,
                    finalUrl: null,
                    redirects,
                    message:
                        "A URL containing embedded credentials was blocked."
                };
            }

            let publicHost = false;

            try {
                publicHost = await hostnameHasOnlyPublicAddresses(
                    currentUrl.hostname
                );
            } catch {
                publicHost = false;
            }

            if (!publicHost) {
                return {
                    status: "blocked",
                    redirectCount: redirects.length,
                    finalUrl: null,
                    redirects,
                    message:
                        "The destination was local, private, reserved, or could not be resolved."
                };
            }

            const response = await fetch(currentUrl.href, {
                method: "HEAD",
                redirect: "manual",
                signal: AbortSignal.timeout(5000),
                headers: {
                    "User-Agent": "ScamLens-Redirect-Check/1.0"
                }
            });

            const location = response.headers.get("location");

            const redirectStatus = [301, 302, 303, 307, 308]
                .includes(response.status);

            if (!redirectStatus || !location) {
                return {
                    status: "checked",
                    redirectCount: redirects.length,
                    finalUrl: currentUrl.href,
                    redirects,
                    message: redirects.length
                        ? `The redirect check found ${redirects.length} redirect(s).`
                        : "No HTTP redirect was found by the HEAD-request check. Some sites may behave differently for browser or GET requests."
                };
            }

            if (hop === maxRedirects) {
                return {
                    status: "limit_reached",
                    redirectCount: redirects.length,
                    finalUrl: currentUrl.href,
                    redirects,
                    message:
                        `The redirect check reached its limit of ${maxRedirects} redirects.`
                };
            }

            let nextUrl;

            try {
                nextUrl = new URL(location, currentUrl);
            } catch {
                return {
                    status: "unavailable",
                    redirectCount: redirects.length,
                    finalUrl: null,
                    redirects,
                    message:
                        "The server returned an invalid redirect destination."
                };
            }

            redirects.push({
                statusCode: response.status,
                from: currentUrl.href,
                to: nextUrl.href
            });

            currentUrl = nextUrl;
        }
    } catch (error) {
        console.error("Redirect check failed:", error.message);

        return {
            status: "unavailable",
            redirectCount: redirects.length,
            finalUrl: null,
            redirects,
            message:
                "The redirect chain could not be fully checked. The site may block HEAD requests or the request may have timed out."
        };
    }

    return {
        status: "unavailable",
        redirectCount: redirects.length,
        finalUrl: null,
        redirects,
        message: "The redirect chain could not be fully checked."
    };
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
            message: "The URL is too long."
        });
    }

    let parsedUrl;

    try {
        parsedUrl = new URL(submittedUrl.trim());
    } catch {
        return res.status(400).json({
            status: "error",
            message: "Enter a valid URL, including https:// or http://."
        });
    }

    if (
        !["http:", "https:"].includes(parsedUrl.protocol) ||
        !parsedUrl.hostname ||
        !parsedUrl.hostname.includes(".") ||
        parsedUrl.username ||
        parsedUrl.password
    ) {
        return res.status(400).json({
            status: "error",
            message: "Enter a valid HTTP or HTTPS website URL without embedded credentials."
        });
    }

    const urlAnalysis = analyseUrl(parsedUrl);
    const shoppingAnalysis = analyseShoppingUrl(parsedUrl);

    const [
        reputation,
        virusTotal,
        domainAge,
        redirectCheck
    ] = await Promise.all([
        checkUrlhaus(parsedUrl.href),
        checkVirusTotal(parsedUrl.href),
        checkDomainAge(parsedUrl.hostname),
        checkRedirectChain(parsedUrl.href)
    ]);

    const findings = [
        ...urlAnalysis.findings,
        ...shoppingAnalysis.signals
    ];

    const localScore = Math.min(
        urlAnalysis.score + shoppingAnalysis.score,
        60
    );

    let reputationScore = 0;

    if (reputation.status === "listed") {
        reputationScore = Math.max(reputationScore, 60);

        findings.push({
            points: 60,
            message:
                "URLhaus lists this URL as associated with malware distribution."
        });
    } else {
        findings.push({
            points: 0,
            message: reputation.status === "not_listed"
                ? "URLhaus found no listing. This does not prove the website is safe."
                : "URLhaus could not provide a complete reputation result."
        });
    }

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
                `VirusTotal reports ${maliciousCount} malicious engine detection(s) for this URL.`
        });
    } else if (virusTotal.status === "suspicious") {
        reputationScore = Math.max(reputationScore, 15);

        findings.push({
            points: 15,
            message:
                `VirusTotal reports ${Number(virusTotal.suspicious) || 0} suspicious detection(s).`
        });
    } else {
        findings.push({
            points: 0,
            message: virusTotal.status === "analyzed"
                ? "VirusTotal reported no malicious or suspicious detections in its existing analysis. This does not guarantee safety."
                : "VirusTotal could not provide a usable existing analysis."
        });
    }

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
            "Avoid opening this link or entering credentials or payment details.",
            "Verify the seller using an independently obtained official contact method."
        ]
        : score >= 40 || virusTotal.status === "suspicious"
            ? [
                "Verify the exact registered domain independently.",
                "Do not enter passwords, OTPs, UPI PINs, or payment details until verified."
            ]
            : [
                "Review all available warning signals before buying.",
                "A low score does not guarantee safety; verify the seller and payment method independently."
            ];

    const trustProfile = {
        hostname: parsedUrl.hostname,
        registeredDomain: shoppingAnalysis.registeredDomain,
        protocol: parsedUrl.protocol.replace(":", "").toUpperCase(),
        usesHttps: parsedUrl.protocol === "https:",
        port: parsedUrl.port ||
            (parsedUrl.protocol === "https:" ? "443" : "80"),
        domainAge,
        redirects: redirectCheck
    };

    const scoreBreakdown = {
        urlPatternScore: urlAnalysis.score,
        shoppingScore: shoppingAnalysis.score,
        localScore,
        reputationScore
    };

    return res.json({
        status: "success",
        url: parsedUrl.href,
        trustProfile,
        scoreBreakdown,
        score,
        riskLabel,
        recommendations,
        findings: findings.map(item => item.message),
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
            "This is a preliminary risk assessment, not a verified fraud verdict or probability of fraud. Domain age and redirect checks may be unavailable or incomplete. URLhaus and VirusTotal results do not guarantee safety. ScamLens does not submit a new URL to VirusTotal for analysis."
    });
});

// Handle malformed JSON and unexpected server errors.
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