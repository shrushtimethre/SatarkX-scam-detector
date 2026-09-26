let currentScanId = null;


// ==========================================
// MAIN THREAT ANALYZER
// ==========================================

async function analyzeThreat() {

    const input = document.getElementById("message");
    const result = document.getElementById("result");
    const emptyResult = document.getElementById("emptyResult");
    const riskLevel = document.getElementById("riskLevel");
    const score = document.getElementById("score");
    const progressBar = document.getElementById("progressBar");
    const reasonsList = document.getElementById("reasons");
    const button = document.getElementById("analyzeBtn");

    const totalAnalyses = document.getElementById("totalAnalyses");
    const highRiskCount = document.getElementById("highRiskCount");
    const suspiciousCount = document.getElementById("suspiciousCount");
    const lowRiskCount = document.getElementById("lowRiskCount");

    const text = input.value.trim();

    if (!text) {
        alert("Please paste a message or URL first.");
        return;
    }

    button.disabled = true;
    button.innerHTML = "Analyzing...";

    try {

        const response = await fetch("/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                text: text
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Analysis failed");
        }


        // ==========================================
        // SAVE SCAN ID
        // ==========================================

        currentScanId = data.scan_id;


        // ==========================================
        // UPDATE DASHBOARD COUNTERS
        // ==========================================

        const total = Number(totalAnalyses.textContent) + 1;
        totalAnalyses.textContent = total;

        if (data.risk_color === "high") {

            highRiskCount.textContent =
                Number(highRiskCount.textContent) + 1;

        } else if (data.risk_color === "medium") {

            suspiciousCount.textContent =
                Number(suspiciousCount.textContent) + 1;

        } else {

            lowRiskCount.textContent =
                Number(lowRiskCount.textContent) + 1;
        }

        updateDashboardBars();


        // ==========================================
        // SHOW RESULT
        // ==========================================

        emptyResult.classList.add("hidden");
        result.classList.remove("hidden");

        riskLevel.textContent = data.risk_level;
        score.textContent = data.score;

        progressBar.style.width = data.score + "%";


        // ==========================================
        // RISK LEVEL COLOR
        // ==========================================

        if (data.risk_color === "high") {

            riskLevel.style.color = "#fb7185";

        } else if (data.risk_color === "medium") {

            riskLevel.style.color = "#fbbf24";

        } else {

            riskLevel.style.color = "#34d399";
        }


        // ==========================================
        // WHY WAS IT FLAGGED?
        // ==========================================

        reasonsList.innerHTML = "";

        data.reasons.forEach((reason) => {

            const li = document.createElement("li");

            li.textContent = reason;

            reasonsList.appendChild(li);
        });


        // ==========================================
        // NEW FEATURE:
        // WHAT SHOULD YOU DO?
        // ==========================================

        showSafetyGuidance(data.risk_color);


        // ==========================================
        // EXPORT JSON
        // ==========================================

        const exportBtn = document.getElementById("exportBtn");

        if (exportBtn) {

            exportBtn.onclick = () => {

                if (currentScanId) {

                    window.open(
                        `/download/${currentScanId}`,
                        "_blank"
                    );
                }
            };
        }


        // ==========================================
        // SCROLL TO RESULT
        // ==========================================

        result.scrollIntoView({
            behavior: "smooth",
            block: "nearest"
        });


        // ==========================================
        // REFRESH HISTORY
        // ==========================================

        await refreshHistory();


    } catch (error) {

        alert("Error: " + error.message);

    } finally {

        button.disabled = false;

        button.innerHTML =
            '<span>Analyze Threat</span><span>→</span>';
    }
}


// ==========================================
// SAFETY GUIDANCE
// ==========================================

function showSafetyGuidance(riskColor) {

    // Remove previous guidance if already present
    const oldGuidance =
        document.getElementById("satarkGuidance");

    if (oldGuidance) {
        oldGuidance.remove();
    }


    // Create main guidance box
    const guidanceBox = document.createElement("div");

    guidanceBox.id = "satarkGuidance";

    guidanceBox.style.marginTop = "20px";
    guidanceBox.style.padding = "18px";
    guidanceBox.style.borderRadius = "14px";
    guidanceBox.style.background = "rgba(15, 23, 42, 0.8)";
    guidanceBox.style.border = "1px solid rgba(96, 165, 250, 0.25)";


    // Heading
    const heading = document.createElement("h3");

    heading.textContent = "🛡️ What should you do?";

    heading.style.marginBottom = "12px";


    // Guidance list
    const list = document.createElement("ul");

    list.style.paddingLeft = "22px";


    let guidance = [];


    // ==========================================
    // HIGH RISK
    // ==========================================

    if (riskColor === "high") {

        guidance = [

            "Do not click suspicious links.",

            "Do not share OTP, PIN, password or banking details.",

            "Do not send money to the sender.",

            "Verify the message through the organisation's official website or app.",

            "If you have already lost money or shared sensitive information, report the incident immediately."
        ];

    }


    // ==========================================
    // MEDIUM RISK
    // ==========================================

    else if (riskColor === "medium") {

        guidance = [

            "Do not respond immediately.",

            "Avoid clicking unknown or suspicious links.",

            "Verify the sender using an official source.",

            "Never share OTP, PIN or password.",

            "If the message seems fraudulent, consider reporting it."
        ];

    }


    // ==========================================
    // LOW RISK
    // ==========================================

    else {

        guidance = [

            "No major scam indicators were detected.",

            "Still verify unexpected messages before taking action.",

            "Never share OTP, PIN or passwords with anyone."
        ];
    }


    // Add guidance items
    guidance.forEach((item) => {

        const li = document.createElement("li");

        li.textContent = item;

        li.style.marginBottom = "8px";

        list.appendChild(li);
    });


    guidanceBox.appendChild(heading);
    guidanceBox.appendChild(list);


    // ==========================================
    // REPORT BUTTON
    // ==========================================

    if (riskColor === "high" || riskColor === "medium") {

        const reportButton = document.createElement("button");

        reportButton.id = "reportScamBtn";

        reportButton.type = "button";

        reportButton.textContent =
            "🚨 Report This Scam";


        reportButton.style.marginTop = "15px";
        reportButton.style.padding = "12px 18px";
        reportButton.style.border = "none";
        reportButton.style.borderRadius = "10px";
        reportButton.style.cursor = "pointer";
        reportButton.style.fontWeight = "700";
        reportButton.style.fontSize = "14px";
        reportButton.style.background = "#ef4444";
        reportButton.style.color = "#ffffff";


        reportButton.onclick = function () {

            reportScam();
        };


        guidanceBox.appendChild(reportButton);
    }


    // ==========================================
    // INSERT AFTER REASONS
    // ==========================================

    const reasonsSection =
        document.querySelector(".reasons");

    if (reasonsSection) {

        reasonsSection.appendChild(guidanceBox);
    }
}


// ==========================================
// REPORT SCAM
// ==========================================

function reportScam() {

    const confirmed = confirm(
        "You will be redirected to the official National Cyber Crime Reporting Portal. Continue?"
    );

    if (!confirmed) {
        return;
    }

    window.open(
        "https://cybercrime.gov.in/Webform/Index.aspx",
        "_blank"
    );
}

// ==========================================
// DASHBOARD BARS
// ==========================================

function updateDashboardBars() {

    const high =
        Number(
            document.getElementById("highRiskCount").textContent || 0
        );

    const suspicious =
        Number(
            document.getElementById("suspiciousCount").textContent || 0
        );

    const low =
        Number(
            document.getElementById("lowRiskCount").textContent || 0
        );

    const total =
        Math.max(
            high + suspicious + low,
            1
        );


    document.getElementById("barHigh").style.width =
        `${(high / total) * 100}%`;

    document.getElementById("barSuspicious").style.width =
        `${(suspicious / total) * 100}%`;

    document.getElementById("barLow").style.width =
        `${(low / total) * 100}%`;
}


// ==========================================
// SCAN HISTORY
// ==========================================

async function refreshHistory() {

    const res = await fetch("/history");

    const data = await res.json();

    const tbody =
        document.getElementById("historyTableBody");


    if (!tbody || !data.history) {
        return;
    }


    tbody.innerHTML = "";


    data.history.slice(0, 8).forEach((item) => {

        const row =
            document.createElement("tr");


        row.innerHTML = `
            <td>${item.timestamp}</td>

            <td>
                <span class="risk-pill ${item.risk_color}">
                    ${item.risk_level}
                </span>
            </td>

            <td>${item.score}</td>

            <td>
                ${(item.text || "").slice(0, 50)}
                ${(item.text || "").length > 50 ? "..." : ""}
            </td>

            <td>
                <a
                    href="/download/${item.id}"
                    class="download-link"
                    target="_blank">
                    Export
                </a>
            </td>
        `;


        tbody.appendChild(row);
    });
}


// ==========================================
// QUICK TEST BUTTONS
// ==========================================

function setExample(type) {

    const input =
        document.getElementById("message");


    if (type === "safe") {

        input.value =
            "Hello! Hope you are having a great day. See you tomorrow.";

    }

    else if (type === "suspicious") {

        input.value =
            "URGENT! Your account needs verification. Please verify your account immediately using this link: http://example.com/verify";

    }

    else {

        input.value =
            "URGENT! Your bank account will be blocked today. Send your OTP and password immediately to verify your KYC. Click here: http://192.168.1.10/verify";
    }


    input.focus();
}


// ==========================================
// PAGE LOAD
// ==========================================

window.addEventListener("DOMContentLoaded", () => {

    const result =
        document.getElementById("result");

    const emptyResult =
        document.getElementById("emptyResult");


    if (result && emptyResult) {

        result.classList.add("hidden");

        emptyResult.classList.remove("hidden");
    }


    updateDashboardBars();


    document
        .getElementById("refreshHistoryBtn")
        ?.addEventListener(
            "click",
            refreshHistory
        );


    refreshHistory();
});