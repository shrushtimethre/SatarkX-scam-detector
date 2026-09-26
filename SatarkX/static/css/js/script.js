
async function analyzeThreat() {

    const input = document.getElementById("message");
    const result = document.getElementById("result");
    const riskLevel = document.getElementById("riskLevel");
    const score = document.getElementById("score");
    const progressBar = document.getElementById("progressBar");
    const reasonsList = document.getElementById("reasons");
    const button = document.getElementById("analyzeBtn");

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

        result.classList.remove("hidden");

        riskLevel.textContent = data.risk_level;
        score.textContent = data.score;

        progressBar.style.width = data.score + "%";

        if (data.risk_color === "high") {
            riskLevel.style.color = "#ef4444";
        } else if (data.risk_color === "medium") {
            riskLevel.style.color = "#facc15";
        } else {
            riskLevel.style.color = "#22c55e";
        }

        reasonsList.innerHTML = "";

        data.reasons.forEach(function(reason) {

            const li = document.createElement("li");

            li.textContent = reason;

            reasonsList.appendChild(li);
        });

        result.scrollIntoView({
            behavior: "smooth"
        });

    } catch (error) {

        alert("Error: " + error.message);

    } finally {

        button.disabled = false;

        button.innerHTML =
            "<span>Analyze Threat</span><span>→</span>";
    }
}