
const typeInput = document.getElementById("type");
const textInput = document.getElementById("input");
const checkButton = document.getElementById("check");
const result = document.getElementById("result");

checkButton.addEventListener("click", async () => {
  const type = typeInput.value;
  const input = textInput.value.trim();

  result.className = "";

  if (!input) {
    result.textContent = "Please enter a URL or email message.";
    result.classList.add("error");
    return;
  }

  checkButton.disabled = true;
  checkButton.textContent = "Checking...";
  result.textContent = "Analyzing your input...";

  try {
    const endpoint = type === "url"
      ? "http://127.0.0.1:8000/detect/url"
      : "http://127.0.0.1:8000/detect/email";

    const payload = type === "url"
      ? { url: input }
      : { text: input };

    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const data = await response.json();
    const label = String(data.label || "unknown").toLowerCase();
    const score = data.score;

    result.className = ["safe", "suspicious", "phishing"]
      .includes(label) ? label : "error";

    result.replaceChildren();

    const heading = document.createElement("h3");
    heading.textContent = `Result: ${label.toUpperCase()}`;
    result.appendChild(heading);

    const scoreLine = document.createElement("p");
    scoreLine.style.textAlign = "left";
    scoreLine.style.margin = "8px 0 0";
    scoreLine.textContent = `Risk score: ${score ?? "Not provided"}`;
    result.appendChild(scoreLine);

  } catch (error) {
    result.className = "error";
    result.textContent =
      "Could not connect to the detector API. Check that your backend is running and allows requests from this page.";
    console.error(error);
  } finally {
    checkButton.disabled = false;
    checkButton.textContent = "Check Now";
  }
});
