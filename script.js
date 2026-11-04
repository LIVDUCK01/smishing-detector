const API_BASE = "http://127.0.0.1:8001";

const form = document.getElementById("scanForm");
const input = document.getElementById("msgInput");
const submitBtn = document.getElementById("submitBtn");
const resultSection = document.getElementById("result");
const errorMsg = document.getElementById("errorMsg");

const verdictBox = document.getElementById("verdictBox");
const verdictLabel = document.getElementById("verdictLabel");
const verdictDetail = document.getElementById("verdictDetail");

const mlScoreEl = document.getElementById("mlScore");
const mlMeterEl = document.getElementById("mlMeter");
const urlScoreEl = document.getElementById("urlScore");
const urlMeterEl = document.getElementById("urlMeter");
const urlListEl = document.getElementById("urlList");
const timingEl = document.getElementById("timing");

const VERDICT_LEVEL = {
  "위험": "danger",
  "주의": "warn",
  "안전": "safe",
};

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  const message = input.value.trim();
  if (!message) return;

  setLoading(true);
  hideError();

  try {
    const res = await fetch(`${API_BASE}/diagnose`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });

    if (!res.ok) {
      throw new Error(`서버 응답 오류 (${res.status})`);
    }

    const data = await res.json();

    if (data.error) {
      throw new Error(data.error);
    }

    renderResult(data);
  } catch (err) {
    showError(
      err.message.includes("Failed to fetch")
        ? "서버에 연결할 수 없습니다. main.py(uvicorn)가 실행 중인지 확인하세요."
        : err.message
    );
  } finally {
    setLoading(false);
  }
});

function renderResult(data) {
  resultSection.classList.remove("result--hidden");

  const level = VERDICT_LEVEL[data.verdict] || "warn";
  verdictBox.dataset.level = level;
  verdictLabel.textContent = `${data.verdict} 판정`;
  verdictDetail.textContent = data.verdict_detail;

  mlScoreEl.textContent = `${data.ml_probability}%`;
  mlMeterEl.style.width = `${Math.min(data.ml_probability, 100)}%`;

  urlScoreEl.textContent = `${data.url_score}점`;
  urlMeterEl.style.width = `${Math.min(data.url_score, 100)}%`;

  urlListEl.innerHTML = "";
  if (data.has_url && data.url_details.length) {
    data.url_details.forEach((item) => {
      const div = document.createElement("div");
      div.className = "urlItem";

      const urlLine = document.createElement("div");
      urlLine.className = "urlItem__url";
      urlLine.textContent = item.is_redirected
        ? `${item.original_url} → ${item.final_url}`
        : item.original_url;
      div.appendChild(urlLine);

      if (item.risk_factors && item.risk_factors.length) {
        const ul = document.createElement("ul");
        ul.className = "urlItem__factors";
        item.risk_factors.forEach((f) => {
          const li = document.createElement("li");
          li.textContent = f;
          ul.appendChild(li);
        });
        div.appendChild(ul);
      }

      urlListEl.appendChild(div);
    });
  }

  timingEl.textContent = `처리 시간 ${data.response_time_ms}ms`;
}

function setLoading(isLoading) {
  submitBtn.disabled = isLoading;
  submitBtn.textContent = isLoading ? "검사 중..." : "검사하기";
}

function showError(text) {
  errorMsg.textContent = text;
  errorMsg.classList.remove("errorMsg--hidden");
}

function hideError() {
  errorMsg.classList.add("errorMsg--hidden");
}
