
const VT_API_KEY = "84542f8a4c60612d96bdaf4c2330a07f776164bd0641f50c6561105f9ed8a106";

const domainInput = document.getElementById("vt-domain");
const checkBtn = document.getElementById("vt-check");
const resultCard = document.getElementById("vt-result");
const domainNameEl = document.getElementById("vt-domain-name");
const statusEl = document.getElementById("vt-status");
const statsTable = document.getElementById("vt-stats");
const whoisPre = document.getElementById("vt-whois");
const rawPre = document.getElementById("vt-raw");

function showAlert(msg){
  if(window.toast && typeof window.toast === 'function'){
    window.toast(msg);
  } else {
    alert(msg);
  }
}

checkBtn.addEventListener("click", async () => {
  const raw = domainInput.value.trim();
  if(!raw) return showAlert("Please enter a domain or URL.");

  // UI reset
  resultCard.classList.add("hidden");
  statusEl.textContent = "Checking...";
  statusEl.className = "vt-status";

  try {
    const cleanDomain = raw.replace(/^https?:\/\//i, "").split("/")[0];

    const url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(cleanDomain)}`;

    const resp = await fetch(url, {
      headers: { "x-apikey": VT_API_KEY }
    });

    if(!resp.ok){

      const txt = await resp.text().catch(()=>"");
      showAlert(`API error ${resp.status}: ${txt || resp.statusText}`);
      return;
    }

    const json = await resp.json();
    displayResult(json, cleanDomain);
  } catch (err) {
    showAlert("Error: " + err.message + ". Note: public API calls may be blocked by CORS — use a server proxy.");
    console.error(err);
  }
});

function displayResult(json, domain){
  const data = json.data?.attributes || {};
  const stats = data.last_analysis_stats || {};

  domainNameEl.innerHTML = `<strong>Domain:</strong> ${domain}`;
  const flagged = (stats.malicious || 0) + (stats.suspicious || 0);

  if(flagged > 0){
    statusEl.textContent = "⚠️ Flagged as suspicious or malicious";
    statusEl.className = "vt-status flagged";
  } else {
    statusEl.textContent = "✅ Safe — No flags detected";
    statusEl.className = "vt-status safe";
  }

  statsTable.innerHTML = `
    <tr><th>Malicious</th><td>${stats.malicious || 0}</td></tr>
    <tr><th>Suspicious</th><td>${stats.suspicious || 0}</td></tr>
    <tr><th>Undetected</th><td>${stats.undetected || 0}</td></tr>
    <tr><th>Timeout</th><td>${stats.timeout || 0}</td></tr>
  `;

  whoisPre.textContent = data.whois ? (data.whois.slice(0, 1000) + (data.whois.length>1000?"\n\n...truncated":"")) : "No WHOIS data available";
  rawPre.textContent = JSON.stringify(json, null, 2);

  resultCard.classList.remove("hidden");

  resultCard.scrollIntoView({behavior:"smooth", block:"center"});
}
