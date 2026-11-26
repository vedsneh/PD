const API = 'http://127.0.0.1:8000';
const reportButton = document.getElementById('reportBtn');
const reportStatus = document.getElementById('reportStatus');
let currentUrl = '';

reportButton.addEventListener('click', submitReport);

async function checkCurrentTab() {
  const loadingEl = document.getElementById('loading');
  const resultDiv = document.getElementById('result');
  const statusEl = document.getElementById('status');

  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

    if (!tab?.url || !tab.url.startsWith('http')) {
      statusEl.textContent = 'This page is not a regular website.';
      loadingEl.textContent = 'This page type cannot be checked.';
      return;
    }

    currentUrl = tab.url;
    statusEl.textContent = new URL(tab.url).hostname;
    const res = await fetch(`${API}/predict`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        url: tab.url
      })
    });

    if (!res.ok) {
      const body = await res.json().catch(() => null);
      const detail = typeof body?.detail === 'string' ? `: ${body.detail}` : '';
      throw new Error(`Server returned ${res.status}${detail}`);
    }

    const data = await res.json();

    loadingEl.style.display = 'none';
    resultDiv.style.display = 'block';
    reportButton.style.display = 'block';

    const isPhishing = data.verdict === 'phishing';
    resultDiv.className = isPhishing ? 'risky' : 'safe';

    resultDiv.textContent = '';
    const title = document.createElement('b');
    title.textContent = String(data.verdict || '').toUpperCase();
    resultDiv.appendChild(title);
    resultDiv.appendChild(document.createElement('br'));
    resultDiv.appendChild(
      document.createTextNode(`Confidence: ${(data.confidence * 100).toFixed(1)}%`)
    );

    if (Array.isArray(data.reasons) && data.reasons.length > 0) {
      const reasonsWrap = document.createElement('div');
      reasonsWrap.className = 'reasons';

      const reasonsTitle = document.createElement('strong');
      reasonsTitle.textContent = isPhishing
        ? 'Why was this flagged?'
        : 'Why was this considered safe?';
      reasonsWrap.appendChild(reasonsTitle);

      const reasonsList = document.createElement('ul');
      reasonsList.id = 'reasonsList';
      data.reasons.forEach((reason) => {
        const li = document.createElement('li');
        li.textContent = reason;
        reasonsList.appendChild(li);
      });
      reasonsWrap.appendChild(reasonsList);
      resultDiv.appendChild(reasonsWrap);
    }
  } catch (err) {
    loadingEl.textContent = err instanceof TypeError
      ? 'Backend not reachable. Is uvicorn running on port 8000?'
      : `Scan failed: ${err instanceof Error ? err.message : String(err)}`;

    console.error(err);
  }
}

async function submitReport() {
  if (!currentUrl || reportButton.disabled) return;

  let domain;
  try {
    domain = new URL(currentUrl).hostname;
  } catch {
    showReportStatus('Could not determine the website domain.', 'error');
    return;
  }

  reportButton.disabled = true;
  reportButton.textContent = 'Submitting report...';
  reportStatus.style.display = 'none';
  reportStatus.textContent = '';
  reportStatus.className = '';

  try {
    const res = await fetch(`${API}/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        domain,
        reason: 'reported from browser extension'
      })
    });

    if (!res.ok) {
      const body = await res.json().catch(() => null);
      const detail = typeof body?.detail === 'string' ? `: ${body.detail}` : '';
      throw new Error(`Server returned ${res.status}${detail}`);
    }

    const data = await res.json();
    reportButton.textContent = 'Domain reported';
    showReportStatus(
      `Report received for ${data.domain}. Community reports: ${data.total_reports}.`,
      'success'
    );
  } catch (err) {
    reportButton.disabled = false;
    reportButton.textContent = 'Report as suspected phishing';
    showReportStatus(
      err instanceof TypeError
        ? 'Could not reach the backend. Is uvicorn running on port 8000?'
        : `Report failed: ${err instanceof Error ? err.message : String(err)}`,
      'error'
    );
    console.error(err);
  }
}

function showReportStatus(message, state) {
  reportStatus.textContent = message;
  reportStatus.className = state;
  reportStatus.style.display = 'block';
}

checkCurrentTab();