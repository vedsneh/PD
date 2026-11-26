chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete' || !tab.url || !tab.url.startsWith('http')) return;

  try {
    const res = await fetch('http://127.0.0.1:8000/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: tab.url }),
    });
    const data = await res.json();

    // badge on the extension icon -- ALWAYS shows, safe or not
    const isPhishing = data.verdict === 'phishing';
    chrome.action.setBadgeText({ tabId, text: isPhishing ? '!' : '✓' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: isPhishing ? '#c0392b' : '#27ae60' });

    if (isPhishing) {
      chrome.tabs.sendMessage(tabId, { type: 'SHOW_WARNING', data }).catch(() => {});
    }
  } catch (e) {
    console.log('Backend not reachable', e);
  }
});