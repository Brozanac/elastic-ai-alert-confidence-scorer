const API_BASE_URL = "http://127.0.0.1:8000";

export async function analyzeAlert(alertJson) {
  const response = await fetch(`${API_BASE_URL}/score-alert/full`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(alertJson)
  });

  if (!response.ok) {
    throw new Error(`Backend returned ${response.status}`);
  }

  return response.json();
}

export async function analyzeAlertWithLLM(alertJson) {
  const response = await fetch(`${API_BASE_URL}/score-alert/llm-explain`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(alertJson)
  });

  if (!response.ok) {
    throw new Error(`Backend returned ${response.status}`);
  }

  return response.json();
}

export async function getHealth() {
  const response = await fetch(`${API_BASE_URL}/health`);

  if (!response.ok) {
    throw new Error("Backend health check failed");
  }

  return response.json();
}

export async function getAlertHistory(limit = 25) {
  const response = await fetch(`${API_BASE_URL}/alerts/history?limit=${limit}`);

  if (!response.ok) {
    throw new Error(`Backend returned ${response.status}`);
  }

  return response.json();
}

export async function getAlertHistoryRecord(historyId) {
  const response = await fetch(`${API_BASE_URL}/alerts/history/${historyId}`);

  if (!response.ok) {
    throw new Error(`Backend returned ${response.status}`);
  }

  return response.json();
}

export async function deleteAlertHistoryRecord(historyId) {
  const response = await fetch(`${API_BASE_URL}/alerts/history/${historyId}`, {
    method: "DELETE"
  });

  if (!response.ok) {
    throw new Error(`Backend returned ${response.status}`);
  }

  return response.json();
}