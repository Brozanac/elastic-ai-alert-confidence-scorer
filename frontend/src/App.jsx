import { useState } from "react";
import { analyzeAlert, getHealth } from "./api";
import "./App.css";

const SAMPLE_ALERT = {
  rule: {
    name: "Suspicious PowerShell Encoded Command",
    severity: "high",
    risk_score: 73
  },
  host: {
    name: "WIN-DEV-01"
  },
  user: {
    name: "user"
  },
  process: {
    name: "powershell.exe",
    command_line: "powershell.exe -NoP -W Hidden -enc SQBFAFgA...",
    parent: {
      name: "winword.exe"
    }
  },
  event: {
    category: ["process"],
    action: "start"
  },
  destination: {
    ip: "185.199.108.133"
  }
};

function App() {
  const [alertInput, setAlertInput] = useState(
    JSON.stringify(SAMPLE_ALERT, null, 2)
  );
  const [result, setResult] = useState(null);
  const [backendStatus, setBackendStatus] = useState("Not checked");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleAnalyze() {
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const parsedAlert = JSON.parse(alertInput);
      const analysis = await analyzeAlert(parsedAlert);
      setResult(analysis);
    } catch (err) {
      if (err instanceof SyntaxError) {
        setError("Invalid JSON. Please check your alert input.");
      } else {
        setError(err.message);
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleHealthCheck() {
    setError("");

    try {
      const health = await getHealth();
      setBackendStatus(health.status === "ok" ? "Online" : "Unknown");
    } catch (err) {
      if (err instanceof SyntaxError) {
        setError("Invalid JSON. Please check your alert input.");
      } else {
        setError("Analysis failed. Please try again.");
      }
    }
  }

  return (
    <main className="app">
      <header className="header">
        <div>
          <p className="eyebrow">Elastic AI Alert Confidence Scorer</p>
          <h1>SOC Alert Confidence Dashboard</h1>
          <p>
            Paste an Elastic-style alert JSON and analyze its confidence score.
          </p>
        </div>

        <div className="backend-card">
          <span>Backend: {backendStatus}</span>
          <button onClick={handleHealthCheck}>Check Backend</button>
        </div>
      </header>

      <section className="layout">
        <section className="panel">
          <h2>Alert JSON</h2>

          <textarea
            value={alertInput}
            onChange={(event) => setAlertInput(event.target.value)}
            spellCheck="false"
          />

          <button className="primary" onClick={handleAnalyze}>
            {loading ? "Analyzing..." : "Analyze Alert"}
          </button>

          {error && <div className="error">{error}</div>}
        </section>

        <section className="panel">
          <h2>Analysis Result</h2>

          {!result && <p>No analysis yet.</p>}

          {result && (
            <>
              <div className="score-card">
                <h3>
                  {result.confidence?.level} — {result.confidence?.score}/100
                </h3>
                <p>
                  <strong>Alert:</strong> {result.alert_name}
                </p>
                <p>
                  <strong>Type:</strong> {result.alert_type}
                </p>
                <p>
                  <strong>Host:</strong> {result.host}
                </p>
                <p>
                  <strong>User:</strong> {result.user}
                </p>
              </div>

              <h3>Score Breakdown</h3>
              <ul>
                <li>
                  Positive Points:{" "}
                  {result.score_breakdown?.positive_points ?? "N/A"}
                </li>
                <li>
                  Negative Points:{" "}
                  {result.score_breakdown?.negative_points ?? "N/A"}
                </li>
                <li>
                  Raw Score: {result.score_breakdown?.raw_score ?? "N/A"}
                </li>
                <li>
                  Final Score: {result.score_breakdown?.final_score ?? "N/A"}
                </li>
              </ul>

              <h3>Evidence</h3>
              <List items={result.evidence} />

              <h3>Missing Context</h3>
              <List items={result.missing_context} />

              <h3>False-Positive Notes</h3>
              <List items={result.false_positive_notes} />

              <h3>MITRE ATT&CK Mapping</h3>
              {(result.mitre_mapping?.mappings || []).length === 0 ? (
                <p>No MITRE mapping found.</p>
              ) : (
                <ul>
                  {result.mitre_mapping.mappings.map((mapping, index) => (
                    <li key={index}>
                      {mapping.technique_id} — {mapping.technique_name}
                    </li>
                  ))}
                </ul>
              )}

              <h3>Analyst Next Steps</h3>
              <ol>
                {(result.analyst_next_steps || []).map((step, index) => (
                  <li key={index}>{step}</li>
                ))}
              </ol>
            </>
          )}
        </section>
      </section>
    </main>
  );
}

function List({ items }) {
  if (!items || items.length === 0) {
    return <p>None.</p>;
  }

  return (
    <ul>
      {items.map((item, index) => (
        <li key={index}>{item}</li>
      ))}
    </ul>
  );
}

export default App;