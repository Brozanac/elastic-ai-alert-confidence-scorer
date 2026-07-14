import { useState } from "react";
import { analyzeAlert, analyzeAlertWithLLM, getHealth } from "./api";
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
    name: "ulas"
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
    action: "start",
    created: "2026-07-06T17:30:00Z"
  },
  destination: {
    ip: "185.199.108.133"
  }
};
const [historyItems, setHistoryItems] = useState([]);
const [historyLoading, setHistoryLoading] = useState(false);

function App() {
  const [alertInput, setAlertInput] = useState(
    JSON.stringify(SAMPLE_ALERT, null, 2)
  );
  const [analysisResult, setAnalysisResult] = useState(null);
  const [llmResult, setLlmResult] = useState(null);
  const [backendStatus, setBackendStatus] = useState("Not checked");
  const [loading, setLoading] = useState(false);
  const [llmLoading, setLlmLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleAnalyze() {
    setLoading(true);
    setError("");
    setAnalysisResult(null);
    setLlmResult(null);

    try {
      const parsedAlert = JSON.parse(alertInput);
      const result = await analyzeAlert(parsedAlert);
      setAnalysisResult(result);
    } catch (err) {
      setError(
        err instanceof SyntaxError
          ? "Invalid JSON. Please check your alert input."
          : `Analysis failed: ${err.message}`
      );
    } finally {
      setLoading(false);
    }
  }

  async function handleAnalyzeWithLLM() {
    setLlmLoading(true);
    setError("");
    setLlmResult(null);

    try {
      const parsedAlert = JSON.parse(alertInput);
      const result = await analyzeAlertWithLLM(parsedAlert);
      setLlmResult(result);
    } catch (err) {
      setError(
        err instanceof SyntaxError
          ? "Invalid JSON. Please check your alert input."
          : `LLM analysis failed: ${err.message}`
      );
    } finally {
      setLlmLoading(false);
    }
  }

  async function handleHealthCheck() {
    setError("");

    try {
      const result = await getHealth();
      setBackendStatus(result.status === "ok" ? "Online" : "Unknown");
    } catch (err) {
      setBackendStatus("Offline");
      setError(`Backend health check failed: ${err.message}`);
    }
  }

  function loadSample(type) {
    if (type === "powershell") {
      setAlertInput(JSON.stringify(SAMPLE_ALERT, null, 2));
      setAnalysisResult(null);
      setLlmResult(null);
      return;
    }

    if (type === "failed-login") {
      const failedLoginAlert = {
        rule: {
          name: "Multiple Failed Logins from External IP",
          severity: "medium",
          risk_score: 47
        },
        host: {
          name: "VPN-GATEWAY-01"
        },
        user: {
          name: "ulas"
        },
        event: {
          category: ["authentication"],
          action: "failed-login",
          created: "2026-07-06T18:10:00Z"
        },
        source: {
          ip: "45.155.205.44"
        }
      };

      setAlertInput(JSON.stringify(failedLoginAlert, null, 2));
      setAnalysisResult(null);
      setLlmResult(null);
      return;
    }

    if (type === "false-positive") {
      const falsePositiveAlert = {
        rule: {
          name: "PowerShell Execution",
          severity: "medium",
          risk_score: 35
        },
        host: {
          name: "SCCM-01"
        },
        user: {
          name: "admin-deploy"
        },
        process: {
          name: "powershell.exe",
          command_line:
            "powershell.exe -ExecutionPolicy Bypass -File deploy_patch.ps1",
          parent: {
            name: "services.exe"
          }
        },
        event: {
          category: ["process"],
          action: "start",
          created: "2026-07-06T19:00:00Z"
        }
      };

      setAlertInput(JSON.stringify(falsePositiveAlert, null, 2));
      setAnalysisResult(null);
      setLlmResult(null);
    }
  }

  return (
    <main className="app-shell">
      <header className="hero">
        <div>
          <p className="eyebrow">Elastic AI Alert Confidence Scorer</p>
          <h1>AI-Assisted SOC Alert Confidence Dashboard</h1>
          <p className="hero-text">
            Paste an Elastic-style alert JSON, analyze the score, inspect the
            evidence, and review analyst next steps.
          </p>
        </div>

        <div className="status-card">
          <span>Backend</span>
          <strong>{backendStatus}</strong>
          <button onClick={handleHealthCheck}>Check</button>
        </div>
      </header>

      <section className="layout">
        <section className="panel input-panel">
          <div className="panel-header">
            <div>
              <h2>Alert JSON</h2>
              <p>Paste an Elastic-style alert object.</p>
            </div>
          </div>

          <div className="sample-buttons">
            <button onClick={() => loadSample("powershell")}>
              Load PowerShell Sample
            </button>
            <button onClick={() => loadSample("failed-login")}>
              Load Failed Login Sample
            </button>
            <button onClick={() => loadSample("false-positive")}>
              Load False Positive Sample
            </button>
          </div>

          <textarea
            value={alertInput}
            onChange={(event) => setAlertInput(event.target.value)}
            spellCheck="false"
          />

          <div className="button-row">
            <button className="primary-button" onClick={handleAnalyze}>
              {loading ? "Analyzing..." : "Analyze Alert"}
            </button>

            <button className="secondary-button" onClick={handleAnalyzeWithLLM}>
              {llmLoading ? "Running LLM..." : "Run LLM Explanation"}
            </button>
          </div>

          {error && <div className="error-box">{error}</div>}
        </section>

        <section className="results-column">
          {!analysisResult && (
            <section className="panel empty-state">
              <h2>No analysis yet</h2>
              <p>
                Run an alert analysis to see confidence score, evidence, MITRE
                mapping, and recommendations.
              </p>
            </section>
          )}

          {analysisResult && <AnalysisResult result={analysisResult} />}

          {llmResult && <LLMResult result={llmResult} />}
        </section>
      </section>
    </main>
  );
}

function AnalysisResult({ result }) {
  const confidence = result.confidence || {};
  const breakdown = result.score_breakdown || {};
  const explanation = result.ai_style_explanation || {};
  const mitreMappings = result.mitre_mapping?.mappings || [];

  return (
    <>
      <section className="panel score-panel">
        <div>
          <p className="eyebrow">Confidence</p>
          <h2>
            {confidence.level} — {confidence.score}/100
          </h2>
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
      </section>

      <section className="grid-two">
        <InfoCard title="Score Breakdown">
          <ul>
            <li>Positive Points: {breakdown.positive_points}</li>
            <li>Negative Points: {breakdown.negative_points}</li>
            <li>Raw Score: {breakdown.raw_score}</li>
            <li>Final Score: {breakdown.final_score}</li>
          </ul>
        </InfoCard>

        <InfoCard title="AI-Style Summary">
          <p>{explanation.executive_summary || "No summary available."}</p>
          <p className="muted">{explanation.safety_note}</p>
        </InfoCard>
      </section>

      <InfoCard title="Scoring Events">
        <div className="event-list">
          {(result.scoring_events || []).map((event, index) => (
            <div className="event-item" key={`${event.component}-${index}`}>
              <strong>
                {event.points > 0 ? "+" : ""}
                {event.points} — {event.component}
              </strong>
              <ul>
                {(event.details || []).map((detail, detailIndex) => (
                  <li key={detailIndex}>{detail}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </InfoCard>

      <section className="grid-two">
        <InfoCard title="Evidence">
          <List items={result.evidence} emptyText="No evidence found." />
        </InfoCard>

        <InfoCard title="Missing Context">
          <List
            items={result.missing_context}
            emptyText="No major missing context."
          />
        </InfoCard>
      </section>

      <InfoCard title="False-Positive Notes">
        <List
          items={result.false_positive_notes}
          emptyText="No obvious false-positive indicators."
        />
      </InfoCard>

      <InfoCard title="MITRE ATT&CK Mapping">
        {mitreMappings.length === 0 ? (
          <p>No MITRE mapping found.</p>
        ) : (
          <div className="event-list">
            {mitreMappings.map((mapping, index) => (
              <div className="event-item" key={index}>
                <strong>
                  {mapping.technique_id} — {mapping.technique_name}
                </strong>
                <p>{mapping.tactic}</p>
                <p className="muted">{mapping.reason}</p>
              </div>
            ))}
          </div>
        )}
      </InfoCard>

      <InfoCard title="Analyst Next Steps">
        <ol>
          {(result.analyst_next_steps || []).map((step, index) => (
            <li key={index}>{step}</li>
          ))}
        </ol>
      </InfoCard>
    </>
  );
}

function LLMResult({ result }) {
  const llm = result.llm_explanation || {};

  return (
    <InfoCard title="LLM Explanation">
      {!llm.enabled && (
        <>
          <p>{llm.message || "LLM explanation unavailable."}</p>
          {llm.error && <p className="error-text">{llm.error}</p>}
        </>
      )}

      {llm.enabled && (
        <>
          <p className="muted">Model: {llm.model}</p>
          <pre className="llm-output">{llm.explanation}</pre>
          <p className="muted">{llm.safety_note}</p>
        </>
      )}
    </InfoCard>
  );
}

function InfoCard({ title, children }) {
  return (
    <section className="panel info-card">
      <h2>{title}</h2>
      {children}
    </section>
  );
}

function List({ items, emptyText }) {
  if (!items || items.length === 0) {
    return <p>{emptyText}</p>;
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