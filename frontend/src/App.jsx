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
        setError("Analysis failed. Please try again.");
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
    } catch {
      setBackendStatus("Offline");
      setError("Backend health check failed. Make sure the backend is running.");
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
              <ScoreSummary result={result} />

              <ScoreBreakdown breakdown={result.score_breakdown} />

              <ScoringEvents events={result.scoring_events} />

              <InfoSection title="Evidence">
                <List items={result.evidence} />
              </InfoSection>

              <InfoSection title="Missing Context">
                <List items={result.missing_context} />
              </InfoSection>

              <InfoSection title="False-Positive Notes">
                <List items={result.false_positive_notes} />
              </InfoSection>

              <MitreMapping mitreMapping={result.mitre_mapping} />

              <InfoSection title="Analyst Next Steps">
                <OrderedList items={result.analyst_next_steps} />
              </InfoSection>

              <AIStyleExplanation explanation={result.ai_style_explanation} />

              <LLMExplanation explanation={result.llm_explanation} />
            </>
          )}
        </section>
      </section>
    </main>
  );
}

function ScoreSummary({ result }) {
  return (
    <div className="score-card">
      <h3>
        {result.confidence?.level ?? "Unknown"} —{" "}
        {result.confidence?.score ?? "N/A"}/100
      </h3>

      <p>
        <strong>Alert:</strong> {result.alert_name ?? "Unknown Alert"}
      </p>

      <p>
        <strong>Type:</strong> {result.alert_type ?? "unknown"}
      </p>

      <p>
        <strong>Host:</strong> {result.host ?? "unknown"}
      </p>

      <p>
        <strong>User:</strong> {result.user ?? "unknown"}
      </p>

      {result.history_id && (
        <p>
          <strong>History ID:</strong> {result.history_id}
        </p>
      )}

      {result.saved_to_history && (
        <p>
          <strong>Saved to History:</strong> Yes
        </p>
      )}
    </div>
  );
}

function ScoreBreakdown({ breakdown }) {
  if (!breakdown) {
    return (
      <InfoSection title="Score Breakdown">
        <p>No score breakdown available.</p>
      </InfoSection>
    );
  }

  return (
    <InfoSection title="Score Breakdown">
      <ul>
        <li>Positive Points: {breakdown.positive_points ?? "N/A"}</li>
        <li>Negative Points: {breakdown.negative_points ?? "N/A"}</li>
        <li>Raw Score: {breakdown.raw_score ?? "N/A"}</li>
        <li>Final Score: {breakdown.final_score ?? "N/A"}</li>
      </ul>
    </InfoSection>
  );
}

function ScoringEvents({ events }) {
  if (!events || events.length === 0) {
    return (
      <InfoSection title="Scoring Events">
        <p>No scoring events available.</p>
      </InfoSection>
    );
  }

  return (
    <InfoSection title="Scoring Events">
      <div className="event-list">
        {events.map((event, index) => (
          <div className="event-item" key={index}>
            <p>
              <strong>
                {event.points > 0 ? "+" : ""}
                {event.points ?? 0}
              </strong>{" "}
              — {event.component ?? "unknown_component"}
            </p>

            <p>{formatDetails(event.details)}</p>
          </div>
        ))}
      </div>
    </InfoSection>
  );
}

function MitreMapping({ mitreMapping }) {
  const mappings = mitreMapping?.mappings || [];

  if (mappings.length === 0) {
    return (
      <InfoSection title="MITRE ATT&CK Mapping">
        <p>No MITRE mapping found.</p>
      </InfoSection>
    );
  }

  return (
    <InfoSection title="MITRE ATT&CK Mapping">
      <ul>
        {mappings.map((mapping, index) => (
          <li key={index}>
            <strong>{mapping.technique_id ?? "Unknown Technique"}</strong> —{" "}
            {mapping.technique_name ?? "Unknown Name"}
          </li>
        ))}
      </ul>
    </InfoSection>
  );
}

function AIStyleExplanation({ explanation }) {
  if (!explanation) {
    return null;
  }

  return (
    <InfoSection title="Local AI-Style Explanation">
      <p>
        <strong>Executive Summary:</strong>{" "}
        {explanation.executive_summary ?? "N/A"}
      </p>

      <p>
        <strong>Evidence Summary:</strong>{" "}
        {explanation.evidence_summary ?? "N/A"}
      </p>

      <p>
        <strong>Missing Context:</strong>{" "}
        {explanation.missing_context_summary ?? "N/A"}
      </p>

      <p>
        <strong>False-Positive Summary:</strong>{" "}
        {explanation.false_positive_summary ?? "N/A"}
      </p>

      <p>
        <strong>MITRE Summary:</strong> {explanation.mitre_summary ?? "N/A"}
      </p>

      <p>
        <strong>Recommendation:</strong>{" "}
        {explanation.recommendation ?? "N/A"}
      </p>

      {explanation.safety_note && (
        <p className="muted">{explanation.safety_note}</p>
      )}
    </InfoSection>
  );
}

function LLMExplanation({ explanation }) {
  if (!explanation) {
    return null;
  }

  if (!explanation.enabled) {
    return (
      <InfoSection title="LLM Explanation">
        <p>{explanation.message ?? "LLM explanation is disabled."}</p>
      </InfoSection>
    );
  }

  return (
    <InfoSection title="LLM Explanation">
      <pre className="plain-text-output">{explanation.explanation}</pre>

      {explanation.safety_note && (
        <p className="muted">{explanation.safety_note}</p>
      )}
    </InfoSection>
  );
}

function InfoSection({ title, children }) {
  return (
    <section className="info-section">
      <h3>{title}</h3>
      {children}
    </section>
  );
}

function List({ items }) {
  if (!items || items.length === 0) {
    return <p>None.</p>;
  }

  return (
    <ul>
      {items.map((item, index) => (
        <li key={index}>{formatDetails(item)}</li>
      ))}
    </ul>
  );
}

function OrderedList({ items }) {
  if (!items || items.length === 0) {
    return <p>None.</p>;
  }

  return (
    <ol>
      {items.map((item, index) => (
        <li key={index}>{formatDetails(item)}</li>
      ))}
    </ol>
  );
}

function formatDetails(value) {
  if (value === null || value === undefined) {
    return "N/A";
  }

  if (typeof value === "string" || typeof value === "number") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.join(", ");
  }

  return JSON.stringify(value);
}

export default App;