# Elastic AI Alert Confidence Scorer

## Project Goal

This project scores Elastic-style security alerts based on confidence.

The goal is to help SOC analysts understand whether an AI-generated alert explanation is strongly supported by evidence, missing important context, or likely to be a false positive.

## Day 1 Progress

Implemented the first rule-based confidence scoring engine.

Current features:

- Accepts Elastic-style alert JSON files
- Scores suspicious process execution alerts
- Detects encoded PowerShell usage
- Detects suspicious Office parent processes
- Identifies missing context
- Identifies simple false-positive indicators
- Prints an analyst-readable report in the terminal

## Current Scoring Factors

Positive indicators:

- High or critical rule severity
- High risk score
- Suspicious process name
- Encoded PowerShell command
- Stealthy PowerShell flags
- Suspicious Office parent process
- Network destination present

Negative indicators:

- Missing host
- Missing user
- Missing process name
- Missing command line
- Missing parent process
- Known admin user
- Known management host

## Example

```bash
python backend/run_day1.py backend/sample_alerts/suspicious_powershell.json

```
```
Example result:
Confidence Score: 100/100
Confidence Level: High
```

## Day 2 Progress

Implemented the API version of the alert confidence scorer.

New features:

- Added FastAPI backend
- Added `/score-alert` endpoint
- Added `/score-alert/report` endpoint
- Added MITRE ATT&CK mapping
- Added analyst next steps
- Added Markdown report generation
- Improved support for authentication-based alerts

## Running the API

```bash
cd backend
uvicorn main:app --reload
```

## Day 3 Progress

Implemented the final MVP workflow.

New features:

- Added safe AI-style explanation layer
- Added `/score-alert/explain` endpoint
- Added `/score-alert/full` endpoint
- Added full alert analysis output
- Added demo runner for all sample alerts
- Improved project presentation for GitHub

## Important Design Choice

The AI-style explanation does not calculate the confidence score.

The score is calculated by a transparent rule-based scoring engine.

The explanation layer only explains:

- What evidence was found
- What context is missing
- What MITRE ATT&CK techniques were mapped
- What the analyst should check next

This reduces the risk of hallucinated or unsupported AI conclusions.

## Final MVP Flow

```text
Elastic-style alert JSON
        ↓
Evidence extraction
        ↓
Confidence scoring
        ↓
MITRE ATT&CK mapping
        ↓
Analyst next steps
        ↓
Safe AI-style explanation
        ↓
JSON or Markdown report

```

## Day 4 Progress

Implemented alert-type-aware scoring.

The scorer now detects the alert category before applying scoring rules.

Supported alert types:

- `process_execution`
- `authentication`
- `network`
- `file_or_malware`
- `privilege_escalation`
- `unknown`

This fixed an important scoring issue: authentication alerts were previously penalized for missing process fields such as `process.name`, `process.command_line`, and `process.parent.name`.

Now, missing context is evaluated based on alert type.

For example:

- Process alerts care about process name, command line, parent process, and destination IP.
- Authentication alerts care about source IP, event action, event outcome, user, and host.
- Network alerts care about source IP, destination IP, destination port, and protocol.
- File alerts care about file name, file path, and file hash.

## New Sample Alerts

Added:

- `network_sensitive_port.json`
- `suspicious_file_download.json`

## Example Result

```text
Alert file: failed_login_bruteforce.json
Rule: Multiple Failed Logins from External IP
Alert Type: authentication
Score: 55/100
Confidence: Medium
```