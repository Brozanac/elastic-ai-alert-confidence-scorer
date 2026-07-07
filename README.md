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