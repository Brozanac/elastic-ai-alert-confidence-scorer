# Backup and Recovery Procedure

## Purpose

Define how alert history and project files can be recovered.

## Assets Requiring Backup

- source code
- documentation
- alert history database, if used for demos
- test evidence
- configuration examples

## Current Backup Method

- Source code is stored in Git.
- Local SQLite database is excluded from Git.
- `.env` is excluded from Git and must be recreated from `.env.example`.

## Recovery Steps

1. Clone the repository.
2. Create a new `.env` from `.env.example`.
3. Install backend dependencies.
4. Install frontend dependencies.
5. Run tests.
6. Start backend and frontend.

## Commands

```bash
git clone <repository>
python -m pip install -r requirements.txt
cd frontend && npm install
python -m pytest -v