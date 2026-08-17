Write-Host "Running backend tests..."
python -m pytest -v

Write-Host "Running Python dependency audit..."
python -m pip-audit -r requirements.txt

Write-Host "Running Bandit..."
python -m bandit -r backend

Write-Host "Running frontend audit..."
Set-Location frontend
npm audit
Set-Location ..

Write-Host "Running Gitleaks..."
gitleaks detect --source . --verbose