Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Setting up PhishWatch Project Environment " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Navigate to the correct directory
$ProjectDir = "Project_Webapp\django Integration\django Integration"
if (Test-Path $ProjectDir) {
    Set-Location $ProjectDir
} else {
    Write-Host "Could not find the directory: $ProjectDir" -ForegroundColor Red
    Write-Host "Please ensure you run this script from the project root." -ForegroundColor Red
    exit 1
}

# Create a virtual environment if it doesn't exist
if (-not (Test-Path ".venv")) {
    Write-Host "[1/4] Creating a new Python Virtual Environment..." -ForegroundColor Yellow
    python -m venv .venv
} else {
    Write-Host "[1/4] Virtual Environment already exists. Skipping creation." -ForegroundColor Green
}

Write-Host "[2/4] Activating Virtual Environment..." -ForegroundColor Yellow
$env:VIRTUAL_ENV="$PWD\.venv"
$env:PATH="$PWD\.venv\Scripts;$env:PATH"

Write-Host "[3/4] Installing Required Libraries..." -ForegroundColor Yellow
python -m pip install --upgrade pip | Out-Null
pip install -r requirements.txt
# Install extra required dependencies that might be missing from requirements.txt
pip install firebase-admin django-redis redis

Write-Host "[4/4] Starting Django Development Server..." -ForegroundColor Green
Write-Host ""
Write-Host "========================================================" -ForegroundColor Magenta
Write-Host " Open your browser to: http://localhost:8000/app/ " -ForegroundColor Magenta
Write-Host "========================================================" -ForegroundColor Magenta
Write-Host ""

Set-Location "django_admin"
python manage.py runserver
