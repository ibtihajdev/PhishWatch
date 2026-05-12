Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "       Starting PhishWatch Server       " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Load .env file if it exists in the root directory
$EnvFile = ".env"
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | Where-Object { $_ -match "^[^#=]+=" } | ForEach-Object {
        $name, $value = $_.Split("=", 2)
        [System.Environment]::SetEnvironmentVariable($name.Trim(), $value.Trim())
    }
}

# Navigate to the correct directory
$ProjectDir = "Project_Webapp\django Integration\django Integration"
if (Test-Path $ProjectDir) {
    Set-Location $ProjectDir
} else {
    Write-Host "Could not find the directory: $ProjectDir" -ForegroundColor Red
    Write-Host "Please ensure you run this script from the project root." -ForegroundColor Red
    exit 1
}

# Activate Virtual Environment
if (Test-Path ".venv") {
    Write-Host "Activating Virtual Environment..." -ForegroundColor Yellow
    $env:VIRTUAL_ENV="$PWD\.venv"
    $env:PATH="$PWD\.venv\Scripts;$env:PATH"
} else {
    Write-Host "Virtual Environment not found! Please run .\install_and_run.ps1 first." -ForegroundColor Red
    exit 1
}

Write-Host "Starting Django Development Server..." -ForegroundColor Green
Write-Host ""
Write-Host "========================================================" -ForegroundColor Magenta
Write-Host " Open your browser to: http://localhost:8000/app/ " -ForegroundColor Magenta
Write-Host "========================================================" -ForegroundColor Magenta
Write-Host ""

Set-Location "django_admin"
python manage.py runserver
