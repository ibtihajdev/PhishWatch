# How to Setup and Run the Project in VS Code

## Prerequisites
- Python 3.8+ installed on your system.

## Step 1: Open the Project in VS Code
1. Open Visual Studio Code.
2. Go to **File > Open Folder** and select the root folder of this project (`Detection-of-Phishing-Website-Using-Machine-Learning-master`).

## Step 2: Open the Terminal
In VS Code, go to **Terminal > New Terminal** (or press `` Ctrl + ` ``). Ensure your terminal is set to PowerShell or Command Prompt.

## Step 3: Install All Libraries
You can easily install all libraries and run the project using the script provided, or by manually running the commands.

### Option A: Use the automated script (Easiest)
Simply run the setup script I've created for you in the terminal:
```powershell
.\install_and_run.ps1
```

### Option B: Manual Installation
Run the following commands in your VS Code terminal:

```powershell
# Navigate to the backend directory
cd "Project_Webapp\django Integration\django Integration"

# Create a virtual environment
python -m venv .venv

# Activate the virtual environment
.\.venv\Scripts\activate

# Install all required libraries
pip install -r requirements.txt
pip install firebase-admin django-redis redis
```

## Step 4: Run the Project
If you used the manual installation, navigate to the folder containing `manage.py` and start the server:

```powershell
cd django_admin
python manage.py runserver
```

## Step 5: Access the Application
Once the server is running, you will see `Starting development server at http://127.0.0.1:8000/`.

- Open your browser and go to: **[http://localhost:8000/app/](http://localhost:8000/app/)**

> **⚠️ Important Note on Login:** Always use `localhost` instead of `127.0.0.1` in your browser URL. Firebase's Google Sign-In security policy blocks `127.0.0.1` by default but allows `localhost`.
