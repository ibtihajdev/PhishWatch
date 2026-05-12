# PhishWatch — Detection of Phishing Websites Using Machine Learning

> **Final Year Project** · Department of Computer Science, Faculty of Computing & IT, University of Gujrat (Pakistan)  
> **Supervised by:** Mr. Adeel Ahmed

---

## 📌 Overview

PhishWatch is an AI-powered phishing URL detection system. It extracts 16 structural and behavioural features from any URL and passes them through a trained **XGBoost classifier** to produce a real-time verdict: **Safe** or **Phishing**, along with a confidence score.

---

## 🧑‍💻 Team

| Name | Roll Number |
|------|------------|
| Muhammad Waseem Raza | 22024119-005 |
| Mian Fasi Ur Rehman | 22024119-067 |
| Ali Abdullah | 22024119-088 |

---

## 🛠 Tech Stack

| Layer | Technology |
|-------|-----------|
| Machine Learning | Python, XGBoost, scikit-learn, pandas |
| Backend API | Django 3.2, Django REST Framework |
| Frontend | HTML5, Vanilla CSS, JavaScript |
| Feature Extraction | python-whois, requests, BeautifulSoup4, ipaddress |

---

## 📁 Project Structure

```
Detection-of-Phishing-Website-Using-Machine-Learning-master/
├── ML work/
│   ├── DataSets/
│   │   ├── urldata.csv           # Primary dataset (11,430 URLs)
│   │   ├── online-valid_ds.csv   # Additional dataset
│   │   └── Benign_url_file.csv   # Benign URL dataset
│   ├── train_xgboost.py          # Model training script
│   └── MODEL_REPORT.md           # Detailed ML report
│
└── Project_Webapp/
    ├── phisbusterv2/             # Frontend (open index.html)
    │   ├── index.html            # Main UI
    │   └── assets/css/custom.css # Dark theme styles
    │
    └── django Integration/django Integration/django_admin/
        ├── manage.py
        ├── api/
        │   ├── views.py              # Prediction & health endpoints
        │   ├── urls.py               # /predict/ and /health/
        │   ├── phishing_url_detection.py  # 16-feature extractor
        │   ├── tests.py              # Django test suite
        │   └── XGBoostClassifier.pickle.dat  # Trained model
        └── django_admin/
            └── settings.py
```

---

## 🚀 Setup & Running

### 1. Train the ML Model

```powershell
cd "d:\Detection-of-Phishing-Website-Using-Machine-Learning-master\ML work"
# Activate your virtual environment first, then:
python train_xgboost.py
```

This outputs:
- `XGBoostClassifier.pickle.dat` — trained model (auto-saved to API folder)
- `model_metrics.json` — accuracy, F1, feature importances

### 2. Start the Django Backend

```powershell
cd "d:\Detection-of-Phishing-Website-Using-Machine-Learning-master\Project_Webapp\django Integration\django Integration\django_admin"
.venv\Scripts\activate
python manage.py runserver
```

Backend runs at: `http://127.0.0.1:8000`

### 3. Open the Frontend

Open `Project_Webapp/phisbusterv2/index.html` directly in a browser.

---

## 🔌 API Reference

### `POST /predict/`

**Request:**
```json
{ "url": "https://www.example.com" }
```

**Response:**
```json
{
  "success": true,
  "ml_verdict": "Legitimate",
  "confidence": 97.4,
  "domain": "example.com",
  "features": {
    "Have_IP": 0,
    "Have_At": 0,
    "URL_Length": 0,
    ...
  }
}
```

### `GET /health/`
```json
{ "status": "ok", "model_loaded": true }
```

---

## 🤖 Model Details

| Parameter | Value |
|-----------|-------|
| Algorithm | XGBoost Classifier |
| n_estimators | 300 |
| max_depth | 6 |
| learning_rate | 0.05 |
| subsample | 0.8 |
| colsample_bytree | 0.8 |
| Train/Test split | 80% / 20% |
| Cross-validation | 5-fold Stratified |

See `ML work/MODEL_REPORT.md` for full results after training.

---

## 🔍 16 Extracted Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | Have_IP | IP address used instead of domain |
| 2 | Have_At | `@` symbol in URL |
| 3 | URL_Length | URL length ≥ 54 characters |
| 4 | URL_Depth | Number of sub-folders in path |
| 5 | Redirection | Double slash `//` after scheme |
| 6 | https_Domain | Missing HTTPS |
| 7 | TinyURL | URL shortening service used |
| 8 | Prefix/Suffix | Hyphen `-` in domain name |
| 9 | DNS_Record | No DNS record found |
| 10 | Web_Traffic | Not in Alexa top 100K |
| 11 | Domain_Age | Domain age < 6 months |
| 12 | Domain_End | Domain expires within 6 months |
| 13 | iFrame | Invisible iFrame present |
| 14 | Mouse_Over | Fake URL shown on hover |
| 15 | Right_Click | Right-click disabled |
| 16 | Web_Forwards | Excessive HTTP redirects |

---

## 🧪 Running Tests

```powershell
cd "...django_admin"
python manage.py test api
```

Tests cover: health endpoint, response structure, validation, and smoke tests.

---

## 📜 License

Academic project — University of Gujrat, 2026.
