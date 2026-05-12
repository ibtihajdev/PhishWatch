# Machine Learning & Dataset Showcase

This directory contains the original machine learning workflow, exploratory data analysis, and the diverse datasets used to research and train the phishing detection model. While the final web application uses heuristic approximations of this model, this folder showcases the rigorous data science foundation of the project.

## 📊 Datasets

The project leverages a comprehensive collection of benign and malicious URLs, compiled from multiple sources to ensure a robust and generalized machine learning model.

### Primary Datasets (`/DataSets`)
- **`Benign_url_file.csv`** (4.1 MB): A massive collection of verified safe, benign URLs used as the negative class.
- **`online-valid_ds.csv`** (3.2 MB): Validated real-world URLs.
- **`urldata.csv`** (500 KB): A balanced dataset containing extracted features and target labels used for rapid training iterations.

### University Research Dataset (`/DataSets/Dataset from New burn Uni`)
This subdirectory contains an extensive, multi-class dataset categorized by attack vector, complete with specialized feature-selection splits (BestFirst, InfoGain):
- **Phishing**: `Phishing.csv`, `Phishing_BestFirst.csv`, `Phishing_Infogain.csv`
- **Malware**: `Malware.csv`, `Malware_BestFirst.csv`, `Malware_Infogain.csv`
- **Spam**: `Spam.csv`, `Spam_BestFirst.csv`, `Spam_Infogain.csv`
- **Defacement**: `Defacement.csv`, `Defacement_BestFirst.csv`, `Defacement_Infogain.csv`
- **Combined Aggregates**: `All.csv` (11.6 MB)

## 📓 Jupyter Notebooks

The data science pipeline is documented across interactive Jupyter notebooks:

1. **`URL_Feature_Extraction_from_Datasets.ipynb`**
   - **Purpose:** Demonstrates the feature engineering process.
   - **Details:** Shows how raw URLs are parsed to extract 17 key features (e.g., domain age, presence of '@', redirect behaviors, etc.) using libraries like `BeautifulSoup` and `python-whois`.

2. **`Phishing Website Detection Training & Testing Models on Datasets.ipynb`**
   - **Purpose:** The core machine learning experimentation lab.
   - **Details:** Walks through data loading, preprocessing, model selection, hyperparameter tuning, and evaluation metrics. It culminates in the export of the `XGBoostClassifier.pickle.dat` model.

## 🧠 The Model

The culmination of this research was an **XGBoost Classifier** (`XGBoostClassifier.pickle.dat`). 

*(Note: In the current production deployment of the Django web app, a high-performance, rule-based heuristic engine is used in place of real-time model inference to minimize latency and dependency overhead. However, the logic and thresholds were directly inspired by the feature importance derived from this very ML pipeline.)*
