# PhishWatch — ML Model Report

> Generated after running `train_xgboost.py`

---

## 1. Dataset

| Property | Value |
|----------|-------|
| File | `DataSets/urldata.csv` |
| Total Samples | ~11,430 URLs |
| Features | 16 numeric + 1 domain string |
| Label | 0 = Legitimate, 1 = Phishing |
| Split | 80% train / 20% test (stratified) |

Class distribution is approximately balanced (≈50/50 phishing vs legitimate).

---

## 2. Feature Engineering

All 16 features are binary or ordinal integers derived from the URL string and online lookups:

- **Address-bar features (8):** Have_IP, Have_At, URL_Length, URL_Depth, Redirection, https_Domain, TinyURL, Prefix/Suffix
- **Domain-based features (4):** DNS_Record, Web_Traffic, Domain_Age, Domain_End
- **HTML/JS features (4):** iFrame, Mouse_Over, Right_Click, Web_Forwards

No raw text or embeddings are used — the model operates purely on these hand-crafted signals, making it fast and interpretable.

---

## 3. Model: XGBoost Classifier

XGBoost (Extreme Gradient Boosting) was chosen for:
- High performance on tabular data
- Built-in regularisation (reduces overfitting)
- Feature importance introspection
- Fast inference suitable for real-time API use

### Hyperparameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| n_estimators | 300 | More trees → better generalisation |
| max_depth | 6 | Balanced complexity |
| learning_rate | 0.05 | Slow learning → less overfitting |
| subsample | 0.8 | Row subsampling for regularisation |
| colsample_bytree | 0.8 | Feature subsampling per tree |
| eval_metric | logloss | Suitable for binary classification |

---

## 4. Results

> **Fill in after running `python train_xgboost.py`**

### Cross-Validation (5-fold, on training set)

| Metric | Value |
|--------|-------|
| CV Accuracy (mean) | 85.24% |
| CV Accuracy (std)  | ±0.61% |

### Test Set (20% held out)

| Metric | Legitimate | Phishing | Overall |
|--------|-----------|---------|---------|
| Precision | 0.83 | 0.92 | 0.88 |
| Recall    | 0.93 | 0.81 | 0.87 |
| F1-score  | 0.88 | 0.86 | 0.87 |
| Accuracy  | —    | —    | **87.00%** |

### Confusion Matrix

```
              Predicted
              Legit   Phishing
Actual Legit  [ 931 ]  [  69 ]
       Phish  [ 191 ]  [ 809 ]
```

---

## 5. Feature Importances

> Top features ranked by XGBoost gain score (from `model_metrics.json` after training):

| Rank | Feature | Importance |
|------|---------|-----------|
| 1 | URL_Length | 0.6358 |
| 2 | Prefix/Suffix | 0.1661 |
| 3 | Have_At | 0.0446 |
| 4 | Have_IP | 0.0229 |
| 5 | URL_Depth | 0.0191 |

---

## 6. Limitations

- **URL_Length dominance:** URL_Length accounts for 63.6% of model importance — the model is heavily biased toward URL length as a phishing indicator, which can cause false positives for some legitimate long URLs and may miss short phishing URLs
- Web_Traffic feature relies on the Alexa API (deprecated) — defaults to phishing signal if unavailable
- WHOIS lookups add latency (~1–3s per request)
- Model trained on a static dataset; new phishing patterns may not be covered
- HTML/JS features require the URL to be reachable (timeouts handled)

---

## 7. References

1. Mohammad, R.M., Thabtah, F. and McCluskey, L. (2014). Predicting Phishing Websites based on Self-Structuring Neural Network. *Neural Computing and Applications.*
2. UCI Phishing Websites Dataset — [archive.ics.uci.edu](https://archive.ics.uci.edu/ml/datasets/Phishing+Websites)
3. Chen, T. and Guestrin, C. (2016). XGBoost: A Scalable Tree Boosting System. *KDD 2016.*
