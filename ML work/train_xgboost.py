import pandas as pd
import numpy as np
import xgboost as xgb
import pickle
import os
import json
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# ─── Paths ────────────────────────────────────────────────────────────────────
DATA_PATH    = "DataSets/urldata.csv"
MODEL_DIR    = "../Project_Webapp/django Integration/django Integration/django_admin/api"
MODEL_PATH   = os.path.join(MODEL_DIR, "XGBoostClassifier.pickle.dat")
METRICS_PATH = os.path.join(MODEL_DIR, "model_metrics.json")

# ─── Load data ────────────────────────────────────────────────────────────────
print("Loading dataset...")
data = pd.read_csv(DATA_PATH)
print(f"  Dataset shape: {data.shape}")
print(f"  Class distribution:\n{data['Label'].value_counts().to_string()}\n")
data = data.drop(['Domain'], axis=1).copy()

# ─── Drop unreliable/deprecated features ──────────────────────────────────────
# Web_Traffic: Alexa API shut down — returns same fallback value at runtime
# Domain_Age : python-whois returns inconsistent/wrong data for many real domains
# Domain_End : same WHOIS unreliability
DROP_FEATURES = ['Web_Traffic', 'Domain_Age', 'Domain_End']
print(f"Dropping unreliable features: {DROP_FEATURES}")
data = data.drop(columns=DROP_FEATURES)

X = data.drop('Label', axis=1)
y = data['Label']
FEATURE_NAMES = list(X.columns)
print(f"  Remaining features ({len(FEATURE_NAMES)}): {FEATURE_NAMES}\n")

# ─── Train / Test split ───────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)
print(f"Train: {len(X_train)} | Test: {len(X_test)}\n")

# ─── Model ────────────────────────────────────────────────────────────────────
model = xgb.XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1,
)

# ─── Cross-validation ─────────────────────────────────────────────────────────
print("Running 5-fold cross-validation...")
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(model, X_train, y_train, cv=skf, scoring="accuracy", n_jobs=-1)
print(f"  CV Accuracy: {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*100:.2f}%)\n")

# ─── Final fit ────────────────────────────────────────────────────────────────
print("Training final model...")
model.fit(X_train, y_train)

# ─── Evaluation ───────────────────────────────────────────────────────────────
print("\n===== TEST SET EVALUATION =====")
y_pred = model.predict(X_test)
acc    = accuracy_score(y_test, y_pred)
print(f"Accuracy: {acc*100:.2f}%")
print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
cm = confusion_matrix(y_test, y_pred)
print("Confusion Matrix:\n", cm)

importances = {n: float(s) for n, s in zip(FEATURE_NAMES, model.feature_importances_)}
sorted_imp  = dict(sorted(importances.items(), key=lambda x: x[1], reverse=True))
print("\nTop-5 Features:")
for k, v in list(sorted_imp.items())[:5]:
    print(f"  {k}: {v:.4f}")

# ─── Save model + metrics ─────────────────────────────────────────────────────
os.makedirs(MODEL_DIR, exist_ok=True)
with open(MODEL_PATH, "wb") as f:
    pickle.dump(model, f)
print(f"\nModel saved -> {MODEL_PATH}")

report  = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"], output_dict=True)
metrics = {
    "accuracy": round(acc * 100, 2),
    "cv_accuracy_mean": round(cv_scores.mean() * 100, 2),
    "cv_accuracy_std":  round(cv_scores.std()  * 100, 2),
    "feature_names": FEATURE_NAMES,
    "dropped_features": DROP_FEATURES,
    "feature_importances": sorted_imp,
    "classification_report": report,
    "confusion_matrix": cm.tolist(),
    "train_size": int(len(X_train)),
    "test_size":  int(len(X_test)),
}
with open(METRICS_PATH, "w") as f:
    json.dump(metrics, f, indent=2)
print(f"Metrics saved -> {METRICS_PATH}\nDone!")
