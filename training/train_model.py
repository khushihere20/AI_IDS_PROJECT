import pandas as pd
import joblib
import json
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score

# ==============================
# 1. LOAD DATASET
# ==============================
DATA_PATH = "../data/nsl_kdd.csv"
data = pd.read_csv(DATA_PATH)

# ==============================
# 2. ATTACK CLASS MAPPING
# ==============================
attack_mapping = {
    # DoS attacks
    "back": "DoS", "land": "DoS", "neptune": "DoS",
    "pod": "DoS", "smurf": "DoS", "teardrop": "DoS",

    # Probe attacks
    "ipsweep": "Probe", "nmap": "Probe",
    "portsweep": "Probe", "satan": "Probe",

    # R2L attacks
    "ftp_write": "R2L", "guess_passwd": "R2L",
    "imap": "R2L", "multihop": "R2L",
    "phf": "R2L", "spy": "R2L",
    "warezclient": "R2L", "warezmaster": "R2L",

    # U2R attacks
    "buffer_overflow": "U2R", "loadmodule": "U2R",
    "perl": "U2R", "rootkit": "U2R",

    # Normal
    "normal": "Normal"
}

# ==============================
# 3. FEATURES & TARGET
# ==============================
X = data.iloc[:, :-1]
y_raw = data.iloc[:, -1]

# Map attack names to classes
y = y_raw.map(attack_mapping)

# Safety check
if y.isnull().sum() > 0:
    raise ValueError("❌ Unmapped attack types found in dataset")

# ==============================
# 4. ENCODE CATEGORICAL FEATURES
# ==============================
feature_encoders = {}

for col in X.select_dtypes(include=["object"]).columns:
    le = LabelEncoder()
    X[col] = le.fit_transform(X[col])
    feature_encoders[col] = list(le.classes_)

# ==============================
# 5. ENCODE TARGET LABELS
# ==============================
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

# ==============================
# 6. SAVE METADATA (IMPORTANT)
# ==============================
with open("feature_columns.json", "w") as f:
    json.dump({
        "features": list(X.columns),
        "attack_classes": list(label_encoder.classes_),
        "categorical_encoders": feature_encoders
    }, f, indent=4)

# ==============================
# 7. TRAIN / TEST SPLIT
# ==============================
X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

# ==============================
# 8. MODEL TRAINING
# ==============================
model = RandomForestClassifier(
    n_estimators=250,
    max_depth=None,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# ==============================
# 9. EVALUATION
# ==============================
preds = model.predict(X_test)
accuracy = accuracy_score(y_test, preds) * 100
print(f"✅ Model Accuracy: {accuracy:.2f}%")

# ==============================
# 10. SAVE MODEL & ENCODER
# ==============================
joblib.dump(model, "../model/ids_model.pkl")
joblib.dump(label_encoder, "../model/label_encoder.pkl")

print("✅ Model, Label Encoder & Metadata saved successfully")
