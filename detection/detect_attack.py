import joblib
import pandas as pd

# Load trained model
model = joblib.load("../model/ids_model.pkl")

def detect_intrusion(input_data):
    """
    input_data: dictionary of network features
    """
    df = pd.DataFrame([input_data])
    prediction = model.predict(df)[0]

    if prediction == 0:
        return "Normal Traffic"
    elif prediction == 1:
        return "DoS Attack"
    elif prediction == 2:
        return "Probe Attack"
    elif prediction == 3:
        return "R2L Attack"
    else:
        return "U2R Attack"

# Example test
sample_data = {
    "duration": 0,
    "protocol_type": 1,
    "service": 22,
    "flag": 9,
    "src_bytes": 54540,
    "dst_bytes": 8314
}

result = detect_intrusion(sample_data)
print("Detection Result:", result)
