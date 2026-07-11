# train_exe_model.py

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import pefile

# =========================
# Step 1: Create Dataset
# =========================
# Format: [file_size, entropy, label]
# label: 1 = malware, 0 = safe

data = [
    # Malware
    [12000, 6.5, 3, 1],
    [15000, 7.2, 4, 1],
    [20000, 7.8, 5, 1],
    [30000, 7.9, 6, 1],
    [18000, 6.8, 4, 1],

    # SAFE (important)
    [200000000, 6.7, 8, 0],   # VS Code-like
    [150000000, 6.5, 7, 0],
    [100000000, 6.2, 6, 0],
    [50000000, 5.8, 5, 0],
    [30000000, 5.5, 4, 0]
]

df = pd.DataFrame(data, columns=["size", "entropy", "num_sections", "label"])
df["num_sections"] = 3

print("📊 Dataset:")
print(df)

# =========================
# Step 2: Split Features
# =========================
X = df[["size", "entropy", 'num_sections']]
y = df["label"]

# =========================
# Step 3: Train Model
# =========================
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

print("\n✅ Model trained successfully")

# =========================
# Step 4: Save Model
# =========================
joblib.dump(model, "exe_model.pkl")

print("💾 Model saved as exe_model.pkl")

# =========================
# Step 5: Test Model
# =========================
test_sample = [[10000, 7.0, 3]]  # example input
prediction = model.predict(test_sample)

print("\n🧪 Test Prediction for [size=10000, entropy=7.0]:")
print("Prediction:", "Malware" if prediction[0] == 1 else "Safe")