import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier

# Features: [packet_count, mean_size, std_size, mean_iat, std_iat (jitter), unique_ports]
X = []
y = []

# 0: Benign (Normal traffic)
for _ in range(1000):
    X.append([np.random.randint(15, 60), np.random.uniform(400, 1100), np.random.uniform(50, 200), np.random.uniform(0.1, 0.5), np.random.uniform(0.05, 0.2), np.random.randint(1, 3)])
    y.append(0)

# 1: Port Scan (Reconnaissance)
for _ in range(300):
    X.append([np.random.randint(30, 100), np.random.uniform(54, 80), np.random.uniform(0, 10), np.random.uniform(0.01, 0.05), np.random.uniform(0.001, 0.01), np.random.randint(20, 80)])
    y.append(1)

# 2: Botnet C2 Beaconing (Zero Jitter Pulse)
for _ in range(300):
    X.append([np.random.randint(10, 25), np.random.uniform(150, 300), np.random.uniform(2, 15), np.random.uniform(1.0, 3.0), np.random.uniform(0.0001, 0.003), 1])
    y.append(2)

# 3: Volumetric DDoS (Burst surge)
for _ in range(300):
    X.append([np.random.randint(400, 1000), np.random.uniform(64, 128), np.random.uniform(0, 15), np.random.uniform(0.0001, 0.002), np.random.uniform(0.00001, 0.0005), 1])
    y.append(3)

X = np.array(X)
y = np.array(y)

# Train Random Forest Classifier
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X, y)

# Save Model
joblib.dump(clf, "threat_model.pkl")
print("✅ Threat Model Trained Successfully & Saved as 'threat_model.pkl'!")