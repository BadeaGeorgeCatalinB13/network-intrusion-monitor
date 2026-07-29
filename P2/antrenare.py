import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

df = pd.read_csv("trafic_normal.csv")
model = IsolationForest(contamination=0.05, random_state=42)
model.fit(df)
joblib.dump(model, "model_anomalii.joblib")
print("[*] Modelul Isolation Forest a fost antrenat și salvat cu succes!")
