from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from joblib import dump, load
import os
import csv
import pandas as pd

MODEL_FILE = "ai/models/eks_root_cause_model.joblib"
DATA_FILE = "ai/data/eks_issue_training_data.csv"


def train_model():
    """Train a basic model for root cause prediction"""
    if not os.path.exists(DATA_FILE):
        print(f" Training data '{DATA_FILE}' not found.")
        return None

    df = pd.read_csv(DATA_FILE)
    X = df["event_message"]
    y = df["root_cause"]

    model = Pipeline([
        ('tfidf', TfidfVectorizer()),
        ('clf', LogisticRegression())
    ])

    model.fit(X, y)

    # Save model
    os.makedirs(os.path.dirname(MODEL_FILE), exist_ok=True)
    temp_file = MODEL_FILE.replace(".joblib", "_temp.joblib")
    
    try:
        dump(model, temp_file)
        os.rename(temp_file, MODEL_FILE)
        print(f"Model trained and saved to {MODEL_FILE}")
        return model
    except Exception as e:
        print(f" Model save failed: {e}")
        return None


def load_model():
    """Load pre-trained model"""
    if not os.path.exists(MODEL_FILE):
        print("Model file not found. Retraining...")
        return train_model()
    try:
        model = load(MODEL_FILE)
        print("Loaded existing model.")
        return model
    except Exception as e:
        print(f"Model loading failed: {e}")
        return train_model()


def predict_root_cause(event_message):
    """Predict root cause from event message"""
    model = load_model()
    if not model:
        return {"predicted_cause": "Unknown", "confidence": 0}
    try:
        pred = model.predict([event_message])
        proba = model.predict_proba([event_message]).max()
        return {
            "predicted_cause": pred[0],
            "confidence": round(proba * 100, 2)
        }
    except Exception as e:
        return {"error": str(e)}