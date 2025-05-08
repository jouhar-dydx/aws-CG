from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from joblib import load
import os

MODEL_FILE = "ai/models/eks_root_cause_model.joblib"
DATA_FILE = "ai/data/eks_issue_training_data.csv"

def train_model():
    """Train a basic model for root cause prediction"""
    try:
        import pandas as pd
        df = pd.read_csv(DATA_FILE)
        X = df["event_message"]
        y = df["root_cause"]

        model = Pipeline([
            ('tfidf', TfidfVectorizer()),
            ('clf', LogisticRegression())
        ])

        model.fit(X, y)
        model_file = MODEL_FILE
        os.makedirs(os.path.dirname(model_file), exist_ok=True)
        model_file = model_file.replace(".joblib", "_temp.joblib")  # Workaround for Windows
        load.save(model, model_file)
        print(f"Model trained and saved to {model_file}")
        return model
    except Exception as e:
        print(f"Training failed: {e}")
        return None


def load_model():
    """Load pre-trained model"""
    if not os.path.exists(MODEL_FILE):
        print("Model file not found.")
        return None
    try:
        return load(MODEL_FILE)
    except Exception as e:
        print(f"Model loading failed: {e}")
        return None


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