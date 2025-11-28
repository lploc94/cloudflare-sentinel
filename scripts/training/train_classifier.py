#!/usr/bin/env python3
"""
Request Classifier Training Script

Train a lightweight classifier for web attack detection.
Output model is compatible with cloudflare-sentinel's ML module.

Usage:
    python train_classifier.py --data dataset.jsonl --output ../models/classifier.json

Dataset format (JSONL):
    {"text": "GET /api/users?id=1", "label": "safe"}
    {"text": "GET /api/users?id=1' OR '1'='1", "label": "sqli"}
    {"text": "GET /search?q=<script>alert(1)</script>", "label": "xss"}
"""

import argparse
import json
from pathlib import Path
from typing import List, Dict, Any

import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix


# Vectorizer config - MUST match TypeScript implementation
VECTORIZER_CONFIG = {
    "n_features": 4096,
    "analyzer": "char_wb",
    "ngram_range": (3, 5),
    "alternate_sign": False,  # Important for JS compatibility
    "norm": None,             # Important for JS compatibility
}


def load_dataset(path: str) -> tuple[List[str], List[str]]:
    """Load dataset from JSONL file."""
    texts = []
    labels = []
    
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                texts.append(item['text'])
                labels.append(item['label'])
    
    print(f"Loaded {len(texts)} samples")
    print(f"Labels: {set(labels)}")
    
    return texts, labels


def create_vectorizer() -> HashingVectorizer:
    """Create HashingVectorizer with JS-compatible config."""
    return HashingVectorizer(**VECTORIZER_CONFIG)


def train_model(X, y, model_type: str = 'logistic'):
    """Train classifier."""
    if model_type == 'logistic':
        clf = LogisticRegression(
            max_iter=1000,
            multi_class='multinomial',
            solver='lbfgs',
            C=1.0,
        )
    elif model_type == 'sgd':
        clf = SGDClassifier(
            loss='log_loss',
            penalty='l2',
            max_iter=1000,
            tol=1e-3,
        )
    else:
        raise ValueError(f"Unknown model type: {model_type}")
    
    clf.fit(X, y)
    return clf


def export_model(clf, vectorizer: HashingVectorizer, output_path: str):
    """Export model to JSON for TypeScript inference."""
    classes = clf.classes_.tolist()
    
    # For binary classification, sklearn outputs single weight row
    # We need to expand to 2 rows for consistent inference
    if len(classes) == 2:
        # weights[0] = -coef (for class 0: safe)
        # weights[1] = +coef (for class 1: suspicious)
        weights = [
            (-clf.coef_[0]).tolist(),
            clf.coef_[0].tolist(),
        ]
        bias = [
            -clf.intercept_[0],
            clf.intercept_[0],
        ]
    else:
        weights = clf.coef_.tolist()
        bias = clf.intercept_.tolist()
    
    model = {
        "type": "logistic_regression",
        "classes": classes,
        "weights": weights,
        "bias": bias,
        "vectorizer": {
            "nFeatures": vectorizer.n_features,
            "ngramRange": list(vectorizer.ngram_range),
            "analyzer": vectorizer.analyzer,
        }
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(model, f, indent=2)
    
    # Calculate model size
    size_bytes = Path(output_path).stat().st_size
    print(f"Model saved to {output_path} ({size_bytes / 1024:.1f} KB)")


def evaluate_model(clf, X_test, y_test):
    """Evaluate model performance."""
    y_pred = clf.predict(X_test)
    
    print("\n=== Classification Report ===")
    print(classification_report(y_test, y_pred))
    
    print("\n=== Confusion Matrix ===")
    print(confusion_matrix(y_test, y_pred))
    
    # Cross-validation score
    print(f"\nAccuracy: {clf.score(X_test, y_test):.4f}")


def main():
    parser = argparse.ArgumentParser(description='Train request classifier')
    parser.add_argument('--data', required=True, help='Path to training data (JSONL)')
    parser.add_argument('--output', default='models/classifier.json', help='Output model path')
    parser.add_argument('--model', default='logistic', choices=['logistic', 'sgd'], help='Model type')
    parser.add_argument('--test-size', type=float, default=0.2, help='Test set size (0-1)')
    args = parser.parse_args()
    
    # Load data
    texts, labels = load_dataset(args.data)
    
    # Create vectorizer
    vectorizer = create_vectorizer()
    
    # Transform texts
    print("\nVectorizing texts...")
    X = vectorizer.fit_transform(texts)
    print(f"Feature matrix shape: {X.shape}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, labels, 
        test_size=args.test_size, 
        random_state=42,
        stratify=labels
    )
    print(f"Train: {X_train.shape[0]}, Test: {X_test.shape[0]}")
    
    # Train
    print(f"\nTraining {args.model} classifier...")
    clf = train_model(X_train, y_train, args.model)
    
    # Evaluate
    evaluate_model(clf, X_test, y_test)
    
    # Export
    print("\nExporting model...")
    export_model(clf, vectorizer, args.output)
    
    print("\n✅ Done!")


if __name__ == '__main__':
    main()
