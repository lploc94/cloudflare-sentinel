/**
 * ML module for request classification
 * 
 * Provides lightweight inference compatible with scikit-learn models.
 * 
 * ## Training (Python)
 * 
 * ```python
 * from sklearn.feature_extraction.text import HashingVectorizer
 * from sklearn.linear_model import LogisticRegression
 * import json
 * 
 * # Configure vectorizer (MUST match JS config)
 * vectorizer = HashingVectorizer(
 *     n_features=4096,
 *     analyzer='char_wb',
 *     ngram_range=(3, 5),
 *     alternate_sign=False,  # Important!
 *     norm=None              # Important!
 * )
 * 
 * # Train
 * X = vectorizer.fit_transform(texts)
 * clf = LogisticRegression()
 * clf.fit(X, labels)
 * 
 * # Export to JSON
 * model = {
 *     "type": "logistic_regression",
 *     "classes": clf.classes_.tolist(),
 *     "weights": clf.coef_.tolist(),
 *     "bias": clf.intercept_.tolist(),
 *     "vectorizer": {
 *         "nFeatures": 4096,
 *         "ngramRange": [3, 5],
 *         "analyzer": "char_wb"
 *     }
 * }
 * 
 * with open("model.json", "w") as f:
 *     json.dump(model, f)
 * ```
 * 
 * ## Inference (Worker)
 * 
 * ```typescript
 * import { LinearClassifier } from 'cloudflare-sentinel/ml';
 * import modelJson from './model.json';
 * 
 * const classifier = new LinearClassifier(modelJson);
 * 
 * const prediction = classifier.predictText("SELECT * FROM users WHERE id=1");
 * // { class: 'sqli', confidence: 0.95, ... }
 * ```
 */

export { murmurhash3_32 } from './murmurhash3';
export { HashingVectorizer, type HashingVectorizerOptions } from './hashing-vectorizer';
export { 
  LinearClassifier, 
  MultiOutputClassifier,
  type ModelWeights, 
  type MultiOutputModelWeights,
  type Prediction,
  type MultiOutputPrediction,
} from './classifier';
