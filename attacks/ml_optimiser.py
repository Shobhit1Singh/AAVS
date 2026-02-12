"""
Machine Learning Payload Optimizer
Learns which payloads are most effective
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
from typing import List, Dict, Any
from pathlib import Path
import logging
from colorama import Fore, Style

logger = logging.getLogger(__name__)


class MLPayloadOptimizer:
    """
    Uses ML to predict which payloads are most likely to find vulnerabilities
    """
    
    def __init__(self, model_path: str = 'output/ml_models'):
        self.model_path = Path(model_path)
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        # Models
        self.classifier = None
        self.vectorizer = TfidfVectorizer( analyzer="char",
    ngram_range=(2,5),
    max_features=1000)
        
        # Training data
        self.training_payloads = []
        self.training_labels = []  # 1 = found vuln, 0 = safe
        
        self.is_trained = False
    
    def add_training_data(self, payload: str, found_vulnerability: bool):
        """
        Add a test result to training data
        
        Args:
            payload: The attack payload that was sent
            found_vulnerability: Whether it found a vulnerability
        """
        self.training_payloads.append(str(payload))
        self.training_labels.append(1 if found_vulnerability else 0)
    
    def train(self):
        """
        Train the model on collected data
        """
        if len(self.training_payloads) < 10:
            logger.warning(
                f"{Fore.YELLOW}Not enough training data ({len(self.training_payloads)} samples). "
                f"Need at least 10.{Style.RESET_ALL}"
            )
            return False
        
        try:
            print(f"\n{Fore.CYAN}Training ML model...{Style.RESET_ALL}")
            
            # Vectorize payloads
            X = self.vectorizer.fit_transform(self.training_payloads)
            y = np.array(self.training_labels)
            print("X shape:", X.shape)
            print("Sample payload:", self.training_payloads[:3])
            print("Feature names:", self.vectorizer.get_feature_names_out()[:20])
            logging.basicConfig(level=logging.INFO)
            opt = MLPayloadOptimizer()

            for i in range(12):
                opt.add_training_data(f"<script>{i}</script>", i % 2 == 0)
                opt.train()

            # feature_names = self.vectorizer.get_feature_names_out()
            # print(feature_names)
            # print("X shape:", X.shape)
            # print("Sample payload:", self.training_payloads[:3])
            # print("Feature names:", self.vectorizer.get_feature_names_out()[:20])

            # Train classifier
            self.classifier = RandomForestClassifier(
                n_estimators=50,
                max_depth=10,
                random_state=42
            )
            self.classifier.fit(X, y)
            
            # Calculate accuracy
            accuracy = self.classifier.score(X, y)
            
            self.is_trained = True
            
            print(f"{Fore.GREEN}✓ Model trained on {len(self.training_payloads)} samples "
                  f"(accuracy: {accuracy:.2%}){Style.RESET_ALL}\n")
            
            return True
            
        except Exception as e:
            logger.error(f"{Fore.RED}Training failed: {e}{Style.RESET_ALL}")
            return False
    
    def predict_effectiveness(self, payloads: List[str]) -> List[float]:
        """
        Predict how likely each payload is to find a vulnerability
        
        Returns:
            List of probabilities (0.0 - 1.0) for each payload
        """
        if not self.is_trained or not self.classifier:
            # Return uniform probabilities if not trained
            return [0.5] * len(payloads)
        
        try:
            X = self.vectorizer.transform([str(p) for p in payloads])
            probabilities = self.classifier.predict_proba(X)
            # Return probability of finding vulnerability (class 1)
            return probabilities[:, 1].tolist()
        except Exception as e:
            logger.error(f"{Fore.RED}Prediction failed: {e}{Style.RESET_ALL}")
            return [0.5] * len(payloads)
    
    def get_top_payloads(self, payloads: List[str], top_n: int = 10) -> List[str]:
        """
        Get the most promising payloads based on ML prediction
        """
        if len(payloads) <= top_n:
            return payloads
        
        scores = self.predict_effectiveness(payloads)
        
        # Sort by score descending
        sorted_indices = np.argsort(scores)[::-1]
        
        top_payloads = [payloads[i] for i in sorted_indices[:top_n]]
        
        logger.info(
            f"{Fore.CYAN}ML selected top {top_n} payloads from {len(payloads)} candidates{Style.RESET_ALL}"
        )
        
        return top_payloads
    
    def save_model(self):
        """Save trained model to disk"""
        if not self.is_trained:
            logger.warning("No trained model to save")
            return
        
        try:
            model_file = self.model_path / 'payload_classifier.pkl'
            vectorizer_file = self.model_path / 'vectorizer.pkl'
            
            joblib.dump(self.classifier, model_file)
            joblib.dump(self.vectorizer, vectorizer_file)
            
            logger.info(f"{Fore.GREEN}✓ Model saved to {self.model_path}{Style.RESET_ALL}")
        except Exception as e:
            logger.error(f"{Fore.RED}Failed to save model: {e}{Style.RESET_ALL}")
    
    def load_model(self):
        """Load trained model from disk"""
        try:
            model_file = self.model_path / 'payload_classifier.pkl'
            vectorizer_file = self.model_path / 'vectorizer.pkl'
            
            if not model_file.exists() or not vectorizer_file.exists():
                logger.info("No saved model found")
                return False
            
            self.classifier = joblib.load(model_file)
            self.vectorizer = joblib.load(vectorizer_file)
            self.is_trained = True
            
            logger.info(f"{Fore.GREEN}✓ Model loaded from {self.model_path}{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            logger.error(f"{Fore.RED}Failed to load model: {e}{Style.RESET_ALL}")
            return False
    
    def get_stats(self) -> Dict:
        """Get optimizer statistics"""
        return {
            'is_trained': self.is_trained,
            'training_samples': len(self.training_payloads),
            'vulnerable_samples': sum(self.training_labels),
            'safe_samples': len(self.training_labels) - sum(self.training_labels),
        }    
