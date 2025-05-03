import os
import pickle
import logging
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Constants
MODEL_PATH = 'phishing_model.joblib'
FEATURE_NAMES_PATH = 'feature_names.joblib'
FEATURE_IMPORTANCES_PATH = 'feature_importances.joblib'

def train_model(X, y, feature_names=None):
    """
    Train a RandomForest model on the provided data
    
    Args:
        X (DataFrame): The feature data
        y (Series): The target labels
        feature_names (list): Names of the features
        
    Returns:
        tuple: The trained model, feature names, and feature importances
    """
    try:
        # Split the data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Create and train the RandomForest model
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=10,
            min_samples_leaf=4,
            random_state=42,
            n_jobs=-1
        )
        
        logger.info("Training the model...")
        model.fit(X_train, y_train)
        
        # Evaluate the model
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        logger.info(f"Model evaluation on test set:")
        logger.info(f"Accuracy: {accuracy:.4f}")
        logger.info(f"Precision: {precision:.4f}")
        logger.info(f"Recall: {recall:.4f}")
        logger.info(f"F1 Score: {f1:.4f}")
        
        # Get feature importances
        feature_importances = model.feature_importances_
        
        # Save the model and feature information
        joblib.dump(model, MODEL_PATH)
        
        if feature_names is not None:
            joblib.dump(feature_names, FEATURE_NAMES_PATH)
            joblib.dump(feature_importances, FEATURE_IMPORTANCES_PATH)
        
        return model, feature_names, feature_importances
        
    except Exception as e:
        logger.error(f"Error training model: {str(e)}")
        raise e

def load_model():
    """
    Load the trained model. If the model doesn't exist, it will train a new one.
    
    Returns:
        tuple: The trained model, feature names, and feature importances
    """
    try:
        if os.path.exists(MODEL_PATH) and os.path.exists(FEATURE_NAMES_PATH) and os.path.exists(FEATURE_IMPORTANCES_PATH):
            # Load the existing model and feature information
            logger.info("Loading existing model...")
            model = joblib.load(MODEL_PATH)
            feature_names = joblib.load(FEATURE_NAMES_PATH)
            feature_importances = joblib.load(FEATURE_IMPORTANCES_PATH)
        else:
            # Train a new model
            logger.info("No existing model found. Training a new model...")
            from utils.data_processor import load_and_preprocess_data
            
            # Load and preprocess the data
            X, y, feature_names = load_and_preprocess_data()
            
            # Train the model
            model, feature_names, feature_importances = train_model(X, y, feature_names)
        
        return model, feature_names, feature_importances
        
    except Exception as e:
        logger.error(f"Error loading model: {str(e)}")
        raise e

def predict_url(model, features_dict, feature_names):
    """
    Predict if a URL is phishing based on its features
    
    Args:
        model: The trained RandomForest model
        features_dict (dict): Dictionary of URL features
        feature_names (list): Names of the features used by the model
        
    Returns:
        tuple: (prediction, probability, features_df)
            - prediction: 1 for phishing, 0 for legitimate
            - probability: Confidence score for the prediction
            - features_df: DataFrame of the features used for prediction
    """
    try:
        # Create a DataFrame from the features dictionary
        features_df = pd.DataFrame([features_dict])
        
        # Ensure that the features are in the correct order and all are present
        for feature in feature_names:
            if feature not in features_df.columns:
                features_df[feature] = 0
        
        # Reorder columns to match the training data
        features_df = features_df[feature_names]
        
        # Make the prediction
        prediction = model.predict(features_df)[0]
        
        # Get the probability of the prediction
        probabilities = model.predict_proba(features_df)[0]
        probability = probabilities[1] if prediction == 1 else probabilities[0]
        
        return prediction, probability, features_df
        
    except Exception as e:
        logger.error(f"Error making prediction: {str(e)}")
        raise e