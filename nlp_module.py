#!/usr/bin/env python3
"""
Phase 2: NLP Analysis & Classification Module
Advanced text analysis using transformer models and topic modeling
"""

import sqlite3
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import logging
import re

# NLP Libraries
try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
    from sentence_transformers import SentenceTransformer
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.decomposition import LatentDirichletAllocation
    from sklearn.cluster import KMeans
    import torch
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False
    logging.warning("Advanced NLP libraries not available. Using basic analysis.")

import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.stem import PorterStemmer
from collections import Counter, defaultdict

# Download required NLTK data
try:
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
    nltk.download('averaged_perceptron_tagger', quiet=True)
except:
    pass

logger = logging.getLogger(__name__)

@dataclass
class AnalysisResult:
    """Structure for analysis results"""
    content_id: int
    text_analysis: Dict[str, Any]
    classification: Dict[str, float]
    topics: List[Tuple[str, float]]
    risk_score: float
    entities: Dict[str, List[str]]
    sentiment: Dict[str, float]
    language: str
    metadata: Dict[str, Any]

class TextPreprocessor:
    """Advanced text preprocessing and cleaning"""
    
    def __init__(self):
        self.stemmer = PorterStemmer()
        try:
            self.stop_words = set(stopwords.words('english'))
        except:
            self.stop_words = set()
        
        # Patterns for different content types
        self.html_pattern = re.compile(r'<[^>]+>')
        self.url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        
    def clean_text(self, text: str) -> str:
        """Clean and normalize text"""
        if not text:
            return ""
        
        # Remove HTML tags
        text = self.html_pattern.sub(' ', text)
        
        # Replace URLs with placeholder
        text = self.url_pattern.sub('[URL]', text)
        
        # Replace emails with placeholder
        text = self.email_pattern.sub('[EMAIL]', text)
        
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text
    
    def tokenize_and_filter(self, text: str, min_length: int = 3) -> List[str]:
        """Tokenize text and filter tokens"""
        try:
            tokens = word_tokenize(text.lower())
        except:
            tokens = text.lower().split()
        
        # Filter tokens
        filtered_tokens = [
            self.stemmer.stem(token) 
            for token in tokens 
            if (token.isalpha() and 
                len(token) >= min_length and 
                token not in self.stop_words)
        ]
        
        return filtered_tokens
    
    def extract_sentences(self, text: str) -> List[str]:
        """Extract sentences from text"""
        try:
            return sent_tokenize(text)
        except:
            return text.split('.')

class CrimeClassifier:
    """Classify content for potential criminal activity"""
    
    def __init__(self):
        self.categories = {
            'drugs': ['drug', 'narcotic', 'cocaine', 'heroin', 'marijuana', 'pills', 'pharmacy'],
            'weapons': ['weapon', 'gun', 'pistol', 'rifle', 'explosive', 'ammunition', 'firearm'],
            'fraud': ['fraud', 'scam', 'fake', 'counterfeit', 'stolen', 'credit card', 'identity'],
            'hacking': ['hack', 'exploit', 'malware', 'ransomware', 'ddos', 'botnet', 'vulnerability'],
            'trafficking': ['trafficking', 'smuggling', 'border', 'transport', 'delivery'],
            'legitimate': ['research', 'academic', 'legal', 'education', 'privacy', 'security']
        }
        
        # Load transformer model if available
        if HAS_TRANSFORMERS:
            try:
                self.model_name = "distilbert-base-uncased-finetuned-sst-2-english"
                self.classifier = pipeline("sentiment-analysis", model=self.model_name)
                self.sentence_model = SentenceTransformer('all-MiniLM-L6-v2')
                logger.info("Loaded transformer models successfully")
            except Exception as e:
                logger.warning(f"Could not load transformer models: {e}")
                self.classifier = None
                self.sentence_model = None
        else:
            self.classifier = None
            self.sentence_model = None
    
    def classify_content(self, text: str) -> Dict[str, float]:
        """Classify content into categories"""
        text_lower = text.lower()
        scores = {}
        
        # Simple keyword-based classification
        for category, keywords in self.categories.items():
            score = 0
            for keyword in keywords:
                if keyword in text_lower:
                    score += text_lower.count(keyword)
            
            # Normalize by text length
            scores[category] = score / max(len(text.split()), 1)
        
        return scores
    
    def calculate_risk_score(self, classification: Dict[str, float]) -> float:
        """Calculate overall risk score"""
        risk_weights = {
            'drugs': 0.8,
            'weapons': 0.9,
            'fraud': 0.7,
            'hacking': 0.6,
            'trafficking': 0.9,
            'legitimate': -0.5  # Negative weight for legitimate content
        }
        
        risk_score = sum(
            classification.get(category, 0) * weight 
            for category, weight in risk_weights.items()
        )
        
        # Normalize to 0-1 range
        return max(0, min(1, risk_score))
    
    def analyze_sentiment(self, text: str) -> Dict[str, float]:
        """Analyze sentiment of text"""
        if self.classifier:
            try:
                # Use transformer model
                result = self.classifier(text[:512])  # Truncate for model limits
                return {
                    'label': result[0]['label'],
                    'score': result[0]['score']
                }
            except:
                pass
        
        # Fallback to simple sentiment analysis
        positive_words = ['good', 'great', 'excellent', 'amazing', 'wonderful', 'fantastic']
        negative_words = ['bad', 'terrible', 'awful', 'horrible', 'disgusting', 'worst']
        
        text_lower = text.lower()
        pos_count = sum(1 for word in positive_words if word in text_lower)
        neg_count = sum(1 for word in negative_words if word in text_lower)
        
        if pos_count > neg_count:
            return {'label': 'POSITIVE', 'score': 0.6}
        elif neg_count > pos_count:
            return {'label': 'NEGATIVE', 'score': 0.6}
        else:
            return {'label': 'NEUTRAL', 'score': 0.5}

class TopicModeler:
    """Topic modeling and trend analysis"""
    
    def __init__(self, n_topics: int = 10):
        self.n_topics = n_topics
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2),
            min_df=2
        )
        self.lda_model = LatentDirichletAllocation(
            n_components=n_topics,
            random_state=42,
            max_iter=100
        )
        self.is_fitted = False
    
    def fit_topics(self, documents: List[str]) -> None:
        """Fit topic model on documents"""
        if not documents:
            return
        
        try:
            # Vectorize documents
            doc_vectors = self.vectorizer.fit_transform(documents)
            
            # Fit LDA model
            self.lda_model.fit(doc_vectors)
            self.is_fitted = True
            
            logger.info(f"Topic model fitted with {len(documents)} documents")
            
        except Exception as e:
            logger.error(f"Error fitting topic model: {e}")
    
    def get_topics(self, n_words: int = 5) -> List[Tuple[int, List[str]]]:
        """Get topics with top words"""
        if not self.is_fitted:
            return []
        
        topics = []
        feature_names = self.vectorizer.get_feature_names_out()
        
        for topic_idx, topic in enumerate(self.lda_model.components_):
            top_words_idx = topic.argsort()[-n_words:][::-1]
            top_words = [feature_names[i] for i in top_words_idx]
            topics.append((topic_idx, top_words))
        
        return topics
    
    def predict_topics(self, text: str) -> List[Tuple[int, float]]:
        """Predict topics for new text"""
        if not self.is_fitted:
            return []
        
        try:
            text_vector = self.vectorizer.transform([text])
            topic_probs = self.lda_model.transform(text_vector)[0]
            
            # Return topics sorted by probability
            topic_scores = [(i, prob) for i, prob in enumerate(topic_probs)]
            topic_scores.sort(key=lambda x: x[1], reverse=True)
            
            return topic_scores
        
        except Exception as e:
            logger.error(f"Error predicting topics: {e}")
            return []

class NLPAnalyzer:
    """Main NLP analysis coordinator"""
    
    def __init__(self, db_path: str = "research_data.db"):
        self.db_path = db_path
        self.preprocessor = TextPreprocessor()
        self.classifier = CrimeClassifier()
        self.topic_modeler = TopicModeler()
        
        # Initialize topic model with existing data
        self._initialize_topic_model()
    
    def _initialize_topic_model(self):
        """Initialize topic model with existing documents"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT content FROM crawl_results WHERE content IS NOT NULL")
                documents = [row[0] for row in cursor.fetchall()]
                
                if documents:
                    # Clean documents
                    cleaned_docs = [
                        self.preprocessor.clean_text(doc) 
                        for doc in documents
                    ]
                    
                    # Fit topic model
                    self.topic_modeler.fit_topics(cleaned_docs)
                    logger.info(f"Topic model initialized with {len(documents)} documents")
        
        except Exception as e:
            logger.error(f"Error initializing topic model: {e}")
    
    def analyze_content(self, content_id: int, text: str) -> AnalysisResult:
        """Perform comprehensive NLP analysis on content"""
        
        # Preprocess text
        cleaned_text = self.preprocessor.clean_text(text)
        tokens = self.preprocessor.tokenize_and_filter(cleaned_text)
        sentences = self.preprocessor.extract_sentences(cleaned_text)
        
        # Text statistics
        text_analysis = {
            'word_count': len(text.split()),
            'sentence_count': len(sentences),
            'avg_sentence_length': len(text.split()) / max(len(sentences), 1),
            'token_count': len(tokens),
            'unique_tokens': len(set(tokens)),
            'lexical_diversity': len(set(tokens)) / max(len(tokens), 1)
        }
        
        # Classification
        classification = self.classifier.classify_content(text)
        risk_score = self.classifier.calculate_risk_score(classification)
        
        # Topic modeling
        topics = self.topic_modeler.predict_topics(cleaned_text)
        
        # Sentiment analysis
        sentiment = self.classifier.analyze_sentiment(text)
        
        # Language detection (simplified)
        language = self._detect_language(text)
        
        # Extract additional entities
        entities = self._extract_advanced_entities(text)
        
        return AnalysisResult(
            content_id=content_id,
            text_analysis=text_analysis,
            classification=classification,
            topics=topics[:5],  # Top 5 topics
            risk_score=risk_score,
            entities=entities,
            sentiment=sentiment,
            language=language,
            metadata={
                'analyzed_at': datetime.now().isoformat(),
                'model_version': '1.0',
                'tokens_sample': tokens[:10]  # Sample of tokens
            }
        )
    
    def _detect_language(self, text: str) -> str:
        """Simple language detection"""
        # This is a simplified implementation
        # In practice, you'd use a library like langdetect
        common_english_words = ['the', 'and', 'is', 'in', 'to', 'of', 'a', 'that', 'it', 'with']
        
        text_lower = text.lower()
        english_count = sum(1 for word in common_english_words if word in text_lower)
        
        return 'en' if english_count > 2 else 'unknown'
    
    def _extract_advanced_entities(self, text: str) -> Dict[str, List[str]]:
        """Extract additional entities beyond basic regex"""
        entities = defaultdict(list)
        
        # Time expressions
        time_patterns = [
            r'\b\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM)?\b',
            r'\b(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\b',
            r'\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b'
        ]
        
        for pattern in time_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            entities['time_expressions'].extend(matches)
        
        # Price/money patterns
        money_pattern = r'\$\d+(?:\.\d{2})?|\d+\s*(?:USD|EUR|BTC|ETH)'
        money_matches = re.findall(money_pattern, text, re.IGNORECASE)
        entities['monetary_values'].extend(money_matches)
        
        # Location patterns
        location_pattern = r'\b(?:in|at|from|to)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\b'
        location_matches = re.findall(location_pattern, text)
        entities['locations'].extend(location_matches)
        
        return dict(entities)
    
    def batch_analyze(self) -> List[AnalysisResult]:
        """Analyze all content in database"""
        results = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, content, title 
                    FROM crawl_results 
                    WHERE content IS NOT NULL
                """)
                
                for row in cursor.fetchall():
                    content_id, content, title = row
                    
                    # Combine title and content for analysis
                    full_text = f"{title}\n\n{content}" if title else content
                    
                    try:
                        analysis = self.analyze_content(content_id, full_text)
                        results.append(analysis)
                        
                        # Save analysis results to database
                        self._save_analysis_result(analysis)
                        
                        logger.info(f"Analyzed content ID {content_id}, risk score: {analysis.risk_score:.2f}")
                        
                    except Exception as e:
                        logger.error(f"Error analyzing content {content_id}: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Error in batch analysis: {e}")
        
        return results
    
    def _save_analysis_result(self, result: AnalysisResult):
        """Save analysis results to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create analysis table if not exists
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS content_analysis (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        content_id INTEGER,
                        risk_score REAL,
                        classification TEXT,
                        topics TEXT,
                        sentiment TEXT,
                        text_analysis TEXT,
                        entities TEXT,
                        language TEXT,
                        analyzed_at DATETIME,
                        FOREIGN KEY (content_id) REFERENCES crawl_results (id)
                    )
                ''')
                
                cursor.execute('''
                    INSERT OR REPLACE INTO content_analysis 
                    (content_id, risk_score, classification, topics, sentiment, 
                     text_analysis, entities, language, analyzed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    result.content_id,
                    result.risk_score,
                    json.dumps(result.classification),
                    json.dumps(result.topics),
                    json.dumps(result.sentiment),
                    json.dumps(result.text_analysis),
                    json.dumps(result.entities),
                    result.language,
                    datetime.now()
                ))
                
                conn.commit()
        
        except Exception as e:
            logger.error(f"Error saving analysis result: {e}")
    
    def get_risk_summary(self) -> Dict[str, Any]:
        """Get summary of risk analysis"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get risk distribution
                cursor.execute("""
                    SELECT 
                        CASE 
                            WHEN risk_score >= 0.7 THEN 'High'
                            WHEN risk_score >= 0.4 THEN 'Medium'
                            ELSE 'Low'
                        END as risk_level,
                        COUNT(*) as count
                    FROM content_analysis
                    GROUP BY risk_level
                """)
                
                risk_distribution = dict(cursor.fetchall())
                
                # Get average risk score
                cursor.execute("SELECT AVG(risk_score) FROM content_analysis")
                avg_risk = cursor.fetchone()[0] or 0
                
                # Get top categories
                cursor.execute("""
                    SELECT classification, COUNT(*) as count
                    FROM content_analysis
                    WHERE json_extract(classification, '$.drugs') > 0.1
                       OR json_extract(classification, '$.weapons') > 0.1
                       OR json_extract(classification, '$.fraud') > 0.1
                    GROUP BY classification
                    ORDER BY count DESC
                    LIMIT 5
                """)
                
                return {
                    'risk_distribution': risk_distribution,
                    'average_risk_score': round(avg_risk, 3),
                    'total_analyzed': sum(risk_distribution.values()),
                    'high_risk_count': risk_distribution.get('High', 0)
                }
        
        except Exception as e:
            logger.error(f"Error generating risk summary: {e}")
            return {}
    
    def get_topic_trends(self) -> List[Dict[str, Any]]:
        """Get trending topics from analysis"""
        topics = self.topic_modeler.get_topics(n_words=8)
        
        trend_data = []
        for topic_id, words in topics:
            trend_data.append({
                'topic_id': topic_id,
                'keywords': words,
                'topic_name': self._generate_topic_name(words),
                'relevance_score': 0.8  # Placeholder
            })
        
        return trend_data
    
    def _generate_topic_name(self, words: List[str]) -> str:
        """Generate a human-readable topic name"""
        # Simple heuristic based on top words
        if any(word in ['drug', 'narcotic', 'pills'] for word in words):
            return "Drug-related Content"
        elif any(word in ['weapon', 'gun', 'firearm'] for word in words):
            return "Weapons Discussion"
        elif any(word in ['hack', 'exploit', 'malware'] for word in words):
            return "Cybersecurity/Hacking"
        elif any(word in ['privacy', 'anonymous', 'secure'] for word in words):
            return "Privacy & Security"
        elif any(word in ['research', 'academic', 'study'] for word in words):
            return "Research & Academic"
        else:
            return f"Topic: {', '.join(words[:3])}"

class ReportGenerator:
    """Generate analysis reports"""
    
    def __init__(self, db_path: str = "research_data.db"):
        self.db_path = db_path
    
    def generate_intelligence_report(self) -> Dict[str, Any]:
        """Generate comprehensive intelligence report"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get basic statistics
                cursor.execute("SELECT COUNT(*) FROM crawl_results")
                total_pages = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM content_analysis")
                analyzed_pages = cursor.fetchone()[0]
                
                # Get high-risk content
                cursor.execute("""
                    SELECT cr.url, cr.title, ca.risk_score, ca.classification
                    FROM crawl_results cr
                    JOIN content_analysis ca ON cr.id = ca.content_id
                    WHERE ca.risk_score >= 0.5
                    ORDER BY ca.risk_score DESC
                    LIMIT 10
                """)
                
                high_risk_content = [
                    {
                        'url': row[0],
                        'title': row[1],
                        'risk_score': row[2],
                        'classification': json.loads(row[3]) if row[3] else {}
                    }
                    for row in cursor.fetchall()
                ]
                
                # Get entity statistics
                cursor.execute("""
                    SELECT entity_type, COUNT(*) as count
                    FROM extracted_entities
                    GROUP BY entity_type
                    ORDER BY count DESC
                """)
                
                entity_stats = dict(cursor.fetchall())
                
                # Get recent activity
                cursor.execute("""
                    SELECT DATE(timestamp) as date, COUNT(*) as count
                    FROM crawl_results
                    WHERE timestamp >= datetime('now', '-7 days')
                    GROUP BY DATE(timestamp)
                    ORDER BY date DESC
                """)
                
                recent_activity = [
                    {'date': row[0], 'count': row[1]}
                    for row in cursor.fetchall()
                ]
                
                return {
                    'report_generated': datetime.now().isoformat(),
                    'summary': {
                        'total_pages_crawled': total_pages,
                        'pages_analyzed': analyzed_pages,
                        'high_risk_pages': len(high_risk_content),
                        'entities_extracted': sum(entity_stats.values())
                    },
                    'high_risk_content': high_risk_content,
                    'entity_distribution': entity_stats,
                    'recent_activity': recent_activity,
                    'recommendations': self._generate_recommendations(high_risk_content)
                }
        
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return {'error': str(e)}
    
    def _generate_recommendations(self, high_risk_content: List[Dict]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if len(high_risk_content) > 5:
            recommendations.append("High volume of risky content detected. Consider increasing monitoring frequency.")
        
        if any(item['risk_score'] > 0.8 for item in high_risk_content):
            recommendations.append("Critical risk content found. Immediate review recommended.")
        
        # Analyze patterns in classifications
        drug_related = sum(1 for item in high_risk_content 
                          if item['classification'].get('drugs', 0) > 0.5)
        if drug_related > 2:
            recommendations.append("Multiple drug-related content detected. Focus monitoring on pharmaceutical channels.")
        
        weapon_related = sum(1 for item in high_risk_content 
                           if item['classification'].get('weapons', 0) > 0.5)
        if weapon_related > 1:
            recommendations.append("Weapons-related content found. Enhanced security protocols advised.")
        
        if not recommendations:
            recommendations.append("No immediate threats detected. Continue regular monitoring.")
        
        return recommendations

def main():
    """Main function to run NLP analysis"""
    logger.info("Starting NLP Analysis Module")
    
    # Initialize analyzer
    analyzer = NLPAnalyzer()
    
    # Run batch analysis
    logger.info("Running batch analysis on crawled content...")
    results = analyzer.batch_analyze()
    
    if results:
        logger.info(f"Analysis completed for {len(results)} items")
        
        # Print summary
        risk_summary = analyzer.get_risk_summary()
        logger.info(f"Risk Summary: {risk_summary}")
        
        # Get topic trends
        topics = analyzer.get_topic_trends()
        logger.info("Detected Topics:")
        for topic in topics[:5]:
            logger.info(f"  - {topic['topic_name']}: {topic['keywords']}")
        
        # Generate intelligence report
        report_generator = ReportGenerator()
        report = report_generator.generate_intelligence_report()
        
        logger.info("Intelligence Report Generated:")
        logger.info(f"  Total Pages: {report['summary']['total_pages_crawled']}")
        logger.info(f"  High Risk Pages: {report['summary']['high_risk_pages']}")
        logger.info(f"  Entities Extracted: {report['summary']['entities_extracted']}")
        
        # Print recommendations
        logger.info("Recommendations:")
        for rec in report.get('recommendations', []):
            logger.info(f"  - {rec}")
    
    else:
        logger.info("No content found for analysis. Run crawler first.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()