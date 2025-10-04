#!/usr/bin/env python3
"""
Educational Dark Web Research Crawler
Phase 1: Core Architecture & Secure Crawling Module

IMPORTANT: This is for educational and legitimate research purposes only.
Uses simulated/test data to demonstrate concepts safely.
"""

import asyncio
import aiohttp
import json
import sqlite3
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from urllib.parse import urljoin, urlparse
import re
import time
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class CrawlResult:
    """Data structure for crawl results"""
    url: str
    content: str
    title: str
    timestamp: datetime
    content_type: str
    status_code: int
    metadata: Dict[str, Any]
    extracted_entities: Dict[str, List[str]]

class DatabaseManager:
    """Handles database operations for crawled data"""
    
    def __init__(self, db_path: str = "research_data.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with required tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Main crawl results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS crawl_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE NOT NULL,
                    content TEXT,
                    title TEXT,
                    timestamp DATETIME,
                    content_type TEXT,
                    status_code INTEGER,
                    content_hash TEXT,
                    metadata TEXT
                )
            ''')
            
            # Extracted entities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS extracted_entities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    crawl_id INTEGER,
                    entity_type TEXT,
                    entity_value TEXT,
                    confidence REAL,
                    FOREIGN KEY (crawl_id) REFERENCES crawl_results (id)
                )
            ''')
            
            # Keywords and alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS keyword_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    crawl_id INTEGER,
                    keyword TEXT,
                    context TEXT,
                    alert_level TEXT,
                    timestamp DATETIME,
                    FOREIGN KEY (crawl_id) REFERENCES crawl_results (id)
                )
            ''')
            
            conn.commit()
            logger.info("Database initialized successfully")
    
    def save_crawl_result(self, result: CrawlResult) -> int:
        """Save crawl result to database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            content_hash = hashlib.sha256(result.content.encode()).hexdigest()
            
            cursor.execute('''
                INSERT OR REPLACE INTO crawl_results 
                (url, content, title, timestamp, content_type, status_code, content_hash, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.url,
                result.content,
                result.title,
                result.timestamp,
                result.content_type,
                result.status_code,
                content_hash,
                json.dumps(result.metadata, default=str)
            ))
            
            crawl_id = cursor.lastrowid
            
            # Save extracted entities
            for entity_type, entities in result.extracted_entities.items():
                for entity in entities:
                    cursor.execute('''
                        INSERT INTO extracted_entities 
                        (crawl_id, entity_type, entity_value, confidence)
                        VALUES (?, ?, ?, ?)
                    ''', (crawl_id, entity_type, entity, 0.8))  # Default confidence
            
            conn.commit()
            return crawl_id

class EntityExtractor:
    """Extract entities from crawled content"""
    
    def __init__(self):
        # Regex patterns for common entities
        self.patterns = {
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'bitcoin_address': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
            'onion_url': re.compile(r'[a-z2-7]{16,56}\.onion'),
            'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'phone': re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
            'username': re.compile(r'@[a-zA-Z0-9_]+'),
        }
        
        # High-risk keywords for research purposes
        self.risk_keywords = {
            'high': ['weapon', 'explosive', 'trafficking', 'child', 'exploit'],
            'medium': ['drugs', 'hack', 'fraud', 'stolen', 'illegal'],
            'low': ['anonymous', 'privacy', 'secure', 'crypto']
        }
    
    def extract_entities(self, content: str) -> Dict[str, List[str]]:
        """Extract entities from content using regex patterns"""
        entities = {}
        
        for entity_type, pattern in self.patterns.items():
            matches = pattern.findall(content.lower())
            entities[entity_type] = list(set(matches))  # Remove duplicates
        
        return entities
    
    def detect_risk_keywords(self, content: str) -> List[Dict[str, Any]]:
        """Detect risk keywords in content"""
        alerts = []
        content_lower = content.lower()
        
        for level, keywords in self.risk_keywords.items():
            for keyword in keywords:
                if keyword in content_lower:
                    # Get context around keyword
                    start = max(0, content_lower.find(keyword) - 50)
                    end = min(len(content), content_lower.find(keyword) + 50)
                    context = content[start:end]
                    
                    alerts.append({
                        'keyword': keyword,
                        'level': level,
                        'context': context,
                        'timestamp': datetime.now()
                    })
        
        return alerts

class SecureCrawler:
    """Secure web crawler with Tor-like simulation"""
    
    def __init__(self, max_concurrent: int = 5, delay: float = 1.0):
        self.max_concurrent = max_concurrent
        self.delay = delay
        self.session = None
        self.db_manager = DatabaseManager()
        self.entity_extractor = EntityExtractor()
        self.crawled_urls = set()
    
    async def __aenter__(self):
        # Simulate Tor proxy configuration
        connector = aiohttp.TCPConnector(limit=self.max_concurrent)
        timeout = aiohttp.ClientTimeout(total=30)
        
        # In real implementation, this would use Tor proxy
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'Research-Crawler/1.0'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def fetch_page(self, url: str) -> Optional[CrawlResult]:
        """Fetch a single page with error handling"""
        if url in self.crawled_urls:
            return None
        
        try:
            logger.info(f"Crawling: {url}")
            
            async with self.session.get(url) as response:
                content = await response.text()
                
                # Extract title
                title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
                title = title_match.group(1) if title_match else "No Title"
                
                # Extract entities
                entities = self.entity_extractor.extract_entities(content)
                
                # Detect risk keywords
                risk_alerts = self.entity_extractor.detect_risk_keywords(content)
                
                result = CrawlResult(
                    url=url,
                    content=content,
                    title=title.strip(),
                    timestamp=datetime.now(),
                    content_type=response.content_type or 'text/html',
                    status_code=response.status,
                    metadata={
                        'content_length': len(content),
                        'risk_alerts': risk_alerts,
                        'links_found': len(re.findall(r'<a[^>]+href=["\']([^"\']+)', content))
                    },
                    extracted_entities=entities
                )
                
                self.crawled_urls.add(url)
                return result
                
        except Exception as e:
            logger.error(f"Error crawling {url}: {str(e)}")
            return None
    
    async def crawl_urls(self, urls: List[str]) -> List[CrawlResult]:
        """Crawl multiple URLs concurrently"""
        results = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def crawl_with_semaphore(url):
            async with semaphore:
                result = await self.fetch_page(url)
                if result:
                    # Save to database
                    crawl_id = self.db_manager.save_crawl_result(result)
                    logger.info(f"Saved crawl result {crawl_id} for {url}")
                
                await asyncio.sleep(self.delay)  # Rate limiting
                return result
        
        tasks = [crawl_with_semaphore(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out None results and exceptions
        valid_results = [r for r in results if isinstance(r, CrawlResult)]
        return valid_results

class ResearchDataGenerator:
    """Generate synthetic research data for testing"""
    
    def __init__(self):
        self.sample_pages = [
            {
                'url': 'http://research-forum-1.local/index.html',
                'content': '''
                <html>
                <head><title>Research Forum - Privacy Discussion</title></head>
                <body>
                    <h1>Privacy and Security Research</h1>
                    <p>Welcome to our research forum discussing privacy tools and anonymous communication.</p>
                    <p>Contact: research@example.com for academic collaboration.</p>
                    <p>Bitcoin donations: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</p>
                    <div class="post">
                        <p>User @researcher123 posted: "Studying anonymous networks for legitimate research."</p>
                    </div>
                </body>
                </html>
                '''
            },
            {
                'url': 'http://marketplace-sim.local/shop.html',
                'content': '''
                <html>
                <head><title>Marketplace Simulation</title></head>
                <body>
                    <h1>Educational Marketplace Simulation</h1>
                    <p>This is a simulated marketplace for research purposes.</p>
                    <div class="listing">
                        <h3>Digital Privacy Tools</h3>
                        <p>Educational materials about online privacy and security.</p>
                        <p>Seller: @privacy_educator</p>
                    </div>
                </body>
                </html>
                '''
            }
        ]
    
    def get_sample_urls(self) -> List[str]:
        """Get sample URLs for testing"""
        return [page['url'] for page in self.sample_pages]
    
    def simulate_server_response(self, url: str) -> str:
        """Simulate server response for testing"""
        for page in self.sample_pages:
            if page['url'] == url:
                return page['content']
        return "<html><head><title>404</title></head><body>Page not found</body></html>"

async def main():
    """Main function to demonstrate the crawler"""
    logger.info("Starting Educational Dark Web Research Crawler")
    
    # Initialize components
    data_generator = ResearchDataGenerator()
    sample_urls = data_generator.get_sample_urls()
    
    # For demonstration, we'll use sample data instead of real crawling
    async with SecureCrawler(max_concurrent=3, delay=0.5) as crawler:
        logger.info(f"Starting to crawl {len(sample_urls)} sample URLs")
        
        # In a real implementation, this would crawl actual .onion sites through Tor
        # For educational purposes, we simulate the process
        for url in sample_urls:
            content = data_generator.simulate_server_response(url)
            
            # Extract title
            title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
            title = title_match.group(1) if title_match else "No Title"
            
            # Extract entities
            entities = crawler.entity_extractor.extract_entities(content)
            
            # Create result
            result = CrawlResult(
                url=url,
                content=content,
                title=title.strip(),
                timestamp=datetime.now(),
                content_type='text/html',
                status_code=200,
                metadata={
                    'content_length': len(content),
                    'risk_alerts': crawler.entity_extractor.detect_risk_keywords(content),
                    'links_found': len(re.findall(r'<a[^>]+href=["\']([^"\']+)', content))
                },
                extracted_entities=entities
            )
            
            # Save to database
            crawl_id = crawler.db_manager.save_crawl_result(result)
            logger.info(f"Processed and saved: {url} (ID: {crawl_id})")
            
            # Print extracted entities
            for entity_type, entity_list in entities.items():
                if entity_list:
                    logger.info(f"  Found {entity_type}: {entity_list}")
    
    logger.info("Crawling completed. Data saved to research_data.db")
    
    # Display summary statistics
    with sqlite3.connect("research_data.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM crawl_results")
        total_pages = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM extracted_entities")
        total_entities = cursor.fetchone()[0]
        
        logger.info(f"Summary: {total_pages} pages crawled, {total_entities} entities extracted")

if __name__ == "__main__":
    asyncio.run(main())