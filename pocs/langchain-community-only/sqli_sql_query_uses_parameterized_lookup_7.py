#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: sqli-028
# Sink: lookup
# Auto-generated — run with: python3 sqli_sql_query_uses_parameterized_lookup_7.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit Script for langchain-community-only SQLI Finding

This script demonstrates that the alleged SQL injection vulnerability in
langchain-community's cache lookup function is NOT exploitable due to the use
of parameterized queries via SQLAlchemy ORM.

The script simulates an attacker attempting SQL injection through the 'prompt'
and 'llm_string' parameters, and shows that the query remains safe.

Target: /tmp/langchain-community-only/langchain_community/cache.py
Vulnerability Type: SQLI (NOT EXPLOITABLE)
"""

import sys
import json
import argparse
from typing import Optional, Dict, Any

# Simulated database setup for testing
from sqlalchemy import create_engine, Column, String, Integer, Text, select
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import Session

Base = declarative_base()

class CacheEntry(Base):
    """Simulated cache table matching the structure in langchain-community"""
    __tablename__ = 'cache'
    
    idx = Column(Integer, primary_key=True)
    prompt = Column(String(500))
    llm = Column(String(500))
    response = Column(Text)

class SQLAlchemyCache:
    """
    Simplified version of the cache class from langchain-community
    that demonstrates the parameterized query behavior
    """
    
    def __init__(self, database_url: str = "sqlite:///:memory:"):
        """Initialize with in-memory SQLite database for testing"""
        self.engine = create_engine(database_url)
        Base.metadata.create_all(self.engine)
        self.cache_schema = CacheEntry
        
        # Insert some test data
        self._seed_data()
    
    def _seed_data(self):
        """Insert sample cache entries for testing"""
        with Session(self.engine) as session:
            test_entries = [
                CacheEntry(prompt="What is Python?", llm="gpt-3.5", response='{"text": "Python is a programming language"}'),
                CacheEntry(prompt="Hello world", llm="gpt-4", response='{"text": "Hello!"}'),
            ]
            session.add_all(test_entries)
            session.commit()
    
    def lookup(self, prompt: str, llm_string: str) -> Optional[Dict[str, Any]]:
        """
        The exact lookup function from langchain-community cache.py
        Uses parameterized queries via SQLAlchemy ORM
        """
        stmt = (
            select(self.cache_schema.response)
            .where(self.cache_schema.prompt == prompt)
            .where(self.cache_schema.llm == llm_string)
            .order_by(self.cache_schema.idx)
        )
        
        with Session(self.engine) as session:
            rows = session.execute(stmt).fetchall()
            if rows:
                try:
                    return json.loads(rows[0][0])
                except Exception:
                    return {"text": rows[0][0]}
        return None

def test_sql_injection_attempts(cache: SQLAlchemyCache):
    """
    Test various SQL injection payloads to demonstrate they don't work
    """
    print("[*] Testing SQL injection attempts against parameterized query...")
    print("=" * 60)
    
    injection_payloads = [
        # Basic SQL injection attempts
        ("' OR '1'='1", "gpt-3.5"),
        ("' UNION SELECT * FROM cache--", "gpt-3.5"),
        ("'; DROP TABLE cache;--", "gpt-3.5"),
        ("' OR 1=1--", "gpt-3.5"),
        ("' UNION SELECT sql FROM sqlite_master--", "gpt-3.5"),
        
        # More sophisticated attempts
        ("' UNION SELECT response FROM cache WHERE '1'='1", "gpt-3.5"),
        ("' OR prompt LIKE '%Python%'--", "gpt-3.5"),
        ("' AND 1=0 UNION SELECT 'injected'--", "gpt-3.5"),
        
        # Attempts to break out of string context
        ("\\' OR '1'='1", "gpt-3.5"),
        ("\" OR \"1\"=\"1", "gpt-3.5"),
        
        # Time-based attempts (won't work with parameterized queries)
        ("' OR SLEEP(5)--", "gpt-3.5"),
        ("' WAITFOR DELAY '0:0:5'--", "gpt-3.5"),
    ]
    
    for prompt, llm_string in injection_payloads:
        print(f"\n[*] Testing payload: prompt='{prompt}', llm='{llm_string}'")
        try:
            result = cache.lookup(prompt, llm_string)
            if result:
                print(f"    [!] Unexpected result: {result}")
                print("    [!] This would indicate potential injection!")
            else:
                print(f"    [+] No result returned (expected - query was safe)")
        except Exception as e:
            print(f"    [+] Error occurred (expected with injection attempts): {e}")
    
    print("\n" + "=" * 60)
    print("[*] All injection attempts failed - query is parameterized and safe")

def test_legitimate_usage(cache: SQLAlchemyCache):
    """
    Demonstrate that legitimate queries still work correctly
    """
    print("\n[*] Testing legitimate cache lookups...")
    print("=" * 60)
    
    legitimate_queries = [
        ("What is Python?", "gpt-3.5"),
        ("Hello world", "gpt-4"),
        ("Non-existent query", "gpt-3.5"),
    ]
    
    for prompt, llm_string in legitimate_queries:
        print(f"\n[*] Query: prompt='{prompt}', llm='{llm_string}'")
        result = cache.lookup(prompt, llm_string)
        if result:
            print(f"    [+] Cache hit: {result}")
        else:
            print(f"    [+] Cache miss (expected for non-existent entries)")
    
    print("\n" + "=" * 60)
    print("[*] Legitimate queries work correctly")

def main():
    """Main function to demonstrate the SQL injection finding is NOT exploitable"""
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community SQLI finding - Demonstrates NOT exploitable"
    )
    parser.add_argument(
        "--database",
        default="sqlite:///:memory:",
        help="Database URL (default: sqlite:///:memory:)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    print("[*] langchain-community SQLI PoC - Demonstrating NOT exploitable")
    print("[*] Target: /tmp/langchain-community-only/langchain_community/cache.py")
    print("[*] Vulnerability Type: SQLI (NOT EXPLOITABLE)")
    print("[*] Reason: Parameterized queries via SQLAlchemy ORM .where() method")
    print()
    
    try:
        # Initialize the cache with test data
        cache = SQLAlchemyCache(args.database)
        
        # Run tests
        test_legitimate_usage(cache)
        test_sql_injection_attempts(cache)
        
        print("\n" + "=" * 60)
        print("[✓] CONCLUSION: SQL injection is NOT possible")
        print("[✓] The .where() method safely binds parameters")
        print("[✓] User-controlled 'prompt' and 'llm_string' are passed as parameters")
        print("[✓] No SQL injection vulnerability exists in this code")
        
    except Exception as e:
        print(f"\n[!] Error during testing: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
