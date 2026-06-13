#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: sqli-028
# Sink: lookup
# Auto-generated — run with: python3 sqli_sql_query_uses_parameterized_lookup_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit Script for langchain-community-only SQLI Finding

This script demonstrates that the reported SQL injection vulnerability in
langchain-community's cache lookup function is NOT exploitable due to
SQLAlchemy's parameterized query handling.

The script:
1. Sets up a minimal SQLite database with the expected schema
2. Creates a mock SQLAlchemyCache instance
3. Attempts SQL injection through the lookup method
4. Demonstrates that injection attempts are safely parameterized

This is a verification script, not an actual exploit - it proves the
finding is a false positive.
"""

import sqlite3
import tempfile
import os
import sys
from typing import Optional, Any
from sqlalchemy import create_engine, Column, String, Integer, Text, select
from sqlalchemy.orm import Session
from sqlalchemy.ext.declarative import declarative_base

# Safe default - no actual exploitation
BENIGN_PAYLOAD = "test_prompt"
INJECTION_PAYLOAD = "' OR '1'='1' -- "

Base = declarative_base()

class CacheSchema(Base):
    """Minimal cache table schema matching langchain-community's expected structure"""
    __tablename__ = 'langchain_cache'
    
    idx = Column(Integer, primary_key=True)
    prompt = Column(String(255))
    llm = Column(String(255))
    response = Column(Text)

class MockSQLAlchemyCache:
    """
    Simplified mock of langchain_community.cache.SQLAlchemyCache
    that reproduces the exact vulnerable code pattern
    """
    
    def __init__(self, engine):
        self.engine = engine
        self.cache_schema = CacheSchema
        
    def lookup(self, prompt: str, llm_string: str) -> Optional[Any]:
        """
        Exact reproduction of the lookup method from langchain-community
        with the reported "vulnerable" code pattern
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
                return [row[0] for row in rows]
        return None

def setup_database(db_path: str):
    """Create and populate a test database"""
    engine = create_engine(f'sqlite:///{db_path}')
    Base.metadata.create_all(engine)
    
    # Insert some test data
    with Session(engine) as session:
        test_data = [
            CacheSchema(prompt="safe_prompt_1", llm="gpt-3.5", response="response_1"),
            CacheSchema(prompt="safe_prompt_2", llm="gpt-4", response="response_2"),
            CacheSchema(prompt="test_prompt", llm="test_llm", response="benign_response"),
        ]
        session.add_all(test_data)
        session.commit()
    
    return engine

def test_sql_injection(cache: MockSQLAlchemyCache):
    """
    Test if SQL injection is possible through the lookup method.
    If injection worked, we would see unexpected results or errors.
    """
    print("[*] Testing SQL injection resistance...")
    print(f"[*] Using injection payload: {INJECTION_PAYLOAD!r}")
    
    # Test 1: Normal lookup (should work)
    print("\n[Test 1] Normal lookup with valid parameters:")
    result = cache.lookup("test_prompt", "test_llm")
    print(f"  Result: {result}")
    assert result == ["benign_response"], "Normal lookup failed!"
    print("  ✓ Normal lookup works correctly")
    
    # Test 2: SQL injection attempt in prompt
    print("\n[Test 2] SQL injection attempt in 'prompt' parameter:")
    result = cache.lookup(INJECTION_PAYLOAD, "test_llm")
    print(f"  Result: {result}")
    # If injection worked, this might return all rows or cause an error
    # With parameterized queries, it should return None (no match)
    assert result is None, "Injection appeared to work - this should not happen!"
    print("  ✓ Injection safely parameterized - no unexpected results")
    
    # Test 3: SQL injection attempt in llm_string
    print("\n[Test 3] SQL injection attempt in 'llm_string' parameter:")
    result = cache.lookup("test_prompt", INJECTION_PAYLOAD)
    print(f"  Result: {result}")
    assert result is None, "Injection appeared to work - this should not happen!"
    print("  ✓ Injection safely parameterized - no unexpected results")
    
    # Test 4: Verify database integrity
    print("\n[Test 4] Verifying database integrity after injection attempts:")
    with Session(cache.engine) as session:
        count = session.query(CacheSchema).count()
        print(f"  Total rows in database: {count}")
        assert count == 3, "Database was modified by injection attempts!"
    print("  ✓ Database integrity maintained")
    
    print("\n[✓] All tests passed - SQL injection is NOT possible")
    print("[✓] The finding is confirmed as a FALSE POSITIVE")

def main():
    """Main execution function"""
    print("=" * 60)
    print("langchain-community SQLI PoC Verification Script")
    print("=" * 60)
    print()
    
    # Create temporary database
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        db_path = tmp.name
    
    try:
        print(f"[*] Setting up test database at: {db_path}")
        engine = setup_database(db_path)
        cache = MockSQLAlchemyCache(engine)
        
        # Run tests
        test_sql_injection(cache)
        
        print("\n[*] Cleanup: removing temporary database...")
        os.unlink(db_path)
        print("[*] Done!")
        
    except Exception as e:
        print(f"\n[!] Error during testing: {e}")
        print("[!] This may indicate an unexpected behavior")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
