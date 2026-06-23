#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: sqli-029
# Sink: _delete_previous
# Auto-generated — run with: python3 sqli_sql_query_uses_sqlalchemy__delete_previous.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit Script for langchain-community-only SQLI Finding

This script demonstrates that the reported SQL injection vulnerability in
langchain-community's cache.py is NOT exploitable. The code uses SQLAlchemy's
parameterized ORM queries, which safely handle user input.

The script:
1. Sets up a minimal test environment with SQLAlchemy
2. Replicates the vulnerable code pattern from the library
3. Attempts SQL injection through the 'prompt' and 'llm_string' parameters
4. Demonstrates that injection is not possible due to parameterized queries

Usage:
    python3 poc_sqli_langchain.py [--target-url URL]

Note: This is a local PoC that doesn't require a running server.
"""

import argparse
import hashlib
import sys
from typing import Optional

# SQLAlchemy imports
from sqlalchemy import create_engine, Column, String, Integer, delete
from sqlalchemy.orm import declarative_base, Session

# Safe by default - use a benign test payload
BENIGN_PAYLOAD = "test_prompt"
SAFE_LLM_STRING = "test_llm"


def get_md5(text: str) -> str:
    """Compute MD5 hash of input text (safe operation)."""
    return hashlib.md5(text.encode()).hexdigest()


# Define a minimal cache schema matching the library's structure
Base = declarative_base()


class CacheEntry(Base):
    """Simulated cache table from langchain-community."""
    __tablename__ = "langchain_cache"

    id = Column(Integer, primary_key=True)
    prompt = Column(String)
    prompt_md5 = Column(String)
    llm = Column(String)
    response = Column(String)


def setup_database():
    """Create an in-memory SQLite database with the cache table."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    return engine


def insert_test_data(session: Session):
    """Insert sample cache entries for testing."""
    entries = [
        CacheEntry(
            prompt="safe_prompt_1",
            prompt_md5=get_md5("safe_prompt_1"),
            llm="gpt-3.5",
            response="response_1"
        ),
        CacheEntry(
            prompt="safe_prompt_2",
            prompt_md5=get_md5("safe_prompt_2"),
            llm="gpt-4",
            response="response_2"
        ),
        CacheEntry(
            prompt=BENIGN_PAYLOAD,
            prompt_md5=get_md5(BENIGN_PAYLOAD),
            llm=SAFE_LLM_STRING,
            response="benign_response"
        ),
    ]
    for entry in entries:
        session.add(entry)
    session.commit()


def _delete_previous(session: Session, cache_schema, prompt: str, llm_string: str):
    """
    Replicates the vulnerable code pattern from langchain-community's cache.py.
    
    This is the exact code that was flagged for SQL injection.
    """
    stmt = (
        delete(cache_schema)
        .where(cache_schema.prompt_md5 == get_md5(prompt))
        .where(cache_schema.llm == llm_string)
        .where(cache_schema.prompt == prompt)
    )
    session.execute(stmt)
    session.commit()


def attempt_sql_injection(session: Session, prompt: str, llm_string: str) -> bool:
    """
    Attempt SQL injection through the parameters.
    
    Returns True if injection appears to have worked (unlikely), False otherwise.
    """
    print(f"\n[*] Testing with prompt='{prompt}' and llm_string='{llm_string}'")
    
    # Count entries before
    before_count = session.query(CacheEntry).count()
    print(f"    Entries before: {before_count}")
    
    try:
        _delete_previous(session, CacheEntry, prompt, llm_string)
        print(f"    Query executed successfully")
    except Exception as e:
        print(f"    Query failed with error: {e}")
        return False
    
    # Count entries after
    after_count = session.query(CacheEntry).count()
    print(f"    Entries after: {after_count}")
    
    # Check if deletion happened (expected behavior for matching entries)
    if after_count < before_count:
        print(f"    Deleted {before_count - after_count} entries")
        return True
    else:
        print(f"    No entries deleted (no match)")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community SQLI finding - demonstrates non-exploitability"
    )
    parser.add_argument(
        "--target-url",
        help="Not used in this local PoC (included for interface compatibility)",
        default="http://localhost:8000"
    )
    args = parser.parse_args()
    
    print("=" * 60)
    print("PoC: langchain-community SQL Injection Analysis")
    print("=" * 60)
    print("\n[+] Setting up test environment...")
    
    # Setup database
    engine = setup_database()
    
    with Session(engine) as session:
        insert_test_data(session)
        print("[+] Test data inserted successfully")
        
        # Test 1: Normal operation with benign payload
        print("\n" + "-" * 40)
        print("Test 1: Normal operation (benign payload)")
        print("-" * 40)
        attempt_sql_injection(session, BENIGN_PAYLOAD, SAFE_LLM_STRING)
        
        # Test 2: Attempt SQL injection in prompt parameter
        print("\n" + "-" * 40)
        print("Test 2: SQL injection attempt in 'prompt' parameter")
        print("-" * 40)
        sql_injection_prompt = "'; DROP TABLE langchain_cache; --"
        attempt_sql_injection(session, sql_injection_prompt, SAFE_LLM_STRING)
        
        # Test 3: Attempt SQL injection in llm_string parameter
        print("\n" + "-" * 40)
        print("Test 3: SQL injection attempt in 'llm_string' parameter")
        print("-" * 40)
        sql_injection_llm = "'; DELETE FROM langchain_cache; --"
        attempt_sql_injection(session, BENIGN_PAYLOAD, sql_injection_llm)
        
        # Test 4: Attempt SQL injection with UNION
        print("\n" + "-" * 40)
        print("Test 4: SQL injection attempt with UNION")
        print("-" * 40)
        union_injection = "' UNION SELECT * FROM langchain_cache; --"
        attempt_sql_injection(session, union_injection, SAFE_LLM_STRING)
        
        # Verify database integrity
        print("\n" + "-" * 40)
        print("Verification: Database integrity check")
        print("-" * 40)
        remaining = session.query(CacheEntry).count()
        print(f"    Total entries remaining: {remaining}")
        
        if remaining == 3:  # Original 3 entries should still exist
            print("\n[✓] SUCCESS: Database integrity maintained!")
            print("    SQL injection was NOT possible - queries are parameterized.")
            print("    The vulnerability finding is correctly classified as NOT_EXPLOITABLE.")
        else:
            print(f"\n[!] WARNING: Database state changed unexpectedly!")
            print("    This would indicate a potential vulnerability.")
            sys.exit(1)
    
    print("\n" + "=" * 60)
    print("PoC Complete - No SQL injection possible")
    print("=" * 60)


if __name__ == "__main__":
    main()
