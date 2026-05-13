#!/usr/bin/env python3
"""
MCP Server Test Runner
Run with: python3 test_runner.py
"""
import subprocess
import json
import os
import sys

API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
SERVER_PATH = "./semantic-server"

if not API_KEY:
    print("Error: OPENROUTER_API_KEY not set")
    sys.exit(1)

request_id = [1]

def call_tool(proc, name, args):
    req = {"jsonrpc": "2.0", "id": request_id[0], "method": "tools/call", 
           "params": {"name": name, "arguments": args}}
    request_id[0] += 1
    proc.stdin.write(json.dumps(req) + "\n")
    proc.stdin.flush()
    resp = proc.stdout.readline()
    if resp:
        try:
            r = json.loads(resp)
            if "result" in r:
                c = r["result"].get("content", [])
                if c:
                    return json.loads(c[0].get("text", "{}"))
        except:
            pass
    return None

def main():
    proc = subprocess.Popen([SERVER_PATH], stdin=subprocess.PIPE, stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE, text=True, bufsize=1,
                            env={**os.environ, "OPENROUTER_API_KEY": API_KEY})
    
    tests_passed = 0
    tests_failed = 0
    
    # Test 1
    data = call_tool(proc, "extract_semantic_tree", {"url": "https://httpbin.org/html"})
    if data and data.get("compressed_tokens"):
        print("✓ extract_semantic_tree")
        tests_passed += 1
    else:
        print("✗ extract_semantic_tree")
        tests_failed += 1
    
    # Test 2
    data = call_tool(proc, "analyze_page", {"url": "https://httpbin.org/forms/post"})
    if data and data.get("semantic"):
        print("✓ analyze_page")
        tests_passed += 1
    else:
        print("✗ analyze_page")
        tests_failed += 1
    
    # Test 3
    data = call_tool(proc, "serialize_for_llm", {"url": "https://httpbin.org/html"})
    if data and data.get("format") == "[WEBFURL]":
        print("✓ serialize_for_llm")
        tests_passed += 1
    else:
        print("✗ serialize_for_llm")
        tests_failed += 1
    
    proc.terminate()
    proc.wait()
    
    print(f"\nPassed: {tests_passed}, Failed: {tests_failed}")
    sys.exit(0 if tests_failed == 0 else 1)

if __name__ == "__main__":
    main()
