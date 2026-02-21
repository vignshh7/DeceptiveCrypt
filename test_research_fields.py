#!/usr/bin/env python3
"""
Test script to verify improved research field generation
"""

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from encryption.honey_crypto import honey_encrypt_real_text_v2, honey_decrypt_or_fake_v2

# Test research document content
research_content = """Name=CyberSec Research Team
type=research_notes
project=vulnerability_assessment
milestone=analysis_phase
owner=security_analyst
priority=high
status=in_progress

action_item_1=Review security logs for anomalies
action_item_2=Document vulnerability findings
action_item_3=Prepare security recommendations"""

print("Original research content:")
print(research_content)
print("\n" + "="*50 + "\n")

# Test with correct key first to encrypt
correct_key = "correct_secret"
iterations = 150000

print("Encrypting with correct key...")
encrypted_blob = honey_encrypt_real_text_v2(
    research_content.encode('utf-8'), 
    correct_key, 
    iterations, 
    "file_3.txt"
)

# Test with wrong key to see honey content
fake_key = "wrong_key_123" 

print("Honey decrypted content (with wrong key):")
honey_result = honey_decrypt_or_fake_v2(encrypted_blob, fake_key, "file_3.txt")
print(honey_result.decode('utf-8'))

print("\n" + "="*50 + "\n")

# Test multiple times to see variety
for i in range(3):
    print(f"Test {i+1} (wrong key: wrong_key_{i}):")
    honey_result = honey_decrypt_or_fake_v2(encrypted_blob, f"wrong_key_{i}", "file_3.txt")
    print(honey_result.decode('utf-8'))
    print("-" * 30)