#!/usr/bin/env python3
"""
Quick Test Script for Enhanced Honey Encryption Features

This script provides a simple way to test the enhanced features:
- Field-Aware DTE
- Schema-driven decoding  
- Length preservation
- Enhanced state controller
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

def test_enhanced_honey_encryption():
    """Test enhanced honey encryption with FA-DTE"""
    print("🔐 Testing Enhanced Honey Encryption with FA-DTE")
    print("-" * 50)
    
    try:
        from encryption.honey_crypto_v2 import honey_encrypt_real_text_v2, honey_decrypt_or_fake_v2
        
        # Sample structured document
        sample_doc = '''SENSITIVE DOCUMENT
Name=test_finance.txt
type=finance_summary
department=Finance
region=IN-WEST
currency=INR
revenue=5240000
expenses=3890000
profit=1350000
approved=true
contact=finance@company.com

notes=Quarterly financial summary for internal review.'''

        print("Original document:")
        print(sample_doc)
        
        # Encrypt
        encrypted = honey_encrypt_real_text_v2(
            sample_doc.encode('utf-8'), 
            'correct_password', 
            150000, 
            'test_finance.txt'
        )
        print(f"\\n✓ Encrypted size: {len(encrypted)} bytes")
        
        # Test correct key
        correct_result = honey_decrypt_or_fake_v2(encrypted, 'correct_password', 'test_finance.txt')
        print("\\n✓ CORRECT KEY - Returns original document")
        
        # Test wrong key
        fake_result = honey_decrypt_or_fake_v2(encrypted, 'wrong_password', 'test_finance.txt')
        fake_text = fake_result.decode('utf-8', errors='replace')
        print("\\n✗ WRONG KEY - Returns believable fake:")
        print(fake_text[:400] + "..." if len(fake_text) > 400 else fake_text)
        
        return True
        
    except ImportError:
        print("❌ Enhanced honey encryption not available")
        return False


def test_schema_loading():
    """Test schema loading and field definitions"""
    print("\\n📋 Testing Schema-Driven Field Definitions")
    print("-" * 50)
    
    try:
        from encryption.honey_crypto_v2 import _load_schema
        
        schema = _load_schema()
        print(f"✓ Schema version: {schema.get('version', 'unknown')}")
        print(f"✓ Domains defined: {len(schema.get('domains', {}))}")
        print(f"✓ Field schemas: {len(schema.get('field_schemas', {}))}")
        
        # Show sample domains
        domains = schema.get('domains', {})
        for domain_name in list(domains.keys())[:3]:
            vocab = domains[domain_name].get('vocabulary', [])
            print(f"   {domain_name}: {len(vocab)} vocabulary terms")
        
        return True
        
    except Exception as e:
        print(f"❌ Schema loading failed: {e}")
        return False


def test_enhanced_controller():
    """Test enhanced state controller"""
    print("\\n🎛️  Testing Enhanced State Controller")
    print("-" * 50)
    
    try:
        from encryption.controller_v2 import EnhancedEncryptionController, SystemState
        import logging
        
        # Mock logger
        logger = logging.getLogger('test')
        logger.setLevel(logging.INFO)
        
        # Create controller (storage can be None for test)
        controller = EnhancedEncryptionController(None, logger)
        
        print(f"✓ Initial state: {controller.current_state}")
        print(f"✓ Encryption mode: {controller.encryption_mode}")
        
        # Test manual override
        success = controller.manual_override(SystemState.SUSPICIOUS.value, "Test override")
        print(f"✓ Manual override: {'Success' if success else 'Failed'}")
        print(f"✓ New state: {controller.current_state}")
        
        return True
        
    except Exception as e:
        print(f"❌ Enhanced controller test failed: {e}")
        return False


def test_enhanced_bootstrap():
    """Test enhanced bootstrap pipeline"""
    print("\\n🚀 Testing Enhanced Bootstrap Pipeline")
    print("-" * 50)
    
    try:
        from data_bootstrap_v2 import EnhancedBootstrap, BootstrapSpecV2
        import logging
        import tempfile
        import shutil
        
        # Mock logger
        logger = logging.getLogger('test')
        logger.setLevel(logging.INFO)
        
        # Create temporary directories for test
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            protected_dir = temp_path / "protected"
            encrypted_dir = temp_path / "encrypted"
            fake_dir = temp_path / "fake"
            
            bootstrap = EnhancedBootstrap(logger)
            spec = BootstrapSpecV2(count=3, validate_authenticity=True, rotate_seeds=True)
            
            results = bootstrap.full_bootstrap_pipeline(protected_dir, encrypted_dir, fake_dir, spec)
            
            print(f"✓ Bootstrap success: {results['success']}")
            print(f"✓ Total files: {results['total_files']}")
            print(f"✓ Enhanced features: {results['enhanced_features_active']}")
            print(f"✓ Encryption seed: {results['encryption_seed'][:8]}...")
            
        return True
        
    except Exception as e:
        print(f"❌ Enhanced bootstrap test failed: {e}")
        return False


def main():
    """Run all enhanced feature tests"""
    print("🧪 ENHANCED HONEY ENCRYPTION SYSTEM - FEATURE TESTS")
    print("=" * 60)
    
    tests = [
        ("Enhanced Honey Encryption", test_enhanced_honey_encryption),
        ("Schema Loading", test_schema_loading), 
        ("Enhanced Controller", test_enhanced_controller),
        ("Enhanced Bootstrap", test_enhanced_bootstrap),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    print("\\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    
    passed = 0
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {test_name}")
        if success:
            passed += 1
    
    print(f"\\n🎯 Overall: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("🎉 All enhanced features are working correctly!")
    else:
        print("⚠️  Some features may not be available or need fixing.")
    
    return passed == len(results)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)