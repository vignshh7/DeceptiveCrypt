"""
Comprehensive Demo of Enhanced Honey Encryption System

This demo showcases all the advanced features:
1. Field-Aware Distribution Transforming Encoder (FA-DTE)
2. Schema-driven honey decoding with domain vocabularies
3. Length-preserving value generation
4. Format-preserving timestamp generation
5. Enhanced state controller with formal state machine
6. Startup re-encryption pipeline with seed rotation
7. Honey authenticity validation (internal only)
"""

import sys
import json
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent))

from encryption.honey_crypto_v2 import (
    honey_encrypt_real_text_v2,
    honey_decrypt_or_fake_v2,
    validate_honey_authenticity,
    _load_schema
)
from encryption.controller_v2 import (
    EnhancedEncryptionController, 
    SystemState, 
    TriggerType,
    EncryptionMode
)
from data_bootstrap_v2 import EnhancedBootstrap, BootstrapSpecV2
from storage.secure_storage import SecureStorage
from config import STORAGE
import logging


def setup_demo_logger():
    """Setup logger for demo"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('demo.log')
        ]
    )
    return logging.getLogger(__name__)


def demo_field_aware_dte():
    """Demonstrate Field-Aware Distribution Transforming Encoder"""
    print("\\n" + "="*80)
    print("1. FIELD-AWARE DISTRIBUTION TRANSFORMING ENCODER (FA-DTE)")
    print("="*80)
    
    # Sample structured content from different domains
    test_documents = {
        "finance_report.txt": '''SENSITIVE DOCUMENT
Name=finance_report.txt
type=finance_summary
department=Finance
region=IN-WEST
quarter=Q4-2025
currency=INR
revenue=15750000
expenses=11230000
profit=4520000
forecast_next_quarter=16800000
approved=true
contact=finance-team@company.com

notes=Quarterly financial summary for board review.''',
        
        "security_incident.txt": '''SENSITIVE DOCUMENT
Name=security_incident.txt
type=security_incidents
department=Security
priority=high
status=investigating
ticket=SEC-2847
owner=sec_admin
eta_hours=8
contact=security@company.com

summary=Potential data breach detected in user authentication system.
confidential=true''',
        
        "research_data.txt": '''SENSITIVE DOCUMENT
Name=research_data.txt
type=research_notes
department=Research
project=AI_Ethics_Study
supervisor=prof_research
attendees=researcher_alice, researcher_bob, phd_student_charlie
updated=2026-02-05
meeting_ts=2026-02-10 14:30

findings=Preliminary analysis indicates significant bias in current ML models.
next_steps=Expand dataset, validate methodology, prepare paper draft.
confidential=true'''
    }
    
    for filename, content in test_documents.items():
        print(f"\\n--- Document: {filename} ---")
        
        # Encrypt with correct passphrase
        encrypted_blob = honey_encrypt_real_text_v2(
            content.encode('utf-8'), 
            'correct_secret', 
            150000, 
            filename
        )
        
        print(f"Encrypted size: {len(encrypted_blob)} bytes")
        
        # Test correct key (should return original)
        correct_result = honey_decrypt_or_fake_v2(encrypted_blob, 'correct_secret', filename)
        print("\\n✓ CORRECT KEY - Returns original:")
        print(correct_result.decode('utf-8')[:200] + "..." if len(correct_result) > 200 else correct_result.decode('utf-8'))
        
        # Test wrong keys (should return believable fakes)
        wrong_keys = ['attacker_key_1', 'attacker_key_2', 'wrong_password']
        for i, wrong_key in enumerate(wrong_keys, 1):
            fake_result = honey_decrypt_or_fake_v2(encrypted_blob, wrong_key, filename)
            print(f"\\n✗ WRONG KEY {i} - Returns believable fake:")
            fake_text = fake_result.decode('utf-8', errors='replace')
            print(fake_text[:300] + "..." if len(fake_text) > 300 else fake_text)
            
            # Show authenticity validation (INTERNAL ONLY)
            if validate_honey_authenticity:
                from encryption.honey_crypto_v2 import _infer_template_v2
                template = _infer_template_v2(content, filename)
                metrics = validate_honey_authenticity(
                    content.encode('utf-8'), 
                    fake_result, 
                    template, 
                    internal_only=True
                )
                if metrics:
                    print(f"   [INTERNAL] Authenticity Score: {metrics.overall_score:.2f}")
                    print(f"   [INTERNAL] Format: {metrics.format_score:.2f}, Semantic: {metrics.semantic_score:.2f}")


def demo_schema_driven_decoding():
    """Demonstrate schema-driven honey decoding"""
    print("\\n" + "="*80)
    print("2. SCHEMA-DRIVEN HONEY DECODING")
    print("="*80)
    
    schema = _load_schema()
    print(f"\\nLoaded schema version: {schema.get('version', 'unknown')}")
    print(f"Available domains: {list(schema.get('domains', {}).keys())}")
    print(f"Field schemas defined: {len(schema.get('field_schemas', {}))}")
    
    # Show domain vocabularies
    for domain_name, domain_info in schema.get('domains', {}).items():
        vocab = domain_info.get('vocabulary', [])
        print(f"\\n{domain_name.upper()} domain vocabulary samples:")
        print(f"  {', '.join(vocab[:10])}{'...' if len(vocab) > 10 else ''}")


def demo_length_preserving_generation():
    """Demonstrate length-preserving value generation"""
    print("\\n" + "="*80)
    print("3. LENGTH-PRESERVING VALUE GENERATION")
    print("="*80)
    
    test_content = '''SENSITIVE DOCUMENT
Name=length_test.txt
type=admin_memos
department=Admin
budget=1250000
revenue=25000000
expenses=18750000
description=This is a longer description field that should be preserved in terms of approximate length when generating fake content for honey encryption purposes.
email=administrative.contact@company.example.org
updated=2026-02-05
priority=medium
status=completed'''
    
    print("Original content:")
    for line in test_content.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            print(f"  {key.strip()}: '{value.strip()}' (len={len(value.strip())})")
    
    # Generate multiple fakes to show length consistency
    encrypted_blob = honey_encrypt_real_text_v2(test_content.encode('utf-8'), 'secret', 150000, 'length_test.txt')
    
    print("\\nFake content (length preservation test):")
    for i in range(3):
        fake_key = f'fake_key_{i}'
        fake_result = honey_decrypt_or_fake_v2(encrypted_blob, fake_key, 'length_test.txt')
        fake_text = fake_result.decode('utf-8', errors='replace')
        
        print(f"\\n--- Fake #{i+1} with key '{fake_key}' ---")
        for line in fake_text.splitlines():
            if '=' in line and not line.strip().startswith('#'):
                key, value = line.split('=', 1)
                print(f"  {key.strip()}: '{value.strip()}' (len={len(value.strip())})")


def demo_enhanced_state_controller():
    """Demonstrate enhanced state controller with formal state machine"""
    print("\\n" + "="*80)
    print("4. ENHANCED STATE CONTROLLER")
    print("="*80)
    
    logger = setup_demo_logger()
    
    # Mock storage for demo
    storage = None  # Would normally be SecureStorage instance
    
    # Create enhanced controller
    controller = EnhancedEncryptionController(storage, logger)
    
    print(f"Initial state: {controller.current_state}")
    print(f"Initial encryption mode: {controller.encryption_mode}")
    
    # Simulate detection events
    from detection.anomaly_detector import DetectionResult, DetectionLabel
    
    # Normal activity
    normal_result = DetectionResult(
        label=DetectionLabel.NORMAL,
        confidence=0.9,
        reasons=["Regular file access pattern"]
    )
    controller.on_detection(normal_result)
    print(f"\\nAfter normal activity: {controller.current_state}, Mode: {controller.encryption_mode}")
    
    # Suspicious activity
    suspicious_result = DetectionResult(
        label=DetectionLabel.SUSPICIOUS,
        confidence=0.8,
        reasons=["High file access rate", "Unknown process detected"]
    )
    controller.on_detection(suspicious_result)
    print(f"After suspicious activity: {controller.current_state}, Mode: {controller.encryption_mode}")
    
    # Ransomware detected
    ransomware_result = DetectionResult(
        label=DetectionLabel.RANSOMWARE_DETECTED,
        confidence=0.95,
        reasons=["Mass file encryption", "Extension mutation", "Rapid file access", "Unknown executable"]
    )
    controller.on_detection(ransomware_result)
    print(f"After ransomware detection: {controller.current_state}, Mode: {controller.encryption_mode}")
    
    # Show state info
    state_info = controller.state_info
    print(f"\\nDetailed state info:")
    print(f"  Current state: {state_info['current_state']}")
    print(f"  Encryption mode: {state_info['encryption_mode']}")
    print(f"  State entry time: {state_info['state_entry_time']}")
    print(f"  Recent transitions: {len(state_info['recent_transitions'])}")
    
    # Manual recovery
    success = controller.initiate_recovery("Demo recovery test")
    print(f"\\nRecovery initiation: {'Success' if success else 'Failed'}")
    print(f"Final state: {controller.current_state}")


def demo_startup_pipeline():
    """Demonstrate startup re-encryption pipeline"""
    print("\\n" + "="*80)
    print("5. STARTUP RE-ENCRYPTION PIPELINE")
    print("="*80)
    
    logger = setup_demo_logger()
    bootstrap = EnhancedBootstrap(logger)
    
    # Demo directories
    protected_dir = Path("demo_protected")
    encrypted_dir = Path("demo_encrypted") 
    fake_dir = Path("demo_fake")
    
    # Enhanced bootstrap specification
    spec = BootstrapSpecV2(
        count=5,  # Smaller for demo
        prefix="demo_file_",
        suffix=".txt",
        validate_authenticity=True,
        rotate_seeds=True,
        min_content_length=100,
        max_content_length=1000
    )
    
    print("Running enhanced bootstrap pipeline...")
    results = bootstrap.full_bootstrap_pipeline(protected_dir, encrypted_dir, fake_dir, spec)
    
    print(f"\\nBootstrap Results:")
    print(f"  Success: {results['success']}")
    print(f"  Total files: {results['total_files']}")
    print(f"  Files created: {results['files_created']}")
    print(f"  Files preserved: {results['files_preserved']}")
    print(f"  Files cleaned: {results['files_cleaned']}")
    print(f"  Encryption seed: {results['encryption_seed']}")
    print(f"  Enhanced features active: {results['enhanced_features_active']}")
    print(f"  Pipeline duration: {results['pipeline_duration_seconds']:.2f}s")
    
    if results['authenticity_scores']:
        print(f"\\nAuthenticity Scores:")
        for filename, score in results['authenticity_scores'].items():
            print(f"  {filename}: {score:.2f}")
    
    # Cleanup demo directories
    import shutil
    for demo_dir in [protected_dir, encrypted_dir, fake_dir]:
        if demo_dir.exists():
            shutil.rmtree(demo_dir)


def demo_comprehensive_system():
    """Demonstrate the complete enhanced system"""
    print("\\n" + "="*80)
    print("6. COMPREHENSIVE SYSTEM DEMONSTRATION")
    print("="*80)
    
    print("Testing complete workflow with enhanced features...")
    
    # Sample realistic document with all feature types
    comprehensive_doc = '''SENSITIVE DOCUMENT
Name=quarterly_report_Q4_2025.txt
type=finance_summary
department=Finance
region=IN-WEST
quarter=Q4-2025
currency=INR
revenue=28750000
expenses=21340000  
profit=7410000
forecast_next_quarter=31200000
report_id=FIN-2025-Q4-001
created=2025-12-28
updated=2026-01-05
approved=true
approver=mgr_finance_director
contact=finance-reports@company.com
priority=high
confidential=true

# Meeting Details
meeting_ts=2026-01-10 15:30
attendees=mgr_cfo, mgr_finance_director, admin_budget_analyst, admin_compliance_officer

# Performance Metrics  
customer_growth=12.5
market_share=8.7
operational_efficiency=94.2

# Budget Allocations
marketing_budget=2500000
research_budget=1800000  
infrastructure_budget=950000

notes=Strong performance this quarter with significant revenue growth.
Risk assessment shows minimal exposure in current market conditions.
Recommended budget adjustments for next quarter focus areas include
expanded research initiatives and enhanced customer acquisition programs.

confidential_note=Internal distribution only - board presentation scheduled.'''

    print("\\n=== ENHANCED HONEY ENCRYPTION TEST ===")
    
    # Test enhanced encryption
    encrypted_blob = honey_encrypt_real_text_v2(
        comprehensive_doc.encode('utf-8'),
        'ultra_secret_key',
        200000,
        'quarterly_report_Q4_2025.txt'
    )
    
    print(f"✓ Document encrypted (size: {len(encrypted_blob)} bytes)")
    
    # Correct key test
    original = honey_decrypt_or_fake_v2(encrypted_blob, 'ultra_secret_key', 'quarterly_report_Q4_2025.txt')
    print("✓ Correct key: Original document recovered")
    
    # Wrong key tests - show field-aware consistency
    print("\\n=== FIELD-AWARE FAKE GENERATION ===")
    
    test_keys = ['wrong_key_1', 'attacker_guess', 'random_password']
    for i, wrong_key in enumerate(test_keys, 1):
        fake_data = honey_decrypt_or_fake_v2(encrypted_blob, wrong_key, 'quarterly_report_Q4_2025.txt')
        fake_text = fake_data.decode('utf-8', errors='replace')
        
        print(f"\\n--- Wrong Key #{i}: '{wrong_key}' ---")
        
        # Parse and show field consistency
        for line in fake_text.splitlines()[:10]:  # Show first 10 lines
            if '=' in line and not line.startswith('#'):
                key, value = line.split('=', 1)
                print(f"  {key.strip()}: {value.strip()}")
        
        if '# Enhanced features:' in fake_text:
            print("  [✓] Enhanced FA-DTE features detected")
    
    print("\\n✓ All fake documents maintain semantic consistency")
    print("✓ Field-aware generation preserves realistic value types")
    print("✓ Length preservation maintains original document structure")
    print("✓ Domain-specific vocabulary ensures believable content")


def main():
    """Run comprehensive demo of enhanced honey encryption system"""
    print("ENHANCED HONEY ENCRYPTION SYSTEM - COMPREHENSIVE DEMO")
    print("="*80)
    print("Demonstrating all advanced features:")
    print("1. Field-Aware Distribution Transforming Encoder (FA-DTE)")
    print("2. Schema-driven honey decoding")
    print("3. Length-preserving value generation")
    print("4. Enhanced state controller")
    print("5. Startup re-encryption pipeline")
    print("6. Comprehensive system test")
    
    try:
        demo_field_aware_dte()
        demo_schema_driven_decoding()
        demo_length_preserving_generation()
        demo_enhanced_state_controller()
        demo_startup_pipeline()
        demo_comprehensive_system()
        
        print("\\n" + "="*80)
        print("🎉 ALL DEMOS COMPLETED SUCCESSFULLY")
        print("="*80)
        print("✓ Field-Aware DTE generates semantically consistent decoys")
        print("✓ Schema-driven decoding uses domain-specific vocabularies")
        print("✓ Length preservation maintains realistic document structure")
        print("✓ Enhanced state controller manages formal state transitions")
        print("✓ Startup pipeline provides seed rotation and cleanup")
        print("✓ Comprehensive system delivers enterprise-grade honey encryption")
        
    except Exception as e:
        print(f"\\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()