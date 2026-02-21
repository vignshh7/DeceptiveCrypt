"""
Enhanced State Controller with Formal State Machine for AES ↔ Honey Mode Switching

This module implements a sophisticated state machine for encryption mode management:
1. Formal state definitions with transition rules
2. Trigger-based mode switching with thresholds
3. State persistence and recovery capabilities
4. Audit logging for security analysis
5. Configurable detection sensitivity
"""

from __future__ import annotations

import threading
import time
import json
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Any

from config import CRYPTO, STORAGE
from detection.anomaly_detector import DetectionResult, DetectionLabel
from storage.secure_storage import SecureStorage


class EncryptionMode(Enum):
    """Encryption operation modes"""
    NORMAL_AES = "NORMAL_AES"
    HONEY = "HONEY"


class SystemState(Enum):
    """System security states"""
    NORMAL_AES = "NORMAL_AES"          # Normal operation, AES encryption
    SUSPICIOUS = "SUSPICIOUS"          # Suspicious activity detected
    HONEY_ACTIVE = "HONEY_ACTIVE"      # Honey encryption engaged
    RECOVERY = "RECOVERY"              # Post-incident recovery mode


class TriggerType(Enum):
    """Event trigger types for state transitions"""
    FILE_ACCESS_RATE = "FILE_ACCESS_RATE"
    EXTENSION_MUTATION = "EXTENSION_MUTATION" 
    UNKNOWN_PROCESS = "UNKNOWN_PROCESS"
    MASS_ENCRYPTION = "MASS_ENCRYPTION"
    ENTROPY_ANOMALY = "ENTROPY_ANOMALY"
    BEHAVIORAL_PATTERN = "BEHAVIORAL_PATTERN"
    MANUAL_OVERRIDE = "MANUAL_OVERRIDE"
    SYSTEM_RECOVERY = "SYSTEM_RECOVERY"


@dataclass
class StateTransition:
    """State transition record"""
    timestamp: str
    from_state: str
    to_state: str
    trigger: str
    trigger_data: Dict[str, Any]
    confidence: float
    reason: str


@dataclass 
class TriggerThreshold:
    """Configurable thresholds for trigger activation"""
    file_access_rate_per_minute: int = 50
    unknown_process_threshold: float = 0.8
    mass_encryption_file_count: int = 10  
    entropy_deviation_threshold: float = 2.0
    extension_mutation_count: int = 5
    suspicious_duration_minutes: int = 5
    recovery_cooldown_minutes: int = 30


@dataclass
class SystemMetrics:
    """Current system security metrics"""
    file_access_count: int = 0
    unknown_processes: Set[str] = None
    encrypted_file_count: int = 0
    entropy_samples: List[float] = None
    extension_mutations: Dict[str, int] = None
    last_reset: str = ""
    
    def __post_init__(self):
        if self.unknown_processes is None:
            self.unknown_processes = set()
        if self.entropy_samples is None:
            self.entropy_samples = []
        if self.extension_mutations is None:
            self.extension_mutations = {}
        if not self.last_reset:
            self.last_reset = datetime.now().isoformat()


@dataclass
class ControllerStateV2:
    """Enhanced controller state with metrics and history"""
    current_state: str = SystemState.NORMAL_AES.value
    encryption_mode: str = EncryptionMode.NORMAL_AES.value
    last_transition: str = ""
    metrics: SystemMetrics = None
    thresholds: TriggerThreshold = None
    transitions_history: List[StateTransition] = None
    state_entry_time: str = ""
    
    def __post_init__(self):
        if self.metrics is None:
            self.metrics = SystemMetrics()
        if self.thresholds is None:
            self.thresholds = TriggerThreshold()
        if self.transitions_history is None:
            self.transitions_history = []
        if not self.state_entry_time:
            self.state_entry_time = datetime.now().isoformat()


class EnhancedEncryptionController:
    """Enhanced encryption controller with formal state machine"""
    
    def __init__(self, storage: SecureStorage, logger, state_file: Optional[Path] = None):
        self._storage = storage
        self._logger = logger
        self._lock = threading.Lock()
        self._state_file = state_file or Path("controller_state.json")
        self._state = self._load_state()
        
        # State machine definition
        self._transitions = self._define_state_machine()
        self._reset_metrics_timer()
    
    def _define_state_machine(self) -> Dict[str, Dict[str, List[str]]]:
        """Define valid state transitions with trigger conditions"""
        return {
            SystemState.NORMAL_AES.value: {
                TriggerType.FILE_ACCESS_RATE.value: [SystemState.SUSPICIOUS.value],
                TriggerType.EXTENSION_MUTATION.value: [SystemState.SUSPICIOUS.value],
                TriggerType.UNKNOWN_PROCESS.value: [SystemState.SUSPICIOUS.value],
                TriggerType.ENTROPY_ANOMALY.value: [SystemState.SUSPICIOUS.value],
                TriggerType.MASS_ENCRYPTION.value: [SystemState.HONEY_ACTIVE.value],
                TriggerType.BEHAVIORAL_PATTERN.value: [SystemState.HONEY_ACTIVE.value],
            },
            SystemState.SUSPICIOUS.value: {
                TriggerType.MASS_ENCRYPTION.value: [SystemState.HONEY_ACTIVE.value],
                TriggerType.BEHAVIORAL_PATTERN.value: [SystemState.HONEY_ACTIVE.value],
                TriggerType.SYSTEM_RECOVERY.value: [SystemState.NORMAL_AES.value],
                TriggerType.FILE_ACCESS_RATE.value: [SystemState.HONEY_ACTIVE.value],
            },
            SystemState.HONEY_ACTIVE.value: {
                TriggerType.MANUAL_OVERRIDE.value: [SystemState.RECOVERY.value],
                TriggerType.SYSTEM_RECOVERY.value: [SystemState.RECOVERY.value],
            },
            SystemState.RECOVERY.value: {
                TriggerType.SYSTEM_RECOVERY.value: [SystemState.NORMAL_AES.value],
                TriggerType.MANUAL_OVERRIDE.value: [SystemState.NORMAL_AES.value],
            }
        }
    
    def _load_state(self) -> ControllerStateV2:
        """Load controller state from persistent storage"""
        try:
            if self._state_file.exists():
                with open(self._state_file, 'r') as f:
                    data = json.load(f)
                    # Reconstruct objects
                    state = ControllerStateV2(**data)
                    # Restore complex objects
                    state.metrics.unknown_processes = set(state.metrics.unknown_processes)
                    return state
        except Exception as e:
            self._logger.warning(f"[WARNING] Could not load state: {e}")
        
        return ControllerStateV2()
    
    def _save_state(self) -> None:
        """Persist controller state to storage"""
        try:
            # Convert sets to lists for JSON serialization
            state_dict = asdict(self._state)
            state_dict['metrics']['unknown_processes'] = list(self._state.metrics.unknown_processes)
            
            with open(self._state_file, 'w') as f:
                json.dump(state_dict, f, indent=2)
        except Exception as e:
            self._logger.warning(f"[WARNING] Could not save state: {e}")
    
    def _reset_metrics_timer(self) -> None:
        """Reset metrics periodically"""
        def reset_worker():
            while True:
                time.sleep(60)  # Reset every minute
                with self._lock:
                    now = datetime.now()
                    last_reset = datetime.fromisoformat(self._state.metrics.last_reset)
                    
                    if (now - last_reset).total_seconds() >= 60:
                        self._state.metrics.file_access_count = 0
                        self._state.metrics.encrypted_file_count = 0
                        self._state.metrics.entropy_samples = []
                        self._state.metrics.extension_mutations = {}
                        self._state.metrics.last_reset = now.isoformat()
                        self._save_state()
        
        reset_thread = threading.Thread(target=reset_worker, daemon=True)
        reset_thread.start()
    
    def _evaluate_triggers(self, result: DetectionResult) -> List[Tuple[TriggerType, float, Dict[str, Any]]]:
        """Evaluate which triggers are activated by detection result"""
        activated_triggers = []
        
        # File access rate trigger
        self._state.metrics.file_access_count += 1
        if self._state.metrics.file_access_count >= self._state.thresholds.file_access_rate_per_minute:
            activated_triggers.append((
                TriggerType.FILE_ACCESS_RATE, 
                0.9,
                {"access_count": self._state.metrics.file_access_count, "threshold": self._state.thresholds.file_access_rate_per_minute}
            ))
        
        # Mass encryption trigger
        if result.label == DetectionLabel.RANSOMWARE_DETECTED:
            self._state.metrics.encrypted_file_count += 1
            if self._state.metrics.encrypted_file_count >= self._state.thresholds.mass_encryption_file_count:
                activated_triggers.append((
                    TriggerType.MASS_ENCRYPTION,
                    0.95,
                    {"encrypted_count": self._state.metrics.encrypted_file_count, "threshold": self._state.thresholds.mass_encryption_file_count}
                ))
        
        # Extension mutation trigger
        for reason in result.reasons:
            if "extension" in reason.lower():
                ext = reason.split()[-1] if " " in reason else "unknown"
                self._state.metrics.extension_mutations[ext] = self._state.metrics.extension_mutations.get(ext, 0) + 1
                total_mutations = sum(self._state.metrics.extension_mutations.values())
                if total_mutations >= self._state.thresholds.extension_mutation_count:
                    activated_triggers.append((
                        TriggerType.EXTENSION_MUTATION,
                        0.8,
                        {"mutations": dict(self._state.metrics.extension_mutations), "total": total_mutations}
                    ))
        
        # Unknown process trigger
        for reason in result.reasons:
            if "process" in reason.lower():
                process_id = hashlib.md5(reason.encode()).hexdigest()[:8]
                self._state.metrics.unknown_processes.add(process_id)
                if len(self._state.metrics.unknown_processes) >= 3:  # Multiple unknown processes
                    activated_triggers.append((
                        TriggerType.UNKNOWN_PROCESS,
                        self._state.thresholds.unknown_process_threshold,
                        {"processes": list(self._state.metrics.unknown_processes)}
                    ))
        
        # Behavioral pattern trigger (based on detection result)
        if result.label == DetectionLabel.RANSOMWARE_DETECTED and len(result.reasons) >= 3:
            activated_triggers.append((
                TriggerType.BEHAVIORAL_PATTERN,
                0.85,
                {"patterns": result.reasons[:5]}
            ))
        
        return activated_triggers
    
    def _can_transition(self, from_state: str, to_state: str, trigger: TriggerType) -> bool:
        """Check if state transition is valid"""
        valid_transitions = self._transitions.get(from_state, {})
        valid_targets = valid_transitions.get(trigger.value, [])
        return to_state in valid_targets
    
    def _execute_transition(self, to_state: str, trigger: TriggerType, trigger_data: Dict[str, Any], confidence: float, reason: str) -> bool:
        """Execute state transition with logging"""
        from_state = self._state.current_state
        
        if not self._can_transition(from_state, to_state, trigger):
            self._logger.warning(f"[WARNING] Invalid transition: {from_state} -> {to_state} via {trigger.value}")
            return False
        
        # Record transition
        transition = StateTransition(
            timestamp=datetime.now().isoformat(),
            from_state=from_state,
            to_state=to_state,
            trigger=trigger.value,
            trigger_data=trigger_data,
            confidence=confidence,
            reason=reason
        )
        
        # Update state
        self._state.current_state = to_state
        self._state.last_transition = transition.timestamp
        self._state.state_entry_time = transition.timestamp
        self._state.transitions_history.append(transition)
        
        # Update encryption mode
        if to_state == SystemState.HONEY_ACTIVE.value:
            self._state.encryption_mode = EncryptionMode.HONEY.value
        else:
            self._state.encryption_mode = EncryptionMode.NORMAL_AES.value
        
        # Log transition
        self._logger.info(f"[STATE] Transition: {from_state} -> {to_state} (trigger: {trigger.value}, confidence: {confidence:.2f})")
        self._logger.info(f"[STATE] Reason: {reason}")
        
        if to_state == SystemState.HONEY_ACTIVE.value:
            self._logger.error("[SECURITY] HONEY ENCRYPTION ACTIVATED - Real data protected")
        elif to_state == SystemState.RECOVERY.value:
            self._logger.warning("[SECURITY] Recovery mode - Manual intervention required")
        elif to_state == SystemState.NORMAL_AES.value and from_state != SystemState.NORMAL_AES.value:
            self._logger.info("[SECURITY] Normal operation restored")
        
        self._save_state()
        return True
    
    def _auto_recovery_check(self) -> None:
        """Check for automatic recovery conditions"""
        if self._state.current_state == SystemState.SUSPICIOUS.value:
            state_entry = datetime.fromisoformat(self._state.state_entry_time)
            now = datetime.now()
            
            if (now - state_entry).total_seconds() >= self._state.thresholds.suspicious_duration_minutes * 60:
                # Auto-recover from suspicious state if no escalation
                self._execute_transition(
                    SystemState.NORMAL_AES.value,
                    TriggerType.SYSTEM_RECOVERY, 
                    {"auto_recovery": True, "duration_minutes": (now - state_entry).total_seconds() / 60},
                    0.7,
                    "Automatic recovery from suspicious state timeout"
                )
    
    @property
    def current_state(self) -> str:
        """Get current system state"""
        with self._lock:
            return self._state.current_state
    
    @property
    def encryption_mode(self) -> str:
        """Get current encryption mode"""
        with self._lock:
            return self._state.encryption_mode
    
    @property  
    def state_info(self) -> Dict[str, Any]:
        """Get comprehensive state information"""
        with self._lock:
            return {
                "current_state": self._state.current_state,
                "encryption_mode": self._state.encryption_mode,
                "state_entry_time": self._state.state_entry_time,
                "last_transition": self._state.last_transition,
                "metrics": asdict(self._state.metrics),
                "recent_transitions": [asdict(t) for t in self._state.transitions_history[-5:]]
            }
    
    def on_detection(self, result: DetectionResult) -> None:
        """Process detection result and manage state transitions"""
        with self._lock:
            # Evaluate triggers
            activated_triggers = self._evaluate_triggers(result)
            
            # Auto recovery check
            self._auto_recovery_check()
            
            current_state = self._state.current_state
            
            # Process highest confidence trigger
            if activated_triggers:
                trigger, confidence, trigger_data = max(activated_triggers, key=lambda x: x[1])
                
                # Determine target state based on current state and trigger
                target_state = None
                if current_state == SystemState.NORMAL_AES.value:
                    if trigger in [TriggerType.MASS_ENCRYPTION, TriggerType.BEHAVIORAL_PATTERN]:
                        target_state = SystemState.HONEY_ACTIVE.value
                    else:
                        target_state = SystemState.SUSPICIOUS.value
                elif current_state == SystemState.SUSPICIOUS.value:
                    if trigger in [TriggerType.MASS_ENCRYPTION, TriggerType.BEHAVIORAL_PATTERN, TriggerType.FILE_ACCESS_RATE]:
                        target_state = SystemState.HONEY_ACTIVE.value
                
                if target_state and target_state != current_state:
                    reason = f"{result.label.value} detection with {len(result.reasons)} indicators"
                    self._execute_transition(target_state, trigger, trigger_data, confidence, reason)
    
    def manual_override(self, target_state: str, reason: str = "Manual intervention") -> bool:
        """Manually override system state"""
        with self._lock:
            try:
                target_enum = SystemState(target_state)
                return self._execute_transition(
                    target_state,
                    TriggerType.MANUAL_OVERRIDE,
                    {"manual": True, "user_reason": reason},
                    1.0,
                    f"Manual override: {reason}"
                )
            except ValueError:
                self._logger.error(f"[ERROR] Invalid target state: {target_state}")
                return False
    
    def initiate_recovery(self, reason: str = "System recovery initiated") -> bool:
        """Initiate recovery sequence"""
        with self._lock:
            if self._state.current_state == SystemState.HONEY_ACTIVE.value:
                return self._execute_transition(
                    SystemState.RECOVERY.value,
                    TriggerType.SYSTEM_RECOVERY,
                    {"recovery_initiated": True},
                    0.9,
                    reason
                )
            return False
    
    def protect_file_snapshot(self, src_file: Path, user_passphrase: str, iterations: int) -> None:
        """Store secure snapshot based on current encryption mode"""
        if not src_file.exists() or not src_file.is_file():
            return

        mode = self.encryption_mode
        
        if mode == EncryptionMode.NORMAL_AES.value:
            self._storage.store_real_encrypted(src_file, user_passphrase, iterations)
            return

        if mode == EncryptionMode.HONEY.value:
            self._storage.store_honey_encrypted(src_file, user_passphrase, iterations)
            self._logger.error("[ATTACKER] Honey encrypted data delivered")
            self._logger.info("[USER] Real data remains secure")


# Backwards compatibility
EncryptionController = EnhancedEncryptionController
CryptoMode = EncryptionMode