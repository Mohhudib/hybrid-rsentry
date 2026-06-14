export const RULE_NAME = {
  CANARY_TOUCHED:        'Canary File Modified by Untrusted Process',
  ENTROPY_SPIKE:         'High-Entropy File Writes (Encryption Behavior)',
  PROCESS_ANOMALY:       'Suspicious Process Lineage Detected',
  COMBINED_ALERT:        'Multi-Vector Ransomware Behavior',
  CONTAINMENT_TRIGGERED: 'Host Isolation Initiated',
  CONTAINMENT_COMPLETE:  'Containment Verified',
  MARKOV_REPOSITION:     'Adaptive Canary Reposition',
  HEARTBEAT:             'System Heartbeat',
  RANSOMWARE_RENAME:     'Ransomware File Extension Rename Detected',
  RANSOMWARE_CREATED:    'Ransomware Encrypted File Created',
  CANARY_DELETED:        'Canary File Deleted by Untrusted Process',
};

export const MITRE = {
  CANARY_TOUCHED:        [{ id: 'T1485', name: 'Data Destruction',               tac: 'Impact' }],
  ENTROPY_SPIKE:         [{ id: 'T1486', name: 'Data Encrypted for Impact',       tac: 'Impact' }],
  PROCESS_ANOMALY:       [{ id: 'T1059', name: 'Command & Scripting Interpreter', tac: 'Execution' }],
  COMBINED_ALERT:        [{ id: 'T1486', name: 'Data Encrypted for Impact',       tac: 'Impact' }, { id: 'T1485', name: 'Data Destruction', tac: 'Impact' }],
  CONTAINMENT_TRIGGERED: [{ id: 'T1486', name: 'Data Encrypted for Impact',       tac: 'Impact' }],
  RANSOMWARE_RENAME:     [{ id: 'T1486', name: 'Data Encrypted for Impact',       tac: 'Impact' }],
  RANSOMWARE_CREATED:    [{ id: 'T1486', name: 'Data Encrypted for Impact',       tac: 'Impact' }],
  CANARY_DELETED:        [{ id: 'T1485', name: 'Data Destruction',                tac: 'Impact' }],
};
