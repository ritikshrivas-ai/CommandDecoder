# CommandDecoder Pro - Advanced Command Analysis Toolkit 🔍🛡️

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![GitHub Release](https://img.shields.io/badge/release-v2.0-orange)

CommandDecoder Pro is a modular, real-time command analysis toolkit designed for red teams, bug bounty hunters, and security analysts. It instantly decodes suspicious commands, extracts IOCs, maps MITRE ATT&CK techniques, scores threats, and generates actionable YARA rules. Built for fast-paced, high-stakes environments where precision and efficiency are critical.

---

## Features

- **Multi-layer Command Decoding:**  
  Decodes obfuscated payloads (Base64, hex, PowerShell, bash, etc.) on the fly.

- **IOC Extraction:**  
  Extracts URLs, IPs, hashes, domains, file paths, and more, with contextual risk profiling.

- **MITRE ATT&CK Mapping:**  
  Automatic mapping to relevant TTPs (expanded database for common offensive techniques).

- **Threat Scoring:**  
  Calculates a composite threat score based on IOCs, TTPs, and behavioral indicators.

- **Behavior Analysis:**  
  Flags file, network, system, process, and exfiltration activity.

- **YARA Rule Generation:**  
  Creates custom YARA rules from detected indicators for rapid detection engineering.

- **History Tracking:**  
  Maintains a searchable, exportable history of all analyzed commands.

- **GUI:**  
  Modern, responsive Tkinter interface with dark mode, tabbed navigation, context menus, and real-time progress.

---

## Quick Start

### Installation

```bash
git clone https://github.com/ritikshrivas-ai/CommandDecoder.git
cd CommandDecoder
python3 commanddecoder.py
```

**Requirements:**  
- Python 3.7+
- Tkinter (standard with most Python installations)

_No external dependencies required._

---

## Usage

1. **Paste/Type Suspicious Command:**  
   - Use the input panel to add suspect PowerShell, CMD, Bash, or encoded payloads.
2. **Analyze Command:**  
   - Click "Analyze Command" to start decoding and threat assessment.
3. **Review Results:**  
   - Switch between tabs for:
     - Decoded command
     - Threat analysis
     - IOC extraction
     - MITRE mapping
     - YARA rules
     - Behavior breakdown
4. **Export/Copy:**  
   - Right-click IOCs for quick copy/search.
   - Generate and export YARA rules for your detection pipeline.

---

## Security & Operational Notes

- **No automatic execution or sandboxing:**  
  Commands are decoded and analyzed statically.  
  _Never run untrusted payloads directly from the tool._

- **No cloud connectivity:**  
  All analysis is local, preserving operational security and privacy.

- **All user input is retained in local history unless cleared/exported explicitly.**

---

## Example Use Cases

- Rapid triage of suspicious commands from incident logs, phishing emails, or endpoint telemetry.
- Decoding and analyzing payloads during exploit development or red team engagements.
- Quick YARA rule generation for threat hunting and detection engineering.
- IOC enrichment and MITRE mapping for reporting and documentation.

---

## Screenshots

<!-- Add relevant screenshots here if desired -->

---

## License

MIT License — see [LICENSE](LICENSE).

---

## About

Developed by [Ritik Shrivas](https://github.com/ritikshrivas-ai)  
2023–2025 | Offensive Security Tooling

---

## Contact & Contributions

- Issues, feature requests, and pull requests are welcome.
- For custom modules or operational integration, reach out via GitHub.
