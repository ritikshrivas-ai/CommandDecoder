# CommandDecoder Pro - Advanced Command Analysis Toolkit 🔍🛡️

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![GitHub Release](https://img.shields.io/badge/release-v2.0-orange)

CommandDecoder Pro is an advanced toolkit designed to analyze suspicious commands, deobfuscate encoded strings, extract IOCs, and map them to MITRE ATT&CK techniques. Ideal for forensic analysts, threat hunters, and red teamers.

---

## 📚 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Technical Details](#-technical-details)
- [Screenshots](#-screenshots)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🚀 Features

### 🎯 Core Capabilities

- **Multi-Layer Decoding:**
  - Base64 decoding (`powershell -enc`)
  - Hex decoding (`\x41\x42`)
  - String reversal patterns (`-join[...]`)
  - PowerShell-specific obfuscation handling (e.g. backticks)

- **IOC Extraction:**

  ```python
  # Supported Indicators
  URL         = r"(https?://[^\s\"']+)"
  IPv4        = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
  File Path   = r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*"
  SHA256 Hash = r"\b[a-fA-F0-9]{64}\b"

**Threat Scoring:**
- Visual gauge (0-10 scale)
- Color-coded risk levels (🟢 Low → 🔴 Critical)
- Weighted scoring algorithm

**YARA Rule Generation:**
- Automatic rule creation from IOCs
- Customizable rule templates
- MITRE technique integration

**MITRE ATT&CK Mapping:**

```python
{

"T1059.001": "Command-Line Interface: PowerShell",
  "T1105": "Ingress Tool Transfer",
  "T1140": "Deobfuscate/Decode Files"
}

