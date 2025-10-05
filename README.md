# AEO Security Tool
> Automate AEO compliance verification with SBOM-based security scanning and ISMS integration.

## 🚀 Overview
AEO Security Tool is a CLI-based automation pipeline for AEO (Authorized Economic Operator) compliance verification, providing SBOM generation, vulnerability scanning, EOL checking, and automated report generation with digital signatures.
<br><br>The project is designed for automated security auditing, compliance verification, and standardized evidence generation for AEO certification, with seamless integration into modern CI/CD workflows.

## ✨ Features
### Automated SBOM Generation
Integrates with Syft to automatically generate Software Bill of Materials in CycloneDX format.<br>
### Vulnerability Scanning 
Uses Grype to detect CVEs, map CVSS scores, and identify security vulnerabilities in software components.<br>
### EOL/EOS Detection
Automatically checks End-of-Life status for all software components using endoflife.date API.<br>
### Compliance Reporting
Generates standardized PDF reports mapped to ISMS vulnerability management requirements for AEO certification.<br>
### Digital Signatures
Uses Cosign to digitally sign reports and artifacts, ensuring integrity and authenticity.<br>
### CI/CD Integration
Command-line interface and GitHub Actions support for easy integration into automated workflows.<br>

## 🏗️ Architecture
```
                                    +---------------------+
                                    |  Source Code /      |
                                    |  Container Image    |
                                    +----------+----------+
                                               |
                                               v
                                    +---------------------+
                                    |   SBOM Generation   |   (Syft)
                                    +----------+----------+
                                               |
                                  CycloneDX    v
                                    +---------------------+
                                    |   aeo-tool-core     |
                                    |   (Orchestrator)    |
                                    +----------+----------+
                                               |
                            +------------------+-------------------+
                            |                                      |
                            v                                      v
                  +---------------------+                +---------------------+
                  | Vulnerability Scan  |                |   EOL Checker       |
                  |    (Grype)          |                | (endoflife.date)    |
                  +----------+----------+                +----------+----------+
                            |                                      |
                            +------------------+-------------------+
                                               |
                                               v
                                    +---------------------+
                                    |  Report Generator   |
                                    | (PDF + HTML + JSON) |
                                    +----------+----------+
                                               |
                                               v
                                    +---------------------+
                                    | Digital Signature   |   (Cosign)
                                    +----------+----------+
                                               |
                                               v
                                    +---------------------+
                                    |  Evidence Bundle    |
                                    | (AEO Certification) |
                                    +---------------------+
```

## ⚡ Getting Started

## 👨‍💻 Team
### 👩🏻‍💻 Development Team

### 🔬 Research Contributors
