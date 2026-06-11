# 🌌 LLM Obfuscation Detection (LLMObfuscDetection)

Welcome to the **LLM Obfuscation Detection** repository. This project is a comprehensive research suite designed for studying, detecting, and analyzing code obfuscation techniques in Android applications (APKs), with a particular focus on those potentially enhanced, generated, or detected by Large Language Models (LLMs).

---

## 📋 Table of Contents
- [Overview](#-overview)
- [Project Structure](#-project-structure)
- [Modules](#-modules)
  - [1. LLM Obfuscator Detector](#1-llm-obfuscator-detector)
  - [2. GroundTruth Dataset & SAST Tools](#2-groundtruth-dataset--sast-tools)
- [Getting Started](#-getting-started)
- [License](#-license)

---

## 🔍 Overview

The **LLMObfuscDetection** project aims to provide researchers and security analysts with a robust framework for studying modern Android obfuscation. As LLMs become more capable of generating and refactoring code, the complexity and variety of obfuscation patterns are increasing. At the same time, LLMs offer new avenues for *detecting* these obfuscations. 

This repository provides both the datasets/tools for traditional static analysis and an innovative LLM-powered detection suite.

---

## 📂 Project Structure

At the root level, the repository is split into two primary modules:

| Directory | Description |
| :--- | :--- |
| **[`LLMObfuscatorDetector/`](./LLMObfuscatorDetector)** | Python-based experimental suite that uses LLMs (OpenAI, Gemini, Ollama) to automatically detect and classify obfuscation techniques in Smali code. |
| **[`GroundTruthDataset & SAST Tools/`](./GroundTruthDataset%20&%20SAST%20Tools)** | A curated collection of Android APKs (Ground Truth) and a Dockerized suite of traditional SAST (Static Application Security Testing) tools. |

---

## 🧩 Modules

### 1. LLM Obfuscator Detector

Located in [`LLMObfuscatorDetector/`](./LLMObfuscatorDetector), this module leverages advanced static analysis (decompilation of APKs to Smali using apktool) coupled with prompt-based LLM queries to determine:
1. **Obfuscation Detection**: Whether a given Android application is obfuscated.
2. **Obfuscation Classification**: What specific obfuscation techniques (e.g., Reflection, ConstStringEncryption, MethodRename, etc.) were applied.

**Key Features**:
- Support for multiple LLMs: OpenAI (GPT-4o), Google Gemini, and local open-source models via Ollama.
- Automated filtering of system/third-party libraries to isolate target code.
- Statistical sampling and majority-voting for robust LLM predictions.

> [!TIP]
> For more details and execution instructions, please read the [LLMObfuscatorDetector README](./LLMObfuscatorDetector/README.md).

### 2. GroundTruth Dataset & SAST Tools

Located in [`GroundTruthDataset & SAST Tools/`](./GroundTruthDataset%20&%20SAST%20Tools), this module serves as the foundational data and traditional security analysis environment.

**Key Components**:
- **Dataset (`apk/`)**: A collection of Android applications serving as the ground truth for comparative analysis (Clean vs. Obfuscated).
- **Docker Suite (`docker-tools/`)**: Integrates industry-standard SAST tools (Trueseeing, APKHunt, SEBASTiAn) into a single, automated workflow for fast, reproducible security audits.

> [!TIP]
> For detailed instructions on setting up the Docker environment and analyzing the dataset, please refer to the [Dataset & Tools README](./GroundTruthDataset%20&%20SAST%20Tools/README.md).

---

## 🛠️ Getting Started

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Mobile-IoT-Security-Lab/LLMObfuscDetection.git
   cd LLMObfuscDetection
   ```

2. **Choose Your Path**:
   - To experiment with LLM-based detection, navigate to `LLMObfuscatorDetector/` and install the required Python dependencies.
   - To run traditional SAST tools on the dataset, navigate to `GroundTruthDataset & SAST Tools/docker-tools/` and start the Docker environment.

---

## 🤝 Contributing

We welcome contributions to both the dataset and the tool suite! If you have new APKs to add, improvements to the analysis scripts, or new prompt engineering strategies for the LLM detector, please open a Pull Request.

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for more information.
