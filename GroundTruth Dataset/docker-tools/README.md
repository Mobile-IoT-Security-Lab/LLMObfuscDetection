# 🧬 APK Analyzer Suite

A comprehensive, Dockerized environment for automated Android application analysis, focusing on security research and obfuscation detection. This suite integrates industry-standard tools to provide deep insights into APK behavior, structure, and potential vulnerabilities.

---

## 🚀 Overview

The **APK Analyzer Suite** is designed to streamline the process of reverse engineering and security auditing for Android applications. By leveraging a multi-tool approach, it captures a wide range of data, from static code analysis to resource deobfuscation.

## ✨ Key Features

This suite integrates the following powerful tools:

*   **[Trueseeing](https://github.com/alterakey/trueseeing)**: A fast, multi-threaded APK analysis tool for finding vulnerabilities and inconsistencies.
*   **[APKHunt](https://github.com/Cyber-99/APKHunt)**: A comprehensive static analysis tool for Android apps (SAST for APKs).
*   **[SEBASTiAn](https://github.com/TalosSec/sebastian)**: Advanced deobfuscation and resource analysis.
*   **[JADX](https://github.com/skylot/jadx)**: Dex to Java decompiler.
*   **[dex2jar](https://github.com/pxb1988/dex2jar)**: Tools to work with Android .dex and Java .class files.

---

## 🛠️ Getting Started

### Prerequisites

*   [Docker](https://docs.docker.com/get-docker/)
*   [Docker Compose](https://docs.docker.com/compose/install/)

### Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/luca959/LLMObfuscDataSet.git
    cd LLMObfuscDataSet/docker-tools
    ```

2.  Build and start the environment:
    ```bash
    docker compose up -d
    ```

---

## 📖 Usage

### 1. Prepare APKs
Place the APK files you wish to analyze in the `apks/` directory:
```bash
cp /path/to/my_app.apk ./apks/
```

### 2. Run Analysis
Execute the analysis script inside the `analyzer` container:
```bash
docker compose exec analyzer /app/RunningScript.sh
```

## 📊 Results & Output

All analysis reports and artifacts are stored in the `results/` directory:

*   **`results/SEBASTiAn/`**: JSON, TXT, and PDF reports from SEBASTiAn.
*   **`results/APKHunt/`**: Detailed findings from APKHunt.
*   **`results/Trueseeing/`**: JSON reports from Trueseeing analysis.
*   **`results/results.csv`**: A consolidated summary of all analyzed APKs.

---

## 📂 Project Structure

```text
docker-tools/
├── APKHunt/          # APKHunt tool binaries/scripts
├── apks/             # Folder for input APKs
├── results/          # Folder for output reports
├── Dockerfile        # Environment configuration
├── docker-compose.yml # Service orchestration
├── RunningScript.sh  # Main analysis orchestrator
├── AddToCSV.py       # Result consolidation script
└── ToolParser.py     # Log and report parser
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an issue for any bugs or feature requests.

## 📄 License

This project is licensed under the MIT License - see the `LICENSE` file for details (if applicable).
