# Network Log Anomaly Annotation Tool (Tkinter GUI)

A Python-based implementation of a **Human-in-the-Loop Data Annotation Pipeline** designed for Cybersecurity Analytics. Submitted as the final practical course project at NIELIT.

## 📌 Project Concept
Machine Learning models used in Security Operations Centers (SOCs) require highly accurate ground-truth datasets to identify active cyber threats. This project bridges data annotation fundamentals with threat hunting by turning unstructured firewall logs into a clean, binary-labeled training set for network intrusion detection systems (IDS).

## 🔬 Core Components
1. **Data Synthesizer (`Data_Generator.py`):** Programmatically constructs mock network flows, injecting known indicators of compromise (IoC) such as anomalous data volumes and insecure administration ports.
2. **Interactive Desktop GUI (`labeler.py`):** A custom Tkinter application enforcing strict data schema rules, processing column metadata, and eliminating case-sensitivity issues during human validation.

## 🎯 Annotation Schema & Rules
The analyst labels data based on specific Indicators of Compromise (IoC):
* **Label 0 (Normal):** Routine web or internal traffic on standard ports with standard payload sizes.
* **Label 1 (Anomaly):** Security threats indicated by non-standard port activity (e.g., SSH port 22 probing, reverse-shell port 4444) or extreme data transfers indicating potential data exfiltration.

## 🚀 How to Run the Project
1. **Install Dependencies:**
   Ensure you have `pandas` installed in your Python environment:
   ```bash
   pip install -r requirements.txt
   ```
2. **Step 1: Generate Raw Dataset**
   Run the data generator to build the unannotated firewall log file (`raw_network_logs.csv`):
   ```bash
   python Data_Generator.py
   ```
3. **Step 2: Launch the GUI Annotation App**
   Run the interactive interface to manually audit, label, and tag the network threats:
   ```bash
   python labeler.py
   ```
4. **Output:** The application dynamically compiles your inputs and exports a clean, ready-to-train model dataset named `final_annotated_security_logs.csv`.
