# Network Recon Dashboard

A powerful, user-friendly web interface for network security auditing. This tool automates the process of scanning networks using Nmap and presents the findings in a clean, professional dashboard.

## 🚀 Features
- **Automated Scanning:** Quick and intense scan profiles to suit your audit needs.
- **Web Interface:** A sleek UI built with Tailwind CSS for easy interaction.
- **Report Generation:** Automatically generates detailed `recon_report.md` files after every scan.
- **Real-time Results:** View live hosts and port analysis directly in your browser.

## 🛠 Prerequisites
- **Python 3.x**
- **Nmap** installed on your system (`sudo apt install nmap`)
- **Flask** (installed via requirements.txt)

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/Network-Recon-Dashboard.git](https://github.com/YOUR_USERNAME/Network-Recon-Dashboard.git)
   cd Network-Recon-Dashboard
2.Setup a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate

3.Install dependencies:

   ```bash
   pip install -r requirements.txt

🖥 Usage
Run the application using the following command:

Bash
sudo .venv/bin/python3 app.py
Then, open your browser and navigate to http://127.0.0.1:5000.

⚠️ Disclaimer
This tool is for educational and authorized security testing purposes only. The developer assumes no liability for any misuse of this tool. Always ensure you have explicit permission before scanning any network.
