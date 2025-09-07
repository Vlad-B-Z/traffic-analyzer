# 🚦 Traffic Analyzer

A simple Python project for **network traffic analysis**.  
It demonstrates how cybersecurity specialists can monitor network traffic, detect anomalies, and generate reports.

---

## 🧐 What does this tool do?

1. **Sniff packets in real time**  
   - Captures live network traffic using **Scapy**.  
   - Extracts IP addresses, protocols (TCP/UDP), and ports.  

2. **Analyze PCAP files**  
   - Reads packet capture (`.pcap`) files.  
   - Useful when live sniffing is not possible.  

3. **Generate CSV reports**  
   - `packets.csv` → detailed log of all packets.  
   - `summary.txt` → short summary with top IPs, protocols, and ports.  
   - `top_*.csv` → top 10 lists for IPs, ports, and protocols.  

4. **Visualize results**  
   - Uses **Matplotlib** to generate a simple chart (e.g., top destination ports).  
   - Provides a quick overview of network activity.

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/Vlad-B-Z/traffic-analyzer.git
cd traffic-analyzer

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## ▶️ Usage

### 1. Live Sniff (Linux)
⚠️ Requires `sudo` or Python raw socket capability.

```bash
sudo python3 main.py --iface eth0 --duration 30
```

- `--iface` = network interface (e.g. `eth0`, `wlan0`).  
- `--duration` = capture time in seconds (default = 20).  

### 2. Analyze from PCAP

```bash
python3 main.py --pcap samples/example.pcap
```

### 3. Visualize

```bash
python3 visualize.py out/packets.csv
```

---

## 📂 Output

- `out/packets.csv` — detailed log of all packets.  
- `out/summary.txt` — short summary (protocols, top IPs, top ports).  
- `out/top_*.csv` — top 10 lists for IPs, ports, and protocols.  

---

## 🔑 Permissions

For live sniffing without sudo, grant raw socket capability to Python:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))
```

---

## 🎯 Why is this important in Cybersecurity?

- **Network monitoring** is the first step in detecting attacks, malware, or suspicious activity.  
- By analyzing traffic, we can identify unusual IPs or ports.  
- This tool is a simple demonstration of how cybersecurity specialists start investigating network data.  

---

## 🎥 Demo

👉 Add your screencast link here (YouTube / Google Drive).  

---

## 🛠 Technologies

- [Python 3](https://www.python.org/)  
- [Scapy](https://scapy.net/)  
- [Pandas](https://pandas.pydata.org/)  
- [Matplotlib](https://matplotlib.org/)  

---

## 📜 License

MIT — free to use, modify, and share.
