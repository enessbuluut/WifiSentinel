# WifiSentinel 🚨📡

WifiSentinel is an open-source tool designed to detect, analyze, and provide basic security monitoring of devices and network activities within your local network. It works on both IPv4 and IPv6 networks and offers network visibility through multiple protocol-based scanning methods.

## 🌟 What Has Been Done So Far

- **Network Interface Management:**  
  - The `interface_utils.py` module detects active network interfaces, identifies their types (Ethernet, Wi-Fi, VPN, etc.), and makes them selectable.  
  - Detailed IPv4, IPv6, and MAC address information is collected.

- **ARP Scanner:**  
  - Finds devices on IPv4 networks using the ARP protocol.

- **IPv6 Neighbor Discovery (ND) Scanner:**  
  - Uses the ND protocol to discover devices on IPv6 networks.

- **ICMP Ping Sender and Flood Tool:**  
  - Sends ICMP Echo Request (ping) packets to specified IP addresses.  
  - A simple flood (load) attack simulator that sends high volumes of ping packets using multithreading.

- **TCP SYN Scanner (Planned):**  
  - Will scan target machines using TCP SYN packets for port scanning.

## 🛠️ Technical Features (For Now)

- Developed in Python.
- Cross-platform support (Windows, Linux, macOS).
- Modular structure allows adding new scanning techniques.
- User-friendly command-line interface.
- Basic DoS-style testing through multithreading.
- Network interface and address information gathered via `psutil` and `socket` libraries.

## 🚧 Future Plans

- Develop advanced and performance-oriented scanning modules in C/C++ or Java.
- Add packet-level analysis and anomaly detection.
- Expand port scanning and vulnerability detection.
- Implement logging, reporting, and automated alert systems.
- GUI integration for better usability.

## 🧩 Project Structure

- `interface/` → Network interface detection and address collection modules  
- `ping_attack/` → ICMP flood and ping sending tools  
- `scanner/` → ARP, ND, and planned TCP SYN scanner modules  
- `nd_test.py` → IPv6 ND scanner test file  
- README.md → Project introduction and usage guide

---

WifiSentinel is primarily designed as an open-source platform for learning, exploration, and basic network security research. It is an ideal starting point for those wanting to discover network devices, understand protocols, and lay the groundwork for advanced security applications.
