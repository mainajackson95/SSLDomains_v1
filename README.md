### **SSLDomains_v1 - SSL Certificate Domain Extractor**  

**SSLDomains_v1** is a powerful tool designed for security researchers, penetration testers, and network analysts to extract domain names from SSL/TLS certificates within a given IP range. The tool scans target IPs, retrieves SSL certificates, and extracts both the **Common Name (CN)** and **Subject Alternative Names (SANs)**. Additionally, it performs HTTP(S) status checks on the extracted domains to identify active hosts.  

---

### **🔹 Features**  
✅ **Extracts SSL Certificate Data** – Retrieves and parses SSL/TLS certificates from live hosts.  
✅ **Supports Subject Alternative Names (SANs)** – Detects all associated domains in the certificate.  
✅ **Automated HTTPS Checks** – Verifies the accessibility of extracted domains.  
✅ **Customizable IP Range Scanning** – Allows users to define IP blocks for scanning.  
✅ **Optimized Performance** – Includes request throttling to evade WAF detections.  
✅ **CSV Logging** – Saves results with IP, domain, status code, and response headers.  

---

### **🔹 Installation**  
To install the required dependencies, run the `install_requirements.py` script:  
```bash
python install_requirements.py
```
This will automatically install the following required packages:  
- **pyOpenSSL**  
- **requests**  
- **urllib3**  
- **ipaddress**  

Alternatively, you can install them manually:  
```bash
pip install pyOpenSSL requests urllib3 ipaddress
```

---

### **🔹 Usage**  
Run the script and provide an IP block when prompted:  
```bash
python SSLDomains_v1.py
```
Follow the on-screen instructions to input the IP range (e.g., `192.168.1.`), and the tool will scan IPs from `192.168.1.1` to `192.168.1.255`.  

---

### **🔹 Output Format**  
Results are saved in `domains.csv` with the following format:  
```
IP | Host | Status Code | Headers
```

---

### **🔹 Use Cases**  
- **Bug Bounty & Pentesting** – Identify hidden subdomains associated with SSL certificates.  
- **Network Reconnaissance** – Map domains hosted on a given IP range.  
- **Security Research** – Analyze SSL/TLS certificate configurations for potential weaknesses.  

---

### **🔹 Disclaimer**  
This tool is intended for **ethical** and **legal security testing** only. Unauthorized scanning may violate terms of service or local laws. **Use responsibly.** 🚀  

---
