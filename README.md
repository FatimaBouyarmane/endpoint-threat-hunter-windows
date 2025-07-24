# Endpoint Threat Hunter for Windows

## Setup

1. Install Python 3.8+  
2. Install dependencies: `pip install -r requirements.txt`  
3. Get AbuseIPDB API key from https://www.abuseipdb.com/  
4. Set API key in `config.yaml`

## Run

```bash
python main.py


---

# How to use?

- Run `pip install -r requirements.txt`  
- Add your AbuseIPDB API key in `config.yaml`  
- Run `python main.py` in Windows Powershell or CMD

---

This starter will let you autonomously detect brute force attempts on Windows, enrich data with threat intel, and produce a simple report your team can use immediately.

---

If you want, I can help you extend this with:

- Parsing PowerShell logs  
- Detecting suspicious process creations  
- Parsing scheduled task creations  
- Adding richer report/dashboards

Just ask!
