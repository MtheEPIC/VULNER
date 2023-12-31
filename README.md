# VULNER

###  An Automatic Vulnerability Scanner Tool

Identifying vulnerabilities inside the network takes time and should be executed often.
Using automation can help improve the process and identify vulnerabilities before attackers do.

This tool run LAN Reconnaissance and runs a simple Weaponization phase to check for common issues.
**VULNER** Provides An Easy way to alert of possible attack vectors. 
 
## Information
This tool is for educational purpose only, usage for attacking targets without prior mutual consent is illegal.
Developers assume no liability and are not responsible for any misuse or damage cause by this program.

## Features
- Fully Automating host discovery.
- Port Service Scanning using Nmap.
- Using Different DataBases for common CVEs.
- Automatically attempts to connect to found targets.
- Generate report in a text and web format.

# Installation 
Instructions on how to install *VULNER*
```bash
git clone https://github.com/MtheEPIC/VULNER.git
cd VULNER
chmod u+x installer.sh 
sudo ./installer.sh
```
Instructions on how to check if the install was successful
```bash 
sudo ./installer.sh -q
```

# Execution 
Default scanning mode
```bash
chmod u+x vuln.sh 
sudo ./vuln.sh
```
Report Mode 
```bash
chmod u+x vuln.sh 
sudo ./vuln.sh -r IP
```

## Tools Overview
| Scan Mode | Report Mode	|
| ------------  | ------------ |
|![success](https://github.com/MtheEPIC/VULNER/assets/59831504/102cf1a6-4a99-468e-8db5-595aa669dd11)|![report](https://github.com/MtheEPIC/VULNER/assets/59831504/701d2cf3-c2b4-4c5a-87f5-6137baa9d4d9)

## License
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the **License** file for more details.