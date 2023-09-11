# Description

This is a toy project to study different vunerabilities. 

Linkovi:
https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv

https://nvd.nist.gov/vuln/data-feeds

https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.json.zip
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.zip
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2022.json.zip
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.zip


https://gitlab.com/exploit-database/exploitdb



## Instructions

Required data files:
- `files_exploits.csv` from exploitdb
- `cisa_known_exploited_vulnerabilities.csv` (only 2020-2023)
- `Vendors.csv`, exported from Vendors.xls
- `nvdcve-1.1-202*.json` in data/ directory (import only json2020-2023)

To run:
- `python3 create_C_NC.py`

Outputs:
- `C.csv`: C set
- `N.csv`: N set
- `Debug*.csv`: various debug outputs with CVEs that need to be checked

