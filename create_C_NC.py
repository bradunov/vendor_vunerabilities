import json
from datetime import datetime
import glob
import csv

from process_common import extract_assigner, extract_ref_dom, extract_cpe


def extract_all(d, C, NC, DEBUG, cisa, vendors, file_exploits):

    cnt = 0
    Ccnt = 0
    Ncnt = 0
    CD1cnt = 0
    CD2cnt = 0
    ND1cnt = 0
    ND2cnt = 0
    for cve in d["CVE_Items"]:
        cve_id = cve["cve"]["CVE_data_meta"]["ID"]

        new_ref = {"cve_id" : cve_id}

        new_ref["isCISA"] = False
        new_ref["CISAExploitDate"] = None
        new_ref["CISAVendorProject"] = None

        # Add CISA references if any
        if cve_id in cisa.keys():
            new_ref["isCISA"] = True
            new_ref["CISAExploitDate"] = cisa[cve_id]["dateAdded"]
            new_ref["CISAVendorProject"] = cisa[cve_id]["vendorProject"]

        # Extract assigners (e.g. security@android.com)
        assigner_mail = cve["cve"]["CVE_data_meta"]["ASSIGNER"].lower()
        _assigner_user, new_ref["assigner_tld"] = extract_assigner(assigner_mail)

        # Example: NVD-CWE-noinfo
        if len(cve["cve"]["problemtype"]["problemtype_data"][0]["description"]) > 0:
            new_ref["type"] = cve["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]
        else:
            new_ref["type"] = ""

        new_ref["publishedDate"] = cve["publishedDate"]
        new_ref["lastModifiedDate"] = cve["lastModifiedDate"]

        # Severity metrics
        new_ref["v2BaseScore"] = 0
        new_ref["v2BaseSeverity"] = ""
        new_ref["v3BaseScore"] = 0
        new_ref["v3BaseSeverity"] = ""
        if "baseMetricV3" in cve["impact"].keys():
            # Example: 7.8
            new_ref["v3BaseScore"] = cve["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            # Example: HIGH
            new_ref["v3BaseSeverity"] = cve["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
        if "baseMetricV2" in cve["impact"].keys():
            # Example: 7.5
            new_ref["v2BaseScore"] = cve["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
            # Example: HIGH
            new_ref["v2BaseSeverity"] = cve["impact"]["baseMetricV2"]["severity"]

        # References
        ref_cnt = 0
        aRefTypes = ["Vendor Advisory", "Patch", "Mitigation", "Release Notes", "Exploit"]
        aref_data = cve["cve"]["references"]["reference_data"]

        new_ref["tags"] = []

        for rd in aref_data:
            dom, _ = extract_ref_dom(rd["url"])

            for tag in rd["tags"]:
                if tag in aRefTypes:
                    new_ref["tags"].append({
                        "tag" : tag,
                        "refSource" : dom
                    })




        # Recursively go through CPEs
        def rec(nodes, cpe_vendors):
            for n in nodes:
                for k,v in n.items():
                    if k == "children":
                        cpe_vendors = rec(v, cpe_vendors)
                    elif k == "cpe_match":
                        for cm in v:
                            if cm["vulnerable"]:
                                vendor, product, version = extract_cpe(cm["cpe23Uri"])
                                cpe_vendors.add(vendor)

            return cpe_vendors


        # CPEs (one entry per CPE vendor)
        cpe_vendors = set()
        cpe_vendors = rec(cve["configurations"]["nodes"], cpe_vendors)

        new_ref["cpe_vendors"] = cpe_vendors


        if new_ref["isCISA"]:
            v = vendors["KEV name"].get(new_ref["CISAVendorProject"].strip().lower())
            if v:
                new_ref["CISAKEVName"] = v["KEV name"]
                new_ref["CISAVendorNAME"] = v["NAME"]
                new_ref["CISAVendorImportant"] = v["IMPORTANT"]

                #industry(vi) = Vendor.xls -> column J ’Industrial’ for vendor.vend.name(vi)==vendor.kev(vi) 
                new_ref["CISAIndustry"] = v["Industrial"].strip().lower() == "industry"
                #os(vi) = Vendor.xls -> column I ‘isOpenSource’ for vendor.vend.name(vi)==vendor.kev(vi) 
                new_ref["CISAisOSS"] = v["isOpenSource"].strip().lower() == "1"

                # psirt(vi)= Vendor.xls -> column AA ‘isPSIRT’ 
                # vadvisory(vi)= Vendor.xls -> column AF ‘Advisory’ 
                # vdpolicy(vi)= Vendor.xls -> column AG ‘VulnDiscPolicy’ 
                # contact(vi)= Vendor.xls -> column AH ‘Contact’ 
                # bugbounty(vi)= Vendor.xls -> column AI ‘BugBounty2’ 

                new_ref["psirt"] = v["isPSIRT"]
                new_ref["vadvisory"] = v["Advisory"]
                new_ref["vdpolicy"] = v["VulnDiscPolicy"]
                new_ref["contact"] = v["Contact"]
                new_ref["bugbounty"] = v["BugBounty2"]

                if new_ref["CISAVendorImportant"] == "1":
                    new_ref["CVSS"] = new_ref["v3BaseScore"]
                    new_ref["POC"] = False

                    # poc.nvd(vi) = 1 if CVE	.json file -> references:reference_data:tag==’exploit’ (not CISA), else =0 
                    contains_explot = any(item.get('tag').lower() == 'exploit' for item in new_ref["tags"])
                    # poc.edb(vi) = 1 if CVE(vi)∈EDB database, else =0 
                    contains_explot = contains_explot or cve_id in file_exploits.keys()
                    if contains_explot:
                        new_ref["POC"] = True

                    # patch(vi) =1  (if in CISA) 
                    new_ref["PATCH"] = True

                    #supplychaincnt(vi) = CVE.json file -> CPE count 
                    new_ref["SUP_CHAIN"] = new_ref["cpe_vendors"]

                    C.append(new_ref)
                    Ccnt += 1
                else:
                    DEBUG["CD1"].append(new_ref)
                    CD1cnt += 1
            else:
                DEBUG["CD2"].append(new_ref)
                CD2cnt += 1
        else:

            # if CVE.json -> references:reference_data:tag == ‘patch’ OR ‘mitigation’ OR ‘release note’ OR ‘vendor advisory’ OR ‘third party advisory’,  
            # then patch(cvi) = CVE.json -> references:reference_data:tag  
            patch = any(item.get('tag').lower() == 'patch' for item in new_ref["tags"]) or \
                any(item.get('tag').lower() == 'mitigation' for item in new_ref["tags"]) or \
                any(item.get('tag').lower() == 'release notes' for item in new_ref["tags"]) or \
                any(item.get('tag').lower() == 'vendor advisory' for item in new_ref["tags"]) or \
                any(item.get('tag').lower() == 'third party advisory' for item in new_ref["tags"])
            
            # if vendor.nvd.vadv (cvi) ∈ {Vendors.xls column AB ‘VendorAdv’ field} 
            vendor_adv = None
            for item in new_ref["tags"]:
                if item.get('tag').lower() == 'vendor advisory':
                    vendor_adv = item.get('refSource')
                    break
            
            vendor = None
            if vendor_adv:
                v = vendors["advisory"].get(vendor_adv.strip().lower())
                if v:
                    if v["IMPORTANT"] == "1":
                        vendor = v
                        new_ref["VendorAdv"] = vendor_adv
                        new_ref["VendorImportant"] = v["IMPORTANT"]
                        new_ref["VendorNAME"] = v["NAME"]
                    else:
                        DEBUG["ND1"].append(new_ref)
                        ND1cnt += 1


            if not vendor:
                # vendor.nvd.assigner(cvi) = CVE.JSON field cve:CVE_data_meta:ASSIGNER  
                assigner = cve["cve"]["CVE_data_meta"]["ASSIGNER"]

                # if vendor.nvd.assigner(cvi) ∈ {Vendors.xls Column X ‘assigner’ field}
                v = vendors["assigner"].get(assigner.strip().lower())
                if v:
                    vendor = v
                    new_ref["VendorAssigner"] = assigner
                    new_ref["VendorImportant"] = v["IMPORTANT"]
                    new_ref["VendorNAME"] = v["NAME"]

                # Ne razumem sta radim ako nije pronadjen assigner
                # To ce biti previse cesto


            if not vendor:
                #if vendor.nvd.cpe(cvi) ∈ {Vendors.xls -> Colum Y ‘CPE’} 
                for cpev in new_ref["cpe_vendors"]:
                    v = vendors["cpe"].get(cpev.strip().lower())
                    if v:
                        if v["IMPORTANT"] == "1":
                            vendor = v
                            new_ref["VendorCPE"] = v["CPE"]
                            new_ref["VendorImportant"] = v["IMPORTANT"]
                            new_ref["VendorNAME"] = v["NAME"]
                            break


            if vendor:

                #industry(vi) = Vendor.xls -> column J ’Industrial’ for vendor.vend.name(vi)==vendor.kev(vi) 
                new_ref["CISAIndustry"] = vendor["Industrial"].strip().lower() == "industry"
                #os(vi) = Vendor.xls -> column I ‘isOpenSource’ for vendor.vend.name(vi)==vendor.kev(vi) 
                new_ref["CISAisOSS"] = vendor["isOpenSource"].strip().lower() == "1"

                # psirt(vi)= Vendor.xls -> column AA ‘isPSIRT’ 
                # vadvisory(vi)= Vendor.xls -> column AF ‘Advisory’ 
                # vdpolicy(vi)= Vendor.xls -> column AG ‘VulnDiscPolicy’ 
                # contact(vi)= Vendor.xls -> column AH ‘Contact’ 
                # bugbounty(vi)= Vendor.xls -> column AI ‘BugBounty2’ 

                new_ref["psirt"] = vendor["isPSIRT"]
                new_ref["vadvisory"] = vendor["Advisory"]
                new_ref["vdpolicy"] = vendor["VulnDiscPolicy"]
                new_ref["contact"] = vendor["Contact"]
                new_ref["bugbounty"] = vendor["BugBounty2"]

                # Add missing fields
                if "VendorAdv" not in new_ref.keys():
                    new_ref["VendorAdv"] = ""
                if "VendorAssigner" not in new_ref.keys():
                    new_ref["VendorAssigner"] = ""
                if "VendorCPE" not in new_ref.keys():
                    new_ref["VendorCPE"] = ""


                NC.append(new_ref)
                Ncnt += 1




            # debug["ND2"].append(new_ref)
            # ND2cnt += 1

        cnt += 1

        # DEBUG
        # if Ncnt > 5:
        #     break

    print(f"Stats: {cnt} {Ccnt} {Ncnt} {CD1cnt} {CD2cnt} {ND1cnt} {ND2cnt}")

    return C, NC, DEBUG


def export_csv(d, filename):
    if len(d) == 0:
        print(f"File {filename} empty")
        return
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, d[0].keys())
        f.write("#")
        w.writeheader()
        for r in d:
            w.writerow(r)



# Load EDB (exploits)
file_exploits = {}
with open('files_exploits.csv', newline='') as csvfile:
    cvsreader = csv.reader(csvfile, delimiter=',')
    cnt = 0
    for row in cvsreader:
        if cnt > 0:
            # Example (1046): OSVDB-17251;CVE-2005-2236;CVE-2005-2232
            cves = row[11].split(";")
            for cve in cves:
                if cve[0:len("CVE-")] == "CVE-":
                    file_exploits[cve] = row
            
        cnt += 1
#print(json.dumps(file_exploits, indent=2))



# Load CISA
cisa = {}
with open('cisa_known_exploited_vulnerabilities.csv', newline='') as csvfile:
    cvsreader = csv.reader(csvfile, delimiter=',')
    cnt = 0
    for row in cvsreader:
        if cnt > 0:
            cisa[row[0]] = {
                "vendorProject": row[1],
                "dateAdded": row[4]
            }
        cnt += 1
#print(json.dumps(cisa, indent=2))


# Load Vendors
vendors = {
    "KEV name": {},
    "advisory": {},
    "assigner": {},
    "cpe": {}
}
with open('Vendors.csv', newline='') as csvfile:
    cvsreader = csv.reader(csvfile, delimiter=',')
    cnt = 0
    for row in cvsreader:
        if cnt > 0:
            v = {}
            for i in range(len(row)):
                v[head[i]] = row[i]
            #DEBUG
            if v["KEV name"].find(",") != -1:
                print("Vendors DEBUG:", v)
            vendors["KEV name"][v["KEV name"].strip().lower()] = v
            vendors["advisory"][v["VendorAdv"].strip().lower()] = v
            vendors["assigner"][v["assigner"].strip().lower()] = v
            vendors["cpe"][v["CPE"].strip().lower()] = v
        else:
            head = row
            head[0] = "NAME"
        cnt += 1
#print(json.dumps(vendors, indent=2))


C = []
NC = []
DEBUG = {
    "CD1" : [],
    "CD2" : [],
    "ND1" : [],
    "ND2" : []
}

files = glob.glob("data/*.json") 
#files = ["data/nvdcve-1.1-2021.json"]
#files = ["data/nvdcve-1.1-2019.json"]

for file in files:
    # Otvori originalnu CVE bazu
    print("Processing: ", file)
    f = open(file, encoding="utf8")
    d = json.load(f)
    f.close()

    C, NC, DEBUG = extract_all(d, C, NC, DEBUG, cisa, vendors, file_exploits)



print("\nStore:")
#print(C)
#print(json.dumps(refs, indent=2))
export_csv(C, "C.csv")
export_csv(NC, "NC.csv")
export_csv(DEBUG["CD1"], "CD1.csv")
export_csv(DEBUG["CD2"], "CD2.csv")
export_csv(DEBUG["ND1"], "ND1.csv")
export_csv(DEBUG["ND2"], "ND2.csv")



