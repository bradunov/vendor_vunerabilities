import json
from datetime import datetime
import glob
import csv

from process_common import extract_assigner, extract_ref_dom, extract_cpe
# !! in process_common check the list of tlds - added some missing

def extract_all(d, C, NC, DEBUG, cisa, vendors, file_exploits):

    cnt = 0
    Ccnt = 0
    Ncnt = 0
    Debug_inCISA_notimpcnt = 0
    Debug_inCISA_notinVendorscnt = 0
    Debug_VA_notimpcnt = 0
    Debug_VA_notfndcnt = 0
    Debug_notin_assignerscnt = 0

    # For every CVE from json (?) do:
    for cve in d["CVE_Items"]:
        cve_id = cve["cve"]["CVE_data_meta"]["ID"]

        new_ref = {"cve_id" : cve_id}

        #set default value
        new_ref["isCISA"] = False
        new_ref["CISAExploitDate"] = None
        new_ref["CISAVendorProject"] = None

        # Add CISA references if any - if cve_id is in cisa xls
        if cve_id in cisa.keys():
            new_ref["isCISA"] = True
            new_ref["CISAExploitDate"] = cisa[cve_id]["dateAdded"]
            new_ref["CISAVendorProject"] = cisa[cve_id]["vendorProject"]

        # Extract assigners (e.g. security@android.com) za svaki json unos
        assigner_mail = cve["cve"]["CVE_data_meta"]["ASSIGNER"].lower()
        _assigner_user, new_ref["assigner_tld"] = extract_assigner(assigner_mail)

        # Extract CWE - Example: NVD-CWE-noinfo
        if len(cve["cve"]["problemtype"]["problemtype_data"][0]["description"]) > 0:
            new_ref["type"] = cve["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]
        else:
            new_ref["type"] = ""

        #record date published and modified
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
        #define ref types we are interested in, and read values (URLs)
        aRefTypes = ["Vendor Advisory", "Patch", "Mitigation", "Release Notes", "Exploit"]
        aref_data = cve["cve"]["references"]["reference_data"]

        #for each CVE now record type of tag, and value of the extracted domain (vendor)
        new_ref["tags"] = []

        foundVendorAdv = []
        for rd in aref_data:
            dom, long_dom = extract_ref_dom(rd["url"])

            for tag in rd["tags"]:
                if tag in aRefTypes:
                    if tag == "Vendor Advisory":
                        if not dom in foundVendorAdv:
                            foundVendorAdv.append(dom)
                    new_ref["tags"].append({
                        "tag" : tag,
                        "refSource" : dom,
                        "refSourceLong" : long_dom
                    })

        if len(foundVendorAdv) > 1:
            new_ref["multipleTags"] = foundVendorAdv
        else:
            new_ref["multipleTags"] = []


        # Read CPE vendor from CVEs: Recursively go through CPEs
        def rec(nodes, cpe_vendors, cpe_vendor_product):
            for n in nodes:
                for k,v in n.items():
                    if k == "children":
                        cpe_vendors, cpe_vendor_product = rec(v, cpe_vendors, cpe_vendor_product)
                    elif k == "cpe_match":
                        for cm in v:
                            if cm["vulnerable"]:
                                vendor, product, version = extract_cpe(cm["cpe23Uri"])
                                cpe_vendors.add(vendor)
                                cpe_vendor_product.add(vendor+"_"+product)

            return cpe_vendors, cpe_vendor_product


        # CPEs (one entry per CPE vendor): vendor and vendor product
        cpe_vendors = set()
        cpe_vendor_product = set()
        cpe_vendors, cpe_vendor_product = rec(cve["configurations"]["nodes"], cpe_vendors, cpe_vendor_product)

        new_ref["cpe_vendors"] = cpe_vendors
        new_ref["cpe_vendor_product"] = cpe_vendor_product



        # Creating set C:
        # for each CVE that has 'isCISA' field active:
        if new_ref["isCISA"]:

            # .get fatches value of CISA vendor name from CISA file
            # v becomes a value from Vendors.xls providing its KEV name field is same as the fatched CISA vendor name
            # (ie: if CISA name exists among KEV, v gets Vendor.xls for that KEV name, otherwise it returns 0)
            v = vendors["KEV name"].get(new_ref["CISAVendorProject"].strip().lower())
            # if v<>0 then we record from Vendors.xls: Kev Name, Name, important
            if v:
                new_ref["CISAKEVName"] = v["KEV name"]
                new_ref["CISAVendorNAME"] = v["NAME"]
                new_ref["CISAVendorImportant"] = v["IMPORTANT"]


                if new_ref["CISAVendorImportant"] == "1":

                    ### Confounding variables

                    #industry(vi) = Vendor.xls -> column J ’Industrial’ for vendor.vend.name(vi)==vendor.kev(vi) 
                    new_ref["CF_Industry"] = v["Industrial"].strip().lower()
                    #os(vi) = Vendor.xls -> column I ‘isOpenSource’ for vendor.vend.name(vi)==vendor.kev(vi) 
                    new_ref["CF_isOSS"] = v["isOpenSource"].strip().lower() == "1"

                    new_ref["CF_CVSS"] = new_ref["v3BaseScore"]
                    new_ref["CF_POC"] = False

                    # poc.nvd(vi) = 1 if CVE	.json file -> references:reference_data:tag==’exploit’ (not CISA), else =0 
                    contains_explot = any(item.get('tag').lower() == 'exploit' for item in new_ref["tags"])
                    # poc.edb(vi) = 1 if CVE(vi)∈EDB database, else =0 
                    contains_explot = contains_explot or cve_id in file_exploits.keys()
                    if contains_explot:
                        new_ref["CF_POC"] = True

                    # patch(vi) =1  (if in CISA) 
                    new_ref["CF_PATCH"] = True

                    #supplychaincnt(vi) = CVE.json file -> CPE count 
                    new_ref["CF_SUP_CHAIN"] = len(new_ref["cpe_vendors"])
                    new_ref["CF_SUP_CHAIN_PROD"] = len(new_ref["cpe_vendor_product"])



                    ### Risk factors

                    # psirt(vi)= Vendor.xls -> column AA ‘isPSIRT’ 
                    # vadvisory(vi)= Vendor.xls -> column AF ‘Advisory’ 
                    # vdpolicy(vi)= Vendor.xls -> column AG ‘VulnDiscPolicy’ 
                    # contact(vi)= Vendor.xls -> column AH ‘Contact’ 
                    # bugbounty(vi)= Vendor.xls -> column AI ‘BugBounty2’ 

                    new_ref["GP_psirt"] = v["isPSIRT"]
                    new_ref["GP_vadvisory"] = v["Advisory"]
                    new_ref["GP_vdpolicy"] = v["VulnDiscPolicy"]
                    new_ref["GP_contact"] = v["Contact"]
                    new_ref["GP_bugbounty"] = v["BugBounty2"]



                    C.append(new_ref)
                    Ccnt += 1
                else:
                    DEBUG["Debug_inCISA_notimp"].append(new_ref)
                    Debug_inCISA_notimpcnt += 1
            else:
                DEBUG["Debug_inCISA_notinVendors"].append(new_ref)
                Debug_inCISA_notinVendorscnt += 1
        else:
        #Creating set NC
            # capturing cf(patch)
            # if CVE.json -> references:reference_data:tag == ‘patch’ OR ‘mitigation’ OR ‘release note’ OR ‘vendor advisory’ OR ‘third party advisory’,  
            # then patch(cvi) = CVE.json -> references:reference_data:tag  
            patch = any(item.get('tag').lower() == 'patch' for item in new_ref["tags"]) or \
                any(item.get('tag').lower() == 'mitigation' for item in new_ref["tags"]) or \
                any(item.get('tag').lower() == 'release notes' for item in new_ref["tags"]) or \
                any(item.get('tag').lower() == 'vendor advisory' for item in new_ref["tags"]) or \
                any(item.get('tag').lower() == 'third party advisory' for item in new_ref["tags"])
            
            if not patch:
                continue
            else: 
                new_ref["PATCH"] = True


            # CAPTURING VENDOR NAME

            # 1) Per Vendor Advisory:

            # starting with vendor advisory:
            # reading the tags, and for each tag that is ='vendor adv' read extracted domain from ref
            # /if vendor.nvd.vadv (cvi) ∈ {Vendors.xls column AB ‘VendorAdv’ field} /
            # here: vendor_adv becomes the url from ref source 
            vendor = None
            vendor_adv = None
            for item in new_ref["tags"]:
                if item.get('tag').lower() == 'vendor advisory':
                    vendor_adv = item.get('refSource')
            
                    v = vendors["advisory"].get(vendor_adv.strip().lower())
     
                    # v gets the value of the stripped url from refsource for the field where it matches with field AB in Vendors.xls
                    # otherwise it becomes 0 (ie when there is no match = not in the Vendors.xls)

                    # if v<>0 then if it is important we record from Vendors.xls: extracted vendavd domain, Name, important;
                    # else we pring a debug for those in but not important
                    if v:
                        if v["IMPORTANT"] == "1":
                            vendor = v
                            new_ref["VendorAdv"] = vendor_adv
                            new_ref["VendorImportant"] = v["IMPORTANT"]
                            new_ref["VendorNAME"] = v["NAME"]
                        else:
                            # ova dva ispod dodata da bi debug lista imala info koji mi trebaju
                            new_ref["VendorAdv"] = vendor_adv
                            new_ref["VendorNAME"] = v["NAME"]
                            new_ref["VendorImportant"] = v["IMPORTANT"]
                            DEBUG["Debug_VA_notimp"].append(new_ref)
                            Debug_VA_notimpcnt += 1
                    else:
                        DEBUG["Debug_VA_notfnd"].append(new_ref)
                        Debug_VA_notfndcnt += 1

                    if vendor:
                        break


            # !!  ubaciti ND0: print if vend_adv<>0 but not in Vendors (dakle korak ispred 'Important')

            # 2) Per Vendor Advisory:

            # vend<>0 if recognising from extracting vendor advisory succeeded (it became v above);
            # otherwise v is  still None and we proceed with finding the assigner
            if not vendor:
                # reading assigner and checking vendor per assigner name
                # vendor.nvd.assigner(cvi) = CVE.JSON field cve:CVE_data_meta:ASSIGNER  
                assigner = cve["cve"]["CVE_data_meta"]["ASSIGNER"]

                # Extract assigners (e.g. security@android.com) za svaki json unos
                assignertld = None
                _assigner_user, assignertld = extract_assigner(assigner)

                # if vendor.nvd.assigner(cvi) ∈ {Vendors.xls Column X ‘assigner’ field}, else print for debug
                # v gets the value of 'assigner' field from json if it matches the 'assigner' field in vendors (ie Vendors.xls)
                                
                v = vendors["assigner"].get(assignertld.strip().lower())

                # !! Ovde iznad je postojao problem: poredio je vendors.assigner sa assigner iz json u neskracenoj formi
                # umesto toga stavljamo da proverava u skracenoj formi - zato ide assignertld.strip a ne assigner.strip


                # if assigner value is not 0, then read Important, name and assigner from Vendors.xls; else mark that assigner
                if v:
                    vendor = v
                    new_ref["VendorAssigner"] = assignertld
                    new_ref["VendorImportant"] = v["IMPORTANT"]
                    new_ref["VendorNAME"] = v["NAME"]
                else:  
                    DEBUG["Debug_notin_assigners"].append(new_ref)
                    Debug_notin_assignerscnt += 1

            # 3) Per CPE:

            # if vendor is not among assigners either, then extract from CPE:
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


            # if vendor is recognised, then read cf and gp, else skip
            if vendor:

                # Add missing fields
                if "VendorAdv" not in new_ref.keys():
                    new_ref["VendorAdv"] = ""
                if "VendorAssigner" not in new_ref.keys():
                    new_ref["VendorAssigner"] = ""
                if "VendorCPE" not in new_ref.keys():
                    new_ref["VendorCPE"] = ""


                ### Confounding variables

                #industry(vi) = Vendor.xls -> column J ’Industrial’ for vendor.vend.name(vi)==vendor.kev(vi) 
                new_ref["CF_Industry"] = vendor["Industrial"].strip().lower()
                #os(vi) = Vendor.xls -> column I ‘isOpenSource’ for vendor.vend.name(vi)==vendor.kev(vi) 
                new_ref["CF_isOSS"] = vendor["isOpenSource"].strip().lower() == "1"

                new_ref["CF_CVSS"] = new_ref["v3BaseScore"]
                new_ref["CF_POC"] = False

                # poc.nvd(vi) = 1 if CVE	.json file -> references:reference_data:tag==’exploit’ (not CISA), else =0 
                contains_explot = any(item.get('tag').lower() == 'exploit' for item in new_ref["tags"])
                # poc.edb(vi) = 1 if CVE(vi)∈EDB database, else =0 
                contains_explot = contains_explot or cve_id in file_exploits.keys()
                if contains_explot:
                    new_ref["CF_POC"] = True

                # patch(vi) =1  (if in CISA) 
                new_ref["CF_PATCH"] = True

                #supplychaincnt(vi) = CVE.json file -> CPE count 
                new_ref["CF_SUP_CHAIN"] = len(new_ref["cpe_vendors"])
                new_ref["CF_SUP_CHAIN_PROD"] = len(new_ref["cpe_vendor_product"])


                ### Risk factors

                # psirt(vi)= Vendor.xls -> column AA ‘isPSIRT’ 
                # vadvisory(vi)= Vendor.xls -> column AF ‘Advisory’ 
                # vdpolicy(vi)= Vendor.xls -> column AG ‘VulnDiscPolicy’ 
                # contact(vi)= Vendor.xls -> column AH ‘Contact’ 
                # bugbounty(vi)= Vendor.xls -> column AI ‘BugBounty2’ 
                new_ref["GP_psirt"] = vendor["isPSIRT"]
                new_ref["GP_vadvisory"] = vendor["Advisory"]
                new_ref["GP_vdpolicy"] = vendor["VulnDiscPolicy"]
                new_ref["GP_contact"] = vendor["Contact"]
                new_ref["GP_bugbounty"] = vendor["BugBounty2"]



                NC.append(new_ref)
                Ncnt += 1


        cnt += 1

        # DEBUG
        # if Ncnt > 5:
        #     break

    print(f"Stats - no. entries (total CVE, C, NC, Debug files): {cnt} {Ccnt} {Ncnt} {Debug_inCISA_notimpcnt} {Debug_inCISA_notinVendorscnt} {Debug_VA_notimpcnt} {Debug_VA_notfndcnt} {Debug_notin_assignerscnt}")

    return C, NC, DEBUG

# izbacuje fajlove: C, NC, i sve Debug - sa brojem unosa u svakom
def export_csv(d, filename):
    if len(d) == 0:
        print(f"File {filename} empty")
        return
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        print(f"Exporting {filename} with {len(d)} entries")


        w = csv.DictWriter(f, d[0].keys())
        f.write("#")
        w.writeheader()
        for r in d:
            w.writerow(r)






if __name__ == "__main__":

    # Load EDB (exploits)
    file_exploits = {}
    with open('files_exploits.csv', encoding="utf8", newline='') as csvfile:
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
    print(f"Total exploits: {len(file_exploits)}")
    #print(json.dumps(file_exploits, indent=2))



    # Load CISA
    cisa = {}
    with open('cisa_known_exploited_vulnerabilities.csv', encoding="utf8", newline='') as csvfile:
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
    print(f"Total CISA: {len(cisa)}")


    # Load Vendors
    vendors = {
        "KEV name": {},
        "advisory": {},
        "assigner": {},
        "cpe": {}
    }
    with open('Vendors.csv', encoding="utf8", newline='') as csvfile:
        cvsreader = csv.reader(csvfile, delimiter=',')
        cnt = 0
        for row in cvsreader:
            if cnt > 0:
                v = {}
                for i in range(len(row)):
                    v[head[i]] = row[i]
                # ?? sta radi ovo 'head' iznad?
                # DEBUG   sta je  -1 ispod?
                if v["KEV name"].find(",") != -1:
                    print("Vendors DEBUG:", v)
                # ?? sta radi ovo ispod?
                vendors["KEV name"][v["KEV name"].strip().lower()] = v
                vendors["advisory"][v["VendorAdv"].strip().lower()] = v
                vendors["assigner"][v["assigner"].strip().lower()] = v
                vendors["cpe"][v["CPE"].strip().lower()] = v
            else:
                head = row
                head[0] = "NAME"
            cnt += 1
    #print(json.dumps(vendors, indent=2))
    print(f"Total vendors (KEV name, advisory, assigner, cpe): {len(vendors['KEV name'])}/{len(vendors['advisory'])}/{len(vendors['assigner'])}/{len(vendors['cpe'])}")

    C = []
    NC = []
    DEBUG = {
        "Debug_inCISA_notimp" : [],
        "Debug_inCISA_notinVendors" : [],
        "Debug_VA_notimp" : [],
        "Debug_VA_notfnd" : [],
        "Debug_notin_assigners" : []
    }

    files = glob.glob("data/*.json") 
    #files = ["data/nvdcve-1.1-2020.json"]
    #files = ["data/nvdcve-1.1-2021.json"]
    #files = ["data/nvdcve-1.1-2022.json"]
    #files = ["data/nvdcve-1.1-2023.json"]

    for file in files:
        # Otvori originalnu CVE bazu
        print("Processing: ", file)
        f = open(file, encoding="utf8")
        d = json.load(f)
        f.close()
        print("CVEs:", len(d))
        # ?? sta je ovaj print? izbacuje CVEs: 6 za sve json fajlove
        C, NC, DEBUG = extract_all(d, C, NC, DEBUG, cisa, vendors, file_exploits)



    print("\nStore:")
    #print(C)
    #print(json.dumps(refs, indent=2))
    export_csv(C, "C.csv")
    export_csv(NC, "NC.csv")
    export_csv(DEBUG["Debug_inCISA_notimp"], "Debug_inCISA_notimp.csv")
    export_csv(DEBUG["Debug_inCISA_notinVendors"], "Debug_inCISA_notinVendors.csv")
    export_csv(DEBUG["Debug_VA_notimp"], "Debug_VA_notimp.csv")
    export_csv(DEBUG["Debug_VA_notfnd"], "Debug_VA_notfnd.csv")
    export_csv(DEBUG["Debug_notin_assigners"], "Debug_notin_assigners.csv")




