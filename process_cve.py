import json
from datetime import datetime
import glob
import csv

from process_common import extract_assigner, extract_ref_dom, extract_cpe, LA_post


def extract_cve(d, refs, cpes, cisa):

    cnt = 0
    for cve in d["CVE_Items"]:
        cve_id = cve["cve"]["CVE_data_meta"]["ID"]

        # Extract assigners
        assigner_mail = cve["cve"]["CVE_data_meta"]["ASSIGNER"].lower()
        assigner_user, assigner_tld = extract_assigner(assigner_mail)

        if len(cve["cve"]["problemtype"]["problemtype_data"][0]["description"]) > 0:
            type = cve["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]
        else:
            type = ""

        publishedDate = cve["publishedDate"]
        lastModifiedDate = cve["lastModifiedDate"]

        # Severity metrics
        v2BaseScore = 0
        v2BaseSeverity = ""
        v3BaseScore = 0
        v3BaseSeverity = ""
        if "baseMetricV3" in cve["impact"].keys():
            v3BaseScore = cve["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            v3BaseSeverity = cve["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
        if "baseMetricV2" in cve["impact"].keys():
            v2BaseScore = cve["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
            v2BaseSeverity = cve["impact"]["baseMetricV2"]["severity"]

        # References
        ref_cnt = 0
        aRefTypes = ["Vendor Advisory", "Patch", "Mitigation", "Release Notes", "Exploit"]
        aref_data = cve["cve"]["references"]["reference_data"]
        for rd in aref_data:
            dom, _ = extract_ref_dom(rd["url"])

            for tag in rd["tags"]:
                if tag in aRefTypes:
                    refs.append({
                        "type" : "ref",
                        "cve_id" : cve_id, 
                        "assigner" : assigner_tld,
                        "type" : type,
                        "publishedDate" : publishedDate,
                        "lastModifiedDate" : lastModifiedDate,
                        "v2BaseScore" : v2BaseScore,
                        "v2BaseSeverity" : v2BaseSeverity,
                        "v3BaseScore" : v3BaseScore,
                        "v3BaseSeverity" : v3BaseSeverity,
                        "exploitDate" : "",
                        "refCnt" : ref_cnt,
                        "refSource" : dom,
                        "tag" : tag
                    })
                    ref_cnt += 1

        # Add CISA references if any
        if cve_id in cisa.keys():
            refs.append({
                "type" : "ref",
                "cve_id" : cve_id, 
                "assigner" : assigner_tld,
                "type" : type,
                "publishedDate" : publishedDate,
                "lastModifiedDate" : lastModifiedDate,
                "v2BaseScore" : v2BaseScore,
                "v2BaseSeverity" : v2BaseSeverity,
                "v3BaseScore" : v3BaseScore,
                "v3BaseSeverity" : v3BaseSeverity,
                "exploitDate" : cisa[cve_id],
                "refCnt" : ref_cnt,
                "refSource" : "CISA",
                "tag" : "Exploit"
            })
            ref_cnt += 1




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


        cpe_cnt = 0
        for cpe_vendor in cpe_vendors:
            cpes.append({
                "type" : "CPE",
                "cve_id" : cve_id, 
                "assigner" : assigner_tld,
                "type" : type,
                "publishedDate" : publishedDate,
                "lastModifiedDate" : lastModifiedDate,
                "v2BaseScore" : v2BaseScore,
                "v2BaseSeverity" : v2BaseSeverity,
                "v3BaseScore" : v3BaseScore,
                "v3BaseSeverity" : v3BaseSeverity,
                "cpeCnt" : cpe_cnt,
                "cpeVendor" : cpe_vendor
            })
            cpe_cnt += 1



        cnt += 1
        # if cnt > 10:
        #     break

    return refs, cpes


def export_csv(d, filename):
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, d[0].keys())
        f.write("#")
        w.writeheader()
        for r in d:
            w.writerow(r)

refs = []
cpes = []


# Load CISA
cisa = {}
with open('cisa_known_exploited_vulnerabilities.csv', newline='') as csvfile:
    cvsreader = csv.reader(csvfile, delimiter=',')
    for row in cvsreader:
        cisa[row[0]] = row[4]
#print(json.dumps(cisa, indent=2))


files = glob.glob("data/*.json") 
#files = ["data/nvdcve-1.1-2021.json"]
#files = ["data/nvdcve-1.1-2019.json"]

for file in files:
    # Otvori originalnu CVE bazu
    print("Processing: ", file)
    f = open(file, encoding="utf8")
    d = json.load(f)
    f.close()

    refs, cpes = extract_cve(d, refs, cpes, cisa)



print("\nrefs:")
#print(refs)
#print(json.dumps(refs, indent=2))
export_csv(refs, "cve_references.csv")
#LA_post(refs)

print("\ncpes:")
#print(cpes)
#print(json.dumps(cpes, indent=2))
export_csv(cpes, "cve_CPEs.csv")
#LA_post(cpes)



