import json
from datetime import datetime
import glob

from process_common import extract_assigner, extract_ref_dom, extract_cpe


def extract_vendors(d, assigners, vendor_advisory, patch, mitigation, release_notes, exploit, cpe):

    cnt = 0

    for cve in d["CVE_Items"]:

        # Extract assigners
        assigner_mail = cve["cve"]["CVE_data_meta"]["ASSIGNER"].lower()
        assigner_user, assigner_tld = extract_assigner(assigner_mail)


        if not assigner_mail in assigners.keys():
            assigners[assigner_mail] = {
                "user": assigner_user,
                "tld": assigner_tld
            }



        aref_data = cve["cve"]["references"]["reference_data"]

        def incr_count(d, k, desc):
            if not k in d.keys():
                d[k] = {
                    "desc" : desc.lower(),
                    "cnt" : 0
                }
            d[k]["cnt"] += 1


        for rd in aref_data:
            dom, long_dom = extract_ref_dom(rd["url"])

            is_vendor_advisory = 0
            is_patch = 0
            is_mitigation = 0
            is_release_notes = 0
            is_exploit = 0

            if "Vendor Advisory" in rd["tags"]:
                is_vendor_advisory += 1
            if "Patch" in rd["tags"]:
                is_patch += 1
            if "Mitigation" in rd["tags"]:
                is_mitigation += 1
            if "Release Notes" in rd["tags"]:
                is_release_notes += 1
            if "Exploit" in rd["tags"]:
                is_exploit += 1

            if is_vendor_advisory:
                incr_count(vendor_advisory, dom, long_dom)
            if is_patch:
                incr_count(patch, dom, long_dom)
            if is_mitigation:
                incr_count(mitigation, dom, long_dom)
            if is_release_notes:
                incr_count(release_notes, dom, long_dom)
            if is_exploit:
                incr_count(exploit, dom, long_dom)


        # Recursively go through CPEs
        def rec(nodes, cpe):
            for n in nodes:
                for k,v in n.items():
                    if k == "children":
                        cpe = rec(v, cpe)
                    elif k == "cpe_match":
                        for cm in v:
                            if cm["vulnerable"]:
                                vendor, product, version = extract_cpe(cm["cpe23Uri"])
                                if not vendor in cpe.keys():
                                    cpe[vendor] = {
                                        "cert" : 0,
                                        "cnt" : 0,
                                        "assigner": "",
                                        "vendor_advisory": "",
                                        "patch": "",
                                        "mitigation": "",
                                        "release_notes": "",
                                        "mis_vendor_advisory": set(),
                                        "mis_patch": set(),
                                        "mis_mitigation": set(),
                                        "mis_release_notes": set()
                                    }
                                cpe[vendor]["cnt"] += 1
                                if vendor == assigner_tld:
                                    cpe[vendor]["cert"] = 1

                                for rd in aref_data:
                                    dom, long_dom = extract_ref_dom(rd["url"])

                                    if "Vendor Advisory" in rd["tags"]:
                                        cpe[vendor]["mis_vendor_advisory"].add(dom)
                                    if "Patch" in rd["tags"]:
                                        cpe[vendor]["mis_patch"].add(dom)
                                    if "Mitigation" in rd["tags"]:
                                        cpe[vendor]["mis_mitigation"].add(dom)
                                    if "Release Notes" in rd["tags"]:
                                        cpe[vendor]["mis_release_notes"].add(dom)

            return cpe


        cpe = rec(cve["configurations"]["nodes"], cpe)

        cnt += 1

        #if cnt > 10:
        #    break



    return assigners, vendor_advisory, patch, mitigation, release_notes, exploit, cpe


def export_csv(d, filename):
    cnt = 0
    with open(filename, 'w') as f:
        for k,v in d.items():
            # Print header if needed
            if isinstance(v, dict):
                if cnt == 0:
                    f.write("# key, ")
                    for k in v.keys():
                        f.write(k + ", ")
                    f.write("\n")
                    cnt += 1
            f.write(str(k) + ", ")
            if isinstance(v, dict):
                for k1,v1 in v.items():
                    f.write(str(v1) + ", ")
            else:
                f.write(str(v))
            f.write("\n")



assigners = {}
vendor_advisory = {}
patch = {}
mitigation = {}
release_notes = {}
exploit = {}
cpe = {}


files = glob.glob("data/*.json") 
#files = glob.glob("data/nvdcve-1.1-202?.json") 
#files = ["data/nvdcve-1.1-2021.json"]
#files = glob.glob("data/nvdcve-1.1-2021.json") 

for file in files:
    # Otvori originalnu CVE bazu
    print("Processing: ", file)
    f = open(file)
    d = json.load(f)
    f.close()


    assigners, vendor_advisory, patch, mitigation, release_notes, exploit, cpe = extract_vendors(\
        d, assigners, vendor_advisory, patch, mitigation, release_notes, exploit, cpe)


# Find matching assigner in CPE, if any

assigner_keys = set()
for v in assigners.values():
    assigner_keys.add(v["tld"])

for k in cpe.keys():
    if k in assigner_keys:
        cpe[k]["assigner"] = k
    else:
        cpe[k]["assigner"] = ""
    if k in vendor_advisory.keys():
        cpe[k]["vendor_advisory"] = k
    else:
        cpe[k]["vendor_advisory"] = ""
    if k in patch.keys():
        cpe[k]["patch"] = k
    else:
        cpe[k]["patch"] = ""
    if k in mitigation.keys():
        cpe[k]["mitigation"] = k
    else:
        cpe[k]["mitigation"] = ""
    if k in release_notes.keys():
        cpe[k]["release_notes"] = k
    else:
        cpe[k]["release_notes"] = ""


#print(json.dumps(vendor_arr, indent=2))
#print(json.dumps(vendors, indent=2))


#print(vendor_arr)
print("\nassigners:")
#print(assigners)
#print(json.dumps(assigners, indent=2))
export_csv(assigners, "assigners.csv")

print("\nvendor_advisory:")
#print(vendor_advisory)
#print(json.dumps(vendor_advisory, indent=2))
export_csv(vendor_advisory, "vendor_advisory.csv")

print("\npatch:")
#print(patch)
#print(json.dumps(patch, indent=2))
export_csv(patch, "patch.csv")

print("\nmitigation:")
#print(mitigation)
#print(json.dumps(mitigation, indent=2))
export_csv(mitigation, "mitigation.csv")

print("\nrelease_notes:")
#print(release_notes)
#print(json.dumps(release_notes, indent=2))
export_csv(release_notes, "release_notes.csv")

print("\nexploit:")
#print(exploit)
#print(json.dumps(exploit, indent=2))
export_csv(exploit, "exploit.csv")

print("\ncpe:")
#print(cpe)
#print(json.dumps(cpe, indent=2))
export_csv(cpe, "cpe.csv")







