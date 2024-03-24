import csv
import json
import argparse
from enum import Enum
import random

# !!! setuj atribut pri aktiviranju koda: -p: attr=psirt, ili -b: attr=bugbounty)

class ComparisonMethod(Enum):
    PCERT = "pcert"
    BUGBOUNTY = "bugbounty"
    OTHER = "other"


def stats(integer_list):
    # Calculate and display the minimum, maximum, median, and average
    minimum = min(integer_list)
    maximum = max(integer_list)
    sorted_list = sorted(integer_list)
    n = len(integer_list)

    # if number of elements is 
    if n % 2 == 0:
        median = (sorted_list[n // 2 - 1] + sorted_list[n // 2]) / 2
    else:
        median = sorted_list[n // 2]

    average = sum(integer_list) / n

    # Calculate and display percentiles (25th, 75th, and any other desired percentiles)
    # ???
    def calculate_percentile(sorted_list, percentile):
        k = (n - 1) * percentile / 100
        f = int(k)
        c = k - f
        if f == n - 1:
            return sorted_list[-1]
        else:
            return sorted_list[f] + c * (sorted_list[f + 1] - sorted_list[f])

    percentile_25 = calculate_percentile(sorted_list, 25)
    percentile_75 = calculate_percentile(sorted_list, 75)

    return minimum, maximum, median, average, percentile_25, percentile_75


def load_data(filename):
    C = []
    with open(filename, newline='') as csvfile:
        cvsreader = csv.reader(csvfile, delimiter=',')
        cnt = 0
        for row in cvsreader:
            if cnt == 0:
                header = row
                header[0] = header[0][1:]
            else:
                c = {}
                for i in range(0, len(row)):
                    c[header[i]] = row[i].strip()
                C.append(c)
            cnt += 1
    # DEBUG
    # print(json.dumps(C, indent=2))
    # exit(0)
    return C



# checking if vendors are same in cvi and svi: if (c[vendor]<>nc[vendor]) return, jer ne smeju biti isti vendori za sample i case
def equal_vendors(c, nc):
    if c["CISAVendorNAME"].strip().lower() == nc["VendorNAME"].strip().lower():
        return True
    else:
        return False


# Similarity function
    # OS: equal (0 or 1) 
    # POC: equal (either in EDB or ‘exploit’ reference tag in NVD) 
    # Industry: equal (per type) 
    # CVSS: "baseScore 3" scope: round() +-1 
    # e.g. 4.3-> 4, similarity: 3-5 
    # Patch: equal (by default) 
    # supplychaincnt: x<10, 10<x<20, 20<x     
    # u zavisnoti od toga da li radimo psirt ili bugbonty, onaj drugi koristimo kao confounding takodje
def similar(c, nc, selected_method):
    # print(f"C: {json.dumps(c, indent=2)}\n")
    # print(f"NC: {json.dumps(nc, indent=2)}\n")
    # print(f"CF_isOSS: {c['CF_isOSS']} {nc['CF_isOSS']}")
    # print(f"CF_Industry: {c['CF_Industry']} {nc['CF_Industry']}")
    # print(f"CF_SUP_CHAIN: {c['CF_SUP_CHAIN']} {nc['CF_SUP_CHAIN']}")
    # print(f"CF_CVSS: {c['CF_CVSS']} {nc['CF_CVSS']}")

    if c["CF_isOSS"] != nc["CF_isOSS"]:
        return False
    if c["CF_POC"] != nc["CF_POC"]:
        return False
    if c["CF_Industry"] != nc["CF_Industry"]:
        return False
    # razlika CVSS treba da nije veca od 1
    if abs(float(c["CF_CVSS"]) - float(nc["CF_CVSS"])) > 1:
        return False
    # ??? treba nam slicnost prema broju: supplychaincnt: x<10, 10<x<20, 20<x
    if int(c["CF_SUP_CHAIN"]) > 1 != int(nc["CF_SUP_CHAIN"]) > 1:
        return False
    #if round(int(c["CF_SUP_CHAIN_PROD"]) / 10) != round(int(nc["CF_SUP_CHAIN_PROD"]) / 10):
    #    return False

    if selected_method == ComparisonMethod.PCERT:
        if c["GP_bugbounty"] != nc["GP_bugbounty"]:
            return False
    elif selected_method == ComparisonMethod.BUGBOUNTY:
        if c["GP_psirt"] != nc["GP_psirt"]:
            return False


    return True



def get_stats(C):
    stats = {
        "CF_isOSS": 0,
        "CF_Industry": 0,
        "CF_POC": 0,
        "CF_SUP_CHAIN_GT": 0,
        "CF_MAX_SUP_CHAIN": 0,
        "CF_SUP_CHAIN_PROD_GT": 0,
        "CF_MAX_SUP_CHAIN_PROD": 0,
        "CF_CVSS_GT_7": 0,
        "GP_psirt": 0,
        "GP_vadvisory": 0,
        "GP_vdpolicy": 0,
        "GP_contact": 0,
        "GP_bugbounty": 0        
    }

    S = []
    SP = []

    # broji koliko je elemenata skupa sa svakom od karaktertika (nije nam mnogo vazno ali je korisno)
    for c in C:
        if c["CF_isOSS"] == "True":
            stats["CF_isOSS"] += 1
        if c["CF_Industry"]:
            stats["CF_Industry"] += 1
        if c["CF_POC"] == "True":
            stats["CF_POC"] += 1
        S.append(int(c["CF_SUP_CHAIN"]))
        SP.append(int(c["CF_SUP_CHAIN_PROD"]))
        if float(c["CF_CVSS"]) > 7:
            stats["CF_CVSS_GT_7"] += 1
        if c["GP_psirt"] == "1":
            stats["GP_psirt"] += 1
        if c["GP_vadvisory"] == "1":
            stats["GP_vadvisory"] += 1
        if c["GP_vdpolicy"] == "1":
            stats["GP_vdpolicy"] += 1
        if c["GP_contact"] == "1":
            stats["GP_contact"] += 1
        if c["GP_bugbounty"] == "1":
            stats["GP_bugbounty"] += 1
    return stats, S, SP




def parse_arguments():
    def validate_options(args):
        if not any(vars(args).values()):
            raise argparse.ArgumentTypeError("At least one option must be selected.")
        return args

    parser = argparse.ArgumentParser(description="Compare entries using different methods.")
    parser.add_argument("-p", "--pcert", action="store_true", help="Use pcert to compare entries.")
    parser.add_argument("-b", "--bugbounty", action="store_true", help="Use bugbounty to compare entries.")
    parser.add_argument("-o", "--other", action="store_true", help="Use other method to compare entries.")
    args = parser.parse_args()
    return validate_options(args)




def save_dict_to_json(dictionary, filename):
    with open(filename, 'w') as json_file:
        json.dump(dictionary, json_file, indent=4)


def save_dict_to_csv(list_of_dicts, filename):
    if not list_of_dicts:
        print("Error: List of dictionaries is empty.")
        return
    fieldnames = list_of_dicts[0].keys()  # Assuming all dictionaries have the same keys
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in list_of_dicts:
            writer.writerow(row)


if __name__ == "__main__":
# sta je ovo iznad?

    args = parse_arguments()
    selected_method = None

    if args.pcert:
        selected_method = ComparisonMethod.PCERT
        print("Using pcert to compare entries.")
    if args.bugbounty:
        selected_method = ComparisonMethod.BUGBOUNTY
        print("Using bugbounty to compare entries.")
    if args.other:
        selected_method = ComparisonMethod.OTHER
        print("Using other method to compare entries.")


    C = load_data("C.csv")
    print(f"Total C: {len(C)}")
    if False:
        print(json.dumps(C, indent=2))
        exit(0)

    NC = load_data("NC.csv")
    print(f"Total NC: {len(NC)}")
    if False:
        print(json.dumps(NC, indent=2))
        exit(0)


    # radi statistiku C i NC
    st, S, SP = get_stats(C)
    print(f"C stats: {json.dumps(st, indent=2)}\n")
    minimum, maximum, median, average, percentile_25, percentile_75 = stats(S)
    print(f"S stats: minimum={minimum} maximum={maximum} median={median} average={average:.2f} percentile_25={percentile_25} percentile_75={percentile_75}\n")
    minimum, maximum, median, average, percentile_25, percentile_75 = stats(SP)
    print(f"SP stats: minimum={minimum} maximum={maximum} median={median} average={average:.2f} percentile_25={percentile_25} percentile_75={percentile_75}\n")
    st, S, SP = get_stats(NC)
    print(f"\nNC stats: {json.dumps(st, indent=2)}\n")
    minimum, maximum, median, average, percentile_25, percentile_75 = stats(S)
    print(f"S stats: minimum={minimum} maximum={maximum} median={median} average={average:.2f} percentile_25={percentile_25} percentile_75={percentile_75}\n")
    minimum, maximum, median, average, percentile_25, percentile_75 = stats(SP)
    print(f"SP stats: minimum={minimum} maximum={maximum} median={median} average={average:.2f} percentile_25={percentile_25} percentile_75={percentile_75}\n")

    # Sampling (proverava similarity cvi i i ncvi, i da nije isti vendor)
    l = []
    NC_log = []
    NC_pairs = []
    #skup = []
    for c in C:
        cnt = 0
        NC_sample = []
        for nc in NC:
            if similar(c, nc, selected_method) and not equal_vendors(c, nc):
                cnt += 1
                NC_sample.append(nc)

        if cnt > 100:
            print(f"{c['cve_id']} {cnt}")
            # !!!
            # izaberi random 1 od njih (zovemo ga s - izabrani parnjak od tog c)
            # upisi u fajl: taj c i izabrani parnjak s
            # napravi skup S sa svim svi (append...)
        l.append(cnt)
        if NC_sample:
            random_element = random.choice(NC_sample)
            NC_pairs.append({
                "cvi" : c,
                "ncvi" : random_element
            })
            NC_log.append({
                "cvi" : c["cve_id"],
                "ncvi" : random_element["cve_id"]
            })
    minimum, maximum, median, average, percentile_25, percentile_75 = stats(l)
    print(f"Similarity stats: minimum={minimum} maximum={maximum} median={median} average={average:.2f} percentile_25={percentile_25} percentile_75={percentile_75}\n")


    # !!!
    # potrebna statistika:
     # attribute = GP_psirt ili GP_bugbounty (setovan pri pokretanju koda)
        # a = broj clanova C za koje je atribut=false {za attr=psirt: ...["GP_psirt"] != "1"; za attr=bugbounty: ...["GP_bugbounty"] != "1"}
        # b = broj clanova S za koje je atribut=false
        # c = broj clanova C za koje je atribut=true {za attr=psirt: ...["GP_psirt"] == "1"; za attr=bugbounty: ...["GP_bugbounty"] == "1"}
        # d = broj clanova S za koje je atribut=true
    # Racunamo:
        # Association 1: if c/a+c < d/b+d
        # Association 2: if a/a+c > b/b+d
        # CER = a/a+b
        # EER = c/c+d
        # ARR = CER - ERR = a/a+b  –  c/c+d
        # RR = EER/CER = c*(a+b) / a*(c+d)
        # RRR = 1 - EER/CER
        # Sensitivity = a/(a + c) 
        # Specificity = d/(b + d)
    a = 0
    b = 0
    c = 0
    d = 0

    if selected_method == ComparisonMethod.PCERT:
        selected_key = "GP_psirt"
    elif selected_method == ComparisonMethod.BUGBOUNTY:
        selected_key = "GP_bugbounty"
    else:
        print("Error: Selected method is not valid.")
        exit(1)

    for cs in NC_pairs:
        cvi = cs["cvi"]
        sample = cs["ncvi"]

        if cvi[selected_key] != "1":
            a += 1
        if sample[selected_key] != "1":
            b += 1
    c = len(NC_pairs) - a
    d = len(NC_pairs) - b
    CER = a/(a+b)
    EER = c/(c+d)
    ARR = CER - EER
    RR = EER/CER
    RRR = 1 - EER/CER
    Sensitivity = a/(a + c)
    Specificity = d/(b + d)
    print(f"a: {a} b: {b} c: {c} d: {d}")
    print(f"Association 1: {c/(a+c) < d/(b+d)}")
    print(f"Association 2: {a/(a+c) > b/(b+d)}")
    print(f"CER: {CER} EER: {EER} ARR: {ARR} RR: {RR} RRR: {RRR} Sensitivity: {Sensitivity} Specificity: {Specificity}")

    save_dict_to_json(NC_pairs, 'NC_pairs.json')
    save_dict_to_csv(NC_log, 'NC_log.csv')



