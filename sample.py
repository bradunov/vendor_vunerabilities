import csv
import json



def stats(integer_list):
    # Calculate and display the minimum, maximum, median, and average
    minimum = min(integer_list)
    maximum = max(integer_list)
    sorted_list = sorted(integer_list)
    n = len(integer_list)

    if n % 2 == 0:
        median = (sorted_list[n // 2 - 1] + sorted_list[n // 2]) / 2
    else:
        median = sorted_list[n // 2]

    average = sum(integer_list) / n

    # Calculate and display percentiles (25th, 75th, and any other desired percentiles)
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
    return C



# CVSS: "baseScore 3" scope: round() +-1 
# e.g. 4.3-> 4, similarity: 3-5 
# POC: equal (either in EDB or ‘exploit’ reference tag in NVD) 
# Patch: equal (by default) 
# Industry: equal (per type) 
# OS: equal (0 or 1) 
# supplychaincnt: x<10, 10<x<20, 20<x     
def similar(c, nc):
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
    if int(c["CF_SUP_CHAIN"]) > 1 != int(nc["CF_SUP_CHAIN"]) > 1:
        return False
    if round(int(c["CF_SUP_CHAIN_PROD"]) / 10) != round(int(nc["CF_SUP_CHAIN_PROD"]) / 10):
        return False
    if abs(float(c["CF_CVSS"]) - float(nc["CF_CVSS"])) > 1:
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




if __name__ == "__main__":

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


    l = []
    for c in C:
        cnt = 0
        for nc in NC:
            if similar(c, nc):
                cnt += 1
        if cnt < 10:
            print(f"{c['cve_id']} {cnt}")
        l.append(cnt)

    minimum, maximum, median, average, percentile_25, percentile_75 = stats(l)

    print(f"Similarity stats: minimum={minimum} maximum={maximum} median={median} average={average:.2f} percentile_25={percentile_25} percentile_75={percentile_75}\n")







