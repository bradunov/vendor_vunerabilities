# importing module, which are used later:
import csv
import json
import argparse
from enum import Enum
import random
import pandas as pd
import numpy as np
from scipy.stats import chi2_contingency
import os
from sklearn.linear_model import LogisticRegression


# definisemo argumente koji ce se koristiti pri aktiviranju koda (-p: attr=psirt, -b: attr=bugbounty, other-drugo ako bude trebalo)
class ComparisonMethod(Enum):
    PCERT = "pcert"
    BUGBOUNTY = "bugbounty"
    OTHER = "other"

# deinisemo argumente za startovanje koda, i u skladu sa time atribute koji ce da se koriste: 
# -p je PSIRT, 
# -b je Bug bounty, 
# -o je other (mozda ubuduce)
# -i integer broj bootstrap iteracija (default je 10)
def parse_arguments():
    def validate_options(args):
        if not any(vars(args).values()):
            raise argparse.ArgumentTypeError("At least one option must be selected.")
        return args

    parser = argparse.ArgumentParser(description="Compare entries using different methods. Set number of bootstrap iterrations.")
    parser.add_argument("-p", "--pcert", action="store_true", help="Use PSIRT to compare entries.")
    parser.add_argument("-b", "--bugbounty", action="store_true", help="Use bugbounty to compare entries.")
    parser.add_argument("-o", "--other", action="store_true", help="Use other method to compare entries.")
    parser.add_argument("-i", "--iterations", type=int, default=10, help="Number of bootstrap iterations")
    args = parser.parse_args()
    return validate_options(args)


# omogucavamo snimanje dictionary u json
def save_dict_to_json(dictionary, filename):
    with open(filename, 'w') as json_file:
        json.dump(dictionary, json_file, indent=4)

# omogucavamo snimanje dictionary u csv
def save_dict_to_csv(list_of_dicts, filename):
    if not isinstance(list_of_dicts, list) or not all(isinstance(d, dict) for d in list_of_dicts):
        print("Error: Input is not a list of dictionaries.")
        return
    if not list_of_dicts:
        print("Error: List of dictionaries is empty.")
        return
    fieldnames = list_of_dicts[0].keys()  # Assuming all dictionaries have the same keys
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in list_of_dicts:
            writer.writerow(row)


# for median and confidence interval:
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


# broji koliko je elemenata skupa sa svakom od karaktertika (nije nam mnogo vazno ali je korisno)
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

        # za pokretanje u main ako nam treba da radi statistiku C i NC
        # st, S, SP = get_stats(C)
        # print(f"C stats: {json.dumps(st, indent=2)}\n")
        # minimum, maximum, median, average, percentile_25, percentile_75 = stats(S)
        # print(f"S stats: minimum={minimum} maximum={maximum} median={median} average={average:.2f} percentile_25={percentile_25} percentile_75={percentile_75}\n")
        # minimum, maximum, median, average, percentile_25, percentile_75 = stats(SP)
        # print(f"SP stats: minimum={minimum} maximum={maximum} median={median} average={average:.2f} percentile_25={percentile_25} percentile_75={percentile_75}\n")
        # st, S, SP = get_stats(NC)
        # print(f"\nNC stats: {json.dumps(st, indent=2)}\n")
        # minimum, maximum, median, average, percentile_25, percentile_75 = stats(S)
        # print(f"S stats: minimum={minimum} maximum={maximum} median={median} average={average:.2f} percentile_25={percentile_25} percentile_75={percentile_75}\n")
        # minimum, maximum, median, average, percentile_25, percentile_75 = stats(SP)
        # print(f"SP stats: minimum={minimum} maximum={maximum} median={median} average={average:.2f} percentile_25={percentile_25} percentile_75={percentile_75}\n")


# ucitavamo C iz fajla C
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
    # DEBUG primer ako treba:
    # print(json.dumps(C, indent=2))
    # exit(0)
    return C



# checking if vendors are same in cvi and svi: if (c[vendor]<>nc[vendor]) return, 
# jer ne smeju biti isti vendori za sample i case
def equal_vendors(c, nc):
# !! proveri da li je CISAVendorNAME od C isto sto i VendorNAME NC parnjaka
    if c["CISAVendorNAME"].strip().lower() == nc["VendorNAME"].strip().lower():
        return True
    else:
        return False



# Similarity function
def similar(c, nc, selected_method):
    # OS: equal (0 or 1) 
    # POC: equal (either in EDB or ‘exploit’ reference tag in NVD) 
    # Industry: equal (per type) 
    # CVSS: "baseScore 3" scope: round() +-1 
    # e.g. 4.3-> 4, similarity: 3-5 
    # Patch: equal (by default) 
    # supplychaincnt: x<10, 10<x<20, 20<x  - ne za sada   
    # u zavisnoti od 'selected method' - da li radimo psirt ili bugbonty, onaj drugi koristimo kao confounding takodje:

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
    
    # treba nam slicnost prema broju: supplychaincnt: x<10, 10<x<20, 20<x (za sada ne treba)
    # if int(c["CF_SUP_CHAIN"]) > 1 != int(nc["CF_SUP_CHAIN"]) > 1:
    #    return False

    # Supply chain product (za sad nam ne treba):
    # if round(int(c["CF_SUP_CHAIN_PROD"]) / 10) != round(int(nc["CF_SUP_CHAIN_PROD"]) / 10):
    #    return False

    # odabir argumenta za startovanje programa utice na atribute i confounding: 
    # ako se izabere psirt, onda bug bounty ide kao confounding; i obratno
    if selected_method == ComparisonMethod.PCERT:
        if c["GP_bugbounty"] != nc["GP_bugbounty"]:
            return False
    elif selected_method == ComparisonMethod.BUGBOUNTY:
        if c["GP_psirt"] != nc["GP_psirt"]:
            return False

    return True


# prolazimo kroz C, prepoznajemo jedinstvene vendore i brojimo ih, i grupisemo cvi prema vendoru
def C_by_vendors(c):
    total_distinct_names = 0
    name_groups = {}
    # Iterate through the dictionary to collect unique CISAVendorNAME and their corresponding entries
    for entry in c:
        name = entry['CISAVendorNAME'] # extracts the value of "CISAVendorNAME"" attribute from the current entry and assigns it to the variable name
        if name not in name_groups:
            name_groups[name] = [entry]
            total_distinct_names += 1
        else:
            name_groups[name].append(entry)
    return total_distinct_names, name_groups
    

# Iz grupa cvi grupisanih prema istom vendoru random izvlacimo samo po jednog predstavnika cvi' - tako pravimo skup C';
# Randomly select one entry for each distinct name group
def create_cprim(name_groups):
    cprim = []
    for name, entries in name_groups.items():
        selected_entry = random.choice(entries)
        cprim.append(selected_entry)
    return cprim


# za svaki clan Cvend biramo random jednog predstavnika iz NC - stvaramo parove cvi-svi
def sampling(Cvend, NC, selected_method):
    l = []
    NC_log = []
    NC_pairs = [] # skup parova cvi-svi
    for c in Cvend:
        cnt = 0
        NC_sample = []  # skup svih svi za jedan cvi
            
        # prvo pravimo svi listu mogucih parnjaka za svaki cvi': proverava similarity cvi' i svakog svi, i da nije isti vendor:
        for nc in NC:
            if similar(c, nc, selected_method) and not equal_vendors(c, nc):
                cnt += 1  # brojimo koliko je slicnih za svaki cvi 
                NC_sample.append(nc)  # skladistimo sve svi pandane u skup NC_sample
        l.append(cnt)

            # provera:
            #  ako hocemo da stampamo pregled koliko koji cvi ima pandana:
            # if cnt == 0:
            #    print(f"CVE without a pair: {c['cve_id']}")
            # if cnt <10 and cnt>1:
            #    print(f"{c['cve_id']} {cnt}")
                    
        # potom za svaki cvi' izvlacimo jednog svi parnjaka random iz podskupa svih pandana
        if NC_sample:   # Ako skup NC_sample svih svi pandana datoj cvi nije prazan
            random_element = random.choice(NC_sample)  # biramo jedan svi random
            NC_pairs.append({
                "cvi" : c,
                "svi" : random_element
            })  # dodajemo sve CF i GP informacije o cvi i o svi u NC_pairs, da bi ih potom brojali)
            NC_log.append({
                "cvi" : c["cve_id"],
                "svi" : random_element["cve_id"]
            })  # dodajemo samo CVEID od cvi i od svi u NC_log za licnu upotrebu/kontrolu kroz cvs fajl (CVE-ID parova)
    return NC_pairs, NC_log


# brojanje a, b, c, d
        # attribute = GP_psirt ili GP_bugbounty (setovan pri pokretanju koda)
            # a = broj clanova C koji su exposed to good practice - za koje je atribut=true {za attr=psirt: ...["GP_psirt"] == "1"; za attr=bugbounty: ...["GP_bugbounty"] == "1"}
            # b = broj clanova S koji su exposed to good practice - za koje je atribut=true
            # c = broj clanova C koji nisu exposed to good practice - za koje je atribut=false {za attr=psirt: ...["GP_psirt"] != "1"; za attr=bugbounty: ...["GP_bugbounty"] != "1"}
            # d = broj clanova S koji nisu exposed to good practice - za koje je atribut=false
def count(NC_pairs, selected_key):
    a = 0
    b = 0
    c = 0
    d = 0
    for cs in NC_pairs:  #razdvajamo bazu NC_pairs na cvi i svi
        cvi = cs["cvi"]
        sample = cs["svi"]
        if cvi[selected_key] != "1":  # ako za dati cvi PSIRT/BB nije 1 (i.e. false) dizemo c za jedan (c je cvi sa false)
            c += 1
        if sample[selected_key] != "1":   # ako za dati svi PSIRT/BB nije 1 (i.e. false) dizemo d za jedan (d je cvi sa false)
            d += 1
    a = len(NC_pairs) - c  # a je total broj u C minus c
    b = len(NC_pairs) - d  # b je total broj u Sample minus d
    return a, b, c, d


# racunanje OR, RR, RRR, ARR
def calculate_risk(a, b, c, d):
    OR = (a*d)/(c*b) # OR = a/b / c/d
    CER = c/(c+d)       # Control Event Rate
    EER = a/(a+b)       # Experimental Event Rate
    RR = EER/CER        # RR = EER/CER = a*(c+d) / c*(a+b) 
    RRR = 1 - EER/CER
    ARR = CER - EER     # ARR = CER - EER = c/c+d - a/a+b
    return OR, RR, RRR, ARR


# racunanje specificity i sensitivity
def calculate_SensSpec(a, b, c, d):
    Sensitivity = a/(a + c)  # ovo se nece menjati kroz random jer C ostaje isti
    Specificity = d/(b + d)  # ovo ce se menjati u zavinosti od random
    return Sensitivity, Specificity


#Chi2 test and p value
def chi_square(a, b, c, d):
    contingency_table = np.array([[a, c], [b, d]])              # Create contingency table
    chi2, p_value, _, _ = chi2_contingency(contingency_table)   # Perform Chi-Square test of independence (one-tailed)
    p_value_1t = p_value / 2                                    # Since the chi2_contingency function provides a two-tailed p-value, we divide by 2 for a one-tailed test
    return chi2, p_value_1t


# main program: sa ovim ispod mu kazemo 'ovo pokreni samo ako je direktno pozvano iz command prompta'
# (ako se poziva iz drugog fajla nece raditi -> prebaci u funkciju ovo ispod ako bude neophodno)
if __name__ == "__main__":

    # citanje argumenta pri startovanju
    args = parse_arguments()
    selected_method = None

    print(f"Number of bootstrap iterations: {args.iterations}")
    if args.pcert:
        selected_method = ComparisonMethod.PCERT
        print("Using pcert to compare entries.")
    if args.bugbounty:
        selected_method = ComparisonMethod.BUGBOUNTY
        print("Using bugbounty to compare entries.")
    if args.other:
        selected_method = ComparisonMethod.OTHER
        print("Using other method to compare entries.")

    if selected_method == ComparisonMethod.PCERT:
        selected_key = "GP_psirt"
    elif selected_method == ComparisonMethod.BUGBOUNTY:
        selected_key = "GP_bugbounty"

    else:
        print("Error: Selected method is not valid.")
        exit(1)

    # ucitavanje C i NC iz CSVova
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

    # izdvajamo jedinstvene vendore u C (da bi potom u bootstrapu random birali jedinstvenog predstavnika cvi')
    total_distinct_names, name_groups = C_by_vendors(C)
    # print("Total distinct Name values:", total_distinct_names)

    # !!! Bootstrap
    bootstrap_values_OR = []
    bootstrap_values_RR = []
    bootstrap_values_RRR = []
    bootstrap_values_ARR = []
    bootstrap_values_Spec = []
    bootstrap_values_Sens = []
    bootstrap_values_chi2 = []
    bootstrap_values_p = []

    median_OR = 0
    median_RR = 0
    median_RRR = 0
    median_ARR = 0
    median_Spec = 0
    median_Sens = 0
    median_chi2 = 0
    median_p = 0

    # Number of bootstrap iterations
    num_iterations = args.iterations

    for _ in range(num_iterations):

        # 1)
        # pravimo C' (C sa samo jednim random izabranim predstavnikom svakog vendora) i stavljamo ga u Cvend
        Cvend = create_cprim(name_groups)
        
                # provera:
                # #print(Cvend)

                # provera:
                # iterate through the keys of the Cvend dictionary (which contain the "CISAVendorName" values) 
                # and prints each one separately:
                # print("Name values of Cvend:")
                # for name in Cvend.keys():
                #    print(name)

        # 2)
        # Sampling:
        NC_pairs, NC_log = sampling(Cvend, NC, selected_method)

        # 3)
        # statistika:
        # prebrojavamo a, b, c i d iz NC_pairs (koji sadrzi info i o cvi i o parnjaku svi) u zavisnoti od prakse (PSIRT ili BB)
        a, b, c, d = count(NC_pairs, selected_key)

        # racunamo rizik
        OR, RR, RRR, ARR = calculate_risk(a, b, c, d)

        # racunamo sensitivity i specificity
        Sensitivity, Specificity = calculate_SensSpec(a, b, c, d)

        #racunamo chi2 i p
        chi2, p_value_1t = chi_square(a, b, c, d)

        # Store the result u nizove
        bootstrap_values_OR.append(OR)
        bootstrap_values_RR.append(RR)
        bootstrap_values_RRR.append(RRR)
        bootstrap_values_ARR.append(ARR)
        bootstrap_values_Spec.append(Specificity)
        bootstrap_values_Sens.append(Sensitivity)
        bootstrap_values_chi2.append(chi2)
        bootstrap_values_p.append(p_value_1t)

    # !!! end of bootstrap loop


    # Calculate the median of the bootstrap values
    median_OR = np.median(bootstrap_values_OR)
    median_RR = np.median(bootstrap_values_RR)
    median_RRR = np.median(bootstrap_values_RRR)
    median_ARR = np.median(bootstrap_values_ARR)
    median_Spec = np.median(bootstrap_values_Spec)
    median_Sens = np.median(bootstrap_values_Sens)
    median_chi2 = np.median(bootstrap_values_chi2)
    median_p = np.median(bootstrap_values_p)

    # bootstrap 95% confidence intervals (CI) for chi2 statistics - to provide a range of likely values for the chi-square statistic
    lower_bound_chi2 = np.percentile(bootstrap_values_chi2, 2.5)
    upper_bound_chi2 = np.percentile(bootstrap_values_chi2, 97.5)

    # bootstrap 95% confidence intervals (CI) for p-value 
    lower_bound_p = np.percentile(bootstrap_values_p, 2.5)
    upper_bound_p = np.percentile(bootstrap_values_p, 97.5)


    # Save the median values to a CSV file (appending if the file exists)
    medians_df = pd.DataFrame({
        'type': [selected_key],
        'iterations': [num_iterations],
        'OR': [median_OR],
        'RR': [median_RR],
        'RRR': [median_RRR],
        'ARR': [median_ARR],
        'Specificity': [median_Spec],
        'Sensitivity': [median_Sens],
        'Chi2' : [median_chi2],
        'CI (chi2) - lower' : [lower_bound_chi2],
        'CI (chi2) - upper': [upper_bound_chi2],
        'p-value (1-tail)' : [median_p],
        'CI (p) - lower' : [lower_bound_p],
        'CI (p) - upper': [upper_bound_p]
    })

    # Define the filename
    filename = 'medians.csv'

    # Check if the file exists, if it does, append without header, otherwise write with header
    if os.path.isfile(filename):
        medians_df.to_csv(filename, mode='a', header=False, index=False)
    else:
        medians_df.to_csv(filename, index=False)

    print("Median values saved to 'medians.csv'")


    # Save bootstrap_values to a CSV file
    bootstrap_values_df = pd.DataFrame({
        'OR': bootstrap_values_OR,
        'RR': bootstrap_values_RR,
        'RRR': bootstrap_values_RRR,
        'ARR': bootstrap_values_ARR,
        'Specificity': bootstrap_values_Spec,
        'Sensitivity': bootstrap_values_Sens, 
        'Chi2' : bootstrap_values_chi2,
        'p-value (1-tail)' : bootstrap_values_p 
    })
    bootstrap_values_df.to_csv('bootstrap_values.csv', index=False)

    print("Bootstrap values saved to 'bootstrap_values.csv'")


    # snimamo rezultate u falove: NC_pairs (sve cvi i svi podatke) u json, a samo CVEID od cvi i svi u .cvs, za interni pregled
    save_dict_to_json(NC_pairs, 'NC_pairs.json')
    save_dict_to_csv(NC_pairs, 'NC_pairs.csv')
    save_dict_to_csv(NC_log, 'NC_log.csv')
    save_dict_to_json(Cvend, 'Cvend.json')
    save_dict_to_csv(Cvend, 'Cvend.csv')


    # stampamo rezultate
    # print(f"a: {a} b: {b} c: {c} d: {d}")
    # print(f"Association 1: {c/(a+c) < d/(b+d)}")
    # print(f"Association 2: {a/(a+c) > b/(b+d)}")
    # print(f"CER: {CER} EER: {EER}")
    # print(f"OR: {median_OR} RR: {median_RR} RRR: {median_RRR} ARR: {median_ARR} Specificity: {median_Spec}" Sensitivity: {median_Sens})

    # Create arrays for exposure and outcomes
    # array of 1 for exposed and 0 for unexposed:
    #exposure = np.concatenate([np.ones(a + b), np.zeros(c + d)]).reshape(-1, 1)
    ## array of 1 for outcome and 0 for no outcome:
    #outcomes = np.concatenate([np.ones(a + c), np.zeros(b + d)])

    # Ensure lengths match
    #if len(exposure) != len(outcomes):
        #print("Effect size error: Lengths of exposure and outcomes arrays do not match.")
    #else:
        ## Perform logistic regression
        #model = LogisticRegression()
        #model.fit(exposure, outcomes)
#
        ## Calculate effect size (odds ratio)
        #effect_size = np.exp(model.coef_[0][0])
#
        #print("Estimated effect size:", effect_size)


