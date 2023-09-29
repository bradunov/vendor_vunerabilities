import json
from datetime import datetime

import requests
import datetime
import hashlib
import hmac
import base64
import json


reg_domains = {
    # TLD
    "com": [],
    "org": [],
    "gov": [],
    "net": [],
    "dev": [],
    "edu": [],
    "info": [],
    "to" : [],
    "co" : [],
    "cc" : [],
    "cl" : [],
    "re" : [],
    "cf" : [],
    "cx" : [],
    "cat" : [],
    "name" : [],
    "page" : [],
    "party" : [],
    "security" : [],
    "support" : [],
    "codes" : [],
    "chat" : [],
    "services" : [],
    "systems" : [],
    "global" : [],
    "foundation" : [],
    "fish" : [],
    "one" : [],
    "pro" : [],
    "ltd" : [],
    "lol" : [],
    "my" : [],
    "computer" : [],
    "company" : [],
    "kernel" : [],
    "ninja" : [],
    "xyz" : [],
    "blog" : [],
    "tech" : [],
    "top" : [],
    "website" : [],
    "news" : [],
    "biz" : [],
    "sh" : [],
    "site" : [],
    "video" : [],
    "wiki" : [],
    "app" : [],
    "cat" : [],
    "ooo" : [],
    "camera" : [],
    "community" : [],
    "network" : [],
    "today" : [],
    "trust" : [],
    "watch" : [],
    "tube" : [],
    "zone" : [],
    "link" : [], 
    "google" : [],
    "wien" : [],
    "toyota" : [],
    "media" : [],
    "online": [],
    "canon" :[],
    "cloud" : [],
    "vip": [],
    "dance" :[], 
    "works" :[],
    "aero" : [],
    "audio" : [],
    "sharp" : [],
    "social" : [],
    "team" : [],
    "live" : [],
    "games" : [],
    # Countries
    "jp" : ["or", "co"],
    "ru" : [],
    "us" : [],
    "uk" : ["com", "gov", "org", "edu", "ac"],
    "cz" : ["com", "gov", "org", "edu", "ac"],
    "pl" : ["com", "gov", "org", "edu", "ac"],
    "il" : ["com", "gov", "org", "edu", "ac"],
    "tr" : ["com", "gov", "org", "edu", "ac"],
    "sg" : ["com", "gov", "org", "edu", "ac"],
    "tw" : ["com", "gov", "org", "edu", "ac"],
    "br" : ["com", "gov", "org", "edu", "ac"],
    "au" : ["com", "gov", "org", "edu", "ac"],
    "np" : ["com", "gov", "org", "edu", "ac"],
    "hk" : ["com", "gov", "org", "edu", "ac"],
    "ua" : ["com", "gov", "org", "edu", "ac"],
    "mx" : ["com", "gov", "org", "edu", "ac"],
    "ph" : ["com", "gov", "org", "edu", "ac"],
    "ca" : [],
    "ae" : [],
    "ee" : [],
    "ws" : [],
    "af" : [],
    "im" : [],
    "me" : [],
    "ir" : [],
    "so" : [],
    "su" : [],
    "in" : [],
    "kz" : [],
    "hu" : [],
    "ga" : [],
    "rs" : [],
    "si" : [],
    "lu" : [],
    "su" : [],
    "ml" : [],
    "th" : ["in"],
    "mk" : [],
    "md" : [],
    "sr" : [],
    "dk" : [],
    "tf" : [],
    "vn" : [],
    "by" : [],
    "be" : [],
    "ro" : [],
    "fr" : [],
    "it" : [],
    "hr" : [],
    "pt" : [],
    "se" : [],
    "eu" : [],
    "ly" : [],
    "nu" : [],
    "ht" : [],
    "at" : [],
    "lt" : [],
    "io" : [],
    "es" : [],
    "sk" : [],
    "de" : [],
    "lv" : [],
    "ar" : [],
    "ie" : [],
    "ch" : [],
    "fi" : [],
    "gr" : [],
    "nl" : [],
    "tv" : [],
    "ai" : [],
    "no" : [],
    "za" : [],
    "ma" : [],
    "pm" : [],
    "tk" : [],
    "cy" : [],
    "is" : [],
    "ci" : [],
    "li" : [],
    "id" : ["co", "or"],
    "kr" : ["co", "or"],
    "nz" : ["co", "or"],
    "cn" : ["com", "gov", "org"]
}


def extract_tld(fqdn):
    if ":" in fqdn:
        a = fqdn.split(":")
        fqdn = a[0].strip()

    a = fqdn.lower().split(".")

    if a[-1] not in reg_domains.keys():
        print("Unknown domain:", a[-1], a)
        return fqdn

    if len(a) >= 2 and a[-2] not in reg_domains[a[-1]]:
        return a[-2]
    else:
        return a[-3]

    # if len(a) >= 2 and \
    #     a[-1] in reg_domains.keys() and \
    #     a[-2] not in reg_domains[a[-1]]:
    #     print(a[-1], a)


def extract_assigner(assigner_mail):
    assigner = assigner_mail.split("@")
    user = assigner[0]
    tld = extract_tld(assigner[1])
    return user, tld


def extract_ref_dom(url):
    # Some entries have bugs, like: https://https://www.abc.com, which happens sufficiently often
    url = url.replace("https://https://", "https://")
    long_dom = url.split("/")[2].lower().strip()
    dom = extract_tld(long_dom)
    return dom, long_dom

def extract_cpe(cpe_uri):
    ac = cpe_uri.lower().split(":")
    vendor = ac[3].strip()
    product = ac[4].strip()
    version = ac[5].strip()
    return vendor, product, version

       


secrets = {
    "la_workspace_id": "XXXXX",
    "la_primary_key": "XXXXX"   
}


# Build the API signature
def _LA_build_signature(workspace_id, primary_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
    decoded_key = base64.b64decode(primary_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(workspace_id,encoded_hash)
    return authorization

# Build and send a request to the POST API
def _LA_post_data(json_str_body, log_type):
    workspace_id=secrets["la_workspace_id"]
    primary_key=secrets["la_primary_key"]
    body = json_str_body
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = _LA_build_signature(
        workspace_id, primary_key, rfc1123date, content_length, method, content_type, resource
    )
    uri = 'https://' + workspace_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,data=body, headers=headers)
    if not (response.status_code >= 200 and response.status_code <= 299):
        #print("\n\n****** Log Analytics error, response code: {}\n\n".format(response.status_code))
        raise ValueError("Log Analytics error, response code: {}\n\n".format(response.status_code))




def LA_post(d):
    i = 0
    step = 1000
    while i*step < len(d):
        b = i*step
        e = min((i+1)*step, len(d))
        print("LA from ", b, "to", e, "out of", len(d))
        s = json.dumps(d[b:e], sort_keys=True, default=str)
        _LA_post_data(s, "CVE")
        i += 1

