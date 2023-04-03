import requests
import IO_Module as IOm
from tqdm import tqdm


def check_url(url):
    #* Check host reachability
    pass


def preparation():
    #* Determine the Typical Service Response (Dynamic and Static parts)
    pass

def request(jwt, url, mode):
    req = requests.get(url, cookies={"jwt":jwt})

    if mode == "sc":
        if req.status_code != 404:
            IOm.print_JWT(jwt)
            
