import os
import requests
import IO_Module as IOm
from tqdm import tqdm


def check_url(url):
    #* Check host reachability
    #! Solution below prints useless output
    # response = os.system("ping -c 1 " + url)

    # if response == 0:
    #     return True
    # else:
    #     return False
    pass


def get_status_code(url, jwt):
    global default_code
    req = requests.head(url, cookies={"jwt":jwt})

    default_code = req.status_code
    

def preparation(url, token):
    #* Determine the Typical Service Response (Dynamic and Static parts)
    pass

def request(jwt, key, url, mode, filename):
    if url == 'None':
        return IOm.write_to_file(jwt, filename)

    if mode == "sc":
        req = requests.head(url, cookies={"jwt":jwt}, headers={"Authorization":jwt})
        if req.status_code != default_code:
            IOm.print_JWT(jwt, key)
            return True
        else: 
            return False
    
    elif mode == "ra":
        pass
