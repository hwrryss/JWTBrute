import sys
import os
import string
from tqdm import tqdm
from termcolor import cprint

# more human-readable prints
def printerr(msg): return cprint(msg, 'red')
def printnote(msg): return cprint(msg, 'blue')
def printsol(msg): return cprint(msg, 'green')
def printstage(msg): return cprint(msg, 'white', attrs=["bold"])
def printdebug(msg): return cprint(msg, 'cyan')


def help():
    print("Usage: python3 jwtbrute -t {token} -u {url} -w {wordlist} -c {param=value} {param2=value} -a 12, -m sc\n")
    print("-t, --token           Base JWT token")
    print("-u, --url             Target url ")
    print("-a, --attack-type     Vulnerabilities you wish to check for")
    print("-m, --mode            Specify how JWTBrute should judge the responses of the web service")
    print("-w, --wordlist        Wordlist for bruteforcing HMAC key (rockyou.txt by default)")
    print("-c, --corrections     Corrections to JWT payload (key=value)")

def launch_info(url, token, corrections, attack_type, mode, wordlist):

    attack_types = {
        "0":"Weak Key",
        "1":"Algorithm: None",
        "2":"Null Signature",
        "3":"Key Injection"
    }

    print('\n')
    printdebug(f"Target URL: {url}")
    printdebug(f"Sample JWT: {token}")
    printdebug(f"Provided Corrections: {' '.join([str(c[0] + '=' + c[1]) for c in corrections])}")
    printdebug(f"Attack Type: {', '.join([attack_types[t] for t in attack_type])}")
    printdebug(f"Mode: {mode}")
    printdebug(f"Wordlist: {wordlist}")
    print('\n')

def print_JWT(jwt):
    tqdm.write(" [+] This JWT might work! " + jwt+ "\n")
    # printsol(f"[+] This JWT might work! {jwt}") # breaks the progres bar


def get_input():
    jwt_alphabet = string.ascii_letters + './+' + string.digits
    available_flags = ["--url", "--corrections", "--verbose", "--wordlist", "--token", "--help", "--attack-type", "--mode", "-m","-a" "-h", "-t", "-w", "-v", "-c", "-u"]

    sys.argv = sys.argv[1:]

    if sys.argv == []:
        print("No input was provided! Aborting...")
        exit()

    if "-h" in sys.argv:
        help()
        exit()
    else:

        #* finding token in sys.argv
        if "-t" not in sys.argv and "--token" not in sys.argv:
            printerr("ERROR: Token was not provided! Aborting...")
            exit()
        else:
            try:
                i = sys.argv.index("-t")
            except:
                i = sys.argv.index("--token")

            if i != len(sys.argv)-1:
                if sys.argv[i+1][0] == "-":
                    printerr("ERROR: Token was not provided! Aborting...")
                    exit()
                else:
                    token = sys.argv[i+1]
            else:
                printerr("ERROR: Token was not provided! Aborting...")
                exit()

        #* finding attack method in sys.argv
        if "-a" not in sys.argv and "--attack-type" not in sys.argv:
            printerr("ERROR: Attack method was not provided ! Aborting...")
            exit()
        else:
            try:
                i = sys.argv.index("-a")
            except:
                i = sys.argv.index("--attack-type")

            if i != len(sys.argv)-1:
                if sys.argv[i+1][0] == "-":
                    printerr("ERROR: Attack method was not provided! Aborting...")
                    exit()
                else:
                    attack_type = sys.argv[i+1]
            else:
                printerr("ERROR: Attack method was not provided! Aborting...")
                exit()
        
        #* finding mode in sys.argv
        if "-m" not in sys.argv and "--mode" not in sys.argv:
            printnote("NOTE: Mode was not provided! Using status codesby default")
            mode = "sc"
        else:
            try:
                i = sys.argv.index("-m")
            except:
                i = sys.argv.index("--mode")

            if i != len(sys.argv)-1:
                if sys.argv[i+1][0] == "-":
                    printerr("ERROR: Mode was mentioned but not provided! Aborting...")
                    exit()
                else:
                    mode = sys.argv[i+1]

            else:
                printerr("ERROR: Mode was mentioned but not provided! Aborting...")
                exit()

        #* finding url in sys.argv
        if "-u" not in sys.argv and "--url" not in sys.argv:
            printerr("ERROR: Target URL was not provided! Aborting...")
            exit()
        else:
            try:
                i = sys.argv.index("-u")
            except:
                i = sys.argv.index("--url")

            if i != len(sys.argv)-1:
                if sys.argv[i+1][0] == "-":
                    printerr("ERROR: Target URL was not provided! Aborting...")
                    exit()
                else:
                    url = sys.argv[i+1]
            else:
                printerr("ERROR: Target URL was not provided! Aborting...")
                exit()

        #* finding payload corrections in sys.argv
        if "-c" not in sys.argv and "--corrections" not in sys.argv:
            corrections = None
            printnote("NOTE: No corrections were provided. Double-check if that is what you need. We don't want you to bruteforce for nothing :)")
        else:
            corrections = []
            try:
                i = sys.argv.index("-c")
            except:
                i = sys.argv.index("--corrections")

            if i == len(sys.argv)-1:
                printnote("NOTE: No corrections were provided. Double-check if that is what you need. We don't want you to bruteforce for nothing :)")
            else:
                while i != len(sys.argv)-1:
                    if sys.argv[i+1][0] == "-":
                        printnote("NOTE: No corrections were provided. Double-check if that is what you need. We don't want you to bruteforce for nothing :)")
                        break
                    i+=1
                    corrections.append(sys.argv[i].split("="))


        #* finding worlist in sys.argv
        if "-w" not in sys.argv and "--wordlist" not in sys.argv:
            printnote("NOTE: Wordlist was not provided, using rockyou.txt as defualt...")
            wordlist = "rockyou.txt"

        else:
            try:
                i = sys.argv.index("-w")
            except:
                i = sys.argv.index("--wordlist")

            if i != len(sys.argv)-1:
                if sys.argv[i+1][0] == "-":
                    printnote("NOTE: Wordlist was not provided, using rockyou.txt as defualt...")
                    wordlist = "rockyou.txt"
                else:
                    wordlist = sys.argv[i+1]

            else:
                printnote("NOTE: Wordlist was not provided, using rockyou.txt as defualt...")
                wordlist = "rockyou.txt"

        # Some Error Handling
        if mode not in ["sc", "ra"]:
            printerr(f"Unknown mode! --> {mode}")
            exit()

        if attack_type not in '0123':
            printerr(f"Unknown attack method! --> {attack_type}")
            exit()
        else:
            attack_type = list(attack_type)

        if not os.path.exists("./" + wordlist):
            printerr(f"Specidied wordlist doesn't seem to exist! --> {wordlist}")
            exit()
        
        return url, token, corrections, attack_type, mode, wordlist
