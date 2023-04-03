import IO_Module as IOm
import JWT_Module as JWTm


if __name__ == "__main__":
    url, token, corrections, attack_type, mode, wordlist= IOm.get_input()

    IOm.launch_info(url, token, corrections, attack_type, mode, wordlist)

    if '0' in attack_type:
        IOm.printstage("Enumerating keys...")
        JWTm.weak_key(token, corrections, wordlist, url, mode)
        IOm.printstage("Finished enumerating keys \n")

    if '1' in attack_type:
        IOm.printstage("Exploiting Alg:None Vulnerability")
        JWTm.alg_none(token, corrections, url, mode)
        IOm.printstage("Finished exploiting \n")
    
    if '2' in attack_type:
        IOm.printstage("Exploiting Null Signature Vulnerability")
        JWTm.sign_null(token, corrections, url, mode)
        IOm.printstage("Finished exploiting \n")
    
    if '3' in attack_type:
        IOm.printstage("Exploiting Key Injection Vulnerability")
        JWTm.key_injection(token, corrections, url, mode)
        IOm.printstage("Finished exploiting \n")

    IOm.printstage("JWTBrute finished.")

