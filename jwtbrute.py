import IO_Module as IOm
import JWT_Module as JWTm
import HTTP_Module as HTTPm


if __name__ == "__main__":
    url, token, corrections, attack_type, mode, wordlist, filename = IOm.get_input()

    IOm.launch_info(url, token, corrections, attack_type, mode, wordlist)

    # #checking if host is up
    # HTTPm.check_url(url.split(":")[1][2:])
    if not url.startswith("http://") and not url.startswith("https://") and not url == 'None':
        file = open(url, "r")
        urls = file.readlines()
        for i in range(len(urls)):
            urls[i] = urls[i].replace("\n", "")
    else:
        urls = [url]

    for url in urls:
        if url != 'None':
            IOm.printstage(f"Checking url: {url}")

        if mode == "sc":
            HTTPm.get_status_code(url, token)
        if mode == "ra":
            HTTPm.preparation(url, token)

        if '0' in attack_type:
            IOm.printstage("Enumerating keys...")
            JWTm.weak_key(token, corrections, wordlist, url, mode, filename)
            IOm.printstage("Finished enumerating keys \n")

        if '1' in attack_type:
            IOm.printstage("Exploiting Alg:None Vulnerability")
            JWTm.alg_none(token, corrections, url, mode, filename)
            IOm.printstage("Finished exploiting \n")
        
        if '2' in attack_type:
            IOm.printstage("Exploiting Null Signature Vulnerability")
            JWTm.sign_null(token, corrections, url, mode, filename)
            IOm.printstage("Finished exploiting \n")
        
        if '3' in attack_type:
            IOm.printstage("Exploiting Key Injection Vulnerability")
            JWTm.key_injection(token, corrections, url, mode, filename)
            IOm.printstage("Finished exploiting \n")

IOm.printstage("JWTBrute finished.")

