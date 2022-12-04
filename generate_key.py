import rsa
import config

def check_files():
    ##return true if values do not exist
    valid1 = False
    valid2 = False

    try:
        open("id_rsa").close()
    except:
        valid1 = True
    try:
        open("id_rsa.pub").close()
    except:
        valid2 = True

    return (valid1 == valid2 == True)


def gen_key():
    publicKey, privateKey = rsa.newkeys(config.BITS)
    with open("id_rsa", "w+b") as f:
        f.write(privateKey.save_pkcs1())
    
    with open("id_rsa.pub", "w+b") as f:
        f.write(publicKey.save_pkcs1())


def main():
    first_check_answer = input("GENERATE NEW KEYS? (Y/N)").lower()
    if first_check_answer != "y":
        print("CANCELLING")
        return False
    
    if not check_files():
        second_check_answer = input("SOME VALUES MAY ALREADY EXIST, CONTINUE? (Y/N)").lower()
        if second_check_answer != "y":
            print("CANCELLING")
            return False
    
    print("GENERATING")
    gen_key()

    print("KEYS GENERATED!")

main()