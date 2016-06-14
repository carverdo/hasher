
def get_hashes(fileName='hashes/hash.txt'):
    try: return open(fileName).readlines()
    except: return