from wrappers import *

# ===============
# HC SETUP
# ===============
def test_strt(toggle=False):
    """
    Dictionary attacks, choose straight, OR
    with toggling (only finds up to 8 characters)
    """
    hc.reset()
    hc.set_my_ios(hash_file='tests/hashes/hash.txt',
                  words_ls=['wordlists/phpbb.txt'],
                  rules_ls=['rules/combinator.rule'],
                  outfile='tests/crk_phpbb.txt')
    if not toggle:
        hc.straight()
    else:
        hc.toggle_case(toggle_max=8)

def test_comby():
    """left and right dictionary combines """
    hc.reset()
    hc.set_my_ios(hash_file='tests/hashes/lefthash.txt',
                  words_ls=['tests/wordlists/lefts.txt'],
                  outfile='tests/crk_left.txt')
    hc.combinator()

def test_brute():
    """mask attack (modern brute-force)"""
    hc.reset()
    hc.set_my_ios(hash_file='tests/hashes/4dig.txt',
                  masks_file='tests/masks/4dig.hcmask',
                  outfile='tests/crk_bf.txt')
    hc.brute_force(increment=True)

def test_permu():
    """permutation"""
    hc.reset()
    hc.set_my_ios(hash_file='tests/hashes/lefthash.txt',
                  words_ls=['tests/wordlists/lefts.txt'],
                  outfile='tests/crk_prmu.txt')
    hc.permutation()

def test_table():
    """table"""
    hc.reset()
    hc.set_my_ios(hash_file='tests/hashes/table_look.txt',
                  words_ls=['tests/wordlists/lefts.txt'],
                  table_file='tests/tables/tab.table',
                  outfile='tests/crk_tab.txt')
    hc.table_lookup()

print '============================================='
hc = hcHashcatWrapper(verbose=True)
hc.hash_type = '0'  # md5
# test_strt()
# test_comby()
# test_brute()
# test_permu()
test_table()

# ===============
# OCL SETUP
# ===============
def otest_strt(toggle=False):
    """
    Dictionary attacks, choose straight, OR
    with toggling (only finds up to 8 characters)
    """
    ocl.reset()
    ocl.hash_type = "100"
    ocl.set_my_ios(
        hash_file='tests/hashes/example100.hash',
        words_ls=['tests/wordlists/example.dict'],
        outfile='tests/crk_strt.txt',
        rules_ls=['rules/best64.rule', 'rules/custom.rule']
    )
    if not toggle:
        ocl.straight()
    else:
        pass  # ocl.toggle_case(toggle_max=8)

def otest_brute():
    """mask attack (modern brute-force)"""
    ocl.reset()
    ocl.set_my_ios(hash_file='tests/hashes/4dig.txt',
                  masks_file='tests/masks/4dig.hcmask',
                  outfile='tests/crk_bf.txt')
    ocl.brute_force(increment=True)

def otest_comby():
    """left and right dictionary combines """
    ocl.reset()
    ocl.set_my_ios(hash_file='tests/hashes/comby.hash',
                   words_ls=['tests/wordlists/lefts.dict',
                             'tests/wordlists/rights.dict'],
                   outfile='tests/crk_comby.txt')
    ocl.combinator()

def otest_hybrid_mask():
    """this one takes awhile"""
    ocl.reset()
    ocl.mask = "?a?a?a?a"
    ocl.markov_threshold = 32
    ocl.set_my_ios(hash_file='tests/hashes/example0.hash',
                   words_ls=['tests/wordlists/example.dict'],
                   outfile='tests/crk_hmd.txt'
    )
    ocl.hybrid_mask_dict()

"""
print '============================================='
import os
path_to_exe = 'c:/users/admin/documents/cudaHashcat-2.01'
os.chdir(path_to_exe)
ocl = oclHashcatWrapper(verbose=True)

# otest_strt()
# otest_brute()
# otest_comby()
# otest_hybrid_mask()

"""