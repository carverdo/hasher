m_bin_dir = 'Guessing your home directory for hashcat...'
m_arch = '[*] Checking architecture:'
m_bits = '{} bit'
m_os = '[*] Checking OS type:'
m_win = 'Windows'
m_lin = 'Linux'
m_cuda = '[*] Using CUDA version'
m_ocl = '[*] Using OCL version'
m_cmd_g = '{}cudaHashcat{}{}'
m_cmd_ng = '{}oclHashcat{}{}'
m_cmd = '[*] Using cmd: {}'
m_reset = '[*] Variables reset to defaults'
m_norestore = '[-] Restore file not found!'
m_restore_fail = '[-] Error reading restore file'
m_readout = 'Reading output file: {}'
m_stdoe = '[*] STD{} thread started'
m_stdo_fail = '[!] Could not start STD{} thread'
m_hc_cmd = '--------- Hashcat CMD Test ---------'
m_filler = '------------------------------------'
m_runfail = '[-] None type in string. Required option missing'

m_rules = '[*] ({}) Rules files specified. Verifying files...'
m_rulesfound = '\t[+]{} Found!'
m_rulesNOTfound = '\t[+]{} NOT Found!'

m_strt_atk = '[*] Starting Straight (0) attack'
m_comby_atk = '[*] Starting Combinator (1) attack'
m_comby_fail = '[-] You need two files to make up self.word_files'
m_bf_atk = '[*] Starting Brute-Force (3) attack'
m_hydi_atk = '[*] Starting Hybrid dict + mask (6) attack'
m_hydi_fail = '[-] You need a self.mask_file or self.mask'
m_hyma_atk = '[*] Starting Hybrid mask + dict (7) attack'

m_tog_atk = '[*] Starting Toggle-case (2) attack'
m_perm_atk = '[*] Starting Permutation (4) attack'
m_tabl_atk = '[*] Starting Table-lookup (5) attack'

m_stop_bkgd = '[*] Stopping background process...'

m_proc_excpt = '''
[PROCESS EXCEPTION]'
\t** This could have happened for several reasons **
\t1. GOOD: Process successfully completed before stop call
\t2. BAD: Process failed to run initially (likely path or argv error)
\t3. UGLY: Unknown - Check your running processes for a zombie
'''

m_code_exit = '[*] Program exited with code: {}'
m_hashdi = '[*] {} = {}'
m_build_arg = '[*] Building argv'
m_short = '[*] Checking for short options'

m_fmt = 'I256sIIIQII{}s'

m_cli = 'hashcat-cli{}'
m_sse2 = '[*] Using SSE2 version'
m_avx = '[*] Using AVX version'
m_xop = '[*] Using XOP version'