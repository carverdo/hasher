class HashcatWrapper(object):

    hashcat = None			# Main hashcat process once initiated by the start() function
    q = Queue()				# Output queue for stdout collection. Allows for async (non-blocking) read from subprocess
    eq = Queue()			# Output queue for stderr collection.
    stats = None			# TODO: Determine best place to collect stats for hashcat
    stdout_thread = None		# Thread to gather stdout from hashcat subprocess
    stderr_thread = None		# Thread to gather stderr from hashcat subprocess
    initialized = False
    defaults_changed = []
    defaults = {}

    hash_type_dict = {

            'MD5' :     '0' ,
            'md5($pass.$salt)' :    '10' ,
            'md5($salt.$pass)' :   '20' ,
            'md5(unicode($pass).$salt)' :    '30' ,
            'md5($salt.unicode($pass))' :    '40' ,
            'HMAC-MD5 (key = $pass)' :   '50' ,
            'HMAC-MD5 (key = $salt)' :    '60' ,
            'SHA1' :   '100' ,
            'sha1($pass.$salt)' :   '110' ,
            'sha1($salt.$pass)' :   '120' ,
            'sha1(unicode($pass).$salt)' :   '130' ,
            'sha1($salt.unicode($pass))' :   '140' ,
            'HMAC-SHA1 (key = $pass)' :   '150' ,
            'HMAC-SHA1 (key = $salt)' :   '160' ,
            'sha1(LinkedIn)' :   '190' ,
            'MySQL' :   '300' ,
            'phpass' :   '400' ,
            'MD5(Wordpress)' :   '400' ,
            'MD5(phpBB3)' :   '400' ,
            'md5crypt' :   '500' ,
            'MD5(Unix)' :   '500' ,
            'FreeBSD MD5' :   '500' ,
            'Cisco-IOS MD5' :   '500' ,
            'SHA-1 (Django)':   '800',
            'MD4' :   '900' ,
            'NTLM' :  '1000' ,
            'Domain Cached Credentials:' :  '1100',
            'mscash' :  '1100' ,
            'SHA256' :  '1400' ,
            'sha256($pass.$salt)' :  '1410' ,
            'sha256($salt.$pass)' :  '1420' ,
            'sha256(unicode($pass).$salt)' :  '1430' ,
            'sha256($salt.unicode($pass))' :  '1440' ,
            'HMAC-SHA256 (key = $pass)' :  '1450' ,
            'HMAC-SHA256 (key = $salt)' :  '1460' ,
            'md5apr1' :  '1600' ,
            'MD5(APR)' :  '1600' ,
            'Apache MD5' :  '1600' ,
            'SHA512' :  '1700' ,
            'sha512($pass.$salt)' :  '1710' ,
            'sha512($salt.$pass)' :  '1720' ,
            'sha512(unicode($pass).$salt)' :  '1730' ,
            'sha512($salt.unicode($pass))' :  '1740' ,
            'HMAC-SHA512 (key = $pass)' :  '1750' ,
            'HMAC-SHA512 (key = $salt)' :  '1760' ,
            'sha512crypt, SHA512(Unix)' :  '1800' ,
            'Cisco-PIX MD5' :  '2400' ,
            'WPA/WPA2' :  '2500' ,
            'Double MD5' :  '2600' ,
            'bcrypt' :  '3200' ,
            'Blowfish(OpenBSD)' :  '3200' ,
            'MD5(Sun)': '3300',
            'md5(md5(md5($pass)))' : '3500',
            'md5(md5($salt).$pass)' : '3610',
            'md5($salt.md5($pass))' : '3710',
            'md5($pass.md5($salt))' : '3720',
            'md5($salt.$pass.$salt)' : '3810',
            'md5(md5($pass).md5($salt))' : '3910',
            'md5($salt.md5($salt.$pass))' : '4010',
            'md5($salt.md5($pass.$salt))' : '4110',
            'md5($username.0.$pass)' : '4210',
            'md5(strtoupper(md5($pass)))' : '4300',
            'md5(sha1($pass))' : '4400',
            'Double SHA1' : '4500',
            'sha1(sha1(sha1($pass)))' : '4600',
            'sha1(md5($pass))' : '4700',
            'MD5(Chap)': '4800',
            'SHA-3(Keccak)' :  '5000' ,
            'Half MD5' :  '5100' ,
            'Password Safe SHA-256' :  '5200' ,
            'IKE-PSK MD5' :  '5300' ,
            'IKE-PSK SHA1' :  '5400' ,
            'NetNTLMv1-VANILLA': '5500' ,
            'NetNTLMv1+ESS' :  '5500' ,
            'NetNTLMv2' :  '5600' ,
            'Cisco-IOS SHA256' :  '5700' ,
            'Samsung Android Password/PIN' :  '5800' ,
            'AIX {smd5}' :  '6300' ,
            'AIX {ssha256}' :  '6400' ,
            'AIX {ssha512}' :  '6500' ,
            'AIX {ssha1}' :  '6700' ,
            'Lastpass' :  '6800' ,
            'GOST R 34.11-94' :  '6900' ,
            'Fortigate (FortiOS)' : '7000',
            'OSX v10.8 / v10.9' :  '7100' ,
            'GRUB 2' :  '7200' ,
            'IPMI2 RAKP HMAC-SHA1': '7300',
            'sha256crypt' :  '7400' ,
            'SHA256(Unix)' :  '7400' ,
            'Plaintext': '9999',
            'Joomla' :    '11' ,
            'osCommerce, xt:Commerce' :    '21' ,
            'nsldap, SHA-1(Base64), Netscape LDAP SHA' :   '101' ,
            'nsldaps, SSHA-1(Base64), Netscape LDAP SSHA' :   '111' ,
            'Oracle 11g' :   '112' ,
            'SMF > v1.1' :  '121' ,
            'OSX v10.4, v10.5, v10.6' :   '122' ,
            'EPi' : '123',
            'MSSQL(2000)' :   '131' ,
            'MSSQL(2005)' :   '132' ,
            'EPiServer 6.x < v4' :   '141' ,
            'EPiServer 6.x > v4' :  '1441' ,
            'SSHA-512(Base64), LDAP {SSHA512}' :  '1711' ,
            'OSX v10.7' :  '1722' ,
            'MSSQL(2012)' :  '1731' ,
            'vBulletin < v3.8.5' :  '2611' ,
            'vBulletin > v3.8.5' :  '2711' ,
            'IPB2+, MyBB1.2+' :  '2811' ,
            'WebEdition CMD': '3721',
            'Redmine Project Management Web App': '7600'
    }

    cmd_short_switch = {

            'attack-mode' : 'a',
            'hash-type' : 'm',
            'version' : 'V',
            'help' : 'h',
            'outfile' : 'o',
            'separator' : 'p',
            'salt-file' : 'e',
            'segment-size' : 'c',
            'threads' : 'n',
            'words-skip' : 's',
            'words-limit': 'l',
            'rules-file' : 'r',
            'generate-rules' : 'g',
            'custom-charset1' : '1',
            'custom-charset2' : '2',
            'custom-charset3' : '3',
            'custom-charset4' : '4',
            'table-file' : 't'
    }

    cmd_equal_required = [

            'outfile-format',
            'debug-mode'  ,
            'debug-file' ,
            'outfile-check-dir',
            'generate-rules-func-min',
            'generate-rules-func-max',
            'generate-rules-seed',
            'toggle-min',
            'toggle-max',
            'pw-min',
            'pw-max',
            'perm-min',
            'perm-max',
            'table-min',
            'table-max'
    ]

    ignore_vars = [
            'defaults',
            'hash_type',
            'words_files',
            'hash_file',
            'rules_files',
            'masks_file',
            'charset_file',
            'mask',
            'safe_dict'
    ]











































    def __init__(self, bin_dir=".", cpu_type=None, verbose=False):

        self.verbose = verbose
        self.reset()                                    # Reset all variables
        self.bin_dir = bin_dir							# Directory where Hashcat is installed
        bits = "32"

        if self.verbose: print "[*] Checking architecture:",

        if sys.maxsize > 2**32:
            bits = "64"

        else:
            bits = "32"

        if bits == "32" and cpu_type != None:
            print "[E] " + cpu_type + " is only supported on 64 bit!"
            sys.exit()

        if self.verbose: print bits+" bit"
        if self.verbose: print "[*] Checking OS type:",

        if "Win" in platform.system():

            if self.verbose: print "Windows"

            if cpu_type == None:
                self.cmd = "hashcat-cli"+bits + " "
                if self.verbose: print "[*] Using SSE2 version"

            elif cpu_type.lower() == "avx":
                self.cmd = "hashcat-cliAVX "
                if self.verbose: print "[*] Using AVX version"

            elif cpu_type.lower() == "xop":
                self.cmd = "hashcat-cliXOP "
                if self.verbose: print "[*] Using XOP version"

        else:

            if self.verbose: print "Linux"

            if cpu_type == None:
                self.cmd = "hashcat-cli"+bits + ".bin"
                if self.verbose: print "[*] Using SSE2 version"

            elif cpu_type.lower() == "avx":
                self.cmd = "hashcat-cliAVX.bin"
                if self.verbose: print "[*] Using AVX version"

            elif cpu_type.lower() == "xop":
                self.cmd = "hashcat-cliXOP.bin"
                if self.verbose: print "[*] Using XOP version"

        if self.verbose: print "[*] Using cmd: " + self.cmd

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):

        self.stop()

    def __setattr__(self, name, value):

        try:
            if not value == self.defaults[name] and name not in self.ignore_vars:
                self.defaults_changed.append(name)

        except Exception as e:
            pass

        finally:
            object.__setattr__(self,name,value)

    def reset(self):

        if self.is_running():
            self.stop()
            self.stdout_thread = None
            self.stderr_thread = None

        self.hash_file = None			# File with target hashes
        self.words_files = []			# List of dictionary files
        self.rules_files = []			# List of rules files
        self.masks_file = None
        self.charset_file = None
        self.hash_type = 0
        self.eula = False
        self.help = False
        self.version = False
        self.quiet = False
        self.hex_salt = False
        self.hex_charset = False
        self.outfile = None
        self.outfile_format = 0
        self.separator = ":"
        self.show = False
        self.left = False
        self.username = False
        self.remove = False
        self.stdout = False
        self.disable_potfile = False
        self.debug_file = None
        self.debug_mode = None
        self.salt_file = None
        self.segment_size = 32
        self.threads = 8
        self.words_skip = 0
        self.words_limit = 0
        self.generate_rules = 0
        self.generate_rules_func_min = 1
        self.generate_rules_func_max = 4
        self.custom_charset1 = "?|?d?u"
        self.custom_charset2 = "?|?d"
        self.custom_charset3 = "?|?d*!$@_"
        self.custom_charset4 = None
        self.toggle_min = 1
        self.toggle_max = 16
        self.pw_min = 1
        self.pw_max = 10
        self.perm_min = 2
        self.perm_max = 10
        self.table_file = None
        self.table_min = 2
        self.table_max = 10
        self.mask = None

        self.default = None
        self.defaults = copy.deepcopy({key:vars(self)[key] for key in vars(self) if key != 'stdout_thread' or 'sterr_thread'})
        self.defaults_changed = []

        if self.verbose: print "[*] Variables reset to defaults"

































































    def get_hashes(self, output_file_path=None, fields=(), sep=None):

        if output_file_path == None:

            if self.outfile == None:
                return

            else:
                output_file_path = self.outfile

        if sep == None:
            sep = self.separator

        try:
            # Get cracked hashes
            with open(output_file_path, "rb") as output_file:

                if self.verbose: print "Reading output file: " + output_file_path
                results = [record.rstrip('\n\r').rsplit(sep) for record in output_file.readlines()]

            if len(fields) == 0 and len(results) > 0 or len(results) > 0 and len(fields) != len(results[0]):

                # Default field names are f1....fN where N is the number of items in the results line
                fields = tuple(["f"+str(i) for i in range(len(results[0]))])

            if len(results) > 0:

                if len(fields) == len(results[0]):

                    # Returns a list of dictionary objects with fields mapped to variables
                    return [dict(zip(fields, record)) for record in results]

            else:

                return [{}]

        except IOError as FileError:

            return [{}]

    def enqueue_output(self, out, queue):

        for line in iter(out.readline, b''):

            queue.put(line)
            out.flush()

        out.close()

    def g_stdout(self): # Different than oclHashcatWrapper because hashcat has a "stdout" cmd switch

        out = ""
        try:
            out = self.q.get_nowait()

        except Empty:
            out = ""

        return out.rstrip()

    def stderr(self):

        out = ""
        try:
            out = self.eq.get_nowait()

        except Empty:
            out = ""

        return out.rstrip()


    def start(self, cmd=None, argv=[]):

        if cmd == None:
            cmd = self.cmd

        if self.hashcat != None and self.is_running():
            self.stop()

        run_cmd = [os.path.join(self.bin_dir,cmd)] + argv		# Create full path to main binary

        if self.verbose: print "[+] STDIN: " + ' '.join(run_cmd)

        self.hashcat = Popen(run_cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE, bufsize=1, close_fds=ON_POSIX)

        # Start a new thread to queue async output from stdout
        stdout_thread = Thread(target=self.enqueue_output, args=(self.hashcat.stdout, self.q))
        stdout_thread.daemon = True

        # Start a new thread to queue async output from stderr
        stderr_thread = Thread(target=self.enqueue_output, args=(self.hashcat.stderr, self.eq))
        stderr_thread.daemon = True

        try:
            stdout_thread.start()
            if self.verbose: print "[*] STDOUT thread started"

        except Exception as e:
            if self.verbose: print "[!] Could not start STDOUT thread"

        try:
            stderr_thread.start()
            if self.verbose: print "[*] STDERR thread started"

        except Exception as e:
            if self.verbose: print "[!] Could not start STDERR thread"

    def test(self, cmd=None, argv=[]):

        if cmd == None:
            cmd = self.cmd

        run_cmd = [os.path.join(self.bin_dir,cmd)] + argv		# Create full path to main binary

        if run_cmd and not None in run_cmd:

	  print "--------- Hashcat CMD Test ---------"
	  print ' '.join(run_cmd)
	  print "------------------------------------"

	else:
	  if self.verbose: print "[-] None type in string. Required option missing"

    def straight(self, TEST=False):

        argv = self.build_args()

        if self.hash_type not in self.hash_type_dict.values():
            hash_code = self.find_code()

        else:
            hash_code = self.hash_type

        try:
            argv.insert(0, self.words_files[0])

        except IndexError as EmptyListError:
            return

        argv.insert(0, self.hash_file)
        argv.insert(0, "0")
        argv.insert(0, "-a")
        argv.insert(0, str(hash_code))
        argv.insert(0, "-m")

        # Add rules if specified
        if self.verbose: print "[*] (" + str(len(self.rules_files)) + ") Rules files specified. Verifying files..."

        for rules in self.rules_files:

            if not os.path.isabs(rules): rules = os.path.join(self.bin_dir,rules)

            if os.path.isfile(rules):

                if self.verbose: print "\t[+] " + rules + " Found!"

                argv.append("-r")
                argv.append(rules)

            else:

                if self.verbose: print "\t[-] " + rules + " NOT Found!"
                pass


        if self.verbose: print "[*] Starting Straight (0) attack"

        if TEST:
            self.test(argv=argv)

        else:
            self.start(argv=argv)

        return self.get_RTCODE()

    def combinator(self, argv=[], TEST=False):

        argv = self.build_args()

        if self.hash_type not in self.hash_type_dict.values():
            hash_code = self.find_code()

        else:
            hash_code = self.hash_type

        try:
            argv.insert(0, self.words_files[1])
            argv.insert(0, self.words_files[0])

        except IndexError as EmptyListError:
            return

        argv.insert(0, self.hash_file)
        argv.insert(0, "1")
        argv.insert(0, "-a")
        argv.insert(0, str(hash_code))
        argv.insert(0, "-m")

        if self.verbose: print "[*] Starting Combinator (1) attack"

        if TEST:
            self.test(argv=argv)

        else:
            self.start(argv=argv)

        return self.get_RTCODE()

    def toggle_case(self, argv=[], TEST=False):

        argv = self.build_args()

        if self.hash_type not in self.hash_type_dict.values():
            hash_code = self.find_code()

        else:
            hash_code = self.hash_type

        try:
            argv.insert(0, self.words_files[0])

        except IndexError as EmptyListError:
            return

        argv.insert(0, self.hash_file)
        argv.insert(0, "2")
        argv.insert(0, "-a")
        argv.insert(0, str(hash_code))
        argv.insert(0, "-m")

        if self.verbose: print "[*] Starting Toggle-case (2) attack"

        if TEST:
            self.test(argv=argv)

        else:
            self.start(argv=argv)

        return self.get_RTCODE()

    def brute_force(self, argv=[], TEST=False):

        argv = self.build_args()

        if self.hash_type not in self.hash_type_dict.values():
            hash_code = self.find_code()

        else:
            hash_code = self.hash_type

        try:
            argv.insert(0, self.words_files[0])

        except IndexError as EmptyListError:
            return

        argv.insert(0, self.hash_file)
        argv.insert(0, "3")
        argv.insert(0, "-a")
        argv.insert(0, str(hash_code))
        argv.insert(0, "-m")

        if self.verbose: print "[*] Starting Brute-Force (3) attack"

        if TEST:
            self.test(argv=argv)

        else:
            self.start(argv=argv)

        return self.get_RTCODE()

    def permutation(self, argv=[], TEST=False):

        argv = self.build_args()

        if self.hash_type not in self.hash_type_dict.values():
            hash_code = self.find_code()

        else:
            hash_code = self.hash_type

        try:
            argv.insert(0, self.words_files[0])

        except IndexError as EmptyListError:
            return

        argv.insert(0, self.hash_file)
        argv.insert(0, "4")
        argv.insert(0, "-a")
        argv.insert(0, str(hash_code))
        argv.insert(0, "-m")

        if self.verbose: print "[*] Starting Permutation (4) attack"

        if TEST:
            self.test(argv=argv)

        else:
            self.start(argv=argv)

        return self.get_RTCODE()

    def table_lookup(self, argv=[], TEST=False):

        argv = self.build_args()

        if self.hash_type not in self.hash_type_dict.values():
            hash_code = self.find_code()

        else:
            hash_code = self.hash_type

        try:
            argv.insert(0, self.words_files[0])

        except IndexError as EmptyListError:
            return

        argv.insert(0, self.hash_file)
        argv.insert(0, "4")
        argv.insert(0, "-a")
        argv.insert(0, str(hash_code))
        argv.insert(0, "-m")

        if self.verbose: print "[*] Starting Table-lookup (5) attack"

        if TEST:
            self.test(argv=argv)

        else:
            self.start(argv=argv)

        return self.get_RTCODE()

    def stop(self):

        RTCODE = self.get_RTCODE()
        if self.is_running():

            if self.verbose: print "[*] Stopping background process...",
            try:

                self.hashcat.kill()

                if self.verbose: print "[Done]"

            except Exception as ProcessException:

                if not RTCODE in (-2,-1,0,2):

                    if self.verbose:

                        print "[PROCESS EXCEPTION]"
                        print "\t** This could have happened for several reasons **"
                        print "\t1. GOOD: Process successfully completed before stop call"
                        print "\t2. BAD: Process failed to run initially (likely path or argv error)"
                        print "\t3. UGLY: Unknown - Check your running processes for a zombie"

                else:
                    if self.verbose: print "[Done]"


        if self.verbose: print "[*] Program exited with code: " + str(RTCODE)

    def is_running(self):

        if self.get_RTCODE() == None:		# Return value of None indicates process hasn't terminated

            return True

        else:
            return False


    def get_RTCODE(self):

        '''

        status codes on exit:
        =====================
        -1 = error
         0 = cracked
         1 = exhausted
         2 = aborted

        '''

        try:
            return self.hashcat.poll()

        except Exception as e:
            return -99          # Hasn't been started



    def find_code(self):	    # Find the hashcat hash code

        try:

            # Returns the first code that matches the type text
            return str(self.hash_type_dict[difflib.get_close_matches(self.hash_type, self.hash_type_dict.keys())[0]])

        except Exception as CodeNotFoundError:
            return 0

        return 0			# Return default MD5

    def str_from_code(self, code):	# Reverse lookup find code from string

        for code_str in self.hash_type_dict:

            if str(code).lower() == str(self.hash_type_dict[code_str]).lower():

                if self.verbose: print "[*] " + str(code_str) + " = " + str(self.hash_type_dict[code_str])
                return code_str

        else:
            return "UNKNOWN"


    def build_args(self):

        if self.verbose: print "[*] Building argv"

        # Check if any defaults are changed
        argv = []

        for option in self.defaults_changed:

            value = str(getattr(self, option))			# Get the value assigned to the option
            option = option.replace('_','-')			# Convert Python snake_style var to cmd line dash format

            if option in self.cmd_short_switch.keys():		# Use short switches if available

                if self.verbose: print "[*] Checking for short options"
                option = "-" + self.cmd_short_switch[option]
                argv.append(option)
                argv.append(str(value))

            else:

                if option in self.cmd_equal_required:
                    argv.append("--" + option + "=" + str(value))

                else:
                    argv.append("--" + option)

        return argv


    def clear_rules(self):

        self.rules_files = []

    def clear_words(self):

        self.words_files = []

