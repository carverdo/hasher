




import copy
import difflib
import os
import platform
import struct
import sys
from Queue import Queue, Empty
from collections import namedtuple, OrderedDict
from subprocess import Popen,PIPE
from threading import Thread

ON_POSIX = 'posix' in sys.builtin_module_names


'''
            Wrapper Class for oclHashcat (GPU)
'''
class oclHashcatWrapper(object):

    hashcat = None			# Main hashcat process once initiated by the start() function
    q = Queue()				# Output queue for stdout collection. Allows for async (non-blocking) read from subprocess
    eq = Queue()			# Output queue for stderr collection.
    stats = None			# Stats from restore file and stdout collected in a dictionary
    stdout_thread = None		# Thread to gather stdout from hashcat subprocess
    stderr_thread = None		# Thread to gather stderr from hashcat subprocess
    # initialized = False  # NEW LINE
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
            'MySQL323' :   '200' ,
            'MySQL4.1' :   '300' ,
            'MySQL5' :   '300' ,
            'phpass' :   '400' ,
            'MD5(Wordpress)' :   '400' ,
            'MD5(phpBB3)' :   '400' ,
            'md5crypt' :   '500' ,
            'MD5(Unix)' :   '500' ,
            'FreeBSD MD5' :   '500' ,
            'Cisco-IOS MD5' :   '500' ,
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
            'descrypt' :  '1500' ,
            'DES(Unix)' :  '1500' ,
            'Traditional DES' :  '1500' ,
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
            'Domain Cached Credentials2':  '2100' ,
            'mscash2' :  '2100' ,
            'Cisco-PIX MD5' :  '2400' ,
            'Cisco-ASA MD5' : '2410' ,
            'WPA/WPA2' :  '2500' ,
            'Double MD5' :  '2600' ,
            'LM' :  '3000' ,
            'Oracle 7-10g':  '3100' ,
            'DES(Oracle)' :  '3100' ,
            'bcrypt' :  '3200' ,
            'Blowfish(OpenBSD)' :  '3200' ,
            'md5($salt.md5($pass))' :  '3710' ,
            'md5(sha1($pass))' : '4400',
            'Double SHA1' : '4500',
            'sha1(md5($pass))' : '4700',
            'MD5(Chap)': '4800',
            'iSCSI CHAP authentication' : '4800',
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
            'RipeMD160' :  '6000' ,
            'Whirlpool' :  '6100' ,
            'TrueCrypt 5.0+ PBKDF2-HMAC-RipeMD160 (XTS AES)' :  '6211' ,
            'TrueCrypt 5.0+ PBKDF2-HMAC-SHA512 (XTS AES)' :  '6221' ,
            'TrueCrypt 5.0+ PBKDF2-HMAC-Whirlpool (XTS AES)' :  '6231' ,
            'TrueCrypt 5.0+ PBKDF2-HMAC-RipeMD160 + boot-mode (XTS AES)' :  '6241' ,
            'TrueCrypt 5.0+ PBKDF2-HMAC-RipeMD160 + hidden-volume (XTS AES)' :  '6251' ,
            'TrueCrypt 5.0+ PBKDF2-HMAC-SHA512 + hidden-volume (XTS AES)' :  '6261' ,
            'TrueCrypt 5.0+ PBKDF2-HMAC-Whirlpool + hidden-volume (XTS AES)' :  '6271' ,
            'TrueCrypt 5.0+ PBKDF2-HMAC-RipeMD160 + hidden-volume + boot-mode (XTS AES)' :  '6281' ,
            'AIX {smd5}' :  '6300' ,
            'AIX {ssha256}' :  '6400' ,
            'AIX {ssha512}' :  '6500' ,
            '1Password, agilekeychain' :  '6600' ,
            'AIX {ssha1}' :  '6700' ,
            'Lastpass' :  '6800' ,
            'GOST R 34.11-94' :  '6900' ,
            'OSX v10.8 / v10.9' :  '7100' ,
            'GRUB 2' :  '7200' ,
            'IPMI2 RAKP HMAC-SHA1': '7300',
            'sha256crypt' :  '7400' ,
            'SHA256(Unix)' :  '7400' ,
            'Kerberos 5 AS-REQ Pre-Auth etype 23' :  '7500' ,
            'Redmine Project Management Web App' : '7600' ,
            'SAP CODVN B (BCODE)' : '7700',
            'SAP CODVN F/G (PASSCODE)' : '7800' ,
            'Drupal7' : '7900' ,
            'Sybase ASE' : '8000',
            'Citrix Netscaler': '8100',
            '1Password, cloudkeychain': '8200',
            'DNSSEC (NSEC3)' : '8300' ,
            'WBB3, Woltlab Burning Board 3' : '8400' ,
            'RACF' : '8500' ,
            'Lotus Notes/Domino 5' : '8600' ,
            'Lotus Notes/Domino 6' : '8700' ,
            'Android FDE' : '8800' ,
            'scrypt' : '8900' ,
            'Password Safe v2' : '9000' ,
            'Lotus Notes/Domino 8' : '9100' ,
            'Joomla' :    '11' ,
            'osCommerce, xt:Commerce' :    '21' ,
            'Juniper Netscreen/SSG (ScreenOS)' :    '22' ,
            'Skype' :    '23' ,
            'nsldap, SHA-1(Base64), Netscape LDAP SHA' :   '101' ,
            'nsldaps, SSHA-1(Base64), Netscape LDAP SSHA' :   '111' ,
            'Oracle 11g' :   '112' ,
            'SMF > v1.1' :  '121' ,
            'OSX v10.4, v10.5, v10.6' :   '122' ,
            'MSSQL(2000)' :   '131' ,
            'MSSQL(2005)' :   '132' ,
            'PeopleSoft' :   '133' ,
            'EPiServer 6.x < v4' :   '141' ,
            'hMailServer' :  '1421' ,
            'EPiServer 6.x > v4' :  '1441' ,
            'SSHA-512(Base64), LDAP {SSHA512}' :  '1711' ,
            'OSX v10.7' :  '1722' ,
            'MSSQL(2012)' :  '1731' ,
            'MSSQL(2014)' :  '1731' ,
            'vBulletin < v3.8.5' :  '2611' ,
            'PHPS' :  '2612' ,
            'vBulletin > v3.8.5' :  '2711' ,
            'IPB2+, MyBB1.2+' :  '2811' ,
            'Mediawiki B type' :  '3711'
    }

    cmd_short_switch = {

            'attack-mode' : 'a',
            'hash-type' : 'm',
            'version' : 'V',
            'help' : 'h',
            'benchmark' : 'b',
            'markov-threshold' : 't',
            'outfile' : 'o',
            'separator' : 'p',
            'segment-size' : 'c',
            'gpu-devices' : 'd',
            'workload-profile' : 'w',
            'gpu-accel' : 'n',
            'gpu-loops' : 'u',
            'skip' : 's',
            'limit' : 'l',
            'rule-left' : 'j',
            'rule-right' : 'k',
            'rules-file' : 'r',
            'generate-rules' : 'g',
            'custom-charset1' : '1',
            'custom-charset2' : '2',
            'custom-charset3' : '3',
            'custom-charset4' : '4',
            'increment' : 'i'
    }

    cmd_equal_required = [
            'benchmark-mode',
            'status-timer',
            'markov-hcstat',
            'markov-threshold',
            'runtime',
            'session',
            'restore-timer',
            'outfile-format',
            'remove-time',
            'debug-mode'  ,
            'debug-file' ,
            'induction-dir',
            'outfile-check-dir',
            'cpu-affinity',
            'gpu-temp-abort',
            'gpu-temp-retain',
            'generate-rules-func-min',
            'generate-rules-func-max',
            'generate-rules-seed',
            'increment-min',
            'increment-max'
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
            'safe_dict',
            'bits'
    ]

    def __init__(self, bin_dir=".", gcard_type="cuda", verbose=False):

        self.verbose = verbose
        self.reset()
        self.bin_dir = bin_dir							# Directory where oclHashcat is installed
        self.bits = "32"

        if self.verbose: print "[*] Checking architecture:",

        if sys.maxsize > 2**32:
            self.bits = "64"

        else:
            self.bits = "32"

        if self.verbose: print self.bits+" bit"
        if self.verbose: print "[*] Checking OS type:",

        if "Win" in platform.system():

            if self.verbose: print "Windows"

            if gcard_type.lower() == "cuda":
                self.cmd = "cudaHashcat"+self.bits + " "
                if self.verbose: print "[*] Using CUDA version"

            else:
                self.cmd = "oclHashcat"+self.bits + " "
                if self.verbose: print "[*] Using OCL version"

            if self.verbose: print "[*] Using cmd: " + self.cmd
        else:

            if self.verbose: print "Linux"

            if gcard_type.lower() == "cuda":
                self.cmd = "./cudaHashcat"+self.bits + ".bin"
                if self.verbose: print "[*] Using CUDA version"

            else:
                self.cmd = "./oclHashcat"+self.bits  + ".bin"
                if self.verbose: print "[*] Using OCL version"

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
            ## self.hashcat = None  # NEW LINE NO NO
            self.stdout_thread = None
            self.stderr_thread = None

        self.hash_file = None			# File with target hashes
        self.words_files = []			# List of dictionary files
        self.rules_files = []			# List of rules files
        self.masks_file = None
        self.charset_file = None
        self.eula = False
        self.help = False
        self.version = False
        self.quiet = False
        self.show = False
        self.left = False
        self.username = False
        self.remove = False
        self.force = False
        self.runtime = 0
        self.hex_salt = False
        self.hex_charset = False
        self.hex_wordlist = False
        self.segment_size = 1
        self.bitmap_max = None
        self.gpu_async = False
        self.gpu_devices = None
        self.gpu_accel = None
        self.gpu_loops = None
        self.gpu_temp_disable = False
        self.gpu_temp_abort = 90
        self.gpu_temp_retain = 80
        self.powertune_disable = False
        self.skip = None
        self.limit = None
        self.keyspace = False
        self.rule_left = ":"
        self.rule_right = ":"
        self.generate_rules = 0
        self.generate_rules_func_min = 1
        self.generate_rules_func_max = 4
        self.generate_rules_seed = None
        self.hash_type = 0
        self.increment = False
        self.increment_min = 1
        self.increment_max = 54
        self.benchmark = False
        self.benchmark_mode = 1
        self.status = False
        self.status_timer = 10
        self.status_automat = False
        self.loopback = False
        self.weak_hash_threshold = 100
        self.markov_hcstat = None
        self.markov_disable = False
        self.markov_classic = False
        self.markov_threshold = 0
        self.session = "default_session"
        self.restore = False
        self.restore_disable = False
        self.outfile = None
        self.outfile_format = 3
        self.outfile_autohex_disable = False
        self.outfile_check_timer = None
        self.separator = ":"
        self.disable_potfile = False
        self.remove_timer = None
        self.potfile_disable = False
        self.debug_mode = None
        self.debug_file = None
        self.induction_dir = None
        self.outfile_check_dir = None
        self.cpu_affinity = None
        self.cleanup_rules = False
        self.custom_charset1 = "?|?d?u"
        self.custom_charset2 = "?|?d"
        self.custom_charset3 = "?|?d*!$@_"
        self.custom_charset4 = None
        self.mask = None


        # self.defaults = copy.deepcopy({key:vars(self)[key] for key in vars(self) if key != 'restore_struct'})

        self.defaults = copy.deepcopy(
            {key:vars(self)[key] for key in vars(self)
             if key not in ['hashcat', 'stdout_thread', 'sterr_thread']}
        )
        self.defaults_changed = []

        if self.verbose: print "[*] Variables reset to defaults"

    def get_restore_stats(self, restore_file_path=None):

        '''
            Now retrieving the restore file using struct, namedtuples and OrderedDict.
            There is a pointer to argv which differs in size between 32-/64 bit systems.
            With the current code you can't correctly parse a restore file created with
            the 32 bit version of oclHashcat on a 64 bit system (and vice versa).
            Any ideas/patches are welcome.
        '''

        if not restore_file_path:
            restore_file_path = os.path.join(self.bin_dir, self.session + ".restore")


        try:
          # Get stats from restore file
          with open(restore_file_path, "r") as restore_file:

              try:
                self.restore_struct = restore_file.read()

              except Exception as FileReadError:
                if self.verbose: "[-] Error reading restore file"
                return

              if self.bits == "64":
                  fmt = 'I256sIIIQIQ%ds' % (len(self.restore_struct) - 296)
              else: # 32 bit system
                  fmt = 'I256sIIIQII%ds' % (len(self.restore_struct) - 288)
              struct_tuple = namedtuple('struct_tuple', 'version_bin cwd pid dictpos maskpos pw_cur argc argv_pointer argv')
              struct_tuple = struct_tuple._make(struct.unpack(fmt, self.restore_struct))
              self.stats = OrderedDict(zip(struct_tuple._fields, struct_tuple))
              self.stats['cwd'] = self.stats['cwd'].rstrip('\0')

              try:
                  self.stats['argv'] = self.stats['argv'].split('\n')
                  self.stats['argv'][0] = os.path.basename(self.stats['argv'][0]).split('.')[0]

              except Exception as ValueError:
                self.stats['argv'][0] = "oclHashcat"

        except IOError as FileError:
          if self.verbose: print "[-] Restore file not found!"

    def get_hashes(self, output_file_path=None, fields=(), sep=None):
        print 'OFP start', self.outfile
        if output_file_path == None:

            if self.outfile == None:
                print 'OF got outfile', self.outfile
                return

            else:
                output_file_path = self.outfile
                print 'OFP set', output_file_path

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
            print 'aaaaaaaaagh'
            return [{}]

    def enqueue_output(self, out, queue):

        for line in iter(out.readline, b''):

            queue.put(line)
            out.flush()

        out.close()

    def stdout(self):

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
        print 'RCRC', run_cmd


        if self.verbose: print "[+] STDIN: " + ' '.join(run_cmd)

        self.hashcat = Popen(run_cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE, bufsize=1, close_fds=ON_POSIX)

        # Start a new thread to queue async output from stdout
        stdout_thread = Thread(target=self.enqueue_output, args=(self.hashcat.stdout, self.q))
        print 'TO', self.hashcat.stdout
        print 'QR', self.q
        stdout_thread.daemon = True

        # Start a new thread to queue async output from stderr
        stderr_thread = Thread(target=self.enqueue_output, args=(self.hashcat.stderr, self.eq))
        print 'TO', self.hashcat.stderr
        print 'QR', self.eq
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

    def hybrid_dict_mask(self, argv=[], TEST=False):

        argv = self.build_args()

        if self.hash_type not in self.hash_type_dict.values():
            hash_code = self.find_code()

        else:
            hash_code = self.hash_type

        if self.masks_file == None and self.mask == None:
            return

        else:
            if self.masks_file:
                mask = self.masks_file

            else:
                mask = self.mask

        try:
            argv.insert(0, mask)

        except IndexError as EmptyListError:
            return

        argv.insert(0, self.words_files[0])
        argv.insert(0, self.hash_file)
        argv.insert(0, "6")
        argv.insert(0, "-a")
        argv.insert(0, str(hash_code))
        argv.insert(0, "-m")

        if self.verbose: print "[*] Starting Hybrid dict + mask (6) attack"

        if TEST:
            self.test(argv=argv)

        else:
            self.start(argv=argv)

        return self.get_RTCODE()

    def hybrid_mask_dict(self, argv=[], TEST=False):

        argv = self.build_args()

        if self.hash_type not in self.hash_type_dict.values():
            hash_code = self.find_code()

        else:
            hash_code = self.hash_type

        try:
            argv.insert(0, self.words_files[0])

        except IndexError as EmptyListError:
            return

        if self.masks_file == None and self.mask == None:
            return

        else:
            if self.masks_file:
                mask = self.masks_file

            else:
                mask = self.mask

        argv.insert(0, mask)
        argv.insert(0, self.hash_file)
        argv.insert(0, "7")
        argv.insert(0, "-a")
        argv.insert(0, str(hash_code))
        argv.insert(0, "-m")

        if self.verbose: print "[*] Starting Hybrid mask + dict (7) attack"

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
        -2 = gpu-watchdog alarm
        -1 = error
         0 = cracked
         1 = exhausted
         2 = aborted

        '''

        try:
            print 'xx', self.hashcat.poll()
            return self.hashcat.poll()

        except Exception as e:
            print 'ho'
            return -99          # Hasn't been started



    def find_code(self):	# Find the hashcat hash code

        try:

            # Returns the first code that matches the type text
            return str(self.hash_type_dict[difflib.get_close_matches(self.hash_type, self.hash_type_dict.keys())[0]])

        except Exception as CodeNotFoundError:
            return 0

        # return 0			# Return default MD5

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


    def clear_rules(self): self.rules_files = []

    def clear_words(self): self.words_files = []


if __name__ == '__main__':

    # will work if there is no .pot file

    path_to_exe = 'c:/users/admin/documents/cudaHashcat-2.01'
    import os
    os.chdir(path_to_exe)

    ocl = oclHashcatWrapper(verbose=True)


    ocl.outfile = 'bosh.txt'
    ocl.hash_type = '0'
    ocl.words_files.append('wordlists/phpbb.txt')
    ocl.hash_file = 'tests/hashes/hashc.txt'
    ocl.straight()
    """

    argv = ['-m', '0', 'a', '100', 'tests/hashes/hashc.txt', 'wordlists/phpbb.txt', '-o', 'bosh.txt']
    ocl.outfile = 'bosh.txt'
    print ocl.cmd
    ocl.start(ocl.cmd, argv)

    while ocl.is_running():
        pass
        print ocl.get_hashes(fields=('first', 'second', 'third'))

    """

    """
    with oclHashcatWrapper(bin_dir=path_to_exe, verbose=True) as hashcat:

        hashcat.hash_file = "example0.hash"
        hashcat.words_files.append("example.dict")
        hashcat.rules_files.append("rules/best64.rule")
        hashcat.rules_files.append("rules/custom.rule")
        hashcat.hash_type = "NTLM"
        hashcat.outfile = "myoutput.txt"
        hashcat.straight()

        while hashcat.is_running():
            pass
            print hashcat.get_hashes(fields=('first', 'second', 'third'))

    """



    """

        hashcat.hash_type = '0'
        hashcat.hash_file = "example0.hash"
        hashcat.markov_threshold = 32
        hashcat.words_files.append("example.dict")
        hashcat.mask = "?a?a?a?a"

        hashcat.hybrid_mask_dict()

        # while hashcat.is_running(): print hashcat.stdout()	# Simple Stream gobbler
    """