#!/usr/bin/env python
"""
"""
# import time, traceback,
# from pprint import pprint
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

import config
from msgs import *

# =================
# Wrapper Class for oclHashcat (GPU)
# =================
class OCLVars(object):
    # Tailor
    config.HASH_TYPE_DICT.update(config.OCL_HASH_TYPE_DICT)
    config.CMD_SHORT_SWITCH.update(config.OCL_CMD_SHORT_SWITCH)
    config.CMD_EQUAL_REQUIRED += config.OCL_CMD_EQUAL_REQUIRED
    config.IGNORE_VARS += config.OCL_IGNORE_VARS
    # Apply
    hash_type_dict = config.HASH_TYPE_DICT
    cmd_short_switch = config.CMD_SHORT_SWITCH
    cmd_equal_required = config.CMD_EQUAL_REQUIRED
    ignore_vars = config.IGNORE_VARS


# =================
# MAIN CLASS, Hashcat
# =================
class oclHashcatWrapper(config.OCLresetVars, OCLVars):
    # Main hashcat process once initiated by the start() function
    hashcat = None
    # Output queue for stdout, stderr collection.
    # Allows for async (non-blocking) read from subprocess
    q = Queue()
    eq = Queue()
    # Stats from restore file and stdout collected in a dictionary
    stats = None
    # Thread to gather stdout, stderr from hashcat subprocess
    stdout_thread = None
    stderr_thread = None
    # initialized = False
    defaults = {}

    def __init__(self, bin_dir='.', gcard_type="cuda", verbose=False):
        self.verbose = verbose
        self.reset()
        # Localise to the directory where Hashcat is installed
        self.bin_dir = bin_dir   # or self.guess_bin_dir()
        os.chdir(self.bin_dir)
        # Build stub and cmd line
        stub, msg = self.build_stub(gcard_type)
        m_tmp, self.cmd = self.build_cmd(stub)
        # And message
        self.msg_pack(m_arch, m_bits.format(self.bits), m_os,
                      m_tmp, msg, m_cmd.format(self.cmd))

    def __enter__(self): return self

    def __exit__(self, type, value, traceback): self.stop()

    def __setattr__(self, name, value):
        try:
            if not value == self.defaults[name] and name \
                    not in self.ignore_vars:
                self.defaults_changed.append(name)
        except Exception as e:
            pass
        finally:
            object.__setattr__(self, name, value)

    # =================
    # MAIN OPERATIVE FUNCTION(S)
    # =================
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

        self.hashcat = Popen(run_cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE, bufsize=1, close_fds=config.ON_POSIX)

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






















    # =================
    # HELPERS
    # =================
    def reset(self):
        super(oclHashcatWrapper, self).__init__()
        if self.is_running():
            self.stop()
            self.stdout_thread = None
            self.stderr_thread = None
        self.defaults = copy.deepcopy(
            {key: vars(self)[key] for key in vars(self)
             # if key != 'restore_struct'}
            if key not in ['hashcat', 'stdout_thread', 'sterr_thread']}
        )
        self.msg_pack(m_reset)

    def guess_bin_dir(self):
        self.msg_pack(m_bin_dir)
        for dirName, subdirList, fileList in os.walk(config.WALK_ROOT):
            if dirName.lower().find('cudahashcat') > -1 \
                    or dirName.find('oclhashcat') > -1:
                return dirName

    def build_stub(self, gcard_type):
        if sys.maxsize > 2**32:
            self.bits = "64"
        else:
            self.bits = "32"
        if gcard_type.lower() == "cuda":
            stub, msg = m_cmd_g, m_cuda
        else:
            stub, msg = m_cmd_ng, m_ocl
        return stub, msg

    def build_cmd(self, tmp):
        if "Win" in platform.system():
            return m_win, tmp.format('', self.bits, ' ')
        else:
            return m_lin, tmp.format('./', self.bits, '.bin')

    def msg_pack(self, *args):
        if self.verbose:
            for a in args:
                print a

    def set_my_ios(self, hash_file=None, words_files=None, rules_files=None,
                   masks_file=None, table_file=None, outfile=None):
        if not hash_file:
            print m_runfail
            return
        self.hash_file = hash_file
        if words_files:
            self.words_files.append(words_files)
        if rules_files:
            self.rules_files.append(rules_files)
        self.masks_file = masks_file
        self.table_file = table_file
        self.outfile = outfile

    def clear_rules(self): self.rules_files = []

    def clear_words(self): self.words_files = []


if __name__ == '__main__':

    # will work if there is no .pot file

    path_to_exe = 'c:/users/admin/documents/cudaHashcat-2.01'
    import os
    os.chdir(path_to_exe)
    ocl = oclHashcatWrapper(verbose=True)
    """
    ocl.outfile = 'bosh.txt'
    ocl.hash_type = '0'
    ocl.words_files.append('wordlists/phpbb.txt')
    ocl.hash_file = 'tests/hashes/hashc.txt'
    ocl.straight()

    """
    hashcat = oclHashcatWrapper(verbose=True)  # with as hashcat:  # bin_dir=path_to_exe,
    hashcat.outfile = "myoutput.txt"
    hashcat.hash_type = "NTLM"
    hashcat.hash_type = "100"  ##!!!
    hashcat.words_files.append("example.dict")
    hashcat.hash_file = "example0.hash"
    hashcat.hash_file = "example100.hash"  ##!!!
    hashcat.rules_files.append("rules/best64.rule")
    hashcat.rules_files.append("rules/custom.rule")
    hashcat.straight()
    """
    #while hashcat.is_running():
    #    pass
    #    print hashcat.get_hashes(fields=('first', 'second', 'third'))
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