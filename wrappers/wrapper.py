"""
Main wrapper.
"""
import copy
import difflib
import os
import platform
import sys
from Queue import Queue, Empty
from subprocess import Popen, PIPE
from threading import Thread

import config
import msgs


# =================
# Wrapper Class for both CPU and GPU
# PART 1: config / vars etc.
# =================
class Vars(object):
    # Namespace settings (just for tidiness / keep editors error msgs down.
    # These ones are named in subsequent code.
    # Not critical: captured in .run_reset() anyway
    argv = []
    bits = 0
    defaults_changed = []
    defaults = {}
    hash_type = 0
    hash_file = None
    words_files = []
    rules_files = []
    outfile = None
    mask = None
    masks_file = None
    table_file = None
    session = "default_session"
    separator = ":"

    def __init__(self, choice='cpu'):
        # super(Vars, self).__init__()
        # 1a. Tailor settings as per the Config
        if choice == 'cpu':
            config.HASH_TYPE_DICT.update(config.HC_HASH_TYPE_DICT)
            config.CMD_SHORT_SWITCH.update(config.HC_CMD_SHORT_SWITCH)
            config.CMD_EQUAL_REQUIRED += config.HC_CMD_EQUAL_REQUIRED
            config.IGNORE_VARS += config.HC_IGNORE_VARS
        else:
            config.HASH_TYPE_DICT.update(config.OCL_HASH_TYPE_DICT)
            config.CMD_SHORT_SWITCH.update(config.OCL_CMD_SHORT_SWITCH)
            config.CMD_EQUAL_REQUIRED += config.OCL_CMD_EQUAL_REQUIRED
            config.IGNORE_VARS += config.OCL_IGNORE_VARS
        # 1b. Apply Config
        self.hash_type_dict = config.HASH_TYPE_DICT
        self.cmd_short_switch = config.CMD_SHORT_SWITCH
        self.cmd_equal_required = config.CMD_EQUAL_REQUIRED
        self.ignore_vars = config.IGNORE_VARS
        # 2. Reset
        self.run_reset(choice)

    def run_reset(self, choice):
        if choice == 'cpu':
            for key, value in config.HCresetVars().__dict__.items():
                object.__setattr__(self, key, value)
        else:
            for key, value in config.OCLresetVars().__dict__.items():
                object.__setattr__(self, key, value)

# =================
# WRAPPER PART 2: functions
# =================
class Backbone(Vars):
    """
    Main hashcat process initiated by the start() function
    """
    hashcat = None
    # Output queue for stdout, stderr collection.
    # Allows for async (non-blocking) read from subprocess.
    q = Queue()
    eq = Queue()
    # TODO: Determine best place to collect stats for hashcat
    stats = None
    # Thread to gather stdout, stderr from hashcat subprocess
    stdout_thread = None
    stderr_thread = None

    def __init__(self, bin_dir='.', choice='cpu', cpu_type=None,
                 gcard_type='cuda', verbose=False):
        super(Backbone, self).__init__(choice)
        self.verbose = verbose
        self.reset(choice)
        # Localise to the directory where Hashcat is installed
        #todo Need to fix the bin_dir lang below; worked for hc, but not ocl
        self.bin_dir = bin_dir  # or self.guess_bin_dir()
        # os.chdir(self.bin_dir)
        # Build stub and cmd line
        if choice == 'cpu':
            stub, msg = self.build_stub(cpu_type)
        else:
            stub, msg = self.build_stub(gcard_type)
        m_tmp, self.cmd = self.build_cmd(stub)
        # And message
        self.msg_pack(msgs.m_arch, msgs.m_bits.format(self.bits), msgs.m_os,
                      m_tmp, msg, msgs.m_cmd.format(self.cmd))

    def __enter__(self): return self

    def __exit__(self, type, value, traceback): self.stop()

    def __setattr__(self, name, value):
        try:
            if not value == self.defaults[name] and name \
                    not in self.ignore_vars:
                self.defaults_changed.append(name)
        except Exception:
            pass
        finally:
            object.__setattr__(self, name, value)

    # =================
    # MAIN OPERATIVE FUNCTION(S)
    # =================
    def start(self, cmd=None, argv=[]):
        if cmd is None:
            cmd = self.cmd
        if self.hashcat is not None and self.is_running:
            self.stop()
        # Create full path to main binary
        run_cmd = [os.path.join(self.bin_dir, cmd)] + argv
        self.msg_pack("[+] STDIN: " + ' '.join(run_cmd))
        self. hashcat = Popen(run_cmd,
                              stdout=PIPE, stdin=PIPE, stderr=PIPE,
                              bufsize=1,
                              close_fds=config.ON_POSIX)
        # Start a new thread to queue async output from stdout, stderr
        self.thrd_starter(self.hashcat.stdout, self.q, 'OUT')
        self.thrd_starter(self.hashcat.stderr, self.eq, 'ERR')

    def test(self, cmd=None, argv=[]):
        if cmd is None:
            cmd = self.cmd
        # Create full path to main binary
        run_cmd = [os.path.join(self.bin_dir, cmd)] + argv
        if run_cmd and None not in run_cmd:
            self.msg_pack(msgs.m_hc_cmd, ' '.join(run_cmd), msgs.m_filler)
        else:
            self.msg_pack(msgs.m_runfail)

    # =================
    # ATTACK HELPERS
    # =================
    def build_args(self):
        self.msg_pack(msgs.m_build_arg)
        # Check if any defaults are changed
        argv = []
        for option in self.defaults_changed:
            # Get the value assigned to the option
            value = str(getattr(self, option))
            # Convert Python snake_style var to cmd line dash format
            option = option.replace('_', '-')
            # Use short switches if available
            if option in self.cmd_short_switch.keys():
                self.msg_pack(msgs.m_short)
                option = "-" + self.cmd_short_switch[option]
                argv.append(option)
                argv.append(str(value))
            else:
                if option in self.cmd_equal_required:
                    argv.append("--" + option + "=" + str(value))
                else:
                    argv.append("--" + option)
        return argv

    def common_attack_pattern(self, test, a, msg):
        try:
            self.argv_inserts(self.words_files[0], self.hash_file, a, '-a',
                              self._get_hashcode(), '-m')
            return self._attack_tail(msg, self.argv, test)
        except IndexError:
            return

    def argv_inserts(self, *args):
        for a in args:
            self.argv.insert(0, a)

    def _get_hashcode(self):
        if self.hash_type not in self.hash_type_dict.values():
            hash_code = self.find_code()
        else:
            hash_code = self.hash_type
        return str(hash_code)

    def add_rules(self):
        self.msg_pack(msgs.m_rules.format(str(len(self.rules_files))))
        for rules in self.rules_files:
            if not os.path.isabs(rules):
                rules = os.path.join(self.bin_dir, rules)
            if os.path.isfile(rules):
                self.msg_pack(msgs.m_rulesfound.format(rules))
                self.argv.append("-r")
                self.argv.append(rules)
            else:
                self.msg_pack(msgs.m_rulesNOTfound.format(rules))
                pass

    def _attack_tail(self, msg, argv, test):
        self.msg_pack(msg)
        if test:
            self.test(argv=argv)
        else:
            self.start(argv=argv)
        return self.get_rtcode()

    def stop(self):
        rtcode = self.get_rtcode()
        if self.is_running:
            self.msg_pack(msgs.m_stop_bkgd)
            try:
                self.hashcat.kill()
                self.msg_pack("[Done]")
            except Exception as ProcessException:
                if rtcode not in (-2, -1, 0, 2):
                    self.msg_pack(msgs.m_proc_excpt)
                else:
                    self.msg_pack("[Done]")
        self.msg_pack(msgs.m_code_exit.format(str(rtcode)))

    @property
    def is_running(self):
        """
        :return: Bool
        """
        # Return value of None indicates process hasn't terminated
        if self.get_rtcode() is None:
            return True
        else:
            return False

    def get_rtcode(self):
        """
        status codes on exit:
        =====================
        [-2 = gpu-watchdog alarm]
        -1 = error
         0 = cracked
         1 = exhausted
         2 = aborted
        """
        try:
            return self.hashcat.poll()
        except Exception:
            return -99  # Hasn't been started

    # =================
    # GET RESULTS
    # =================
    def get_hashes(self, output_file_path=None, fields=(), sep=None):
        if output_file_path is None:
            if self.outfile is None:
                return
            else:
                output_file_path = self.outfile
        if sep is None:
            sep = self.separator
        try:
            # Get cracked hashes
            with open(output_file_path, "rb") as output_file:
                self.msg_pack(msgs.m_readout.format(output_file_path))
                results = [record.rstrip('\n\r').rsplit(sep) for
                           record in output_file.readlines()]
            if len(fields) == 0 and len(results) > 0 \
                    or len(results) > 0 and len(fields) != len(results[0]):
                # Default field names f1....fN
                # where N is the #items in results line
                fields = tuple(["f" + str(i) for i in range(len(results[0]))])
            if len(results) > 0:
                if len(fields) == len(results[0]):
                    # Returns list-o-dicts with fields mapped to variables
                    return [dict(zip(fields, record)) for record in results]
            else:
                return [{}]
        except IOError:
            return [{}]

    # =================
    # QUEUEING & THREADING
    # =================
    @staticmethod
    def enqueue_output(out, queue):
        for line in iter(out.readline, b''):
            queue.put(line)
            out.flush()
        out.close()

    def stderr(self):
        try:
            return self.eq.get_nowait().rstrip()
        except Empty:
            return ""

    def thrd_starter(self, thrd_obj, q_ref, tailor):
        std_thread = Thread(target=self.enqueue_output,
                            args=(thrd_obj, q_ref))
        std_thread.daemon = True
        try:
            std_thread.start()
            self.msg_pack(msgs.m_stdoe.format(tailor))
        except Exception:
            self.msg_pack(msgs.m_stdo_fail.format(tailor))

    # =================
    # HELPERS
    # =================
    def reset(self, *args, **kwargs):
        self.run_reset(*args, **kwargs)
        if self.is_running:
            self.stop()
            self.stdout_thread = None
            self.stderr_thread = None
        self.defaults = copy.deepcopy(
            {key: vars(self)[key] for key in vars(self)
             if key not in ['hashcat', 'stdout_thread', 'sterr_thread']}
        )
        self.msg_pack(msgs.m_reset)

    def guess_bin_dir(self):
        self.msg_pack(msgs.m_bin_dir)
        for dirName, subdirList, fileList in os.walk(config.WALK_ROOT):
            if dirName.lower().find('hashcat') > -1:
                if dirName.lower().find('cuda') == -1 and \
                                dirName.lower().find('cuda') == -1:
                    return dirName

    def build_stub(self, cpu_type):
        if sys.maxsize > 2**32:
            self.bits = "64"
        else:
            self.bits = "32"
        if self.bits == "32" and cpu_type is not None:
            print "[E] " + cpu_type + " is only supported on 64 bit!"
            sys.exit()
        if cpu_type is None:
            stub, msg = msgs.m_cli.format(str(self.bits)), msgs.m_sse2
        elif cpu_type.lower() == "avx":
            stub, msg = msgs.m_cli.format('AVX'), msgs.m_avx
        elif cpu_type.lower() == "xop":
            stub, msg = msgs.m_cli.format('XOP'), msgs.m_xop
        return stub + '{}', msg

    def build_cmd(self, tmp):
        if "Win" in platform.system():
            return msgs.m_win, tmp.format(' ')
        else:
            return msgs.m_lin, tmp.format('.bin')

    def msg_pack(self, *args):
        if self.verbose:
            for a in args:
                print a

    def set_my_ios(self, hash_file=None, words_ls=None, rules_ls=None,
                   masks_file=None, table_file=None, outfile=None):
        if not hash_file:
            print msgs.m_runfail
            return
        self.hash_file = hash_file
        if words_ls:
            self.words_files = words_ls
        if rules_ls:
            self.rules_files = rules_ls
        self.masks_file = masks_file
        self.table_file = table_file
        self.outfile = outfile

    def clear_rules(self): self.rules_files = []

    def clear_words(self): self.words_files = []

    def find_code(self):
        """
        :return: Find the hashcat hash code (first match); default is MD5
        """
        try:
            return str(self.hash_type_dict[
                           difflib.get_close_matches(
                               self.hash_type, self.hash_type_dict.keys())
                           [0]]
                       )
        except:
            return 0

    def str_from_code(self, code):
        """
        :param code: string object to be looked up in hash_type_dict
        :return: Reverse lookup find code from string
        """
        for code_str in self.hash_type_dict:
            if str(code).lower() == str(self.hash_type_dict[code_str]).lower():
                self.msg_pack(
                    msgs.m_hashdi.format(
                        str(code_str), str(self.hash_type_dict[code_str])
                    )
                )
                return code_str
        else:
            return "UNKNOWN"


