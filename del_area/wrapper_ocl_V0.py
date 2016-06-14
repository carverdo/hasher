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
from subprocess import Popen, PIPE
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
class oclHashcatWrapper_OLD(config.OCLresetVars, OCLVars):
    # Main hashcat process initiated by the start() function
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
        self.hashcat = Popen(run_cmd,
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
            self.msg_pack(m_hc_cmd, ' '.join(run_cmd), m_filler)
        else:
            self.msg_pack(m_runfail)

    # =================
    # ATTACKS
    # =================
    def straight(self, test=False, a='0', msg=m_strt_atk):
        self.argv = self.build_args()
        self.add_rules()
        self.common_attack_pattern(test, a, msg)

    def combinator(self, test=False, a='1', msg=m_comby_atk):
        self.argv = self.build_args()
        try:
            self.argv.insert(0, self.words_files[1])
            self.common_attack_pattern(test, a, msg)
        except IndexError:
            print m_comby_fail
            return

    def brute_force(self, increment=False, test=False, a='3', msg=m_bf_atk):
        """
        These days this is done by using a maskfile which limits the wordspace.
        NB changed it from words to masks_files (to be more consistent with the
        docs).
        """
        self.argv = self.build_args()
        if increment:
            self.argv.insert(0, '--increment')
        try:
            self.argv_inserts(self.masks_file, self.hash_file, a, '-a',
                              self._get_hashcode(), '-m')
            return self._attack_tail(msg, self.argv, test)
        except IndexError:
            return

    def hybrid_dict_mask(self, test=False, a='6', msg=m_hydi_atk):
        self.argv = self.build_args()
        mask = self.masks_file or self.mask
        if not mask:
            return
        try:
            self.argv.insert(0, mask)
            self.common_attack_pattern(test, a, msg)
        except IndexError:
            print m_hydi_fail
            return

    def hybrid_mask_dict(self, test=False, a='7', msg=m_hyma_atk):
        self.argv = self.build_args()
        mask = self.masks_file or self.mask
        if not mask:
            return
        try:
            self.argv.insert(0, self.words_files[0])
            self.argv_inserts(mask, self.hash_file, a, '-a',
                              self._get_hashcode(), '-m')
            return self._attack_tail(msg, self.argv, test)
        except IndexError:
            return

    # =================
    # ATTACK HELPERS
    # =================
    def build_args(self):
        self.msg_pack(m_build_arg)
        # Check if any defaults are changed
        argv = []
        for option in self.defaults_changed:
            # Get the value assigned to the option
            value = str(getattr(self, option))
            # Convert Python snake_style var to cmd line dash format
            option = option.replace('_', '-')
            # Use short switches if available
            if option in self.cmd_short_switch.keys():
                self.msg_pack(m_short)
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
        self.msg_pack(m_rules.format(str(len(self.rules_files))))
        for rules in self.rules_files:
            if not os.path.isabs(rules):
                rules = os.path.join(self.bin_dir, rules)
            if os.path.isfile(rules):
                self.msg_pack(m_rulesfound.format(rules))
                self.argv.append("-r")
                self.argv.append(rules)
            else:
                self.msg_pack(m_rulesNOTfound.format(rules))
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
            self.msg_pack(m_stop_bkgd)
            try:
                self.hashcat.kill()
                self.msg_pack("[Done]")
            except Exception as ProcessException:
                if rtcode not in (-2, -1, 0, 2):
                    self.msg_pack(m_proc_excpt)
                else:
                    self.msg_pack("[Done]")
        self.msg_pack(m_code_exit.format(str(rtcode)))

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
        -2 = gpu-watchdog alarm
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
                self.msg_pack(m_readout.format(output_file_path))
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

    def get_restore_stats(self, restore_file_path=None):
        """
        Now retrieving the restore file using struct, namedtuples and
        OrderedDict. There is a pointer to argv which differs in size
        between 32-/64 bit systems.

        With the current code you can't correctly parse a restore file
        created with the 32 bit version of oclHashcat on a 64 bit system
        (and vice versa).

        Any ideas/patches are welcome.
        """
        if not restore_file_path:
            restore_file_path = os.path.join(self.bin_dir,
                                             self.session + ".restore")
        try:
            # Get stats from restore file
            with open(restore_file_path, "r") as restore_file:
                try:
                    self.restore_struct = restore_file.read()
                except IOError:
                    self.msg_pack(m_restore_fail)
                    return
                if self.bits == "64":
                    fmt = 296
                # 32 bit system
                else:
                    fmt = 288
                fmt = m_fmt.format(len(self.restore_struct) - fmt)
                struct_tuple = namedtuple(
                    'struct_tuple',
                    'version_bin cwd pid dictpos maskpos pw_cur argc argv_pointer argv'
                )
                struct_tuple = struct_tuple._make(
                    struct.unpack(fmt, self.restore_struct))
                self.stats = OrderedDict(zip(struct_tuple._fields,
                                             struct_tuple))
                self.stats['cwd'] = self.stats['cwd'].rstrip('\0')
                try:
                    self.stats['argv'] = self.stats['argv'].split('\n')
                    self.stats['argv'][0] = os.path.basename(
                        self.stats['argv'][0]).split('.')[0]
                except ValueError:
                    self.stats['argv'][0] = "oclHashcat"
        except IOError:
            self.msg_pack(m_norestore)

    # =================
    # QUEUEING & THREADING
    # =================
    @staticmethod
    def enqueue_output(out, queue):
        for line in iter(out.readline, b''):
            queue.put(line)
            out.flush()
        out.close()

    def stdout(self):
        try:
            return self.q.get_nowait().rstrip()
        except Empty:
            return ""

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
            self.msg_pack(m_stdoe.format(tailor))
        except Exception:
            self.msg_pack(m_stdo_fail.format(tailor))

    # =================
    # HELPERS
    # =================
    def reset(self):
        super(oclHashcatWrapper_OLD, self).__init__()
        if self.is_running:
            self.stop()
            self.stdout_thread = None
            self.stderr_thread = None
        self.defaults = copy.deepcopy(
            {key: vars(self)[key] for key in vars(self)
             if key not in ['hashcat', 'stdout_thread', 'sterr_thread']}
        )  # if key != 'restore_struct'}
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

    def set_my_ios(self, hash_file=None, words_ls=None, rules_ls=None,
                   masks_file=None, table_file=None, outfile=None):
        if not hash_file:
            print m_runfail
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
        :param code:
        :return: Reverse lookup find code from string
        """
        for code_str in self.hash_type_dict:
            if str(code).lower() == str(self.hash_type_dict[code_str]).lower():
                self.msg_pack(
                    m_hashdi.format(
                        str(code_str), str(self.hash_type_dict[code_str])
                    )
                )
                return code_str
        else:
            return "UNKNOWN"


if __name__ == "__main__":
    path_to_exe = 'c:/users/admin/documents/cudaHashcat-2.01'
    os.chdir(path_to_exe)
    ocl = oclHashcatWrapper_OLD(verbose=True)
    ocl.hash_type = "100"
    ocl.set_my_ios(
        hash_file='tests/hashes/example100.hash',
        words_ls=['tests/wordlists/example.dict'],
        outfile='tests/crk_strt.txt',
        rules_ls=['rules/best64.rule', 'rules/custom.rule']
    )
    ocl.straight()

