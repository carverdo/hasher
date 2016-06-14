#!/usr/bin/env python
"""
"""
import os
import platform
import struct
import sys
from Queue import Empty
from collections import namedtuple, OrderedDict

import msgs
from wrappers.wrapper import Backbone


# ==========================
# MAIN CLASS: oclHashcat GPU
# ==========================
class oclHashcatWrapper(Backbone):

    def __init__(self, choice='gpu', **kwargs):
        super(oclHashcatWrapper, self).__init__(choice=choice, **kwargs)

    # =================
    # ATTACKS
    # =================
    def straight(self, test=False, a='0', msg=msgs.m_strt_atk):
        self.argv = self.build_args()
        self.add_rules()
        self.common_attack_pattern(test, a, msg)

    def combinator(self, test=False, a='1', msg=msgs.m_comby_atk):
        self.argv = self.build_args()
        try:
            self.argv.insert(0, self.words_files[1])
            self.common_attack_pattern(test, a, msg)
        except IndexError:
            print msgs.m_comby_fail
            return

    def brute_force(self, increment=False, test=False, a='3', msg=msgs.m_bf_atk):
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

    def hybrid_dict_mask(self, test=False, a='6', msg=msgs.m_hydi_atk):
        self.argv = self.build_args()
        mask = self.masks_file or self.mask
        if not mask:
            return
        try:
            self.argv.insert(0, mask)
            self.common_attack_pattern(test, a, msg)
        except IndexError:
            print msgs.m_hydi_fail
            return

    def hybrid_mask_dict(self, test=False, a='7', msg=msgs.m_hyma_atk):
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
    # GET RESULTS
    # =================
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
                    self.msg_pack(msgs.m_restore_fail)
                    return
                if self.bits == "64":
                    fmt = 296
                # 32 bit system
                else:
                    fmt = 288
                fmt = msgs.m_fmt.format(len(self.restore_struct) - fmt)
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
            self.msg_pack(msgs.m_norestore)

    # =================
    # QUEUEING & THREADING
    # =================
    def stdout(self):
        try:
            return self.q.get_nowait().rstrip()
        except Empty:
            return ""

    # =================
    # HELPERS
    # =================
    def build_stub(self, gcard_type):
        if sys.maxsize > 2**32:
            self.bits = "64"
        else:
            self.bits = "32"
        if gcard_type.lower() == "cuda":
            stub, msg = msgs.m_cmd_g, msgs.m_cuda
        else:
            stub, msg = msgs.m_cmd_ng, msgs.m_ocl
        return stub, msg

    def build_cmd(self, tmp):
        if "Win" in platform.system():
            return msgs.m_win, tmp.format('', self.bits, ' ')
        else:
            return msgs.m_lin, tmp.format('./', self.bits, '.bin')



if __name__ == "__main__":
    path_to_exe = 'c:/users/admin/documents/cudaHashcat-2.01'
    os.chdir(path_to_exe)

    ocl = oclHashcatWrapper(verbose=True)
    ocl.hash_type = "100"
    ocl.set_my_ios(
        hash_file='tests/hashes/example100.hash',
        words_ls=['tests/wordlists/example.dict'],
        outfile='tests/Xcrk_strt.txt',
        rules_ls=['rules/best64.rule', 'rules/custom.rule']
    )
    ocl.straight()