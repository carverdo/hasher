#!/usr/bin/env python
"""
"""
from Queue import Empty
import msgs
from wrappers.wrapper import Backbone


# =======================
# MAIN CLASS: Hashcat CPU
# =======================
class hcHashcatWrapper(Backbone):

    def __init__(self, *args, **kwargs):
        super(hcHashcatWrapper, self).__init__(*args, **kwargs)

    # =================
    # ATTACKS
    # =================
    def straight(self, test=False, a='0', msg=msgs.m_strt_atk):
        """Dictionary-based attack with the option of rules."""
        self.argv = self.build_args()
        self.add_rules()
        self.common_attack_pattern(test, a, msg)

    def combinator(self, test=False, a='1', msg=msgs.m_comby_atk):
        """
        Each word in left dictionary has each word in right dictionary
        added to it; in hashcat straight the left and right are the same dict.
        NB Did not add left and right rules (couldn't get to work)
        """
        self.argv = self.build_args()
        self.common_attack_pattern(test, a, msg)

    def toggle_case(self, toggle_max=16, test=False, a='2', msg=msgs.m_tog_atk):
        """
        Every dictionary word has case toggling applied to EVERY letter
        to create every combination
        """
        self.argv = self.build_args()
        self.argv.insert(0, '--toggle-max={}'.format(toggle_max))
        self.common_attack_pattern(test, a, msg)

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

    def permutation(self, test=False, a='4', msg=msgs.m_perm_atk):
        """
        Each word in dictionary generates all permutations of itself.
        """
        self.argv = self.build_args()
        self.common_attack_pattern(test, a, msg)

    def table_lookup(self, test=False, a='5', msg=msgs.m_tabl_atk):
        """
        Create a lookup table with two columns: the characters in your password
        list and their transforms, e.g. a=a, a=A, a=8 etc.
        """
        self.argv = self.build_args()
        self.common_attack_pattern(test, a, msg)

    # =================
    # QUEUEING & THREADING
    # Different than oclHashcatWrapper
    # because hashcat has a "stdout" cmd switch
    # =================
    def g_stdout(self):
        try:
            return self.q.get_nowait().rstrip()
        except Empty:
            return ""


if __name__ == "__main__":
    """
    from hashes import get_hashes
    hashlist = get_hashes()
    print hashlist
    """
    path_to_exe = 'c:/users/admin/documents/hashcat-2.00'
    # os.chdir(path_to_exe)

    hc = hcHashcatWrapper(verbose=True)
    hc.set_my_ios(hash_file='tests/hashes/hash.txt',
                  words_ls=['wordlists/phpbb.txt'],
                  rules_ls=['rules/combinator.rule'],
                  outfile='tests/Xcrk_phpbb.txt')
    hc.straight()
    # print hc.get_hashes()
