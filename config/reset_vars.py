"""
BaseClass for hc_ and ocl_reset_vars.
"""


class resetVars(object):
    def __init__(self):
        # The first 3 (or 4) items can be considered core
        self.hash_type = 0
        self.hash_file = None        # File with target hashes
        self.words_files = []        # List of dictionary files
        self.rules_files = []        # List of rules files
        # Other Files
        self.charset_file = None
        self.debug_file = None
        self.disable_potfile = False
        self.outfile = None
        # Settings for Class
        self.argv = []
        self.bits = 0
        self.defaults_changed = []
        self.masks_file = None
        self.table_file = None
        # Other Settings
        self.hex_salt = False
        self.hex_charset = False
        self.left = False
        self.remove = False
        self.separator = ":"
        self.show = False
        self.username = False
        # Rules, Masks, Charsets
        self.generate_rules = 0
        self.generate_rules_func_min = 1
        self.generate_rules_func_max = 4
        self.custom_charset1 = "?|?d?u"
        self.custom_charset2 = "?|?d"
        self.custom_charset3 = "?|?d*!$@_"
        self.custom_charset4 = None
        self.mask = None
        # misc
        self.debug_mode = None
        self.eula = False
        self.help = False
        self.quiet = False
        self.version = False
