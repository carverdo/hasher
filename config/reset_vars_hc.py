from reset_vars import resetVars


class HCresetVars(resetVars):
    def __init__(self):
        super(HCresetVars, self).__init__()
        # diff dict vals
        self.outfile_format = 0
        self.segment_size = 32
        # new attrs
        self.stdout = False
        self.salt_file = None
        self.threads = 8
        self.words_skip = 0
        self.words_limit = 0
        self.toggle_min = 1
        self.toggle_max = 16
        self.pw_min = 1
        self.pw_max = 10
        self.perm_min = 2
        self.perm_max = 10
        self.table_min = 2
        self.table_max = 10
        self.default = None


if __name__ == '__main__':
    hrv = HCresetVars()
    print hrv.separator
    print hrv.perm_max
