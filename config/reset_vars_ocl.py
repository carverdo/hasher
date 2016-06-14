from reset_vars import resetVars


class OCLresetVars(resetVars):
    def __init__(self):
        super(OCLresetVars, self).__init__()
        # diff dict vals
        self.outfile_format = 3
        self.segment_size = 1
        # new attrs
        self.benchmark = False
        self.benchmark_mode = 1
        self.bitmap_max = None
        self.cleanup_rules = False
        self.cpu_affinity = None
        self.force = False
        self.generate_rules_seed = None
        self.gpu_accel = None
        self.gpu_async = False
        self.gpu_devices = None
        self.gpu_loops = None
        self.gpu_temp_abort = 90
        self.gpu_temp_disable = False
        self.gpu_temp_retain = 80
        self.hex_wordlist = False
        self.increment = False
        self.increment_max = 54
        self.increment_min = 1
        self.induction_dir = None
        self.keyspace = False
        self.limit = None
        self.loopback = False
        self.markov_classic = False
        self.markov_disable = False
        self.markov_hcstat = None
        self.markov_threshold = 0
        self.outfile_autohex_disable = False
        self.outfile_check_dir = None
        self.outfile_check_timer = None
        self.potfile_disable = False  #todo REPETITION vs disable_pot?
        self.powertune_disable = False
        self.remove_timer = None
        self.restore = False
        self.restore_disable = False
        self.rule_left = ":"
        self.rule_right = ":"
        self.runtime = 0
        self.session = "default_session"
        self.skip = None
        self.status = False
        self.status_automat = False
        self.status_timer = 10
        self.weak_hash_threshold = 100


if __name__ == '__main__':
    ocl = OCLresetVars()
    print ocl.separator
    print ocl.session
