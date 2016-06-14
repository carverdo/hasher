"""
class HCVars(object):
    # Tailor
    config.HASH_TYPE_DICT.update(config.HC_HASH_TYPE_DICT)
    config.CMD_SHORT_SWITCH.update(config.HC_CMD_SHORT_SWITCH)
    config.CMD_EQUAL_REQUIRED += config.HC_CMD_EQUAL_REQUIRED
    config.IGNORE_VARS += config.HC_IGNORE_VARS
    # Apply
    hash_type_dict = config.HASH_TYPE_DICT
    cmd_short_switch = config.CMD_SHORT_SWITCH
    cmd_equal_required = config.CMD_EQUAL_REQUIRED
    ignore_vars = config.IGNORE_VARS
"""

