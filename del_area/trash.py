
import config



class Odd(object):

    def __init__(self):
        self.c = 100

class Par(object):

    def __init__(self, a, b):
        super(Par, self).__init__()
        self.a = a
        self.b = b

class Conf(object):
    y = 10
    z = 11

class Son(Par, Odd, Conf):
    def __init__(self, *args):
        super(Son, self).__init__(*args)


class Fried(object):
    def __init__(self):
        self.fr = 'fr'
        print config.HCresetVars().__dict__
        for name, value in config.HCresetVars().__dict__.items():
            print name, value
            object.__setattr__(self, name, value)

if __name__ == '__main__':
    ss = Son(1,2)
    ff = Fried()