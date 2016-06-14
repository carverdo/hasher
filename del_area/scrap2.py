
class AA(object):

    def __init__(self, bd=1, choice='cpu', v=20):
        print bd, choice, v


class BB(AA):

    def __init__(self, choice='cuda', **kwargs):
        super(BB, self).__init__(choice=choice, **kwargs)
        print 'here', choice

bb = BB(bd=2,v=3)