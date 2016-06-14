import platform

from config.reset_vars_ocl import OCLresetVars


class Scrap(OCLresetVars):

    def __init__(self):
        self.aa = platform.system()
        self.bb = []

    def reset(self):
        print 'hey'
        self._reset()

    def buzz(self,  obj):
        try: obj.start()
        except: print 'nonstt'

    def got_obj(self, obj):
        print self.__dict__
        if obj is self.__dict__[obj][0]: self.will_run()
        else:
            self.__dict__[obj][0].insert(0, obj)
            self.will_run()

        self.will_run()

    def will_run(self): print 'wr'

    def exiter(self): print 'do nothing'




import os, fnmatch

#find the location of sunnyexplorer.exe
def find_files(directory, pattern):
    for root, dirs, files in os.walk(directory):
        for basename in files:
            if fnmatch.fnmatch(basename, pattern):
                filename = os.path.join(root, basename)
                yield filename

for filename in find_files('c','*.exe'):
    print filename
    print ('Found Sunny Explorer data in:', filename)




WALK_ROOT = 'c:/'
def guess_bindir():
    for dirName, subdirList, fileList in os.walk(WALK_ROOT):
        if dirName.find('hashcat') > -1:
            return dirName

# for fname in fileList: print('\t%s' % fname)

if __name__ == '__main__':
    sc = Scrap()
    bindir = guess_bindir()
    print bindir