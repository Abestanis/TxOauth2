import os
import sys

#try:
#    import _preamble
#except ImportError:
#    try:
#        sys.exc_clear()
#    except AttributeError:
#    # exc_clear() (and the requirement for it) has been removed from Py3
#       pass


def main():
    # begin chdir armor
    sys.path[:] = map(os.path.abspath, sys.path)
    # end chdir armor
    sys.path.insert(0, os.path.abspath(os.getcwd()))
    from twisted.scripts.trial import run
    run()

if __name__ == '__main__':
    main()
