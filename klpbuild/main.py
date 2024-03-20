import sys

from klpbuild.cmd import main_func


def main():
    sys.tracebacklimit = 0
    main_func(sys.argv[1:])


if __name__ == "__main__":
    main()
