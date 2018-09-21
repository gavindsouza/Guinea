# imports - module imports
from Guinea.util.sniffer import sniff


def main():
    code = 0
    # TBD: app was intended to be a suite of various applications
    # the various services would be shown as a drop-down menu in this function
    # currently only sniff module exists
    try:
        sniff()
    except (KeyboardInterrupt, SystemExit):
        print("Program Stopped")
    return code


if __name__ == "__main__":
    main()
