import sys
import logging


def configureLogging(verbosity_level):
    logger = logging.getLogger("")
    logger.setLevel(logging.DEBUG)

    # Create handlers
    c_handler = logging.StreamHandler(sys.stdout)
    logfile = "{0}.log".format(__file__)
    f_handler = logging.FileHandler(logfile)
    if verbosity_level == 0:
        c_handler.setLevel(logging.ERROR)
    elif verbosity_level == 1:
        c_handler.setLevel(logging.INFO)
    elif verbosity_level == 2:
        c_handler.setLevel(logging.DEBUG)
    else:
        print("verbosity level {0} not supported, quitting..".format(verbosity_level))
        exit(1)

    f_handler.setLevel(logging.DEBUG)

    # Create formatters and add it to handlers
    c_format = logging.Formatter('{asctime:s} | {levelname:8s} | {message:s}', style='{')
    f_format = logging.Formatter('{asctime:s} | {levelname:8s} | {message:s}', style='{')
    c_handler.setFormatter(c_format)
    f_handler.setFormatter(f_format)

    # Add handlers to the logger
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)
    return logger
