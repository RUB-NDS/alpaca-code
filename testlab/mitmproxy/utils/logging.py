import logging
from datetime import datetime
import os


def init_logging(log_level, log_path=""):
    logging.basicConfig(level=log_level, format='%(asctime)s %(name)-15s %(levelname)-8s %(message)s',
                        datefmt='%d.%m.%Y %H:%M')

    if log_path:
        if not os.path.exists(log_path):
            os.makedirs(log_path)

        filename = "xprotocol_{}.log".format(datetime.now().strftime("%Y%m%d_%H%M%S"))
        fh = logging.FileHandler("{}/{}".format(log_path, filename), 'w')
        fh.setLevel(log_level)

        formatter = logging.Formatter('%(asctime)s %(name)-15s %(levelname)-8s %(message)s')
        fh.setFormatter(formatter)
        logging.getLogger().addHandler(fh)


def _log(logger, message, level):
    logging.getLogger(logger).log(level, message)


def _info(logger, message):
    _log(logger, message, logging.INFO)


def _debug(logger, message):
    _log(logger, message, logging.DEBUG)


def _warning(logger, message):
    _log(logger, message, logging.WARNING)


def _error(logger, message):
    _log(logger, message, logging.ERROR)


def _exception(logger, message):
    logging.getLogger(logger).exception(message)
