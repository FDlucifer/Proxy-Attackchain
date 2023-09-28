#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import logging
import sys
class ImpacketFormatter(logging.Formatter):
    def __init__(self):
        logging.Formatter.__init__(self, '%(bullet)s %(message)s \033[0m', None)

    def format(self, record):
        if record.levelno == logging.INFO:
            record.bullet = '[*]'
        elif record.levelno == logging.CRITICAL:
            record.bullet = '\033[1;32;m[+]'
        elif record.levelno == logging.WARNING:
            record.bullet = '[!]'
        elif record.levelno == logging.DEBUG:
            record.bullet = "[*]"
        else:
            record.bullet = '\033[1;31;m[-]'
        return logging.Formatter.format(self, record)


def init():
    # We add a StreamHandler and formatter to the root logger
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ImpacketFormatter())
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)
