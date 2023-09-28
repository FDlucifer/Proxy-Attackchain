#!/usr/bin/env python
# -*- coding: UTF-8 -*-


class global_var:
    success = False
    fail = False
    getpriv = False
    restore = ""


def set_suc(status):
    global_var.success = status


def get_suc():
    return global_var.success


def set_fail(status):
    global_var.fail = status


def get_fail():
    return global_var.fail


def set_priv(status):
    global_var.getpriv = status


def get_priv():
    return global_var.getpriv


def set_restore(rfile):
    global_var.restore = rfile


def get_restore():
    return global_var.restore
