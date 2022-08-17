from viper.common.abstracts import Module
from viper.core.session import __sessions__
import os

class ApkLeaks(Module):
    cmd = 'apkleaks'
    #It recquires to install apkleaks
    description = 'This module run apkleaks for finding potential interesting strings that may be used for pivoting'
    authors = ['Alejandro Prada']
    categories = ['android']

    def run(self):
        self.log('info', "[+] Searching for leaks in the APK.")
        if not __sessions__.is_set():
            # No open session.
            return
        apk_file = __sessions__.current.file.path
        stream = os.popen('apkleaks -f '+apk_file)
        output = stream.read()
        self.log('info', output)
        self.log('info', "[+] Analysis completed")


