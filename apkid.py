from viper.common.abstracts import Module
from viper.core.session import __sessions__
import os

class ApkId(Module):
    cmd = 'apkid'
    #It recquires to install APKiD
    description = 'This module runs APKiD for finding more information about how an APK was made. Similar to PEiD but for Android'
    authors = ['Alejandro Prada']
    categories = ['android']

    def run(self):
        self.log('info', "[+] Running APKiD")
        if not __sessions__.is_set():
            # No open session.
            return
        apk_file = __sessions__.current.file.path
        stream = os.popen('apkid '+apk_file)
        output = stream.read()
        self.log('info', output)
        self.log('info', "[+] Analysis completed")
