import shutil

from viper.common.abstracts import Module
from viper.core.session import __sessions__
import codecs
import os

try:
    import yara

    HAVE_Y = True
except ImportError:
    HAVE_Y = False


class YaraAndroid(Module):
    cmd = 'yarandroid'
    # It recquires to install apktool.
    description = 'This module allows you to scan with Yara all the files within an Android Application.'
    authors = ['Alejandro Prada']
    categories = ['Android', 'static analysis', 'triage']

    def __init__(self):
        super(YaraAndroid, self).__init__()
        if not HAVE_Y:
            self.log('error', 'Missing dependency, install python-yara (`pip install python-yara`)')
            return
        self.parser.add_argument('-r', '--rules', help='Path to the yara index file.')
        self.parser.add_argument('-c', '--create', help='Creates an index file with all '
                                                        'your yara rules. It needs the path'
                                                        ' to the folder with the rules. ')

    def matches_callback(self, data):
        self.log('info', 'Match of rule: ' + data['rule'] + ":")
        for s in data['strings']:
            #self.log('info', s)
            self.log('info', "0x" + str(s[0]) + ":" + s[1] + ": " + str(s[2]))
        self.log('info', '\b')

        return yara.CALLBACK_CONTINUE

    def scan_directory(self, compiled_yara_rules, scan_dir):
        match_list = []
        for folder, subfolders, files in os.walk(scan_dir):
            for file in files:
                path = os.path.join(folder, file)
                try:
                    file_name, file_extension = os.path.splitext(file)
                    if file_extension in ['.so', '.xml', '.dex', '.smali', '.properties']:
                        with codecs.open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            matches = compiled_yara_rules.match(data=f.read(), externals={'filename': file},
                                                                callback=self.matches_callback,
                                                                which_callbacks=yara.CALLBACK_MATCHES)
                        if len(matches) > 0:
                            match_list.append(matches)
                except Exception as e:
                    self.log('info', e)
                    pass
        return match_list

    def create_yara_index(self, path_rules):
        yara_rules = os.listdir(path_rules)
        yara_rules_dir = {}
        self.log('info', 'Creating Yara index.')
        with open(path_rules + 'malware_android_index.yar', 'w+') as f:
            for y in yara_rules:
                if 'malware_android_index.yar' not in y:
                    self.log('info', 'Adding ' + y + ' to the index.')
                    yara_rules_dir[y] = path_rules + "yara_rules/" + y
                    f.write("include " + "\"" + path_rules + y + "\"")
                    f.write('\n')
        self.log('info', 'malware_android_index.yar file has been created.')

    def clean_tmp(self,filepath):
        try:
            shutil.rmtree(filepath)
        except OSError as error:
            self.log('info', error)
            self.log('info', 'The folder at tmp containing the decompiled files was not removed.')

    def run(self):
        super(YaraAndroid, self).run()
        if not __sessions__.is_set():
            # No open session.
            return
        if self.args is None:
            self.log('error', 'you need to pass an argument.')
            return
        else:
            if self.args.create:
                path_rules = self.args.create
                self.create_yara_index(path_rules)

            if self.args.rules:
                path_index = self.args.rules
                rules = yara.compile(path_index)
                self.log('info', "Decompiling APK ...")
                apk_file = __sessions__.current.file.path
                filename = apk_file.split("/")[-1].replace(".apk", "")
                stream = os.popen('apktool d -r -s ' + apk_file + " -o /tmp/" + filename)
                output = stream.read()
                self.log('info', output)
                self.log('info', 'Scanning files within APK with Yara ...')
                self.log('info', 'Scanning ' + apk_file.replace(".apk", ""))
                yara_matches = self.scan_directory(rules, "/tmp/" + filename)
                if len(yara_matches) == 1:
                    self.log('info', 'There is 1 match.')
                    self.log('info', str(yara_matches))
                elif len(yara_matches) > 1:
                    self.log('info', 'There are ' + str(len(yara_matches)) + ' matches.')
                    for y in yara_matches:
                        self.log('info', '\t' + " " + str(y[0]))
                else:
                    self.log('info', 'There aren\'t matches')
                self.clean_tmp("/tmp/"+filename)
                self.log('info', "Analysis completed.")
