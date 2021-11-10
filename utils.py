import pathlib
import os
import re
import requests

class Setup:
    _dest = ''
    _cs_file = ''
    _rpm_dir = ''
    _ex_dir = ''
    _ipa_dir = ''

    def __init__(self, destination, redownload):
        # Prefer the argument over the environment
        self._dest = destination
        if not self._dest:
            self._dest = os.getenv('KLP_ENV_DIR')

        if not os.path.isdir(self._dest):
            raise ValueError('Destiny should be a directory')

        self._redownload = redownload

        self._cs_file = ''
        self._rpm_dir = pathlib.Path(self._dest, 'kernel-rpms')
        self._ex_dir = pathlib.Path(self._dest, 'ex-kernels')
        self._ipa_dir = pathlib.Path(self._dest, 'ipa-clones')

    def find_cs_file(self, err=False):
        # If KLP_CS_FILE env var is populated, is must be a valid file
        self._cs_file = os.getenv('KLP_CS_FILE')
        if self._cs_file and  not os.path.isfile(self._cs_file):
            raise ValueError(self._cs_file + ' is not a valid file!')

        if not self._cs_file:
            self._cs_file = pathlib.Path(self._dest, 'codestreams.in')

        # If err is true, return error instead of only populare cs_file member
        if err and not os.path.isfile(self._cs_file):
            raise ValueError('Couldn\'t find codestreams.in file')

    def parse_cs(self, sle_version):
        # match = re.search('SLE(\d+)\-?S?P?\d+?_Update_(\d+)', sle_version)
        # if not match:
            # ValueError(sle_version + ' is not a valid codestream')

        # if match.group(3) == 0:
            # maint_repo = 'standard'
            # pkg=''
        # else:

        #SLE15_Update_25
        #SLE15-SP1_Update_18
        print("")

    def download_codestream_file(self):
        self.find_cs_file()

        if os.path.isfile(self._cs_file) and not self._redownload:
            print('Found codestreams.in file, skipping download.')
            return
        elif not self._cs_file:
            self._cs_file = pathlib.Path(self._dest, 'codestreams.in')

        print('Downloading the codestreams.in file into ' + self._cs_file)
        req = requests.get('https://gitlab.suse.de/live-patching/sle-live-patching-data/raw/master/supported.csv')

        # exit on error
        req.raise_for_status()

        first_line = True
        with open(self._cs_file, 'w') as f:
            for line in req.iter_lines():
                # skip empty lines
                if not line:
                    continue

                # skip file header
                if first_line:
                    first_line = False
                    continue

                # remove the last two columns, which are dates of the line
                # and add a fifth field with the forth one + rpm- prefix, and
                # remove the micro version number
                columns = line.decode('utf-8').split(',')
                rpm_name = 'rpm-' + re.sub('\.\d+$', '', columns[2])

                f.write(columns[0] + ',' + columns[1] + ',' + columns[2] + ',,' + rpm_name + '\n')

    def prepare_env(self):
        self.download_codestream_file()
        # FIXME: download the rpms, extract them in the correct places inside
