from datetime import datetime
import git
import jinja2
import pathlib

class Template:
    _mod = ''
    _bsc = ''
    _cve = ''
    _conf = ''
    _ktype = ''
    _env = None

    def __init__(self, mod, vmlinux, bsc, cve, conf, ktype):
        # TODO: get these values from a file created by prepare command
        self._mod = mod
        self._bsc = bsc
        self._cve = cve
        self._conf = conf
        self._ktype = ktype
        try:
            conf = git.GitConfigParser()
            self._user = conf.get_value('user', 'name')
            self._email = conf.get_value('user', 'email')
        except:
            raise RuntimeError('Please define name/email in global git config')

        if not mod and not vmlinux:
            raise ValueError('Either --mod or --vmlinux needs to be specified')

        if mod and vmlinux:
            raise ValueError('You can\'t specify both --mod and --vmlinux')

        self._env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'), \
                    trim_blocks=True)

    def GenerateLivePatches(self):
        fname = 'kgr_patch' if self._ktype == 'kgr' else 'livepatch'
        fname = fname + '_' + self._bsc

        bsc = pathlib.Path(self._bsc)
        bsc.mkdir(exist_ok=True)

        for ext in ['h', 'c']:
            templ = self._env.get_template('lp-' + ext + '.j2')

            templ.globals['year'] = datetime.today().year

            if self._mod:
                templ.globals['mod'] = self._mod

            lp_file = pathlib.Path(bsc, fname + '.' + ext)
            with open(lp_file, 'w') as f:
                f.write(templ.render(bsc = self._bsc,
                                    cve = self._cve,
                                    config = self._conf,
                                    ktype = self._ktype,
                                    user = self._user,
                                    email = self._email))
