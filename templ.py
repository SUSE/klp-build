import jinja2
from datetime import datetime

class Template:
    _mod = ''
    _bsc = ''
    _cve = ''
    _conf = ''
    _ktype = ''
    _env = None

    def __init__(self, mod, bsc, cve, conf, ktype):
        # TODO: get these values from a file created by prepare command
        self._mod = mod
        self._bsc = bsc
        self._cve = cve
        self._conf = conf
        self._ktype = ktype

        self._env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'), \
                    trim_blocks=True)

    def GenerateLivePatches(self):
        fname = 'kgraft_patch' if self._ktype == 'kgr' else 'livepatch'
        fname = fname + '_' + self._bsc

        for ext in ['h', 'c']:
            templ = self._env.get_template('lp-' + ext + '.j2')

            templ.globals['year'] = datetime.today().year

            with open(fname + '.' + ext, 'w') as f:
                f.write(templ.render(mod = self._mod,
                                    bsc = self._bsc,
                                    cve = self._cve,
                                    config = self._conf,
                                    ktype = self._ktype))
