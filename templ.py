from datetime import datetime
import jinja2
from pathlib import Path
import os

class Template:
    def __init__(self, cfg, cs):
        self.cfg = cfg
        self.bsc = cfg.bsc

        # Modules like snd-pcm needs to be replaced by snd_pcm in LP_MODULE
        # and in kallsyms lookup
        self._mod = self.cfg.conf.get('mod', '').replace('-', '_')

        if cs:
            self._cs = cs
            self._jcs = self.cfg.codestreams[cs]
            self._ktype = self._jcs['rename_prefix']
            self._files = list(self._jcs['files'].keys())
            self._funcs = []

        self._templ_path = Path(os.path.dirname(__file__), 'templates')

    def GeneratePatchedFuncs(self):
        with open(Path(self.cfg.bsc, 'patched_funcs.csv'), 'w') as f:
            for fun in self._funcs:
                mod = 'vmlinux' if not self._mod else self._mod
                f.write('{} {} klpp_{} IS_ENABLED({})\n'.format(mod, fun, fun,
                    self.cfg.conf['conf']))

    def GenerateLivepatchFile(self, ext, out_name, src_file, ext_file,
            include_header):
        if not out_name and not src_file:
            raise RuntimeError('Both out_name and src_file are empty.  Aborting.')

        if src_file:
            # Will be used when generating patched_funcs.csv
            self._funcs.extend(self._jcs['files'][src_file])

            src_file = str(Path(src_file).name)

            lp_inc_dir = str(Path(self.cfg.get_work_dir(self._cs), 'work_' + src_file))
            lp_file = self.cfg.bsc + '_' + src_file
        else:
            lp_inc_dir = ''
            lp_file = None

        # out_name empty means that we want the final file as:
        #       bscXXXXXXX_{src_name}.c
        if not out_name:
            out_name = lp_file

        fsloader = jinja2.FileSystemLoader([self._templ_path, lp_inc_dir])
        env = jinja2.Environment(loader=fsloader, trim_blocks=True)

        templ = env.get_template('lp-' + ext + '.j2')
        templ.globals['year'] = datetime.today().year
        if self._mod:
            templ.globals['mod'] = self._mod

        if include_header:
            templ.globals['include_header'] = True

        with open(Path(self.cfg.bsc, out_name).with_suffix('.' + ext), 'w') as f:
            f.write(templ.render(bsc = self.cfg.bsc,
                                bsc_num = self.cfg.bsc_num,
                                fname = os.path.splitext(out_name)[0],
                                inc_src_file = lp_file,
                                inc_exts_file = ext_file,
                                cve = self.cfg.conf['cve'],
                                config = self.cfg.conf['conf'],
                                ktype = self._ktype,
                                user = self.cfg.user,
                                email = self.cfg.email,
                                commits = self.cfg.conf['commits']))

    def GenerateLivePatches(self):
        # If the livepatch contains only one file, generate only the livepatch
        # one
        bsc = Path(self.cfg.bsc)
        bsc.mkdir(exist_ok=True)

        # We need at least one header file for the livepatch
        out_name = 'kgr_patch' if self._ktype == 'kgr' else 'livepatch'
        out_name = out_name + '_' + self.cfg.bsc

        self.GenerateLivepatchFile('h', out_name, None, None, False)

        if len(self._files) == 1:
            self.GenerateLivepatchFile('c', out_name, self._files[0], 'exts',
                    True)
            return

        # Run the template engine for each touched source file.
        for src_file in self._files:
            self.GenerateLivepatchFile('c', None, src_file, 'exts', False)

        # One additional file to encapsulate the _init and _clenaup methods
        # of the other source files
        self.GenerateLivepatchFile('c', out_name, None, None, True)

    @staticmethod
    def generate_commit_msg(cfg):
        fsloader = jinja2.FileSystemLoader(Path(os.path.dirname(__file__),
                                            'templates'))
        env = jinja2.Environment(loader=fsloader, trim_blocks=True)

        templ = env.get_template('commit.j2')
        return templ.render(bsc = cfg.bsc,
                            bsc_num = cfg.bsc_num,
                            cve = cfg.conf['cve'],
                            user = cfg.user,
                            email = cfg.email,
                            commits = cfg.conf['commits'])
