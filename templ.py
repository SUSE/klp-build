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
        self._mod = self.cfg.conf.get('mod', '')
        if self._mod:
            self._mod = self._mod.replace('-', '_')

        self.cs = cs
        self.cs_data = self.cfg.codestreams[cs]

    def GeneratePatchedFuncs(self):
        mod = 'vmlinux' if not self._mod else self._mod
        conf = self.cfg.conf['conf']
        if conf:
                conf = f' IS_ENABLED({conf})'

        with open(Path(self.bsc, 'patched_funcs.csv'), 'w') as f:
            for _, funcs in self.cs_data['files'].items():
                for func in funcs:
                    f.write(f'{mod} {func} klpp_{func}{conf}\n')

    def __GenerateLivepatchFile(self, ext, out_name, src_file, ext_file,
            include_header):
        if not out_name and not src_file:
            raise RuntimeError('Both out_name and src_file are empty.  Aborting.')

        if src_file:
            src_file = str(Path(src_file).name)

            lp_inc_dir = str(Path(self.cfg.get_work_dir(self.cs), 'work_' + src_file))
            lp_file = self.bsc + '_' + src_file
        else:
            lp_inc_dir = ''
            lp_file = None

        # out_name empty means that we want the final file as:
        #       bscXXXXXXX_{src_name}.c
        if not out_name:
            out_name = lp_file

        fsloader = jinja2.FileSystemLoader([Path(os.path.dirname(__file__),
                                            'templates'), lp_inc_dir])
        env = jinja2.Environment(loader=fsloader, trim_blocks=True)

        templ = env.get_template('lp-' + ext + '.j2')
        templ.globals['year'] = datetime.today().year
        if self._mod:
            templ.globals['mod'] = self._mod

        # 15.4 onwards we don't have module_mutex, so template generate
        # different code
        sle = int(self.cs_data['sle'])
        sp = int(self.cs_data['sp'])
        if sle < 15 or (sle == 15 and sp < 4):
                templ.globals['mod_mutex'] = True

        if include_header:
            templ.globals['include_header'] = True

        with open(Path(self.bsc, out_name).with_suffix('.' + ext), 'w') as f:
            f.write(templ.render(bsc = self.bsc,
                                bsc_num = self.cfg.bsc_num,
                                fname = os.path.splitext(out_name)[0],
                                inc_src_file = lp_file,
                                inc_exts_file = ext_file,
                                cve = self.cfg.conf['cve'],
                                config = self.cfg.conf['conf'],
                                user = self.cfg.user,
                                email = self.cfg.email,
                                commits = self.cfg.conf['commits']))

    def GenerateLivePatches(self):
        # If the livepatch contains only one file, generate only the livepatch
        # one
        bsc = Path(self.bsc)
        bsc.mkdir(exist_ok=True)

        # We need at least one header file for the livepatch
        out_name = 'livepatch_' + self.bsc

        self.__GenerateLivepatchFile('h', out_name, None, None, False)

        files = self.cs_data['files']
        if len(files.keys()) == 1:
            self.__GenerateLivepatchFile('c', out_name, next(iter(files)), 'exts',
                    True)
            return

        # Run the template engine for each touched source file.
        for src_file, funcs in files.items():
            self.__GenerateLivepatchFile('c', None, src_file, 'exts', False)

        # One additional file to encapsulate the _init and _clenaup methods
        # of the other source files
        self.__GenerateLivepatchFile('c', out_name, None, None, True)

    @staticmethod
    def generate_commit_msg_file(cfg):
        fsloader = jinja2.FileSystemLoader(Path(os.path.dirname(__file__),
                                            'templates'))
        env = jinja2.Environment(loader=fsloader, trim_blocks=True)

        templ = env.get_template('commit.j2')
        buf = templ.render(bsc = cfg.bsc,
                            bsc_num = cfg.bsc_num,
                            cve = cfg.conf['cve'],
                            user = cfg.user,
                            email = cfg.email,
                            commits = cfg.conf['commits'])

        with open(Path(cfg.bsc_path, 'commit.msg'), 'w') as f:
            f.write(buf)
