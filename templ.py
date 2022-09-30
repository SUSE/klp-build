from datetime import datetime
import git
import jinja2
from pathlib import Path
import os

class Template:
    def __init__(self, cfg):
        self.cfg = cfg

        # Modules like snd-pcm needs to be replaced by snd_pcm in LP_MODULE
        # and in kallsyms lookup
        self.mod = self.cfg.conf.get('mod', '').replace('-', '_')

        try:
            git_data = git.GitConfigParser()
            self.user = git_data.get_value('user', 'name')
            self.email = git_data.get_value('user', 'email')
        except:
            raise ValueError('Please define name/email in global git config')

    def GeneratePatchedFuncs(self, lp_path, files):
        conf = self.cfg.conf['conf']
        if conf:
            conf = f' IS_ENABLED({conf})'

        with open(Path(lp_path, 'patched_funcs.csv'), 'w') as f:
            for _, funcs in files.items():
                for func in funcs:
                    f.write(f'{self.mod} {func} klpp_{func}{conf}\n')

    def get_template(self, cs, template, inc_dir):
        loaddirs = [Path(os.path.dirname(__file__), 'templates')]
        if inc_dir:
            loaddirs.append(inc_dir)

        fsloader = jinja2.FileSystemLoader(loaddirs)
        env = jinja2.Environment(loader=fsloader, trim_blocks=True)
        templ = env.get_template(template)

        templ.globals['year'] = datetime.today().year
        templ.globals['bsc'] = self.cfg.bsc
        templ.globals['bsc_num'] = self.cfg.bsc_num
        templ.globals['cve'] = self.cfg.conf['cve']
        templ.globals['commits'] = self.cfg.conf['commits']
        templ.globals['user'] = self.user
        templ.globals['email'] = self.email

        # We don't have a specific codestreams when creating the commit file
        if not cs:
            return templ

        # 15.4 onwards we don't have module_mutex, so template generate
        # different code
        sle, sp, _ = self.cfg.get_cs_tuple(cs)
        if sle < 15 or (sle == 15 and cs_data['sp'] < 4):
            templ.globals['mod_mutex'] = True

        if self.mod != 'vmlinux':
            templ.globals['mod'] = mod

        if self.cfg.conf['conf']:
            templ.globals['config'] = self.cfg.conf['conf']

        return templ

    def __GenerateLivepatchFile(self, lp_path, cs, ext, src_file, use_src_name=False):
        if src_file:
            lp_inc_dir = str(Path(self.cfg.get_work_dir(cs), 'work_' + src_file))
            lp_file = f'{self.cfg.bsc}_{src_file}'
        else:
            lp_inc_dir = None
            lp_file = None

        # if use_src_name is True, the final file will be:
        #       bscXXXXXXX_{src_name}.c
        # else:
        #       livepatch_bscXXXXXXXX.c
        if use_src_name:
            out_name = lp_file
        else:
            out_name = f'livepatch_{self.cfg.bsc}.{ext}'

        fname = Path(out_name).with_suffix('')
        templ = self.get_template(cs, 'lp-' + ext + '.j2', lp_inc_dir)

        if 'livepatch_' in out_name and ext == 'c':
            templ.globals['include_header'] = True

        if ext == 'c' and src_file:
            templ.globals['inc_exts_file'] = 'exts'

        with open(Path(lp_path, out_name), 'w') as f:
            f.write(templ.render(fname = fname, inc_src_file = lp_file))

    def GenerateLivePatches(self, cs):
        cs_data = self.cfg.codestreams[cs]

        lp_path = self.cfg.get_cs_lp_dir(cs)
        lp_path.mkdir(exist_ok=True)

        files = cs_data['files']
        self.GeneratePatchedFuncs(lp_path, files)

        self.__GenerateLivepatchFile(lp_path, cs, 'h', None)

        # If the livepatch touches only one file the final livepatch file will
        # be names livepatch_XXXX
        if len(files.keys()) == 1:
            src = Path(list(files.keys())[0]).name
            self.__GenerateLivepatchFile(lp_path, cs, 'c', src)
            return

        # Run the template engine for each touched source file.
        for src_file, _ in files.items():
            src = str(Path(src_file).name)
            self.__GenerateLivepatchFile(lp_path, cs, 'c', src, True)

        # One additional file to encapsulate the _init and _clenaup methods
        # of the other source files
        self.__GenerateLivepatchFile(lp_path, cs, 'c', None)

    def generate_commit_msg_file(self):
        templ = self.get_template(None, 'commit.j2', None)

        with open(Path(self.cfg.bsc_path, 'commit.msg'), 'w') as f:
            f.write(templ.render())
