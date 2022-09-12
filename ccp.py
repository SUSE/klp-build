import json
from pathlib import Path, PurePath
from natsort import natsorted
import os
import re
import shutil
import subprocess

import concurrent.futures

class CCP:
    def __init__(self, cfg):
        self.cfg = cfg
        self._proc_files = []

        self.env = os.environ

        gcc_ver = subprocess.check_output(['gcc', '-dumpversion']).decode().strip()
        # gcc12 has a problem with kernel and xrealloc implementation
        if gcc_ver != '12':
            self.cc = 'gcc'
        # if gcc12 is the default compiler, check if gcc11 is available
        elif gcc_ver == '12' and shutil.which('gcc-11'):
            self.cc = 'gcc-11'
        else:
            raise RuntimeError('Only gcc12 is available, and it\'s problematic with kernel sources')

        # the current blacklisted function, more can be added as necessary
        self.env['KCP_EXT_BLACKLIST'] = "__xadd_wrong_size,__bad_copy_from,__bad_copy_to,rcu_irq_enter_disabled,rcu_irq_enter_irqson,rcu_irq_exit_irqson,verbose,__write_overflow,__read_overflow,__read_overflow2,__real_strnlen,twaddle,set_geometry,valid_floppy_drive_params"

    def unquote_output(self, matchobj):
        return matchobj.group(0).replace('"', '')

    def process_make_output(self, filename, output, sle, sp):
        fname = str(filename)

        ofname = '.' + filename.name.replace('.c', '.o.d')
        ofname = Path(filename.parent, ofname)

        cmd_args_regex = '(-Wp,{},{}\s+-nostdinc\s+-isystem.*{});'

        result = re.search(cmd_args_regex.format('-MD', ofname, fname), str(output).strip())
        if not result:
            # 15.4 onwards changes the regex a little: -MD -> -MMD
            result = re.search(cmd_args_regex.format('-MMD', ofname, fname), str(output).strip())

        if not result:
            raise RuntimeError(f'Failed to get the kernel cmdline for file {str(ofname)} in {sle}{sp}')

        # some strings  have single quotes around double quotes, so remove the
        # outer quotes
        output = result.group(1).replace('\'', '')

        # also remove double quotes from macros like -D"KBUILD....=.."
        output = re.sub('-D"KBUILD_([\w\#\_\=\(\)])+"', self.unquote_output, output)

        # -flive-patching and -fdump-ipa-clones are only present in upstream gcc
        # 15.4u0 options
        # -fno-allow-store-data-races and -Wno-zero-length-bounds
        # 15.4u1 options
        # -mindirect-branch-cs-prefix appear in 15.4u1
        # more options to be removed
        # -mharden-sls=all
        for opt in ['-flive-patching=inline-clone', '-fdump-ipa-clones',
                '-fno-allow-store-data-races', '-Wno-zero-length-bounds',
                '-mindirect-branch-cs-prefix', '-mharden-sls=all']:
            output = output.replace(opt, '')

        if int(sle) >= 15 and int(sp) >= 2:
            output += ' -D_Static_assert(e,m)='

        return output

    def get_make_cmd(self, filename, jcs, odir):
        filename = PurePath(filename)
        file_ = filename.with_suffix('.o')
        completed = subprocess.run(['make', '-sn', f'CC={self.cc}',
                                    f'HOSTCC={self.cc}', file_], cwd=odir,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, check=True)

        return self.process_make_output(filename, completed.stdout.decode(),
                                        jcs['sle'], jcs['sp'])

    # extract the last component of the path, like the basename bash # function
    def lp_out_file(self, fname):
        return self.cfg.bsc + '_' + PurePath(fname).name

    def execute_ccp(self, jcs, fname, funcs, out_dir, sdir, odir, env):
        lp_out = Path(out_dir, self.lp_out_file(fname))
        ppath = self.cfg.pol_path

        ccp_args = [self.cfg.ccp_path]
        for arg in ['may-include-header', 'can-externalize-fun', 'shall-externalize-fun', 'shall-externalize-obj',
                'modify-externalized-sym', 'rename-rewritten-fun']:
            ccp_args.append(f'--pol-cmd-{arg}={ppath}/kgr-ccp-pol-{arg}.sh')

        ccp_args.append(f'--pol-cmd-modify-patched-fun-sym={ppath}/kgr-ccp-pol-modify-patched-sym.sh')

        ccp_args.extend(['--compiler=x86_64-gcc-9.1.0', '-i', f'{funcs}',
                        '-o', f'{str(lp_out)}', '--'])

        ccp_args.extend(self.get_make_cmd(fname, jcs, odir).split(' '))

        ccp_args = list(filter(None, ccp_args))

        with open(Path(out_dir, 'klp-ccp.out'), 'w') as f:
            subprocess.run(ccp_args, cwd=odir, stdout=f, stderr=f, env=env,
                        check=True)

		# Remove the local path prefix of the klp-ccp generated comments
        # Open the file, read, seek to the beginning, write the new data, and
        # then truncate (which will use the current position in file as the
        # size)
        with open(str(lp_out), 'r+') as f:
            file_buf = f.read()
            f.seek(0)
            f.write(file_buf.replace(f'from {str(sdir)}/', 'from '))
            f.truncate()

		# Generate the list of exported symbols
        exts = []

        for ext_file in ['fun_exts', 'obj_exts']:
            ext_path = Path(out_dir, ext_file)
            if not ext_path.exists():
                continue

            with open(ext_path) as f:
                for l in f:
                    l = l.strip()
                    if not l.startswith('KALLSYMS'):
                        continue

                    _, sym, var, mod = l.split(' ')
                    if mod == 'vmlinux':
                        mod = ''

                    exts.append( (sym, var, mod) )

        exts.sort(key=lambda tup : tup[0])

        ext_list = []
        for ext in exts:
            sym, var, mod = ext

            sym = f'\t{{ "{sym}",'
            if not mod:
                var = f' (void *)&{var} }},'
            else:
                var = f' (void *)&{var},'
                mod = f' "{mod}" }},'

            # 73 here is because a tab is 8 spaces, so 72 + 8 == 80, which is
            # our goal when splitting these lines
            if len(sym + var + mod) < 73:
                ext_list.append(sym + var + mod)

            elif len(sym + var) < 73:
                ext_list.append(sym + var)
                if mod:
                    ext_list.append('\t ' + mod)

            else:
                ext_list.append(sym)
                if len(var + mod) < 73:
                    ext_list.append(f'\t {var}{mod}')
                else:
                    ext_list.append(f'\t {var}')
                    if mod:
                        ext_list.append(f'\t {mod}')

        with open(Path(out_dir, 'exts'), 'w') as f:
            f.write('\n'.join(ext_list))

    # Group all codestreams that share code in a format like bellow:
    #   { '15.2u10' : [ 15.2u11 15.3u10 15.3u12 ] }
    # Will be converted to:
    #   15.2u10-11 15.3u10 15.3u12
    # The returned value will be a list of lists, each internal list will
    # contain all codestreams which share the same code
    def classify_codestreams(self, cs_dict):
        file_cs_list = []
        for cs in cs_dict.keys():

            # Group all codestreams that share the same codestream by a new dict
            # divided by the SLE version alone, making it easier to process
            # later
            cs_group = {}
            relatives = [cs] + cs_dict[cs]
            for l in [cs] + cs_dict[cs]:
                prefix, up = l.split('u')
                if not cs_group.get(prefix, ''):
                    cs_group[prefix] = [up]
                else:
                    cs_group[prefix].append(up)

            cs_list = []
            for g in cs_group.keys():
                similars = [int(cs_group[g].pop(0))]

                while True:
                    if not cs_group[g]:
                        break

                    r = int(cs_group[g].pop(0))
                    if r == similars[len(similars) - 1] + 1:
                        similars.append(r)
                        continue

                    # Current one is different, dump what we stored and clean
                    # similars
                    if len(similars) == 1:
                        cs_list.append('{}u{}'.format(g, similars[0]))
                    else:
                        cs_list.append('{}u{}-{}'.format(g, similars[0],
                            similars[len(similars) - 1]))

                    similars = [r]

                if len(similars) == 1:
                    cs_list.append('{}u{}'.format(g, similars[0]))
                else:
                    cs_list.append('{}u{}-{}'.format(g, similars[0],
                                        similars[len(similars) - 1]))

            file_cs_list.append(cs_list)

        return natsorted(file_cs_list)

    def group_equal_files(self):
        codestreams = []
        files = {}
        cs_groups = {}

        print('\nGrouping codestreams for each file processed by ccp:')

        # Use set to remove duplicated names
        for fname in set(self._proc_files):
            src_out = self.lp_out_file(fname)

            for fsrc in Path(self.cfg.bsc_path, 'c').rglob(src_out):
                with open(fsrc, 'r+') as fi:
                    buf = fi.read()

                    # get the cs from the file path
                    # /<rootfs>/.../bsc1197705/c/15.3u4/x86_64/work_cls_api.c/bsc1197705_cls_api.c
                    cs = fsrc.parts[-4]

                    m = re.search('#include "(.+kconfig.h)"', buf)
                    if not m:
                        raise RuntimeError(f'File {str(fsrc)} without an include to kconfig.h')

                    kconfig = m.group(1)

                    # check for duplicate kconfig lines
                    for c in codestreams:
                        if kconfig == files[c]['kconfig']:
                            raise RuntimeError(f'{cs}\'s kconfig is the same of {c}')

                    src = re.sub('#include ".+kconfig.h"', '', buf)

                    # Remove any mentions to klpr_trace, since it's currently
                    # buggy in klp-ccp
                    src = re.sub('.+klpr_trace.+', '', src)

                    codestreams.append(cs)
                    files[cs] = { 'kconfig' : kconfig, 'src' : src }

            members = {}
            # rglob can list codestreams unordered
            codestreams = natsorted(codestreams)
            toprocess = codestreams.copy()

            while len(toprocess):
                # in the second pass processed will contain data
                if not toprocess:
                    break

                codestreams = toprocess.copy()

                c = codestreams.pop(0)
                toprocess.remove(c)
                members[c] = []

                while True:
                    if not len(codestreams):
                        break

                    cs = codestreams.pop(0)
                    if files[c]['src'] == files[cs]['src']:
                        members[c].append(cs)
                        toprocess.remove(cs)

            # members will contain a dict with the key as a codestream and the
            # values will be a list of codestreams that share the code
            cs_groups[fname] = self.classify_codestreams(members)

        with open(Path(self.cfg.bsc_path, 'groups.json'), 'w') as f:
            f.write(json.dumps(cs_groups, indent=4))

        for file in cs_groups.keys():
            print(f'\t{file}')

            for css in cs_groups[file]:
                print(f"\t\t{' '.join(css)}")

    def process_ccp(self, cs):
        jcs = self.cfg.codestreams[cs]

        sdir = Path(self.cfg.ex_dir, jcs['cs'], 'usr', 'src', 'linux-' + jcs['kernel'])
        odir = Path(str(sdir) + '-obj', 'x86_64', 'default')

        # Needed, otherwise threads would interfere with each other
        env = self.env.copy()

        env['KCP_MOD_SYMVERS'] = str(Path(odir, 'Module.symvers'))
        env['KCP_READELF'] = jcs['readelf']
        env['KCP_KBUILD_ODIR'] = str(odir)
        env['KCP_KBUILD_SDIR'] = str(sdir)
        env['KCP_PATCHED_OBJ'] = jcs['object']
        env['KCP_RENAME_PREFIX'] = 'klp'

        for fname, funcs in jcs['files'].items():
            print(f'\t{cs}\t\t{fname}')

            self._proc_files.append(fname)
            base_fname = Path(fname).name

            out_dir = Path(self.cfg.get_work_dir(cs), f'work_{base_fname}')
            # remove any previously generated files
            shutil.rmtree(out_dir, ignore_errors=True)
            out_dir.mkdir(parents=True, exist_ok=True)
            # create symlink to the respective codestream file
            os.symlink(Path(sdir, fname), Path(out_dir, base_fname))
            env['KCP_WORK_DIR'] = str(out_dir)

            env['KCP_IPA_CLONES_DUMP'] = str(Path(self.cfg.get_ipa_dir(jcs['cs']),
                                                f'{fname}.000i.ipa-clones'))

            self.execute_ccp(jcs, fname, ','.join(funcs), out_dir, sdir, odir,
                    env)

    def run_ccp(self):
        print(f'Work directory: {self.cfg.bsc_path}')

        # working_cs could be populated by the setup
        if not self.cfg.working_cs:
            self.cfg.working_cs = self.cfg.filter_cs(self.cfg.codestreams.keys(), True)

        print('\nRunning klp-ccp...')
        print('\tCodestream\tFile')
        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            results = executor.map(self.process_ccp, self.cfg.working_cs)
            for result in results:
                if result:
                    print(f'{cs}: {result}')

        self.group_equal_files()
