import json
import pathlib
import os
import re
import shutil
import subprocess

class CCP:
    _cs = None
    _conf = None

    def __init__(self, cfg):
        with open(pathlib.Path(cfg.bsc_path, 'codestreams.json')) as f:
            self._cs = json.loads(f.read())

        with open(pathlib.Path(cfg.bsc_path, 'conf.json')) as f:
            self._conf = json.loads(f.read())

        self.cfg = cfg
        self._proc_files = []

    def unquote_output(self, matchobj):
        return matchobj.group(0).replace('"', '')

    def process_make_output(self, filename, output, sle, sp):
        fname = str(filename)

        ofname = '.' + filename.name.replace('.c', '.o.d')
        ofname = pathlib.Path(filename.parent, ofname)

        # FIXME: is this regex accurate?
        cmd_args_regex = '(-Wp,-MD,{} -nostdinc -isystem.*{});'.format(ofname, fname)
        result = re.search(cmd_args_regex, str(output).strip())
        if not result:
            return None

        # some strings  have single quotes around double quotes, so remove the
        # outer quotes
        output = result.group(1).replace('\'', '')

        # also remove double quotes from macros like -D"KBUILD....=.."
        output = re.sub('-D"KBUILD_([\w\#\_\=\(\)])+"', self.unquote_output, output)

        # -flive-patching and -fdump-ipa-clones are only present in upstream gcc
        output = output.replace('-flive-patching=inline-clone', '')
        output = output.replace('-fdump-ipa-clones', '')

        if int(sle) >= 15 and int(sp) >= 2:
            output += ' -D_Static_assert(e,m)='

        return output

    def get_make_cmd(self, filename, jcs, odir):
        filename = pathlib.PurePath(filename)
        file_ = filename.with_suffix('.o')
        completed = subprocess.run(['make', '-sn', file_], cwd=odir, capture_output=True, text=True)
        if completed.returncode != 0:
            raise RuntimeError('klp-ccp returned {}, stderr: {}'.format(completed.returncode, completed.stderr))
        return self.process_make_output(filename, completed.stdout, jcs['sle'], jcs['sp'])

    # extract the last component of the path, like the basename bash # function
    def lp_out_file(self, fname):
        return self.cfg.bsc + '_' + pathlib.PurePath(fname).name

    def execute_ccp(self, jcs, fname, funcs, out_dir, sdir, odir):
        ccp_path = '/home/mpdesouza/kgr/ccp/build/klp-ccp'
        pol_path = '/home/mpdesouza/kgr/scripts/ccp-pol'
        lp_out = pathlib.Path(out_dir, self.lp_out_file(fname))

        ccp_args = [ccp_path]
        for arg in ['may-include-header', 'can-externalize-fun', 'shall-externalize-fun', 'shall-externalize-obj',
                'modify-externalized-sym', 'rename-rewritten-fun']:
            ccp_args.append('--pol-cmd-{0}={1}/kgr-ccp-pol-{0}.sh'.format(arg, pol_path))

        ccp_args.append('--pol-cmd-modify-patched-fun-sym={}/kgr-ccp-pol-modify-patched-sym.sh'.format(pol_path))

        ccp_args.extend(['--compiler=x86_64-gcc-9.1.0', '-i', '{}'.format(funcs),
                        '-o', '{}'.format(str(lp_out)), '--'])

        ccp_args.extend(self.get_make_cmd(fname, jcs, odir).split(' '))

        ccp_args = list(filter(None, ccp_args))

        completed = subprocess.run(ccp_args, cwd=odir, text=True, capture_output=True)
        if completed.returncode != 0:
            raise ValueError('klp-ccp returned {}, stderr: {}\nArgs: {}'.format(completed.returncode, completed.stderr, ' '.join(ccp_args)))

		# Remove the local path prefix of the klp-ccp generated comments
        # Open the file, read, seek to the beginning, write the new data, and
        # then truncate (which will use the current position in file as the
        # size)
        with open(str(lp_out), 'r+') as f:
            file_buf = f.read()
            f.seek(0)
            f.write(file_buf.replace('from ' + str(sdir) + '/', 'from '))
            f.truncate()

		# Generate the list of exported symbols
        exts = []

        for ext_file in ['fun_exts', 'obj_exts']:
            ext_path = pathlib.Path(out_dir, ext_file)
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

            sym = '\t{{ "{}",'.format(sym)
            if not mod:
                var = ' (void *)&{} }},'.format(var)
            else:
                var = ' (void *)&{},'.format(var)
                mod = ' "{}" }},'.format(mod)

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
                    ext_list.append('\t ' + var + mod)
                else:
                    ext_list.append('\t ' + var)
                    if mod:
                        ext_list.append('\t ' + mod)

        with open(pathlib.Path(out_dir, 'exts'), 'w') as f:
            f.write('\n'.join(ext_list))

    # Group all codestreams that share code in a format like bellow:
    #   { '15.2u10' : [ 15.2u11 15.3u10 15.3u12 ] }
    # Will be converted to:
    #   15.2u10-11 15.3u10 15.3u12
    def classify_codestreams(self, cs_dict):
        for cs in cs_dict.keys():
            relatives = [cs]
            for c in cs_dict[cs]:
                relatives.append(c)

            # All the codestreams related to the same key share the same code.
            r = relatives.pop(0)

            # A cs that does not share code with any other
            if not len(relatives):
                print('\t{}'.format(r))
                continue

            # We have other codestreams in the relatives list, so we share code with
            # other codestreams
            buf = ''
            while True:
                if not r:
                    break

                # siblings is used to check is the current cs has more than one
                # 'sibling' prefix and an update + 1. When it's not the case, the cs
                # in question is alone, so we should avoid printing the up date
                siblings = False
                prefix, up = r.split('u')
                while True:
                    # If we don't have more cs to process in this list, check if we
                    # had more than one cs with the same prefix, and only if yes,
                    # append the upper. This avoids duplicating the update number.
                    if not len(relatives):
                        buf += ' ' + r
                        if siblings:
                            buf += '-' + up
                        r = None
                        break

                    m = relatives.pop(0)
                    mprefix, mup = m.split('u')
                    if prefix == mprefix and int(mup) == int(up) + 1:
                        siblings = True
                        up = mup
                        continue

                    buf += ' ' + r
                    if siblings:
                      buf += '-' + up
                    # start grouping the different codestream
                    r = m
                    break

            print('\t{}'.format(buf.strip()))

    def group_equal_files(self):
        codestreams = []
        files = {}

        print('\nGrouping codestreams for each file processed by ccp:')

        for fname in self._proc_files:
            src_out = self.lp_out_file(fname)

            for fsrc in pathlib.Path(self.cfg.bsc_path, 'c').rglob(src_out):
                with open(fsrc, 'r+') as fi:
                    buf = fi.read()

                    # get the cs from the file path
                    # /<rootfs>/.../bsc1197705/c/15.3u4/x86_64/work_cls_api.c/bsc1197705_cls_api.c
                    cs = fsrc.parts[-4]

                    m = re.search('#include "(.+kconfig.h)"', buf)
                    if not m:
                        raise RuntimeError('File {} without an include to kconfig.h')

                    kconfig = m.group(1)

                    # check for duplicate kconfig lines
                    for c in codestreams:
                        if kconfig == files[c]['kconfig']:
                            raise RuntimeError('{}\'s kconfig is the same of {}'.format(cs,
                                c))

                    src = re.sub('#include ".+kconfig.h"', '', buf)

                    codestreams.append(cs)
                    files[cs] = { 'kconfig' : kconfig, 'src' : src }

            members = {}
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
            print('\t{}'.format(fname))
            self.classify_codestreams(members)
            print('')

    def run_ccp(self):
        # the current blacklisted function, more can be added as necessary
        os.environ['KCP_EXT_BLACKLIST'] = "__xadd_wrong_size,__bad_copy_from,__bad_copy_to,rcu_irq_enter_disabled,rcu_irq_enter_irqson,rcu_irq_exit_irqson,verbose,__write_overflow,__read_overflow,__read_overflow2,__real_strnlen"

        print('Work directory: {}'.format(self.cfg.bsc_path))

        if self.cfg.filter:
            print('Applying filter...')

        for cs in self._cs.keys():
            if self.cfg.filter and not re.match(self.cfg.filter, cs):
                print('Skipping {}'.format(cs))
                continue

            jcs = self._cs[cs]
            if not jcs['files']:
                continue

            ex = self._conf['ex_kernels']
            ipa = self._conf['ipa_clones']
            ipa_dir = pathlib.Path(ipa, jcs['cs'], 'x86_64')

            sdir = pathlib.Path(ex, jcs['cs'], 'usr', 'src', 'linux-' + jcs['kernel'])
            odir = pathlib.Path(str(sdir) + '-obj', 'x86_64', 'default')
            symvers = pathlib.Path(odir, 'Module.symvers')
            work_path = pathlib.Path(self.cfg.bsc_path, 'c', cs, 'x86_64')

            os.environ['KCP_MOD_SYMVERS'] = str(symvers)
            os.environ['KCP_READELF'] = jcs['readelf']
            os.environ['KCP_KBUILD_ODIR'] = str(odir)
            os.environ['KCP_KBUILD_SDIR'] = str(sdir)
            os.environ['KCP_PATCHED_OBJ'] = jcs['object']
            os.environ['KCP_RENAME_PREFIX'] = jcs['rename_prefix']

            print(cs)

            for fname in jcs['files']:
                print('\t', fname)

                self._proc_files.append(fname)

                out_dir = pathlib.Path(work_path, 'work_' + pathlib.Path(fname).name)
                # remove any previously generated files
                shutil.rmtree(out_dir, ignore_errors=True)
                out_dir.mkdir(parents=True, exist_ok=True)
                os.environ['KCP_WORK_DIR'] = str(out_dir)

                ipa_file_path = pathlib.Path(ipa_dir, fname + '.000i.ipa-clones')
                os.environ['KCP_IPA_CLONES_DUMP'] = str(ipa_file_path)

                self.execute_ccp(jcs, fname, ','.join(jcs['files'][fname]),
                                out_dir, sdir, odir)

        self.group_equal_files()
