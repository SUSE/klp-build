import json
import pathlib
import os
import re
import shutil
import subprocess

class CCP:
    _cs = None
    _conf = None

    def __init__(self, bsc, work_dir):
        bsc_path = pathlib.Path(work_dir, 'bsc' + str(bsc))
        with open(pathlib.Path(bsc_path, 'codestreams.json')) as f:
            self._cs = json.loads(f.read())

        with open(pathlib.Path(bsc_path, 'conf.json')) as f:
            self._conf = json.loads(f.read())

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

        # -flive-patching and -fdump-ipa-clones are only present in upstream gcc
        output = output.replace('-flive-patching=inline-clone', '')
        output = output.replace('-fdump-ipa-clones', '')

        if int(sle) >= 15 and int(sp) >= 2:
            output += ' -D_Static_assert(e,m)='

        return output

    def get_make_cmd(self, filename, jcs):
        filename = pathlib.PurePath(filename)
        file_ = filename.with_suffix('.o')
        completed = subprocess.run(['make', '-sn', file_], cwd=jcs['odir'], capture_output=True, text=True)
        if completed.returncode != 0:
            raise RuntimeError('klp-ccp returned {}, stderr: {}'.format(completed.returncode, completed.stderr))
        return self.process_make_output(filename, completed.stdout, jcs['sle'], jcs['sp'])

    def execute_ccp(self, jcs, fname, funcs, work_dir):
        # extract the last component of the path, like the basename bash # function
        fname_ = pathlib.PurePath(fname).name

        ccp_path = '/home/mpdesouza/kgr/ccp/build/klp-ccp'
        pol_path = '/home/mpdesouza/kgr/scripts/ccp-pol'
        lp_out = pathlib.Path(work_dir, fname_)

        ccp_args = [ccp_path]
        for arg in ['may-include-header', 'can-externalize-fun', 'shall-externalize-fun', 'shall-externalize-obj',
                'modify-externalized-sym', 'rename-rewritten-fun']:
            ccp_args.append('--pol-cmd-{0}={1}/kgr-ccp-pol-{0}.sh'.format(arg, pol_path))

        ccp_args.append('--pol-cmd-modify-patched-fun-sym={}/kgr-ccp-pol-modify-patched-sym.sh'.format(pol_path))

        ccp_args.extend(['--compiler=x86_64-gcc-9.1.0', '-i', '{}'.format(funcs),
                        '-o', '{}'.format(str(lp_out)), '--'])

        ccp_args.extend(self.get_make_cmd(fname, jcs).split(' '))

        ccp_args = list(filter(None, ccp_args))

        completed = subprocess.run(ccp_args, cwd=jcs['odir'], text=True, capture_output=True)
        if completed.returncode != 0:
            raise ValueError('klp-ccp returned {}, stderr: {}'.format(completed.returncode, completed.stderr))

		# Remove the local path prefix of the klp-ccp generated comments
        # Open the file, read, seek to the beginning, write the new data, and
        # then truncate (which will use the current position in file as the
        # size)
        with open(str(lp_out), 'r+') as f:
            file_buf = f.read()
            f.seek(0)
            f.write(file_buf.replace(jcs['sdir'] + '/', ''))
            f.truncate()

		# Generate the list of exported symbols
        exts = []
        mod = self._conf['mod']
        mod_len = len(mod) if mod else 0

        for ext_file in ['fun_exts', 'obj_exts']:
            ext_path = pathlib.Path(work_dir, ext_file)
            if not ext_path.exists():
                continue

            with open(ext_path) as f:
                for line in f:
                    if not line.startswith('KALLSYMS'):
                        continue
                    _, sym, var, _ = line.split(' ')
                    exts.append( (sym, var) )

        exts.sort(key=lambda tup : tup[0])

        ext_list = []
        for ext in exts:
            sym, var = ext
            buf = '\t{{ "{}", (void *)&{}'.format(sym, var)
            if mod:
                buf += ', "{}" }},\n'.format(mod)
            else:
                buf += ' }},\n'.format(var)

            ext_list.append(buf)

        with open(pathlib.Path(work_dir, 'exts'), 'w') as f:
            f.writelines(ext_list)

    def run_ccp(self):
        # the current blacklisted function, more can be added as necessary
        os.environ['KCP_EXT_BLACKLIST'] = "__xadd_wrong_size,__bad_copy_from,__bad_copy_to,rcu_irq_enter_disabled,rcu_irq_enter_irqson,rcu_irq_exit_irqson,verbose,__write_overflow,__read_overflow,__read_overflow2"

        for cs in self._cs.keys():
            jcs = self._cs[cs]
            if not jcs['files']:
                continue

            os.environ['KCP_MOD_SYMVERS'] = jcs['symvers']
            os.environ['KCP_READELF'] = jcs['readelf']
            os.environ['KCP_KBUILD_ODIR'] = jcs['odir']
            os.environ['KCP_KBUILD_SDIR'] = jcs['sdir']
            os.environ['KCP_PATCHED_OBJ'] = jcs['object']
            os.environ['KCP_RENAME_PREFIX'] = jcs['rename_prefix']

            print(cs)

            for index, fname in enumerate(jcs['files']):
                print('\t', fname)
                work_dir = jcs['work_dir'][index]
                os.environ['KCP_WORK_DIR'] = work_dir
                os.environ['KCP_IPA_CLONES_DUMP'] = jcs['ipa_clones'][index]

                # remove any previously generated files
                shutil.rmtree(work_dir, ignore_errors=True)
                pathlib.Path(work_dir).mkdir(parents=True, exist_ok=True)

                self.execute_ccp(jcs, fname, ','.join(jcs['files'][fname]),
                                jcs['work_dir'][index])
