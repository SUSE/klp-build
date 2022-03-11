import json
import pathlib
import os
import re
import subprocess

import sys

class CCP:
    _cs = None

    def __init__(self, bsc):
        cs_file = pathlib.Path('/home/mpdesouza/bsc' +  bsc, 'codestreams.json')
        with open(cs_file, 'r') as f:
            self._cs = json.loads(f.read())

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
            outpuut = output + " -D'_Static_assert(e,m)='"

        return output

    def get_make_cmd(self, filename, jcs):
        filename = pathlib.PurePath(filename)
        file_ = filename.with_suffix('.o')
        completed = subprocess.run(['make', '-sn', file_], cwd=jcs['odir'], capture_output=True, text=True)
        return self.process_make_output(filename, completed.stdout, jcs['sle'], jcs['sp'])

    def execute_ccp(self, odir, fname, funcs, work_dir, cmd):
        # extract the last component of the path, like the basename bash # function
        fname = pathlib.PurePath(fname).name

        ccp_path = '/home/mpdesouza/kgr/ccp/build/klp-ccp'
        pol_path = '/home/mpdesouza/kgr/scripts/ccp-pol'
        lp_out = pathlib.Path(work_dir, fname)

        ccp_args = [ccp_path]
        for arg in ['may-include-header', 'can-externalize-fun', 'shall-externalize-fun', 'shall-externalize-obj',
                'modify-externalized-sym', 'modify-patched-func-sym', 'rename-rewritten-fun']:
            ccp_args.append('--pol-cmd-{0}={1}/kgr-ccp-pol{0}'.format(arg, pol_path))

        ccp_args.extend('--compiler=xx86_64-gcc-9.1.0', '-i {}'.format(funcs),
                        '-o {}'.format(str(lp_out)), '--', cmd)

        completed = subprocess.run(ccp_args, cwd=odir, capture_output=True, text=True)

		# Remove the local path prefix of the klp-ccp generated comments
		#sed -i '/klp-ccp: from / s/\/[a-z].*sr\/src\/linux\(-[0-9]\+\(\.[0-9]\+\)*\)\+\///' \
		#	$LP_SRC

		# Generate the list of exported symbols
		#for f in `ls $work_dir/{fun,obj}_exts`; do
		#	~/kgr/scripts/kgr-format-kallsyms-exts.pl $f >> ${LP_SRC}.exts
		#done

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
            os.environ['KCP_PATCHED_OBJECT'] = jcs['object']
            os.environ['KCP_RENAME_PREFIX'] = jcs['rename_prefix']

            for index, fname in jcs['files']:
                print(cs, fname)
                cmd = self.get_make_cmd(fname, jcs)
                os.environ['KCP_WORK_DIR'] = jcs['work_dir'][index]
                os.environ['KCP_IPA_CLONES_DUMP'] = jcs['ipa_clones'][index]

                self.execute_ccp(jcs['odir'], fname, ','.join(jcs['files'][index]),
                    jcs['work_dir'][index], cmd)
