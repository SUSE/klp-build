from collections import OrderedDict
import concurrent.futures
import json
import logging
import os
from pathlib import Path, PurePath
from natsort import natsorted
import re
import shutil
import subprocess
from threading import Lock

from config import Config
from templ import TemplateGen

class CCP(Config):
    def __init__(self, bsc, bsc_filter, avoid_ext):
        super().__init__(bsc, bsc_filter)

        self.env = os.environ

        # Prefer the env var to the HOME directory location
        ccp_path = os.getenv('KLP_CCP_PATH', '')
        if ccp_path and not Path(ccp_path).is_file():
            raise RuntimeError('KLP_CCP_PATH does not point to a file')

        elif not ccp_path:
            ccp_path = Path(Path().home(), 'kgr', 'ccp', 'build', 'klp-ccp')
            if not ccp_path.exists():
                raise RuntimeError('klp-ccp not found in ~/kgr/ccp/build/klp-ccp. Please set KLP_CCP_PATH env var to a valid klp-ccp binary')

        self.ccp_path = str(ccp_path)

        pol_path = os.getenv('KLP_CCP_POL_PATH')
        if pol_path and not Path(pol_path).is_dir():
            raise RuntimeError('KLP_CCP_POL_PATH does not point to a directory')

        elif not pol_path:
            pol_path = Path(Path().home(), 'kgr', 'scripts', 'ccp-pol')
            if not pol_path.is_dir():
                raise RuntimeError('ccp-pol not found at ~/kgr/scripts/ccp-pol/.  Please set KLP_CCP_POL_PATH env var to a valid ccp-pol directory')

        self.pol_path = str(pol_path)

        gcc_ver = int(subprocess.check_output(['gcc',
                                               '-dumpversion']).decode().strip())
        # gcc12 and higher have a problem with kernel and xrealloc implementation
        if gcc_ver < 12:
            self.cc = 'gcc'
        # if gcc12 or higher is the default compiler, check if gcc7 is available
        elif shutil.which('gcc-7'):
            self.cc = 'gcc-7'
        else:
            raise RuntimeError('Only gcc12 or higher are available, and it\'s problematic with kernel sources')

        # List of symbols that are currently not resolvable for klp-ccp
        avoid_syms = ['__xadd_wrong_size', '__bad_copy_from', '__bad_copy_to',
                    'rcu_irq_enter_disabled', 'rcu_irq_enter_irqson',
                    'rcu_irq_exit_irqson', 'verbose', '__write_overflow',
                    '__read_overflow', '__read_overflow2', '__real_strnlen',
                    'twaddle', 'set_geometry', 'valid_floppy_drive_params',
                    '__real_memchr_inv', '__real_kmemdup',
                    'lockdep_rtnl_is_held',
                    'lockdep_rht_mutex_is_held',
                    'debug_lockdep_rcu_enabled', 'lockdep_rcu_suspicious',
                    'rcu_read_lock_bh_held', 'lock_acquire',
                    'preempt_count_add', 'rcu_read_lock_any_held',
                    'preempt_count_sub', 'lock_release',
                    'trace_hardirqs_off', 'trace_hardirqs_on',
                    'debug_smp_processor_id', 'lock_is_held_type',
                    'mutex_lock_nested', 'rcu_read_lock_held',
                    '__bad_unaligned_access_size'
                    ]
        # The backlist tells the klp-ccp to always copy the symbol code,
        # instead of externalizing. This helps in cases where different archs
        # have different inline decisions, optimizing and sometimes removing the
        # symbols.
        if avoid_ext:
            avoid_syms.extend(avoid_ext)

        self.env['KCP_EXT_BLACKLIST'] = ','.join(avoid_syms)
        self.env['KCP_READELF'] = 'readelf'
        self.env['KCP_RENAME_PREFIX'] = 'klp'

        self.total = 0

        self.make_lock = Lock()

    def unquote_output(self, matchobj):
        return matchobj.group(0).replace('"', '')

    def process_make_output(self, cs, filename, output):
        fname = str(filename)

        ofname = '.' + filename.name.replace('.c', '.o.d')
        ofname = Path(filename.parent, ofname)

        cmd_args_regex = '(-Wp,{},{}\s+-nostdinc\s+-isystem.*{});'

        result = re.search(cmd_args_regex.format('-MD', ofname, fname), str(output).strip())
        if not result:
            # 15.4 onwards changes the regex a little: -MD -> -MMD
            result = re.search(cmd_args_regex.format('-MMD', ofname, fname), str(output).strip())

        if not result:
            raise RuntimeError(f'Failed to get the kernel cmdline for file {str(ofname)} in {cs}')

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

        sle, sp, _, _ = self.get_cs_tuple(cs)
        if sle >= 15:
            if sp >= 2:
                output += ' -D_Static_assert(e,m)='
            if sp >= 4:
                output += ' -D__auto_type=int'
                output += ' -D__has_attribute(x)=0'

        return output

    def get_make_cmd(self, out_dir, cs, filename, odir):
        filename = PurePath(filename)
        file_ = filename.with_suffix('.o')

        with open(Path(out_dir, 'make.out'), 'w') as f:
            completed = subprocess.check_output(['make', '-sn', f'CC={self.cc}',
                                                 f'KLP_CS={cs}',
                                                 f'HOSTCC={self.cc}',
                                                 'WERROR=0',
                                                 'CFLAGS_REMOVE_objtool=-Werror',
                                                 file_], cwd=odir,
                                        stderr=f)

            ret = self.process_make_output(cs, filename, completed.decode())
            # save the cmdline
            f.write(ret)

            if not ' -pg ' in ret:
                logging.warning(f'{cs}:{file_} is not compiled with livepatch support (-pg flag)')

            return ret

        return None

    def execute_ccp(self, cs, fname, funcs, out_dir, sdir, odir, env):
        lp_name = self.lp_out_file(fname)
        lp_out = Path(out_dir, lp_name)
        ppath = self.pol_path

        ccp_args = [self.ccp_path]
        for arg in ['may-include-header', 'can-externalize-fun', 'shall-externalize-fun', 'shall-externalize-obj',
                'modify-externalized-sym', 'rename-rewritten-fun']:
            ccp_args.append(f'--pol-cmd-{arg}={ppath}/kgr-ccp-pol-{arg}.sh')

        ccp_args.append(f'--pol-cmd-modify-patched-fun-sym={ppath}/kgr-ccp-pol-modify-patched-sym.sh')

        ccp_args.extend(['--compiler=x86_64-gcc-9.1.0', '-i', f'{funcs}',
                        '-o', f'{str(lp_out)}', '--'])

        # Make can regenerate fixdep for each file being processed per
        # codestream, so avoid the TXTBUSY error by serializing the 'make -sn'
        # calls. Make is pretty fast, so there isn't a real slow down here.
        with self.make_lock:
            ccp_args.extend(self.get_make_cmd(out_dir, cs, fname, odir).split(' '))

        ccp_args = list(filter(None, ccp_args))

        with open(Path(out_dir, 'klp-ccp.out'), 'w') as f:
            # Write the command line used
            f.write('\n'.join(ccp_args) + '\n')
            f.flush()
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

        os.symlink(lp_out, Path(self.get_cs_dir(cs), lp_name))

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
                    if not self.is_mod(mod):
                        mod = ''

                    exts.append( (sym, var, mod) )

        exts.sort(key=lambda tup : tup[0])

        # store the externalized symbols and module used in this codestream file
        symbols = {}
        for ext in exts:
            sym, mod = ext[0], ext[2]
            if not mod:
                mod = 'vmlinux'

            symbols.setdefault(mod, [])
            symbols[mod].append(sym)

        self.codestreams[cs]['files'][fname]['ext_symbols'] = symbols

    # Group all codestreams that share code in a format like bellow:
    #   [15.2u10 15.2u11 15.3u10 15.3u12 ]
    # Will be converted to:
    #   15.2u10-11 15.3u10 15.3u12
    # The returned value will be a list of lists, each internal list will
    # contain all codestreams which share the same code
    def classify_codestreams(cs_list):
        # Group all codestreams that share the same codestream by a new dict
        # divided by the SLE version alone, making it easier to process
        # later
        cs_group = {}
        for cs in cs_list:
            prefix, up = cs.split('u')
            if not cs_group.get(prefix, ''):
                cs_group[prefix] = [int(up)]
            else:
                cs_group[prefix].append(int(up))

        ret_list = []
        for cs, ups in cs_group.items():
            if len(ups) == 1:
                ret_list.append(f'{cs}u{ups[0]}')
                continue

            sim = []
            while len(ups):
                if not sim:
                    sim.append(ups.pop(0))
                    continue

                cur = ups.pop(0)
                last_item = sim[len(sim) - 1]
                if last_item + 1 <= cur:
                    sim.append(cur)
                    continue

                # they are different, print them
                if len(sim) == 1:
                    ret_list.append(f'{cs}u{sim[0]}')
                else:
                    ret_list.append(f'{cs}u{sim[0]}-{last_item}')

                sim = [cur]

            # Loop finished, check what's in similar list to print
            if len(sim) == 1:
                ret_list.append(f'{cs}u{sim[0]}')
            elif len(sim) > 1:
                last_item = sim[len(sim) - 1]
                ret_list.append(f'{cs}u{sim[0]}-{last_item}')

        return ' '.join(ret_list)

    def get_work_lp_file(self, cs, fname):
        return Path(self.get_work_dir(cs, fname), self.lp_out_file(fname))

    def group_equal_files(self, args):
        cs_files = {}
        cs_groups = {}

        # Mount the cs_files dict
        for arg in args:
            _, file, cs, _ = arg
            if not cs_files.get(cs, ''):
                cs_files[cs] = []

            fpath = self.get_work_lp_file(cs, file)
            with open(fpath, 'r+') as fi:
                src = fi.read()

            src = re.sub('#include \".+kconfig\.h\"', '', src)
            # Since 15.4 klp-ccp includes a compiler-version.h header
            src = re.sub('#include \".+compiler\-version\.h\"', '', src)
            # Since RT variants, there is now an definition for auto_type
            src = src.replace('#define __auto_type int\n', '')

            # Remove any mentions to klpr_trace, since it's currently
            # buggy in klp-ccp
            src = re.sub('.+klpr_trace.+', '', src)

            cs_files[cs].append((file , src ))

        cs_equal = []
        processed = []

        toprocess = list(cs_files.keys())
        while len(toprocess):
            current_cs_list = []

            # Get an element, and check if it wasn't associated with a previous
            # codestream
            cs = toprocess.pop(0)
            if cs in processed:
                continue

            # last element, it's different from all other codestreams, so add it
            # to the cs_equal alone.
            if not toprocess:
                cs_equal.append([cs])
                break

            # start a new list with the current element to compare with others
            current_cs_list.append(cs)
            data_cs = cs_files[cs]
            len_data = len(data_cs)

            # Compare the file names, and file content between codestrams,
            # trying to find ones that have the same files and contents
            for cs_proc in toprocess:
                data_proc = cs_files[cs_proc]

                if len_data != len(data_proc):
                    continue

                ok = True
                for i in range(len_data):
                    file, src = data_cs[i]
                    file_proc, src_proc = data_proc[i]

                    if file != file_proc or src != src_proc:
                        ok = False
                        break

                # cs is equal to cs_proc, with the same number of files, same
                # file names, and the files have the same content. So we don't
                # need to process cs_proc later in the process
                if ok:
                    processed.append(cs_proc)
                    current_cs_list.append(cs_proc)

            # Append the current list of equal codestreams to a global list to
            # be grouped later
            cs_equal.append(natsorted(current_cs_list))

        # cs_equal will contain a list of lists with codestreams that share the
        # same code
        groups = []
        for cs_list in cs_equal:
            groups.append(CCP.classify_codestreams(cs_list))

        with open(Path(self.bsc_path, 'groups'), 'w') as f:
            f.write('\n'.join(groups))

        logging.info('\nGrouping codestreams that share the same content and files:')
        for group in groups:
            logging.info(f'\t{group}')

    def get_ipa_dir(self, cs, arch='x86_64'):
        kernel = self.get_cs_kernel(cs)
        if self.cs_is_rt(cs):
            return Path(self.get_data_dir(cs), 'usr', 'src',
                        f'linux-{kernel}-rt-obj', arch, 'rt')

        return Path(self.get_data_dir(cs), 'usr', 'src', f'linux-{kernel}-obj',
                    arch, 'default')

    def process_ccp(self, args):
        i, fname, cs, fdata = args

        sdir = self.get_sdir(cs)
        odir = Path(f'{sdir}-obj', self.get_odir(cs))

        # Needed, otherwise threads would interfere with each other
        env = self.env.copy()

        env['KCP_MOD_SYMVERS'] = str(Path(odir, 'Module.symvers'))
        env['KCP_KBUILD_ODIR'] = str(odir)
        env['KCP_KBUILD_SDIR'] = str(sdir)
        env['KCP_PATCHED_OBJ'] = self.get_module_obj('x86_64', cs, fdata['module'])

        # The header text has two tabs
        cs_info = cs.ljust(15, ' ')
        idx = f'({i}/{self.total})'.rjust(15, ' ')

        logging.info(f'{idx} {cs_info} {fname}')

        base_fname = Path(fname).name

        out_dir = self.get_work_dir(cs, fname)
        out_dir.mkdir(parents=True, exist_ok=True)
        # create symlink to the respective codestream file
        os.symlink(Path(sdir, fname), Path(out_dir, base_fname))
        env['KCP_WORK_DIR'] = str(out_dir)

        env['KCP_IPA_CLONES_DUMP'] = str(Path(self.get_ipa_dir(cs),
                                              f'{fname}.000i.ipa-clones'))

        self.execute_ccp(cs, fname, ','.join(fdata['symbols']), out_dir, sdir, odir,
                env)

    def run_ccp(self):
        logging.info(f'Work directory: {self.bsc_path}')

        working_cs = self.filter_cs(verbose=True)

        # Make it perform better by spawning a process_ccp function per
        # cs/file/funcs tuple, instead of spawning a thread per codestream
        args = []
        i = 1
        for cs, data in working_cs.items():
            # remove any previously generated files
            shutil.rmtree(self.get_cs_dir(cs), ignore_errors=True)

            for fname, fdata in data['files'].items():
                args.append((i, fname, cs, fdata))
                i += 1

        self.total = len(args)
        logging.info(f'\nRunning klp-ccp for {len(args)} file(s)...')
        logging.info('\t\tCodestream\tFile')

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            results = executor.map(self.process_ccp, args)
            for result in results:
                if result:
                    logging.error(f'{cs}: {result}')

        # Save the ext_symbols set by execute_ccp
        self.flush_cs_file()

        self.group_equal_files(args)

        tem = TemplateGen(self.bsc_num, self.filter)
        tem.generate_commit_msg_file()

        logging.info('Checking the externalized symbols in other architectures...')

        missing_syms = OrderedDict()

        # Iterate over each codestream, getting each file processed, and all
        # externalized symbols of this file
        # While we are at it, create the livepatches per codestream
        for cs, _ in working_cs.items():
            tem.GenerateLivePatches(cs)

            # Map all symbols related to each obj, to make it check the output
            # of nm only once per object
            obj_syms = {}
            for f, fdata in self.get_cs_files(cs).items():
                for obj, syms in fdata['ext_symbols'].items():
                    obj_syms.setdefault(obj, [])
                    obj_syms[obj].extend(syms)

            for obj, syms in obj_syms.items():
                missing = self.check_symbol_archs(cs, obj, syms)
                if missing:
                    for arch, arch_syms in missing.items():
                        missing_syms.setdefault(arch, {})
                        missing_syms[arch].setdefault(obj, {})
                        missing_syms[arch][obj].setdefault(cs, [])
                        missing_syms[arch][obj][cs].extend(arch_syms)

            tem.CreateKbuildFile(cs)

        if missing_syms:
            with open(Path(self.bsc_path, 'missing_syms'), 'w') as f:
                f.write(json.dumps(missing_syms, indent=4))

            logging.warning('Symbols not found:')
            logging.warn(json.dumps(missing_syms, indent=4))
