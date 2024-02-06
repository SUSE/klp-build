from collections import OrderedDict
import concurrent.futures
import difflib as dl
import json
import logging
from natsort import natsorted
import os
from pathlib import Path, PurePath
import re
import shutil
import subprocess
from threading import Lock

from config import Config
from templ import TemplateGen

class CE(Config):
    def __init__(self, bsc, bsc_filter):
        super().__init__(bsc, bsc_filter)

        self.app = 'ce'

        # Prefer the env var to the HOME directory location
        ce_path = os.getenv('KLP_CE_PATH', '')
        if ce_path and not Path(ce_path).is_file():
            raise RuntimeError('KLP_CE_PATH does not point to a file')

        elif not ce_path:
            ce_path = Path(Path().home(), 'git', 'clang-extract', 'clang-extract')
            if not ce_path.exists():
                raise RuntimeError('clang-extract not found in ~/git/clang-extract/clang-extract. Please set KLP_CE_PATH env var to a valid clang-extract binary')

        self.ce_path = str(ce_path)

        self.total = 0

        self.make_lock = Lock()

        self.tem = TemplateGen(self.bsc_num, self.filter, self.app)

    def unquote_output(self, matchobj):
        return matchobj.group(0).replace('"', '')

    # Check if the extract command line is compilable with gcc
    def test_gcc_cmd(self, cmd):
        subprocess.check_output(self.cc + ' ' + cmd)

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

        return output

    def get_make_cmd(self, out_dir, cs, filename, odir):
        filename = PurePath(filename)
        file_ = filename.with_suffix('.o')

        with open(Path(out_dir, 'make.out.txt'), 'w') as f:
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
        return Path(self.get_work_dir(cs, fname, self.app), self.lp_out_file(fname))

    def get_cs_code(self, args):
        cs_files = {}

        # Mount the cs_files dict
        for arg in args:
            _, file, cs, _ = arg
            cs_files.setdefault(cs, [])

            fpath = self.get_work_lp_file(cs, file)
            with open(fpath, 'r+') as fi:
                src = fi.read()

                src = re.sub('#include \".+kconfig\.h\"', '', src)
                # Since 15.4 klp-ccp includes a compiler-version.h header
                src = re.sub('#include \".+compiler\-version\.h\"', '', src)
                # We have problems with externalized symbols on macros. Ignore
                # codestream names specified on paths that are placed on the
                # expanded macros
                src = re.sub(f'{self.data}.+{file}', '', src)
                # We can have more details that can differ for long expanded
                # macros, like the patterns bellow
                src = re.sub(f'\.lineno = \d+,', '', src)

                # Remove any mentions to klpr_trace, since it's currently
                # buggy in klp-ccp
                src = re.sub('.+klpr_trace.+', '', src)

                # Remove clang-extract comments
                src = re.sub('clang-extract: .+', '', src)

                cs_files[cs].append((file , src ))

        return cs_files

    # cs_list should be only two entries
    def diff_cs(self, cs_list):
        args = []
        f1 = {}
        f2 = {}
        for cs in cs_list:
            for fname, _ in self.get_cs_files(cs).items():
                args.append((_, fname, cs, _))

        cs_code = self.get_cs_code(args)
        f1 = cs_code.get(cs_list[0])
        f2 = cs_code.get(cs_list[1])

        assert(len(f1) == len(f2))

        for i in range(len(f1)):
            content1 = f1[i][1].splitlines()
            content2 = f2[i][1].splitlines()

            for l in dl.unified_diff(content1, content2, fromfile=f1[i][0],
                                     tofile=f2[i][0]):
                print(l)

    # Get the code for each codestream, removing boilerplate code
    def group_equal_files(self, args):
        cs_equal = []
        processed = []

        cs_files = self.get_cs_code(args)
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
            groups.append(CE.classify_codestreams(cs_list))

        with open(Path(self.bsc_path, self.app, 'groups'), 'w') as f:
            f.write('\n'.join(groups))

        logging.info('\nGrouping codestreams that share the same content and files:')
        for group in groups:
            logging.info(f'\t{group}')

    def execute(self, cs, fname, funcs, out_dir, obj):
        odir = self.get_odir(cs)
        symvers = str(Path(odir, 'Module.symvers'))
        ipa = str(Path(self.get_ipa_dir(cs), f'{fname}.000i.ipa-clones'))

        lp_name = self.lp_out_file(fname)
        lp_out = Path(out_dir, lp_name)

        lp_dsc = 'lp.dsc'
        dsc_out = Path(out_dir, lp_dsc)

        ce_args = [self.ce_path]

        # Make can regenerate fixdep for each file being processed per
        # codestream, so avoid the TXTBUSY error by serializing the 'make -sn'
        # calls. Make is pretty fast, so there isn't a real slow down here.
        with self.make_lock:
            ce_args.extend(self.get_make_cmd(out_dir, cs, fname, odir).split(' '))

        ce_args = list(filter(None, ce_args))

        # Now add the macros to tell clang-extract what to do
        ce_args.extend([f'-DCE_DEBUGINFO_PATH={obj}',
                        f'-DCE_IPACLONES_PATH={ipa}',
                        f'-DCE_SYMVERS_PATH={symvers}',
                        f'-DCE_EXTRACT_FUNCTIONS={funcs}',
                        f'-DCE_OUTPUT_FILE={lp_out}',
                        f'-DCE_DSC_OUTPUT={dsc_out}'])

        # Keep includes is necessary so don't end up expanding all headers,
        # generating a huge amount of code. This only makes sense for the
        # kernel so far.
        ce_args.extend(['-DCE_KEEP_INCLUDES',
                        '-DCE_RENAME_SYMBOLS'])

        with open(Path(out_dir, 'ce.out.txt'), 'w') as f:
            # Write the command line used
            f.write('\n'.join(ce_args) + '\n')
            f.flush()
            subprocess.run(ce_args, cwd=odir, stdout=f, stderr=f, check=True)

		# Generate the list of exported symbols
        exts = []
        with open(dsc_out) as f:
            for l in f:
                l = l.strip()
                if l.startswith('#'):
                    mod = 'vmlinux'
                    if l.count(':') == 2:
                        sym, _, mod = l.replace('#', '').split(':')
                    else:
                        sym, _ = l.replace('#', '').split(':')
                    exts.append( (sym, mod) )

        exts.sort(key=lambda tup : tup[0])

        # store the externalized symbols and module used in this codestream file
        symbols = {}
        for ext in exts:
            sym, mod = ext

            symbols.setdefault(mod, [])
            symbols[mod].append(sym)

        self.codestreams[cs]['files'][fname]['ext_symbols'] = symbols

        self.tem.CreateMakefile(cs, fname)

    def get_ipa_dir(self, cs, arch='x86_64'):
        kernel = self.get_cs_kernel(cs)
        if self.cs_is_rt(cs):
            return Path(self.get_data_dir(arch), 'usr', 'src',
                        f'linux-{kernel}-rt-obj', arch, 'rt')

        return Path(self.get_data_dir(arch), 'usr', 'src', f'linux-{kernel}-obj',
                    arch, 'default')

    def process(self, args):
        i, fname, cs, fdata = args

        obj = self.get_module_obj('x86_64', cs, fdata['module'])

        # The header text has two tabs
        cs_info = cs.ljust(15, ' ')
        idx = f'({i}/{self.total})'.rjust(15, ' ')

        logging.info(f'{idx} {cs_info} {fname}')

        out_dir = self.get_work_dir(cs, fname, self.app)
        out_dir.mkdir(parents=True, exist_ok=True)

        # create symlink to the respective codestream file
        os.symlink(Path(self.get_sdir(cs), fname), Path(out_dir,
                                                        Path(fname).name))

        self.execute(cs, fname, ','.join(fdata['symbols']), out_dir, obj)

    def run(self):
        logging.info(f'Work directory: {self.bsc_path}')

        working_cs = self.filter_cs(verbose=True)

        # Make it perform better by spawning a process function per
        # cs/file/funcs tuple, instead of spawning a thread per codestream
        args = []
        i = 1
        for cs, data in working_cs.items():
            # remove any previously generated files
            shutil.rmtree(self.get_cs_dir(cs, self.app), ignore_errors=True)

            for fname, fdata in data['files'].items():
                args.append((i, fname, cs, fdata))
                i += 1

        self.total = len(args)
        logging.info(f'\nRunning clang-extract for {len(args)} file(s)...')
        logging.info('\t\tCodestream\tFile')

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            results = executor.map(self.process, args)
            for result in results:
                if result:
                    logging.error(f'{cs}: {result}')

        # Save the ext_symbols set by execute
        self.flush_cs_file()

        self.tem.refresh_codestreams(self.codestreams)

        self.group_equal_files(args)

        self.tem.generate_commit_msg_file()

        logging.info('Checking the externalized symbols in other architectures...')

        missing_syms = OrderedDict()

        # Iterate over each codestream, getting each file processed, and all
        # externalized symbols of this file
        # While we are at it, create the livepatches per codestream
        for cs, _ in working_cs.items():
            self.tem.GenerateLivePatches(cs)

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

            self.tem.CreateKbuildFile(cs)

        if missing_syms:
            with open(Path(self.bsc_path, 'missing_syms'), 'w') as f:
                f.write(json.dumps(missing_syms, indent=4))

            logging.warning('Symbols not found:')
            logging.warn(json.dumps(missing_syms, indent=4))
