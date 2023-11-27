import concurrent.futures
import logging
import os
from pathlib import Path, PurePath
import re
import shutil
import subprocess
from threading import Lock

from config import Config

# clang-extract executer
class CE(Config):
    def __init__(self, bsc, bsc_filter):
        super().__init__(bsc, bsc_filter)

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

    def execute_ce(self, cs, fname, funcs, out_dir, sdir, obj):
        odir = Path(f'{sdir}-obj', self.get_odir(cs))
        symvers = str(Path(odir, 'Module.symvers'))
        ipa = str(Path(self.get_ipa_dir(cs), f'{fname}.000i.ipa-clones'))

        lp_name = self.lp_out_file(fname)
        dsc_out = Path(out_dir, 'lp.dsc')
        lp_out = Path(out_dir, lp_name)

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

        # FIXME: DEBUG
        # The __OPTIMIZE__ is necessary due to problem on compiletime_error
        # macro. This needs to be fixed on clang-extract.
        ce_args.extend([f'-DCE_DUMP_PASSES',
                        f'-DCE_KEEP_INCLUDES',
                        f'-U__OPTIMIZE__'])

        with open(Path(out_dir, 'klp-ce.out.txt'), 'w') as f:
            # Write the command line used
            f.write('\n'.join(ce_args) + '\n')
            f.flush()
            subprocess.run(ce_args, cwd=odir, stdout=f, stderr=f, check=True)

        os.symlink(lp_out, Path(self.get_cs_dir(cs), lp_name))

    def get_ipa_dir(self, cs, arch='x86_64'):
        kernel = self.get_cs_kernel(cs)
        if self.cs_is_rt(cs):
            return Path(self.get_data_dir(cs), 'usr', 'src',
                        f'linux-{kernel}-rt-obj', arch, 'rt')

        return Path(self.get_data_dir(cs), 'usr', 'src', f'linux-{kernel}-obj',
                    arch, 'default')

    def process_ce(self, args):
        i, fname, cs, fdata = args

        obj = self.get_module_obj('x86_64', cs, fdata['module'])

        # The header text has two tabs
        cs_info = cs.ljust(15, ' ')
        idx = f'({i}/{self.total})'.rjust(15, ' ')

        logging.info(f'{idx} {cs_info} {fname}')

        out_dir = self.get_work_dir(cs, fname)
        out_dir.mkdir(parents=True, exist_ok=True)

        self.execute_ce(cs, fname, ','.join(fdata['symbols']), out_dir,
                        self.get_sdir(cs), obj)

    def run_ce(self):
        logging.info(f'Work directory: {self.bsc_path}')

        working_cs = self.filter_cs(verbose=True)

        # Make it perform better by spawning a process_ce function per
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
        logging.info(f'\nRunning clang-extract for {len(args)} file(s)...')
        logging.info('\t\tCodestream\tFile')

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            results = executor.map(self.process_ce, args)
            for result in results:
                if result:
                    logging.error(f'{cs}: {result}')
