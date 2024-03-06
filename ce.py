from pathlib import Path
import shutil

from config import Config

class CE(Config):
    def __init__(self, bsc, bsc_filter):
        super().__init__(bsc, bsc_filter)

        self.app = 'ce'

        self.ce_path = shutil.which('clang-extract')
        if not self.ce_path:
            raise RuntimeError('clang-extract not found. Aborting.')

    # Check if the extract command line is compilable with gcc
	# Generate the list of exported symbols
    def get_symbol_list(self, out_dir):
        exts = []
        dsc_out = Path(out_dir, 'lp.dsc')
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

        return symbols

    def cmd_args(self, cs, fname, funcs, out_dir, fdata, cmd):
        odir = self.get_odir(cs)
        symvers = str(self.get_cs_symvers(cs))
        ipa = str(self.get_ipa_file(cs, fname))
        obj = self.get_module_obj('x86_64', cs, fdata['module'])

        lp_name = self.lp_out_file(fname)
        lp_out = Path(out_dir, lp_name)

        dsc_out = Path(out_dir, 'lp.dsc')

        ce_args = [self.ce_path]

        ce_args.extend(cmd.split(' '))

        ce_args = list(filter(None, ce_args))

        # Now add the macros to tell clang-extract what to do
        ce_args.extend([f'-DCE_DEBUGINFO_PATH={obj}',
                        f'-DCE_SYMVERS_PATH={symvers}',
                        f'-DCE_EXTRACT_FUNCTIONS={funcs}',
                        f'-DCE_IPACLONES_PATH={ipa}',
                        f'-DCE_OUTPUT_FILE={lp_out}',
                        f'-DCE_DSC_OUTPUT={dsc_out}'])

        # Keep includes is necessary so don't end up expanding all headers,
        # generating a huge amount of code. This only makes sense for the
        # kernel so far.
        ce_args.extend(['-DCE_KEEP_INCLUDES',
                        '-DCE_RENAME_SYMBOLS'])


        return ce_args, None
