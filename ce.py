from pathlib import Path
import shutil

from config import Config
from lp_utils import ARCH

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
        ce_args = [self.ce_path]
        ce_args.extend(cmd.split(' '))

        ce_args = list(filter(None, ce_args))

        # Now add the macros to tell clang-extract what to do
        ce_args.extend([f'-DCE_DEBUGINFO_PATH={self.get_module_obj(ARCH, cs, fdata["module"])}',
                        f'-DCE_SYMVERS_PATH={self.get_cs_boot_file(cs, "symvers")}',
                        f'-DCE_OUTPUT_FILE={Path(out_dir, self.lp_out_file(fname))}',
                        f'-DCE_OUTPUT_FUNCTION_PROTOTYPE_HEADER={Path(out_dir, "proto.h")}',
                        f'-DCE_DSC_OUTPUT={Path(out_dir, "lp.dsc")}',
                        f'-DCE_EXTRACT_FUNCTIONS={funcs}',
                       ])

        # clang-extract works without ipa-clones, so don't hard require it
        ipa_f = self.get_ipa_file(cs, fname)
        if ipa_f.exists():
            ce_args.extend([f'-DCE_IPACLONES_PATH={ipa_f}'])

        # Keep includes is necessary so don't end up expanding all headers,
        # generating a huge amount of code. This only makes sense for the
        # kernel so far.
        ce_args.extend(['-DCE_KEEP_INCLUDES',
                        '-DCE_RENAME_SYMBOLS'])

        # For debug purposes. Uncomment for dumping clang-extract passes
        #ce_args.extend(['-DCE_DUMP_PASSES'])


        return ce_args, None
