import logging
from pathlib import Path, PurePath
import re
import subprocess

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

    return ret_list


def unquote_output(matchobj):
    return matchobj.group(0).replace('"', '')

def process_make_output(cs, filename, output):
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
    return re.sub('-D"KBUILD_([\w\#\_\=\(\)])+"', unquote_output, output)

def get_make_cmd(cc, out_dir, cs, filename, odir):
    filename = PurePath(filename)
    file_ = filename.with_suffix('.o')

    with open(Path(out_dir, 'make.out.txt'), 'w') as f:
        completed = subprocess.check_output(['make', '-sn', f'CC={cc}',
                                             f'KLP_CS={cs}',
                                             f'HOSTCC={cc}',
                                             'WERROR=0',
                                             'CFLAGS_REMOVE_objtool=-Werror',
                                             file_], cwd=odir,
                                    stderr=f)

        ret = process_make_output(cs, filename, completed.decode())
        # save the cmdline
        f.write(ret)

        if not ' -pg ' in ret:
            logging.warning(f'{cs}:{file_} is not compiled with livepatch support (-pg flag)')

        return ret

    return None
