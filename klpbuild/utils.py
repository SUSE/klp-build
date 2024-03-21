import platform

ARCH = platform.processor()
ARCHS = ["ppc64le", "s390x", "x86_64"]


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
        prefix, up = cs.split("u")
        if not cs_group.get(prefix, ""):
            cs_group[prefix] = [int(up)]
        else:
            cs_group[prefix].append(int(up))

    ret_list = []
    for cs, ups in cs_group.items():
        if len(ups) == 1:
            ret_list.append(f"{cs}u{ups[0]}")
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
                ret_list.append(f"{cs}u{sim[0]}")
            else:
                ret_list.append(f"{cs}u{sim[0]}-{last_item}")

            sim = [cur]

        # Loop finished, check what's in similar list to print
        if len(sim) == 1:
            ret_list.append(f"{cs}u{sim[0]}")
        elif len(sim) > 1:
            last_item = sim[len(sim) - 1]
            ret_list.append(f"{cs}u{sim[0]}-{last_item}")

    return ret_list
