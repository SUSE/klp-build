#!/usr/bin/env python3
import jinja2
import sys

env = jinja2.Environment(loader=jinja2.FileSystemLoader('.'), trim_blocks=True, cache_size=0)
t = env.get_template(sys.argv[1])

mod='firedtv'

print(t.render(bsc='bsc1192020',
                mod=mod,
                config='CONFIG_FIREDTV',
                ktype='kgr'))
