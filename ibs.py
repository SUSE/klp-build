import concurrent.futures
import json
from lxml import etree
import os
from osctiny import Osc
import re

class IBS:
    def __init__(self, cfg):
        self.cfg = cfg
        self.osc = Osc(url='https://api.suse.de')

        ibs_user = re.search('(\w+)@', cfg.email).group(1)
        self.prj_prefix = 'home:{}:klp'.format(ibs_user)

    # The projects has different format: 12_5u5 instead of 12.5u5
    def get_projects(self):
        ret = self.osc.search.project("starts-with(@name, '{}')".format(self.prj_prefix))
        prjs = []
        for result in ret.findall('project'):
            prjs.append(result.get('name'))

        return prjs

    def delete_project(self, prj):
        exists = self.osc.projects.exists(prj)
        if not exists:
            return

        ret = self.osc.projects.delete(prj)
        if type(ret) is not bool:
            print(etree.tostring(ret))
            raise ValueError(prj)

        print('Removed ' + prj)


    def status(self):
        prjs = {}
        ret = self.osc.search.project("starts-with(@name, '{}')".format(self.prj_prefix))

        for result in ret.findall('project'):
            prj = result.get('name')
            prjs[prj] = {}

            ret = self.osc.build.get(prj)

            for res in ret.findall('result'):
                code = res.xpath('status/@code')[0]
                prjs[prj][res.get('arch')] = code

        for prj, archs in prjs.items():
            st = []
            for k, v in archs.items():
                st.append('{}: {}'.format(k, v))
            print('{}\t{}'.format(prj, '\t'.join(st)))

    def cleanup(self):
        prjs = self.get_projects()

        if len(prjs) == 0:
            return

        print('{} projects found.'.format(len(prjs)))

        if self.cfg.filter:
            filtered = []
            for prj in prjs:
                if not re.match(self.cfg.filter, prj.replace('_', '.')):
                    continue

                filtered.append(prj)

            prjs = filtered

        print('Removing {} projects.'.format(len(prjs)))

        # Remove the projects
        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            results = executor.map(self.delete_project, prjs)
            for result in results:
                if result:
                    print(result)
