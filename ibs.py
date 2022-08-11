import concurrent.futures
import errno
import json
from lxml import etree
from pathlib import Path
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
        return self.osc.search.project("starts-with(@name, '{}')".format(self.prj_prefix))

    def get_project_names(self):
        names = []
        for result in self.get_projects().findall('project'):
            names.append(result.get('name'))

        return names

    def delete_project(self, prj):
        if not self.osc.projects.exists(prj):
            return

        ret = self.osc.projects.delete(prj)
        if type(ret) is not bool:
            print(etree.tostring(ret))
            raise ValueError(prj)

        print('Removed ' + prj)

    def download_rpms(self, args):
        prj, arch, filename = args
        try:
            ret = self.osc.build.get_binary(prj, 'devbuild', arch, 'klp', filename)
            with open(Path(self.cfg.bsc_download, filename), "wb") as f:
                f.write(ret)

            print('\t{}: ok'.format(filename))
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise RuntimeError('download error on {}: {}'.format(prj, filename))

    def download(self):
        for result in self.get_projects().findall('project'):
            prj = result.get('name')
            archs = result.xpath('repository/arch')
            rpms = []
            for arch in archs:
                ret = self.osc.build.get_binary_list(prj, 'devbuild', arch, 'klp')
                rpm_name = '{}.rpm'.format(arch)
                for rpm in ret.xpath('binary/@filename'):
                    if not rpm.endswith(rpm_name):
                        continue
                    rpms.append( (prj, arch, rpm) )

            print('Downloading {} packages'.format(prj))
            #with concurrent.futures.ThreadPoolExecutor(max_workers=len(rpms)) as executor:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                results = executor.map(self.download_rpms, rpms)
                for result in results:
                    if result:
                        print(result)

    def status(self):
        prjs = {}
        for prj in self.get_project_names():
            prjs[prj] = {}

            for res in self.osc.build.get(prj).findall('result'):
                code = res.xpath('status/@code')[0]
                prjs[prj][res.get('arch')] = code

        for prj, archs in prjs.items():
            st = []
            for k, v in archs.items():
                st.append('{}: {}'.format(k, v))
            print('{}\t{}'.format(prj, '\t'.join(st)))

    def cleanup(self):
        prjs = self.get_project_names()

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
