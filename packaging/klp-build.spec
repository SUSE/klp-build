#
# spec file for package klp-build
#
# Copyright (c) 2026 SUSE LLC
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same as for the pristine package itself (unless the license
# for the pristine package is not an Open Source License, in which case
# the license is the MIT License). An, "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

Name:           klp-build
Version:        2.0.1
Release:        0
Summary:        The SUSE kernel livepatching creation tool
License:        GPL-2.0-only
Group:          Development/Tools/Other
URL:            https://github.com/SUSE/klp-build
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  python-rpm-macros
BuildRequires:  python3-setuptools
BuildRequires:  fdupes
Requires:       python3-GitPython
Requires:       python3-Mako
Requires:       python3-MarkupSafe
Requires:       python3-filelock
Requires:       python3-lxml
Requires:       python3-natsort
Requires:       python3-osc-tiny
Requires:       python3-pyelftools
Requires:       python3-bugzilla
Requires:       python3-requests
Requires:       python3-tabulate
Requires:       python3-termcolor
Requires:       python3-zstandard
Requires:       git
Requires:       gcc7
BuildArch:      noarch

%description
klp-build is the kernel livepatching creation tool for SUSE Linux
Enterprise. It automates the process of creating, extracting, building,
and testing kernel livepatches. It integrates with the Internal/Open
Build Service (IBS/OBS) and provides a streamlined workflow for
livepatch developers.

%prep
%autosetup -n %{name}-%{version}

%build
export KLP_BUILD_VERSION="%{version}"
%python3_build

%install
export KLP_BUILD_VERSION="%{version}"
%python3_install
install -Dm644 klp-build.1 %{buildroot}%{_mandir}/man1/klp-build.1
%fdupes %{buildroot}%{python3_sitelib}

%files
%license LICENSE
%doc README.md
%{_bindir}/klp-build
%{_mandir}/man1/klp-build.1%{?ext_man}
%{python3_sitelib}/klpbuild/
%{python3_sitelib}/scripts/
%{python3_sitelib}/klp_build-*.egg-info/

%changelog
