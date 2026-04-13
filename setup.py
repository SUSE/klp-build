import os

import setuptools

with open("README.md", "r") as f:
    long_description = f.read()

# When building from a tarball (e.g. RPM packaging), set KLP_BUILD_VERSION
# to inject the version statically. When unset, setuptools-git-versioning
# derives it from git tags automatically.
_version = os.environ.get("KLP_BUILD_VERSION")
_git_versioning = {}
_setup_requires = []

if not _version:
    _git_versioning = {"enabled": True}
    _setup_requires = ["setuptools-git-versioning>=2.0,<3"]

setuptools.setup(
    name="klp-build",
    version=_version,
    author="Marcos Paulo de Souza",
    author_email="mpdesouza@suse.com",
    description="The kernel livepatching creation tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.suse.de/live-patching/klp-build",
    packages=setuptools.find_packages(exclude=["tests"]),
    package_data={"scripts": ["run-kgr-test.sh", "config-merge"]},
    python_requires=">=3.11",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
    ],
    entry_points={
        "console_scripts": ["klp-build=klpbuild.main:main"],
    },
    install_requires=[
        "configparser",
        "cached_property",
        "GitPython",
        "lxml",
        "mako",
        "markupsafe",
        "natsort",
        "osc-tiny",
        "requests",
        "filelock",
        "pyelftools",
        "zstandard",
        "python-bugzilla",
        "python-magic",
        "tabulate",
        "termcolor"
    ],
    setuptools_git_versioning=_git_versioning,
    setup_requires=_setup_requires,
)
