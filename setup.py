import setuptools

with open("README.md", "r") as f:
    long_description = f.read()


setuptools.setup(
    name="klp-build",
    author="Marcos Paulo de Souza",
    author_email="mpdesouza@suse.com",
    description="The kernel livepatching creation tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.suse.de/live-patching/klp-build",
    packages=setuptools.find_packages(exclude=["tests"]),
    package_data={"scripts": ["run-kgr-test.sh"]},
    python_requires=">=3.6",
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
        "zstandard"
    ],
    setuptools_git_versioning={
        "enabled": True,
    },
    setup_requires=[
        "setuptools-git-versioning>=2.0,<3"
    ],
)
