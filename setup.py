import setuptools

with open("README.md", "r") as f:
    long_description = f.read()


setuptools.setup(
    name="klp-build",
    version="0.0.1",
    author="Marcos Paulo de Souza",
    author_email="mpdesouza@suse.com",
    description="The kernel livepatching creation tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.suse.de/live-patching/klp-build",
    packages=setuptools.find_packages(exclude=["tests"]),
    package_data={
        "scripts" : [
            "run-kgr-test.sh"
        ]
    },
    python_requires=">=3.6",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
    ],
    entry_points={
        "console_scripts": ["klp-build=klpbuild.main:main"],
    },
    install_requires=[
        "cached_property",
        "GitPython",
        "lxml",
        "mako",
        "markupsafe",
        "natsort",
        "osc-tiny",
        "requests",
    ],
)
