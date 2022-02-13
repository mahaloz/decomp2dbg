try:
    from setuptools import setup
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    from distutils.core import setup
    import os
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

setup(
    name='decomp2gef',
    version='1.2.0',
    packages=packages,
    install_requires=[
        "sortedcontainers",
        "PyQT5",
        "pyelftools"
    ],
    description='Syncing framework for decompilers and debuggers',
    url='https://github.com/mahaloz/decomp2gef',
)
