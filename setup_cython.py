"""Cython build script — compiles MarlinSpike modules to .so shared objects.

Run from the repo root:

    python setup_cython.py build_ext --inplace
"""
from Cython.Build import cythonize
from setuptools import setup

setup(
    ext_modules=cythonize(
        [
            "marlinspike/engine.py",
            "marlinspike/auth.py",
            "marlinspike/models.py",
            "marlinspike/config.py",
        ],
        compiler_directives={"language_level": "3"},
    ),
)
