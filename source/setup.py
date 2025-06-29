from setuptools import setup, find_packages
import py2exe

setup(
    console = [
      "source/main.py"
    ],
    windows = [
    ],
    options = {
        "py2exe" : {
            "dist_dir": "bin",
            "includes": "charset_normalizer.md__mypyc",
        }
    },
    packages = find_packages(),
)
