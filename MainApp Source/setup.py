from setuptools import setup, find_packages
import py2exe

setup(
    console = [
      "main.py"
    ],
    windows = [
    ],
    options = {
        "py2exe" : {
            "dist_dir": "../MainApp",
            "packages": ["pyshark"],
        }
    },
    packages = find_packages()
)
