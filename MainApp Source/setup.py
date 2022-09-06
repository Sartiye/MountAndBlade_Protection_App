from distutils.core import setup
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
    }
)
