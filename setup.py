# Copyright (c) 2020 Stig Rune Sellevag
#
# This file is distributed under the MIT License. See the accompanying file
# LICENSE.txt or http://www.opensource.org/licenses/mit-license.php for terms
# and conditions.

import setuptools


setuptools.setup(
    name="snram",
    version="0.1",
    author="Stig Rune Sellevag",
    author_email="stig-rune.sellevag@ffi.no",
    license="MIT License",
    description="Network Risk Assessment",
    url="git@gitlabu.ffi.no:srs/snram.git",
    packages=setuptools.find_packages(),
    install_requires=[
        "numpy",
        "matplotlib",
        "pandas",
        "networkx",
        "pyomo"
    ],
    scripts=["scripts/snram_run.py"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
