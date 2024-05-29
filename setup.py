import re
from pathlib import Path

from setuptools import find_packages, setup

CURDIR = Path(__file__).absolute().parent

with (CURDIR / "src" / "TestBenchCliReporter" / "__main__.py").open(encoding="utf-8") as f:
    match = re.search('\n__version__ = "(.*)"', f.read())
    VERSION = match.group(1) if match else "unknown"

with Path("README.md").open() as fh:
    long_description = fh.read()

setup(
    name="testbench-cli-reporter",
    version=VERSION,
    author="imbus AG | Zacharias Daum & René Rohner",
    author_email="rene.rohner@imbus.de",
    description="CLI Tool to Export XML-Full-Reports from TestBench",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/imbus/testbench-cli-reporter",
    package_dir={"": "src"},
    packages=find_packages("src"),
    entry_points={
        "console_scripts": [
            "testbench-cli-reporter=TestBenchCliReporter.__main__:main",
            "TestBenchCliReporter=TestBenchCliReporter.__main__:main",
        ]
    },
    classifiers=[
        "Environment :: Console",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Testing",
        "Topic :: Software Development :: Testing :: Acceptance",
    ],
    install_requires=[
        "questionary>=1.9.0",
        "requests",
        "urllib3",
        "typing-extensions >= 3.7.4.3",
    ],
    python_requires=">=3.7",
)
