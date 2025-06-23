#!/bin/bash

pushd "$(dirname "$0")" > /dev/null

pyinstaller -i ../imbusTB.ico --onefile --name TestBenchCliReporter --clean -y --distpath . run.py

popd > /dev/null
