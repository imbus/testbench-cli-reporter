pushd %~dp0
pyinstaller -i ../imbusTB.ico --onefile --name TestBenchCliReporter --clean -y --distpath . run.py
popd
