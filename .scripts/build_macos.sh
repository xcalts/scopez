python -m pip install -U nuitka
nuitka --standalone --onefile --follow-imports --lto=yes --assume-yes-for-downloads ./src/main.py
mv ./main.bin ./scopez
tar -cvf scopez.tar ./scopez
7z a -tgzip -mx=9 scopez.tar.gz scopez.tar
mv scopez.tar.gz scopez-macos-arm64.tar.gz
rm -rf main.build
rm -rf main.dist
rm -rf main.onefile-build
rm scopez.tar
rm scopez