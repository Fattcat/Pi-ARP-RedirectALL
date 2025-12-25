- https://www.reqrypt.org/windivert.html
## command to start
```
pyinstaller ^
  --onefile ^
  --windowed ^
  --add-binary "WinDivert.dll;." ^
  --hidden-import pydivert ^
  --name "ARP-MITM" ^
  main.py
```
