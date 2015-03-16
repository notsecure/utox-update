#Self-updater for uTox
downloads signed updates from dl.utox.org

#How it works

1. Builds are made locally and signed with libsodium's crypto_sign_ed25519() and my secret signing key then uploaded to dl.utox.org

2. Updater reads the latest version (dl.utox.org/version), if it already has this version it skips to last step

3. Downloads dl.utox.org/OSARCH-latest over http (ex: win64-latest  for windows 64 bit)

4. Uses libsodium's crypto_sign_ed25519_open() using my public signing key (88905F2946BE7C4BBDECE467149C1D7848F4BC4FEC1AD1AD6F97786EFEF3CDA1) to verify the build

5. Checks the 4 byte timestamp to verify that the build is not expired (1 week)

6. Decompresses the build, writes it to a file

7. Run the file

#Adding and modifiying resources
* The resource.rc file contains the main dialog definition, default icon, and mainfest that enables visual styles.
* Use [ResEdit](www.resedit.net) to open and modify it.

#Building
* requires mingw-w64
* on windows use build.bat
* on linux use build.sh

#Todo

* Remove libsodium dependency