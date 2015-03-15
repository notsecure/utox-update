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

#Building

    windres icon.rc -O coff -o icon.res
    gcc icon.res main.c utils.c xz/*.c -lcomctl32 -luuid -lole32 -lgdi32 -lws2_32 -lsodium -s -Ofast

#Todo

* Remove libsodium dependency