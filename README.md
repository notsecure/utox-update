Self-updater for uTox, downloads signed updates from dl.utox.org

How it works

1) Downloads dl.utox.org/latest-OS-ARCH over http (ex: latest-win-64  for windows 64 bit)

2) libsodium's crypto_sign_ed25519_open() using my public signing key (88905F2946BE7C4BBDECE467149C1D7848F4BC4FEC1AD1AD6F97786EFEF3CDA1)

Todo

-Version checking
-Compression
-Windows version which downloads 32bit or 64bit depending system