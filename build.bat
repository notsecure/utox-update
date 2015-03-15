mkdir build

windres resources.rc -O coff -o build/resources.res

gcc -o build/utox-update.exe build/resources.res main.c utils.c xz/*.c -lcomctl32 -luuid -lole32 -lgdi32 -lws2_32 -lsodium -s -Ofast