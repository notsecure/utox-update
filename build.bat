mkdir build

windres resource.rc -O coff -o build/resource.res

gcc -o build/utox-update.exe build/resource.res main.c utils.c xz/*.c -lcomctl32 -luuid -lole32 -lgdi32 -lws2_32 -lsodium -mwindows -s -Ofast