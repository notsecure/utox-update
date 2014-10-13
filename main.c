#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32_IE
#define _WIN32_IE 0x0800
#endif

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0600

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#include <commctrl.h>
#include <shobjidl.h>
#include <shlobj.h>
#define close(x) closesocket(x)

#include <sodium.h>
#include "xz/xz.h"

#define GET_NAME "win32-latest"
#define HOST "dl.utox.org"

#define VERSION 2

static const uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES] = {
    0x88, 0x90, 0x5F, 0x29, 0x46, 0xBE, 0x7C, 0x4B, 0xBD, 0xEC, 0xE4, 0x67, 0x14, 0x9C, 0x1D, 0x78,
    0x48, 0xF4, 0xBC, 0x4F, 0xEC, 0x1A, 0xD1, 0xAD, 0x6F, 0x97, 0x78, 0x6E, 0xFE, 0xF3, 0xCD, 0xA1
};

static const uint8_t self_update_public_key[crypto_sign_ed25519_PUBLICKEYBYTES] = {
    0x52, 0xA7, 0x9B, 0xCA, 0x48, 0x35, 0xD6, 0x34, 0x5E, 0x7D, 0xEF, 0x8B, 0x97, 0xC3, 0x54, 0x2D,
    0x37, 0x9A, 0x9A, 0x8B, 0x00, 0xEB, 0xF3, 0xA8, 0xAD, 0x03, 0x92, 0x3E, 0x0E, 0x50, 0x77, 0x58
};

static const char request_version[] =
    "GET /version1 HTTP/1.0\r\n"
    "Host: " HOST "\r\n"
    "\r\n";

static char request[] =
    "GET /" GET_NAME " HTTP/1.0\r\n"
    "Host: " HOST "\r\n"
    "\r\n";

static char filename[32] = GET_NAME;
static uint8_t recvbuf[0x10000];

static HHOOK hook;
static int state;
static void *addr;
static int family, addrlen;
static HWND progress_update;
static _Bool restart;
static _Bool enable[3];

uint32_t inflate(void *dest, void *src, uint32_t dest_size, uint32_t src_len)
{
    xz_crc32_init();

    struct xz_dec *dec = xz_dec_init(XZ_SINGLE, 0);
    if(!dec) {
        return 0;
    }

    struct xz_buf buf = {
        .in = src,
        .in_pos = 0,
        .in_size = src_len,

        .out = dest,
        .out_pos = 0,
        .out_size = dest_size,
    };

    int r = xz_dec_run(dec, &buf);
    xz_dec_end(dec);

    printf("%i\n", r);

    /* out_pos is only set on success*/
    return buf.out_pos;
}

void* checksignature(void *data, uint32_t dlen, const uint8_t *pk, unsigned long long *olen)
{
    void *mdata;
    int r;

    mdata = malloc(dlen);
    if(!mdata) {
        printf("malloc failed\n");
        free(data);
        return NULL;
    }

    r = crypto_sign_ed25519_open(mdata, olen, data, dlen, pk);
    free(data);

    if(r == -1) {
        printf("invalid signature\n");
        free(mdata);
        return NULL;
    }

    return mdata;
}

void* download(int family, const void *addr, size_t addrlen, const char *request, uint16_t requestlen, uint32_t *olen, uint32_t maxlen)
{
    uint32_t sock, len, rlen, dlen;
    void *data;
    _Bool header = 0;

    sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if(sock == ~0) {
        printf("socket failed\n");
        return NULL;
    }

    if(connect(sock, addr, addrlen) != 0) {
        printf("connect failed\n");
        close(sock);
        return NULL;
    }

    if(send(sock, request, requestlen, 0) != requestlen) {
        printf("send failed\n");
        close(sock);
        return NULL;
    }

    while((len = recv(sock, (char*)recvbuf, 0xFFFF, 0)) > 0) {
        if(!header) {
            /* work with a null-terminated buffer */
            recvbuf[len] = 0;

            /* check for "Not Found" response (todo: only check first line of response)*/
            if(strstr((char*)recvbuf, "404 Not Found\r\n")) {
                printf("Not Found\n");
                break;
            }

            /* find the length field */
            char *str = strstr((char*)recvbuf, "Content-Length: ");
            if(!str) {
                printf("invalid HTTP response (1)\n");
                break;
            }

            /* parse the length field */
            str += sizeof("Content-Length: ") - 1;
            dlen = strtol(str, NULL, 10);
            if(dlen > maxlen) {
                printf("too large\n");
                break;
            }

            /* find the end of the http response header */
            str = strstr(str, "\r\n\r\n");
            if(!str) {
                printf("invalid HTTP response (2)\n");
                break;
            }

            str += sizeof("\r\n\r\n") - 1;

            /* allocate buffer to read into) */
            data = malloc(dlen);
            if(!data) {
                printf("malloc failed (1) (%u)\n", dlen);
                break;
            }

            printf("Download size: %u\n", dlen);

            /* read the first piece */
            rlen = len - (str - (char*)recvbuf);
            memcpy(data, str, rlen);

            header = 1;
            continue;
        }

        /* check if received too much */
        if(rlen + len > dlen) {
            printf("bad download\n");
            break;
        }

        memcpy(data + rlen, recvbuf, len); rlen += len;
        if(progress_update) {
            PostMessage(progress_update, PBM_SETPOS, (rlen * 100) / dlen, 0);
        }
    }

    close(sock);

    if(!header) {
        /* read nothing or invalid header */
        printf("download() failed\n");
        return NULL;
    } else if(rlen != dlen) {
        printf("number of bytes read does not match (%u)\n", rlen);
        free(data);
        return NULL;
    }

    *olen = dlen;
    return data;
}

void* download_signed(int family, const void *addr, size_t addrlen, const char *request, uint16_t requestlen, uint32_t *olen, uint32_t maxlen, const uint8_t *pk)
{
    void *data, *mdata;
    uint32_t len, t;
    time_t now;
    unsigned long long mlen;

    data = download(family, addr, addrlen, request, requestlen, &len, maxlen + crypto_sign_ed25519_BYTES);
    if(!data) {
        return NULL;
    }

    mdata = checksignature(data, len, pk, &mlen);
    if(!mdata) {
        return NULL;
    }

    time(&now);
    memcpy(&t, mdata, 4);

    printf("signed %u, now %u\n", (uint32_t)t, (uint32_t)now);

    if(t < now && now - t >= 60 * 60 * 24 * 8) {
        /* build is more than 1 week old: expired */
        printf("expired signature (%u)\n", (uint32_t)(now - t));
        free(mdata);
        return NULL;
    }

    *olen = mlen;
    return mdata;
}

void* download_signed_compressed(int family, const void *addr, size_t addrlen, const char *request, uint16_t requestlen, uint32_t *olen, uint32_t maxlen, const uint8_t *pk)
{
    void *data, *mdata;
    uint32_t len, mlen;

    mdata = download_signed(family, addr, addrlen, request, requestlen, &mlen, maxlen, pk);
    if(!mdata) {
        printf("file download failed\n");
        return NULL;
    }

    /* inflate */
    data = malloc(maxlen);
    if(!data) {
        printf("malloc failed (2) (%u)\n", maxlen);
        free(mdata);
        return NULL;
    }

    len = inflate(data, mdata + 4, maxlen, mlen - 4);
    free(mdata);
    if(len == 0) {
        printf("inflate failed\n");
        free(data);
        return NULL;
    }

    *olen = len;
    return data;
}

static _Bool selfupdate(void *data, uint32_t dlen)
{
    #ifdef __WIN32__
    char file_path[MAX_PATH], new_path[MAX_PATH];
    uint32_t len;
    FILE *file;

    len = GetModuleFileName(NULL, file_path, MAX_PATH);
    memcpy(new_path, file_path, len);
    new_path[len++] = '.';
    new_path[len++] = 'o';
    new_path[len++] = 'l';
    new_path[len++] = 'd';
    new_path[len] = 0;

    DeleteFile(new_path);
    MoveFile(file_path, new_path);

    file = fopen(file_path, "wb");
    if(!file) {
        return 0;
    }

    fwrite(data, 1, dlen, file);
    fclose(file);

    ShellExecute(NULL, "open", file_path, NULL, NULL, SW_SHOW);
    return 1;
    #else
    /* self update not implemented */
    return 0;
    #endif
}

static void versioncheck_thread(void *arg)
{
    FILE *file;
    void *data;
    char *str;
    uint32_t len;
    struct addrinfo *root, *info;
    _Bool newversion;

    if(getaddrinfo(HOST, "80", NULL, &root) != 0) {
        printf("getaddrinfo failed\n");
        EndDialog(arg, 1);
        return;
    }

    info = root;
    newversion = 0;
    do {
        data = download_signed(info->ai_family, info->ai_addr, info->ai_addrlen, request_version, sizeof(request_version) - 1, &len, 7 + 4, public_key);
        if(!data) {
            printf("version download failed\n");
            continue;
        }

        if(len != 7 + 4) {
            printf("invalid version length (%u)\n", len);
            free(data);
            continue;
        }

        str = data + 4;
        len -= 4;

        if(str[6] > VERSION + '0') {
            printf("new updater version available (%u)\n", str[6]);
            free(data);

            memcpy(request + 8, "selfpdate", sizeof("selfpdate") - 1);
            data = download_signed_compressed(info->ai_family, info->ai_addr, info->ai_addrlen, request, sizeof(request) - 1, &len, 1024 * 1024 * 4, self_update_public_key);
            if(!data) {
                printf("self update download failed\n");
                break;
            }

            if(selfupdate(data, len)) {
                printf("successful self update\n");
                filename[0] = 0;
                restart = 1;
            }
            free(data);
            break;
        }

        if(str[5] == ' ') {
            str[5] = 0;
        } else {
            str[6] = 0;
        }

        strcpy(filename + 6, str);
        strcat(filename, ".exe");
        printf("Version: %s\n", str);
        free(data);

        /* check if we already have this version */
        file = fopen(filename, "rb");
        if(file) {
            printf("Already up to date\n");
            fclose(file);
            break;
        }

        family = info->ai_family;
        addrlen = info->ai_addrlen;
        addr = malloc(addrlen);
        if(!addr) {
            break;
        }

        memcpy(addr, info->ai_addr, addrlen);
        newversion = 1;
        break;
    } while((info = info->ai_next));

    freeaddrinfo(root);
    EndDialog(arg, !newversion);
}

static void download_thread(void *arg)
{
    FILE *file;
    void *data;
    uint32_t len, rlen;

    HWND *hwnd = arg;

    progress_update = hwnd[1];
    data = download_signed_compressed(family, addr, addrlen, request, sizeof(request) - 1, &len, 1024 * 1024 * 4, public_key);
    progress_update = NULL;
    if(!data) {
        goto FAIL;
    }

    printf("Inflated size: %u\n", len);

    /* delete old version */
    file = fopen("version", "rb");
    if(file) {
        char oldname[32];
        rlen = fread(oldname, 1, sizeof(oldname) - 1, file);
        oldname[rlen] = 0;

        DeleteFile(oldname);
        fclose(file);
    }

    /* write file */
    file = fopen(filename, "wb");
    if(!file) {
        printf("fopen failed\n");
        free(data);
        goto FAIL;
    }

    rlen = fwrite(data, 1, len, file);
    fclose(file);
    free(data);
    if(rlen != len) {
        printf("write failed (%u)\n", rlen);
        goto FAIL;
    }

    /* write version to file */
    file = fopen("version", "wb");
    if(file) {
        fprintf(file, "%s", filename);
        fclose(file);
    }

    EndDialog(hwnd[0], 0);
    return;
FAIL:
    EndDialog(hwnd[0], 1);
}

static LRESULT CALLBACK HookProc(INT nCode, WPARAM wParam, LPARAM lParam)
{
    if(state && nCode == HC_ACTION) {
        CWPSTRUCT* p = (CWPSTRUCT*)lParam;
        if(p->message == WM_INITDIALOG) {
            char pszClassName[32];
            GetClassName(p->hwnd, pszClassName, sizeof(pszClassName));
            if(strcmp(pszClassName, "#32770") == 0) {
                HWND wnd;
                if(state == 1 || state == 2) {
                    wnd = FindWindowEx(p->hwnd, NULL, NULL, "OK");
                    if(wnd) {
                        SetWindowText(wnd, "Cancel");
                    }
                }

                if(state == 2) {
                    RECT r;
                    GetClientRect(p->hwnd, &r);
                    wnd = CreateWindowEx(0, PROGRESS_CLASS, NULL, WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 10, 50, r.right - 20, 30, p->hwnd, NULL, GetModuleHandle(NULL), NULL);

                    HWND *arg = malloc(sizeof(HWND) * 2);
                    arg[0] = p->hwnd;
                    arg[1] = wnd;
                    _beginthread(download_thread, 0, arg);
                } else if (state == 1) {
                    _beginthread(versioncheck_thread, 0, p->hwnd);
                } else {
                    RECT r;
                    GetClientRect(p->hwnd, &r);
                    WPARAM font = (WPARAM)GetStockObject(DEFAULT_GUI_FONT);
                    wnd = CreateWindowEx(0, "Button", "Create Start Menu shortcut", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 15, 10, r.right - 20, 25, p->hwnd, (HMENU)0x8000, GetModuleHandle(NULL), NULL);
                    SendMessage(wnd, WM_SETFONT, font, 0);
                    SendMessage(wnd, BM_SETCHECK, BST_CHECKED, 0); enable[0] = 1;
                    wnd = CreateWindowEx(0, "Button", "Create Desktop shortcut", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 15, 35, r.right - 20, 25, p->hwnd, (HMENU)0x8001, GetModuleHandle(NULL), NULL);
                    SendMessage(wnd, WM_SETFONT, font, 1);
                    SendMessage(wnd, BM_SETCHECK, BST_CHECKED, 0); enable[1] = 1;
                    wnd = CreateWindowEx(0, "Button", "Open tox:// URLs with uTox", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 15, 60, r.right - 20, 25, p->hwnd, (HMENU)0x8002, GetModuleHandle(NULL), NULL);
                    SendMessage(wnd, WM_SETFONT, font, 1);
                    SendMessage(wnd, BM_SETCHECK, BST_CHECKED, 0); enable[2] = 1;
                }
            }
        }

        if(state == 3 && p->message == WM_COMMAND) {
            char pszClassName[32];
            GetClassName(p->hwnd, pszClassName, sizeof(pszClassName));
            if(strcmp(pszClassName, "#32770") == 0) {
                if(p->wParam & 0x8000) {
                    enable[p->wParam & 3] = !enable[p->wParam & 3];
                }
            }
        }
    }
    return CallNextHookEx(hook, nCode, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR cmd, int nCmdShow)
{
    if(*cmd) {
        HMODULE hModule = GetModuleHandle(NULL);
        char path[MAX_PATH], *s;
        int len = GetModuleFileName(hModule, path, MAX_PATH);
        s = path + len;
        while(*s != '\\') {
            s--;
        }
        *s = 0;
        SetCurrentDirectory(path);
    }

    FILE *file;
    uint32_t len;
    /* initialize winsock */
    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    /* check if we are on a 64-bit system*/
    _Bool iswow64 = 0;
    _Bool (WINAPI *fnIsWow64Process)(HANDLE, _Bool*)  = (void*)GetProcAddress(GetModuleHandleA("kernel32"),"IsWow64Process");
    if(fnIsWow64Process) {
        fnIsWow64Process(GetCurrentProcess(), &iswow64);
    }

    if(iswow64) {
        /* replace the arch in the request/filename strings (todo: not use constants for offsets) */
        request[8] = '6';
        request[9] = '4';
        filename[3] = '6';
        filename[4] = '4';
        printf("detected 64bit system\n");
    }

    /* init common controls */
    INITCOMMONCONTROLSEX InitCtrlEx;

    InitCtrlEx.dwSize = sizeof(INITCOMMONCONTROLSEX);
	InitCtrlEx.dwICC = ICC_PROGRESS_CLASS;
	InitCommonControlsEx(&InitCtrlEx);

    /* run */
    hook = SetWindowsHookEx(WH_CALLWNDPROC, HookProc, hInstance, GetCurrentThreadId());

    state = 1;
    if(MessageBox(NULL, "Checking for new updates...", "uTox Updater", MB_OK)) {
        goto END;
    }

    file = fopen("version", "rb");
    if(file) {
        fclose(file);

        state = 0;
        if(MessageBox(NULL, "A new version of uTox is available.\nUpdate?", "uTox Updater", MB_YESNO | MB_ICONQUESTION) != IDYES) {
            goto END;
        }
    } else {
        state = 3;
        if(MessageBox(NULL, "\t\t\t\t\t\t\r\n\r\n\r\n\r\n\r\n\r\n", "uTox Updater", MB_OKCANCEL) != IDOK) {
            goto END;
        }

        printf("options: %u %u %u\n", enable[0], enable[1], enable[2]);

        state = 0;

        HRESULT hr;
        _Bool quit = 0;
        wchar_t selfpath[MAX_PATH];
        GetModuleFileNameW(hInstance, selfpath, MAX_PATH);

        hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        if(SUCCEEDED(hr)) {
            IFileOpenDialog *pFileOpen;
            hr = CoCreateInstance(&CLSID_FileOpenDialog, NULL, CLSCTX_ALL, &IID_IFileOpenDialog, (void*)&pFileOpen);
            if(SUCCEEDED(hr)) {
                /*wchar_t *sh_path;
                hr = SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, NULL, &sh_path);
                if(SUCCEEDED(hr)) {
                    IShellItem *si;
                    hr = SHCreateItemFromParsingName(sh_path, NULL, &IID_IShellItem, (void**)&si);
                    if(SUCCEEDED(hr)) {
                        hr = pFileOpen->lpVtbl->SetDefaultFolder(pFileOpen, si);
                        si->lpVtbl->Release(si);
                    }

                    CoTaskMemFree(sh_path);
                }*/

                hr = pFileOpen->lpVtbl->SetOptions(pFileOpen, FOS_PICKFOLDERS);
                hr = pFileOpen->lpVtbl->SetTitle(pFileOpen, L"Install Location");
                hr = pFileOpen->lpVtbl->Show(pFileOpen, NULL);
                if(SUCCEEDED(hr)) {
                    IShellItem *pItem;
                    hr = pFileOpen->lpVtbl->GetResult(pFileOpen, &pItem);
                    if(SUCCEEDED(hr)) {
                        PWSTR pszFilePath;
                        hr = pItem->lpVtbl->GetDisplayName(pItem, SIGDN_FILESYSPATH, &pszFilePath);

                        // Display the file name to the user.
                        if(SUCCEEDED(hr)) {
                            SetCurrentDirectoryW(pszFilePath);
                            CreateDirectory("Tox", NULL);
                            SetCurrentDirectory("Tox");
                            CoTaskMemFree(pszFilePath);
                            CopyFileW(selfpath, L"utox_runner.exe", 0);
                        }
                        pItem->lpVtbl->Release(pItem);
                    }
                } else {
                    quit = 1;
                }
                pFileOpen->lpVtbl->Release(pFileOpen);
            }
        } else {
            quit = 1;
        }

        if(quit) {
            //CoUninitialize();
            goto END;
        }

        if(!SUCCEEDED(hr)) {
            wchar_t path[MAX_PATH];
            BROWSEINFOW bi = {
                .pszDisplayName = path,
                .lpszTitle = L"Install Location",
                .ulFlags = BIF_USENEWUI | BIF_NONEWFOLDERBUTTON,
            };
            LPITEMIDLIST lpItem = SHBrowseForFolderW(&bi);
            if(!lpItem) {
                goto END;
            }

            SHGetPathFromIDListW(lpItem, path);
            SetCurrentDirectoryW(path);
            CreateDirectory("Tox", NULL);
            SetCurrentDirectory("Tox");
            CopyFileW(selfpath, L"utox_runner.exe", 0);
        }

        char dir[MAX_PATH];
        if(enable[0] || enable[1]) {
            //start menu
            IShellLink* psl;

            // Get a pointer to the IShellLink interface. It is assumed that CoInitialize
            // has already been called.
            hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLink, (LPVOID*)&psl);
            if(SUCCEEDED(hr)) {
                IPersistFile* ppf;

                // Set the path to the shortcut target and add the description.

                GetCurrentDirectory(MAX_PATH, dir);
                psl->lpVtbl->SetWorkingDirectory(psl, dir);
                strcat(dir, "\\utox_runner.exe");
                psl->lpVtbl->SetPath(psl, dir);
                psl->lpVtbl->SetDescription(psl, "Tox");

                // Query IShellLink for the IPersistFile interface, used for saving the
                // shortcut in persistent storage.
                hr = psl->lpVtbl->QueryInterface(psl, &IID_IPersistFile, (LPVOID*)&ppf);

                if(SUCCEEDED(hr)) {
                    wchar_t wsz[MAX_PATH];
                    if(enable[0]) {
                        hr = SHGetFolderPathW(NULL, CSIDL_STARTMENU, NULL, 0, wsz);
                        if(SUCCEEDED(hr)) {
                            printf("%ls\n", wsz);
                            wcscat(wsz, L"\\Programs\\Tox.lnk");
                            hr = ppf->lpVtbl->Save(ppf, wsz, TRUE);
                        }
                    }

                    if(enable[1]) {
                        hr = SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, wsz);
                        if(SUCCEEDED(hr)) {
                            wcscat(wsz, L"\\Tox.lnk");
                            hr = ppf->lpVtbl->Save(ppf, wsz, TRUE);
                        }
                    }

                    ppf->lpVtbl->Release(ppf);
                }
                psl->lpVtbl->Release(psl);
            }
        }

        if(enable[2]) {
            GetCurrentDirectory(MAX_PATH, dir);
            strcat(dir, "\\utox_runner.exe");

            char str[MAX_PATH];

            HKEY key;
            if(RegCreateKeyEx(HKEY_CLASSES_ROOT, "tox", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL) == ERROR_SUCCESS) {
                printf("nice\n");
                RegSetValueEx(key, NULL, 0, REG_SZ, (BYTE*)"URL:Tox Protocol", sizeof("URL:Tox Protocol"));
                RegSetValueEx(key, "URL Protocol", 0, REG_SZ, (BYTE*)"", sizeof(""));

                HKEY key2;
                if(RegCreateKeyEx(key, "DefaultIcon", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key2, NULL) == ERROR_SUCCESS) {
                    int i = sprintf(str, "%s,101", dir) + 1;
                    RegSetValueEx(key2, NULL, 0, REG_SZ, (BYTE*)str, i);
                }

                if(RegCreateKeyEx(key, "shell", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key2, NULL) == ERROR_SUCCESS) {
                    if(RegCreateKeyEx(key2, "open", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL) == ERROR_SUCCESS) {
                        if(RegCreateKeyEx(key, "command", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key2, NULL) == ERROR_SUCCESS) {
                            int i = sprintf(str, "%s %%1", dir) + 1;
                            RegSetValueEx(key2, NULL, 0, REG_SZ, (BYTE*)str, i);
                        }
                    }
                }
            }
        }

        CoUninitialize();
    }

    state = 2;
    if(MessageBox(NULL, "Downloading update\t\t\t\t\t\t\r\n\r\n\r\n\r\n", "uTox Updater", MB_OK)) {
        goto END;
    }

    state = 0;
    MessageBox(NULL, "Update successful.", "uTox Updater", MB_OK);

    printf("success!\n");

    END:
    if(!restart) {
        file = fopen("version", "rb");
        if(file) {
            len = fread(filename, 1, sizeof(filename) - 1, file);
            filename[len] = 0;
            fclose(file);
        }

        ShellExecute(NULL, "open", filename, cmd, NULL, SW_SHOW);
    }

    free(addr);
    UnhookWindowsHookEx(hook);
    return 0;
}
