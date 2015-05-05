#include <stdint.h>
#include <stdio.h>

#ifndef _WIN32_IE
#define _WIN32_IE 0x0800
#endif

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0600

#include <winsock2.h>
#include <windows.h>
#include <windowsx.h>
#include <shlobj.h>
#include <process.h>

#include "utils.h"
#include "consts.h"
#include "resource.h"

#define TOX_VERSION_NAME_MAX_LEN 32

#define UTOX_TITLE "uTox"
#define TOX_EXE_NAME "uTox.exe"

static char TOX_VERSION_NAME[TOX_VERSION_NAME_MAX_LEN];

static char TOX_UPDATER_PATH[MAX_PATH];
static uint32_t TOX_UPDATER_PATH_LEN;

static _Bool is_tox_installed;

// Called arguments

PSTR MY_CMD_ARGS;
HINSTANCE MY_HINSTANCE;

// Common UI

static HWND main_window;
static HWND progressbar;
static HWND status_label;


void set_download_progress(int progress) {
    if (progressbar) {
        PostMessage(progressbar, PBM_SETPOS, progress, 0);
    }
}

void set_current_status(char *status) {
    SetWindowText(status_label, status);
}

static void init_tox_version_name() {
    FILE *version_file = fopen("version", "rb");

    if (version_file) {
        int len = fread(TOX_VERSION_NAME, 1, sizeof(TOX_VERSION_NAME) - 1, version_file);
        TOX_VERSION_NAME[len] = 0;
        fclose(version_file);

        is_tox_installed = 1;
    }
}

#define UTOX_UPDATER_PARAM " --no-updater"

static void open_utox_and_exit() {
    char str[strlen(MY_CMD_ARGS) + sizeof(UTOX_UPDATER_PARAM)];
    strcpy(str, MY_CMD_ARGS);
    strcat(str, UTOX_UPDATER_PARAM);
    ShellExecute(NULL, "open", TOX_EXE_NAME, str, NULL, SW_SHOW);

    fclose(LOG_FILE);
    exit(0);
}

static void restart_updater() {
    ShellExecute(NULL, "open", TOX_UPDATER_PATH, MY_CMD_ARGS, NULL, SW_SHOW);

    fclose(LOG_FILE);
    exit(0);
}

static char* download_new_updater(uint32_t *new_updater_len) {
    char *new_updater = download_loop_all_host_ips(1, TOX_DOWNNLOAD_HOSTS, NUMBER_UPDATE_HOSTS, SELF_UPDATER_FILE_NAME, strlen(SELF_UPDATER_FILE_NAME), new_updater_len, 1024 * 1024 * 4, TOX_SELF_PUBLICK_UPDATE_KEY, 0, 0);

    return new_updater;
}

static _Bool install_new_updater(void *new_updater_data, uint32_t new_updater_data_len)
{
#ifdef __WIN32__
    char new_path[MAX_PATH] = {0};
    FILE *file;

    memcpy(new_path, TOX_UPDATER_PATH, TOX_UPDATER_PATH_LEN);
    strcat(new_path, ".old");

    DeleteFile(new_path);
    MoveFile(TOX_UPDATER_PATH, new_path);

    file = fopen(TOX_UPDATER_PATH, "wb");
    if(!file) {
        LOG_TO_FILE("failed to write new updater");
        return 0;
    }

    fwrite(new_updater_data, 1, new_updater_data_len, file);

    fclose(file);

    ShellExecute(NULL, "open", TOX_UPDATER_PATH, NULL, NULL, SW_SHOW);
    return 1;
#else
    /* self update not implemented */
    return 0;
#endif
}

/* return 0 on success.
 * return -1 if could not write file.
 * return -2 if download failed.
 */
static int download_and_install_new_utox_version()
{
    FILE *file;
    void *new_version_data;
    uint32_t len, rlen;
    new_version_data = download_loop_all_host_ips(1, TOX_DOWNNLOAD_HOSTS, NUMBER_UPDATE_HOSTS, GET_NAME, strlen(GET_NAME), &len, 1024 * 1024 * 4, TOX_SELF_PUBLICK_KEY, TOX_VERSION_NAME, APPENDED_VERSION_LENGTH);

    if (!new_version_data) {
        LOG_TO_FILE("download failed\n");
        if (is_tox_installed) {
            open_utox_and_exit();
        }

        return -2;
    }

    LOG_TO_FILE("Inflated size: %u\n", len);

    /* delete old version if found */
    file = fopen("version", "rb");
    if (file) {
        char old_name[32];
        rlen = fread(old_name, 1, sizeof(old_name) - 1, file);
        old_name[rlen] = 0;

        /* Only there for smooth update from old updater. */
        DeleteFile(old_name);
        fclose(file);
    }

    /* write file */
    file = fopen(TOX_EXE_NAME, "wb");
    if (!file) {
        LOG_TO_FILE("fopen failed\n");
        free(new_version_data);
        return -1;
    }

    rlen = fwrite(new_version_data, 1, len, file);
    fclose(file);
    free(new_version_data);
    if (rlen != len) {
        LOG_TO_FILE("write failed (%u)\n", rlen);
        return -1;
    }

    /* write version to file */
    file = fopen("version", "wb");
    if (file) {
        rlen = fwrite(TOX_VERSION_NAME, 1, APPENDED_VERSION_LENGTH, file);
        fclose(file);
        if (rlen != APPENDED_VERSION_LENGTH) {
            return -1;
        }

        return 0;
    }

    return -1;
}

static int check_new_version()
{
    FILE *file;
    char *new_version_data;
    uint32_t len;

    new_version_data = download_loop_all_host_ips(0, TOX_DOWNNLOAD_HOSTS, NUMBER_UPDATE_HOSTS, VERSION_FILE_NAME, strlen(VERSION_FILE_NAME), &len, 7 + 4, TOX_SELF_PUBLICK_KEY, 0, 0);

    if (!new_version_data) {
        LOG_TO_FILE("version download failed\n");
        return -1;
    }

    if (len != 7 + 4) {
        LOG_TO_FILE("invalid version length (%u)\n", len);
        free(new_version_data);
        return -1;
    }

    char str[7];
    memcpy(str, new_version_data + 4, 7);

    if (str[6] > VERSION + '0') {
        LOG_TO_FILE("new updater version available (%u)\n", str[6]);

        char *new_updater_data;
        uint32_t new_updater_data_len;

        new_updater_data = download_new_updater(&new_updater_data_len);

        if (!new_updater_data) {
            LOG_TO_FILE("self update download failed\n");
        } else {
            if (install_new_updater(new_updater_data, new_updater_data_len)) {
                LOG_TO_FILE("successful self update\n");

                free(new_version_data);

                restart_updater();
            }
        }
    }

    str[6] = 0;

    LOG_TO_FILE("Version: %s\n", str);
    free(new_version_data);

    if (memcmp(TOX_VERSION_NAME + 2, str, 6) == 0) {
        /* check if we already have the exe */
        file = fopen(TOX_EXE_NAME, "rb");
        if (!file) {
            LOG_TO_FILE("We don't have the file\n");
            fclose(file);
            return 1;
        }

        return 0;
    }

    memcpy(TOX_VERSION_NAME + 2, str, 7);
    return 1;
}

/* return 0 on success.
 * return -1 if could not write file.
 * return -2 if download failed.
 */
static int install_tox(int create_desktop_shortcut, int create_startmenu_shortcut, int use_with_tox_url, wchar_t *install_path, int install_path_len) {

    char dir[MAX_PATH];

    wchar_t selfpath[MAX_PATH];
    GetModuleFileNameW(MY_HINSTANCE, selfpath, MAX_PATH);

    SHCreateDirectoryExW(NULL, install_path, NULL);
    SetCurrentDirectoryW(install_path);
    if (CopyFileW(selfpath, L"utox_runner.exe", 0) == 0)
        return -1;

    set_current_status("downloading and installing tox...");

    int ret = download_and_install_new_utox_version();
    if (ret != 0)
        return ret;

    HRESULT hr;

    if (create_desktop_shortcut || create_startmenu_shortcut) {
        hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        if(SUCCEEDED(hr)) {
            //start menu
            IShellLink* psl;

            // Get a pointer to the IShellLink interface. It is assumed that CoInitialize
            // has already been called.
            hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLink, (LPVOID*)&psl);
            if (SUCCEEDED(hr)) {
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

                if (SUCCEEDED(hr)) {
                    wchar_t wsz[MAX_PATH];
                    if (create_startmenu_shortcut) {
                        hr = SHGetFolderPathW(NULL, CSIDL_STARTMENU, NULL, 0, wsz);
                        if (SUCCEEDED(hr)) {
                            LOG_TO_FILE("%ls\n", wsz);
                            wcscat(wsz, L"\\Programs\\Tox.lnk");
                            hr = ppf->lpVtbl->Save(ppf, wsz, TRUE);
                        }
                    }

                    if (create_desktop_shortcut) {
                        hr = SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, wsz);
                        if (SUCCEEDED(hr)) {
                            wcscat(wsz, L"\\Tox.lnk");
                            hr = ppf->lpVtbl->Save(ppf, wsz, TRUE);
                        }
                    }

                    ppf->lpVtbl->Release(ppf);
                }
                psl->lpVtbl->Release(psl);
            }
        }
    }

    if (use_with_tox_url) {
        GetCurrentDirectory(MAX_PATH, dir);
        strcat(dir, "\\" TOX_EXE_NAME);

        char str[MAX_PATH];

        HKEY key;
        if (RegCreateKeyEx(HKEY_CLASSES_ROOT, "tox", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL) == ERROR_SUCCESS) {
            LOG_TO_FILE("nice\n");
            RegSetValueEx(key, NULL, 0, REG_SZ, (BYTE*)"URL:Tox Protocol", sizeof("URL:Tox Protocol"));
            RegSetValueEx(key, "URL Protocol", 0, REG_SZ, (BYTE*)"", sizeof(""));

            HKEY key2;
            if (RegCreateKeyEx(key, "DefaultIcon", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key2, NULL) == ERROR_SUCCESS) {
                int i = sprintf(str, "%s,101", dir) + 1;
                RegSetValueEx(key2, NULL, 0, REG_SZ, (BYTE*)str, i);
            }

            if (RegCreateKeyEx(key, "shell", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key2, NULL) == ERROR_SUCCESS) {
                if (RegCreateKeyEx(key2, "open", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL) == ERROR_SUCCESS) {
                    if (RegCreateKeyEx(key, "command", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key2, NULL) == ERROR_SUCCESS) {
                        int i = sprintf(str, "%s %%1", dir) + 1;
                        RegSetValueEx(key2, NULL, 0, REG_SZ, (BYTE*)str, i);
                    }
                }
            }
        }
    }

    return 0;
}

static void start_installation() {
    HWND desktop_shortcut_checkbox = GetDlgItem(main_window, ID_DESKTOP_SHORTCUT_CHECKBOX);
    HWND startmenu_shortcut_checkbox = GetDlgItem(main_window, ID_STARTMENU_SHORTCUT_CHECKBOX);
    HWND tox_url_checkbox = GetDlgItem(main_window, ID_TOX_URL_CHECKBOX);
    HWND browse_textbox = GetDlgItem(main_window, ID_BROWSE_TEXTBOX);

    _Bool create_desktop_shortcut, create_startmenu_shortcut, use_with_tox_url;

    wchar_t install_path[MAX_PATH];
    int install_path_len = GetWindowTextW(browse_textbox, install_path, MAX_PATH);

    if (install_path_len == 0) {
        MessageBox(main_window, "Please select a folder to install uTox in", "Error", MB_OK);
        return;
    }

    create_desktop_shortcut = Button_GetCheck(desktop_shortcut_checkbox);
    create_startmenu_shortcut = Button_GetCheck(startmenu_shortcut_checkbox);
    use_with_tox_url = Button_GetCheck(tox_url_checkbox);

    LOG_TO_FILE("will install with options: %u %u %u %ls\n", create_desktop_shortcut, create_startmenu_shortcut, use_with_tox_url, install_path);

    if (MessageBox(main_window, "Are you sure you want to continue?", "uTox Updater", MB_YESNO) != IDYES)
        return;

    int ret = install_tox(create_desktop_shortcut, create_startmenu_shortcut, use_with_tox_url, install_path, install_path_len);
    if (ret == 0) {
        set_current_status("installation complete");

        MessageBox(main_window, "Installation successful.", "uTox Updater", MB_OK);
        open_utox_and_exit();
    } else if (ret == -1) {
        set_current_status("could not write to install directory.");
    } else if (ret == -2) {
        set_current_status("download error, please check your internet connection and try again.");
    } else {
        set_current_status("error during installation");

        MessageBox(main_window, "Installation failed. If it's not an internet issue please send the log file (tox_log.txt) to the developers.", "uTox Updater", MB_OK);
        exit(0);
    }
}

static void set_utox_path(wchar_t *path)
{
    HWND browse_textbox = GetDlgItem(main_window, ID_BROWSE_TEXTBOX);

    unsigned int str_len = wcslen(path);
    if (str_len != 0) {
        wchar_t file_path[str_len + sizeof(L"\\uTox")];
        memcpy(file_path, path, str_len * sizeof(wchar_t));
        memcpy(file_path + str_len, L"\\uTox", sizeof(L"\\uTox"));
        SetWindowTextW(browse_textbox, file_path);
    }
}

static void browse_for_install_folder() {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    IFileOpenDialog *pFileOpen;
    hr = CoCreateInstance(&CLSID_FileOpenDialog, NULL, CLSCTX_ALL, &IID_IFileOpenDialog, (void*)&pFileOpen);
    if (SUCCEEDED(hr)) {
        hr = pFileOpen->lpVtbl->SetOptions(pFileOpen, FOS_PICKFOLDERS);
        hr = pFileOpen->lpVtbl->SetTitle(pFileOpen, L"Tox Install Location");
        hr = pFileOpen->lpVtbl->Show(pFileOpen, NULL);

        if (SUCCEEDED(hr)) {
            IShellItem *pItem;
            hr = pFileOpen->lpVtbl->GetResult(pFileOpen, &pItem);

            if (SUCCEEDED(hr)) {
                PWSTR pszFilePath;
                hr = pItem->lpVtbl->GetDisplayName(pItem, SIGDN_FILESYSPATH, &pszFilePath);

                if (SUCCEEDED(hr)) {
                    set_utox_path(pszFilePath);
                    CoTaskMemFree(pszFilePath);
                }
                pItem->lpVtbl->Release(pItem);
            }
        }
        pFileOpen->lpVtbl->Release(pFileOpen);

        CoUninitialize();
    }
    else {
        wchar_t path[MAX_PATH];
        BROWSEINFOW bi = {
            .pszDisplayName = path,
            .lpszTitle = L"Install Location",
            .ulFlags = BIF_USENEWUI | BIF_NONEWFOLDERBUTTON,
        };
        LPITEMIDLIST lpItem = SHBrowseForFolderW(&bi);
        if (!lpItem) {
            return;
        }

        SHGetPathFromIDListW(lpItem, path);
        set_utox_path(path);
    }
}

static void check_updates() {
    set_current_status("fetching new version data...");

    int new_version = check_new_version();

    if (new_version == -1) {
        MessageBox(main_window, "Error fetching latest version data. Please check your internet connection.\n\nExiting now...", "Error", MB_OK);
        exit(0);
    }

    set_current_status("version data fetched successfully");

    if (is_tox_installed) {

        set_download_progress(0);
        set_current_status("Found new version");

        if (new_version && MessageBox(NULL, "A new version of uTox is available.\nUpdate?", "uTox Updater", MB_YESNO | MB_ICONQUESTION) == IDYES) {
            download_and_install_new_utox_version();
        }

        open_utox_and_exit();
    }
}

INT_PTR CALLBACK MainDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);

    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;
    case WM_CLOSE:
        PostQuitMessage(0);
        break;

    case WM_COMMAND: {
        if (HIWORD(wParam) == BN_CLICKED) {
            int id = LOWORD(wParam);
            //HWND control_hwnd = (HWND)lParam;

            switch (id) {
            case ID_CANCEL_BUTTON:
                if (MessageBox(main_window, "Are you sure you want to exit?", "uTox Updater", MB_YESNO) == IDYES) {
                    if (is_tox_installed) {
                        open_utox_and_exit();
                    }
                    else {
                        exit(0);
                    }
                }
                break;

            case ID_INSTALL_BUTTON:
                _beginthread(start_installation, 0, 0);

                break;

            case ID_BROWSE_BUTTON:
                browse_for_install_folder();

                break;
            }
        }
        break;
    }
    }

    return (INT_PTR)FALSE;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR cmd, int nCmdShow)
{
    unsigned int counter = 0;
    while (1) {
        CreateMutex(NULL, 0, UTOX_TITLE);
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            if (counter < 2) {
                Sleep(500);
                ++counter;
            } else {
                return 0;
            }
        } else {
            break;
        }
    }

    MY_CMD_ARGS = cmd;
    MY_HINSTANCE = hInstance;

    TOX_UPDATER_PATH_LEN = GetModuleFileName(NULL, TOX_UPDATER_PATH, MAX_PATH);
    TOX_UPDATER_PATH[TOX_UPDATER_PATH_LEN] = 0;

    {
        char path[MAX_PATH], *s;
        memcpy(path, TOX_UPDATER_PATH, TOX_UPDATER_PATH_LEN + 1);
        s = path + TOX_UPDATER_PATH_LEN;
        while(*s != '\\') {
            s--;
        }

        *s = 0;
        SetCurrentDirectory(path);
    }

    LOG_FILE = fopen("tox_log.txt", "w");
    init_tox_version_name();

    /* initialize winsock */
    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        LOG_TO_FILE("WSAStartup failed\n");
        return 1;
    }

    /* check if we are on a 64-bit system */
    _Bool iswow64 = 0;
    _Bool (WINAPI *fnIsWow64Process)(HANDLE, _Bool*)  = (void*)GetProcAddress(GetModuleHandleA("kernel32"),"IsWow64Process");
    if(fnIsWow64Process) {
        fnIsWow64Process(GetCurrentProcess(), &iswow64);
    }

    if(iswow64) {
        /* replace the arch in the GET_NAME/TOX_VERSION_NAME strings (todo: not use constants for offsets) */
        GET_NAME[3] = '6';
        GET_NAME[4] = '4';
        TOX_VERSION_NAME[0] = '6';
        TOX_VERSION_NAME[1] = '4';
        LOG_TO_FILE("detected 64bit system\n");
    } else {
        GET_NAME[3] = '3';
        GET_NAME[4] = '2';
        TOX_VERSION_NAME[0] = '3';
        TOX_VERSION_NAME[1] = '2';
        LOG_TO_FILE("detected 32bit system\n");
    }

    if (!is_tox_installed) {
        /* init common controls */
        INITCOMMONCONTROLSEX InitCtrlEx;

        InitCtrlEx.dwSize = sizeof(INITCOMMONCONTROLSEX);
        InitCtrlEx.dwICC = ICC_PROGRESS_CLASS;
        InitCommonControlsEx(&InitCtrlEx);

        main_window = CreateDialog(MY_HINSTANCE, MAKEINTRESOURCE(IDD_MAIN_DIALOG), NULL, MainDialogProc);

        if (!main_window) {
            LOG_TO_FILE("error creating main window %lu\n", GetLastError());
            exit(0);
        }

        progressbar = GetDlgItem(main_window, ID_PROGRESSBAR);
        status_label = GetDlgItem(main_window, IDC_STATUS_LABEL);

        // show installer controls
        ShowWindow(GetDlgItem(main_window, ID_INSTALL_BUTTON), SW_SHOW);

        HWND desktop_shortcut_checkbox = GetDlgItem(main_window, ID_DESKTOP_SHORTCUT_CHECKBOX);
        Button_SetCheck(desktop_shortcut_checkbox, 1);
        ShowWindow(desktop_shortcut_checkbox, SW_SHOW);

        HWND startmenu_shortcut_checkbox = GetDlgItem(main_window, ID_STARTMENU_SHORTCUT_CHECKBOX);
        Button_SetCheck(startmenu_shortcut_checkbox, 1);
        ShowWindow(startmenu_shortcut_checkbox, SW_SHOW);

        ShowWindow(GetDlgItem(main_window, ID_TOX_URL_CHECKBOX), SW_SHOW);

        wchar_t appdatalocal_path[MAX_PATH] = {0};
        if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appdatalocal_path) == S_OK) {
            set_utox_path(appdatalocal_path);
        }

        ShowWindow(GetDlgItem(main_window, ID_BROWSE_TEXTBOX), SW_SHOW);
        ShowWindow(GetDlgItem(main_window, ID_BROWSE_BUTTON), SW_SHOW);
        ShowWindow(GetDlgItem(main_window, IDC_INSTALL_FOLDER_LABEL), SW_SHOW);
        ShowWindow(main_window, SW_SHOW);
    }

    _beginthread(check_updates, 0, NULL);

    MSG msg;

    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        DispatchMessage(&msg);
    }

    open_utox_and_exit();

    return 0;
}
