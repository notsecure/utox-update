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
#include <Windowsx.h>
#include <shlobj.h>

#include "utils.h"
#include "consts.h"

#define TOX_FILE_NAME_MAX_LEN 32
static char TOX_FILE_NAME[TOX_FILE_NAME_MAX_LEN] = GET_NAME;
static int TOX_FILE_NAME_LEN;

static char TOX_UPDATER_PATH[MAX_PATH];
static uint32_t TOX_UPDATER_PATH_LEN;

_Bool is_tox_installed;

// Called arguments

PSTR MY_CMD_ARGS;
HINSTANCE MY_HINSTANCE;

// Common UI

static HWND main_window;
static HWND progressbar;
static HWND cancel_button;
static HWND install_button;

// Installer UI
static HWND cancel_button;
static HWND install_button;
static HWND desktop_shortcut_checkbox;
static HWND startmenu_shortcut_checkbox;
static HWND tox_url_checkbox;

static HWND browse_button;
static HWND browse_textbox;
static HWND status_label;

static FILE* LOG_FILE;

void set_download_progress(int progress){
	if (progressbar) {
		PostMessage(progressbar, PBM_SETPOS, progress, 0);
	}
}

void set_current_status(char *status){
	SetWindowText(status_label, status);
}

void init_tox_file_name(){
	FILE *version_file = fopen("version", "rb");
	
	if (version_file) {
		TOX_FILE_NAME_LEN = fread(TOX_FILE_NAME, 1, sizeof(TOX_FILE_NAME) - 1, version_file);
		TOX_FILE_NAME[TOX_FILE_NAME_LEN] = 0;
		fclose(version_file);

		is_tox_installed = 1;
	}
}

static void open_utox_and_exit(){
	FILE *VERSION_FILE;
	int len;

	ShellExecute(NULL, "open", TOX_FILE_NAME, MY_CMD_ARGS, NULL, SW_SHOW);
	
	fclose(LOG_FILE);
	exit(0);
}

static void restart_updater(){
	ShellExecute(NULL, "open", TOX_UPDATER_PATH, MY_CMD_ARGS, NULL, SW_SHOW);
	
	fclose(LOG_FILE);
	exit(0);
}

static char* download_new_updater(int *new_updater_len){
	char *new_updater;

	memcpy(REQUEST + 8, "selfpdate", sizeof("selfpdate") - 1);

	new_updater = download_signed_compressed(TOX_DOWNNLOAD_HOST, sizeof(TOX_DOWNNLOAD_HOST),
		REQUEST, sizeof(REQUEST) - 1,
		new_updater_len,
		1024 * 1024 * 4,
		TOX_SELF_PUBLICK_UPDATE_KEY);

	return new_updater;
}

static _Bool install_new_updater(void *new_updater_data, uint32_t new_updater_data_len)
{
    #ifdef __WIN32__
    char new_path[MAX_PATH];
    FILE *file;

	memcpy(new_path, TOX_UPDATER_PATH, TOX_UPDATER_PATH_LEN);
	strcat(new_path, ".old");

    DeleteFile(new_path);
    MoveFile(TOX_UPDATER_PATH, new_path);

	file = fopen(TOX_UPDATER_PATH, "wb");
    if(!file) {
		fprintf(LOG_FILE, "failed to write new updater");
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

static void download_and_install_new_utox_version()
{
	FILE *file;
	void *new_version_data;
	uint32_t len, rlen;
	new_version_data = download_signed_compressed(TOX_DOWNNLOAD_HOST, sizeof(TOX_DOWNNLOAD_HOST),
									  REQUEST, sizeof(REQUEST) - 1,
									  &len,
									  1024 * 1024 * 4,
									  TOX_SELF_PUBLICK_KEY);

	if (!new_version_data) {
		fprintf(LOG_FILE, "download failed\n");
		open_utox_and_exit();
	}

	fprintf(LOG_FILE, "Inflated size: %u\n", len);

	/* delete old version if found */
	file = fopen("version", "rb");
	if (file) {
		char old_name[32];
		rlen = fread(old_name, 1, sizeof(old_name) - 1, file);
		old_name[rlen] = 0;

		DeleteFile(old_name);
		fclose(file);
	}

	/* write file */
	file = fopen(TOX_FILE_NAME, "wb");
	if (!file) {
		fprintf(LOG_FILE, "fopen failed\n");
		free(new_version_data);
		return;
	}

	rlen = fwrite(new_version_data, 1, len, file);
	fclose(file);
	free(new_version_data);
	if (rlen != len) {
		fprintf(LOG_FILE, "write failed (%u)\n", rlen);
		return;
	}

	/* write version to file */
	file = fopen("version", "wb");
	if (file) {
		fprintf(file, "%s", TOX_FILE_NAME);
		fclose(file);
	}
}

static int check_new_version()
{
	FILE *file;
	char *new_version_data;
	char *str;
	uint32_t len;
	_Bool newversion;

	newversion = 0;

	new_version_data = (char*) download_signed(TOX_DOWNNLOAD_HOST, sizeof(TOX_DOWNNLOAD_HOST),
		(char*)REQUEST_VERSION, sizeof(REQUEST_VERSION) - 1,
		&len,
		7 + 4,
		TOX_SELF_PUBLICK_KEY);

	if (!new_version_data) {
		fprintf(LOG_FILE, "version download failed\n");
		return -1;
	}

	if (len != 7 + 4) {
		fprintf(LOG_FILE, "invalid version length (%u)\n", len);
		free(new_version_data);
		return -1;
	}

	str = new_version_data + 4;
	len -= 4;

	if (str[6] > VERSION + '0') {
		fprintf(LOG_FILE, "new updater version available (%u)\n", str[6]);

		char *new_updater_data;
		int new_updater_data_len;

		new_updater_data = download_new_updater(&new_updater_data_len);
		
		if (!new_updater_data) {
			fprintf(LOG_FILE, "self update download failed\n");
			open_utox_and_exit();
		}

		if (install_new_updater(new_updater_data, new_updater_data_len)) {
			fprintf(LOG_FILE, "successful self update\n");

			free(new_version_data);

			restart_updater();
		}
	}

	if (str[5] == ' ') {
		str[5] = 0;
	}
	else {
		str[6] = 0;
	}

	strcpy(TOX_FILE_NAME + 6, str);
	strcat(TOX_FILE_NAME, ".exe");
	fprintf(LOG_FILE, "Version: %s\n", str);
	free(new_version_data);

	/* check if we already have this version */
	file = fopen(TOX_FILE_NAME, "rb");
	if (file) {
		fprintf(LOG_FILE, "Already up to date\n");
		fclose(file);
		return 0;
	}

	return 1;
}

static _Bool install_tox(int create_desktop_shortcut, int create_startmenu_shortcut, int use_with_tox_url, wchar_t *install_path, int install_path_len){

	char dir[MAX_PATH];

	wchar_t selfpath[MAX_PATH];
	GetModuleFileNameW(MY_HINSTANCE, selfpath, MAX_PATH);

	SetCurrentDirectoryW(install_path);
	CreateDirectory("Tox", NULL);
	SetCurrentDirectory("Tox");
	CopyFileW(selfpath, L"utox_runner.exe", 0);
	

	set_current_status("downloading and installing tox");

	download_and_install_new_utox_version();

	HRESULT hr;

	if (create_desktop_shortcut || create_startmenu_shortcut) {
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
				if (create_desktop_shortcut) {
					hr = SHGetFolderPathW(NULL, CSIDL_STARTMENU, NULL, 0, wsz);
					if (SUCCEEDED(hr)) {
						fprintf(LOG_FILE, "%ls\n", wsz);
						wcscat(wsz, L"\\Programs\\Tox.lnk");
						hr = ppf->lpVtbl->Save(ppf, wsz, TRUE);
					}
				}

				if (create_startmenu_shortcut) {
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

	if (use_with_tox_url) {
		GetCurrentDirectory(MAX_PATH, dir);
		strcat(dir, "\\utox_runner.exe");

		char str[MAX_PATH];

		HKEY key;
		if (RegCreateKeyEx(HKEY_CLASSES_ROOT, "tox", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL) == ERROR_SUCCESS) {
			fprintf(LOG_FILE, "nice\n");
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

	return 1;
}

void start_installiation(){

	_Bool create_desktop_shortcut, create_startmenu_shortcut, use_with_tox_url;

	wchar_t install_path[MAX_PATH];
	int install_path_len = GetWindowTextW(browse_textbox, install_path, MAX_PATH);

	if (install_path_len == 0){
		MessageBox(main_window, "Please select a folder to install uTox in", "Error", MB_OK);
		return;
	}

	create_desktop_shortcut = Button_GetCheck(desktop_shortcut_checkbox);
	create_startmenu_shortcut = Button_GetCheck(startmenu_shortcut_checkbox);
	use_with_tox_url = Button_GetCheck(tox_url_checkbox);

	fprintf(LOG_FILE, "will install with options: %u %u %u %s\n", create_desktop_shortcut, create_startmenu_shortcut, use_with_tox_url, install_path);

	if (MessageBox(main_window, "Confirm installing Tox on your computer ?", "", MB_YESNOCANCEL) != IDYES)
		return;

	if (install_tox(create_desktop_shortcut, create_startmenu_shortcut, use_with_tox_url, install_path, install_path_len)){
		set_current_status("Installiation completed");

		MessageBox(main_window, "Installed Success", "uTox Install", MB_OK);
		open_utox_and_exit();
	}
	else{
		set_current_status("Error during installiation");

		MessageBox(main_window, "Installiation Failed, Please send the log file to the developers", "uTox Install", MB_OK);
		exit(0);
	}
}

void create_installer_ui(){
	RECT r;
	GetClientRect(main_window, &r);
	
	WPARAM font = (WPARAM)GetStockObject(DEFAULT_GUI_FONT);

	install_button = CreateWindowEx(0, "BUTTON", "Install", WS_TABSTOP | WS_VISIBLE | WS_CHILD, 100, 150, 80, 20, main_window, NULL, MY_HINSTANCE, NULL);
	SendMessage(install_button, WM_SETFONT, font, 0);

	desktop_shortcut_checkbox = CreateWindowEx(0, "Button", "Create Start Menu shortcut", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 15, 10, r.right - 20, 25, main_window, NULL, MY_HINSTANCE, NULL);
	SendMessage(desktop_shortcut_checkbox, WM_SETFONT, font, 0);
	SendMessage(desktop_shortcut_checkbox, BM_SETCHECK, BST_CHECKED, 0);

	startmenu_shortcut_checkbox = CreateWindowEx(0, "Button", "Create Desktop shortcut", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 15, 35, r.right - 20, 25, main_window, NULL, MY_HINSTANCE, NULL);
	SendMessage(startmenu_shortcut_checkbox, WM_SETFONT, font, 1);
	SendMessage(startmenu_shortcut_checkbox, BM_SETCHECK, BST_CHECKED, 0);

	tox_url_checkbox = CreateWindowEx(0, "Button", "Open tox:// URLs with uTox", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 15, 60, r.right - 20, 25, main_window, NULL, MY_HINSTANCE, NULL);
	SendMessage(tox_url_checkbox, WM_SETFONT, font, 1);
	SendMessage(tox_url_checkbox, BM_SETCHECK, BST_CHECKED, 0);

	browse_textbox = CreateWindowEx(WS_EX_CLIENTEDGE, "Edit", "", WS_TABSTOP | WS_VISIBLE | WS_CHILD, 15, 200, r.right - 100, 25, main_window, NULL, MY_HINSTANCE, NULL);
	SendMessage(browse_textbox, WM_SETFONT, font, 1);
	SendMessage(browse_textbox, BM_SETCHECK, BST_CHECKED, 0);

	browse_button = CreateWindowEx(0, "Button", "Browse", WS_TABSTOP | WS_VISIBLE | WS_CHILD, r.right - 80, 200, 80, 25, main_window, NULL, MY_HINSTANCE, NULL);
	SendMessage(browse_button, WM_SETFONT, font, 1);
	SendMessage(browse_button, BM_SETCHECK, BST_CHECKED, 0);
}

void browse_for_install_folder(){
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
					SetWindowTextW(browse_textbox, pszFilePath);
					CoTaskMemFree(pszFilePath);
				}
				pItem->lpVtbl->Release(pItem);
			}
		}
		pFileOpen->lpVtbl->Release(pFileOpen);

		CoUninitialize();
	}
	else{
		wchar_t path[MAX_PATH];
		BROWSEINFOW bi = {
			.pszDisplayName = path,
			.lpszTitle = L"Install Location",
			.ulFlags = BIF_USENEWUI | BIF_NONEWFOLDERBUTTON,
		};
		LPITEMIDLIST lpItem = SHBrowseForFolderW(&bi);
		if (!lpItem) {
			open_utox_and_exit();
		}

		SHGetPathFromIDListW(lpItem, path);
		SetWindowTextW(browse_textbox, path);
	}
}
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{

	switch (message)
	{
	case WM_CLOSE:
		PostQuitMessage(0);
		break;

	case WM_COMMAND:{
		if (HIWORD(wParam) == BN_CLICKED){
			int id = LOWORD(wParam);
			HWND control_hwnd = (HWND) lParam;

			if (control_hwnd == cancel_button){
				if (MessageBox(main_window, "Are you sure you want to exit", "uTox", MB_YESNOCANCEL) == IDYES){
					if (is_tox_installed){
						open_utox_and_exit();
					}
					else{
						exit(0);
					}
				}
			}
			else if (control_hwnd == install_button){
				_beginthread(start_installiation, 0, 0);
			}
			else if (control_hwnd == browse_button){
				browse_for_install_folder();
			}
		}
		break;
	}
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;

}

void check_updates(){
	set_current_status("fetching new version data..");

	int new_version = check_new_version();

	if (new_version == -1){
		MessageBox(main_window, "Error fetching latest version data, Please check your internet connection. \n\n Exiting now...", "Error", MB_OK);
		exit(0);
	}

	set_current_status("version data fetched successfully.");

	if (is_tox_installed){

		set_download_progress(0);
		set_current_status("Found new version");

		if (new_version && MessageBox(NULL, "A new version of uTox is available.\nUpdate?", "uTox Updater", MB_YESNO | MB_ICONQUESTION) == IDYES) {
			download_and_install_new_utox_version();
		}

		open_utox_and_exit();
	}
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR cmd, int nCmdShow)
{
	LOG_FILE = fopen("tox_log.txt", "w");

	MY_CMD_ARGS = cmd;
	MY_HINSTANCE = hInstance;

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

	TOX_UPDATER_PATH_LEN = GetModuleFileName(NULL, TOX_UPDATER_PATH, MAX_PATH);

	init_tox_file_name();

    /* initialize winsock */
    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        fprintf(LOG_FILE, "WSAStartup failed\n");
        return 1;
    }

    /* check if we are on a 64-bit system*/
    _Bool iswow64 = 0;
    _Bool (WINAPI *fnIsWow64Process)(HANDLE, _Bool*)  = (void*)GetProcAddress(GetModuleHandleA("kernel32"),"IsWow64Process");
    if(fnIsWow64Process) {
        fnIsWow64Process(GetCurrentProcess(), &iswow64);
    }

    if(iswow64) {
        /* replace the arch in the REQUEST/TOX_FILE_NAME strings (todo: not use constants for offsets) */
        REQUEST[8] = '6';
        REQUEST[9] = '4';
        TOX_FILE_NAME[3] = '6';
        TOX_FILE_NAME[4] = '4';
        fprintf(LOG_FILE, "detected 64bit system\n");
    }

    /* init common controls */
    INITCOMMONCONTROLSEX InitCtrlEx;

    InitCtrlEx.dwSize = sizeof(INITCOMMONCONTROLSEX);
	InitCtrlEx.dwICC = ICC_PROGRESS_CLASS;
	InitCommonControlsEx(&InitCtrlEx);

	WNDCLASS wc = { 0 };
	wc.lpfnWndProc = WndProc;
	wc.hInstance = MY_HINSTANCE;
	wc.hbrBackground = (HBRUSH)(COLOR_WINDOW);
	wc.lpszClassName = "ToxWindow";
	if (!RegisterClass(&wc))
		return 1;

	int width = 600;
	int height = 300;
	int x = (GetSystemMetrics(SM_CXSCREEN) - width) / 2;
	int y = (GetSystemMetrics(SM_CYSCREEN) - height) / 2;

	main_window = CreateWindowEx(WS_EX_APPWINDOW, "ToxWindow", "uTox Updater", WS_OVERLAPPEDWINDOW,
		x, y, width, height, 0, 0, MY_HINSTANCE, NULL);

	RECT r;
	GetClientRect(main_window, &r);

	progressbar = CreateWindowEx(0, PROGRESS_CLASS, NULL, WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 10, 100, r.right - 20, 30, main_window, NULL, hInstance, NULL);

	WPARAM font = (WPARAM)GetStockObject(DEFAULT_GUI_FONT);
	
	status_label = CreateWindowEx(0, "Static", "", WS_TABSTOP | WS_VISIBLE | WS_CHILD, 200, 135, 200, 20, main_window, NULL, hInstance, NULL);
	SendMessage(status_label, WM_SETFONT, font, 1);
	SendMessage(status_label, BM_SETCHECK, BST_CHECKED, 0);

	cancel_button = CreateWindowEx(0, "BUTTON", "Cancel", WS_TABSTOP | WS_VISIBLE | WS_CHILD, 0, 150, 80, 20, main_window, NULL, hInstance, NULL);
	SendMessage(cancel_button, WM_SETFONT, font, 0);

	if (!is_tox_installed){
		create_installer_ui();
	}
	
	ShowWindow(main_window, SW_SHOW);

	_beginthread(check_updates, 0, NULL);

	MSG msg;

	while (GetMessage(&msg, NULL, 0, 0) > 0){
		DispatchMessage(&msg);
	}

	open_utox_and_exit();

    return 0;
}
