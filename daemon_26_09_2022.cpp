#include <iostream>
#include <windows.h>
#include <tchar.h>
#include <aclapi.h>
#include <Sddl.h>
#include <string>
#include <fstream>
#include <sys/stat.h>
#include <vector>
#include <iterator>
#include <winbase.h>
#include <fileapi.h>
#include <winsvc.h>

using namespace std;

SERVICE_STATUS        g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

ACCESS_MODE           AccessMode;

#define PROTECT_FILENAME "template.txt"
#define SERVICE_NAME  (LPSTR)(_T("Protect Daemon"))
#define BUFSIZE MAX_PATH

VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
VOID WINAPI ServiceCtrlHandler(DWORD);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

PSID create_sid();                  // создает world SID
DWORD protect_file(LPTSTR);        // защищает наш файл

void protect_template_file(TCHAR *);
void unprotect_template_file(TCHAR *);

void find_mask_delete(char *, char *);
void search_dirs_delete(char *, char *);
void remove_dir(const char* folder);

struct FileMapping {
    HANDLE hFile;
    HANDLE hMapping;
    size_t fsize;
    unsigned char* dataPtr;
};

FileMapping *fileMappingCreate(const char*);
void fileMappingClose(FileMapping*);

// main entry point
int _tmain(int argc, TCHAR* argv[])
{
    SERVICE_TABLE_ENTRY ServiceTable[] =
            {
                    {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
                    {NULL, NULL}
            };

    if (StartServiceCtrlDispatcher(ServiceTable) == FALSE)
    {
        return GetLastError();
    }

    return 0;
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv)
{
    DWORD Status = E_FAIL;

    // Register our service control handler with the SCM
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);

    if (g_StatusHandle == NULL)
    {
        return;
    }

    // Tell the service controller we are starting
    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
    {
        OutputDebugString(_T(
                                  "My Sample Service: ServiceMain: SetServiceStatus returned error"));
    }

    /*
     * Perform tasks necessary to start the service here
     */

    // Create a service stop event to wait on later
    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL)
    {
        // Error creating event
        // Tell service controller we are stopped and exit
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        g_ServiceStatus.dwCheckPoint = 1;

        if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
        {
            OutputDebugString(_T(
                                      "My Sample Service: ServiceMain: SetServiceStatus returned error"));
        }
        return;
    }

    // Tell the service controller we are started
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
    {
        OutputDebugString(_T(
                                  "My Sample Service: ServiceMain: SetServiceStatus returned error"));
    }

    // Start a thread that will perform the main task of the service
    HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, argv, 0, NULL);

    // Wait until our worker thread exits signaling that the service needs to stop
    WaitForSingleObject(hThread, INFINITE);


    /*
     * Perform any cleanup tasks
     */

    CloseHandle(g_ServiceStopEvent);

    // Tell the service controller we are stopped
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 3;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
    {
        OutputDebugString(_T(
                                  "My Sample Service: ServiceMain: SetServiceStatus returned error"));
    }

    EXIT:
    return;
}

VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode)
{
    switch (CtrlCode)
    {
        case SERVICE_CONTROL_STOP:

            if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
                break;

            /*
             * Perform tasks necessary to stop the service here
             */

            g_ServiceStatus.dwControlsAccepted = 0;
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            g_ServiceStatus.dwWin32ExitCode = 0;
            g_ServiceStatus.dwCheckPoint = 4;

            if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
            {
                OutputDebugString(_T(
                                          "My Sample Service: ServiceCtrlHandler: SetServiceStatus returned error"));
            }

            // This will signal the worker thread to start shutting down
            SetEvent(g_ServiceStopEvent);

            break;

        default:
            break;
    }
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam)
{
    const char* custom_log_name = "ServiceWorkerThread";
    HANDLE event_log = RegisterEventSource(NULL, (LPCSTR)custom_log_name);
    const char* message = "YOY TRIED TO CREATE FILE, BITCH!!1!!!11111!!!!";

    TCHAR *path_to_project_dir = ((TCHAR**)lpParam)[1];
    //GetCurrentDirectory(BUFSIZE, path_to_project_dir);

    ReportEvent(event_log, EVENTLOG_SUCCESS, 0, 0, NULL, 1, 0, (LPCSTR*)(&path_to_project_dir), NULL);


    DWORD dwWaitStatus;
    HANDLE dwChangeHandle = FindFirstChangeNotification(
            path_to_project_dir,                   // directory to watch
            TRUE,                         // do not watch subtree
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME); // watch file name changes

    if (dwChangeHandle == INVALID_HANDLE_VALUE)
    {
        //printf("\n ERROR: FindFirstChangeNotification function failed.\n");
        ExitProcess(GetLastError());
    }

    if (dwChangeHandle == NULL)
    {
        //printf("\n ERROR: Unexpected NULL from FindFirstChangeNotification.\n");
        ExitProcess(GetLastError());
    }

    const char *msgbuf = "Service Started";
    ReportEvent(event_log, EVENTLOG_SUCCESS, 0, 0, NULL, 1, 0, (LPCSTR*)(&msgbuf), NULL);

    //  Periodically check if the service has been requested to stop
    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0)
    {
        dwWaitStatus = WaitForSingleObject(dwChangeHandle, 0);
        if (dwWaitStatus == WAIT_OBJECT_0) {
            const char *msgbuf = "File was created!";
            ReportEvent(event_log, EVENTLOG_SUCCESS, 0, 0, NULL, 1, 0, (LPCSTR*)(&msgbuf), NULL);
            unprotect_template_file(path_to_project_dir);
            TCHAR path_to_protect_file[BUFSIZE];
            sprintf(path_to_protect_file, "%s\\%s", path_to_project_dir, PROTECT_FILENAME);
            // ошибка, что не удалось снять защиту с файла template
            string inp;
            ifstream file;
            file.open(path_to_protect_file);
            if (!file.is_open()) {
                const char *msgbuf1 = "Couldnt open template";
                ReportEvent(event_log, EVENTLOG_SUCCESS, 0, 0, NULL, 1, 0, (LPCSTR*)(&msgbuf1), NULL);
            }
            // ошибка открытия файла
            int i = 0;
            while(getline(file, inp)){
                char* inp_chr;
                if (i++ != 0) {
                    inp_chr = const_cast<char*>(inp.c_str());
                    cout << inp_chr << endl;
                    search_dirs_delete(path_to_project_dir, inp_chr);
                    cout << endl;
                }
            }
            file.close();
            protect_template_file(path_to_project_dir);

            if ( FindNextChangeNotification(dwChangeHandle) == FALSE )
            {
                //printf("\n ERROR: FindNextChangeNotification function failed.\n");
                ExitProcess(GetLastError());
            }
        }


        //  Simulate some work by sleeping

        // Sleep(10000);
    }

    return ERROR_SUCCESS;
}

void remove_dir(const char* folder)
{
    char search_path[BUFSIZE];
    sprintf(search_path, "%s\\%s", folder, "*");
    char s_p[BUFSIZE];
    sprintf(s_p, "%s\\", folder);

    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(search_path, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (strcmp(fd.cFileName, ".") != 0 && strcmp(fd.cFileName, "..") != 0)
                {
                    char s[BUFSIZE];
                    sprintf(s, "%s%s", s_p, fd.cFileName);
                    remove_dir(s);
                }
            }
            else {
                char s[BUFSIZE];
                sprintf(s, "%s%s", s_p, fd.cFileName);
                DeleteFile(s);
            }
        } while (FindNextFile(hFind, &fd));
        FindClose(hFind);
        RemoveDirectory((LPCSTR)folder);
    }
}

PSID create_sid() {
    PSID pEveryoneSID = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld =
            SECURITY_WORLD_SID_AUTHORITY;
    if(!AllocateAndInitializeSid(&SIDAuthWorld, 1,
                                 SECURITY_WORLD_RID,
                                 0, 0, 0, 0, 0, 0, 0,
                                 &pEveryoneSID))
    {
        cout << "Error create_sid";
    }
    return pEveryoneSID;
}

DWORD protect_file (LPTSTR pszObjName) {
    const char* custom_log_name = "protect_file";
    HANDLE event_log = RegisterEventSource(NULL, (LPCSTR)custom_log_name);

    SE_OBJECT_TYPE ObjectType = SE_FILE_OBJECT;                 // тип файла - объект
    LPTSTR pszTrustee = (LPTSTR) create_sid();                  // группа - все
    TRUSTEE_FORM TrusteeForm = TRUSTEE_IS_SID;                  // способ задания группы - по SID
    // для переименования нужен доступ на удаление, если его нет, то и переименовать файл будет нельзя
    // копирование невозможно запретить без запрета на открытие
    DWORD dwAccessRights = DELETE | GENERIC_READ;               // права
    DWORD dwInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;   // наследование

    DWORD dwRes = 0;
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea;

    if (NULL == pszObjName)
        return ERROR_INVALID_PARAMETER;

    // Получить указатель на существующий DACL.
    dwRes = GetNamedSecurityInfo(pszObjName, ObjectType,
                                 DACL_SECURITY_INFORMATION,
                                 NULL, NULL, &pOldDACL, NULL, &pSD);
    if (ERROR_SUCCESS != dwRes) {
        printf( "GetNamedSecurityInfo Error %u\n", dwRes );
        const char* msg = "GetNamedSecurityInfo Error";
        ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)(&msg), NULL);
        goto Cleanup;
    }

    // Инициализировать EXPLICIT_ACCESS структуру для новой ACE.
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = dwAccessRights;
    ea.grfAccessMode = AccessMode;
    ea.grfInheritance= dwInheritance;
    ea.Trustee.TrusteeForm = TrusteeForm;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPTSTR)pszTrustee;

    // слить новый и старый ACL
    dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
    if (ERROR_SUCCESS != dwRes)  {
        printf( "SetEntriesInAcl Error %u\n", dwRes );
        const char* msg = "SetEntriesInAcl Error";
        ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)(&msg), NULL);
        goto Cleanup;
    }

    // вставить новый ACL в DACL.
    dwRes = SetNamedSecurityInfo(pszObjName, ObjectType,
                                 DACL_SECURITY_INFORMATION,
                                 NULL, NULL, pNewDACL, NULL);
    if (ERROR_SUCCESS != dwRes)  {
        printf( "SetNamedSecurityInfo Error %u\n", dwRes );
        const char* msg = "SetNamedSecurityInfo Error";
        ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)(&msg), NULL);
        goto Cleanup;
    }
    else {
        const char* msg = "Unprotect/Protect Success!";
        ReportEvent(event_log, EVENTLOG_SUCCESS, 0, 0, NULL, 1, 0, (LPCSTR*)(&msg), NULL);
    }

    Cleanup:

    if(pSD != NULL)
        LocalFree((HLOCAL) pSD);
    if(pNewDACL != NULL)
        LocalFree((HLOCAL) pNewDACL);

    return dwRes;
}

void unprotect_template_file(TCHAR *path_to_project_dir) {
    TCHAR path_to_protect_file[BUFSIZE];
    sprintf(path_to_protect_file, "%s\\%s", path_to_project_dir, PROTECT_FILENAME);
    AccessMode = SET_ACCESS;
    protect_file(TEXT(path_to_protect_file));
    AccessMode = REVOKE_ACCESS;
    protect_file(TEXT(path_to_protect_file));
}
void protect_template_file(TCHAR *path_to_project_dir) {
    TCHAR path_to_protect_file[BUFSIZE];
    sprintf(path_to_protect_file, "%s\\%s", path_to_project_dir, PROTECT_FILENAME);
    AccessMode = DENY_ACCESS;
    protect_file(TEXT(path_to_protect_file));
}

void find_mask_delete(char *Dir, char *Mask) {
    const char* custom_log_name = "find_mask_delete";
    HANDLE event_log = RegisterEventSource(NULL, (LPCSTR)custom_log_name);
    ReportEvent(event_log, EVENTLOG_SUCCESS, 0, 0, NULL, 1, 0, (LPCSTR*)(&custom_log_name), NULL);

    char buf[BUFSIZE]={0};
    sprintf(buf, "%s\\%s", Dir, Mask);

    WIN32_FIND_DATA FindFileData;
    HANDLE hf;
    hf=FindFirstFile(buf, &FindFileData);

    if (hf!=INVALID_HANDLE_VALUE)
    {
        do
        {
            sprintf(buf, "%s\\%s", Dir, FindFileData.cFileName);
            if (strcmp(FindFileData.cFileName,"..")!=0 && strcmp(FindFileData.cFileName,".")!=0) {
                // если это не родительский и не текущий каталог, задаём права
                cout << buf << endl;
                const char *new_msg = "File found";
                ReportEvent(event_log, EVENTLOG_SUCCESS, 0, 0, NULL, 1, 0, (LPCSTR*)(&new_msg), NULL);
                if (!remove(TEXT(buf))) {
                    printf("File %s deleted\n", buf);
                    const char *msg = "File Deleted?";
                    ReportEvent(event_log, EVENTLOG_SUCCESS, 0, 0, NULL, 1, 0, (LPCSTR*)(&msg), NULL);
                }
                else {
                    if(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        remove_dir(buf);
                    }
                    const char *msg = "Directory Deleted? / Not deleted";
                    ReportEvent(event_log, EVENTLOG_SUCCESS, 0, 0, NULL, 1, 0, (LPCSTR*)(&msg), NULL);
                }
            }
        }
        while (FindNextFile(hf,&FindFileData)!=0);
        FindClose(hf);
    }
}

void search_dirs_delete(char *Dir, char *Mask) {
    find_mask_delete(Dir, Mask);
    char buf[BUFSIZE]={0};
    sprintf(buf, "%s\\%s", Dir, "*");

    WIN32_FIND_DATA FindFileData;
    HANDLE hf;
    hf=FindFirstFile(buf, &FindFileData);


    if (hf!=INVALID_HANDLE_VALUE)
    {
        do
        {
            sprintf(buf, "%s\\%s", Dir, FindFileData.cFileName);
            if (strcmp(FindFileData.cFileName,"..")!=0 && strcmp(FindFileData.cFileName,".")!=0) {
                // если это не родительский и не текущий каталог и это является папкой, выполняем в ней поиск
                if(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    search_dirs_delete(buf, Mask);
                }
            }
        }
        while (FindNextFile(hf,&FindFileData)!=0);
        FindClose(hf);
    }
}



FileMapping * fileMappingCreate(const char* fname) {
    HANDLE hFile = CreateFile(fname, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "fileMappingCreate - CreateFile failed, fname =  " << fname << std::endl;
        return nullptr;
    }

    DWORD dwFileSize = GetFileSize(hFile, nullptr);
    if(dwFileSize == INVALID_FILE_SIZE) {
        std::cerr << "fileMappingCreate - GetFileSize failed, fname =  " << fname << std::endl;
        CloseHandle(hFile);
        return nullptr;
    }

    HANDLE hMapping = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if(hMapping == nullptr) { // yes, NULL, not INVALID_HANDLE_VALUE, see MSDN
        std::cerr << "fileMappingCreate - CreateFileMapping failed, fname =  " << fname << std::endl;
        CloseHandle(hFile);
        return nullptr;
    }

    unsigned char* dataPtr = (unsigned char*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, dwFileSize);
    if(dataPtr == nullptr) {
        std::cerr << "fileMappingCreate - MapViewOfFile failed, fname =  " << fname << std::endl;
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return nullptr;
    }

    FileMapping* mapping = (FileMapping*)malloc(sizeof(FileMapping));
    if(mapping == nullptr) {
        std::cerr << "fileMappingCreate - malloc failed, fname = " << fname << std::endl;
        UnmapViewOfFile(dataPtr);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return nullptr;
    }

    mapping->hFile = hFile;
    mapping->hMapping = hMapping;
    mapping->dataPtr = dataPtr;
    mapping->fsize = (size_t)dwFileSize;

    return mapping;
}

void fileMappingClose(FileMapping* mapping) {
    UnmapViewOfFile(mapping->dataPtr);
    CloseHandle(mapping->hMapping);
    CloseHandle(mapping->hFile);
    free(mapping);
}