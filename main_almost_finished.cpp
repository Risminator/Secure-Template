#include <iostream>
#include <cstdio>
#include <aclapi.h>
#include <Sddl.h>
#include <string>
#include <fstream>
#include <sys/stat.h>
#include <vector>
#include <iterator>
#include <winbase.h>
#include <fileapi.h>
#include <tchar.h>
#include <winsvc.h>

using namespace std;

ACCESS_MODE AccessMode;

#define BUFSIZE MAX_PATH
#define SERVICE_NAME  _T("Protect Daemon")
#define SERVICE_FILENAME "ProtectDaemon.exe"

#define PROTECT_FILENAME "template.txt"

PSID create_sid();                  // создает world SID
DWORD protect_file(LPTSTR);        // защищает наш файл

int create_template(TCHAR *);
void protect_template_file(TCHAR *);
void unprotect_template_file(TCHAR *);

void find_mask_protect(char *, char *);     // обход файлов в папке
void search_dirs_protect(char *, char *);   // рекурсивный обход по папкам

inline bool exists_test (const string&);
void replace(ostream& _o, istream& _i, const string &o, const string &n);

int protect_files(TCHAR *);
int unprotect_files(TCHAR *);
int delete_files(TCHAR *);

int check_pswd(string, TCHAR *);
int change_pswd(TCHAR *path_to_project_dir);

void remove_dir(const char* folder);

int service_install();
int service_remove();
int service_start(TCHAR*);
int service_stop();

// добавить delete_template с предупреждением, что защита со всех файлов будет снята

// DENY добавляет запрет для группы "Все"
// SET устанавливает разрешение для группы "Все"
// REVOKE стирает все разрешающие записи для данной группы

int main(int argc, char *argv[])
{
    TCHAR path_to_project_dir[BUFSIZE];
    int dwRet = GetCurrentDirectory(BUFSIZE, path_to_project_dir);

    int c;
    cout << "Welcome to protect system! Choose the option:\n"
            "1\t[create]\n"
            "2\t[protect]\n"
            "3\t[unprotect]\n"
            "4\t[change]\n"
            "5\t[exit]\n";
    cin >> c;

    switch (c) {
        case 1:
            create_template(path_to_project_dir);
            break;
        case 2:
            protect_files(path_to_project_dir);
            break;
        case 3:
            unprotect_files(path_to_project_dir);
            break;
        case 4:
            change_pswd(path_to_project_dir);
            break;
        case 5:
            break;
        default:
            cout << "Undefined option\n";
            break;
    }

    // unprotect_template_file(path_to_project_dir);
    return 0;
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
        goto Cleanup;
    }

    // вставить новый ACL в DACL.
    dwRes = SetNamedSecurityInfo(pszObjName, ObjectType,
                                 DACL_SECURITY_INFORMATION,
                                 NULL, NULL, pNewDACL, NULL);
    if (ERROR_SUCCESS != dwRes)  {
        printf( "SetNamedSecurityInfo Error %u\n", dwRes );
        goto Cleanup;
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

void find_mask_protect(char *Dir, char *Mask) {
    char buf[1000]={0};
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
                protect_file(TEXT(buf));
            }
        }
        while (FindNextFile(hf,&FindFileData)!=0);
        FindClose(hf);
    }
}
void search_dirs_protect(char *Dir, char *Mask) {
    find_mask_protect(Dir, Mask);
    char buf[1000]={0};
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
                // если это не додительский и не текущий каталог и это является папкой, выполняем в ней поиск
                if(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    search_dirs_protect(buf, Mask);
                }
            }
        }
        while (FindNextFile(hf,&FindFileData)!=0);
        FindClose(hf);
    }
}

inline bool exists_test(const string& name) {
    struct stat buffer;
    return (stat(name.c_str(), &buffer) == 0);
}
void replace(ostream& _o, istream& _i, const string& o, const string& n){
    string::size_type p = 0;
    string s;
    while(getline(_i, s) && !_i.fail()){
        p = 0;
        while((p = s.find(o, p)) != string::npos){
            s.replace(s.begin() + p, s.begin() + (p + o.length()), n);
            p += n.length();
        }
        _o << s << endl;
    }
    _o.flush();
}

int check_pswd(string pswd, TCHAR *path_to_project_dir) {
    TCHAR path_to_protect_file[BUFSIZE];
    sprintf(path_to_protect_file, "%s\\%s", path_to_project_dir, PROTECT_FILENAME);

    unprotect_template_file(path_to_project_dir);

    string inp;
    ifstream file;
    file.open(path_to_protect_file);
    getline(file, inp);

    file.close();
    protect_template_file(path_to_project_dir);
    return strcmp(const_cast<char*>(inp.c_str()), const_cast<char*>(pswd.c_str()));
}
int create_template(TCHAR *path_to_project_dir) {
    TCHAR path_to_protect_file[BUFSIZE];
    sprintf(path_to_protect_file, "%s\\%s", path_to_project_dir, PROTECT_FILENAME);
    if (!exists_test(path_to_protect_file))
    {
        cout << "Let's create file template.txt!\n";
        string inp;
        ofstream template_file;
        template_file.open(path_to_protect_file);

        // ошибка создания файла template.txt
        if (!(template_file.is_open())) {
            cout << "ERROR\n";
            return -1;
        }

        cout << "Enter the password\n";
        cin >> inp;
        template_file << inp << "\n";

        cout << "Enter file name/mask or E for Exit\n";
        cin >> inp;
        while(strcmp(const_cast<char*>(inp.c_str()), "E") != 0) {
            template_file << inp << "\n";
            cin >> inp;
        }

        protect_template_file(path_to_project_dir);
        // обработка ошибки, есть файл не защитился (думаю, надо проверить его на открытие)

        cout << "File template.txt created and protected.\n";
        template_file.close();
    }
    else
        cout << "File template.txt exists\n";
    return 0;
}
int protect_files(TCHAR *path_to_project_dir) {
    TCHAR path_to_protect_file[BUFSIZE];
    sprintf(path_to_protect_file, "%s\\%s", path_to_project_dir, PROTECT_FILENAME);
    if (!exists_test(path_to_protect_file)) {
        cout << "File template.txt doesn't exist. Create it.\n";
        return 0;
    }
    else {
        string pswd;
        cout << "Enter the password\n";
        cin >> pswd;
        if (check_pswd(pswd, path_to_project_dir)) {
            cout << "Wrong password\n";
            return 0;
        }
        else {
            unprotect_template_file(path_to_project_dir);
            // ошибка, что не удалось снять защиту с файла template
            string inp;
            ifstream file;
            file.open(path_to_protect_file);
            // ошибка открытия файла
            int i = 0;
            while(getline(file, inp)){
                char* inp_chr;
                if (i++ != 0) {
                    inp_chr = const_cast<char*>(inp.c_str());
                    cout << inp_chr << endl;
                    AccessMode = DENY_ACCESS;
                    search_dirs_protect(".\\test", inp_chr);
                    cout << endl;
                }
            }
            file.close();
            protect_template_file(path_to_project_dir);
            // ошибка защиты файла template
            service_install();
            service_start(path_to_project_dir);
        }
    }
    return 0;
}
int unprotect_files(TCHAR *path_to_project_dir) {
    TCHAR path_to_protect_file[BUFSIZE];
    sprintf(path_to_protect_file, "%s\\%s", path_to_project_dir, PROTECT_FILENAME);
    if (!exists_test(path_to_protect_file)) {
        cout << "File template.txt doesn't exist. Create it.\n";
        return 0;
    }
    else {
        string pswd;
        cout << "Enter the password\n";
        cin >> pswd;
        if (check_pswd(pswd, path_to_project_dir)) {
            cout << "Wrong password\n";
            return 0;
        }
        else {
            unprotect_template_file(path_to_project_dir);
            // проверка снятия защиты
            string inp;
            ifstream file;
            file.open(path_to_protect_file);
            // проверка открытия
            int i = 0;
            while(getline(file, inp)){
                char* inp_chr;
                if (i++ != 0) {
                    inp_chr = const_cast<char*>(inp.c_str());
                    AccessMode = SET_ACCESS;
                    search_dirs_protect(".\\test", inp_chr);
                    AccessMode = REVOKE_ACCESS;
                    search_dirs_protect(".\\test", inp_chr);
                    cout << endl;
                }
            }
            file.close();
            protect_template_file(path_to_project_dir);
            // проверка установки защиты
            service_stop();
            service_remove();
        }
    }
    return 0;
}
int change_pswd(TCHAR *path_to_project_dir) {
    TCHAR path_to_protect_file[BUFSIZE];
    sprintf(path_to_protect_file, "%s\\%s", path_to_project_dir, PROTECT_FILENAME);
    if (!exists_test(path_to_protect_file)) {
        cout << "File template.txt doesn't exist. Create it.\n";
        return 0;
    }
    else {
        string pswd;
        cout << "Enter the password\n";
        cin >> pswd;
        unprotect_template_file(path_to_project_dir);
        if (check_pswd(pswd, path_to_project_dir)) {
            cout << "Wrong password\n";
            return 0;
        }
        else {
            unprotect_template_file(path_to_project_dir);
            // проверка снятия защиты
            string old_pswd;
            ifstream file;
            file.open(path_to_protect_file);
            // проверка открытия
            getline(file, old_pswd);
            // проверка получения пароля
            file.close();

            string new_pswd;
            cout << "Enter new password\n";
            cin >> new_pswd;

            ifstream fin(path_to_protect_file);
            ofstream fout(".\\tmp.txt");
            replace(fout, fin, old_pswd, new_pswd);
            fout.close();
            fin.close();
            string path = path_to_protect_file;
            remove(path.c_str());
            rename(".\\tmp.txt", path_to_protect_file);

            protect_template_file(path_to_project_dir);
            // проверка установки защиты
        }
    }
    return 0;
}

void find_mask_delete(char *Dir, char *Mask) {
    char buf[1000]={0};
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
                if (!remove(TEXT(buf))) {
                    printf("File %s deleted\n", buf);
                }
                else {
                    if(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        remove_dir(buf);
                    }
                }
            }
        }
        while (FindNextFile(hf,&FindFileData)!=0);
        FindClose(hf);
    }
}
void search_dirs_delete(char *Dir, char *Mask) {
    find_mask_delete(Dir, Mask);
    char buf[1000]={0};
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
int delete_files(TCHAR *path_to_project_dir) {
    TCHAR path_to_protect_file[BUFSIZE];
    sprintf(path_to_protect_file, "%s\\%s", path_to_project_dir, PROTECT_FILENAME);
    if (!exists_test(path_to_protect_file)) {
        cout << "File template.txt doesn't exist. Create it.\n";
        return 0;
    }
    else {
        string pswd;
        cout << "Enter the password\n";
        cin >> pswd;
        if (check_pswd(pswd, path_to_project_dir)) {
            cout << "Wrong password\n";
            return 0;
        }
        else {
            unprotect_template_file(path_to_project_dir);
            // ошибка, что не удалось снять защиту с файла template
            string inp;
            ifstream file;
            file.open(path_to_protect_file);
            // ошибка открытия файла
            int i = 0;
            while(getline(file, inp)){
                char* inp_chr;
                if (i++ != 0) {
                    inp_chr = const_cast<char*>(inp.c_str());
                    cout << inp_chr << endl;
                    search_dirs_delete(".\\test", inp_chr);
                    cout << endl;
                }
            }
            file.close();
            protect_template_file(path_to_project_dir);
            // ошибка защиты файла template
        }
    }
}
void remove_dir(const char* folder)
{
    char search_path[BUFSIZE];
    sprintf(search_path, "%s%s", folder, "/*.*");
    char s_p[BUFSIZE];
    sprintf(s_p, "%s%s", folder, "/");

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
        rmdir(folder);
    }
}

int service_install() {
    const char* custom_log_name = "InstallServiceLog";
    HANDLE event_log = RegisterEventSource(NULL, (LPCSTR)custom_log_name);

    TCHAR servicePath[BUFSIZE];
    int dwRet = GetCurrentDirectory(BUFSIZE, servicePath);
    sprintf(servicePath, "%s\\%s", servicePath, const_cast<char*>(SERVICE_FILENAME));

    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if(!hSCManager) {
        ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)("Error: Can't open Service Control Manager"), NULL);
        return -1;
    }

    SC_HANDLE hService = CreateService(
            hSCManager,
            SERVICE_NAME,
            SERVICE_NAME,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            servicePath,
            NULL, NULL, NULL, NULL, NULL
    );

    if(!hService) {
        int err = GetLastError();
        switch(err) {
            case ERROR_ACCESS_DENIED:
                ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)("Error: ERROR_ACCESS_DENIED"), NULL);
                break;
            case ERROR_CIRCULAR_DEPENDENCY:
                ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)("Error: ERROR_CIRCULAR_DEPENDENCY"), NULL);
                break;
            case ERROR_DUPLICATE_SERVICE_NAME:
                ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)("Error: ERROR_DUPLICATE_SERVICE_NAME"), NULL);
                break;
            case ERROR_INVALID_HANDLE:
                ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)("Error: ERROR_INVALID_HANDLE"), NULL);
                break;
            case ERROR_INVALID_NAME:
                ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)("Error: ERROR_INVALID_NAME"), NULL);
                break;
            case ERROR_INVALID_PARAMETER:
                ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)("Error: ERROR_INVALID_PARAMETER"), NULL);
                break;
            case ERROR_INVALID_SERVICE_ACCOUNT:
                ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)("Error: ERROR_INVALID_SERVICE_ACCOUNT"), NULL);
                break;
            case ERROR_SERVICE_EXISTS:
                ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)("Error: ERROR_SERVICE_EXISTS"), NULL);
                break;
            default:
                ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)("Error: Undefined"), NULL);
        }
        CloseServiceHandle(hSCManager);
        DeregisterEventSource(event_log);
        return -1;
    }
    CloseServiceHandle(hService);

    CloseServiceHandle(hSCManager);
    ReportEvent(event_log, EVENTLOG_SUCCESS, 0, 0, NULL, 1, 0, (LPCSTR*)("Success: Service installed!"), NULL);
    return 0;
}

int service_remove() {
    const char* custom_log_name = "RemoveServiceLog";
    HANDLE event_log = RegisterEventSource(NULL, (LPCSTR)custom_log_name);
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if(!hSCManager) {
        ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)("Error: Can't open Service Control Manager"), NULL);
        DeregisterEventSource(event_log);
        return -1;
    }
    SC_HANDLE hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_STOP | DELETE);
    if(!hService) {
        ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)("Error: Can't remove service"), NULL);
        CloseServiceHandle(hSCManager);
        DeregisterEventSource(event_log);
        return -1;
    }

    DeleteService(hService);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    ReportEvent(event_log, EVENTLOG_SUCCESS, 0, 0, NULL, 1, 0, (LPCSTR*)("Success: Service Removed!"), NULL);
    DeregisterEventSource(event_log);
    return 0;
}

int service_start(TCHAR* dirPath) {
    const char* custom_log_name = "StartServiceLog";
    HANDLE event_log = RegisterEventSource(NULL, (LPCSTR)custom_log_name);
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_START);
    if(!StartService(hService, 1, (LPCSTR*)&dirPath)) {
        CloseServiceHandle(hSCManager);
        ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)("Error: Can't start service"), NULL);
        DeregisterEventSource(event_log);
        return -1;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    ReportEvent(event_log, EVENTLOG_SUCCESS, 0, 0, NULL, 1, 0, (LPCSTR*)("Success: Service Started!"), NULL);
    DeregisterEventSource(event_log);
    return 0;
}

int service_stop() {
    const char* custom_log_name = "StopServiceLog";
    HANDLE event_log = RegisterEventSource(NULL, (LPCSTR)custom_log_name);
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;

    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (NULL == hSCManager)
    {
        printf("OpenSCManager failed (%d)\n", GetLastError());
        return -1;
    }

    SC_HANDLE hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (hService == NULL)
    {
        printf("OpenService failed (%d)\n", GetLastError());
        CloseServiceHandle(hSCManager);
        return -1;
    }

    // Make sure the service is not already stopped.

    if ( !QueryServiceStatusEx(
            hService,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&ssp,
            sizeof(SERVICE_STATUS_PROCESS),
            &dwBytesNeeded ) )
    {
        printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
        goto stop_cleanup;
    }

    if ( ssp.dwCurrentState == SERVICE_STOPPED )
    {
        printf("Service is already stopped.\n");
        goto stop_cleanup;
    }

    if ( !ControlService(
            hService,
            SERVICE_CONTROL_STOP,
            (LPSERVICE_STATUS) &ssp ) )
    {
        printf( "ControlService failed (%d)\n", GetLastError() );
        goto stop_cleanup;
    }

    stop_cleanup:
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
}