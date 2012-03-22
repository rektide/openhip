/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2004-2012 the Boeing Company
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 *  \file  hip_service.c
 *
 *  \authors Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  This contains the main program for the HIP Windows service,
 *          and its initialization code. Multiple threads are spawned that
 *          perform the actual work.
 */

#include <windows.h>
#include <winsvc.h>
#include <windowsx.h>
#include <shellapi.h>
#include <stdio.h>      /* stderr, stdout */
#include <winsock2.h>
#include <iphlpapi.h>
#include <iprtrmib.h>
#include <win32/types.h>
#include <winioctl.h>   /* CTL_CODE */
#include <process.h>    /* _beginthread() */
#include <direct.h>     /* _chdir() */
#include <openssl/applink.c> /* allow debugging against DLL */
#include <openssl/rand.h>       /* RAND_seed() */

#include <hip/hip_service.h>
#include <hip/hip_version.h>
#include <hip/hip_types.h>
#include <hip/hip_funcs.h>
#include <hip/hip_sadb.h>

/*
 * Globals
 */
CHAR szKey[MAX_PATH];
extern HANDLE tapfd;
extern int s_esp, s_esp_udp, s_esp6;
extern int is_dns_thread_disabled();
int g_state;
__u32 get_preferred_lsi(struct sockaddr *addr); /* from hip_util.c */
int str_to_addr(__u8 *data, struct sockaddr *addr); /* from hip_util.c */
extern int init_esp_input(int family, int type, int proto, int port, char *msg);

/* from winsvc.h */
SERVICE_STATUS g_srv_status = {
  SERVICE_WIN32_OWN_PROCESS,            /* dwServiceType */
  SERVICE_START_PENDING,                /* dwCurrentState */
  SERVICE_ACCEPT_STOP,                  /* dwControlsAccepted */
  NO_ERROR,                             /* dwWin32ExitCode */
  NO_ERROR,                             /* dwServiceSpecificExitCode */
  0,                                    /* dwCheckPoint */
  0                                     /* dwWaitHint */
};
SERVICE_STATUS_HANDLE g_srv_status_handle;

char SERVICE_NAME[255] = "HIP";
char DISPLAY_NAME[255] = "HIP";

#define ADAPTER_KEY \
  "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

#define NETWORK_CONNECTIONS_KEY \
  "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

#define REG_INTERFACES_KEY \
  "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"

#define TAP_IOCTL_SET_MEDIA_STATUS CTL_CODE (FILE_DEVICE_UNKNOWN, \
                                             6, \
                                             METHOD_BUFFERED, \
                                             FILE_ANY_ACCESS)

#define TAP_COMPONENT_ID "tap0801"

/*
 * Local function declarations
 */
int check_and_set_tun_address(char *devid, int do_msgbox);
int setup_tap();

/* callback used with RegisterServiceCtrlHandler() */
void WINAPI Handler (DWORD ctrl)
{
  switch (ctrl)
    {
    case SERVICE_CONTROL_STOP:
      g_srv_status.dwCurrentState = SERVICE_STOP_PENDING;
      g_srv_status.dwWin32ExitCode = 0;
      g_srv_status.dwCheckPoint = 0;
      g_srv_status.dwWaitHint = 0;
      g_state = 1;
      break;
    case SERVICE_CONTROL_INTERROGATE:
      break;
    default:
      break;
    }
  SetServiceStatus (g_srv_status_handle, &g_srv_status);
}

/* Utility function to convert path+filename to path */
void strip_filename(char *filename)
{
  int i, len;

  len = strlen(filename);

  /* strip off filename and get path */
  for (i = len - 1; i >= 0; i--)
    {
      if (filename[i] != '\\')
        {
          filename[i] = 0;
        }
      else
        {
          break;
        }
    }

  /* convert '\\' to '/' */
  i = 0;
  while (filename[i] != 0)
    {
      if (filename[i] == '\\')
        {
          filename[i] = '/';
        }
      i++;
    }
}

/*
 * init_reg()
 *
 * Open "HKLM\System\CurrentControlSet\Services\HIP"
 * look for "ImagePath" containing "hip.exe"
 *
 * szKey is then set to proper registry value
 */
void init_reg()
{
  CHAR svcPath[MAX_PATH];
  CHAR szImagePath[MAX_PATH];
  CHAR szBuf[MAX_PATH];
  HKEY hKey, hSubKey;
  DWORD retCode, rv, dwKeyType;
  DWORD dwBufLen = MAX_PATH;
  int i;

  retCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                         "System\\CurrentControlSet\\Services\\",
                         0, KEY_READ, &hKey);
  if (retCode != ERROR_SUCCESS)
    {
      return;
    }

  for (i = 0, retCode = ERROR_SUCCESS; retCode == ERROR_SUCCESS; i++)
    {
      retCode = RegEnumKey(hKey, i, svcPath, MAX_PATH);
      if (retCode != ERROR_SUCCESS)
        {
          continue;
        }
      lstrcpy(szKey, "System\\CurrentControlSet\\Services\\");
      lstrcat(szKey, svcPath);
      if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKey, 0,
                       KEY_QUERY_VALUE, &hSubKey) != ERROR_SUCCESS)
        {
          continue;
        }
      dwBufLen = MAX_PATH;
      rv = RegQueryValueEx(hSubKey, "ImagePath", NULL,
                           &dwKeyType, szImagePath, &dwBufLen);

      if ((rv == ERROR_SUCCESS) &&
          ((dwKeyType == REG_SZ) || (dwKeyType == REG_EXPAND_SZ)) &&
          dwBufLen)
        {
          lstrcpy(szBuf, szImagePath);
          CharLower(szBuf);
          if (strstr(szBuf, "\\hip.exe") != NULL)
            {
              /* XXX in the future, could set status here */
              /*RegSetValueEx(hSubKey, "ProxyStatus", 0,
               *               REG_DWORD, (BYTE *) &status,
               *               sizeof(status));*/
              break;
            }
        }
      RegCloseKey(hSubKey);
    }
  RegCloseKey(hKey);
  return;
}

/* update_status()
 *
 * Writes the status to the registry key "ProxyStatus"
 */
#ifdef __UNUSED__
void update_status(DWORD status)
{
  HKEY hKey;

  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKey, 0,
                   KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
    {
      RegSetValueEx(hKey, "ProxyStatus", 0,
                    REG_DWORD, (BYTE *) &status, sizeof(status));
      RegCloseKey(hKey);
    }
  return;
}

#endif

/*
 * hip_install_service()
 *
 * Install the Windows service.
 */
DWORD hip_install_service()
{
  char path[MAX_PATH];
  char ImagePath[MAX_PATH];
  char *cmd;
  SC_HANDLE scm = 0;
  SC_HANDLE srv = 0;
  int rc = 0;
  if (!GetModuleFileName(0, path, MAX_PATH))
    {
      return(GetLastError());
    }

  if ((cmd = strstr(path, "hip.exe")) == NULL)
    {
      printf("The command name is different from 'hip.exe'\n");
      return(-1);
    }

  sprintf(ImagePath, "\"%s\" -X", path);
  /* service control manager */
  scm = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
  if (!scm)
    {
      return(GetLastError());
    }

  /* install the service */
  srv = CreateService(scm, SERVICE_NAME, DISPLAY_NAME, SERVICE_ALL_ACCESS,
                      SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                      SERVICE_ERROR_NORMAL, ImagePath, 0, 0, 0, 0, 0);
  /* change last two items - account name, password
   * if you do add Cygwin to the user's PATH and not the system's PATH
   * (may return ERROR_INVALID_SERVICE_ACCOUNT) */
  if (!srv)
    {
      rc = GetLastError();
    }
  else
    {
      /* Add a description to the service */
      SERVICE_DESCRIPTION descr =
      {
        "Host Identity Protocol manages identity-based security associations."
      };
      ChangeServiceConfig2(srv, SERVICE_CONFIG_DESCRIPTION, &descr);
      CloseServiceHandle(srv);
    }
  CloseServiceHandle(scm);
  return(rc);
}

/*
 * hip_remove_service()
 *
 * Un-install the Windows service.
 */
DWORD hip_remove_service()
{
  SC_HANDLE scm = 0;
  SC_HANDLE srv = 0;
  int rc = 0;

  /* service control manager */
  scm = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
  if (!scm)
    {
      return(GetLastError());
    }

  /* remove the service */
  srv = OpenService(scm, SERVICE_NAME, DELETE);
  if (!srv)
    {
      rc = GetLastError();
    }
  else
    {
      if (!DeleteService(srv))
        {
          rc = GetLastError();
        }
      CloseServiceHandle(srv);
    }
  CloseServiceHandle(scm);
  return(rc);
}

/*
 * hip_start_service()
 *
 * Starts the Windows service
 */
DWORD hip_start_service()
{
  SC_HANDLE scm = 0;
  SC_HANDLE srv = 0;
  SERVICE_STATUS st;
  int rc = 0;

  memset(&st, 0, sizeof (st));
  if (!(scm = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS)))
    {
      return(GetLastError());
    }

  if (!(srv = OpenService(scm, SERVICE_NAME,
                          SERVICE_START | SERVICE_QUERY_STATUS)))
    {
      return(GetLastError());
    }

  if (!StartService(srv, 0, 0))
    {
      return(GetLastError());
    }

  if (!QueryServiceStatus(srv, &st))
    {
      return(GetLastError());
    }

  {
    DWORD old;
    while (st.dwCurrentState == SERVICE_START_PENDING)
      {
        old = st.dwCheckPoint;
        Sleep (st.dwWaitHint);
        if (!QueryServiceStatus (srv, &st))
          {
            rc = GetLastError ();
            break;
          }
      }
    if (rc)
      {
        ;
      }
    else if (st.dwCurrentState == SERVICE_RUNNING)
      {
        printf ("HIP service has been successfully started\n");
      }
    else
      {
        printf ("HIP service status is %d\n",
                (int)st.dwCurrentState);
      }
  }

  if (srv)
    {
      CloseServiceHandle (srv);
    }
  if (scm)
    {
      CloseServiceHandle (scm);
    }
  return(rc);
}

/*
 * hip_stop_service()
 *
 * Stops the windows service
 */
DWORD hip_stop_service()
{
  SC_HANDLE scm = 0;
  SC_HANDLE srv = 0;
  SERVICE_STATUS st;
  int rc = 0;

  memset(&st, 0, sizeof (st));
  if (!(scm = OpenSCManager (0, 0, SC_MANAGER_ALL_ACCESS)))
    {
      rc = GetLastError ();
    }
  else if (!(srv = OpenService (scm, SERVICE_NAME, SERVICE_STOP)))
    {
      rc = GetLastError ();
    }
  else if (!ControlService (srv, SERVICE_CONTROL_STOP, &st))
    {
      rc = GetLastError ();
    }
  else
    {
      printf ("HIP service has been stopped\n");
    }
  if (srv)
    {
      CloseServiceHandle (srv);
    }
  if (scm)
    {
      CloseServiceHandle (scm);
    }
  return(rc);
}

/* this is from TAP-Win32 driver/macinfo.c */
unsigned char HexStringToDecimalInt (unsigned char p_Character)
{
  unsigned char l_Value = 0;

  if ((p_Character >= 'A') && (p_Character <= 'F'))
    {
      l_Value = (p_Character - 'A') + 10;
    }
  else if ((p_Character >= 'a') && (p_Character <= 'f'))
    {
      l_Value = (p_Character - 'a') + 10;
    }
  else if ((p_Character >= '0') && (p_Character <= '9'))
    {
      l_Value = p_Character - '0';
    }

  return(l_Value);
}

/* Convert first 8 bytes of adapter's GID to a MAC address,
 * of the form: 00:FF:{gid}, in network byte order, ready
 * for use in an Ethernet header */
__u64 gid_to_mac(char *data)
{
  int i;
  unsigned char val;
  __u64 mac = 0;

  for (i = 0; i < 8; i += 2)
    {
      val = HexStringToDecimalInt(data[i + 1]);
      val |= (HexStringToDecimalInt(data[i]) << 4);
      mac |=  val << (24 - (4 * i));
    }

  mac &= 0x00FFFFFFFFFF;
  mac |= 0x00FF00000000;
  return(hton64(mac) >> 16);
}

/*
 * print_hip_service_usage()
 *
 * Print parameters to the hip_service executable
 */
void print_hip_service_usage()
{
  printf("%s v%s HIP Windows service\n", HIP_NAME, HIP_VERSION);
  printf("Usage: hip [option]\n");
  printf("Where option is one of the following:\n");
  printf("  -i\t\tInstall as service.\n");
  printf("  -r\t\tRemove (uninstall) service.\n");
  printf("  -setuptap\tSetup TAP-32 adapter only.\n");
  printf("  -s\t\tStart service.\n");
  printf("  -e\t\tEnd (stop) service.\n");
  printf("  -X\t\tRun as a service.\n");
  printf("  ...\tRemaining arguments are passed to hipd\n");
  printf("With no parameters, will run as a command line program ");
  printf("instead of as a service.\n");
  printf("\n");
}

HANDLE init_tap()
{
  HANDLE hTAP32 = INVALID_HANDLE_VALUE;
  HKEY key;
  int enum_index, retry_attempts;
  char devid[1024], devname[1024];
  long len;
  ULONG status = TRUE;
  HKEY interface_key;
  char path[1024];
  struct sockaddr_in dns;
  char *addr_string;
  MIB_IPFORWARDROW route;
  DWORD dw;
  /* LPVOID lpMsgBuf; */ /* debug */

  printf("init_tap()\n");

  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEY, 0,
                   KEY_READ, &key))
    {
      printf("Unable to read registry:\n");
      return(NULL);
    }

  /* find the adapter with .tap suffix */
  for (enum_index = 0;; enum_index++)
    {
      len = sizeof(devid);
      if (RegEnumKeyEx(key, enum_index, devid, &len,
                       0, 0, 0, NULL) != ERROR_SUCCESS)
        {
          RegCloseKey(key);
          /* we've hit the end of the network connections list */
          printf("init_tap(): Couldn't find TAP-Win32 adapter.\n");
          return(NULL);
        }

      retry_attempts = 0;
init_tap_create_file_retry:
      sprintf(devname, "\\\\.\\Global\\%s.tap", devid);
      hTAP32 = CreateFile(devname,
                          GENERIC_WRITE | GENERIC_READ,
                          0,
                          0,
                          OPEN_EXISTING,
                          FILE_ATTRIBUTE_SYSTEM,
                          0);

      dw = GetLastError();
      /* This is the most common error. We are trying to open
       * this device as a TAP but it is not a TAP-Win32 device,
       * so continue with the search.
       */
      if (dw == ERROR_FILE_NOT_FOUND)
        {
          continue;
          /* This error "A device attached to the system is not
           * functioning." occurs when we've found the TAP but
           * cannot open it. This could be restarting the HIP
           * service, so try again.
           */
        }
      else if (dw == ERROR_GEN_FAILURE)
        {
          if (retry_attempts < 3)
            {
              /* pause 400ms for device to become ready */
              Sleep(400);
              retry_attempts++;
              printf("Retrying open on TAP device...\n");
              goto init_tap_create_file_retry;
            }
        }

      /* debug
       *  FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER|
       *               FORMAT_MESSAGE_FROM_SYSTEM, NULL, dw,
       *               MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
       *               (LPTSTR) &lpMsgBuf, 0, NULL);
       *
       *  printf("DEBUG: devname %s error %d: %s\n",
       *       devname, dw, lpMsgBuf);
       *  LocalFree(lpMsgBuf); */

      /* dw == NO_ERROR */
      if (hTAP32 != INVALID_HANDLE_VALUE)
        {
          RegCloseKey(key);
          CloseHandle(hTAP32);
          break;
        }
    }

  /* Get the MAC address of the TAP-Win32
   * which is of the form 00:FF:{GID}
   */
  g_tap_mac = gid_to_mac(devid + 1);

  if (check_and_set_tun_address(devid, 1) < 0)
    {
      printf("TAP-Win32 setup failed.\n");
      return(NULL);
    }

  /* Open TAP-Win32 device */
  hTAP32 = CreateFile(devname, GENERIC_WRITE | GENERIC_READ, 0, 0,
                      OPEN_EXISTING,
                      FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
  if (hTAP32 == INVALID_HANDLE_VALUE)
    {
      printf("Could not open Windows tap device\n");
      return(NULL);
    }

  /* set TAP-32 status to connected */
  if (!DeviceIoControl (hTAP32, TAP_IOCTL_SET_MEDIA_STATUS,
                        &status, sizeof (status),
                        &status, sizeof (status), &len, NULL))
    {
      printf("failed to set TAP-Win32 status as 'connected'.\n");
      return(NULL);
    }

  Sleep(10);

  /* set NameServer address on TAP-Win32 adapter to 1.x.x.x */
  sprintf (path, "%s\\%s", REG_INTERFACES_KEY, devid);
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0,
                   KEY_WRITE, &interface_key) != ERROR_SUCCESS)
    {
      printf("Error opening registry key: %s", path);
      return(NULL);
    }

  memset(&dns, 0, sizeof(struct sockaddr_in));
  dns.sin_family = AF_INET;
  if (is_dns_thread_disabled())
    {
      memset(SA2IP(&dns), 0, 4);
    }
  else
    {
      get_preferred_lsi(SA(&dns));
    }
  addr_string = inet_ntoa(dns.sin_addr);
  if (RegSetValueEx(interface_key, "NameServer", 0, REG_SZ,
                    addr_string, strlen(addr_string)) != ERROR_SUCCESS)
    {
      printf("Changing TAP-Win32 adapter's NameServer failed\n");
      return(NULL);
    }
  RegCloseKey(interface_key);

  /* also add route for 1.0.0.0/8 to TAP-Win32 */
  memset(&route, 0, sizeof(route));
  route.dwForwardDest = htonl(0x01000000L);
  route.dwForwardMask = htonl(0xFF000000L);
  CreateIpForwardEntry(&route);

  /* add 2001:10::/28 HIT to TAP-Win32 */
  /* TODO */
  /* IPv6 may not be installed */
  /* equivalent of netsh interface ipv6 add address 2001:007x:xxxx ... */
  /* */

  return(hTAP32);
}

/*
 * Check the static IP address for the TAP device and set it if necessary.
 */
int check_and_set_tun_address(char *devid, int do_msgbox)
{
  HKEY interface_key, key;
  DWORD dwVal, dwKeyType, dwBufLen;
  char path[1024], value[512], sLSI[17];
  int enum_index, need_setup = 0;
  long len;
  struct sockaddr_storage lsi;

  /*
   * Get the preferred LSI from hipd, from XML file
   */
  memset(&lsi, 0, sizeof(struct sockaddr_storage));
  lsi.ss_family = AF_INET;
  get_preferred_lsi(SA(&lsi));
  memset(sLSI, 0, sizeof(sLSI));       /* LSI + "\0\0" */
  sprintf(sLSI, "%u.%u.%u.%u", NIPQUAD(LSI4(&lsi)));
  if (LSI4(&lsi) == 0)
    {
      printf("Unable to determine preferred LSI.\n");
      return(-1);
    }
  else
    {
      printf("Using LSI of %s for TAP address.\n", sLSI);
    }

  /*
   * Check registry values for
   * IPAddress, SubnetMask, and EnableDHCP
   */
  sprintf (path, "%s\\%s", REG_INTERFACES_KEY, devid);
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &interface_key)
      != ERROR_SUCCESS)
    {
      printf("Error opening registry key: %s", path);
      return(-1);
    }
  dwBufLen = sizeof(value);
  if (RegQueryValueEx(interface_key, "IPAddress", NULL, &dwKeyType,
                      value, &dwBufLen) != ERROR_SUCCESS)
    {
      printf("Unable to read IP address, doing setup.\n");
      need_setup = 1;
    }
  if ((dwKeyType != REG_MULTI_SZ) ||
      (strncmp(value, sLSI, strlen(sLSI) + 2) != 0))
    {
      need_setup = 1;
    }
  dwBufLen = sizeof(value);
  if (RegQueryValueEx(interface_key, "SubnetMask", NULL, &dwKeyType,
                      value, &dwBufLen) != ERROR_SUCCESS)
    {
      printf("Unable to read network mask, doing setup.\n");
      need_setup = 1;
    }
  if ((dwKeyType != REG_MULTI_SZ) ||
      (strncmp(value, "255.0.0.0\0\0", 11) != 0))
    {
      need_setup = 1;
    }
  dwBufLen = sizeof(dwVal);
  if (RegQueryValueEx(interface_key, "EnableDHCP", NULL, &dwKeyType,
                      (LPBYTE)&dwVal, &dwBufLen) != ERROR_SUCCESS)
    {
      printf("Unable to read DHCP setting, doing setup.\n");
      need_setup = 1;
    }
  if ((dwKeyType != REG_DWORD) || (dwVal != 0x0))
    {
      need_setup = 1;
    }

  RegCloseKey(interface_key);
  if (!need_setup)
    {
      return(0);
    }

  /* Used to prompt user for setup, but now it is important that
   * the TAP address be set to the preferred LSI.
   */
  printf("Configuring the TAP-Win32 adapter.\n");
#if 0
  if (do_msgbox && (MessageBox(NULL,
                               "Your TAP-Win32 interface needs to be setup to run HIP for Windows, shall I do that for you?",
                               "HIP for Windows",
                               MB_YESNO | MB_ICONQUESTION) != IDYES))
    {
      return(-1);
    }
#endif

  /*
   * Write the new values to the registry
   */
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0,
                   KEY_WRITE, &interface_key) != ERROR_SUCCESS)
    {
      printf("Error opening registry key: %s", path);
      return(-1);
    }
  if (RegSetValueEx(interface_key, "IPAddress", 0, REG_MULTI_SZ,
                    sLSI, strlen(sLSI) + 2) != ERROR_SUCCESS)
    {
      printf("Changing TAP-Win32 adapter's IP address failed\n");
      return(-1);
    }
  if (RegSetValueEx(interface_key, "SubnetMask", 0, REG_MULTI_SZ,
                    "255.0.0.0\0\0",
                    strlen("255.0.0.0") + 2) != ERROR_SUCCESS)
    {
      printf("Changing TAP-Win32 adapter's IP mask failed\n");
      return(-1);
    }
  dwVal = 0x0;
  if (RegSetValueEx(interface_key, "EnableDHCP", 0, REG_DWORD,
                    (LPBYTE)&dwVal, sizeof(dwVal)) != ERROR_SUCCESS)
    {
      printf("Changing TAP-Win32 adapter's DHCP setting failed\n");
      return(-1);
    }
  RegCloseKey(interface_key);

  /*
   * Set TAP MTU to 1400
   */
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0,
                   KEY_READ, &key) != ERROR_SUCCESS)
    {
      printf("Error opening registry key: %s", ADAPTER_KEY);
      return(-1);
    }
  /* find the adapter with TAP_COMPONENT_ID (tap0801) */
  for (enum_index = 0;; enum_index++)
    {
      len = sizeof(value);
      if (RegEnumKeyEx(key, enum_index, value, &len,
                       0, 0, 0, NULL) != ERROR_SUCCESS)
        {
          RegCloseKey(key);
          return(0);               /* silently exit if not found */
        }
      sprintf(path, "%s\\%s", ADAPTER_KEY, value);
      if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_READ,
                       &interface_key) != ERROR_SUCCESS)
        {
          continue;
        }
      dwBufLen = sizeof(value);
      if (RegQueryValueEx(interface_key, "ComponentId", NULL,
                          &dwKeyType, value,
                          &dwBufLen) != ERROR_SUCCESS)
        {
          RegCloseKey(interface_key);
          continue;
        }
      RegCloseKey(interface_key);
      if ((dwKeyType != REG_SZ) ||
          (strncmp(value, TAP_COMPONENT_ID,
                   strlen(TAP_COMPONENT_ID)) != 0))
        {
          continue;
        }
      break;
    }

  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_WRITE,
                   &interface_key) != ERROR_SUCCESS)
    {
      printf("Unable to set TAP MTU.\n");
      return(0);           /* non-fatal */
    }
  if (RegSetValueEx(interface_key, "MTU", 0, REG_SZ,
                    "1400", strlen("1400")) != ERROR_SUCCESS)
    {
      printf("Changing TAP-Win32 MTU failed.\n");
    }
  RegCloseKey(interface_key);
  return(0);
}

/*
 * setup_tap()
 *
 * Standalone setup of the TAP-32 driver.
 */
int setup_tap()
{
  HANDLE hTAP32 = INVALID_HANDLE_VALUE;
  HKEY key;
  int enum_index;
  char devid[1024], devname[1024];
  long len;

  printf("setup_tap: ");

  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEY, 0,
                   KEY_READ, &key))
    {
      printf("Unable to read registry:\n");
      return(-1);
    }

  /* find the adapter with .tap suffix */
  for (enum_index = 0;; enum_index++)
    {
      len = sizeof(devid);
      if (RegEnumKeyEx(key, enum_index, devid, &len,
                       0, 0, 0, NULL) != ERROR_SUCCESS)
        {
          DWORD dw;
          LPVOID lpMsgBuf;
          dw = GetLastError();

          RegCloseKey(key);
          printf(
            "setup_tap(): Couldn't find TAP-Win32 adapter.\n");

          FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER |
                         FORMAT_MESSAGE_FROM_SYSTEM, NULL, dw,
                         MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                         (LPTSTR) &lpMsgBuf, 0, NULL);
          printf("Failed with error %d: %s\n", dw, lpMsgBuf);
          LocalFree(lpMsgBuf);;

          return(-1);
        }

      sprintf(devname, "\\\\.\\Global\\%s.tap", devid);
      hTAP32 = CreateFile(devname,
                          GENERIC_WRITE | GENERIC_READ,
                          0,
                          0,
                          OPEN_EXISTING,
                          FILE_ATTRIBUTE_SYSTEM,
                          0);

      if (hTAP32 != INVALID_HANDLE_VALUE)
        {
          RegCloseKey(key);
          CloseHandle(hTAP32);
          break;
        }
    }

  printf("found TAP-32\n");

  RegCloseKey(key);
  return(check_and_set_tun_address(devid, 0));
}

/*
 * init_hip()
 *
 * HIP Windows service initialization. Start all of the threads.
 */
void init_hip(DWORD ac, char **av)
{
  WORD wVer;
  WSADATA wsaData;
  __u32 tunreader_thrd, esp_output_thrd, esp_input_thrd;
  __u32 hipd_thrd, netlink_thrd, dns_thrd, status_thrd;
  int err;
  char hipd_args[255];
  int i;

  printf("%s v%s HIP Windows service\n", HIP_NAME, HIP_VERSION);
  printf("init_hip()\n");

  /* get arguments for hipd */
  memset(hipd_args, 0, sizeof(hipd_args));
  if (ac > 0)
    {
      ac--, av++;
    }
  i = 0;
  while (ac > 0)
    {
      if (i > 0)             /* add a space between parameters */
        {
          hipd_args[i++] = ' ';
        }
      sprintf(&hipd_args[i], "%s", *av);
      i += strlen(*av);
      av++, ac--;
    }

  /* Initialize Windows sockets */
  wVer = MAKEWORD( 2, 2);
  err = WSAStartup(wVer, &wsaData);
  if (err != 0)
    {
      printf("Error finding usable WinSock DLL.\n");
      exit(-1);
    }
  /* Initialize crypto library */
  init_crypto();
  hip_sadb_init();
  g_state = 0;

  /*
   * Kernel helpers
   */
  if (!(netlink_thrd = _beginthread(hip_netlink, 0, NULL)))
    {
      printf("Error creating netlink thread.\n");
      exit(-1);
    }
  if (!(status_thrd = _beginthread(hip_status, 0, NULL)))
    {
      printf("Error creating status thread.\n");
      exit(-1);
    }

  /*
   * HIP daemon
   */
  if (!(hipd_thrd = _beginthread(hipd_main, 0, (void*)&hipd_args)))
    {
      printf("Error creating HIP daemon thread.\n");
      exit(-1);
    }

  /*
   * tap device
   */
  if ((tapfd = init_tap()))
    {
      printf("Initialized TAP device.\n");
    }
  else
    {
      printf("Error initializing TAP device.\n");
      exit(-1);
    }

  if (!(tunreader_thrd = _beginthread(tunreader, 0, NULL)))
    {
      printf("Error creating tunreader thread.\n");
      exit(-1);
    }

  /*
   * ESP and DNS handlers
   */
  if (!(esp_output_thrd = _beginthread(hip_esp_output, 0, NULL)))
    {
      printf("Error creating ESP output thread.\n");
      exit(-1);
    }
  if ((s_esp = init_esp_input(AF_INET, SOCK_RAW, IPPROTO_ESP, 0,
                              "IPv4 ESP")) < 0)
    {
      printf("Error creating IPv4 ESP input socket.\n");
      exit(-1);
    }
  if ((s_esp_udp = init_esp_input(AF_INET, SOCK_RAW, IPPROTO_UDP,
                                  HIP_UDP_PORT, "IPv4 UDP")) < 0)
    {
      printf("Error creating IPv4 UDP input socket.\n");
      exit(-1);
    }

  if (!(esp_input_thrd = _beginthread(hip_esp_input, 0, NULL)))
    {
      printf("Error creating ESP input thread.\n");
      exit(-1);
    }
  if (!is_dns_thread_disabled())
    {
      if (!(dns_thrd = _beginthread(hip_dns, 0, NULL)))
        {
          printf("Error creating DNS thread.\n");
          exit(-1);
        }
    }
}

/******* MAIN ROUTINES *******/

/*
 * ServiceMain()
 *
 * Main routine for HIP service. Runs init_hip()
 */
void WINAPI ServiceMain (DWORD ac, char **av)
{
  char path[MAX_PATH];
  g_srv_status_handle = RegisterServiceCtrlHandler(SERVICE_NAME, Handler);
  if (!g_srv_status_handle)
    {
      return;
    }

  g_srv_status.dwCurrentState = SERVICE_START_PENDING;
  g_srv_status.dwCheckPoint = 0;
  g_srv_status.dwWaitHint = 1000;
  SetServiceStatus (g_srv_status_handle, &g_srv_status);

  /* initialization process */
  if (!GetModuleFileName (0, path, MAX_PATH))
    {
      return;
    }

  strip_filename(path);
  _chdir(path);

  if (freopen("hip_ipsec_error.log", "a", stderr) == NULL)
    {
      return;
    }
  if (freopen("hip_ipsec.log", "a", stdout) == NULL)
    {
      return;
    }
  init_reg();
  init_hip(ac, av);

  /* notify that the service has been started */
  g_srv_status.dwCurrentState = SERVICE_RUNNING;
  g_srv_status.dwCheckPoint = 0;
  g_srv_status.dwWaitHint = 0;
  SetServiceStatus(g_srv_status_handle, &g_srv_status);

  while (g_srv_status.dwCurrentState != SERVICE_STOPPED)
    {
      switch (g_srv_status.dwCurrentState)
        {
        case SERVICE_STOP_PENDING:
          g_srv_status.dwCurrentState = SERVICE_STOPPED;
          SetServiceStatus(g_srv_status_handle, &g_srv_status);
          g_state = 1;
          break;
        default:
          Sleep(1000);
          /* TODO: any HIP status updating here */
          /*ret = hip_check_status();
           *  if (ret >= 0 && ret != status) {
           *       status = ret;
           *       update_status(status);
           *  }*/
          break;
        }
    }

  WSACleanup();
  hip_sadb_deinit();
}

/*
 * main()
 *
 * Main command-line routine.
 */
int main (int argc, char **argv)
{
  int rc;
  char *error_buf;

  argv++, argc--;
  while (argc > 0)
    {
      rc = 0;
      if (strcmp(*argv, "-i") == 0)
        {
          rc = hip_install_service();
          if (rc == 0)
            {
              printf("HIP has been successfully installed ");
              printf("as a service.\n");
            }
        }
      else if (strcmp(*argv, "-r") == 0)
        {
          rc = hip_remove_service();
          if (rc == 0)
            {
              printf("HIP has been successfully ");
              printf("uninstalled.\n");
            }
        }
      else if (strcmp(*argv, "-setuptap") == 0)
        {
          rc = setup_tap();
        }
      else if (strcmp(*argv, "-s") == 0)
        {
          rc = hip_start_service();
        }
      else if (strcmp(*argv, "-e") == 0)
        {
          rc = hip_stop_service();
        }
      else if (strcmp(*argv, "-X") == 0)
        {
          DWORD dw;
          TCHAR szBuf[80];
          LPVOID lpMsgBuf;
          SERVICE_TABLE_ENTRY ent[] = {
            { SERVICE_NAME, ServiceMain }, { 0, 0 },
          };
          StartServiceCtrlDispatcher (ent);
          dw = GetLastError();
          FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER |
                         FORMAT_MESSAGE_FROM_SYSTEM, NULL, dw,
                         MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                         (LPTSTR) &lpMsgBuf, 0, NULL);
          wsprintf(szBuf, "Failed with error %d: %s",
                   dw, lpMsgBuf);
          /* Insert errors that we don't care about here. */
          if (dw != ERROR_IO_PENDING)
            {
              MessageBox(NULL, szBuf, "HIP Error", MB_OK);
            }
          LocalFree(lpMsgBuf);
          exit(0);
          /* Add new hipd option flags here: */
        }
      else if (strstr("-a-d-conf-e-g-i3-m-nr-o-p-q-r1-t-u-v",
                      *argv))
        {
          argv--, argc++;
          goto start_hip;
        }
      else
        {
          print_hip_service_usage();
          exit(0);
        }
      /* print error */
      if (rc)
        {
          FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL, rc, MAKELANGID(LANG_NEUTRAL,
                                             SUBLANG_DEFAULT),
                        (LPTSTR) &error_buf, 0, NULL);
          printf("%s\n", error_buf);
        }
      return(0);
    }     /* end while */

start_hip:
  init_hip(argc, argv);
  while (g_state == 0)
    {
      Sleep(1000);
    }
  WSACleanup();
  hip_sadb_deinit();
  printf("Returning from main(), g_state=%d\n", g_state);
  fflush(stdout);
  return(0);
}

