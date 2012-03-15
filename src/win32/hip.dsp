# Microsoft Developer Studio Project File - Name="hip" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=hip - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "hip.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "hip.mak" CFG="hip - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "hip - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "hip - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "hip - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Yu"stdafx.h" /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386

!ELSEIF  "$(CFG)" == "hip - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /Zp1 /MDd /W3 /Gm /GX /ZI /Od /I "../include" /I "include" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /D "__WIN32__" /D "__UMH__" /D "CONFIG_HIP" /D "WIN32_LEAN_AND_MEAN" /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /i ".\include" /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib advapi32.lib shell32.lib ws2_32.lib iphlpapi.lib iconv.lib libeay32.lib libxml2.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept /libpath:"..\lib"
# SUBTRACT LINK32 /pdb:none

!ENDIF 

# Begin Target

# Name "hip - Win32 Release"
# Name "hip - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\src\hip_cache.c
# End Source File
# Begin Source File

SOURCE=..\src\hip_dht.c
# End Source File
# Begin Source File

SOURCE=.\hip_dns.c
# End Source File
# Begin Source File

SOURCE=.\hip_esp.c
# End Source File
# Begin Source File

SOURCE=..\src\hip_globals.c
# End Source File
# Begin Source File

SOURCE=..\src\hip_input.c
# End Source File
# Begin Source File

SOURCE=..\src\hip_ipsec.c
# End Source File
# Begin Source File

SOURCE=..\src\hip_ipsec_win32.c
# End Source File
# Begin Source File

SOURCE=..\src\hip_keymat.c
# End Source File
# Begin Source File

SOURCE=..\src\hip_main.c
# End Source File
# Begin Source File

SOURCE=..\src\hip_netlink.c
# End Source File
# Begin Source File

SOURCE=.\hip_nl.c
# End Source File
# Begin Source File

SOURCE=..\src\hip_output.c
# End Source File
# Begin Source File

SOURCE=.\hip_sadb.c
# End Source File
# Begin Source File

SOURCE=.\hip_service.c
# End Source File
# Begin Source File

SOURCE=..\src\hip_status.c
# End Source File
# Begin Source File

SOURCE=.\hip_status2.c
# End Source File
# Begin Source File

SOURCE=..\src\hip_util.c
# End Source File
# Begin Source File

SOURCE=.\socketpair.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\checksum.h
# End Source File
# Begin Source File

SOURCE=.\cygwin_ipv6.h
# End Source File
# Begin Source File

SOURCE=..\src\hip.h
# End Source File
# Begin Source File

SOURCE=..\src\hip_globals.h
# End Source File
# Begin Source File

SOURCE=.\hip_sadb.h
# End Source File
# Begin Source File

SOURCE=.\hip_service.h
# End Source File
# Begin Source File

SOURCE=..\src\hip_status.h
# End Source File
# Begin Source File

SOURCE=.\netlink.h
# End Source File
# Begin Source File

SOURCE=".\openvpn-common.h"
# End Source File
# Begin Source File

SOURCE=.\rtnetlink.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
