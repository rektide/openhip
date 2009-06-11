@echo off

rem Similar to settings found in:
rem "c:\Program Files\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT"
rem for MASM:
rem "c:\Program Files\MASM611\BIN\NEW-VARS.BAT"
rem SET PATH=C:\PROGRA~1\MASM611\BIN;%PATH%

rem
rem Root of Visual Developer Studio Common files.
set VSCommonDir=C:\PROGRA~1\MICROS~4\Common

rem
rem Root of Visual Developer Studio installed files.
rem
set MSDevDir=C:\PROGRA~1\MICROS~4\Common\msdev98

rem
rem Root of Visual C++ installed files.
rem
set MSVCDir=C:\PROGRA~1\MICROS~4\VC98


set INCLUDE=C:\Program Files\Microsoft Platform SDK\Include;C:\Program Files\Microsoft Platform SDK\Include\crt;
set LIB=C:\Program Files\Microsoft Platform SDK\Lib;C:\Program Files\Microsoft Visual Studio\VC98\Lib;.\lib
set PATH=%MSDevDir%\BIN;%MSVCDir%\BIN;%VSCommonDir%\TOOLS\%VcOsDir%;%VSCommonDir%\TOOLS;%PATH%
set PATH=C:\Program Files\Microsoft Platform SDK\Bin;%PATH%
