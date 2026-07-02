@ECHO OFF

ECHO Starting restoration process ...

:ROBO
    ECHO Copying user folders from vision2\%USERNAME% to %USERPROFILE% ...
    RoboCopy.exe \\vision2\backups\%USERNAME% %USERPROFILE% *.* /S /COPY:DAT /XF *.DAT* *.dll* /XD *OneDrive* *AppData* *Application* /MT:16 /R:0 /V /ETA
