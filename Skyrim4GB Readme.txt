Skyrim 4GB
==========
by MonochromeWench (the.wench@wenchy.net)

Skyrim4GB is a tool to load SKyrin with the Large Address Aware 
executable flag set so the entire 4GB Virtual Memory Address Space can be used
by the game.

This is my 'official' port of my tool that did the same to Fallout NV.

Skyrim4GB is licensed under the terms of the GNU Lesser General Public License 
version 2.1. Read the included lgpl-2.1.txt for the terms. Source code is included
with the package. Original binaries compiled using Microsoft Visual Studio 2010.


Update History
--------------
1.2

Skyrim4GB will attempt to load the SKSE loader (skse_steam_loader.dll).

Skyrim4GB no longer hooks GetTickCount(). 

1.1

Made some code changes that 'may' improve things for some people. Now checks 
the Bethesda Softworks\Skyrim and Valve\Steam paths for the installation 
directory.

Also will now write out a log file to ~\Documents\My Games\Skyrim\Skyrim4GB.log
that outputs some debugging information that may help track down why it doesn't
work for some people.

If you are getting Steam Application load error 3:0000065432 messages then 
please post the log contents to the discussion thread so I can see whats going
on.

Also compiled the new version with Visual Studio 2010. This may or may not make
any difference.


Running
-------
First, make sure Steam is running. Then run Skyrim4GB.exe to launch the game! 
You don't even need it in the games directory, just make sure skyrim4gb.exe and
skyrim4gb_helper.dll are together.

If your version of Skyrim is not the standard version with the
SteamAppID of 72850 you need to run Skyrim4gb.exe and specify the actual 
SteamAppID on the command line. Example: Skyrim4gb.exe 72850


Technical Details
-----------------

Skyrim4gb.exe performs the following actions

1) Gets the Install Path for the game from the registry value:
   HKEY_LOCAL_MACHINE\SOFTWARE\Bethesda Softworks\Skyrim\Installed Path
2) Changes to the games Directory
3) Copies TESV.exe to TESV.exe.4GB if needed
4) Sets the LARGEADDRESSAWARE bit on TESV.exe.4GB if needed
5) Sets the environment variable SteamAPPId to 72850 (or whatever value was 
   specified on the command line) which tells Steam to run the game (not 
   restart and load the launcher)
6) Creates a new process for TESV.exe.4GB with the main thread suspended
7) Injects skyrim4gb_helper.dll into the TESV.exe.4GB process
8) skyrim4gb_helper unsets the LARGEADDRESSAWARE bit in the loaded headers so 
   when steam verifies the loaded executable in memory it passes
9) skyrim4gb_helper hooks the GetTickCount function to attempt to reduce 
   stuttering
10) skyrim4gb_helper hooks the CreateFileA function so when steam attempts to 
   verify the disk executable file against the loaded memory it loaes that Large Addresses are enabeles in the 
    TESV.4gb.exe
12) Skyrim4GB loader unsuspends the main thread so the game can runds the 
   untouched TESV.exe instead of the modified TESV.exe.4gb
11) The Skyrim4GB loader verifi
