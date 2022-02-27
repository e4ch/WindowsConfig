# WindowsConfig
User configuration of default Windows setup via PowerShell

This short PowerShell script configures a new / default Windows 10 installation (not tested with Win11 yet) to the settings that I usually configure after logging in the first time. As I have to do this quite often on new or temporary servers, I've create this quick script for it.

You probably have different opinions on what you want to configure, therefore you can just use this as template or if you do need at least a part of these configurations, you might want to comment out those settings that you don't want. This is done at the end of this script.

The following settings are getting configured:
- disable Windows snapping (that when you move a Windows near the screen border that it snaps and gets full size)
- disable accessibility enablement (pressing 10 seconds the shift key and these things)
- enable Accent color on window title bar (that an active window moved over another window are not white on white)
- set chitz.bmp as background tile (you probably don't want this; this is retro stuff and the image itself belongs to the old Microsoft Windows 3.1; not part of the MIT license)
- configure send to Notepad (option to enable right-click context menu with the option to send any file to Notepad) - If run elevated, configures this for default (new) users too
- show all notification area icons (set the option to show all icons in the notification area, not only specific ones)
- configure file explorer options (various File Explorer settings, like show all file extensions including system, disable sharing wizard which enables normal sharing, don't hide known files, etc.)
- hide search box (disable the search box in the Taskbar)
- configure never combine Taskbar items (configuration to never combine items on the Taskbar; doesn't exist on Windows 11, so not sure what happens there)
- configure UAC to maximum level (configuration of UAC \[user access control\] to maximum level which mitigates some bypass techniques)
- make C:\TEMP (create a C:\TEMP folder and configure permissions for all users; requires elevation)

