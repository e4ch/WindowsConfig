#############################################################################################################
## This script configures typical configuration on default Windows installations according to my personal  ##
## requirements; configurations that I always need to change every time I log in to a new Windows machine. ##
## copyright 2022 Eric Bauersachs, free for non-commercial usage, changes possibile without notification   ##
## version 4, 2022-03-18																				   ##
#############################################################################################################

##################################
## Console Log Helper functions ##
##################################

function LogError{
	param(
		[string] $text
	)
	process{
		Write-Host $text -ForegroundColor Red
	}
}

function LogWarn{
	param(
		[string] $text
	)
	process{
		Write-Host $text -ForegroundColor Yellow
	}
}

function LogInfo{
	param(
		[string] $text
	)
	process{
		Write-Host $text
	}
}

function LogInfoDone{
	param(
		[string] $text
	)
	process{
		Write-Host $text -ForegroundColor Green
	}
}

function LogHelper{
	param(
		[Int32] $ret,
		[string] $FunctionalityName,
		[string] $ActionType
	)
	process{
		if($ret -eq 2){
			LogInfoDone "$($FunctionalityName) was successfully $($ActionType)."
		}
		if($ret -eq 1){
			LogInfo "$($FunctionalityName) was already $($ActionType)."
		}
	}
}

#####################################################################
## Compressions/Decompression helper functions for contained image ##
#####################################################################

function Get-CompressedByteArray {
	# from https://gist.github.com/marcgeld/bfacfd8d70b34fdf1db0022508b02aca
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
		[byte[]] $byteArray = $(Throw("-byteArray is required"))
	)
	Process {
		Write-Verbose "Get-CompressedByteArray"
	   	[System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
		$gzipStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
	  	$gzipStream.Write( $byteArray, 0, $byteArray.Length )
		$gzipStream.Close()
		$output.Close()
		$tmp = $output.ToArray()
		Write-Output $tmp
	}
}

function Get-DecompressedByteArray {
	# from https://gist.github.com/marcgeld/bfacfd8d70b34fdf1db0022508b02aca
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
		[byte[]] $byteArray = $(Throw("-byteArray is required"))
	)
	Process {
		Write-Verbose "Get-DecompressedByteArray"
		$input = New-Object System.IO.MemoryStream( , $byteArray )
		$output = New-Object System.IO.MemoryStream
		$gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
		$gzipStream.CopyTo( $output )
		$gzipStream.Close()
		$input.Close()
		[byte[]] $byteOutArray = $output.ToArray()
		Write-Output $byteOutArray
	}
}

############################
## Other helper functions ##
############################

function Test-IsAdmin
# from https://devblogs.microsoft.com/scripting/use-function-to-determine-elevation-of-powershell-console/
{
	$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = New-Object Security.Principal.WindowsPrincipal $identity
	$principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function WaitForKeyPressIfNotInIse{
	if(-not $psISE){
		LogInfo "Press any key to finish."
		$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') | Out-Null
	}
}

function CopyFile{
	Param (
		[Parameter(Mandatory)] [String] $SourceFile,
		[Parameter(Mandatory)] [String] $DestinationFolder
	)
	Process {
		$error = "error"
		try{
			Copy-Item $SourceFile -Destination $DestinationFolder -errorAction stop | Out-Null
			$error = ""
		}catch{
			$error = $_.Exception.Message
		}
		$error
	}
}

######################################
## Registry configuration functions ##
######################################

function RegSetDWMustExist{
	param(
		[Parameter(Mandatory)] [String] $RegistryPath,
		[Parameter(Mandatory)] [String] $Name,
		[Parameter(Mandatory)] [Int32] $Value
	)
	process{
		$ret = 0 # 0=error (value/key not found), 1=already correct, 2=successfully changed
		$i = Get-Item $RegistryPath -ErrorAction Ignore
		if($i.Property -contains $Name){
			$oldval = Get-ItemPropertyValue -Path $RegistryPath -Name $Name -ErrorAction Ignore
			if($oldval -ne $null){
				if($oldval.GetType().Name -eq "Int32"){
					if($oldval -ne $Value){
						$reqAdmin = ($RegistryPath.SubString(0,5) -eq "HKLM:")
						$isAdmin = Test-IsAdmin
						if($reqAdmin -and $isAdmin -or -not $reqAdmin){
							New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force | Out-Null
							$ret = 2
						}else{
							LogWarn "Registry change in HKLM requires elevation. Cannot cahnge '$RegistryPath\$Name'."
						}
					}else{
						$ret = 1
					}
				}else{
					LogError "Registry value '$RegistryPath\$Name' exists, but is of wrong type. Cannot set value."
				}
			}else{
				LogError "Error reading old registry value '$RegistryPath\$Name'. Cannot set value."
			}
		}else{
			LogError "Registry value '$RegistryPath\$Name' does not exist. Cannot set value."
		}
		Write-Output $ret
	}
}

function RegSetSZMustExist{
	param(
		[Parameter(Mandatory)] [String] $RegistryPath,
		[Parameter(Mandatory)] [String] $Name,
		[Parameter(Mandatory)] [String] $Value
	)
	process{
		$ret = 0 # 0=error (value/key not found), 1=already correct, 2=successfully changed
		$i = Get-Item $RegistryPath -ErrorAction Ignore
		if($i.Property -contains $Name){
			$oldval = Get-ItemPropertyValue -Path $RegistryPath -Name $Name -ErrorAction Ignore
			if($oldval -ne $null){
				if($oldval.GetType().Name -eq "String"){
					if($oldval -ne $Value){
						New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType String -Force | Out-Null
						$ret = 2
					}else{
						$ret = 1
					}
				}else{
					LogError "Registry value '$RegistryPath\$Name' exists, but is of wrong type. Cannot set value."
				}
			}else{
				LogError "Error reading old registry value '$RegistryPath\$Name'. Cannot set value."
			}
		}else{
			LogError "Registry value '$RegistryPath\$Name' does not exist. Cannot set value."
		}
		Write-Output $ret
	}
}

#################################
## Main configuration settings ##
#################################

function DisableWindowSnapping{
	# generic setting is here:
	# CPL / Ease of Access Center / Make the mouse easier to use -> Prevent windows from being automatically arranged when moved to the edge of the screen
	# same setting here:
	# Settings / System / Multitasking -> Snap windows
	# both are controlled via this registry key:
	# HKCU\Control Panel\Desktop -> value WindowArrangementActive REG_SZ ("0" or "1")
	# Note: If enabled, it is possible to control the individual values (not part of this function, as we disable it)
	# Per default the values don't exist and default to 1 (all enabled)
	# HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -> values SnapFill, SnapAssist, JointResize REG_DWORD

	$ret1 = RegSetSZMustExist "HKCU:\Control Panel\Desktop" "WindowArrangementActive" "0"
	if($ret1 -eq 2){
		LogInfoDone "Disable Windows Snapping was successfully configured."
	}
	if($ret1 -eq 1){
		LogInfo "Disable Windows Snapping was already configured."
	}
}

function DisableAccessibilityEnablement{
	$ret1 = RegSetSZMustExist "HKCU:\Control Panel\Accessibility\StickyKeys" "Flags" "506" # Sticky Keys
	$ret2 = RegSetSZMustExist "HKCU:\Control Panel\Accessibility\ToggleKeys" "Flags" "58" # Toggle Keys
	$ret3 = RegSetSZMustExist "HKCU:\Control Panel\Accessibility\Keyboard Response" "Flags" "122" # Filter Keys
	if($ret1 -eq 1 -and $ret2 -eq 1 -and $ret3 -eq 1){
		LogInfo "All accessibility functions (Sticky Keys, Toggle Keys, Filter Keys) were already disabled."
	}else{
		if($ret1 -eq 2 -and $ret2 -eq 2 -and $ret3 -eq 2){
			LogInfoDone "All accessibility functions (Sticky Keys, Toggle Keys, Filter Keys) were successfully disabled."
		}else{
			# mixed results, give individual details
			LogHelper $ret1 "Accessibility function Sticky Keys" "disabled"
			LogHelper $ret2 "Accessibility function Toggle Keys" "disabled"
			LogHelper $ret3 "Accessibility function Filter Keys" "disabled"
		}
	}
}

function EnableAccentColorOnWindowTitlebar{
	# This setting can be found here:
	# Settings / Personalization / Colors -> Show accent color on the following surfaces: Title bars and window borders
	# if not enabled, you have white on white when windows overlap and you cannot see any borders anymore
	$ret1 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\DWM" "ColorPrevalence" 1
	LogHelper $ret1 "Enable access color on windows titlebar" "configured"
}

function WriteChitzIfNotExists{
	$ret = 0 # 1=file already there, 0=file not there and not an admin to write it, 2=copied successfully
	$ChitzDataCompressedB64=@"
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
"@
	$ChitzDataCompressed=[Convert]::FromBase64String($ChitzDataCompressedB64)
	$ChitzData=Get-DecompressedByteArray -byteArray $ChitzDataCompressed
	$fullpath = Join-Path -Path $env:windir -ChildPath "CHITZ.BMP"
	$fileAlreadyThere = $false
	if(Test-Path -Path $fullpath -PathType Leaf){
		# some file with this name already exists
		$existingContent = Get-Content -Path $fullpath -Raw -Encoding Byte
		if($existingContent.Length -eq $ChitzData.Length){
			$fileAlreadyThere = -not (Compare-Object -ReferenceObject $ChitzData -DifferenceObject $existingContent)
		}
	}
	if($fileAlreadyThere){
		$ret = 1
		LogInfo "The file CHITZ.BMP is already in the WINDOWS folder."
	}else{
		if(Test-IsAdmin){
			[IO.File]::WriteAllBytes($fullpath,$ChitzData)
			LogInfoDone "The file CHITZ.BMP was successfully written to the WINDOWS folder."
			$ret = 2
		}else{
			LogWarn "Cannot write CHITZ.BMP to WINDOWS if not an admin!"
			$ret = 0
		}
	}
	Write-Output $ret
}

function SetChitzBackground{
	$ret1 = WriteChitzIfNotExists
	if($ret1 -eq 1 -or $ret1 -eq 2){
		$ret2 = RegSetSZMustExist "HKCU:\Control Panel\Desktop" "WallPaper" (Join-Path -Path $env:windir -ChildPath "CHITZ.BMP").ToLower()
		$ret3 = RegSetSZMustExist "HKCU:\Control Panel\Desktop" "WallPaperStyle" "0"
		$ret4 = RegSetSZMustExist "HKCU:\Control Panel\Desktop" "TileWallpaper" "1"
		if($ret2 -eq 1 -and $ret3 -eq 1 -and $ret4 -eq 1){
			LogInfo "All Wallpaper settings were already configured."
		}else{
			if($ret2 -eq 2 -and $ret3 -eq 2 -and $ret4 -eq 2){
				LogInfoDone "All Wallpaper settings were successfully configured."
			}else{
				# mixed results, give individual details
				LogHelper $ret2 "Wallpaper setting" "configured"
				LogHelper $ret3 "WallPaperStyle setting" "configured"
				LogHelper $ret3 "TileWallpaper setting" "configured"
			}
		}
	}else{
		LogWarn "As the file couldn't be written, will not configure related settings."
	}
	# Note: New settings don't apply automatically. Even restarting all Explorers won't help to apply.
}

function ConfigureSendToNotepad{
	# for localization, check: HKEY_CLASSES_ROOT\Applications\notepad.exe\shell\edit\command -> %SystemRoot%\system32**kladblok.exe** %1
	# TODO: Currently only English verified
	$fileName = "Notepad.lnk" #or Editor.lnk etc.
	$RegKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility\InboxApp')
	$NumFound = 0
	$RegKey.PSObject.Properties | ForEach-Object {
		if($_.Name -like '*_Notepad_lnk_amd64.lnk' -and $_.TypeNameOfValue -eq 'System.String'){
			# TODO: We have checked TypeNameOfValue, but not if it's really REG_EXPAND_SZ.
			$NumFound++
			$FoundName = $_.Name
			$FoundExpandSz = $_.Value
			LogInfo "Found $($FoundName): $($FoundExpandSz)"
		}
	}
	if($NumFound -eq 1){
		# TODO: We should probably expand this string, but it did never contain anything to expand.
		$srcFile = $FoundExpandSz
		$destFolder=Join-Path -Path $env:appdata -ChildPath "\Microsoft\Windows\SendTo\"
		$destFile=Join-Path -Path $destFolder -ChildPath $fileName
		if(Test-Path -Path $destFile -PathType Leaf){
			LogInfo "The Notepad shortcut is already present in the user's SentTo folder."
		}else{
			$RetError = CopyFile $srcFile $destFolder
			if($RetError -eq ''){
				LogInfoDone "The Notepad shortcut was successfully copied to the user's SentTo folder."
			}else{
				LogError "The Notepad shortcut was not copied to the user's SentTo folder. Error: $($RetError)"
			}
		}
		$destNewUser="C:\Users\Default\AppData\Roaming\Microsoft\Windows\SendTo"
		$destNewUserFile=Join-Path -Path $destNewUser -ChildPath $fileName
		if(Test-Path -Path $destNewUserFile -PathType Leaf){
			LogInfo "The Notepad shortcut is already present in the Default user's SentTo folder."
		}else{
			if(Test-IsAdmin){
				$RetError = CopyFile $srcFile $destNewUser
				if($RetError -eq ''){
					LogInfoDone "The Notepad shortcut was successfully copied to the Default user's SentTo folder."
				}else{
					LogError "The Notepad shortcut was not copied to the Default user's SentTo folder. Error: $($RetError)"
				}
			}else{
				LogWarn "As non-admin, cannot configure SendTo Notepad for new users."
			}
		}
	}else{
		LogError "Cannot evaluate location of Notepad.lnk"
	}
}

function HideSearchBox{
	$ret1 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "SearchboxTaskbarMode" 0
	LogHelper $ret1 "Search box" "hidden"
}

function ShowAllNotificationAreaIcons{
	# This can be configured in this dialog, run: shell:::{05d7b0f4-2121-4eff-bf6b-ed3f69b894d9}
	# or in this new one: Settings / Personalization / Taskbar -> Notification area / Select which icons appear on the taskbar
	$ret1 = RegSetDWMustExist "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" "EnableAutoTray" 0
	LogHelper $ret1 "Notification area 'show all icons'" "configured"
}

function ConfigureFileExplorerOptions{
	$ret01 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "IconsOnly" 1 # Files and Folders / Always show icons, never thumbnails ***
	$ret02 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "AlwaysShowMenus" 1 # Files and Folders / Always show menus
	$ret03 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" "FullPath" 1 # Files and Folders / Display the full path in the title bar
	$ret04 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1 # Files and Folders / Hidden files and folders / 1=Show hidden files, folders, and drives (2=Don't show) ***
	$ret05 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideDrivesWithNoMedia" 0 # Files and Folders / Hide empty drives
	$ret06 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0 # Files and Folders / Hide extensions for known file types ***
	$ret07 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideMergeConflicts" 0 # Files and Folders / Hide folder merge conflicts
	$ret08 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSuperHidden" 1 # Files and Folders / Hide protected operating system files (Recommended) ***
	$ret09 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "SeparateProcess" 1 # Files and Folders / Launch folder windows in a separate process ***
	$ret10 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "PersistBrowsers" 1 # Files and Folders / Restore previous folder windows at logon
	$ret11 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowEncryptCompressedColor" 1 # Files and Folders / Show encrypted or compressed NTFS files in color
	$ret12 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "SharingWizardOn" 0 # Files and Folders / Use Sharing Wizard (Recommended)
	$ret13 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "NavPaneShowAllCloudStates" 1 # Navigation pane / Always show availability status
	$ret14 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "NavPaneExpandToCurrentFolder" 1 # Navigation pane / Expand to open folder
	$ret15 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "NavPaneShowAllFolders" 1 # Navigation pane / Show all folders
	$ret16 = RegSetDWMustExist "HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" "System.IsPinnedToNameSpaceTree" 1 # Navigation pane / Show libraries
	if($ret01 -eq 1 -and $ret02 -eq 1 -and $ret03 -eq 1 -and $ret04 -eq 1 -and $ret05 -eq 1 -and $ret06 -eq 1 -and $ret07 -eq 1 -and $ret08 -eq 1 -and $ret09 -eq 1 -and $ret10 -eq 1 -and $ret11 -eq 1 -and $ret12 -eq 1 -and $ret13 -eq 1 -and $ret14 -eq 1 -and $ret15 -eq 1 -and $ret16 -eq 1){
		LogInfo "All Windows Explorer settings were already configured correctly; no changes made."
	}else{
		if($ret01 -eq 2 -and $ret02 -eq 2 -and $ret03 -eq 2 -and $ret04 -eq 2 -and $ret05 -eq 2 -and $ret06 -eq 2 -and $ret07 -eq 2 -and $ret08 -eq 2 -and $ret09 -eq 2 -and $ret10 -eq 2 -and $ret11 -eq 2 -and $ret12 -eq 2 -and $ret13 -eq 2 -and $ret14 -eq 2 -and $ret15 -eq 2 -and $ret16 -eq 2){
			LogInfoDone "All Windows Explorer settings were Successfully configured."
		}else{
			# mixed results, give individual details
			LogHelper $ret01 "Windows Explorer configuration 'Always show icons, never thumbnails'" "enabled"
			LogHelper $ret02 "Windows Explorer configuration 'Always show menus'" "enabled"
			LogHelper $ret03 "Windows Explorer configuration 'Display the full path in the title bar'" "enabled"
			LogHelper $ret04 "Windows Explorer configuration 'Show hidden files, folders, and drives'" "enabled"
			LogHelper $ret05 "Windows Explorer configuration 'Hide empty drives'" "disabled"
			LogHelper $ret06 "Windows Explorer configuration 'Hide extensions for known file types'" "disabled"
			LogHelper $ret07 "Windows Explorer configuration 'Hide folder merge conflicts'" "disabled"
			LogHelper $ret08 "Windows Explorer configuration 'Hide protected operating system files (Recommended)'" "disabled"
			LogHelper $ret09 "Windows Explorer configuration 'Launch folder windows in a separate process'" "enabled"
			LogHelper $ret10 "Windows Explorer configuration 'Restore previous folder windows at logon'" "enabled"
			LogHelper $ret11 "Windows Explorer configuration 'Show encrypted or compressed NTFS files in color'" "enabled"
			LogHelper $ret12 "Windows Explorer configuration 'Use Sharing Wizard (Recommended)'" "disabled"
			LogHelper $ret13 "Windows Explorer configuration 'Always show availability status'" "enabled"
			LogHelper $ret14 "Windows Explorer configuration 'Expand to open folder'" "enabled"
			LogHelper $ret15 "Windows Explorer configuration 'Show all folders'" "enabled"
			LogHelper $ret16 "Windows Explorer configuration 'Show libraries'" "enabled"
		}
	}
	# *** doesn't apply immediately, requires Explorer restart before options dialog is opened again
	if($ret01 -eq 2 -or $ret04 -eq 2 -or $ret06 -eq 2 -or $ret08 -eq 2 -or $ret09 -eq 2){
		$globalMustRestartExplorer = $true
	}
}

function ConfigureNeverCombineTaskbarItems{
	$ret1 = RegSetDWMustExist "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarGlomLevel" 2
	LogHelper $ret1 "Never combine Taskbar items" "configured"
	if($ret1 -eq 2){
		$globalShouldRestartExplorer = $true
	}
}

function ConfigureUacMaxLevel{
	# Control Panel / User Accounts -> Change User Account Control settings -> move slider to top
	$ret1 = RegSetDWMustExist "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 2
	LogHelper $ret1 "UAC to maximum level" "configured"
}

function MakeCTemp{
	# 1. folder itself
	$folderPathName = "C:\TEMP\"
	$folderName = "TEMP"
	$isAdmin = Test-IsAdmin
	$pathAlreadyExists = Test-Path -Path $folderPathName
	if($pathAlreadyExists){
		LogInfo "Folder $folderPathName already exists."
		$existingFolderName = Get-ChildItem C:\ -filter $folderName -Directory | % { $_.fullname + "\" }
		if($existingFolderName -ceq $folderPathName){
			LogInfo "Folder $folderPathName casing also matches."
		}else{
			$tmp = [IO.Path]::GetRandomFileName()
			$aux1 = Rename-Item -Path $existingFolderName -NewName $tmp -Force *>&1
			if($aux1.Length -eq 0){
				Rename-Item -Path "C:\$tmp" -NewName $folderName -Force
				LogInfoDone "Folder $($folderPathName) casing has been fixed."
			}else{
				LogError "Folder $($folderPathName) renaming of wrong casing failed."
			}
		}
	}else{
		if($isAdmin){
			New-Item -Path $folderPathName -ItemType Directory | Out-Null
			LogInfoDone "Folder $($folderPathName) successfully created."
		}else{
			LogWarn "$($folderPathName) folder can only be created when run elevated."
		}
	}

	# 2. permissions
	if(Test-Path -Path $folderPathName){
		$NewAcl = Get-Acl -Path $folderPathName
		$Rights = $NewAcl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
		$hasAnyInherited = $false
		$foundWrong = $false
		$foundUsers = $false
		$foundSystem = $false
		$foundAdmins = $false
		foreach($r in $Rights){
			if($r.IsInherited){
				$hasAnyInherited = $true
			}else{
				if($r.AccessControlType -ne "Allow" -or $r.InheritanceFlags -ne "ContainerInherit, ObjectInherit" -or $r.PropagationFlags -ne "None"){
					$foundWrong = $true
				}else{
					$foundSomething = $false
					if($r.FileSystemRights -eq "Modify, Synchronize" -and $r.IdentityReference -eq "BUILTIN\Users"){
						$foundSomething = $true
						$foundUsers = $true
					}
					if($r.FileSystemRights -eq "FullControl" -and $r.IdentityReference -eq "NT AUTHORITY\SYSTEM"){
						$foundSomething = $true
						$foundSystem = $true
					}
					if($r.FileSystemRights -eq "FullControl" -and $r.IdentityReference -eq "BUILTIN\Administrators"){
						$foundSomething = $true
						$foundAdmins = $true
					}
					if(-not $foundSomething){
						$foundWrong = $true
					}
				}
			}
		}
		if(-not $foundWrong -and -not $hasAnyInherited -and $foundUsers -and $foundSystem -and $foundAdmins){
			LogInfo "Permissions on $($folderPathName) are already correct."
		}else{
			# Set Permissions
			if($isAdmin){
				$NewAcl.Access | %{$NewAcl.RemoveAccessRule($_)} | Out-Null
				$NewAcl.SetAccessRuleProtection($true, $false)
				$NewAcl.SetAccessRule((New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ("BUILTIN\Administrators", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")))
				$NewAcl.SetAccessRule((New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ("SYSTEM", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")))
				$NewAcl.SetAccessRule((New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ("BUILTIN\Users", "Modify", "ContainerInherit, ObjectInherit", "None", "Allow")))
				Set-Acl -Path $folderPathName -AclObject $NewAcl
				LogInfoDone "Permissions on $folderPathName successfully configured."
			}else{
				LogWarn "Folder $($folderPathName) permissions can only be fixed when run elevated."
			}
		}
	}else{
		LogWarn "Cannot check permissions on non-existent folder $($folderPathName)."
	}
}

##########
## MAIN ##
##########

$ver_major=[Environment]::OSVersion.Version.Major
#[System.Environment]::Is64BitOperatingSystem
$ostxt=(Get-WmiObject -Class Win32_OperatingSystem).Caption
LogInfo "System: $($ostxt)"
if($ver_major -ne 10){
	LogWarn "Not tested with this version of Windows! Running anyway."
}

$globalMustRestartExplorer = $false
$globalShouldRestartExplorer = $false

DisableWindowSnapping
DisableAccessibilityEnablement
EnableAccentColorOnWindowTitlebar
#SetChitzBackground
#TODO: Calc to Scientific -> now in a Windows Store App
#TODO: Paint to default size 5x5 -> now in a Windows Store App
#TODO: Task Manager to Details view and Details Tab -> no easy way to do this, as all data is in one blob
ConfigureSendToNotepad
ShowAllNotificationAreaIcons
ConfigureFileExplorerOptions
HideSearchBox
ConfigureNeverCombineTaskbarItems
ConfigureUacMaxLevel
MakeCTemp

if($globalMustRestartExplorer){
	Stop-Process -Name "explorer"
	LogInfoDone "Windows Explorer killed and restarted to apply the new settings and to avoid that they're getting reverted before application."
	$globalShouldRestartExplorer = $false
}
if($globalShouldRestartExplorer){
	# We could ask for consent here, as this restart is optional, but not really needed.
	Stop-Process -Name "explorer"
	LogInfoDone "Windows Explorer killed and restarted in order to apply the new settings."
	$globalShouldRestartExplorer = $false
}

WaitForKeyPressIfNotInIse

#########
## END ##
#########
