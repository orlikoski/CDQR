## NAME

CDQR — Cold Disk Quick Response tool by Alan Orlikoski

## What is CDQR?
The CDQR tool uses Plaso to parse disk images with specific parsers and create easy to analyze custom reports. The parsers were chosen based on my experience and triaging best practices and the custom reports group like items together to make analysis easier. The design came from the Live Response Model of investigating the important artifacts first. This is meant to be a starting point for investigations, not the complete investigation.

In addition to processing entire forensic images it also parses extracted forensic artifact(s) as an individual file or collection of files inside of a folder structure.

It creates up to 14 Reports (.csv files) based on triaging best practices and the parsing option selected
*  14 Reports for DATT:  
      ```
      Event Logs, File System, MFT, UsnJrnl, Internet History, Prefetch, Registry, Scheduled Tasks, Persistence, System Information, AntiVirus, Firewall, Mac, and Linux
      ```
*  12 Reports for Win:  
      ```
      Event Logs, File System, MFT, UsnJrnl, Internet History, Prefetch, Registry, Scheduled Tasks, Persistence, System Information, AntiVirus, Firewall
      ```
*   7 Reports for Mac and Lin:  
      ```
      File System, Internet History, System Information, AntiVirus, Firewall, Mac, and Linux
      ```

## What's New
*  Ability to parse Mac images
*  Ability to parse Linux images
*  14 Reports for DATT:  
      ```
      Event Logs, File System, MFT, UsnJrnl, Internet History, Prefetch, Registry, Scheduled Tasks, Persistence, System Information, AntiVirus, Firewall, Mac, and Linux
      ```
*  12 Reports for Win:  
      ```
      Event Logs, File System, MFT, UsnJrnl, Internet History, Prefetch, Registry, Scheduled Tasks, Persistence, System Information, AntiVirus, Firewall
      ```
*   7 Reports for Mac and Lin:  
      ```
      File System, Internet History, System Information, AntiVirus, Firewall, Mac, and Linux
      ```
*  Improved the way existing log files and results directories are handled
*  Ability to create an export file

## Fixes
* Fixed the --export function

## Known Bugs
* The Plaso 1.4 MFT parser is not functioning [Plaso Error #556](https://github.com/log2timeline/plaso/issues/556) for disk images but filestat and usrjrnl are working fine.  This will be corrected once Plaso 1.4 is updated.

## Important Notes
* Make sure account has permissions to create files and directories when running cdqr.exe (when in doubt, run as administrator)

## SYNOPSIS

Windows 64-bit binary
```
cdqr.exe [-h] [-p [PARSER]] [--hash] [--max_cpu] [--export] [-v : --version]
```
Python 3.4
```
cdqr.py [-h] [-p [PARSER]] [--hash] [--max_cpu] [--export] [-v : --version]  
```

## DESCRIPTION

This program uses [Plaso](https://github.com/log2timeline/plaso/wiki) and a streamlined list of parsers to quickly analyze a forenisic image file (dd, E01, .vmdk, etc) or group of forensic artifacts.  The results are output in the following report files in CSV format:
*  14 Reports for DATT:  
      ```
      Event Logs, File System, MFT, UsnJrnl, Internet History, Prefetch, Registry, Scheduled Tasks, Persistence, System Information, AntiVirus, Firewall, Mac, and Linux
      ```
*  12 Reports for Win:  
      ```
      Event Logs, File System, MFT, UsnJrnl, Internet History, Prefetch, Registry, Scheduled Tasks, Persistence, System Information, AntiVirus, Firewall
      ```
*   7 Reports for Mac and Lin:  
      ```
      File System, Internet History, System Information, AntiVirus, Firewall, Mac, and Linux
      ```

## ARGUMENTS
* `src_location` — Source file location, such as `Y:\Case\Tag009\sample.E01`, `E:\Artifacts_folder\` or `E:\Artifacts_folder\mylogs.evtx`
* `dst_location` — Destination folder location. If nothing is supplied, then the default is `Results\`


## OPTIONS

* `-h` , `--help` — Show this help message and exit.
* `-p [parser]` , `--parser [parser]` — Choose parser to use. If nothing is chosen then `win` is used.
* `--hash` — Hash all the files as part of the processing of the image.
* `--max_cpu` — Use the same number of workers as cpu cores
* `--export` — Creates gzipped, line delimited json export file
* `-v : --version` — Show version


## PARSER LIST

There are four available parsers for CDQR: `datt` , `win` , `lin` , and `mac` and here the Plaso parsers they represent:
* **win**
  * Plaso v1.4
  ```
  appcompatcache,bagmru,binary_cookies,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,java_idx,mcafee_protection,mft,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msiecf,mstsc_rdp,mstsc_rdp_mru,opera_global,opera_typed_history,prefetch,recycle_bin,recycle_bin_info2,rplog,safari_history,symantec_scanlog,userassist,usnjrnl,windows_boot_execute,windows_boot_verify,windows_run,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winjob,winrar_mru,winreg,winreg_default
  ```
  * Plaso v1.3
  ```
  appcompatcache,bagmru,binary_cookies,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cookies,firefox_downloads,firefox_history,firefox_old_cache,google_drive,java_idx,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msie_zone_software,msiecf,mstsc_rdp,mstsc_rdp_mru,opera_global,opera_typed_history,prefetch,recycle_bin,recycle_bin_info2,rplog,symantec_scanlog,userassist,windows_boot_execute,windows_boot_verify,windows_run,windows_run_software,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winiis,winjob,winrar_mru,winreg,winreg_default
  ```
* **datt**
  * Plaso v1.4
  ```
  airport,android_app_usage,android_calls,android_sms,appcompatcache,apple_id,appusage,asl_log,bagmru,bencode,bencode_transmission,bencode_utorrent,binary_cookies,bsm_log,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,cups_ipp,custom_destinations,esedb,esedb_file_history,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,ipod_device,java_idx,lnk,ls_quarantine,mac_appfirewall_log,mac_document_versions,mac_keychain,mac_securityd,mackeeper_cache,macosx_bluetooth,macosx_install_history,mactime,macuser,macwifi,maxos_software_update,mcafee_protection,mft,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_webcache,msie_zone,msiecf,mstsc_rdp,mstsc_rdp_mru,olecf,olecf_automatic_destinations,olecf_default,olecf_document_summary,olecf_summary,openxml,opera_global,opera_typed_history,pe,plist,plist_default,pls_recall,popularity_contest,prefetch,recycle_bin,recycle_bin_info2,rplog,safari_history,sccm,selinux,skydrive_log,skydrive_log_old,skype,spotlight,spotlight_volume,sqlite,symantec_scanlog,syslog,time_machine,userassist,usnjrnl,utmp,utmpx,windows_boot_execute,windows_boot_verify,windows_run,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winiis,winjob,winrar_mru,winreg,winreg_default,xchatlog,xchatscrollback,zeitgeist
  ```
  * Plaso v1.3
  ```
  android_app_usage,asl_log,bencode,binary_cookies,bsm_log,chrome_cache,chrome_preferences,cups_ipp,custom_destinations,esedb,filestat,firefox_cache,firefox_old_cache,hachoir,java_idx,lnk,mac_appfirewall_log,mac_keychain,mac_securityd,mactime,macwifi,mcafee_protection,msiecf,olecf,openxml,opera_global,opera_typed_history,pcap,pe,plist,pls_recall,popularity_contest,prefetch,recycle_bin,recycle_bin_info2,rplog,selinux,skydrive_log,skydrive_log_error,sqlite,symantec_scanlog,syslog,utmp,utmpx,winevt,winevtx,winfirewall,winiis,winjob,winreg,xchatlog,xchatscrollback,bencode_transmission,bencode_utorrent,esedb_file_history,msie_webcache,olecf_automatic_destinations,olecf_default,olecf_document_summary,olecf_summary,airport,apple_id,ipod_device,macosx_bluetooth,macosx_install_history,macuser,maxos_software_update,plist_default,safari_history,spotlight,spotlight_volume,time_machine,android_calls,android_sms,appusage,chrome_cookies,chrome_extension_activity,chrome_history,firefox_cookies,firefox_downloads,firefox_history,google_drive,ls_quarantine,mac_document_versions,mackeeper_cache,skype,zeitgeist,appcompatcache,bagmru,ccleaner,explorer_mountpoints2,explorer_programscache,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msie_zone_software,mstsc_rdp,mstsc_rdp_mru,userassist,windows_boot_execute,windows_boot_verify,windows_run,windows_run_software,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winrar_mru,winreg_default
  ```
* **mac**
  * Plaso v1.4
  ```
  binary_cookies,bsm_log,chrome_cache,chrome_preferences,filestat,firefox_cache,firefox_cache2,java_idx,mac_appfirewall_log,mac_keychain,mac_securityd,mactime,mcafee_protection,opera_global,opera_typed_history,plist,popularity_contest,selinux,utmp,utmpx,airport,apple_id,macosx_install_history,plist_default,spotlight,spotlight_volume,time_machine,appusage,chrome_cookies,chrome_extension_activity,chrome_history,firefox_cookies,firefox_downloads,firefox_history,google_drive,ls_quarantine,mackeeper_cache
  ```
  * Plaso v1.3  
  ```
  macosx
  ```
* **lin**
  * Plaso v1.4
  ```
  airport,apple_id,appusage,binary_cookies,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,ipod_device,java_idx,mac_appfirewall_log,mac_keychain,mac_securityd,mackeeper_cache,macosx_bluetooth,macosx_install_history,mactime,macuser,maxos_software_update,mcafee_protection,opera_global,opera_typed_history,plist,plist_default,popularity_contest,safari_history,spotlight,spotlight_volume,symantec_scanlog,time_machine,utmp,utmpx
  ```
  * Plaso v1.3  
  ```
  linux
  ```

## DEPENDENCIES

1. 64-bit Windows Operating System 
2. Depending on your preference, either:
  * Win 64-bit: [Plaso 1.4.0 (x64)](https://e366e647f8637dd31e0a13f75e5469341a9ab0ee.googledrive.com/host/0B30H7z4S52FleW5vUHBnblJfcjg/1.4.0/plaso-1.4.0-win-amd64-vs2010.zip) AND [Microsoft Visual C++ 2010 Redistributable Package (x64)](https://www.microsoft.com/en-us/download/details.aspx?id=14632), or
  * Win 32-bit: [Plaso 1.4.0 (x86)](https://e366e647f8637dd31e0a13f75e5469341a9ab0ee.googledrive.com/host/0B30H7z4S52FleW5vUHBnblJfcjg/1.4.0/plaso-1.4.0-win32-vs2008.zip) AND [Microsoft Visual C++ 2008 Redistributable Package (x86)](https://www.microsoft.com/en-us/download/details.aspx?id=29)
3. [Python v3.4](https://www.python.org/downloads/release/python-340/) (if using cdqr.py source code)

## EXAMPLES

```
cdqr.py c:\mydiskimage.vmdk myresults
```
```
cdqr.exe -p win c:\images\badlaptop.e01
```
```
cdqr.exe -p datt --max_cpu C:\artifacts\tag009
```
```
cdqr.exe -p datt --max_cpu C:\artifacts\tag009\$MFT --export
```

## Linux Plaso Install
Run these commands to install lastest stable version of Plaso on Ubuntu
* sudo add-apt-repository ppa:gift/stable
* sudo apt-get install python-plaso

## AUTHOR

* [Alan Orlikoski](https://github.com/rough007)