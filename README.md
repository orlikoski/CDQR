## NAME

CDQR — Cold Disk Quick Response tool by Alan Orlikoski

## What's New
Added Do All The Things! parser (datt)
* This enables all parsers for Plaso (version appropriate) and disables the partion/shadow copy options.  This is meant to assist in processing extracted artifacts and not entire images.
* This can be used on individual files as well as all files in a folder
* example: "cdqr.exe -p datt c:\logs\eventlogs" or "cdqr.exe -p datt c:\logs\eventlogs\security.evt"

Now supports Plaso 1.4!
* Adjusted default parsers for Plaso 1.4
* Added compatibility for Plaso 1.3 and Plaso 1.4
* Removes references to parsers no longer found in Plaso
* Includes the new MFT, USRJRNL, and Fire_fox_cache version 2 parsers found in Plaso 1.4

## Fixes
* Improved Logging

## Known Bugs
* The Plaso 1.4 MFT parser is not functioning [Plaso Error #556](https://github.com/log2timeline/plaso/issues/556) for disk images but filestat and usrjrnl are working fine.  This will be corrected once Plaso 1.4 is updated.

## Important Notes
* Make sure account has permissions to create files and directories when running cdqr.exe (when in doubt, run as administrator)

## SYNOPSIS

Windows 64-bit binary
```
cdqr.exe [-h] [-p [PARSER]] [--hash] [--max_cpu] [--version]
```
Python 3.4
```
cdqr.py [-h] [-p [PARSER]] [--hash] [--max_cpu] [--version]  
```

## DESCRIPTION

This program uses [Plaso](https://github.com/log2timeline/plaso/wiki) and a streamlined list of parsers to quickly analyze a forenisic image file (dd, E01, .vmdk, etc) and subsequently output the following nine report files in CSV format:
* \<Source File Name\>.SuperTimeLine.csv
* Event Log Report.csv
* File System Report.csv
* Internet History Report.csv
* Prefetch Report.csv
* Registry Report.csv
* Scheduled Tasks Report.csv
* Persistence Report.csv
* System Information Report.csv

## ARGUMENTS
* `src_location` — Source file location, such as `Y:\Case\Tag009\sample.E01`
* `dst_location` — Destination folder location. If nothing is supplied, then the default is `Results\`


## OPTIONS

* `-h` , `--help` — Show this help message and exit.
* `-p [parser]` , `--parser [parser]` — Choose parser to use. If nothing is chosen then `default` is used.
* `--hash` — Hash all the files as part of the processing of the image.
* `--max_cpu` — Use the same number of workers as cpu cores
* `--version` — Show version


## PARSER LIST

There are five available parsers for cdqr.py: `default`, `datt` , `win_all` , `win7` , and `winxp` and here is what they translate to for Plaso:
* **default**
  * Plaso v1.4
  ```
  appcompatcache,bagmru,binary_cookies,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,java_idx,mft,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msiecf,mstsc_rdp,mstsc_rdp_mru,opera_global,opera_typed_history,prefetch,recycle_bin,recycle_bin_info2,rplog,safari_history,symantec_scanlog,userassist,usnjrnl,windows_boot_execute,windows_boot_verify,windows_run,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winiis,winjob,winrar_mru,winreg,winreg_default
  ```
  * Plaso v1.3
  ```
  appcompatcache,bagmru,binary_cookies,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cookies,firefox_downloads,firefox_history,firefox_old_cache,google_drive,java_idx,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msie_zone_software,msiecf,mstsc_rdp,mstsc_rdp_mru,opera_global,opera_typed_history,prefetch,recycle_bin,recycle_bin_info2,rplog,symantec_scanlog,userassist,windows_boot_execute,windows_boot_verify,windows_run,windows_run_software,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winiis,winjob,winrar_mru,winreg,winreg_default
  ```
* **datt**
  * Plaso v1.4
  ```
  android_app_usage,asl_log,bencode,binary_cookies,bsm_log,chrome_cache,chrome_preferences,cups_ipp,custom_destinations,esedb,filestat,firefox_cache,firefox_cache2,java_idx,lnk,mac_appfirewall_log,mac_keychain,mac_securityd,mactime,macwifi,mcafee_protection,mft,msiecf,olecf,openxml,opera_global,opera_typed_history,pe,plist,pls_recall,popularity_contest,prefetch,recycle_bin,recycle_bin_info2,rplog,sccm,selinux,skydrive_log,skydrive_log_old,sqlite,symantec_scanlog,syslog,usnjrnl,utmp,utmpx,winevt,winevtx,winfirewall,winiis,winjob,winreg,xchatlog,xchatscrollback,bencode_transmission,bencode_utorrent,esedb_file_history,msie_webcache,olecf_automatic_destinations,olecf_default,olecf_document_summary,olecf_summary,airport,apple_id,ipod_device,macosx_bluetooth,macosx_install_history,macuser,maxos_software_update,plist_default,safari_history,spotlight,spotlight_volume,time_machine,android_calls,android_sms,appusage,chrome_cookies,chrome_extension_activity,chrome_history,firefox_cookies,firefox_downloads,firefox_history,google_drive,ls_quarantine,mac_document_versions,mackeeper_cache,skype,zeitgeist,appcompatcache,bagmru,ccleaner,explorer_mountpoints2,explorer_programscache,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,mstsc_rdp,mstsc_rdp_mru,userassist,windows_boot_execute,windows_boot_verify,windows_run,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winrar_mru,winreg_default
  ```
  * Plaso v1.3
  ```
  android_app_usage,asl_log,bencode,binary_cookies,bsm_log,chrome_cache,chrome_preferences,cups_ipp,custom_destinations,esedb,filestat,firefox_cache,firefox_old_cache,hachoir,java_idx,lnk,mac_appfirewall_log,mac_keychain,mac_securityd,mactime,macwifi,mcafee_protection,msiecf,olecf,openxml,opera_global,opera_typed_history,pcap,pe,plist,pls_recall,popularity_contest,prefetch,recycle_bin,recycle_bin_info2,rplog,selinux,skydrive_log,skydrive_log_error,sqlite,symantec_scanlog,syslog,utmp,utmpx,winevt,winevtx,winfirewall,winiis,winjob,winreg,xchatlog,xchatscrollback,bencode_transmission,bencode_utorrent,esedb_file_history,msie_webcache,olecf_automatic_destinations,olecf_default,olecf_document_summary,olecf_summary,airport,apple_id,ipod_device,macosx_bluetooth,macosx_install_history,macuser,maxos_software_update,plist_default,safari_history,spotlight,spotlight_volume,time_machine,android_calls,android_sms,appusage,chrome_cookies,chrome_extension_activity,chrome_history,firefox_cookies,firefox_downloads,firefox_history,google_drive,ls_quarantine,mac_document_versions,mackeeper_cache,skype,zeitgeist,appcompatcache,bagmru,ccleaner,explorer_mountpoints2,explorer_programscache,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msie_zone_software,mstsc_rdp,mstsc_rdp_mru,userassist,windows_boot_execute,windows_boot_verify,windows_run,windows_run_software,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winrar_mru,winreg_default
  ```
* **win_all**
```
win_gen,win7,winxp,webhist
```
* **win7**
```
win7,webhist
```
* **winxp**
```
winxp,webhist
```


## DEPENDENCIES

1. 64-bit Windows Operating System (a linux-friendly version is planned)
2. Depending on your preference, either:
  * Win 64-bit: [Plaso 1.3.0 (x64)](https://e366e647f8637dd31e0a13f75e5469341a9ab0ee.googledrive.com/host/0B30H7z4S52FleW5vUHBnblJfcjg/1.4.0/plaso-1.4.0-win-amd64-vs2010.zip) AND [Microsoft Visual C++ 2010 Redistributable Package (x64)](https://www.microsoft.com/en-us/download/details.aspx?id=14632), or
  * Win 32-bit: [Plaso 1.3.0 (x86)](https://e366e647f8637dd31e0a13f75e5469341a9ab0ee.googledrive.com/host/0B30H7z4S52FleW5vUHBnblJfcjg/1.4.0/plaso-1.4.0-win32-vs2008.zip) AND [Microsoft Visual C++ 2008 Redistributable Package (x86)](https://www.microsoft.com/en-us/download/details.aspx?id=29)
3. [Python v3.4](https://www.python.org/downloads/release/python-340/)

## EXAMPLES

```
cdqr.py c:\mydiskimage.vmdk myresults
```
```
cdqr.exe -p win_all c:\images\badlaptop.e01
```

## Linux Install
Run these commands to install lastest stable version of Plaso on Ubuntu
* Sudo add-apt-repository ppa:gift/stable
* sudo apt-get install python-plaso

## AUTHOR

* [Alan Orlikoski](https://github.com/rough007)