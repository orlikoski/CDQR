## NAME

CDQR — Cold Disk Quick Response tool by Alan Orlikoski

## What is CDQR?
The CDQR tool uses Plaso to parse disk images with specific parsers and create easy to analyze custom reports. The parsers were chosen based triaging best practices and the custom reports group like items together to make analysis easier. The design came from the Live Response Model of investigating the important artifacts first. This is meant to be a starting point for investigations, not the complete investigation.

In addition to processing entire forensic images it also parses extracted forensic artifact(s) as an individual file or collection of files inside of a folder structure (or inside a .zip file).

It creates up to 16 Reports (.csv files) based on triaging best practices and the parsing option selected
*  16 Reports for DATT:  
      ```
      Appcompat, Login, Event Logs, File System, MFT, UsnJrnl, Internet History, Prefetch, Registry, Scheduled Tasks, Persistence, System Information, AntiVirus, Firewall, Mac, and Linux
      ```
*  14 Reports for Win:  
      ```
      Appcompat, Login, Event Logs, File System, MFT, UsnJrnl, Internet History, Prefetch, Registry, Scheduled Tasks, Persistence, System Information, AntiVirus, Firewall
      ```
*   8 Reports for Mac and Lin:  
      ```
      Login, File System, Internet History, System Information, AntiVirus, Firewall, Mac, and Linux
      ```

## What's New
*  Supports Plaso 1.5.x!!
*  "Login" Report that incorporates login information for Windows and Linux
*  "Appcompat" Report that seperates the Appcompat results into a dedicated report
*  Improved report format for appcompat, event log, file system, mft, prefetch, and scheduled tasks reports
    *   Easier to read
    *   More pivot points
    *   Allows additional sorting options (looking at you Appcompat entry order)
*  ElasticSearch output mode supported
*  Supports .zip file source input detection and handling
*  Python version works on Windows, Linux and Mac
*  Improvements to support the [CCF-VM](https://github.com/rough007/CCF-VM) release 
*  NOTE: Ensure line endings are correct for the OS it is running on

## Important Notes
* Make sure account has permissions to create files and directories when running (when in doubt, run as administrator)

## SYNOPSIS

Windows 64-bit binary or Python 3.x
```
cdqr.[exe|py] [-h] [-p [PARSER]] [--nohash] [--max_cpu] [--export]
                [--es [ES]] [-z] [-v]
                src_location [dst_location]
```

## DESCRIPTION

This program uses [Plaso](https://github.com/log2timeline/plaso/wiki) and a streamlined list of its parsers to quickly analyze a forenisic image file (dd, E01, .vmdk, etc) or group of forensic artifacts.  The results are output in either ElasticSearch, JSON (line delimited), or the following report files in CSV format:
*  16 Reports for DATT:  
      ```
      Appcompat, Login, Event Logs, File System, MFT, UsnJrnl, Internet History, Prefetch, Registry, Scheduled Tasks, Persistence, System Information, AntiVirus, Firewall, Mac, and Linux
      ```
*  14 Reports for Win:  
      ```
      Appcompat, Login, Event Logs, File System, MFT, UsnJrnl, Internet History, Prefetch, Registry, Scheduled Tasks, Persistence, System Information, AntiVirus, Firewall
      ```
*   8 Reports for Mac and Lin:  
      ```
      Login, File System, Internet History, System Information, AntiVirus, Firewall, Mac, and Linux
      ```

## ARGUMENTS
* `src_location` — Source file location, such as `Y:\Case\Tag009\sample.E01`, `E:\Artifacts_folder\` or `E:\Artifacts_folder\mylogs.evtx` or `E:\Artifacts_folder\mylogs.zip`
* `dst_location` — Destination folder location. If nothing is supplied, then the default is `Results\`


## OPTIONS

* `-h` , `--help` — Show this help message and exit.
* `-p [parser]` , `--parser [parser]` — Choose parser to use. If nothing is chosen then `win` is used.
* `--nohash` — Do not hash all the files as part of the processing of the image.
* `--max_cpu` — Use the same number of workers as cpu cores
* `--export` — Creates gzipped, line delimited json export file
* `--es [ES]` — Outputs to elasticsearch database (Default is to localhost)
* `-z` — Indicates the input file is a zip file and needs to be decompressed
* `-v : --version` — Show version


## PARSER LIST

There are four available parsers for CDQR: `datt` , `win` , `lin` , and `mac` and here the Plaso parsers they represent:
* **win**
  * Plaso v1.5.x
  ```
    appcompatcache,bagmru,binary_cookies,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,java_idx,mcafee_protection,mft,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msiecf,mstsc_rdp,mstsc_rdp_mru,network_drives,opera_global,opera_typed_history,prefetch,recycle_bin,recycle_bin_info2,rplog,safari_history,symantec_scanlog,userassist,usnjrnl,windows_boot_execute,windows_boot_verify,windows_run,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winjob,winlogon,winrar_mru,winreg,winreg_default
  ```
  * Plaso v1.4
  ```
  appcompatcache,bagmru,binary_cookies,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,java_idx,mcafee_protection,mft,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msiecf,mstsc_rdp,mstsc_rdp_mru,opera_global,opera_typed_history,prefetch,recycle_bin,recycle_bin_info2,rplog,safari_history,symantec_scanlog,userassist,usnjrnl,windows_boot_execute,windows_boot_verify,windows_run,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winjob,winrar_mru,winreg,winreg_default
  ```
  * Plaso v1.3
  ```
  appcompatcache,bagmru,binary_cookies,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cookies,firefox_downloads,firefox_history,firefox_old_cache,google_drive,java_idx,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msie_zone_software,msiecf,mstsc_rdp,mstsc_rdp_mru,opera_global,opera_typed_history,prefetch,recycle_bin,recycle_bin_info2,rplog,symantec_scanlog,userassist,windows_boot_execute,windows_boot_verify,windows_run,windows_run_software,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winiis,winjob,winrar_mru,winreg,winreg_default
  ```
* **datt**
  * Plaso v1.5.x
  ```
    airport,android_app_usage,android_calls,android_sms,appcompatcache,apple_id,appusage,asl_log,bagmru,bencode,bencode_transmission,bencode_utorrent,binary_cookies,bsm_log,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,cron,cups_ipp,custom_destinations,dockerjson,dpkg,esedb,esedb_file_history,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,imessage,ipod_device,java_idx,kik_messenger,lnk,ls_quarantine,mac_appfirewall_log,mac_document_versions,mac_keychain,mac_securityd,mackeeper_cache,macosx_bluetooth,macosx_install_history,mactime,macuser,macwifi,maxos_software_update,mcafee_protection,mft,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_webcache,msie_zone,msiecf,mstsc_rdp,mstsc_rdp_mru,network_drives,olecf,olecf_automatic_destinations,olecf_default,olecf_document_summary,olecf_summary,openxml,opera_global,opera_typed_history,pe,plist,plist_default,pls_recall,popularity_contest,prefetch,recycle_bin,recycle_bin_info2,rplog,safari_history,sccm,selinux,skydrive_log,skydrive_log_old,skype,spotlight,spotlight_volume,sqlite,ssh,symantec_scanlog,syslog,time_machine,twitter_ios,userassist,usnjrnl,utmp,utmpx,windows_boot_execute,windows_boot_verify,windows_run,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winiis,winjob,winlogon,winrar_mru,winreg,winreg_default,xchatlog,xchatscrollback,zeitgeist,zsh_extended_history
  ```
  * Plaso v1.4
  ```
  airport,android_app_usage,android_calls,android_sms,appcompatcache,apple_id,appusage,asl_log,bagmru,bencode,bencode_transmission,bencode_utorrent,binary_cookies,bsm_log,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,cups_ipp,custom_destinations,esedb,esedb_file_history,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,ipod_device,java_idx,lnk,ls_quarantine,mac_appfirewall_log,mac_document_versions,mac_keychain,mac_securityd,mackeeper_cache,macosx_bluetooth,macosx_install_history,mactime,macuser,macwifi,maxos_software_update,mcafee_protection,mft,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_webcache,msie_zone,msiecf,mstsc_rdp,mstsc_rdp_mru,olecf,olecf_automatic_destinations,olecf_default,olecf_document_summary,olecf_summary,openxml,opera_global,opera_typed_history,pe,plist,plist_default,pls_recall,popularity_contest,prefetch,recycle_bin,recycle_bin_info2,rplog,safari_history,sccm,selinux,skydrive_log,skydrive_log_old,skype,spotlight,spotlight_volume,sqlite,symantec_scanlog,syslog,time_machine,userassist,usnjrnl,utmp,utmpx,windows_boot_execute,windows_boot_verify,windows_run,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winiis,winjob,winrar_mru,winreg,winreg_default,xchatlog,xchatscrollback,zeitgeist
  ```
  * Plaso v1.3
  ```
  android_app_usage,asl_log,bencode,binary_cookies,bsm_log,chrome_cache,chrome_preferences,cups_ipp,custom_destinations,esedb,filestat,firefox_cache,firefox_old_cache,hachoir,java_idx,lnk,mac_appfirewall_log,mac_keychain,mac_securityd,mactime,macwifi,mcafee_protection,msiecf,olecf,openxml,opera_global,opera_typed_history,pcap,pe,plist,pls_recall,popularity_contest,prefetch,recycle_bin,recycle_bin_info2,rplog,selinux,skydrive_log,skydrive_log_error,sqlite,symantec_scanlog,syslog,utmp,utmpx,winevt,winevtx,winfirewall,winiis,winjob,winreg,xchatlog,xchatscrollback,bencode_transmission,bencode_utorrent,esedb_file_history,msie_webcache,olecf_automatic_destinations,olecf_default,olecf_document_summary,olecf_summary,airport,apple_id,ipod_device,macosx_bluetooth,macosx_install_history,macuser,maxos_software_update,plist_default,safari_history,spotlight,spotlight_volume,time_machine,android_calls,android_sms,appusage,chrome_cookies,chrome_extension_activity,chrome_history,firefox_cookies,firefox_downloads,firefox_history,google_drive,ls_quarantine,mac_document_versions,mackeeper_cache,skype,zeitgeist,appcompatcache,bagmru,ccleaner,explorer_mountpoints2,explorer_programscache,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msie_zone_software,mstsc_rdp,mstsc_rdp_mru,userassist,windows_boot_execute,windows_boot_verify,windows_run,windows_run_software,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winrar_mru,winreg_default
  ```
* **mac**
  * Plaso v1.5
  ```
  airport,apple_id,appusage,binary_cookies,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,cron,dockerjson,dpkg,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,imessage,ipod_device,java_idx,mac_appfirewall_log,mac_keychain,mac_securityd,mackeeper_cache,macosx_bluetooth,macosx_install_history,mactime,macuser,maxos_software_update,mcafee_protection,opera_global,opera_typed_history,plist,plist_default,popularity_contest,safari_history,spotlight,spotlight_volume,ssh,symantec_scanlog,time_machine,utmp,utmpx,zsh_extended_history
  ```
  * Plaso v1.4
  ```
  binary_cookies,bsm_log,chrome_cache,chrome_preferences,filestat,firefox_cache,firefox_cache2,java_idx,mac_appfirewall_log,mac_keychain,mac_securityd,mactime,mcafee_protection,opera_global,opera_typed_history,plist,popularity_contest,selinux,utmp,utmpx,airport,apple_id,macosx_install_history,plist_default,spotlight,spotlight_volume,time_machine,appusage,chrome_cookies,chrome_extension_activity,chrome_history,firefox_cookies,firefox_downloads,firefox_history,google_drive,ls_quarantine,mackeeper_cache
  ```
  * Plaso v1.3  
  ```
  macosx
  ```
* **lin**
  * Plaso v1.5.x
  ```
  binary_cookies,bsm_log,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,cron,dockerjson,dpkg,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,imessage,java_idx,mac_appfirewall_log,mcafee_protection,opera_global,opera_typed_history,popularity_contest,safari_history,selinux,ssh,symantec_scanlog,utmp,utmpx,zsh_extended_history
  ```
  * Plaso v1.4
  ```
  airport,apple_id,appusage,binary_cookies,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,ipod_device,java_idx,mac_appfirewall_log,mac_keychain,mac_securityd,mackeeper_cache,macosx_bluetooth,macosx_install_history,mactime,macuser,maxos_software_update,mcafee_protection,opera_global,opera_typed_history,plist,plist_default,popularity_contest,safari_history,spotlight,spotlight_volume,symantec_scanlog,time_machine,utmp,utmpx
  ```
  * Plaso v1.3  
  ```
  linux
  ```

## DEPENDENCIES

1. 64-bit Windows, Linux, or Mac Operating System 
2. Depending on your preference, either:
  * Win 64-bit: [Plaso 1.5.x (x64)](https://github.com/log2timeline/plaso/releases) AND [Microsoft Visual C++ 2010 Redistributable Package (x64)](https://www.microsoft.com/en-us/download/details.aspx?id=14632), or
  * Win 32-bit: [Plaso 1.5.x (x86)](https://github.com/log2timeline/plaso/releases) AND [Microsoft Visual C++ 2008 Redistributable Package (x86)](https://www.microsoft.com/en-us/download/details.aspx?id=29)
3. [Python v3.x](https://www.python.org/downloads/) (if using cdqr.py source code)

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
```
cdqr.exe -z --max_cpu C:\artifacts\tag009\artifacts.zip
```
```
cdqr.exe -z --max_cpu C:\artifacts\tag009\artifacts.zip --es myindexname
```

## Plaso Installation Guides
1. From Plaso's site [Windows Installation Guide](https://github.com/log2timeline/plaso/wiki/Windows-Packaged-Release)
2. From Plaso's site [Ubuntu and SIFT Installation Guide](https://github.com/log2timeline/plaso/wiki/Ubuntu-Packaged-Release)
3. From Plaso's site [Mac OS X Installation Guide](https://github.com/log2timeline/plaso/wiki/Development-release-Mac-OS-X)

## AUTHOR

Alan Orlikoski
* [GitHub](https://github.com/rough007)
* [Twitter](https://twitter.com/AlanOrlikoski)