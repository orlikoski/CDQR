## NAME

CDQR v1.01 — Cold Disk Quick Response tool by Alan Orlikoski

## What's New
Fixes
* Fixed the "no name" output file issue when attempting to parse a mounted image  
* Provided option to use maximum number of CPU cores  
* Updated Scheduled Task report parser  

## Important Notes
* Make sure account has permissions to create files and directories when running cdqr.exe (when in doubt, run as administrator)

## SYNOPSIS

```
cdqr.py [-h] [-p parser] [--hash] src_location [dst_location]
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

## PARSER LIST

There are four available parsers for cdqr.py: `default` , `win_all` , `win7` , and `winxp` and here is what they translate to for Plaso:
* **default**
```
appcompatcache,bagmru,binary_cookies,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cookies,firefox_downloads,firefox_history,firefox_old_cache,google_drive,java_idx,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msie_zone_software,msiecf,mstsc_rdp,mstsc_rdp_mru,opera_global,opera_typed_history,prefetch,recycle_bin,recycle_bin_info2,rplog,symantec_scanlog,userassist,windows_boot_execute,windows_boot_verify,windows_run,windows_run_software,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winiis,winjob,winrar_mru,winreg,winreg_default
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
  * Win 64-bit: [Plaso 1.3.0 (x64)](https://e366e647f8637dd31e0a13f75e5469341a9ab0ee.googledrive.com/host/0B30H7z4S52FleW5vUHBnblJfcjg/1.3.0/plaso-1.3.0-win-amd64-vs2010.zip) AND [Microsoft Visual C++ 2010 Redistributable Package (x64)](https://www.microsoft.com/en-us/download/details.aspx?id=14632), or
  * Win 32-bit: [Plaso 1.3.0 (x86)](https://e366e647f8637dd31e0a13f75e5469341a9ab0ee.googledrive.com/host/0B30H7z4S52FleW5vUHBnblJfcjg/1.3.0/plaso-1.3.0-win32-vs2008.zip) AND [Microsoft Visual C++ 2008 Redistributable Package (x86)](https://www.microsoft.com/en-us/download/details.aspx?id=29)
3. [Python v3.4](https://www.python.org/downloads/release/python-340/)

## EXAMPLES

```
cdqr.py c:\mydiskimage.vmdk
```
```
cdqr.py -p win_all c:\images\badlaptop.e01
```

## AUTHOR

* [Alan Orlikoski](https://github.com/rough007)
