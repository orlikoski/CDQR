CDQR v1.0
Cold Disk Quick Response tool  
Created by: Alan Orlikoski  

DEPENDANCIES:  
1.) Plaso v1.3 static binaries from:  
	Option 1: Plaso for 64-bit MS Visual C++ disto 2010 (https://e366e647f8637dd31e0a13f75e5469341a9ab0ee.googledrive.com/host/0B30H7z4S52FleW5vUHBnblJfcjg/1.3.0/plaso-1.3.0-win-amd64-vs2010.zip)  
	Option 2: Plaso for 32-bit MS Visual C++ disto 2008 (https://e366e647f8637dd31e0a13f75e5469341a9ab0ee.googledrive.com/host/0B30H7z4S52FleW5vUHBnblJfcjg/1.3.0/plaso-1.3.0-win32-vs2008.zip)  
2.) Correct (see above) MS Visual C++ package installed: https://www.microsoft.com/en-us/search/Results.aspx?q=Microsoft%20Visual%20C%2B%2B%20Redistributable%20Package&form=DLC  
3.) Python v3.4 (https://www.python.org/downloads/release/python-340/)  
4.) Currently built to run on Windows 64-bit OS only (linux friendly version is planned)  



WHAT IT DOES:  
This program uses Plaso (https://github.com/log2timeline/plaso/wiki) and a streamlined list of parsers to quickly analyze a forenisic image file (dd, E01, .vmdk, etc) and output nine reports.  

This program uses Plaso to parse the data and generate a report in log2timeline format.  I built it to use my experience in choosing which parsers are best for a quick look to see if there is anything bad on the box.  It then parses the supertimeline report into easily readable sub-reports based on the output from the various Plaso parsers used.  It is meant to be a starting off point used to determine if a deeper inspection is required.  

These reports made by this tool are listed below:  
    \<Source File Name\>.SuperTimeLine.csv  
    Event Log Report.csv  
    File System Report.csv  
    Internet History Report.csv  
    Prefetch Report.csv  
    Registry Report.csv  
    Scheduled Tasks Report.csv  
    Persistence Report.csv  
    System Information Report.csv  


HOW TO USE IT:  
usage: cdqr.py [-h] [-p [PARSER]] [--hash] src_location [dst_location]  
example: cdqr.py c:\mydiskimage.vmdk  

Cold Disk Quick Response Tool (CDLR)  

positional arguments:  
  src_location          Source File location: Y:\Case\Tag009\sample.E01  
  dst_location          Destination Folder location. If nothing is supplied  
                        then the default is 'Results'  

optional arguments:  
  -h, --help            show this help message and exit  
  -p [PARSER], --parser [PARSER]  
                        Choose parser to use. If nothing chosen then 'default'  
                        is used. Option are: default, winxp, win_all, win7  
  --hash                Hash all the files as part of the processing of the  
                        image  

PARSER LIST:  
Here is the list of parsers and what they translate to for Plaso  
    'default'  
        "appcompatcache,bagmru,binary_cookies,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cookies,firefox_downloads,firefox_history,firefox_old_cache,google_drive,java_idx,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msie_zone_software,msiecf,mstsc_rdp,mstsc_rdp_mru,opera_global,opera_typed_history,prefetch,recycle_bin,recycle_bin_info2,rplog,symantec_scanlog,userassist,windows_boot_execute,windows_boot_verify,windows_run,windows_run_software,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winiis,winjob,winrar_mru,winreg,winreg_default"
    'win_all'  
        "win_gen,win7,winxp,webhist"
    'win7'  
        "win7,webhist"
    'winxp'  
        "winxp,webhist"

