# CDLR v1.0
Cold Disk Quick Response tool

DEPENDANCIES: 
1.) Plaso v1.3 static binaries from:
	Option 1: Plaso for 64-bit MS Visual C++ disto 2010 (https://e366e647f8637dd31e0a13f75e5469341a9ab0ee.googledrive.com/host/0B30H7z4S52FleW5vUHBnblJfcjg/1.3.0/plaso-1.3.0-win-amd64-vs2010.zip)
	Option 2: Plaso for 32-bit MS Visual C++ disto 2008 (https://e366e647f8637dd31e0a13f75e5469341a9ab0ee.googledrive.com/host/0B30H7z4S52FleW5vUHBnblJfcjg/1.3.0/plaso-1.3.0-win32-vs2008.zip)
2.) Correct (see above) MS Visual C++ package installed: https://www.microsoft.com/en-us/search/Results.aspx?q=Microsoft%20Visual%20C%2B%2B%20Redistributable%20Package&form=DLC
3.) Python v3.4 (https://www.python.org/downloads/release/python-340/)
4.) Currently built to run on Windows 64-bit OS only (linux friendly version is planned)



WHAT IT DOES:
This program uses Plaso (https://github.com/log2timeline/plaso/wiki) and a streamlined list of parsers to quickly analyze a forenisic image file (dd, E01, .vmdk, etc) and output nine reports.  

These reports are listed below:
	<Source File Name>.SuperTimeLine.csv
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

Created by: Alan Orlikoski