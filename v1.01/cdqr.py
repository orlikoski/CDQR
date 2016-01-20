#!python3
import os, sys, argparse, subprocess, csv, time, datetime, re, multiprocessing

###############################################################################
# Created by: Alan Orlikoski
# Version 1.01
#
# What's New
# 
# Fixes
# 1.) Fixed the "no name" issue when attempting to parse a mounted image
# 2.) Provided option to use maximum number of CPU cores
# 3.) Updated Scheduled Task report parser
#
# DEPENDANCIES: 
# 1.) Plaso v1.3 static binaries from:
#		Option 1: Plaso for 64-bit MS Visual C++ disto 2010 (https://e366e647f8637dd31e0a13f75e5469341a9ab0ee.googledrive.com/host/0B30H7z4S52FleW5vUHBnblJfcjg/1.3.0/plaso-1.3.0-win-amd64-vs2010.zip)
#		Option 2: Plaso for 32-bit MS Visual C++ disto 2008 (https://e366e647f8637dd31e0a13f75e5469341a9ab0ee.googledrive.com/host/0B30H7z4S52FleW5vUHBnblJfcjg/1.3.0/plaso-1.3.0-win32-vs2008.zip)
# 2.) Correct (see above) MS Visual C++ package installed: https://www.microsoft.com/en-us/search/Results.aspx?q=Microsoft%20Visual%20C%2B%2B%20Redistributable%20Package&form=DLC
# 3.) Python v3.4 (https://www.python.org/downloads/release/python-340/)
# 4.) Currently built to run on Windows 64-bit OS only (linux friendly version is planned)
###############################################################################

# Plaso Program Locations (this can be customized for your environment)
log2timeline_location = r"plaso\log2timeline.exe"
psort_location = r"plaso\psort.exe"

# Global Variables
parser_opt = ""
src_loc = ""
dst_loc = ""
start_dt = datetime.datetime.now()
end_dt = datetime.datetime.now()
duration = datetime.datetime.now()

# Dictionary of parsing options from command line to log2timeline
parse_options = {
	'default' : "appcompatcache,bagmru,binary_cookies,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cookies,firefox_downloads,firefox_history,firefox_old_cache,google_drive,java_idx,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msie_zone_software,msiecf,mstsc_rdp,mstsc_rdp_mru,opera_global,opera_typed_history,prefetch,recycle_bin,recycle_bin_info2,rplog,symantec_scanlog,userassist,windows_boot_execute,windows_boot_verify,windows_run,windows_run_software,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winiis,winjob,winrar_mru,winreg,winreg_default",
	'win_all' : "win_gen,win7,winxp,webhist",
	'win7' : "win7,webhist",
	'winxp' : "winxp,webhist",
}

# Ask a yes/no question via input() and return their answer.
def query_file_location(filename):
	# This prompts user for a file location and confirms it exists before returning
	# It returns a valided file location

	while True:
		sys.stdout.write("Please enter valid location for "+filename+": ")
		choice = input()
		if os.path.isfile(choice):
			if choice.endswith(filename):
				return choice



# Ask a yes/no question via input() and return their answer.
def query_yes_no(question, default="yes"):
	# """Ask a yes/no question via input() and return their answer.
	# "question" is a string that is presented to the user.
	# "default" is the presumed answer if the user just hits <Enter>.
	# 	It must be "yes" (the default), "no" or None (meaning
	# 	an answer is required of the user).

	# The "answer" return value is True for "yes" or False for "no".
	# """
	valid = {"yes": True, "y": True, "ye": True,
			 "no": False, "n": False}
	if default is None:
		prompt = " [y/n] "
	elif default == "yes":
		prompt = " [Y/n] "
	elif default == "no":
		prompt = " [y/N] "
	else:
		raise ValueError("invalid default answer: '%s'" % default)

	while True:
		sys.stdout.write(question + prompt)
		choice = input().lower()
		if default is not None and choice == '':
			return valid[default]
		elif choice in valid:
			return valid[choice]
		else:
			sys.stdout.write("Please respond with 'yes' or 'no' "
							 "(or 'y' or 'n').\n")

# Run Log2timeline against a data source
def img_process(my_command):
	myproc = subprocess.Popen(my_command,stdout=mylogfile,stderr=mylogfile)
	counter = 1
	while myproc.poll() is None:
		if counter%2 == 0:
			sys.stdout.write("| Still working...\r")
		else:
			sys.stdout.write("- Still working...\r")
		sys.stdout.flush()
		counter+=1
		time.sleep(1)
	if myproc.returncode == 1:
		print("\nERROR: Something went wrong with log2timeline.exe.  Check "+logfilename+" for details.")
		timingfile.close()
		mylogfile.close()
		sys.exit(1)

# Run psort against plaso db file to output a file in log2timeline format
def create_SuperTimeline(my_command):
	subprocess.call(my_command,stdout=mylogfile,stderr=mylogfile)


def create_reports(dst_loc, csv_file):
	# 7 Reports: Event Logs, File System, Internet History, Prefetch, Registry, Scheduled Tasks, Persistence

	# Create report directory and file names
	rpt_dir_name = dst_loc+"\\Reports"
	rpt_evt_name = rpt_dir_name+"\\Event Log Report.csv"
	rpt_fs_name = rpt_dir_name+"\\File System Report.csv"
	rpt_ih_name = rpt_dir_name+"\\Internet History Report.csv"
	rpt_pf_name = rpt_dir_name+"\\Prefetch Report.csv"
	rpt_reg_name = rpt_dir_name+"\\Registry Report.csv"
	rpt_st_name = rpt_dir_name+"\\Scheduled Tasks Report.csv"
	rpt_per_name = rpt_dir_name+"\\Persistence Report.csv"
	rpt_si_name = rpt_dir_name+"\\System Information Report.csv"

	# Create search strings for each report
	rpt_evt_search = re.compile(r',EVT')
	rpt_fs_search = re.compile(r',FILE|,RECBIN')
	rpt_ih_search = re.compile(r',WEBHIST|windows_typed_urls|chrome_cache|chrome_cookies|chrome_history|firefox_cache|firefox_history|firefox_cookies')
	rpt_pf_search = re.compile(r',prefetch')
	rpt_reg_search = re.compile(r',REG,')
	rpt_st_search = re.compile(r',winjob,|Microsoft-Windows-TaskScheduler')
	rpt_per_search = re.compile(r'appcompatcache|bagmru|shell_item|windows_run|windows_services|windows_task_cache|bagmru|mrulistex_string|mrulist_string|windows_run_software|windows_boot_execute')
	rpt_si_search = re.compile(r'windows_version|windows_sam_users|windows_timezone|Microsoft-Windows-NetworkProfile Computer Name')

	# Create a list of the report names
	lor = [rpt_evt_name,rpt_fs_name,rpt_ih_name,rpt_pf_name,rpt_reg_name,rpt_st_name,rpt_per_name,rpt_si_name]

	# Create Report directory
	if not os.path.isdir(rpt_dir_name):
		os.makedirs(rpt_dir_name)

	# Check if files exist, if so delete them)
	for rpt_name in lor:
		if os.path.isfile(rpt_name):
			os.remove(rpt_name)

	# Open all files for writing
	rpt_evt = open(rpt_evt_name,'w', encoding='utf-8')
	rpt_fs = open(rpt_fs_name,'w', encoding='utf-8')
	rpt_ih = open(rpt_ih_name,'w', encoding='utf-8')
	rpt_pf = open(rpt_pf_name,'w', encoding='utf-8')
	rpt_reg = open(rpt_reg_name,'w', encoding='utf-8')
	rpt_st = open(rpt_st_name,'w', encoding='utf-8')
	rpt_per = open(rpt_per_name,'w', encoding='utf-8')
	rpt_si = open(rpt_si_name,'w', encoding='utf-8')

	# Create list of file handles + search terms
	lofh = [[rpt_evt_search,rpt_evt],[rpt_fs_search,rpt_fs],[rpt_ih_search,rpt_ih],[rpt_pf_search,rpt_pf],[rpt_reg_search,rpt_reg],[rpt_st_search,rpt_st],[rpt_per_search,rpt_per],[rpt_si_search,rpt_si]]

	# Write the header line in each report file
	for item in lofh:
		item[1].write("date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra\n")

	if not os.path.isfile(csv_file):
		print("File not found", csv_file)
		sys.exit(1)

	# Run each search for each report (sequential) and write the results to the report CSV files
	for line in open(csv_file,'r', encoding='utf-8', errors='ignore'):
		#print(line)
		for terms in lofh:
			if terms[0].search(line,re.I):
				terms[1].write(line)
		#sys.exit(1)
	# Close all report files
	for item in lofh:
		item[1].close()
	# Print report created messages
	for item in lor:
		print("Report Created:", item)

# Parsing begins
parser_list = list(parse_options.keys())#["default","win_gen","win7","winxp","linux","android","macosx","test"]

parser = argparse.ArgumentParser(description='Cold Disk Quick Response Tool (CDQR) version 1.01')
parser.add_argument('src_location',nargs=1,help='Source File location: Y:\\Case\\Tag009\\sample.E01')
parser.add_argument('dst_location',nargs='?',default='Results',help='Destination Folder location. If nothing is supplied then the default is \'Results\'')
parser.add_argument('-p','--parser', nargs='?',help='Choose parser to use.  If nothing chosen then \'default\' is used.  Option are: '+', '.join(parse_options))
parser.add_argument('--hash', action='store_true', default=False, help='Hash all the files as part of the processing of the image')
parser.add_argument('--max_cpu', action='store_true', default=False, help='Use the maximum number of cpu cores to process the image')


args=parser.parse_args()

# Parsing the input from the command line and building log2timeline command
# Default log2timeline command
command1 = [log2timeline_location,"-p","--partition","all","--vss_stores","all"]

if args:
# Set log2timeline parsing option(s)
	if args.parser:
		if args.parser not in parser_list:
			print("ERROR: \""+args.parser+ "\" is not a valid parser selection.")
			print("ERROR: Valid parser options are:",', '.join(parser_list))
			print("ERROR: Please verify your command and try again.")
			print("Exiting...")
			sys.exit(1)
		parser_opt = args.parser
	else:
		parser_opt = "default"
	# add parsing options to the command
	command1.append("--parsers")
	command1.append(parse_options[parser_opt])
	print("Using parser:",parser_opt)
	#print("Parser options:",parse_options[parser_opt])

# Set Hashing variable
	if args.hash:
		command1.append("--hashers")
		command1.append("md5")

# Set Number of CPU cores to use
	if args.max_cpu:
		num_cpus = multiprocessing.cpu_count()
		print("Warning: exceeding Plaso recommendations on cpu usage")
	else:
		num_cpus = multiprocessing.cpu_count() -3
		if num_cpus <= 0:
			num_cpus = 1
	command1.append("--workers")
	command1.append(str(num_cpus))
	print("Number of cpu cores to use:",num_cpus)


# Set source location/file
	if not os.path.exists(args.src_location[0]):
		print("ERROR: \""+args.src_location[0]+"\" cannot be found by the system.  Please verify command.")
		print("Exiting...")
		sys.exit(1)
	src_loc = args.src_location[0]
	print("Source data: ",src_loc)

	# Validate log2timeline.exe and psort.exe locations
	if not os.path.isfile(log2timeline_location):
		print("Error: file not found:", log2timeline_location)
		log2timeline_location = query_file_location("log2timeline.exe")

		if not os.path.isfile(psort_location):
			print("Error: file not found:", psort_location)
			psort_location = query_file_location("psort.exe")


# Set source location/file
	dst_loc = args.dst_location.strip('\\')+"_"+datetime.datetime.now().strftime("%d-%b-%y_%H-%M-%S")
	if not os.path.exists(dst_loc):
		os.mkdir(dst_loc)

	print("Destination Folder: ",dst_loc)

# Create DB Filename

db_file = dst_loc+"\\"+src_loc.split('\\')[-1]+".db"
if db_file == dst_loc+"\\.db":
	db_file = dst_loc+"\\"+"mounted_image.db"
print("Database File: ", db_file)

# Create SuperTimeline filename
csv_file = dst_loc+"\\"+src_loc.split('\\')[-1]+".SuperTimeline.csv"
if csv_file == dst_loc+"\\.SuperTimeline.csv":
	csv_file = dst_loc+"\\"+"mounted_image.SuperTimeline.csv"
print("SuperTimeline CSV File: ", csv_file)

# Finalize the log2timeline command with DB file and source data file location
command1.append(db_file)
command1.append(src_loc)

#  Create space in output
print("\n")

# Open Log Files
logfilename = dst_loc+"\\"+src_loc.split('\\')[-1]+".log"
if logfilename == dst_loc+"\\.log":
	logfilename = dst_loc+"\\"+"mounted_image.log"

if os.path.isfile(logfilename):
	os.remove(logfilename)


timingfile_name = dst_loc+"\\"+src_loc.split('\\')[-1]+".timing.log"
if timingfile_name == dst_loc+"\\.timing.log":
	timingfile_name = dst_loc+"\\"+"mounted_image.timing.log"

timingfile = open(timingfile_name,'w')


timingfile.write("Processing started at: "+str(start_dt)+"\n")
print("Processing started at: "+str(start_dt))

mylogfile = open(logfilename,'w')

# Check if the database and supertimeline files already exists and delete them if they do
if os.path.isfile(db_file):
	os.remove(db_file)
if os.path.isfile(csv_file):
	os.remove(csv_file)


##################  EXECTUTION SECTION ############################
# build commands to send
print("\""+"\" \"".join(command1)+"\"")
command2 = [psort_location,"-o","l2tcsv",db_file,"-w",csv_file]

# Process image with log2timeline
print("Parsing image")
img_process(command1)

end_dt = datetime.datetime.now()
duration01 = end_dt - start_dt
print("Parsing ended at: "+str(end_dt))
timingfile.write("Parsing ended at: "+str(end_dt)+"\n")
print("Parsing duration was: "+str(duration01))
timingfile.write("Parsing duration was: "+str(duration01)+"\n")

# Creating Reports
# Create SuperTimeline
start_dt = datetime.datetime.now()
print("\nCreating the SuperTimeline CSV file")
print("\""+"\" \"".join(command2)+"\"")
create_SuperTimeline(command2)
print("SuperTimeline CSV file is created")

# Create individual reports
print("\nCreating the individual reports")
create_reports(dst_loc,csv_file)





print("All reporting complete")
# Closing log file
end_dt = datetime.datetime.now()
duration02 = end_dt - start_dt
print("Reporting ended at: "+str(end_dt))
print("Reporting  duration was: "+str(duration02))
print("Total  duration was: "+str(duration01+duration02))
timingfile.write("Processing/reporting ended at: "+str(end_dt)+"\n")
timingfile.write("Reporting duration was: "+str(duration02)+"\n")
timingfile.write("Total duration was: "+str(duration01+duration02)+"\n")
timingfile.close()
mylogfile.close()
