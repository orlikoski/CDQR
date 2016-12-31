#!/usr/bin/python3
import io, os, sys, argparse, subprocess, csv, time, datetime, re, multiprocessing, gzip, shutil, zipfile
###############################################################################
# Created by: Alan Orlikoski
cdqr_version = "CDQR Version: 3.0"
#
###############################################################################

# Default Parser option
default_parser = "win"


# Plaso Program Locations (default)
if sys.platform[0:3] == "win":
    log2timeline_location = r"plaso\log2timeline.exe"
    psort_location = r"plaso\psort.exe"
else:
    log2timeline_location = r"log2timeline.py"
    psort_location = r"psort.py"

# Global Variables
parser_opt = ""
src_loc = ""
dst_loc = ""
start_dt = datetime.datetime.now()
end_dt = start_dt
duration = end_dt - start_dt
duration01 = end_dt - start_dt
duration02 = end_dt - start_dt
duration03 = end_dt - start_dt
create_db = True
create_st = True
global_es_index = "case_cdqr-"
unzipped_file = False

# Compatible Plaso versions
p_compat = ["1.3","1.4","1.5"]

# Dictionary of parsing options from command line to log2timeline
parse_options15 = {
    'win' : "appcompatcache,bagmru,binary_cookies,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,java_idx,mcafee_protection,mft,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msiecf,mstsc_rdp,mstsc_rdp_mru,network_drives,opera_global,opera_typed_history,prefetch,recycle_bin,recycle_bin_info2,rplog,safari_history,symantec_scanlog,userassist,usnjrnl,windows_boot_execute,windows_boot_verify,windows_run,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winjob,winlogon,winrar_mru,winreg,winreg_default",
    'lin' : "binary_cookies,bsm_log,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,cron,dockerjson,dpkg,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,imessage,java_idx,mac_appfirewall_log,mcafee_protection,opera_global,opera_typed_history,popularity_contest,safari_history,selinux,ssh,symantec_scanlog,utmp,utmpx,zsh_extended_history",
    'mac' : "airport,apple_id,appusage,binary_cookies,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,cron,dockerjson,dpkg,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,imessage,ipod_device,java_idx,mac_appfirewall_log,mac_keychain,mac_securityd,mackeeper_cache,macosx_bluetooth,macosx_install_history,mactime,macuser,maxos_software_update,mcafee_protection,opera_global,opera_typed_history,plist,plist_default,popularity_contest,safari_history,spotlight,spotlight_volume,ssh,symantec_scanlog,time_machine,utmp,utmpx,zsh_extended_history",
    'datt' : "airport,android_app_usage,android_calls,android_sms,appcompatcache,apple_id,appusage,asl_log,bagmru,bencode,bencode_transmission,bencode_utorrent,binary_cookies,bsm_log,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,cron,cups_ipp,custom_destinations,dockerjson,dpkg,esedb,esedb_file_history,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,imessage,ipod_device,java_idx,kik_messenger,lnk,ls_quarantine,mac_appfirewall_log,mac_document_versions,mac_keychain,mac_securityd,mackeeper_cache,macosx_bluetooth,macosx_install_history,mactime,macuser,macwifi,maxos_software_update,mcafee_protection,mft,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_webcache,msie_zone,msiecf,mstsc_rdp,mstsc_rdp_mru,network_drives,olecf,olecf_automatic_destinations,olecf_default,olecf_document_summary,olecf_summary,openxml,opera_global,opera_typed_history,pe,plist,plist_default,pls_recall,popularity_contest,prefetch,recycle_bin,recycle_bin_info2,rplog,safari_history,sccm,selinux,skydrive_log,skydrive_log_old,skype,spotlight,spotlight_volume,sqlite,ssh,symantec_scanlog,syslog,time_machine,twitter_ios,userassist,usnjrnl,utmp,utmpx,windows_boot_execute,windows_boot_verify,windows_run,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winiis,winjob,winlogon,winrar_mru,winreg,winreg_default,xchatlog,xchatscrollback,zeitgeist,zsh_extended_history",
}

parse_options14 = {
    'win' : "appcompatcache,bagmru,binary_cookies,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,java_idx,mcafee_protection,mft,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msiecf,mstsc_rdp,mstsc_rdp_mru,opera_global,opera_typed_history,prefetch,recycle_bin,recycle_bin_info2,rplog,safari_history,symantec_scanlog,userassist,usnjrnl,windows_boot_execute,windows_boot_verify,windows_run,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winjob,winrar_mru,winreg,winreg_default",
    'lin' : "binary_cookies,bsm_log,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,java_idx,mac_appfirewall_log,mcafee_protection,opera_global,opera_typed_history,popularity_contest,safari_history,selinux,symantec_scanlog,utmp,utmpx",
    'mac' : "airport,apple_id,appusage,binary_cookies,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,ipod_device,java_idx,mac_appfirewall_log,mac_keychain,mac_securityd,mackeeper_cache,macosx_bluetooth,macosx_install_history,mactime,macuser,maxos_software_update,mcafee_protection,opera_global,opera_typed_history,plist,plist_default,popularity_contest,safari_history,spotlight,spotlight_volume,symantec_scanlog,time_machine,utmp,utmpx",
    'datt' : "airport,android_app_usage,android_calls,android_sms,appcompatcache,apple_id,appusage,asl_log,bagmru,bencode,bencode_transmission,bencode_utorrent,binary_cookies,bsm_log,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,cups_ipp,custom_destinations,esedb,esedb_file_history,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,ipod_device,java_idx,lnk,ls_quarantine,mac_appfirewall_log,mac_document_versions,mac_keychain,mac_securityd,mackeeper_cache,macosx_bluetooth,macosx_install_history,mactime,macuser,macwifi,maxos_software_update,mcafee_protection,mft,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_webcache,msie_zone,msiecf,mstsc_rdp,mstsc_rdp_mru,olecf,olecf_automatic_destinations,olecf_default,olecf_document_summary,olecf_summary,openxml,opera_global,opera_typed_history,pe,plist,plist_default,pls_recall,popularity_contest,prefetch,recycle_bin,recycle_bin_info2,rplog,safari_history,sccm,selinux,skydrive_log,skydrive_log_old,skype,spotlight,spotlight_volume,sqlite,symantec_scanlog,syslog,time_machine,userassist,usnjrnl,utmp,utmpx,windows_boot_execute,windows_boot_verify,windows_run,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winiis,winjob,winrar_mru,winreg,winreg_default,xchatlog,xchatscrollback,zeitgeist",
}

parse_options13 = {
    'win' : "appcompatcache,bagmru,binary_cookies,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cookies,firefox_downloads,firefox_history,firefox_old_cache,google_drive,java_idx,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msie_zone_software,msiecf,mstsc_rdp,mstsc_rdp_mru,opera_global,opera_typed_history,prefetch,recycle_bin,recycle_bin_info2,rplog,symantec_scanlog,userassist,windows_boot_execute,windows_boot_verify,windows_run,windows_run_software,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winiis,winjob,winrar_mru,winreg,winreg_default",
    'lin' : "linux",
    'mac' : "macosx",
    'datt' : "android_app_usage,asl_log,bencode,binary_cookies,bsm_log,chrome_cache,chrome_preferences,cups_ipp,custom_destinations,esedb,filestat,firefox_cache,firefox_old_cache,hachoir,java_idx,lnk,mac_appfirewall_log,mac_keychain,mac_securityd,mactime,macwifi,mcafee_protection,msiecf,olecf,openxml,opera_global,opera_typed_history,pcap,pe,plist,pls_recall,popularity_contest,prefetch,recycle_bin,recycle_bin_info2,rplog,selinux,skydrive_log,skydrive_log_error,sqlite,symantec_scanlog,syslog,utmp,utmpx,winevt,winevtx,winfirewall,winiis,winjob,winreg,xchatlog,xchatscrollback,bencode_transmission,bencode_utorrent,esedb_file_history,msie_webcache,olecf_automatic_destinations,olecf_default,olecf_document_summary,olecf_summary,airport,apple_id,ipod_device,macosx_bluetooth,macosx_install_history,macuser,maxos_software_update,plist_default,safari_history,spotlight,spotlight_volume,time_machine,android_calls,android_sms,appusage,chrome_cookies,chrome_extension_activity,chrome_history,firefox_cookies,firefox_downloads,firefox_history,google_drive,ls_quarantine,mac_document_versions,mackeeper_cache,skype,zeitgeist,appcompatcache,bagmru,ccleaner,explorer_mountpoints2,explorer_programscache,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msie_zone_software,mstsc_rdp,mstsc_rdp_mru,userassist,windows_boot_execute,windows_boot_verify,windows_run,windows_run_software,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winrar_mru,winreg_default"
}

####################### BEGIN FUNCTIONS ############################

def query_plaso_location():
    # This prompts user for a plaso location and confirms it exists before returning
    # a valided file location
    while True:
        sys.stdout.writelines("Please enter valid location for Plaso directory: ")
        p_path = input()
        # Verify files exist
        l2t_loc = p_path.rstrip("/")+"/log2timeline.exe"
        p_loc = p_path.rstrip("/")+"/psort.exe"
        if not os.path.isfile(l2t_loc):
            print("ERROR: "+l2t_loc+" does not exist")
        else:
            if not os.path.isfile(p_loc):
                print("ERROR: "+p_loc+" does not exist")
            else:
                return l2t_loc, p_loc

# Ask a yes/no question via input() and return their answer.
def query_yes_no(question, default="yes"):
    if default == "yes":
        prompt = " [Y/n]"
        yes = set(['yes','y', 'ye', ''])
        no = set(['no','n'])
    else:
        prompt = " [y/N]"
        yes = set(['yes','ye','y'])
        no = set(['no','n',''])

    while True:
        sys.stdout.writelines(question + prompt+": ")
        choice = input().lower()
        if choice in yes:
            return True
        elif choice in no:
            return False
        else:
            sys.stdout.write("Please respond with 'yes' or 'no'")

def status_marker(myproc):
    counter = 1
    while myproc.poll() is None:
        if counter%2 == 0:
            sys.stdout.writelines("| Still working...\r")
        else:
            sys.stdout.writelines("- Still working...\r")
        sys.stdout.flush()
        counter+=1
        time.sleep(1)

    if myproc.poll() != 0:
        print("ERROR: There was a problem. See log for details in log.")
        mylogfile.writelines("ERROR: There was a problem. See details in log.\n")
        print("\nExiting.......")
        sys.exit(1)

def create_reports(dst_loc, csv_file):
    # Create report directory and file names
    rpt_dir_name = dst_loc+"/Reports"
    rpt_evt_name = rpt_dir_name+"/Event Log Report.csv"
    rpt_fsfs_name = rpt_dir_name+"/File System Report.csv"
    rpt_fsmft_name = rpt_dir_name+"/MFT Report.csv"
    rpt_fsusnjrnl_name = rpt_dir_name+"/UsnJrnl Report.csv"
    rpt_ih_name = rpt_dir_name+"/Internet History Report.csv"
    rpt_pf_name = rpt_dir_name+"/Prefetch Report.csv"
    rpt_reg_name = rpt_dir_name+"/Registry Report.csv"
    rpt_st_name = rpt_dir_name+"/Scheduled Tasks Report.csv"
    rpt_per_name = rpt_dir_name+"/Persistence Report.csv"
    rpt_si_name = rpt_dir_name+"/System Information Report.csv"
    rpt_av_name = rpt_dir_name+"/AntiVirus Report.csv"
    rpt_fw_name = rpt_dir_name+"/Firewall Report.csv"
    rpt_mac_name = rpt_dir_name+"/Mac Report.csv"
    rpt_lin_name = rpt_dir_name+"/Linux Report.csv"
    rpt_login_name = rpt_dir_name+"/Login Report.csv"

    # RC1 search strings for each report (windows)
    rpt_evt_search = re.compile(r'winevt,|winevtx,')
    rpt_fsfs_search = re.compile(r'filestat,|recycle_bin')
    rpt_fsmft_search = re.compile(r',mft,')
    rpt_fsusnjrnl_search = re.compile(r',usnjrnl,')
    rpt_ih_search = re.compile(r'binary_cookies,|chrome_cache,|chrome_preferences,|,firefox_cache,|firefox_cache2,|java_idx,|msiecf,|opera_global,|opera_typed_history,|safari_history,|chrome_cookies,|chrome_extension_activity,|chrome_history,|firefox_cookies,|firefox_downloads,|firefox_history,|google_drive,|windows_typed_urls,')
    rpt_pf_search = re.compile(r'prefetch,,')
    rpt_reg_search = re.compile(r'winreg,|winreg_default,')
    rpt_st_search = re.compile(r'winjob,|windows_task_cache,|cron,')
    rpt_per_search = re.compile(r'appcompatcache,|bagmru,|mrulist_shell_item_list,|mrulist_string,|mrulistex_shell_item_list,|mrulistex_string,|mrulistex_string_and_shell_item,|mrulistex_string_and_shell_item_list,|msie_zone,|mstsc_rdp,|mstsc_rdp_mru,|userassist,|windows_boot_execute,|windows_boot_verify,|windows_run,|windows_sam_users,|windows_services,|winrar_mru,')
    rpt_si_search = re.compile(r'rplog,|explorer_mountpoints2,|explorer_programscache,|windows_shutdown,|windows_timezone,|windows_usb_devices,|windows_usbstor_devices,|windows_version,|network_drives,|dpkg,')
    rpt_av_search = re.compile(r'mcafee_protection,|symantec_scanlog,|winfirewall,|ccleaner,')
    rpt_fw_search = re.compile(r'winfirewall,|mac_appfirewall_log,')
    rpt_mac_search = re.compile(r'mac_keychain,|mac_securityd,|mactime,|plist,|airport,|apple_id,|ipod_device,|macosx_bluetooth,|macosx_install_history,|macuser,|maxos_software_update,|plist_default,|spotlight,|spotlight_volume,|time_machine,|appusage,|mackeeper_cache,|imessage,')
    rpt_lin_search = re.compile(r'bsm_log,|popularity_contest,|selinux,|zsh_extended_history')
    rpt_login_search = re.compile(r'dockerjson,|ssh,|winlogon,|utmp,|utmpx,')
    # Create a list of the report names
    if parser_opt == "datt":
        lor = [rpt_evt_name,rpt_fsfs_name,rpt_fsmft_name,rpt_fsusnjrnl_name,rpt_ih_name,rpt_pf_name,rpt_reg_name,rpt_st_name,rpt_per_name,rpt_si_name,rpt_av_name,rpt_fw_name,rpt_mac_name,rpt_lin_name,rpt_login_name]
    elif parser_opt == "win":
        lor = [rpt_evt_name,rpt_fsfs_name,rpt_fsmft_name,rpt_fsusnjrnl_name,rpt_ih_name,rpt_pf_name,rpt_reg_name,rpt_st_name,rpt_per_name,rpt_si_name,rpt_av_name,rpt_fw_name,rpt_login_name]
    else:
        lor = [rpt_fsfs_name,rpt_ih_name,rpt_si_name,rpt_av_name,rpt_fw_name,rpt_mac_name,rpt_lin_name,rpt_login_name]

    # Create Report directory
    if not os.path.isdir(rpt_dir_name):
        os.makedirs(rpt_dir_name)

    # Check if files exist
    create_rep = True
    all_reports_exit = True
    existing_report_list = []
    for rpt_name in lor:
        if not os.path.isfile(rpt_name):
            all_reports_exit = False
        else:
            existing_report_list.append(rpt_name)

    if all_reports_exit:
        if query_yes_no("\nAll sub-reports already exist.  Would you like to delete these files?","no"):
            for rpt_name in lor:
                os.remove(rpt_name)
        else:
            create_rep = False

    if create_rep:
        # Create list of file handles + search terms based on the parser option selected
        if parser_opt == "datt":
            # Open all report files for writing
            rpt_evt = open(rpt_evt_name,'a+', encoding='utf-8')
            rpt_fsfs = open(rpt_fsfs_name,'a+', encoding='utf-8')
            rpt_fsmft = open(rpt_fsmft_name,'a+', encoding='utf-8')
            rpt_fsusnjrnl = open(rpt_fsusnjrnl_name,'a+', encoding='utf-8')
            rpt_ih = open(rpt_ih_name,'a+', encoding='utf-8')
            rpt_pf = open(rpt_pf_name,'a+', encoding='utf-8')
            rpt_reg = open(rpt_reg_name,'a+', encoding='utf-8')
            rpt_st = open(rpt_st_name,'a+', encoding='utf-8')
            rpt_per = open(rpt_per_name,'a+', encoding='utf-8')
            rpt_si = open(rpt_si_name,'a+', encoding='utf-8')
            rpt_av = open(rpt_av_name,'a+', encoding='utf-8')
            rpt_fw = open(rpt_fw_name,'a+', encoding='utf-8')
            rpt_mac = open(rpt_mac_name,'a+', encoding='utf-8')
            rpt_lin = open(rpt_lin_name,'a+', encoding='utf-8')
            rpt_log = open(rpt_login_name,'a+', encoding='utf-8')
            lofh = [[rpt_evt_search,rpt_evt,rpt_evt_name],[rpt_fsfs_search,rpt_fsfs,rpt_fsfs_name],[rpt_fsmft_search,rpt_fsmft,rpt_fsmft_name],[rpt_fsusnjrnl_search,rpt_fsusnjrnl,rpt_fsusnjrnl_name],[rpt_ih_search,rpt_ih,rpt_ih_name],[rpt_pf_search,rpt_pf,rpt_pf_name],[rpt_reg_search,rpt_reg,rpt_reg_name],[rpt_st_search,rpt_st,rpt_st_name],[rpt_per_search,rpt_per,rpt_per_name],[rpt_si_search,rpt_si,rpt_si_name],[rpt_av_search,rpt_av,rpt_av_name],[rpt_fw_search,rpt_fw,rpt_fw_name],[rpt_mac_search,rpt_mac,rpt_mac_name],[rpt_lin_search,rpt_lin,rpt_lin_name],[rpt_login_search,rpt_log,rpt_login_name]]
        elif parser_opt == "win":
            # Open windows report files for writing
            rpt_evt = open(rpt_evt_name,'a+', encoding='utf-8')
            rpt_fsfs = open(rpt_fsfs_name,'a+', encoding='utf-8')
            rpt_fsmft = open(rpt_fsmft_name,'a+', encoding='utf-8')
            rpt_fsusnjrnl = open(rpt_fsusnjrnl_name,'a+', encoding='utf-8')
            rpt_ih = open(rpt_ih_name,'a+', encoding='utf-8')
            rpt_pf = open(rpt_pf_name,'a+', encoding='utf-8')
            rpt_reg = open(rpt_reg_name,'a+', encoding='utf-8')
            rpt_st = open(rpt_st_name,'a+', encoding='utf-8')
            rpt_per = open(rpt_per_name,'a+', encoding='utf-8')
            rpt_si = open(rpt_si_name,'a+', encoding='utf-8')
            rpt_av = open(rpt_av_name,'a+', encoding='utf-8')
            rpt_fw = open(rpt_fw_name,'a+', encoding='utf-8')
            rpt_log = open(rpt_login_name,'a+', encoding='utf-8')
            lofh = [[rpt_evt_search,rpt_evt,rpt_evt_name],[rpt_fsfs_search,rpt_fsfs,rpt_fsfs_name],[rpt_fsmft_search,rpt_fsmft,rpt_fsmft_name],[rpt_fsusnjrnl_search,rpt_fsusnjrnl,rpt_fsusnjrnl_name],[rpt_ih_search,rpt_ih,rpt_ih_name],[rpt_pf_search,rpt_pf,rpt_pf_name],[rpt_reg_search,rpt_reg,rpt_reg_name],[rpt_st_search,rpt_st,rpt_st_name],[rpt_per_search,rpt_per,rpt_per_name],[rpt_si_search,rpt_si,rpt_si_name],[rpt_av_search,rpt_av,rpt_av_name],[rpt_fw_search,rpt_fw,rpt_fw_name],[rpt_login_search,rpt_log,rpt_login_name]]
        else:
            # Open Mac / Linux report files for writing
            rpt_fsfs = open(rpt_fsfs_name,'a+', encoding='utf-8')
            rpt_ih = open(rpt_ih_name,'a+', encoding='utf-8')
            rpt_si = open(rpt_si_name,'a+', encoding='utf-8')
            rpt_av = open(rpt_av_name,'a+', encoding='utf-8')
            rpt_fw = open(rpt_fw_name,'a+', encoding='utf-8')
            rpt_mac = open(rpt_mac_name,'a+', encoding='utf-8')
            rpt_lin = open(rpt_lin_name,'a+', encoding='utf-8')
            rpt_log = open(rpt_login_name,'a+', encoding='utf-8')
            lofh = [[rpt_fsfs_search,rpt_fsfs,rpt_fsfs_name],[rpt_ih_search,rpt_ih,rpt_ih_name],[rpt_si_search,rpt_si,rpt_si_name],[rpt_av_search,rpt_av,rpt_av_name],[rpt_fw_search,rpt_fw,rpt_fw_name],[rpt_mac_search,rpt_mac,rpt_mac_name],[rpt_lin_search,rpt_lin,rpt_lin_name],[rpt_login_search,rpt_log,rpt_login_name]]

        # Write the header line in each new report file
        for item in lofh:
            if os.stat(item[2]).st_size == 0:
                item[1].writelines("date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra\n")

        if not os.path.isfile(csv_file):
            print("File not found", csv_file)
            mylogfile.writelines("File not found " + csv_file+"\n")
            sys.exit(1)

        # Run each search for each report (sequential) and write the results to the report CSV files
        counter = 1
        counter2 = True
        for line in io.open(csv_file,'r', encoding='utf-8'):
            if counter%1000 == 0:
                if counter2:
                    sys.stdout.writelines("| Still working...\r")
                    counter2 = False
                else:
                    sys.stdout.writelines("- Still working...\r")
                    counter2 = True
            for terms in lofh:
                if terms[0].search(line,re.I):
                    terms[1].writelines(line)
            sys.stdout.flush()
            counter+=1
        # Close all report files
        for item in lofh:
            item[1].close()

        # Removing files with no output
        final_lor = []
        final_lor_nodata = []
        for i_filename in lor:
            if os.stat(i_filename).st_size == 111:
                os.remove(i_filename)
                final_lor_nodata.append(i_filename)
            else:
                final_lor.append(i_filename)

        # Print report created messages
        print("Created "+str(len(final_lor))+" Reports")
        mylogfile.writelines("Created "+str(len(final_lor))+" Reports\n")
        for item in final_lor:
            print("Report Created: "+ item)
            mylogfile.writelines("Report Created:" + item + "\n")
        # Print report not created messages
        print("\nDid not keep "+str(len(final_lor_nodata))+" Reports due to no matching data from SuperTimeline")
        mylogfile.writelines("\nDid not keep "+str(len(final_lor_nodata))+" Reports due to no matching data from SuperTimeline\n")
        for item in final_lor_nodata:
            print("Report not kept: "+ item)
            mylogfile.writelines("Report not kept:" + item + "\n")


def plaso_version(log2timeline_location):
    myproc = subprocess.Popen([log2timeline_location,"--version"],stderr=subprocess.PIPE)
    output,err = myproc.communicate()
    pver = ".".join(str(err).split(" ")[-1].split(".")[0:2])
    return(pver)

def output_elasticsearch(srcfilename,casename):
    # Run psort against plaso db file to output to an ElasticSearch server running on the localhost
    print("Exporting results to the ElasticSearch server")
    mylogfile.writelines("Exporting results to the ElasticSearch server\n")

    # Create command to run
    # SAMPLE: psort.py -o elastic --raw_fields --index_name case_test output.db 
    command = [psort_location,"-o","elastic","--raw_fields","--index_name",global_es_index+casename.lower(), srcfilename]
    
    print("\""+"\" \"".join(command)+"\"")
    mylogfile.writelines("\""+"\" \"".join(command)+"\""+"\n")

    # Execute Command
    status_marker(subprocess.Popen(command,stdout=mylogfile,stderr=mylogfile))
    
    print("All entries have been inserted into database with case: "+global_es_index+casename.lower())
    mylogfile.writelines("All entries have been inserted into database with case: "+global_es_index+casename.lower()+"\n")

def unzip_source(src_loc_tmp):
    try:
        outputzipfolder = src_loc_tmp[0:-4]
        print("Attempting to extract .zip file source file: "+src_loc_tmp)
        log_list.append("Attempting to extract .zip file source file: "+src_loc_tmp+"\n")
        with zipfile.ZipFile(src_loc_tmp,"r") as zip_ref:
            zip_ref.extractall(outputzipfolder)
        print("All files extracted to folder: "+outputzipfolder)
        log_list.append("All files extracted to folder: "+outputzipfolder+"\n")
        return outputzipfolder
    except:
        print("Unable to extract file: "+src_loc_tmp)
        log_list.append("Unable to extract file: "+src_loc_tmp+"\n")

def create_export(srcfilename):
    # Create Output filenames
    dstrawfilename = srcfilename[:-3]+"_export.json"
    dstfilename = srcfilename[:-3]+".json.gz"
    if os.path.exists(dstfilename):
        if query_yes_no("\n"+dstfilename+" already exists.  Would you like to delete that file?","no"):
            os.remove(dstfilename)
        else:
            return dstfilename

    # Run psort against plaso db file to output a file in line delimited json format
    print("Creating json line delimited file")
    mylogfile.writelines("Creating json line delimited file\n")

    # Create command to run
    command = [psort_location,"-o","json_line", srcfilename,"-w",dstrawfilename]
    
    print("\""+"\" \"".join(command)+"\"")
    mylogfile.writelines("\""+"\" \"".join(command)+"\""+"\n")

    # Execute Command
    status_marker(subprocess.Popen(command,stdout=mylogfile,stderr=mylogfile))
    
    print("Json line delimited file created")
    mylogfile.writelines("Json line delimited file created"+"\n")
    print("Adding Json line delimited file to "+dstfilename)
    mylogfile.writelines("Adding Json line delimited file to "+dstfilename+"\n")
    mylogfile.writelines("Adding " + dstrawfilename + " to "+ dstfilename +"\n")

    # Compresse the file for export
    with io.open(dstrawfilename, 'rb') as f_in:
        with gzip.open(dstfilename, 'wb') as f_out:
            shutil.copyfileobj(f_in,f_out)
    f_in.close()
    f_out.close()
    os.remove(dstrawfilename)
    print("Cleaning up temporary file: Removed "+ dstrawfilename)
    mylogfile.writelines("Cleaning up temporary file: Removed "+ dstrawfilename +"\n")


    return dstfilename

def get_parser_list(parser_opt,plaso_ver):
    if plaso_ver == "1.5":
        parserlist = parse_options15[parser_opt]
    if plaso_ver == "1.4":
        parserlist = parse_options14[parser_opt]
    if plaso_ver == "1.3":
        parserlist = parse_options13[parser_opt]
    return parserlist


####################### END FUNCTIONS ############################

# Parsing begins
parser_list = ["win","lin","mac","datt"]

parser = argparse.ArgumentParser(description='Cold Disk Quick Response Tool (CDQR)')
parser.add_argument('src_location',nargs=1,help='Source File location: Y:/Case/Tag009/sample.E01')
parser.add_argument('dst_location',nargs='?',default='Results',help='Destination Folder location. If nothing is supplied then the default is \'Results\'')
parser.add_argument('-p','--parser', nargs='?',help='Choose parser to use.  If nothing chosen then \'win\' is used.  Options are: '+', '.join(parser_list))
parser.add_argument('--nohash', action='store_true', default=False, help='Do not hash all the files as part of the processing of the image')
parser.add_argument('--max_cpu', action='store_true', default=False, help='Use the maximum number of cpu cores to process the image')
parser.add_argument('--export', action='store_true' , help='Creates gzipped, line delimited json export file')
parser.add_argument('--es', nargs='?',help='Outputs to elasticsearch database (Default is to localhost)')
parser.add_argument('-z',action='store_true', default=False, help='Indicates the input file is a zip file and needs to be decompressed')
parser.add_argument('-v','--version', action='version', version=cdqr_version)

args=parser.parse_args()

# List to help with logging
log_list = [cdqr_version+"\n"]
print(cdqr_version)

# Parsing the input from the command line and building log2timeline command
if args:
    # Validate log2timeline.exe and psort.exe locations
    if sys.platform[0:3] == "win":
        if not os.path.isfile(log2timeline_location):
          log2timeline_location,psort_location = query_plaso_location()
        # Default log2timeline command
    command1 = [log2timeline_location,"-p","--partition","all","--vss_stores","all"]

# Set log2timeline parsing option(s)
    if args.parser:
        if args.parser not in parser_list:
            print("ERROR: \""+args.parser+ "\" is not a valid parser selection.")
            print("ERROR: Valid parser options are: " + ', '.join(parser_list))
            print("ERROR: Please verify your command and try again.")
            print("Exiting...")
            sys.exit(1)
        parser_opt = args.parser
        # if parser_opt == "datt":
        #     command1 = [log2timeline_location, "-p"]
        if parser_opt == "lin" or parser_opt == "mac":
            command1 = [log2timeline_location,"-p","--partition","all"]
    else:
        # Set Default parser value to "datt"
        parser_opt = default_parser



# Determine if Plaso version is compatible
    # Determine Plaso version and use correct version
    p_ver = plaso_version(log2timeline_location)
    print("Plaso Version: "+p_ver)
    log_list.append("Plaso Version: "+p_ver+"\n")


    plaso_ver = plaso_version(log2timeline_location)
    if plaso_ver not in p_compat:
        print("Plaso version "+plaso_ver+" not supported.....Exiting")
        sys.exit(1)

# Determine if Export is being used and option is valid
    if args.export:
            print("Export data option selected")
            log_list.append("Export data option selected\n")
    # add parsing options to the command
    command1.append("--parsers")
    command1.append(get_parser_list(parser_opt, plaso_ver))
    print("Using parser: "+parser_opt)
    log_list.append("Using parser: " + parser_opt+"\n")

# Set Hashing variable
    if args.nohash:
        command1.append("--hashers")
        command1.append("none")
    else:
        command1.append("--hashers")
        command1.append("md5")

# Set Number of CPU cores to use
    if args.max_cpu:
        num_cpus = multiprocessing.cpu_count()
    else:
        num_cpus = multiprocessing.cpu_count() -3
        if num_cpus <= 0:
            num_cpus = 1
    command1.append("--workers")
    command1.append(str(num_cpus))
    print("Number of cpu cores to use: "+str(num_cpus))
    log_list.append("Number of cpu cores to use: "+str(num_cpus)+"\n")

# Set source location/file
    src_loc = args.src_location[0]
    src_loc = src_loc.replace("\"","/")
    if src_loc.count("/") > 1:
        src_loc = src_loc.rstrip("/")

    if not os.path.exists(src_loc):
        print("ERROR: \""+src_loc+"\" cannot be found by the system.  Please verify command.")
        print("Exiting...")
        sys.exit(1)
    
    if args.z:
        unzipped_file = True
        src_loc = unzip_source(src_loc)

    if src_loc[-4:].lower() == ".zip":
        if query_yes_no("\n"+src_loc+" appears to be a zip file.  Would you like CDQR to unzip it and process the contents?","yes"):
            unzipped_file = True
            src_loc = unzip_source(src_loc)

    print("Source data: "+src_loc)
    log_list.append("Source data: "+src_loc+"\n")

# Set destination location/file
    dst_loc = args.dst_location.strip("/")
    if os.path.exists(dst_loc):
        if not query_yes_no("\n"+dst_loc+" already exists.  Would you like to use that directory anyway?","yes"):
            dst_loc = dst_loc+"_"+datetime.datetime.now().strftime("%d-%b-%y_%H-%M-%S")
            os.makedirs(dst_loc)
    else:
        os.makedirs(dst_loc)

    print("Destination Folder: "+dst_loc)
    log_list.append("Destination Folder: "+dst_loc+"\n")

# Create DB Filename
db_file = dst_loc+"/"+src_loc.split("/")[-1]+".db"
if db_file == dst_loc+"/.db":
    db_file = dst_loc+"/"+"mounted_image.db"
print("Database File: "+ db_file)
log_list.append("Database File: "+db_file+"\n")

# Create SuperTimeline filename
csv_file = dst_loc+"/"+src_loc.split("/")[-1]+".SuperTimeline.csv"
if csv_file == dst_loc+"/.SuperTimeline.csv":
    csv_file = dst_loc+"/"+"mounted_image.SuperTimeline.csv"
print("SuperTimeline CSV File: "+ csv_file)

# Finalize the log2timeline command with DB file and source data file location
command1.append(db_file)
command1.append(src_loc)

#  Create space in output
print("\n")
log_list.append("")

# Open Log Files
logfilename = dst_loc+"/"+src_loc.split("/")[-1]+".log"
if logfilename == dst_loc+"/.log":
    logfilename = dst_loc+"/"+"mounted_image.log"

if os.path.isfile(logfilename):
    os.remove(logfilename)

print(logfilename)
mylogfile = open(logfilename,'w')
mylogfile.writelines("".join(log_list))
print("Processing started at: "+str(start_dt))
mylogfile.writelines("Processing started at: "+str(start_dt)+"\n")

# Check if the database and supertimeline files already exists and ask to keep or delete them if they do
if os.path.isfile(db_file):
    if query_yes_no("\n"+db_file+" already exists.  Would you like to delete this file?","no"):
        print("Removing the existing file: "+db_file)
        mylogfile.writelines("Removing the existing file: "+db_file+"\n")
        os.remove(db_file)
        if os.path.isfile(csv_file):
            print("Removing the existing file: "+csv_file)
            mylogfile.writelines("Removing the existing file: "+csv_file+"\n")
            os.remove(csv_file)
            rpt_dir_name = dst_loc+"/Reports"
            if os.path.isdir(rpt_dir_name):
                print("Removing the existing report directory: "+rpt_dir_name)
                mylogfile.writelines("Removing the existing report directory: "+rpt_dir_name+"\n")
                shutil.rmtree(rpt_dir_name)
    else:
        print("Keeping the existing file: "+db_file)
        create_db = False



##################  EXECTUTION SECTION ############################
# This processes the image using parser option selected and creates .db file
if create_db:
    # Process image with log2timeline
    print("Parsing image")
    mylogfile.writelines("Parsing image"+"\n")
    print("\""+"\" \"".join(command1)+"\"")
    mylogfile.writelines("\""+"\" \"".join(command1)+"\""+"\n")
    ######################  Log2timeline Command Execute  ##########################
    status_marker(subprocess.Popen(command1,stdout=mylogfile,stderr=mylogfile))

    end_dt = datetime.datetime.now()
    duration01 = end_dt - start_dt
    print("Parsing ended at: "+str(end_dt))
    mylogfile.writelines("Parsing ended at: "+str(end_dt)+"\n")
    print("Parsing duration was: "+str(duration01))
    mylogfile.writelines("Parsing duration was: "+str(duration01)+"\n")

if args.es:
    start_dt = datetime.datetime.now()
    print("\nProcess to export to ElasticSearch started")
    mylogfile.writelines("\nProcess to export to ElasticSearch started"+"\n")
    output_elasticsearch(db_file,args.es)
    end_dt = datetime.datetime.now()
    duration03 = end_dt - start_dt
    print("\nProcess to export to ElasticSearch completed")
    mylogfile.writelines("\nProcess to export to ElasticSearch completed"+"\n")
    print("ElasticSearch export process duration was: "+str(duration03))
    mylogfile.writelines("ElasticSearch export process duration was: "+str(duration03)+"\n")
else:
    if os.path.isfile(csv_file):
        if query_yes_no("\n"+csv_file+" already exists.  Would you like to delete this file?","no"):
                print("Removing the existing file: "+csv_file)
                mylogfile.writelines("Removing the existing file: "+csv_file+"\n")
                os.remove(csv_file)
                rpt_dir_name = dst_loc+"/Reports"
                if os.path.isdir(rpt_dir_name):
                    print("Removing the existing report directory: "+rpt_dir_name)
                    mylogfile.writelines("Removing the existing file: "+rpt_dir_name+"\n")
        else:
            print("Keeping the existing file: "+csv_file)
            create_st = False
    # This processes the .db file creates the SuperTimeline
    if create_st:
        command2 = [psort_location,"-o","l2tcsv",db_file,"-w",csv_file]
        # Create SuperTimeline
        start_dt = datetime.datetime.now()
        print("\nCreating the SuperTimeline CSV file")
        mylogfile.writelines("\nCreating the SuperTimeline CSV file"+"\n")
        print("\""+"\" \"".join(command2)+"\"")
        mylogfile.writelines("\""+"\" \"".join(command2)+"\""+"\n")
        ######################  Psort Command Execute  ##########################
        status_marker(subprocess.Popen(command2,stdout=mylogfile,stderr=mylogfile))
        print("SuperTimeline CSV file is created")
        mylogfile.writelines("SuperTimeline CSV file is created\n")

    # Create individual reports
    print("\nCreating the individual reports")
    mylogfile.writelines("\nCreating the individual reports\n")
    create_reports(dst_loc,csv_file)

    print("All reporting complete")
    mylogfile.writelines("All reporting complete\n")

    end_dt = datetime.datetime.now()
    duration02 = end_dt - start_dt
    print("Reporting ended at: "+str(end_dt))
    print("Reporting  duration was: "+str(duration02))
    mylogfile.writelines("Reporting ended at: "+str(end_dt)+"\n")
    mylogfile.writelines("Reporting duration was: "+str(duration02)+"\n")

    start_dt = datetime.datetime.now()
    
    # Export Data (if selected)
    if args.export:
        print("\nProcess to create export document started")
        mylogfile.writelines("\nProcess to create export document started"+"\n")
        # Create the file for export 
        exportfname = create_export(db_file)
        print("Process to create export document complete")
        mylogfile.writelines("Process to create export document complete"+"\n")

        end_dt = datetime.datetime.now()
        duration03 = end_dt - start_dt
        print("Creating export document process duration was: "+str(duration03))
        mylogfile.writelines("Creating export document process duration was: "+str(duration03)+"\n")



# Closing log file and cleaning up
if unzipped_file:
    print("\nRemoving uncompressed files in directory: "+src_loc)
    mylogfile.writelines("\nRemoving uncompressed files in directory: "+src_loc+"\n")
    shutil.rmtree(src_loc)

print("\nTotal  duration was: "+str(duration01+duration02+duration03))
mylogfile.writelines("\nTotal duration was: "+str(duration01+duration02+duration03)+"\n")
mylogfile.close()

