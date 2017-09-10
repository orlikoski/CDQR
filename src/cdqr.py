#!/usr/bin/python3
import io, os, sys, argparse, subprocess, csv, time, datetime, re, multiprocessing, shutil, zipfile, queue, threading
try:
    import zlib
    compression = zipfile.ZIP_DEFLATED
except:
    compression = zipfile.ZIP_STORED

modes = {
    zipfile.ZIP_DEFLATED: 'deflated',
    zipfile.ZIP_STORED: 'stored',
}
###############################################################################
# Created by: Alan Orlikoski
cdqr_version = "CDQR Version: 4.0.1"
# 
###############################################################################
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


# Compatible Plaso versions
p_compat = ["1.3","1.4","1.5"]

# Dictionary of parsing options from command line to log2timeline
parse_options15 = {
    'win' : "sqlite,appcompatcache,bagmru,binary_cookies,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,java_idx,mcafee_protection,mft,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msiecf,mstsc_rdp,mstsc_rdp_mru,network_drives,opera_global,opera_typed_history,prefetch,recycle_bin,recycle_bin_info2,rplog,safari_history,symantec_scanlog,userassist,usnjrnl,windows_boot_execute,windows_boot_verify,windows_run,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winjob,winlogon,winrar_mru,winreg,winreg_default",
    'lin' : "sqlite,binary_cookies,bsm_log,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,cron,dockerjson,dpkg,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,imessage,java_idx,mac_appfirewall_log,mcafee_protection,opera_global,opera_typed_history,popularity_contest,safari_history,selinux,ssh,symantec_scanlog,utmp,utmpx,zsh_extended_history",
    'mac' : "sqlite,airport,apple_id,appusage,binary_cookies,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,cron,dockerjson,dpkg,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,imessage,ipod_device,java_idx,mac_appfirewall_log,mac_keychain,mac_securityd,mackeeper_cache,macosx_bluetooth,macosx_install_history,mactime,macuser,maxos_software_update,mcafee_protection,opera_global,opera_typed_history,plist,plist_default,popularity_contest,safari_history,spotlight,spotlight_volume,ssh,symantec_scanlog,time_machine,utmp,utmpx,zsh_extended_history",
    'datt' : "airport,android_app_usage,android_calls,android_sms,appcompatcache,apple_id,appusage,asl_log,bagmru,bencode,bencode_transmission,bencode_utorrent,binary_cookies,bsm_log,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,cron,cups_ipp,custom_destinations,dockerjson,dpkg,esedb,esedb_file_history,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,imessage,ipod_device,java_idx,kik_messenger,lnk,ls_quarantine,mac_appfirewall_log,mac_document_versions,mac_keychain,mac_securityd,mackeeper_cache,macosx_bluetooth,macosx_install_history,mactime,macuser,macwifi,maxos_software_update,mcafee_protection,mft,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_webcache,msie_zone,msiecf,mstsc_rdp,mstsc_rdp_mru,network_drives,olecf,olecf_automatic_destinations,olecf_default,olecf_document_summary,olecf_summary,openxml,opera_global,opera_typed_history,pe,plist,plist_default,pls_recall,popularity_contest,prefetch,recycle_bin,recycle_bin_info2,rplog,safari_history,sccm,selinux,skydrive_log,skydrive_log_old,skype,spotlight,spotlight_volume,sqlite,ssh,symantec_scanlog,syslog,time_machine,twitter_ios,userassist,usnjrnl,utmp,utmpx,windows_boot_execute,windows_boot_verify,windows_run,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winiis,winjob,winlogon,winrar_mru,winreg,winreg_default,xchatlog,xchatscrollback,zeitgeist,zsh_extended_history",
}

parse_options14 = {
    'win' : "sqlite,appcompatcache,bagmru,binary_cookies,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,java_idx,mcafee_protection,mft,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msiecf,mstsc_rdp,mstsc_rdp_mru,opera_global,opera_typed_history,prefetch,recycle_bin,recycle_bin_info2,rplog,safari_history,symantec_scanlog,userassist,usnjrnl,windows_boot_execute,windows_boot_verify,windows_run,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winjob,winrar_mru,winreg,winreg_default",
    'lin' : "sqlite,binary_cookies,bsm_log,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,java_idx,mac_appfirewall_log,mcafee_protection,opera_global,opera_typed_history,popularity_contest,safari_history,selinux,symantec_scanlog,utmp,utmpx",
    'mac' : "sqlite,airport,apple_id,appusage,binary_cookies,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,ipod_device,java_idx,mac_appfirewall_log,mac_keychain,mac_securityd,mackeeper_cache,macosx_bluetooth,macosx_install_history,mactime,macuser,maxos_software_update,mcafee_protection,opera_global,opera_typed_history,plist,plist_default,popularity_contest,safari_history,spotlight,spotlight_volume,symantec_scanlog,time_machine,utmp,utmpx",
    'datt' : "airport,android_app_usage,android_calls,android_sms,appcompatcache,apple_id,appusage,asl_log,bagmru,bencode,bencode_transmission,bencode_utorrent,binary_cookies,bsm_log,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,cups_ipp,custom_destinations,esedb,esedb_file_history,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cache2,firefox_cookies,firefox_downloads,firefox_history,google_drive,ipod_device,java_idx,lnk,ls_quarantine,mac_appfirewall_log,mac_document_versions,mac_keychain,mac_securityd,mackeeper_cache,macosx_bluetooth,macosx_install_history,mactime,macuser,macwifi,maxos_software_update,mcafee_protection,mft,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_webcache,msie_zone,msiecf,mstsc_rdp,mstsc_rdp_mru,olecf,olecf_automatic_destinations,olecf_default,olecf_document_summary,olecf_summary,openxml,opera_global,opera_typed_history,pe,plist,plist_default,pls_recall,popularity_contest,prefetch,recycle_bin,recycle_bin_info2,rplog,safari_history,sccm,selinux,skydrive_log,skydrive_log_old,skype,spotlight,spotlight_volume,sqlite,symantec_scanlog,syslog,time_machine,userassist,usnjrnl,utmp,utmpx,windows_boot_execute,windows_boot_verify,windows_run,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winiis,winjob,winrar_mru,winreg,winreg_default,xchatlog,xchatscrollback,zeitgeist",
}

parse_options13 = {
    'win' : "sqlite,appcompatcache,bagmru,binary_cookies,ccleaner,chrome_cache,chrome_cookies,chrome_extension_activity,chrome_history,chrome_preferences,explorer_mountpoints2,explorer_programscache,filestat,firefox_cache,firefox_cookies,firefox_downloads,firefox_history,firefox_old_cache,google_drive,java_idx,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msie_zone_software,msiecf,mstsc_rdp,mstsc_rdp_mru,opera_global,opera_typed_history,prefetch,recycle_bin,recycle_bin_info2,rplog,symantec_scanlog,userassist,windows_boot_execute,windows_boot_verify,windows_run,windows_run_software,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winevt,winevtx,winfirewall,winiis,winjob,winrar_mru,winreg,winreg_default",
    'lin' : "linux",
    'mac' : "macosx",
    'datt' : "android_app_usage,asl_log,bencode,binary_cookies,bsm_log,chrome_cache,chrome_preferences,cups_ipp,custom_destinations,esedb,filestat,firefox_cache,firefox_old_cache,hachoir,java_idx,lnk,mac_appfirewall_log,mac_keychain,mac_securityd,mactime,macwifi,mcafee_protection,msiecf,olecf,openxml,opera_global,opera_typed_history,pcap,pe,plist,pls_recall,popularity_contest,prefetch,recycle_bin,recycle_bin_info2,rplog,selinux,skydrive_log,skydrive_log_error,sqlite,symantec_scanlog,syslog,utmp,utmpx,winevt,winevtx,winfirewall,winiis,winjob,winreg,xchatlog,xchatscrollback,bencode_transmission,bencode_utorrent,esedb_file_history,msie_webcache,olecf_automatic_destinations,olecf_default,olecf_document_summary,olecf_summary,airport,apple_id,ipod_device,macosx_bluetooth,macosx_install_history,macuser,maxos_software_update,plist_default,safari_history,spotlight,spotlight_volume,time_machine,android_calls,android_sms,appusage,chrome_cookies,chrome_extension_activity,chrome_history,firefox_cookies,firefox_downloads,firefox_history,google_drive,ls_quarantine,mac_document_versions,mackeeper_cache,skype,zeitgeist,appcompatcache,bagmru,ccleaner,explorer_mountpoints2,explorer_programscache,microsoft_office_mru,microsoft_outlook_mru,mrulist_shell_item_list,mrulist_string,mrulistex_shell_item_list,mrulistex_string,mrulistex_string_and_shell_item,mrulistex_string_and_shell_item_list,msie_zone,msie_zone_software,mstsc_rdp,mstsc_rdp_mru,userassist,windows_boot_execute,windows_boot_verify,windows_run,windows_run_software,windows_sam_users,windows_services,windows_shutdown,windows_task_cache,windows_timezone,windows_typed_urls,windows_usb_devices,windows_usbstor_devices,windows_version,winrar_mru,winreg_default"
}

# All credit for these definitions below to: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx
eventlog_dict = {
    '512':'Windows NT is starting up',
    '513':'Windows is shutting down',
    '514':'An authentication package has been loaded by the Local Security Authority',
    '515':'A trusted logon process has registered with the Local Security Authority',
    '516':'Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits',
    '517':'The audit log was cleared',
    '518':'A notification package has been loaded by the Security Account Manager',
    '519':'A process is using an invalid local procedure call (LPC) port',
    '520':'The system time was changed',
    '521':'Unable to log events to security log',
    '528':'Successful Logon',
    '529':'Logon Failure - Unknown user name or bad password',
    '530':'Logon Failure - Account logon time restriction violation',
    '531':'Logon Failure - Account currently disabled',
    '532':'Logon Failure - The specified user account has expired',
    '533':'Logon Failure - User not allowed to logon at this computer',
    '534':'Logon Failure - The user has not been granted the requested logon type at this machine',
    '535':'Logon Failure - The specified accounts password has expired',
    '536':'Logon Failure - The NetLogon component is not active',
    '537':'Logon failure - The logon attempt failed for other reasons.',
    '538':'User Logoff',
    '539':'Logon Failure - Account locked out',
    '540':'Successful Network Logon',
    '551':'User initiated logoff',
    '552':'Logon attempt using explicit credentials',
    '560':'Object Open',
    '561':'Handle Allocated',
    '562':'Handle Closed',
    '563':'Object Open for Delete',
    '564':'Object Deleted',
    '565':'Object Open (Active Directory)',
    '566':'Object Operation (W3 Active Directory)',
    '567':'Object Access Attempt',
    '576':'Special privileges assigned to new logon',
    '577':'Privileged Service Called',
    '578':'Privileged object operation',
    '592':'A new process has been created',
    '593':'A process has exited',
    '594':'A handle to an object has been duplicated',
    '595':'Indirect access to an object has been obtained',
    '596':'Backup of data protection master key',
    '600':'A process was assigned a primary token',
    '601':'Attempt to install service',
    '602':'Scheduled Task created',
    '608':'User Right Assigned',
    '609':'User Right Removed',
    '610':'New Trusted Domain',
    '611':'Removing Trusted Domain',
    '612':'Audit Policy Change',
    '613':'IPSec policy agent started',
    '614':'IPSec policy agent disabled',
    '615':'IPSEC PolicyAgent Service',
    '616':'IPSec policy agent encountered a potentially serious failure.',
    '617':'Kerberos Policy Changed',
    '618':'Encrypted Data Recovery Policy Changed',
    '619':'Quality of Service Policy Changed',
    '620':'Trusted Domain Information Modified',
    '621':'System Security Access Granted',
    '622':'System Security Access Removed',
    '623':'Per User Audit Policy was refreshed',
    '624':'User Account Created',
    '625':'User Account Type Changed',
    '626':'User Account Enabled',
    '627':'Change Password Attempt',
    '628':'User Account password set',
    '629':'User Account Disabled',
    '630':'User Account Deleted',
    '631':'Security Enabled Global Group Created',
    '632':'Security Enabled Global Group Member Added',
    '633':'Security Enabled Global Group Member Removed',
    '634':'Security Enabled Global Group Deleted',
    '635':'Security Enabled Local Group Created',
    '636':'Security Enabled Local Group Member Added',
    '637':'Security Enabled Local Group Member Removed',
    '638':'Security Enabled Local Group Deleted',
    '639':'Security Enabled Local Group Changed',
    '640':'General Account Database Change',
    '641':'Security Enabled Global Group Changed',
    '642':'User Account Changed',
    '643':'Domain Policy Changed',
    '644':'User Account Locked Out',
    '645':'Computer Account Created',
    '646':'Computer Account Changed',
    '647':'Computer Account Deleted',
    '648':'Security Disabled Local Group Created',
    '649':'Security Disabled Local Group Changed',
    '650':'Security Disabled Local Group Member Added',
    '651':'Security Disabled Local Group Member Removed',
    '652':'Security Disabled Local Group Deleted',
    '653':'Security Disabled Global Group Created',
    '654':'Security Disabled Global Group Changed',
    '655':'Security Disabled Global Group Member Added',
    '656':'Security Disabled Global Group Member Removed',
    '657':'Security Disabled Global Group Deleted',
    '658':'Security Enabled Universal Group Created',
    '659':'Security Enabled Universal Group Changed',
    '660':'Security Enabled Universal Group Member Added',
    '661':'Security Enabled Universal Group Member Removed',
    '662':'Security Enabled Universal Group Deleted',
    '663':'Security Disabled Universal Group Created',
    '664':'Security Disabled Universal Group Changed',
    '665':'Security Disabled Universal Group Member Added',
    '666':'Security Disabled Universal Group Member Removed',
    '667':'Security Disabled Universal Group Deleted',
    '668':'Group Type Changed',
    '669':'Add SID History',
    '670':'Add SID History',
    '671':'User Account Unlocked',
    '672':'Authentication Ticket Granted',
    '673':'Service Ticket Granted',
    '674':'Ticket Granted Renewed',
    '675':'Pre-authentication failed',
    '676':'Authentication Ticket Request Failed',
    '677':'Service Ticket Request Failed',
    '678':'Account Mapped for Logon by',
    '679':'The name: %2 could not be mapped for logon by: %1',
    '680':'Account Used for Logon by',
    '681':'The logon to account: %2 by: %1 from workstation: %3 failed.',
    '682':'Session reconnected to winstation',
    '683':'Session disconnected from winstation',
    '684':'Set ACLs of members in administrators groups',
    '685':'Account Name Changed',
    '686':'Password of the following user accessed',
    '687':'Basic Application Group Created',
    '688':'Basic Application Group Changed',
    '689':'Basic Application Group Member Added',
    '690':'Basic Application Group Member Removed',
    '691':'Basic Application Group Non-Member Added',
    '692':'Basic Application Group Non-Member Removed',
    '693':'Basic Application Group Deleted',
    '694':'LDAP Query Group Created',
    '695':'LDAP Query Group Changed',
    '696':'LDAP Query Group Deleted',
    '697':'Password Policy Checking API is called',
    '806':'Per User Audit Policy was refreshed',
    '807':'Per user auditing policy set for user',
    '808':'A security event source has attempted to register',
    '809':'A security event source has attempted to unregister',
    '848':'The following policy was active when the Windows Firewall started',
    '849':'An application was listed as an exception when the Windows Firewall started',
    '850':'A port was listed as an exception when the Windows Firewall started',
    '851':'A change has been made to the Windows Firewall application exception list',
    '852':'A change has been made to the Windows Firewall port exception list',
    '853':'The Windows Firewall operational mode has changed',
    '854':'The Windows Firewall logging settings have changed',
    '855':'A Windows Firewall ICMP setting has changed',
    '856':'The Windows Firewall setting to allow unicast responses to multicast/broadcast traffic has changed',
    '857':'The Windows Firewall setting to allow remote administration, allowing port TCP 135 and DCOM/RPC, has changed',
    '858':'Windows Firewall group policy settings have been applied',
    '859':'The Windows Firewall group policy settings have been removed',
    '860':'The Windows Firewall has switched the active policy profile',
    '861':'The Windows Firewall has detected an application listening for incoming traffic',
    '1100':'The event logging service has shut down',
    '1101':'Audit events have been dropped by the transport.',
    '1102':'The audit log was cleared',
    '1104':'The security Log is now full',
    '1105':'Event log automatic backup',
    '1108':'The event logging service encountered an error',
    '4608':'Windows is starting up',
    '4609':'Windows is shutting down',
    '4610':'An authentication package has been loaded by the Local Security Authority',
    '4611':'A trusted logon process has been registered with the Local Security Authority',
    '4612':'Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits.',
    '4614':'A notification package has been loaded by the Security Account Manager.',
    '4615':'Invalid use of LPC port',
    '4616':'The system time was changed.',
    '4618':'A monitored security event pattern has occurred',
    '4621':'Administrator recovered system from CrashOnAuditFail',
    '4622':'A security package has been loaded by the Local Security Authority.',
    '4624':'An account was successfully logged on',
    '4625':'An account failed to log on',
    '4626':'User/Device claims information',
    '4627':'Group membership information.',
    '4634':'An account was logged off',
    '4646':'IKE DoS-prevention mode started',
    '4647':'User initiated logoff',
    '4648':'A logon was attempted using explicit credentials',
    '4649':'A replay attack was detected',
    '4650':'An IPsec Main Mode security association was established',
    '4651':'An IPsec Main Mode security association was established',
    '4652':'An IPsec Main Mode negotiation failed',
    '4653':'An IPsec Main Mode negotiation failed',
    '4654':'An IPsec Quick Mode negotiation failed',
    '4655':'An IPsec Main Mode security association ended',
    '4656':'A handle to an object was requested',
    '4657':'A registry value was modified',
    '4658':'The handle to an object was closed',
    '4659':'A handle to an object was requested with intent to delete',
    '4660':'An object was deleted',
    '4661':'A handle to an object was requested',
    '4662':'An operation was performed on an object',
    '4663':'An attempt was made to access an object',
    '4664':'An attempt was made to create a hard link',
    '4665':'An attempt was made to create an application client context.',
    '4666':'An application attempted an operation',
    '4667':'An application client context was deleted',
    '4668':'An application was initialized',
    '4670':'Permissions on an object were changed',
    '4671':'An application attempted to access a blocked ordinal through the TBS',
    '4672':'Special privileges assigned to new logon',
    '4673':'A privileged service was called',
    '4674':'An operation was attempted on a privileged object',
    '4675':'SIDs were filtered',
    '4688':'A new process has been created',
    '4689':'A process has exited',
    '4690':'An attempt was made to duplicate a handle to an object',
    '4691':'Indirect access to an object was requested',
    '4692':'Backup of data protection master key was attempted',
    '4693':'Recovery of data protection master key was attempted',
    '4694':'Protection of auditable protected data was attempted',
    '4695':'Unprotection of auditable protected data was attempted',
    '4696':'A primary token was assigned to process',
    '4697':'A service was installed in the system',
    '4698':'A scheduled task was created',
    '4699':'A scheduled task was deleted',
    '4700':'A scheduled task was enabled',
    '4701':'A scheduled task was disabled',
    '4702':'A scheduled task was updated',
    '4703':'A token right was adjusted',
    '4704':'A user right was assigned',
    '4705':'A user right was removed',
    '4706':'A new trust was created to a domain',
    '4707':'A trust to a domain was removed',
    '4709':'IPsec Services was started',
    '4710':'IPsec Services was disabled',
    '4711':'PAStore Engine (1%)',
    '4712':'IPsec Services encountered a potentially serious failure',
    '4713':'Kerberos policy was changed',
    '4714':'Encrypted data recovery policy was changed',
    '4715':'The audit policy (SACL) on an object was changed',
    '4716':'Trusted domain information was modified',
    '4717':'System security access was granted to an account',
    '4718':'System security access was removed from an account',
    '4719':'System audit policy was changed',
    '4720':'A user account was created',
    '4722':'A user account was enabled',
    '4723':'An attempt was made to change an accounts password',
    '4724':'An attempt was made to reset an accounts password',
    '4725':'A user account was disabled',
    '4726':'A user account was deleted',
    '4727':'A security-enabled global group was created',
    '4728':'A member was added to a security-enabled global group',
    '4729':'A member was removed from a security-enabled global group',
    '4730':'A security-enabled global group was deleted',
    '4731':'A security-enabled local group was created',
    '4732':'A member was added to a security-enabled local group',
    '4733':'A member was removed from a security-enabled local group',
    '4734':'A security-enabled local group was deleted',
    '4735':'A security-enabled local group was changed',
    '4737':'A security-enabled global group was changed',
    '4738':'A user account was changed',
    '4739':'Domain Policy was changed',
    '4740':'A user account was locked out',
    '4741':'A computer account was created',
    '4742':'A computer account was changed',
    '4743':'A computer account was deleted',
    '4744':'A security-disabled local group was created',
    '4745':'A security-disabled local group was changed',
    '4746':'A member was added to a security-disabled local group',
    '4747':'A member was removed from a security-disabled local group',
    '4748':'A security-disabled local group was deleted',
    '4749':'A security-disabled global group was created',
    '4750':'A security-disabled global group was changed',
    '4751':'A member was added to a security-disabled global group',
    '4752':'A member was removed from a security-disabled global group',
    '4753':'A security-disabled global group was deleted',
    '4754':'A security-enabled universal group was created',
    '4755':'A security-enabled universal group was changed',
    '4756':'A member was added to a security-enabled universal group',
    '4757':'A member was removed from a security-enabled universal group',
    '4758':'A security-enabled universal group was deleted',
    '4759':'A security-disabled universal group was created',
    '4760':'A security-disabled universal group was changed',
    '4761':'A member was added to a security-disabled universal group',
    '4762':'A member was removed from a security-disabled universal group',
    '4763':'A security-disabled universal group was deleted',
    '4764':'A groups type was changed',
    '4765':'SID History was added to an account',
    '4766':'An attempt to add SID History to an account failed',
    '4767':'A user account was unlocked',
    '4768':'A Kerberos authentication ticket (TGT) was requested',
    '4769':'A Kerberos service ticket was requested',
    '4770':'A Kerberos service ticket was renewed',
    '4771':'Kerberos pre-authentication failed',
    '4772':'A Kerberos authentication ticket request failed',
    '4773':'A Kerberos service ticket request failed',
    '4774':'An account was mapped for logon',
    '4775':'An account could not be mapped for logon',
    '4776':'The domain controller attempted to validate the credentials for an account',
    '4777':'The domain controller failed to validate the credentials for an account',
    '4778':'A session was reconnected to a Window Station',
    '4779':'A session was disconnected from a Window Station',
    '4780':'The ACL was set on accounts which are members of administrators groups',
    '4781':'The name of an account was changed',
    '4782':'The password hash an account was accessed',
    '4783':'A basic application group was created',
    '4784':'A basic application group was changed',
    '4785':'A member was added to a basic application group',
    '4786':'A member was removed from a basic application group',
    '4787':'A non-member was added to a basic application group',
    '4788':'A non-member was removed from a basic application group..',
    '4789':'A basic application group was deleted',
    '4790':'An LDAP query group was created',
    '4791':'A basic application group was changed',
    '4792':'An LDAP query group was deleted',
    '4793':'The Password Policy Checking API was called',
    '4794':'An attempt was made to set the Directory Services Restore Mode administrator password',
    '4797':'An attempt was made to query the existence of a blank password for an account',
    '4798':'A users local group membership was enumerated.',
    '4799':'A security-enabled local group membership was enumerated',
    '4800':'The workstation was locked',
    '4801':'The workstation was unlocked',
    '4802':'The screen saver was invoked',
    '4803':'The screen saver was dismissed',
    '4816':'RPC detected an integrity violation while decrypting an incoming message',
    '4817':'Auditing settings on object were changed.',
    '4818':'Proposed Central Access Policy does not grant the same access permissions as the current Central Access Policy',
    '4819':'Central Access Policies on the machine have been changed',
    '4820':'A Kerberos Ticket-granting-ticket (TGT) was denied because the device does not meet the access control restrictions',
    '4821':'A Kerberos service ticket was denied because the user, device, or both does not meet the access control restrictions',
    '4822':'NTLM authentication failed because the account was a member of the Protected User group',
    '4823':'NTLM authentication failed because access control restrictions are required',
    '4824':'Kerberos preauthentication by using DES or RC4 failed because the account was a member of the Protected User group',
    '4825':'A user was denied the access to Remote Desktop. By default, users are allowed to connect only if they are members of the Remote Desktop Users group or Administrators group',
    '4826':'Boot Configuration Data loaded',
    '4830':'SID History was removed from an account',
    '4864':'A namespace collision was detected',
    '4865':'A trusted forest information entry was added',
    '4866':'A trusted forest information entry was removed',
    '4867':'A trusted forest information entry was modified',
    '4868':'The certificate manager denied a pending certificate request',
    '4869':'Certificate Services received a resubmitted certificate request',
    '4870':'Certificate Services revoked a certificate',
    '4871':'Certificate Services received a request to publish the certificate revocation list (CRL)',
    '4872':'Certificate Services published the certificate revocation list (CRL)',
    '4873':'A certificate request extension changed',
    '4874':'One or more certificate request attributes changed.',
    '4875':'Certificate Services received a request to shut down',
    '4876':'Certificate Services backup started',
    '4877':'Certificate Services backup completed',
    '4878':'Certificate Services restore started',
    '4879':'Certificate Services restore completed',
    '4880':'Certificate Services started',
    '4881':'Certificate Services stopped',
    '4882':'The security permissions for Certificate Services changed',
    '4883':'Certificate Services retrieved an archived key',
    '4884':'Certificate Services imported a certificate into its database',
    '4885':'The audit filter for Certificate Services changed',
    '4886':'Certificate Services received a certificate request',
    '4887':'Certificate Services approved a certificate request and issued a certificate',
    '4888':'Certificate Services denied a certificate request',
    '4889':'Certificate Services set the status of a certificate request to pending',
    '4890':'The certificate manager settings for Certificate Services changed.',
    '4891':'A configuration entry changed in Certificate Services',
    '4892':'A property of Certificate Services changed',
    '4893':'Certificate Services archived a key',
    '4894':'Certificate Services imported and archived a key',
    '4895':'Certificate Services published the CA certificate to Active Directory Domain Services',
    '4896':'One or more rows have been deleted from the certificate database',
    '4897':'Role separation enabled',
    '4898':'Certificate Services loaded a template',
    '4899':'A Certificate Services template was updated',
    '4900':'Certificate Services template security was updated',
    '4902':'The Per-user audit policy table was created',
    '4904':'An attempt was made to register a security event source',
    '4905':'An attempt was made to unregister a security event source',
    '4906':'The CrashOnAuditFail value has changed',
    '4907':'Auditing settings on object were changed',
    '4908':'Special Groups Logon table modified',
    '4909':'The local policy settings for the TBS were changed',
    '4910':'The group policy settings for the TBS were changed',
    '4911':'Resource attributes of the object were changed',
    '4912':'Per User Audit Policy was changed',
    '4913':'Central Access Policy on the object was changed',
    '4928':'An Active Directory replica source naming context was established',
    '4929':'An Active Directory replica source naming context was removed',
    '4930':'An Active Directory replica source naming context was modified',
    '4931':'An Active Directory replica destination naming context was modified',
    '4932':'Synchronization of a replica of an Active Directory naming context has begun',
    '4933':'Synchronization of a replica of an Active Directory naming context has ended',
    '4934':'Attributes of an Active Directory object were replicated',
    '4935':'Replication failure begins',
    '4936':'Replication failure ends',
    '4937':'A lingering object was removed from a replica',
    '4944':'The following policy was active when the Windows Firewall started',
    '4945':'A rule was listed when the Windows Firewall started',
    '4946':'A change has been made to Windows Firewall exception list. A rule was added',
    '4947':'A change has been made to Windows Firewall exception list. A rule was modified',
    '4948':'A change has been made to Windows Firewall exception list. A rule was deleted',
    '4949':'Windows Firewall settings were restored to the default values',
    '4950':'A Windows Firewall setting has changed',
    '4951':'A rule has been ignored because its major version number was not recognized by Windows Firewall',
    '4952':'Parts of a rule have been ignored because its minor version number was not recognized by Windows Firewall',
    '4953':'A rule has been ignored by Windows Firewall because it could not parse the rule',
    '4954':'Windows Firewall Group Policy settings has changed. The new settings have been applied',
    '4956':'Windows Firewall has changed the active profile',
    '4957':'Windows Firewall did not apply the following rule',
    '4958':'Windows Firewall did not apply the following rule because the rule referred to items not configured on this computer',
    '4960':'IPsec dropped an inbound packet that failed an integrity check',
    '4961':'IPsec dropped an inbound packet that failed a replay check',
    '4962':'IPsec dropped an inbound packet that failed a replay check',
    '4963':'IPsec dropped an inbound clear text packet that should have been secured',
    '4964':'Special groups have been assigned to a new logon',
    '4965':'IPsec received a packet from a remote computer with an incorrect Security Parameter Index (SPI).',
    '4976':'During Main Mode negotiation, IPsec received an invalid negotiation packet.',
    '4977':'During Quick Mode negotiation, IPsec received an invalid negotiation packet.',
    '4978':'During Extended Mode negotiation, IPsec received an invalid negotiation packet.',
    '4979':'IPsec Main Mode and Extended Mode security associations were established.',
    '4980':'IPsec Main Mode and Extended Mode security associations were established',
    '4981':'IPsec Main Mode and Extended Mode security associations were established',
    '4982':'IPsec Main Mode and Extended Mode security associations were established',
    '4983':'An IPsec Extended Mode negotiation failed',
    '4984':'An IPsec Extended Mode negotiation failed',
    '4985':'The state of a transaction has changed',
    '5024':'The Windows Firewall Service has started successfully',
    '5025':'The Windows Firewall Service has been stopped',
    '5027':'The Windows Firewall Service was unable to retrieve the security policy from the local storage',
    '5028':'The Windows Firewall Service was unable to parse the new security policy.',
    '5029':'The Windows Firewall Service failed to initialize the driver',
    '5030':'The Windows Firewall Service failed to start',
    '5031':'The Windows Firewall Service blocked an application from accepting incoming connections on the network.',
    '5032':'Windows Firewall was unable to notify the user that it blocked an application from accepting incoming connections on the network',
    '5033':'The Windows Firewall Driver has started successfully',
    '5034':'The Windows Firewall Driver has been stopped',
    '5035':'The Windows Firewall Driver failed to start',
    '5037':'The Windows Firewall Driver detected critical runtime error. Terminating',
    '5038':'Code integrity determined that the image hash of a file is not valid',
    '5039':'A registry key was virtualized.',
    '5040':'A change has been made to IPsec settings. An Authentication Set was added.',
    '5041':'A change has been made to IPsec settings. An Authentication Set was modified',
    '5042':'A change has been made to IPsec settings. An Authentication Set was deleted',
    '5043':'A change has been made to IPsec settings. A Connection Security Rule was added',
    '5044':'A change has been made to IPsec settings. A Connection Security Rule was modified',
    '5045':'A change has been made to IPsec settings. A Connection Security Rule was deleted',
    '5046':'A change has been made to IPsec settings. A Crypto Set was added',
    '5047':'A change has been made to IPsec settings. A Crypto Set was modified',
    '5048':'A change has been made to IPsec settings. A Crypto Set was deleted',
    '5049':'An IPsec Security Association was deleted',
    '5050':'An attempt to programmatically disable the Windows Firewall using a call to INetFwProfile.FirewallEnabled(FALSE',
    '5051':'A file was virtualized',
    '5056':'A cryptographic self test was performed',
    '5057':'A cryptographic primitive operation failed',
    '5058':'Key file operation',
    '5059':'Key migration operation',
    '5060':'Verification operation failed',
    '5061':'Cryptographic operation',
    '5062':'A kernel-mode cryptographic self test was performed',
    '5063':'A cryptographic provider operation was attempted',
    '5064':'A cryptographic context operation was attempted',
    '5065':'A cryptographic context modification was attempted',
    '5066':'A cryptographic function operation was attempted',
    '5067':'A cryptographic function modification was attempted',
    '5068':'A cryptographic function provider operation was attempted',
    '5069':'A cryptographic function property operation was attempted',
    '5070':'A cryptographic function property operation was attempted',
    '5071':'Key access denied by Microsoft key distribution service',
    '5120':'OCSP Responder Service Started',
    '5121':'OCSP Responder Service Stopped',
    '5122':'A Configuration entry changed in the OCSP Responder Service',
    '5123':'A configuration entry changed in the OCSP Responder Service',
    '5124':'A security setting was updated on OCSP Responder Service',
    '5125':'A request was submitted to OCSP Responder Service',
    '5126':'Signing Certificate was automatically updated by the OCSP Responder Service',
    '5127':'The OCSP Revocation Provider successfully updated the revocation information',
    '5136':'A directory service object was modified',
    '5137':'A directory service object was created',
    '5138':'A directory service object was undeleted',
    '5139':'A directory service object was moved',
    '5140':'A network share object was accessed',
    '5141':'A directory service object was deleted',
    '5142':'A network share object was added.',
    '5143':'A network share object was modified',
    '5144':'A network share object was deleted.',
    '5145':'A network share object was checked to see whether client can be granted desired access',
    '5146':'The Windows Filtering Platform has blocked a packet',
    '5147':'A more restrictive Windows Filtering Platform filter has blocked a packet',
    '5148':'The Windows Filtering Platform has detected a DoS attack and entered a defensive mode; packets associated with this attack will be discarded.',
    '5149':'The DoS attack has subsided and normal processing is being resumed.',
    '5150':'The Windows Filtering Platform has blocked a packet.',
    '5151':'A more restrictive Windows Filtering Platform filter has blocked a packet.',
    '5152':'The Windows Filtering Platform blocked a packet',
    '5153':'A more restrictive Windows Filtering Platform filter has blocked a packet',
    '5154':'The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections',
    '5155':'The Windows Filtering Platform has blocked an application or service from listening on a port for incoming connections',
    '5156':'The Windows Filtering Platform has allowed a connection',
    '5157':'The Windows Filtering Platform has blocked a connection',
    '5158':'The Windows Filtering Platform has permitted a bind to a local port',
    '5159':'The Windows Filtering Platform has blocked a bind to a local port',
    '5168':'Spn check for SMB/SMB2 fails.',
    '5169':'A directory service object was modified',
    '5170':'A directory service object was modified during a background cleanup task',
    '5376':'Credential Manager credentials were backed up',
    '5377':'Credential Manager credentials were restored from a backup',
    '5378':'The requested credentials delegation was disallowed by policy',
    '5440':'The following callout was present when the Windows Filtering Platform Base Filtering Engine started',
    '5441':'The following filter was present when the Windows Filtering Platform Base Filtering Engine started',
    '5442':'The following provider was present when the Windows Filtering Platform Base Filtering Engine started',
    '5443':'The following provider context was present when the Windows Filtering Platform Base Filtering Engine started',
    '5444':'The following sub-layer was present when the Windows Filtering Platform Base Filtering Engine started',
    '5446':'A Windows Filtering Platform callout has been changed',
    '5447':'A Windows Filtering Platform filter has been changed',
    '5448':'A Windows Filtering Platform provider has been changed',
    '5449':'A Windows Filtering Platform provider context has been changed',
    '5450':'A Windows Filtering Platform sub-layer has been changed',
    '5451':'An IPsec Quick Mode security association was established',
    '5452':'An IPsec Quick Mode security association ended',
    '5453':'An IPsec negotiation with a remote computer failed because the IKE and AuthIP IPsec Keying Modules (IKEEXT) service is not started',
    '5456':'PAStore Engine applied Active Directory storage IPsec policy on the computer',
    '5457':'PAStore Engine failed to apply Active Directory storage IPsec policy on the computer',
    '5458':'PAStore Engine applied locally cached copy of Active Directory storage IPsec policy on the computer',
    '5459':'PAStore Engine failed to apply locally cached copy of Active Directory storage IPsec policy on the computer',
    '5460':'PAStore Engine applied local registry storage IPsec policy on the computer',
    '5461':'PAStore Engine failed to apply local registry storage IPsec policy on the computer',
    '5462':'PAStore Engine failed to apply some rules of the active IPsec policy on the computer',
    '5463':'PAStore Engine polled for changes to the active IPsec policy and detected no changes',
    '5464':'PAStore Engine polled for changes to the active IPsec policy, detected changes, and applied them to IPsec Services',
    '5465':'PAStore Engine received a control for forced reloading of IPsec policy and processed the control successfully',
    '5466':'PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory cannot be reached, and will use the cached copy of the Active Directory IPsec policy instead',
    '5467':'PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, and found no changes to the policy',
    '5468':'PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, found changes to the policy, and applied those changes',
    '5471':'PAStore Engine loaded local storage IPsec policy on the computer',
    '5472':'PAStore Engine failed to load local storage IPsec policy on the computer',
    '5473':'PAStore Engine loaded directory storage IPsec policy on the computer',
    '5474':'PAStore Engine failed to load directory storage IPsec policy on the computer',
    '5477':'PAStore Engine failed to add quick mode filter',
    '5478':'IPsec Services has started successfully',
    '5479':'IPsec Services has been shut down successfully',
    '5480':'IPsec Services failed to get the complete list of network interfaces on the computer',
    '5483':'IPsec Services failed to initialize RPC server. IPsec Services could not be started',
    '5484':'IPsec Services has experienced a critical failure and has been shut down',
    '5485':'IPsec Services failed to process some IPsec filters on a plug-and-play event for network interfaces',
    '5632':'A request was made to authenticate to a wireless network',
    '5633':'A request was made to authenticate to a wired network',
    '5712':'A Remote Procedure Call (RPC) was attempted',
    '5888':'An object in the COM+ Catalog was modified',
    '5889':'An object was deleted from the COM+ Catalog',
    '5890':'An object was added to the COM+ Catalog',
    '6144':'Security policy in the group policy objects has been applied successfully',
    '6145':'One or more errors occured while processing security policy in the group policy objects',
    '6272':'Network Policy Server granted access to a user',
    '6273':'Network Policy Server denied access to a user',
    '6274':'Network Policy Server discarded the request for a user',
    '6275':'Network Policy Server discarded the accounting request for a user',
    '6276':'Network Policy Server quarantined a user',
    '6277':'Network Policy Server granted access to a user but put it on probation because the host did not meet the defined health policy',
    '6278':'Network Policy Server granted full access to a user because the host met the defined health policy',
    '6279':'Network Policy Server locked the user account due to repeated failed authentication attempts',
    '6280':'Network Policy Server unlocked the user account',
    '6281':'Code Integrity determined that the page hashes of an image file are not valid...',
    '6400':'BranchCache: Received an incorrectly formatted response while discovering availability of content.',
    '6401':'BranchCache: Received invalid data from a peer. Data discarded.',
    '6402':'BranchCache: The message to the hosted cache offering it data is incorrectly formatted.',
    '6403':'BranchCache: The hosted cache sent an incorrectly formatted response to the clients message to offer it data.',
    '6404':'BranchCache: Hosted cache could not be authenticated using the provisioned SSL certificate.',
    '6405':'BranchCache: %2 instance(s) of event id %1 occurred.',
    '6406':'%1 registered to Windows Firewall to control filtering for the following:',
    '6407':'%1',
    '6408':'Registered product %1 failed and Windows Firewall is now controlling the filtering for %2.',
    '6409':'BranchCache: A service connection point object could not be parsed',
    '6410':'Code integrity determined that a file does not meet the security requirements to load into a process. This could be due to the use of shared sections or other issues',
    '6416':'A new external device was recognized by the system.',
    '6417':'The FIPS mode crypto selftests succeeded',
    '6418':'The FIPS mode crypto selftests failed',
    '6419':'A request was made to disable a device',
    '6420':'A device was disabled',
    '6421':'A request was made to enable a device',
    '6422':'A device was enabled',
    '6423':'The installation of this device is forbidden by system policy',
    '6424':'The installation of this device was allowed, after having previously been forbidden by policy',
}

####################### BEGIN FUNCTIONS ############################

def query_plaso_location():
    # This prompts user for a plaso location and confirms it exists before returning
    # a valided file location
    while True:
        sys.stdout.writelines("Please enter valid location for Plaso directory: ")
        p_path = input()
        # Verify files exist
        l2t_loc = p_path.rstrip("/").rstrip().strip("\"")+"/log2timeline.exe"
        p_loc = p_path.rstrip("/").rstrip().strip("\"")+"/psort.exe"
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

def status_marker(mylogfile,myproc):
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

def multi_thread_reports(mqueue,infile,terms):
    for line in infile:
        if terms[0].search(line,re.I):
            mqueue.put(terms[1].writelines(line.replace("\n"," ").replace("\r"," ")+"\n"))
    print("Report Created:",terms[2])


def create_reports(mylogfile,dst_loc, csv_file,parser_opt):
    start_dt = datetime.datetime.now()
    print("Reporting started at: "+str(start_dt))
    mylogfile.writelines("Reporting started at: "+str(start_dt)+"\n")
    # Create individual reports
    print("\nCreating the individual reports (This will take a long time for large files)")
    mylogfile.writelines("\nCreating the individual reports (This will take a long time for large files)\n")
    # Create report directory and file names
    rpt_dir_name = dst_loc+"/Reports"
    rpt_evt_name = rpt_dir_name+"/Event Log Report.csv"
    rpt_fsfs_name = rpt_dir_name+"/File System Report.csv"
    rpt_fsmft_name = rpt_dir_name+"/MFT Report.csv"
    rpt_fsusnjrnl_name = rpt_dir_name+"/UsnJrnl Report.csv"
    rpt_ih_name = rpt_dir_name+"/Internet History Report.csv"
    rpt_pf_name = rpt_dir_name+"/Prefetch Report.csv"
    rpt_appc_name = rpt_dir_name+"/Appcompat Report.csv"
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
    rpt_ih_search = re.compile(r'sqlite,|binary_cookies,|chrome_cache,|chrome_preferences,|,firefox_cache,|firefox_cache2,|java_idx,|msiecf,|opera_global,|opera_typed_history,|safari_history,|chrome_cookies,|chrome_extension_activity,|chrome_history,|firefox_cookies,|firefox_downloads,|firefox_history,|google_drive,|windows_typed_urls,')
    rpt_pf_search = re.compile(r'prefetch,')
    rpt_appc_search = re.compile(r'appcompatcache,')
    rpt_reg_search = re.compile(r'winreg,|winreg_default,')
    rpt_st_search = re.compile(r'winjob,|windows_task_cache,|cron,')
    rpt_per_search = re.compile(r'bagmru,|mrulist_shell_item_list,|mrulist_string,|mrulistex_shell_item_list,|mrulistex_string,|mrulistex_string_and_shell_item,|mrulistex_string_and_shell_item_list,|msie_zone,|mstsc_rdp,|mstsc_rdp_mru,|userassist,|windows_boot_execute,|windows_boot_verify,|windows_run,|windows_sam_users,|windows_services,|winrar_mru,')
    rpt_si_search = re.compile(r'rplog,|explorer_mountpoints2,|explorer_programscache,|windows_shutdown,|windows_timezone,|windows_usb_devices,|windows_usbstor_devices,|windows_version,|network_drives,|dpkg,')
    rpt_av_search = re.compile(r'mcafee_protection,|symantec_scanlog,|winfirewall,|ccleaner,')
    rpt_fw_search = re.compile(r'winfirewall,|mac_appfirewall_log,')
    rpt_mac_search = re.compile(r'mac_keychain,|mac_securityd,|mactime,|plist,|airport,|apple_id,|ipod_device,|macosx_bluetooth,|macosx_install_history,|macuser,|maxos_software_update,|plist_default,|spotlight,|spotlight_volume,|time_machine,|appusage,|mackeeper_cache,|imessage,')
    rpt_lin_search = re.compile(r'bsm_log,|popularity_contest,|selinux,|zsh_extended_history')
    rpt_login_search = re.compile(r'dockerjson,|ssh,|winlogon,|utmp,|utmpx,')
    # Create a list of the report names
    if parser_opt == "datt":
        lor = [rpt_appc_name,rpt_evt_name,rpt_fsfs_name,rpt_fsmft_name,rpt_fsusnjrnl_name,rpt_ih_name,rpt_pf_name,rpt_reg_name,rpt_st_name,rpt_per_name,rpt_si_name,rpt_av_name,rpt_fw_name,rpt_mac_name,rpt_lin_name,rpt_login_name]
    elif parser_opt == "win":
        lor = [rpt_appc_name,rpt_evt_name,rpt_fsfs_name,rpt_fsmft_name,rpt_fsusnjrnl_name,rpt_ih_name,rpt_pf_name,rpt_reg_name,rpt_st_name,rpt_per_name,rpt_si_name,rpt_av_name,rpt_fw_name,rpt_login_name]
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
            return


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
        rpt_appc = open(rpt_appc_name,'a+', encoding='utf-8')
        rpt_per = open(rpt_per_name,'a+', encoding='utf-8')
        rpt_si = open(rpt_si_name,'a+', encoding='utf-8')
        rpt_av = open(rpt_av_name,'a+', encoding='utf-8')
        rpt_fw = open(rpt_fw_name,'a+', encoding='utf-8')
        rpt_mac = open(rpt_mac_name,'a+', encoding='utf-8')
        rpt_lin = open(rpt_lin_name,'a+', encoding='utf-8')
        rpt_log = open(rpt_login_name,'a+', encoding='utf-8')
        
        lofh = [[rpt_appc_search,rpt_appc,rpt_appc_name],[rpt_evt_search,rpt_evt,rpt_evt_name],[rpt_fsfs_search,rpt_fsfs,rpt_fsfs_name],[rpt_fsmft_search,rpt_fsmft,rpt_fsmft_name],[rpt_fsusnjrnl_search,rpt_fsusnjrnl,rpt_fsusnjrnl_name],[rpt_ih_search,rpt_ih,rpt_ih_name],[rpt_pf_search,rpt_pf,rpt_pf_name],[rpt_reg_search,rpt_reg,rpt_reg_name],[rpt_st_search,rpt_st,rpt_st_name],[rpt_per_search,rpt_per,rpt_per_name],[rpt_si_search,rpt_si,rpt_si_name],[rpt_av_search,rpt_av,rpt_av_name],[rpt_fw_search,rpt_fw,rpt_fw_name],[rpt_mac_search,rpt_mac,rpt_mac_name],[rpt_lin_search,rpt_lin,rpt_lin_name],[rpt_login_search,rpt_log,rpt_login_name]]
    elif parser_opt == "win":
        # Open windows report files for writing
        rpt_evt = open(rpt_evt_name,'a+', encoding='utf-8')
        rpt_fsfs = open(rpt_fsfs_name,'a+', encoding='utf-8')
        rpt_fsmft = open(rpt_fsmft_name,'a+', encoding='utf-8')
        rpt_fsusnjrnl = open(rpt_fsusnjrnl_name,'a+', encoding='utf-8')
        rpt_ih = open(rpt_ih_name,'a+', encoding='utf-8')
        rpt_pf = open(rpt_pf_name,'a+', encoding='utf-8')
        rpt_appc = open(rpt_appc_name,'a+', encoding='utf-8')
        rpt_reg = open(rpt_reg_name,'a+', encoding='utf-8')
        rpt_st = open(rpt_st_name,'a+', encoding='utf-8')
        rpt_per = open(rpt_per_name,'a+', encoding='utf-8')
        rpt_si = open(rpt_si_name,'a+', encoding='utf-8')
        rpt_av = open(rpt_av_name,'a+', encoding='utf-8')
        rpt_fw = open(rpt_fw_name,'a+', encoding='utf-8')
        rpt_log = open(rpt_login_name,'a+', encoding='utf-8')
        lofh = [[rpt_appc_search,rpt_appc,rpt_appc_name],[rpt_evt_search,rpt_evt,rpt_evt_name],[rpt_fsfs_search,rpt_fsfs,rpt_fsfs_name],[rpt_fsmft_search,rpt_fsmft,rpt_fsmft_name],[rpt_fsusnjrnl_search,rpt_fsusnjrnl,rpt_fsusnjrnl_name],[rpt_ih_search,rpt_ih,rpt_ih_name],[rpt_pf_search,rpt_pf,rpt_pf_name],[rpt_reg_search,rpt_reg,rpt_reg_name],[rpt_st_search,rpt_st,rpt_st_name],[rpt_per_search,rpt_per,rpt_per_name],[rpt_si_search,rpt_si,rpt_si_name],[rpt_av_search,rpt_av,rpt_av_name],[rpt_fw_search,rpt_fw,rpt_fw_name],[rpt_login_search,rpt_log,rpt_login_name]]
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

    # Run each search for each report (in parallel) and write the results to the report CSV files
    counter = 1
    counter2 = True
    mqueue = queue.Queue()
    #Open file and read to memory
    SuperTimeline_file = io.open(csv_file,'r', encoding='utf-8').readlines()
    # Create all threads to start
    threads =[]
    for terms in lofh:
        threads.append(threading.Thread(target = multi_thread_reports, args = (mqueue,SuperTimeline_file,terms)))

    [t.start() for t in threads]
    [t.join() for t in threads]

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

    # Print report not created messages
    print("\nDid not keep "+str(len(final_lor_nodata))+" Reports due to no matching data from SuperTimeline")
    mylogfile.writelines("\nDid not keep "+str(len(final_lor_nodata))+" Reports due to no matching data from SuperTimeline\n")
    for item in final_lor_nodata:
        print("Report not kept: "+ item)
        mylogfile.writelines("Report not kept:" + item + "\n")

    # Print report created messages
    print("\nCreated "+str(len(final_lor))+" Reports.  Now improving them")
    mylogfile.writelines("\nCreated "+str(len(final_lor))+" Reports.")



    # Function to improve reports (in parallel)
    if parser_opt == "win":
        report_improvements(lor,mylogfile)


    print("\nAll reporting complete")
    mylogfile.writelines("\nAll reporting complete\n")
    end_dt = datetime.datetime.now()
    duration02 = end_dt - start_dt
    print("Reporting ended at: "+str(end_dt))
    print("Reporting duration was: "+str(duration02))
    mylogfile.writelines("Reporting ended at: "+str(end_dt)+"\n")
    mylogfile.writelines("Reporting duration was: "+str(duration02)+"\n")
    return


def plaso_version(log2timeline_location):
    myproc = subprocess.Popen([log2timeline_location,"--version"],stderr=subprocess.PIPE)
    output,err = myproc.communicate()
    pver = ".".join(str(err).split(" ")[-1].split(".")[0:2])
    return(pver)

def output_elasticsearch(mylogfile,srcfilename,casename,psort_location):
    # Run psort against plaso db file to output to an ElasticSearch server running on the localhost
    print("Exporting results in Kibana format to the ElasticSearch server")
    mylogfile.writelines("Exporting results in Kibana format to the ElasticSearch server\n")

    # Create command to run
    # SAMPLE: psort.py -o elastic --raw_fields --index_name case_test output.db 
    command = [psort_location,"-o","elastic","--raw_fields","--index_name","case_cdqr-"+casename.lower(), srcfilename]
    
    print("\""+"\" \"".join(command)+"\"")
    mylogfile.writelines("\""+"\" \"".join(command)+"\""+"\n")

    # Execute Command
    status_marker(mylogfile,subprocess.Popen(command,stdout=mylogfile,stderr=mylogfile))
    
    print("All entries have been inserted into database with case: "+"case_cdqr-"+casename.lower())
    mylogfile.writelines("All entries have been inserted into database with case: "+"case_cdqr-"+casename.lower()+"\n")

def output_elasticsearch_ts(mylogfile,srcfilename,casename,psort_location):
    # Run psort against plaso db file to output to an ElasticSearch server running on the localhost
    print("Exporting results in TimeSketch format to the ElasticSearch server")
    mylogfile.writelines("Exporting results in TimeSketch format to the ElasticSearch server\n")

    # Create command to run
    # SAMPLE: psort.py -o timesketch --name demo --index case_cdqr-demo demo.db
    command = [psort_location,"-o","timesketch","--name",casename.lower(),"--index",casename.lower(), srcfilename]

    print("\""+"\" \"".join(command)+"\"")
    mylogfile.writelines("\""+"\" \"".join(command)+"\""+"\n")

    # Execute Command
    status_marker(mylogfile,subprocess.Popen(command,stdout=mylogfile,stderr=mylogfile))

    print("All entries have been inserted into TimeSketch database with case: "+casename.lower())
    mylogfile.writelines("All entries have been inserted into TimeSketch database with case: "+casename.lower()+"\n")

def zip_source(inputfile,outputzip):
    try:
        with zipfile.ZipFile(outputzip,"w") as zip_ref:
            zip_ref.write(inputfile, compress_type=compression)
        return
    except Exception as e: 
        print("Unable to compress file: "+inputfile)
        print(e)
        sys.exit(1)

def unzip_source(src_loc_tmp,outputzipfolder):
    try:
        with zipfile.ZipFile(src_loc_tmp,"r") as zip_ref:
            if sys.platform[0:3] == "win":
                zip_ref.extractall(u'\\\\?\\'+os.path.abspath(outputzipfolder))
            else:
                zip_ref.extractall(os.path.abspath(outputzipfolder))
        return outputzipfolder
    except Exception as e: 
        print("Unable to extract file: "+src_loc_tmp)
        print(e)
        sys.exit(1)

def create_export(dst_loc,srcfilename,mylogfile,db_file,psort_location):
    # Create Output filenames
    dstrawfilename = dst_loc+"/"+srcfilename.split("/")[-1]+".json"
    dstfilename = dst_loc+"/"+srcfilename.split("/")[-1]+".json.zip"
    if os.path.exists(dstfilename):
        if query_yes_no("\n"+dstfilename+" already exists.  Would you like to delete that file?","no"):
            os.remove(dstfilename)

    # Run psort against plaso db file to output a file in line delimited json format
    print("Creating json line delimited file")
    mylogfile.writelines("Creating json line delimited file\n")

    # Create command to run
    command = [psort_location,"-o","json_line", db_file,"-w",dstrawfilename]
    
    print("\""+"\" \"".join(command)+"\"")
    mylogfile.writelines("\""+"\" \"".join(command)+"\""+"\n")

    # Execute Command
    status_marker(mylogfile,subprocess.Popen(command,stdout=mylogfile,stderr=mylogfile))
    
    print("Json line delimited file created")
    mylogfile.writelines("Json line delimited file created"+"\n")
    print("Adding Json line delimited file to "+dstfilename)
    mylogfile.writelines("Adding Json line delimited file to "+dstfilename+"\n")
    mylogfile.writelines("Adding " + dstrawfilename + " to "+ dstfilename +"\n")

    # Compresse the file for export
    zip_source(dstrawfilename,dstfilename)
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

###################### REPORT FIXING SECTION ###############################

def prefetch_report_fix(row):
    header_desc_rows = report_header_dict['Prefetch Report.csv'][0][0]
    header_extra_rows = report_header_dict['Prefetch Report.csv'][1][0]

    if row[5] == "WinPrefetch":
        search_desc = re.compile(r'Prefetch \[(.{1,200})\](.{1,20}) - run count (\d{1,10})( (path): (.{1,200})|) (hash): (.{1,15}) (volume): (\d{1,10}) \[(serial number): (.{1,20})  (device path): (.+)\]')
        search_extra = re.compile(r'(md5_hash): (.{1,100})  (number_of_volumes): (\d{1,10})  (version): (\d{1,10})  (volume_device_paths): \[u.(.{1,100}).\]  (volume_serial_numbers): \[(.+)\]')
    else:
        search_desc = re.compile(r'(.{1,200}) (Serial number): (.{1,15}) (Origin): (.+)')
        search_extra = re.compile(r'(md5_hash): (.+) ')
    
    search_results_desc = re.search(search_desc,row[header_desc_rows])

    if row[5] == "WinPrefetch": 
        if search_results_desc:
            if search_results_desc.group(4) == '':
                row[header_desc_rows] = search_results_desc.group(1)+","+search_results_desc.group(3)+",,"+search_results_desc.group(8)+","+search_results_desc.group(10)+","+search_results_desc.group(12)+","+search_results_desc.group(14)+","
            else:
                row[header_desc_rows] = search_results_desc.group(1)+","+search_results_desc.group(3)+","+search_results_desc.group(6)+","+search_results_desc.group(8)+","+search_results_desc.group(10)+","+search_results_desc.group(12)+","+search_results_desc.group(14)+","

        search_results_extra = re.search(search_extra,row[header_extra_rows]) # 'md5_hash','number_of_volumes','version','volume_device_paths','volume_serial_numbers'
        if search_results_extra:
            row[header_extra_rows] = search_results_extra.group(2)+","+search_results_extra.group(4)+","+search_results_extra.group(6)+","+search_results_extra.group(8)+","+search_results_extra.group(10)
    else:
        if search_results_desc: 
            row[header_desc_rows] = ",,,,"+search_results_desc.group(1)+","+search_results_desc.group(3)+",,"+search_results_desc.group(5)

        search_results_extra = re.search(search_extra,row[header_extra_rows])
        if search_results_extra:
            row[header_extra_rows] = search_results_extra.group(2)+",,,,"

    row[12] = row[12].replace('OS:','')
    return row

def appcompat_report_fix(row):
    header_desc_rows = report_header_dict['Appcompat Report.csv'][0][0]
    search_desc = re.compile(r'\[(.{1,100})\] (Cached entry): (\d+) (Path): (.+)')

    header_extra_rows = report_header_dict['Appcompat Report.csv'][1][0]
    search_extra = re.compile(r'(md5_hash): (.{1,50})')
    search_results_desc = re.search(search_desc,row[header_desc_rows])
    if search_results_desc:
        row[header_desc_rows] = search_results_desc.group(1)+","+search_results_desc.group(3)+","+search_results_desc.group(5)+","+search_results_desc.group(5).split('\\')[-1]

    search_results_extra = re.search(search_extra,row[header_extra_rows])
    if search_results_extra:
        row[header_extra_rows] = search_results_extra.group(2).strip()

    row[12] = row[12].replace('OS:','')
    return row

def event_log_report_fix(row): #'Event Log Report.csv':[[10,['event_id','EID_desc','record_number','event_level','source_name','computer_name','message']]
    header_desc_rows = report_header_dict['Event Log Report.csv'][0][0]
    header_extra_rows = report_header_dict['Event Log Report.csv'][1][0]
    if row[4] == "EVT":
        search_desc = re.compile(r'\[(.{1,8}) /.{1,100} (Record Number): (.{1,10}) (Event Level): (.{1,10}) (Source Name): (.{1,300}) (Computer Name): (.{1,100}) (Strings|Message string): (\[(.+)\]|.+)')
        search_extra = re.compile(r'(md5_hash): (.{1,50}) (message_identifier): (.{1,20}) (recovered): (True|False)  (strings_parsed): ({}  (user_sid): (.{1,75}) (xml_string): (.+)|.+)')

        search_results_desc = re.search(search_desc,row[header_desc_rows])
        if search_results_desc:
            try:
                eventlog_string = eventlog_dict[search_results_desc.group(1)]
            except:
                eventlog_string = ""
            row[header_desc_rows] = search_results_desc.group(1)+","+eventlog_string+","+search_results_desc.group(3)+","+search_results_desc.group(5)+","+search_results_desc.group(7)+","+search_results_desc.group(9)+","+((str(search_results_desc.group(12))).replace("\r", " ")).replace("\n", " ")
        search_results_extra = re.search(search_extra,row[header_extra_rows])
        if search_results_extra:
            row[header_extra_rows] = search_results_extra.group(2)+","+search_results_extra.group(4)+","+search_results_extra.group(6)+","+search_results_extra.group(8)+","+str(search_results_extra.group(10))+","+((str(search_results_extra.group(12))).replace("\r", " ")).replace("\n", " ")
    else:
        if row[header_desc_rows] != "desc":
            row[header_desc_rows] = ",,,,,,"
            row[header_extra_rows] = ",,,,,"
    row[12] = row[12].replace('OS:','')
    return row

def scheduled_tasks_report_fix(row):
    header_desc_rows = report_header_dict['Scheduled Tasks Report.csv'][0][0]
    search_desc = re.compile(r'(\[(.{1,200})\] (Task): (.{1,200}): \[(ID): \{(.{1,100})\}\]|(Task): (.{1,200}) \[(Identifier): \{(.{1,100})\}\])')

    header_extra_rows = report_header_dict['Scheduled Tasks Report.csv'][1][0]
    search_extra = re.compile(r'(md5_hash): (.+) ')

    search_results_desc = re.search(search_desc,row[header_desc_rows])
    if search_results_desc:
        if search_results_desc.group(1)[0:4] == "Task":
            row[header_desc_rows] = ","+search_results_desc.group(8)+","+search_results_desc.group(10)
        else:
            row[header_desc_rows] = search_results_desc.group(2)+","+search_results_desc.group(4)+","+search_results_desc.group(6)
    
    search_results_extra = re.search(search_extra,row[header_extra_rows])
    if search_results_extra:
        row[header_extra_rows] = search_results_extra.group(2)
    
    return row


def file_system_report_fix(row):
    if row[0] is not "" and row[0] is not "--":
        header_desc_rows = report_header_dict['File System Report.csv'][0][0]
        FS_search_desc = re.compile(r'(..):(.{1,500})(Type):(.{1,100})')

        header_extra_rows = report_header_dict['File System Report.csv'][1][0]
        FS_search_extra = re.compile(r'(file_size): \((.{1,50}) \)  (file_system_type): (.{1,20})  (is_allocated): (True|False)(  (md5_hash): (.+) |)')

        search_results_desc = re.search(FS_search_desc,row[header_desc_rows])
        if search_results_desc:
            row[header_desc_rows] = search_results_desc.group(2)+","+search_results_desc.group(4)
        search_results_extra = re.search(FS_search_extra,row[header_extra_rows])

        if search_results_extra:
            if search_results_extra.group(7) != '':
                row[header_extra_rows] = search_results_extra.group(2)+","+search_results_extra.group(4)+","+search_results_extra.group(6)+","+search_results_extra.group(9)
            else:
                row[header_extra_rows] = search_results_extra.group(2)+","+search_results_extra.group(4)+","+search_results_extra.group(6)+","
        return row
    else:
        return ["","","","","","","","","","","","","","","","","","","","",""]


def mft_report_fix(row):
    header_desc_rows = report_header_dict['MFT Report.csv'][0][0]
    header_extra_rows = report_header_dict['MFT Report.csv'][1][0]

    if row[4] == "FILE":
        search_desc = re.compile(r'(.{1,100}) (File reference): (.{1,100}) (Attribute name): (\$STANDARD_INFORMATION|\$FILE_NAME)( |)((Name): (.{1,200}) (Parent file reference): (.+)|(\((unallocated)|))')
        search_extra = re.compile(r'(attribute_type): (.{1,20}) (file_attribute_flags): (.{1,20}) (file_system_type): (.{1,20}) (is_allocated): (True|False)  (md5_hash): (.+) ')
    else:
        search_desc = re.compile(r'((.{1,100}) (MAC address): (.{1,20}) (Origin): (.+))')
        search_extra = re.compile(r'(md5_hash): (.+) ')
    
    search_results_desc = re.search(search_desc,row[header_desc_rows])

    if row[4] == "FILE":
        if search_results_desc:
            if search_results_desc.group(5) == "$FILE_NAME":
                row[header_desc_rows] = search_results_desc.group(3)+","+search_results_desc.group(5)+","+search_results_desc.group(9)+","+search_results_desc.group(11).rstrip(r" (unallocated)")+","
            else:
                row[header_desc_rows] = search_results_desc.group(3)+","+search_results_desc.group(5)+",,,"

        search_results_extra = re.search(search_extra,row[header_extra_rows])
        if search_results_extra:
            row[header_extra_rows] = search_results_extra.group(2)+","+search_results_extra.group(4)+","+search_results_extra.group(6)+","+search_results_extra.group(8)+","+search_results_extra.group(10)
    else:
        if search_results_desc:
            row[header_desc_rows] = ",,,,"+search_results_desc.group(1)

        search_results_extra = re.search(search_extra,row[header_extra_rows])
        if search_results_extra:
            row[header_extra_rows] = search_results_extra.group(2)


    row[12] = row[12].replace('OS:','')

    return row




def fix_line(row, report_name):
    if report_name == 'File System Report.csv':
        del row[9]
        del row[10]
        del row[11]
        del row[11]
        del row[10]
    elif report_name == 'Scheduled Tasks Report.csv':
        del row[9]
        del row[12]
        del row[12]
        del row[11]
    elif report_name == 'Event Log Report.csv':
        del row[9]
        del row[12]
        del row[12]
        del row[10]
    elif report_name == 'Appcompat Report.csv':
        del row[3]
        del row[3]
        del row[3]
        del row[4]
        del row[4]
        del row[4]
        del row[5]
        del row[5]
        del row[5]
        del row[5]
    elif report_name == 'MFT Report.csv':
        del row[9]
        del row[12]
        del row[12]
        del row[10]
    elif report_name == 'Prefetch Report.csv':
        del row[9]
        del row[12]
        del row[12]
        del row[10]
    return row

# Report Dictionary (by OS)


report_header_dict = {
    'Appcompat Report.csv':[[10,['source','cached_entry_order','full_path','filename']],[16,['md5_hash']],appcompat_report_fix],
    'Event Log Report.csv':[[10,['event_id','EID_desc','record_number','event_level','source_name','computer_name','message']],[16,['md5_hash','message_id','recovered','strings_parsed','user_sid','xml_string']],event_log_report_fix],
    'File System Report.csv':[[10,['filename','Type']],[16,['file_size','file_system_type','is_allocated','md5_hash']],file_system_report_fix],
    'MFT Report.csv':[[10,['File_reference','Attribute_name','Name','Parent_file_reference','Log_info']],[16,['attribute_type','file_attribute_flags','file_system_type','is_allocated','md5_hash']],mft_report_fix],
#    'UsnJrnl Report.csv':[],
#    'Internet History Report.csv':[],
    'Prefetch Report.csv':[[10,['File_name','Run_count','path','hash','volume','Serial number','Device_path','Origin']],[16,['md5_hash','number_of_volumes','version','volume_device_paths','volume_serial_numbers']],prefetch_report_fix],
#    'Registry Report.csv':[],
    'Scheduled Tasks Report.csv':[[10,['key','task','identification']],[16,['md5_hash']],scheduled_tasks_report_fix],
#    'Persistence Report.csv':[],
#    'System Information Report.csv':[],
#    'AntiVirus Report.csv':[],
#    'Firewall Report.csv':[],
#    'Login Report.csv':[]
}


# Report Improvement Multi-threading
def multi_thread_report_improve(mqueue,mylogfile,report,report_name,tmp_report_name):
    output_list = []
    #mqueue.put(terms[1].writelines(line.replace("\n"," ").replace("\r"," ")+"\n"))
    with io.open(report, 'r', encoding='utf-8') as csvfile:
        print("Improving "+ str(report_name)+" (This will take a long time for large files)")
        mqueue.put(mylogfile.writelines("Improving "+ str(report_name)+" (This will take a long time for large files)"+"\n"))
        for trow in csvfile:
            row = trow.split(',')
            output_list.append((report_header_dict[report_name][2](row)))
        # Print Report to file
        newreport = open(tmp_report_name,'w', encoding='utf-8')
        for line in output_list:
            if line[10] == 'desc':
                for thing in report_header_dict[report_name]:
                    if isinstance(thing, list):
                        line[thing[0]] = ','.join(thing[1])
            mqueue.put(newreport.writelines(','.join(fix_line(line,report_name)).replace("\n"," ").replace("\r"," ")+"\n"))
        newreport.close()

        if os.stat(tmp_report_name).st_size != 0:
            mqueue.put(shutil.copyfile(tmp_report_name,report))
            mqueue.put(os.remove(tmp_report_name))
        print(str(report_name)+":    Complete")
        mqueue.put(mylogfile.writelines(str(report_name)+":    Complete"+"\n"))
    return

# Report Improvements Function
def report_improvements(lor,mylogfile):
    mqueue = queue.Queue()
    threads = []
    for report in lor:
        lonf = []
        report_name = report.split('/')[-1]
        tmp_report_name = os.path.dirname(report)+"/tmp_"+report_name+".csv"
        if tmp_report_name[0] == '/':
            tmp_report_name = tmp_report_name[1:]
        if report_name in report_header_dict:
            if os.path.exists(report):
                lonf.append([report,report_name,tmp_report_name])
        
        for nfile in lonf:
            threads.append(threading.Thread(target = multi_thread_report_improve, args = (mqueue,mylogfile,nfile[0],nfile[1],nfile[2])))

    [t.start() for t in threads]
    [t.join() for t in threads]
    return


# This processes the image using parser option selected and creates .db file
def parse_the_things(mylogfile,command1,db_file,unzipped_file,unzipped_file_loc,csv_file):
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
                    if sys.platform[0:3] == "win":
                        shutil.rmtree(u'\\\\?\\'+os.path.abspath(rpt_dir_name))
                    else:
                        shutil.rmtree(rpt_dir_name)
        else:
            print("Keeping the existing file: "+db_file)
            mylogfile.writelines("Keeping the existing file: "+db_file)
            return

    # Process image with log2timeline
    start_dt = datetime.datetime.now()
    print("Processing started at: "+str(start_dt))
    mylogfile.writelines("Processing started at: "+str(start_dt)+"\n")
    print("Parsing image")
    mylogfile.writelines("Parsing image"+"\n")
    print("\""+"\" \"".join(command1)+"\"")
    mylogfile.writelines("\""+"\" \"".join(command1)+"\""+"\n")
    ######################  Log2timeline Command Execute  ##########################
    status_marker(mylogfile,subprocess.Popen(command1,stdout=mylogfile,stderr=mylogfile))

    end_dt = datetime.datetime.now()
    duration01 = end_dt - start_dt
    print("Parsing ended at: "+str(end_dt))
    mylogfile.writelines("Parsing ended at: "+str(end_dt)+"\n")
    print("Parsing duration was: "+str(duration01))
    mylogfile.writelines("Parsing duration was: "+str(duration01)+"\n")
    # Removing uncompressed file(s)
    if unzipped_file:
        print("\nRemoving uncompressed files in directory: "+unzipped_file_loc)
        mylogfile.writelines("\nRemoving uncompressed files in directory: "+unzipped_file_loc+"\n")
        if sys.platform[0:3] == "win":
            shutil.rmtree(u'\\\\?\\'+os.path.abspath(unzipped_file_loc))
        else:
            shutil.rmtree(unzipped_file_loc)

    return

def create_supertimeline(mylogfile,csv_file,psort_location,db_file):
    # This processes the .db file creates the SuperTimeline
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
            mylogfile.writelines("Keeping the existing file: "+csv_file)
            return
    command2 = [psort_location,"-o","l2tcsv","--status_view","linear",db_file,"-w",csv_file]
    # Create SuperTimeline
    print("\nCreating the SuperTimeline CSV file")
    mylogfile.writelines("\nCreating the SuperTimeline CSV file"+"\n")
    print("\""+"\" \"".join(command2)+"\"")
    mylogfile.writelines("\""+"\" \"".join(command2)+"\""+"\n")
    ######################  Psort Command Execute  ##########################
    status_marker(mylogfile,subprocess.Popen(command2,stdout=mylogfile,stderr=mylogfile))
    print("SuperTimeline CSV file is created")
    mylogfile.writelines("SuperTimeline CSV file is created\n")
    return

def export_to_elasticsearch(mylogfile,args,db_file,psort_location):
    start_dt = datetime.datetime.now()
    print("\nProcess to export to ElasticSearch started")
    mylogfile.writelines("\nProcess to export to ElasticSearch started"+"\n")
    if args.es_kb:
        output_elasticsearch(mylogfile,db_file,args.es_kb[0],psort_location)
    else:
        output_elasticsearch_ts(mylogfile,db_file,args.es_ts[0],psort_location)
    end_dt = datetime.datetime.now()
    duration03 = end_dt - start_dt
    print("\nProcess to export to ElasticSearch completed")
    mylogfile.writelines("\nProcess to export to ElasticSearch completed"+"\n")
    print("ElasticSearch export process duration was: "+str(duration03))
    mylogfile.writelines("ElasticSearch export process duration was: "+str(duration03)+"\n")
    return

def export_to_json(dst_loc,srcfilename,mylogfile,db_file,psort_location):
    # Export Data (if selected)
    print("\nProcess to create export document started")
    mylogfile.writelines("\nProcess to create export document started"+"\n")
    # Create the file for export 
    exportfname = create_export(dst_loc,srcfilename,mylogfile,db_file,psort_location)
    print("Process to create export document complete")
    mylogfile.writelines("Process to create export document complete"+"\n")

    end_dt = datetime.datetime.now()
    duration03 = end_dt - start_dt
    print("Creating export document process duration was: "+str(duration03))
    mylogfile.writelines("Creating export document process duration was: "+str(duration03)+"\n")
    return

def unzip_files(dst_loc,src_loc):
    unzipped_file_loc = dst_loc+"/artifacts/"+src_loc.split("/")[-1][:-4]
    print("Attempting to extract source file: "+src_loc)
    src_loc = unzip_source(src_loc,unzipped_file_loc)
    print("All files extracted to folder: "+src_loc)
    return src_loc

####################### END FUNCTIONS ############################

##################  EXECTUTION SECTION ############################
def main():
    # Default Parser option
    default_parser = "win"
    unzipped_file = False
    unzipped_file_loc = ""


    # Plaso Program Locations (default)
    if sys.platform[0:3] == "win":
        log2timeline_location = r"plaso\log2timeline.exe"
        psort_location = r"plaso\psort.exe"
    else:
        log2timeline_location = r"log2timeline.py"
        psort_location = r"psort.py"

    # Parsing begins
    parser_list = ["win","lin","mac","datt"]

    parser = argparse.ArgumentParser(description='Cold Disk Quick Response Tool (CDQR)')
    parser.add_argument('src_location',nargs=1,help='Source File location: Y:/Case/Tag009/sample.E01')
    parser.add_argument('dst_location',nargs='?',default='Results',help='Destination Folder location. If nothing is supplied then the default is \'Results\'')
    parser.add_argument('-p','--parser', nargs=1,help='Choose parser to use.  If nothing chosen then \'win\' is used.  The parsing options are: '+', '.join(parser_list))
    parser.add_argument('--nohash', action='store_true', default=False, help='Do not hash all the files as part of the processing of the image')
    parser.add_argument('--max_cpu', action='store_true', default=False, help='Use the maximum number of cpu cores to process the image')
    parser.add_argument('--export', action='store_true' , help='Creates zipped, line delimited json export file')
    parser.add_argument('--es_kb', nargs=1,help='Outputs Kibana format to local elasticsearch database. Requires index name. Example: \'--es_kb my_index\'')
    parser.add_argument('--es_ts', nargs=1,help='Outputs TimeSketch format to local elasticsearch database. Requires index/timesketch name. Example: \'--es_ts my_name\'')
    parser.add_argument('--plaso_db', action='store_true', default=False,help='Process an existing Plaso DB file. Example: artifacts.db OR artifacts.plaso')
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
        command1 = [log2timeline_location,"-p","--partition","all","--vss_stores","all","--status_view","linear"]

    # Set log2timeline parsing option(s)
        if args.parser:
            if args.parser[0] not in parser_list:
                print("ERROR: \""+args.parser[0]+ "\" is not a valid parser selection.")
                print("ERROR: Valid parser options are: " + ', '.join(parser_list))
                print("ERROR: Please verify your command and try again.")
                print("Exiting...")
                sys.exit(1)
            parser_opt = args.parser[0]
            # if parser_opt == "datt":
            #     command1 = [log2timeline_location, "-p"]
            if parser_opt == "lin" or parser_opt == "mac":
                command1 = [log2timeline_location,"-p","--partition","all","--status_view","linear"]
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
        src_loc = src_loc.replace("\\\\","/").replace("\\","/").rstrip("/")
        if src_loc.count("/") > 1:
            src_loc = src_loc.rstrip("/")

        if not os.path.exists(src_loc):
            print("ERROR: \""+src_loc+"\" cannot be found by the system.  Please verify command.")
            print("Exiting...")
            sys.exit(1)
        
    # Set destination location/file
        dst_loc = args.dst_location.replace("\\\\","/").replace("\\","/").rstrip("/")

        if os.path.exists(dst_loc):
            if not query_yes_no("\n"+dst_loc+" already exists.  Would you like to use that directory anyway?","yes"):
                dst_loc = dst_loc+"_"+datetime.datetime.now().strftime("%d-%b-%y_%H-%M-%S")
                os.makedirs(dst_loc)
        else:
            os.makedirs(dst_loc)

        print("Destination Folder: "+dst_loc)
        log_list.append("Destination Folder: "+dst_loc+"\n")

        if args.z:
            unzipped_file = True
            src_loc = unzip_files(dst_loc,src_loc)
            unzipped_file_loc = dst_loc+"/artifacts/"
        elif src_loc[-4:].lower() == ".zip":
            if query_yes_no("\n"+src_loc+" appears to be a zip file.  Would you like CDQR to unzip it and process the contents?","yes"):
                unzipped_file = True
                src_loc = unzip_files(dst_loc,src_loc)
                unzipped_file_loc = dst_loc+"/artifacts/"

        print("Source data: "+src_loc)
        log_list.append("Source data: "+src_loc+"\n")

    # Create DB, CSV and Log Filenames
    if args.plaso_db:
        db_file = dst_loc+"/"+src_loc
    else:
        db_file = dst_loc+"/"+src_loc.split("/")[-1]+".db"
    csv_file = dst_loc+"/"+src_loc.split("/")[-1]+".SuperTimeline.csv"
    logfilename = dst_loc+"/"+src_loc.split("/")[-1]+".log"

    # Check to see if it's a mounted drive and update filename if so
    if db_file == dst_loc+"/.db" or db_file[-4:] == ":.db":
        db_file = dst_loc+"/"+"mounted_image.db"
        csv_file = dst_loc+"/"+"mounted_image.SuperTimeline.csv"
        logfilename = dst_loc+"/"+"mounted_image.log"

    print("Log File: "+ logfilename)
    print("Database File: "+ db_file)
    print("SuperTimeline CSV File: "+ csv_file)

    log_list.append("Log File: "+ logfilename+"\n")
    log_list.append("Database File: "+db_file+"\n")
    log_list.append("SuperTimeline CSV File: "+ csv_file+"\n")

    command1.append(db_file)
    command1.append(src_loc)

    if os.path.isfile(logfilename):
        os.remove(logfilename)

    mylogfile = open(logfilename,'w')
    mylogfile.writelines("".join(log_list))

    start_dt = datetime.datetime.now()
    print("\nTotal start time was: "+str(start_dt))
    mylogfile.writelines("\nStart time  was: "+str(start_dt)+"\n")

    # If this is plaso database file, skip parsing
    if args.plaso_db:
        print("WARNING: File must be plaso database file otherwise it will not work.  Example: artifact.db (from CDQR)")
        mylogfile.writelines("\nWARNING: File must be plaso database file otherwise it will not work.  Example: artifact.db (from CDQR)"+"\n")
        db_file = src_loc
    else:
        parse_the_things(mylogfile,command1,db_file,unzipped_file,unzipped_file_loc,csv_file)

    if args.export:
        export_to_json(dst_loc,src_loc,mylogfile,db_file,psort_location)
    elif args.es_kb or args.es_ts:
        export_to_elasticsearch(mylogfile,args,db_file,psort_location)
    else:
        create_supertimeline(mylogfile,csv_file,psort_location,db_file)
        create_reports(mylogfile,dst_loc,csv_file,parser_opt)

    end_dt = datetime.datetime.now()
    duration_full = end_dt - start_dt
    print("\nTotal duration was: "+str(duration_full))
    mylogfile.writelines("\nTotal duration was: "+str(duration_full)+"\n")
    mylogfile.close()


if __name__ == "__main__":
    main()