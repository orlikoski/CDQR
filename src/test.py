#!/usr/bin/python3
import io, os, sys, argparse, subprocess, csv, time, datetime, re, multiprocessing, gzip, shutil, zipfile

#lor = ['Results_new/Reports/Appcompat Report.csv','Results_new/Reports/Event Log Report.csv', 'Results_new/Reports/File System Report.csv', 'Results_new/Reports/MFT Report.csv', 'Results_new/Reports/UsnJrnl Report.csv', 'Results_new/Reports/Internet History Report.csv', 'Results_new/Reports/Prefetch Report.csv', 'Results_new/Reports/Registry Report.csv', 'Results_new/Reports/Scheduled Tasks Report.csv', 'Results_new/Reports/Persistence Report.csv', 'Results_new/Reports/System Information Report.csv', 'Results_new/Reports/AntiVirus Report.csv', 'Results_new/Reports/Firewall Report.csv', 'Results_new/Reports/Login Report.csv']
#lor = ['Results_new/Reports/Event Log Report.csv']
lor = ['Results_new/Reports/Event Log Report.csv']


report_header_dict = {
    'Appcompat Report.csv':[[10,['source','cached_entry_order','full_path','filename']],[16,['md5_hash']]],
    'Event Log Report.csv':[[10,['event_id','record_number','event_level','source_name','computer_name','message']],[16,['md5_hash','message_id','recovered','strings_parsed','user_sid','xml_string']]],
    'File System Report.csv':[[10,['filename','Type']],[16,['file_size','file_system_type','is_allocated','md5_hash']]],
    'MFT Report.csv':[[10,['File_reference','Attribute_name','Name','Parent_file_reference','Log_info']],[16,['attribute_type','file_attribute_flags','file_system_type','is_allocated','md5_hash']]],
    'UsnJrnl Report.csv':[],
    'Internet History Report.csv':[],
    'Prefetch Report.csv':[[10,['File_name','Run_count','path','hash','volume','Serial number','Device_path','Origin']],[16,['md5_hash','number_of_volumes','version','volume_device_paths','volume_serial_numbers']]],
    'Registry Report.csv':[], # Do this one next
    'Scheduled Tasks Report.csv':[[10,['key','task','identification']],[16,['md5_hash']]],
    'Persistence Report.csv':[],
    'System Information Report.csv':[],
    'AntiVirus Report.csv':[],
    'Firewall Report.csv':[],
    'Login Report.csv':[]
}

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

def event_log_report_fix(row):
    header_desc_rows = report_header_dict['Event Log Report.csv'][0][0]
    header_extra_rows = report_header_dict['Event Log Report.csv'][1][0]
    if row[4] == "EVT":
        search_desc = re.compile(r'\[(.{1,8}) /.{1,100} (Record Number): (.{1,10}) (Event Level): (.{1,5}) (Source Name): (.{1,200}) (Computer Name): (.{1,100}) (Strings|Message string): (\[(.+)\]|.+)')
        search_extra = re.compile(r'(md5_hash): (.{1,50}) (message_identifier): (.{1,20}) (recovered): (True|False)  (strings_parsed): ({}  (user_sid): (.{1,75}) (xml_string): (.+)|.+)')

        search_results_desc = re.search(search_desc,row[header_desc_rows])
        if search_results_desc:
            row[header_desc_rows] = search_results_desc.group(1)+","+search_results_desc.group(3)+","+search_results_desc.group(5)+","+search_results_desc.group(7)+","+search_results_desc.group(9)+","+((str(search_results_desc.group(12))).replace("\r", " ")).replace("\n", " ")
        
        search_results_extra = re.search(search_extra,row[header_extra_rows])
        if search_results_extra:
            row[header_extra_rows] = search_results_extra.group(2)+","+search_results_extra.group(4)+","+search_results_extra.group(6)+","+search_results_extra.group(8)+","+str(search_results_extra.group(10))+","+((str(search_results_extra.group(12))).replace("\r", " ")).replace("\n", " ")
    else:
        row[header_desc_rows] = ",,,,,"
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
    header_desc_rows = report_header_dict['File System Report.csv'][0][0]
    FS_search_desc = re.compile(r'(..):(.{1,200})(Type):(.{1,100})')

    header_extra_rows = report_header_dict['File System Report.csv'][1][0]
    FS_search_extra = re.compile(r'(file_size): \((\d{1,50}) \)  (file_system_type): (OS)  (is_allocated): (True|False)(  (md5_hash): (.+) |)')

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

def report_improvements(lor):
    for report in lor:
        output_list = []
        report_name = report.split('/')[-1]
        tmp_report_name = os.path.dirname(report)+"/tmp_report.csv"
        if tmp_report_name[0] == '/':
            tmp_report_name = tmp_report_name[1:]
        if os.path.exists(report):
            with io.open(report, 'r', encoding='utf-8') as csvfile:
                print("Report Name:", report_name)
                print("    Updating Report (This will take a long time for large files)")
                for trow in csvfile:
                    row = trow.split(',')
                    if report_name == 'File System Report.csv':
                        output_list.append((file_system_report_fix(row)))
                    elif report_name == 'Scheduled Tasks Report.csv':
                        output_list.append((scheduled_tasks_report_fix(row)))
                    elif report_name == 'Event Log Report.csv':
                        output_list.append((event_log_report_fix(row)))
                    elif report_name == 'Appcompat Report.csv':
                        output_list.append((appcompat_report_fix(row)))
                    elif report_name == 'MFT Report.csv':
                        output_list.append((mft_report_fix(row)))
                    elif report_name == 'Prefetch Report.csv':
                        output_list.append((prefetch_report_fix(row)))
            # Print Report to file
            newreport = open(tmp_report_name,'w', encoding='utf-8')
            for line in output_list:
                if line[10] == 'desc':
                    for thing in report_header_dict[report_name]:
                        line[thing[0]] = ','.join(thing[1])
                newreport.writelines(','.join(fix_line(line,report_name))+"\n")
            newreport.close()
            if os.stat(tmp_report_name).st_size != 0:
                shutil.copyfile(tmp_report_name,report)
                os.remove(tmp_report_name)
            print("    Complete")
report_improvements(lor)