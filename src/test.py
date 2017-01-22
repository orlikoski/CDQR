#!/usr/bin/python3
import io, os, sys, argparse, subprocess, csv, time, datetime, re, multiprocessing, gzip, shutil, zipfile

lor = ['Results/Reports/Event Log Report.csv', 'Results/Reports/File System Report.csv', 'Results/Reports/MFT Report.csv', 'Results/Reports/UsnJrnl Report.csv', 'Results/Reports/Internet History Report.csv', 'Results/Reports/Prefetch Report.csv', 'Results/Reports/Registry Report.csv', 'Results/Reports/Scheduled Tasks Report.csv', 'Results/Reports/Persistence Report.csv', 'Results/Reports/System Information Report.csv', 'Results/Reports/AntiVirus Report.csv', 'Results/Reports/Firewall Report.csv', 'Results/Reports/Login Report.csv']
#lor = ['Results/Reports/Event Log Report.csv']
#lor = ['Results/Reports/File System Report.csv']


report_header_dict = {
    'Event Log Report.csv':[[10,['event_id','record_number','event_level','source_name','computer_name','message']],[16,['md5_hash','message_id','recovered','strings_parsed','user_sid','xml_string']]],
    'File System Report.csv':[[10,['filename','Type']],[16,['md5_hash']]],
    'MFT Report.csv':[],
    'UsnJrnl Report.csv':[],
    'Internet History Report.csv':[],
    'Prefetch Report.csv':[],
    'Registry Report.csv':[],
    'Scheduled Tasks Report.csv':[[10,['key','task','identifcation']],[16,['md5_hash']]],
    'Persistence Report.csv':[],
    'System Information Report.csv':[],
    'AntiVirus Report.csv':[],
    'Firewall Report.csv':[],
    'Login Report.csv':[]
}

def event_log_report_fix(row):
    header_desc_rows = report_header_dict['Event Log Report.csv'][0][0]
    search_desc = re.compile(r'\[(.{1,8}) /.{1,100} (Record Number): (.{1,10}) (Event Level): (.{1,5}) (Source Name): (.{1,200}) (Computer Name): (.{1,100}) (Strings|Message string): (\[(.+)\]|.+)')

    header_extra_rows = report_header_dict['Event Log Report.csv'][1][0]
    search_extra = re.compile(r'(md5_hash): (.{1,50}) (message_identifier): (.{1,5}) (recovered): (True|False)  (strings_parsed): ({}  (user_sid): (.{1,75}) (xml_string): (.+)|.+)')

    search_results_desc = re.search(search_desc,row[header_desc_rows])
    if search_results_desc:
        row[header_desc_rows] = search_results_desc.group(1)+","+search_results_desc.group(3)+","+search_results_desc.group(5)+","+search_results_desc.group(7)+","+search_results_desc.group(9)+","+str(search_results_desc.group(12))
    search_results_extra = re.search(search_extra,row[header_extra_rows])
    if search_results_extra:
        row[header_extra_rows] = search_results_extra.group(2)+","+search_results_extra.group(4)+","+search_results_extra.group(6)+","+search_results_extra.group(8)+","+str(search_results_extra.group(10))+","+str(search_results_extra.group(12))
    row[12] = row[12].replace('OS:','')
    return row

def scheduled_tasks_report_fix(row):
    header_desc_rows = report_header_dict['Scheduled Tasks Report.csv'][0][0]
    search_desc = re.compile(r'(\[(.{1,200})\] (Task): (.{1,200}): \[(ID): \{(.{1,100})\}\]|(Task): (.{1,200}) \[(Identifier): \{(.{1,100})\}\])')

    header_extra_rows = report_header_dict['Scheduled Tasks Report.csv'][1][0]
    search_extra = re.compile(r'(md5_hash): (.+)')

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
    FS_search_extra = re.compile(r'(file_size): \((\d{1,50}) \)  (file_system_type): (OS)  (is_allocated): (True|False)(  (md5_hash): (.+)|)')

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

def fix_line(row, report_name):
    if report_name == 'File System Report.csv':
        del row[9]
        del row[12]
        del row[12]
        del row[11]
    elif report_name == 'Scheduled Tasks Report.csv':
        del row[9]
        del row[12]
        del row[12]
        del row[11]
    elif report_name == 'Event Log Report.csv':
        del row[9]
        del row[12]
        del row[12]
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
                print("    Updating Report")
                for trow in csvfile:
                    row = trow.split(',')
                    if report_name == 'File System Report.csv':
                        output_list.append((file_system_report_fix(row)))
                    elif report_name == 'Scheduled Tasks Report.csv':
                        output_list.append((scheduled_tasks_report_fix(row)))
                    elif report_name == 'Event Log Report.csv':
                        output_list.append((event_log_report_fix(row)))
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