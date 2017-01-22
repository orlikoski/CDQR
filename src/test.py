#!/usr/bin/python3
import io, os, sys, argparse, subprocess, csv, time, datetime, re, multiprocessing, gzip, shutil, zipfile

#lor = ['Results/Reports/Event Log Report.csv', 'Results/Reports/File System Report.csv', 'Results/Reports/MFT Report.csv', 'Results/Reports/UsnJrnl Report.csv', 'Results/Reports/Internet History Report.csv', 'Results/Reports/Prefetch Report.csv', 'Results/Reports/Registry Report.csv', 'Results/Reports/Scheduled Tasks Report.csv', 'Results/Reports/Persistence Report.csv', 'Results/Reports/System Information Report.csv', 'Results/Reports/AntiVirus Report.csv', 'Results/Reports/Firewall Report.csv', 'Results/Reports/Login Report.csv']
lor = ['Results/Reports/File System Report.csv']

report_header_dict = {
    'Event Log Report.csv':[],
    'File System Report.csv':[[10,['filename','Type']],[16,['file_size','file_system_type','is_allocated','md5_hash']]],
    'MFT Report.csv':[],
    'UsnJrnl Report.csv':[],
    'Internet History Report.csv':[],
    'Prefetch Report.csv':[],
    'Registry Report.csv':[],
    'Scheduled Tasks Report.csv':[],
    'Persistence Report.csv':[],
    'System Information Report.csv':[],
    'AntiVirus Report.csv':[],
    'Firewall Report.csv':[],
    'Login Report.csv':[]
}

def scheduled_tasks_report_fix(row):
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
    return row

def report_improvements(lor):
    for report in lor:
        output_list = []
        report_name = report.split('/')[-1]
        tmp_report_name = os.path.dirname(report)+"/tmp_report.csv"
        if tmp_report_name[0] == '/':
            tmp_report_name = tmp_report_name[1:]
        if os.path.exists(report):
            with open(report, 'r') as csvfile:
                for row in csv.reader(csvfile, delimiter=','):
                    if report.endswith('File System Report.csv'):
                        output_list.append((file_system_report_fix(row)))

            # Print Report to file
            newreport = open(tmp_report_name,'a+', encoding='utf-8')
            #writer = csv.writer(newreport,delimiter=',')
            for line in output_list:
                if line[10] == 'desc':
                    for thing in report_header_dict[report_name]:
                        line[thing[0]] = ','.join(thing[1])
                #line = fix_line(line,report_name)
                newreport.writelines(','.join(fix_line(line,report_name))+"\n")
            newreport.close()
            shutil.copyfile(tmp_report_name,report)
            os.remove(tmp_report_name)


# print(report_header_dict['File System Report.csv'][0])
# print(report_header_dict['File System Report.csv'][1])
# sys.exit(1)
report_improvements(lor)