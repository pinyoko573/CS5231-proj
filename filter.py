import sys
import re
import traceback
from datetime import datetime
import csv
import syscall_dictionary #syscall_dictionary.py

filtered_log_dict = {}
processid_to_auditids_dict = {}
interested_process_ids = [] # Might have duplicates
syscall_dict = syscall_dictionary.syscall_dict
pid_dict = {}

pid_data = [] # For CSV
path_data = [] # For CSV
syscall_data = [] # For CSV

##### FUNCTIONS CALLS FOR PROCESSING LOGS INTO DATA STRUCTURES #####

def process_log(log):
    if log.startswith("type=SYSCALL"):
        handleSyscall(log)
        return
    if log.startswith("type=PROCTITLE"):
        handleProctitle(log)
        return
    if log.startswith("type=PATH"):
        handlePath(log)
        return
    if log.startswith("type=EXECVE"):
        handleExecve(log)
        return
    # print(log)

def getAuditId(log):
    # Define the regular expression pattern to get the timestamp and key
    pattern = r"msg=audit\((?P<audit_id>[\d.:]+)\): (?P<log_content>.*)"

    # Match the pattern in the line
    match = re.search(pattern, log)

    # If a match is found, extract the values
    if match:
        audit_id = match.group("audit_id")
        log_content = match.group("log_content")
        return audit_id, log_content
    else:
        raise ValueError("The log format is not recognised. Log: " + log)
    return None, None

def convertLogContentToDict(log_content):
    # Split key-value pairs by spaces
    pairs_list = log_content.split()

    # Create a dictionary to hold all fields of the log
    log_content_dict = {}
    for pair in pairs_list:
        key, value = pair.split('=', 1)
        # Remove wrapping quotation marks
        if value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        log_content_dict[key] = value

    return log_content_dict

def handleProctitle(log):
    audit_id, log_content = getAuditId(log)
    assert audit_id is not None and log_content is not None, "handleProctitle() should not be executed after getAuditId() error"

    log_content_dict = convertLogContentToDict(log_content)

    if audit_id in filtered_log_dict:
        filtered_log_dict[audit_id].update(log_content_dict)
    else:
        filtered_log_dict[audit_id] = log_content_dict

def handleSyscall(log):
    audit_id, log_content = getAuditId(log)
    assert audit_id is not None and log_content is not None, "handleSyscall() should not be executed after getAuditId() error"

    log_content_dict = convertLogContentToDict(log_content)

    # Add the log content as a value to the main dictionary
    filtered_log_dict[audit_id] = log_content_dict

    # Add the audit_id to processid_to_auditids_dict
    process_id = log_content_dict["pid"]
    if process_id in processid_to_auditids_dict:
        processid_to_auditids_dict[process_id].append(audit_id)
    else:
        processid_to_auditids_dict[process_id] = [audit_id]

    # NOTE: To add other interested processes below (those that we want to build provenance graph for)
    # Check if syscall is the interested syscall (access to secret.txt)
    if log_content_dict["key"] == "CUSTOM_SECRET_FILE":
        interested_process_ids.append(process_id)
        
    # Add pid to the pid tree
    if process_id not in pid_dict:
        pid_dict[process_id] = log_content_dict["ppid"]

# PATH logs only appear if the syscall has items!=0
# It represents the information of the file path referred by syscall args
def handlePath(log):
    audit_id, log_content = getAuditId(log)
    assert audit_id is not None and log_content is not None, "handlePath() should not be executed after getAuditId() error"

    log_content_dict = convertLogContentToDict(log_content)

    if audit_id in filtered_log_dict:
        filtered_log_dict[audit_id].update({ "path"+log_content_dict["item"] : log_content_dict["name"] })
        path_data.append({"log_id":audit_id.split(':')[1], "filepath":log_content_dict["name"]})
    else:
        # AFAIK, this cannot happen. PATH always come after SYSCALL, so entry must exists
        raise ValueError("PATH log exists without SYSCALL log. Log: " + log)

# EXECVE logs only appear if the syscall has syscall=59 (apparently)
# It represents the full commands executed by execve()
def handleExecve(log):
    audit_id, log_content = getAuditId(log)
    assert audit_id is not None and log_content is not None, "handleExecve() should not be executed after getAuditId() error"

    log_content_dict = convertLogContentToDict(log_content)

    if audit_id in filtered_log_dict:
        execve_string = ""
        execve_string_length = int(log_content_dict["argc"])
        for i in range(execve_string_length):
            execve_string = execve_string + " " + log_content_dict["a"+ str(i)]
        filtered_log_dict[audit_id].update({"execve" : execve_string})
    else:
        # AFAIK, this cannot happen. EXECVE always come after SYSCALL, so entry must exists
        raise ValueError("EXECVE log exists without SYSCALL log. Log: " + log)

##### FUNCTIONS CALLS FOR PRINTING INFORMATION FROM DATA STRUCTURE #####
def printSeparator():
    print("======================================================")

def printSmallSeparator():
    print("**********")

def getReadableTime(timestamp_string):
    # Split the timestamp and microseconds
    timestamp, microseconds = map(float, timestamp_string.split(':'))

    # Convert seconds to datetime
    dt_object = datetime.utcfromtimestamp(timestamp)

    return str(dt_object)

def getArguments(log_entry):
    count = 0
    arguments = ""
    while 'a'+str(count) in log_entry:
         arguments += log_entry['a'+str(count)] + ", "
         count += 1
    if count != 0: 
        return arguments[:-2]
    return ""

def printBeautifiedLog(audit_id):
    log_dict = filtered_log_dict[audit_id]
    print("Involved syscall: %s" % syscall_dict[int(log_dict['syscall'])])
    print("Time: %s" % getReadableTime(audit_id))
    print("Executable: %s" % log_dict['exe'])
    
    # To print syscall arguments
    arguments = getArguments(log_dict)
    if arguments != "": 
        print("Arguments: %s" % arguments)
    
    # To print paths if exists
    argument_paths = ""
    paths_count = int(log_dict['items'])
    for i in range(paths_count):
        argument_paths += log_dict['path'+str(i)] + ", "
    if paths_count != 0:
        print("File paths in arguments: %s" % argument_paths[:-2])
        
    # To print execve string if exists
    if 'execve' in log_dict: 
        print("Execve command: %s" % log_dict['execve'])
    
    print("Audit ID: %s" % audit_id)
    
def printAllLogs(process_id):
    count = 1
    for audit_id in processid_to_auditids_dict[process_id]:
        printSmallSeparator()
        print("[Syscall " + str(count) + "]")
        printBeautifiedLog(audit_id)
        count += 1
    printSmallSeparator()

def printInterestedProcessesInfo():
    for process_id in interested_process_ids:
        printSeparator()
        print("Process ID: " + process_id)
        printAllLogs(process_id)
    printSeparator()

##### FUNCTIONS CALLS FOR GENERATING CSV DATA FOR NEO4J #####
def makeCsvFile(file_path, header, data):
    with open(file_path, mode="w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=header)
        writer.writeheader()
        writer.writerows(data)

def getSyscallCsvFile():
    for log_key, log_value in filtered_log_dict.items(): 
        log_id = log_key.split(':')[1]
        pid = log_value['pid']
        syscall = syscall_dict[int(log_value['syscall'])]
        key = log_value['key']
        arguments = getArguments(log_value)
        if log_value['syscall'] == '59' and log_value['success'] == 'yes':
            arguments = log_value['execve']
        syscall_data.append({"log_id":log_id, "pid":pid, "syscall":syscall, "key":key, "arguments":arguments})
    csv_file_path = "syscall.csv"
    header = ["log_id", "pid", "syscall", "key", "arguments"]
    makeCsvFile(csv_file_path, header, syscall_data)

def getPathCsvFile():
    csv_file_path = "path.csv"
    header = ["log_id", "filepath"]
    makeCsvFile(csv_file_path, header, path_data)
    
def getPidCsvFile():
    for pid, ppid in pid_dict.items():
        path = ""
        name = ""
        for audit_id in processid_to_auditids_dict[pid]:
            log_dict = filtered_log_dict[audit_id]
            if log_dict['syscall'] == "59":
                path = log_dict['exe']
                name = log_dict['comm']
                break
        pid_data.append({"pid":pid, "ppid":ppid, "name":name, "path":path})
    
    csv_file_path = "pid.csv"
    header = ["pid", "ppid", "name", "path"]
    makeCsvFile(csv_file_path, header, pid_data)

def getCsvFiles():
    getSyscallCsvFile()
    getPathCsvFile()
    getPidCsvFile()

def convertLog(file_path):
    # Check if the file path is provided as a command-line argument
    # if len(sys.argv) != 2:
    #     print("Usage: python3 file_processor.py <file_path>")
    #     return

    # Extract the file path from the command-line argument
    # file_path = sys.argv[1]

    try:
        # Open the file in read mode
        with open(file_path, "r") as log_file:
            # Read each line and process it
            for line_number, log in enumerate(log_file, start=1):
                process_log(log)

        #### UNCOMMENT THE BELOW 3 prints() TO VIEW THE DATA STRUCTURE ####
        # print(filtered_log_dict)
        # print(processid_to_auditids_dict)
        # print(interested_process_ids)

        # At this point, the log has been added into data structure
        # And we know all the audit_ids called by a process_id
        # And we have a list of the interested process_ids

        # To print the syscalls information called by our interested process
        printInterestedProcessesInfo()
        getCsvFiles()

    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")
        traceback.print_exc()

# if __name__ == "__main__":
#     convertLog()
