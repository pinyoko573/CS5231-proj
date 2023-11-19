import sys
import re
import traceback
 
filtered_log_dict = {}
 
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
 
# PATH logs only appear if the syscall has items!=0
# It represents the information of the file path referred by syscall args
def handlePath(log):
    audit_id, log_content = getAuditId(log)
    assert audit_id is not None and log_content is not None, "handlePath() should not be executed after getAuditId() error"
 
    log_content_dict = convertLogContentToDict(log_content)
 
    if audit_id in filtered_log_dict:
        filtered_log_dict[audit_id].update({ "path"+log_content_dict["item"] : log_content_dict["name"] })
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
 
def main():
    # Check if the file path is provided as a command-line argument
    if len(sys.argv) != 2:
        print("Usage: python3 file_processor.py <file_path>")
        return
 
    # Extract the file path from the command-line argument
    file_path = sys.argv[1]
 
    try:
        # Open the file in read mode
        with open(file_path, "r") as log_file:
            # Read each line and process it
            for line_number, log in enumerate(log_file, start=1):
                process_log(log)
        print(filtered_log_dict)
 
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")
        traceback.print_exc()
 
if __name__ == "__main__":
    main()
