import os
import subprocess
import signal
import sys
from filter import convertLog
from db import exportdb, check_connection

program = None

def signal_handler(sig, frame):
    print('Killing the program...')
    program.kill()

def startAudit(program_path):
    # Stop auditd service and deleting logs
    print('Stopping the auditd service and deleting any existing audit logs...')
    subprocess.call(["sudo", "service", "auditd", "stop"])
    subprocess.call(["sudo", "rm", "-f", "/var/log/audit/audit.log"])

    # Backup current audit rules and replace with our rules
    print('Backing up current audit rules and loading our configuration...')
    subprocess.call(["sudo", "cp", "/etc/audit/rules.d/audit.rules", "/etc/audit/rules.d/audit_old.rules"])
    subprocess.call(["sudo", "cp", "audit.rules", "/etc/audit/rules.d/audit.rules"])

    # Start auditd service
    print('Starting auditd service...')
    subprocess.call(["sudo", "service", "auditd", "start"])

    # Execute the program given
    p = subprocess.Popen([program_path], shell=True)
    print('Sample program is now running!')
    print('Either wait for the program to end, or press Ctrl+C to terminate')
    
    return p

def stopAudit():
    # Stopping auditd service and move backup auditd rules
    print('Stopping auditd service and moving original audit rules...')
    subprocess.call(["sudo", "service", "auditd", "stop"])
    subprocess.call(["sudo", "mv", "/etc/audit/rules.d/audit_old.rules", "/etc/audit/rules.d/audit.rules"])

    # Converting logs into csv
    print('Converting logs to csv data...')
    convertLog("/var/log/audit/audit.log")

    # Inserting csv into neo4j database
    print('Exporting csv data to neo4j...')
    exportdb()

def main():
    global program

    # Check if the file path is provided as a command-line argument
    if len(sys.argv) != 2:
        print("Usage: python3 program.py <sample_program_path>")
        return
    
    # Sudo operations needed to start/stop service
    if os.geteuid() != 0:
        exit("Please run the program as sudo.")

    # Verify db connection
    try:
        check_connection()
    except Exception as e:
        exit(e)

    # Register Ctrl+C signal to kill sample program
    signal.signal(signal.SIGINT, signal_handler)

    # Start audit
    program = startAudit(sys.argv[1])
    file_name = sys.argv[1].split('/')[-1]
    pid = program.pid

    # Wait for the program to execute finish
    ret_value = program.wait()
    print(f'Sample program exited with code {ret_value}')

    # Stop audit
    stopAudit()

    print('You can now view the data in Neo4j Browser, or use the graph in Neo4j Bloom')
    print(f'The program that was executed has the file name {file_name}, pid {pid}')
    
if __name__ == "__main__":
    main()