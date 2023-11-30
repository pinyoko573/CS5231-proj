# System Call Provenance Analysis

![program](https://github.com/pinyoko573/CS5231-proj/assets/87714995/f6a6d149-a539-42e7-a59c-3f0e7f96fc4c)<br>
![neo4j](https://github.com/pinyoko573/CS5231-proj/assets/87714995/390351f2-be06-45b4-8e46-b028339b8a2d)

A tool that audits system calls made from a program using **auditd** and visualize the data into a provenance graph with **Neo4j**.<br>
As there can be too many syscalls invoked from a program, our tool only focuses on malicious syscalls that are mapped to [MITRE's Attack Framework](https://github.com/bfuzzy1/auditd-attack/blob/master/auditd-attack/auditd-attack.rules) in order to reduce log entries.<br><br>
Alternatively, you may also edit the configuration, or define your own rules in auditd.rules.

## How it works

Make sure that neo4j is turned on. <br>
Launch the tool using the following command: `sudo python3 program.py <sample program path>`<br><br>

When the command is executed, existing log file in /var/log/audit/audit.log is deleted and the auditd service is restarted with the configured rules. The sample program is then loaded and if you wish to stop the auditd service, type `stop`. <br><br>

Logs are filtered and converted to 3 CSV files: syscall.csv, pid.csv and path.csv.<br>
These CSV files are used to import data into the Neo4j database, which you can view the provenance graph.

## Installation

The following tools are required:<br>
- auditd (sudo apt-get install auditd)
- [Neo4j Desktop](https://neo4j.com/download/)

### auditd

No further setup is required after installing.

### Neo4j

1. After installation, on the Neo4j DBMS setting, comment out `server.directories.import=import` to allow importing of CSV files outside the neo4j directory and start the Database instance.
2. After running your first sample, on Neo4j Bloom, navigate to Settings (top-left) > Saved Cypher > Add Search Phrase and paste this query (You can give any name for search phrase).

```
MATCH p=(pid:Pid {pid:<pid number that was returned in the program>})-[*]->(c)
RETURN p
```
or
```
MATCH p=(pid:Pid {name:<name of sample that was returned in the program>})-[*]->(c)
RETURN p
```
3. To visualise the nodes better, change the nodes into different colors.


| Node | Filter key | Size & Color |
| --- | --- | ----------- |
| Process (PID) | - | 4x Yellow Circle |
| Files Accessed (Path) | - | 2x Pink Circle |
| Syscall on sensitive configuration programs (e.g. setuid) | CONF_ | 2x Green Circle |
| Syscall on sensitive configuration files (e.g. passwd)  | CONFFILE_ | 2x Dark green Circle |
| Syscall on enumerative tools (e.g. Wireshark, netcat) | TOOL_ | 2x Grey circle |
| Sensitive system calls (e.g. settimeofday) | SYSCALL_ | 2x Purple circle |
| Commands from system call execve | CMD_ | 2x Blue circle |
| Custom user-defined rule  | CUSTOM_ | 4x Red Circle |

*For filter key, set it under Rule-based styling.
<br>

If you would to test on a malicious program, remember to do it on a isolated sandbox.<br>
Have fun!
