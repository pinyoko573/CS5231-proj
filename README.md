# System Call Provenance Analysis

A tool that audits system calls made from a program using **auditd** and visualize the data into a provenance graph with **Neo4j**.<br>
As there can be too many syscalls invoked from a program, our tool only focuses on malicious syscalls that are mapped to [MITRE's Attack Framework](https://github.com/bfuzzy1/auditd-attack/blob/master/auditd-attack/auditd-attack.rules) in order to reduce log entries.<br>
Alternatively, you may also edit the configuration in auditd.rules

## Installation

The following tools are required:<br>
- auditd (sudo apt-get install auditd)
- [Neo4j Desktop](https://neo4j.com/download/)

On the Neo4j DBMS setting, comment out `server.directories.import=import` to allow importing of CSV files outside the neo4j directory.

If you would to test on a malicious program, remember to do it on a isolated sandbox.