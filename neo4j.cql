// Initialize constraints
CREATE CONSTRAINT pidPidConstraint IF NOT EXISTS FOR (p:Pid) REQUIRE p.pid IS UNIQUE;
CREATE CONSTRAINT syscallLogIdConstraint IF NOT EXISTS FOR (s:Syscall) REQUIRE s.log_id IS UNIQUE;

// Load data and relationships
LOAD CSV WITH HEADERS FROM "file:///pid.csv" AS csvLine
MERGE (p1:Pid {pid: toInteger(csvLine.pid)})
ON CREATE SET p1.name = csvLine.name, p1.path = csvLine.path
MERGE (p2:Pid {pid: toInteger(csvLine.ppid)})
MERGE (p2)-[:PARENT_OF]->(p1);

LOAD CSV WITH HEADERS FROM "file:///syscall.csv" AS csvLine
CREATE (s:Syscall {log_id: toInteger(csvLine.log_id), pid: toInteger(csvLine.pid), syscall: csvLine.syscall, key: csvLine.key, arguments: csvLine.arguments})
WITH s
MATCH (p:Pid {pid : s.pid})
CREATE (p)-[:INVOKE]->(s);

LOAD CSV WITH HEADERS FROM "file:///path.csv" AS csvLine
CREATE (p:path {log_id: toInteger(csvLine.log_id), filepath: csvLine.filepath})
WITH p
MATCH (s:Syscall {log_id : p.log_id})
CREATE (s)-[:ACCESS]->(p);

// ------------------------------------------------------------------
// Cypher query
// Show all child nodes from the name of the parent node
MATCH p=(pid:Pid {name:"run-attack.sh"})-[*]->(c)
RETURN p