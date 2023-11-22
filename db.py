from neo4j import GraphDatabase

def exportdb():
    # URI examples: "neo4j://localhost", "neo4j+s://xxx.databases.neo4j.io"
    URI = "neo4j://localhost:7687"
    AUTH = ("neo4j", "password")

    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        try:
            driver.verify_connectivity()

            # Initialize constraints
            driver.execute_query(
                "CREATE CONSTRAINT pidPidConstraint IF NOT EXISTS FOR (p:Pid) REQUIRE p.pid IS UNIQUE"
            )

            driver.execute_query(
                "CREATE CONSTRAINT syscallLogIdConstraint IF NOT EXISTS FOR (s:Syscall) REQUIRE s.log_id IS UNIQUE;"
            )

            # Load data and relationships
            # pid table
            driver.execute_query(
                "LOAD CSV WITH HEADERS FROM \"file:///home/student/Desktop/pid.csv\" AS csvLine " +
                "MERGE (p1:Pid {pid: toInteger(csvLine.pid)}) " +
                "ON CREATE SET p1.name = csvLine.name, p1.path = csvLine.path " +
                "MERGE (p2:Pid {pid: toInteger(csvLine.ppid)}) " +
                "MERGE (p2)-[:PARENT_OF]->(p1);"
            )

            # syscall table
            driver.execute_query(
                "LOAD CSV WITH HEADERS FROM \"file:///home/student/Desktop/syscall.csv\" AS csvLine " +
                "CREATE (s:Syscall {log_id: toInteger(csvLine.log_id), pid: toInteger(csvLine.pid), syscall: csvLine.syscall, key: csvLine.key, arguments: csvLine.arguments}) " +
                "WITH s " +
                "MATCH (p:Pid {pid : s.pid}) " +
                "CREATE (p)-[:INVOKE]->(s);"
            )

            # path table
            driver.execute_query(
                "LOAD CSV WITH HEADERS FROM \"file:///home/student/Desktop/path.csv\" AS csvLine " +
                "CREATE (p:path {log_id: toInteger(csvLine.log_id), filepath: csvLine.filepath}) " +
                "WITH p " +
                "MATCH (s:Syscall {log_id : p.log_id}) " +
                "CREATE (s)-[:ACCESS]->(p);"
            )

            driver.close()
        except Exception as e:
            print(e)
