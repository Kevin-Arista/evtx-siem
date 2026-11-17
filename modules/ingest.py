import duckdb
from evtx import PyEvtxParser
from pathlib import Path
import xxhash

temp_file = "temp.ndjson"

init_table = """
        CREATE TABLE IF NOT EXISTS events (
                provider        VARCHAR        NOT NULL,
                event_id        UBIGINT        NOT NULL,
                timestamp       TIMESTAMP      NOT NULL,
                record_id       UBIGINT        NOT NULL,
                channel         VARCHAR        NOT NULL,
                computer        VARCHAR        NOT NULL,
                event_data      JSON           DEFAULT NULL,
                user_data      JSON           DEFAULT NULL
        );
"""

insert_logs = """
        INSERT INTO events BY NAME
        SELECT 
                Event->'System'->'Provider'->'#attributes'->>'Name' AS provider,
                (Event->'System'->>'EventID')::UBIGINT AS event_id,
                (Event->'System'->'TimeCreated'->'#attributes'->>'SystemTime')::TIMESTAMP AS timestamp,
                (Event->'System'->>'EventRecordID')::UBIGINT AS record_id,
                Event->'System'->>'Channel' AS channel,
                Event->'System'->>'Computer' AS computer,
                Event->>'EventData' AS event_data,
                Event->>'UserData' AS user_data
        FROM read_json(?, format = 'newline_delimited', auto_detect=false, columns={Event:'JSON'});
"""

def parsing(log_name: str) -> None:
        parser = PyEvtxParser(log_name)
        with open(temp_file, "w", encoding="utf-8") as fd:
                for log in parser.records_json():
                        fd.write(log["data"] + "\n")


def normalize(logs_dir_path: str, database_path: str) -> list:
        logs_normalized = []
        # cycle through all folders
        with duckdb.connect(database_path) as con:
                con.execute(init_table)

                dir = Path(logs_dir_path)
                if dir.is_dir():
                        for log_file in dir.iterdir():
                                if log_file.is_file() and log_file.suffix == ".evtx":
                                        parsing(str(log_file))
                                        con.execute(insert_logs, [temp_file])
                                        logs_normalized.append(log_file.name)
                        
                        Path(temp_file).unlink(missing_ok=True)
                        print("Successfully inserted: ", logs_normalized)
                        return logs_normalized                        
                else:
                        print("Not A Valid Dir")
                
        

if __name__ == "__main__":
        normalize("../evtx/siem_sample/", "../db/siem.duckdb")