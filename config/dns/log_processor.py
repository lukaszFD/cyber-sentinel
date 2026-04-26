import os
import mysql.connector
from dotenv import load_dotenv
from datetime import datetime
import re
import tailer

load_dotenv()

def connect_to_db():
    try:
        conn = mysql.connector.connect(
            host=os.getenv("MYSQL_HOST"),
            user=os.getenv("MYSQL_USER"),
            password=os.getenv("MYSQL_PASSWORD"),
            database=os.getenv("MYSQL_DATABASE"),
            charset='utf8mb4'
        )
        return conn
    except Exception as e:
        print(f"Błąd połączenia z bazą: {e}")
        return None

def process_log_line(line):
    match = re.search(r'(query|reply)(?:\[([A-Z0-9]+)\])?\s+([^\s]+)\s+(?:is|from)\s+([^\s]+)', line)

    if match:
        action = match.group(1)
        r_type = match.group(2)
        domain = match.group(3).strip()
        val = match.group(4).strip()

        if not r_type:
            if val == 'NXDOMAIN':
                r_type = 'N/A'
            elif '.' in val and ':' not in val and val not in ['<CNAME>', 'NODATA']:
                r_type = 'A'
            elif ':' in val:
                r_type = 'AAAA'
            else:
                r_type = 'OTHER'
        return {
            'timestamp': datetime.now(),
            'query_type': action,
            'record_type': r_type,
            'domain': domain,
            'source_ip': val if action == 'query' else 'N/A',
            'response_ip': val if action == 'reply' else None
        }
    return None

def insert_dns_record(conn, record):
    cursor = None
    try:
        cursor = conn.cursor()
        sql = """
        INSERT INTO dns_queries (timestamp, query_type, record_type, domain, source_ip, response_ip)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(sql, (
            record['timestamp'],
            record['query_type'],
            record['record_type'],
            record['domain'],
            record['source_ip'],
            record['response_ip']
        ))
        conn.commit()
        print(f"DEBUG: [{record['record_type']}] {record['query_type'].upper()}: {record['domain']}")
    except Exception as e:
        print(f"ERROR: Insert failed: {e}")
        conn.rollback()
    finally:
        if cursor: cursor.close()

def main():
    log_file_path = "/var/log/dns/dns.log"
    conn = connect_to_db()
    if not conn: return

    print(f"Starting to monitor the file {log_file_path} for 'reply' entries...")

    with open(log_file_path, 'r') as log_file:
        for line in tailer.follow(log_file):
            record = process_log_line(line)
            if record:
                insert_dns_record(conn, record)

if __name__ == "__main__":
    main()