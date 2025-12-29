import os
import sys
import mysql.connector
from dotenv import load_dotenv
from datetime import datetime
import re
import time
import tailer

# Load environment variables from .env file
load_dotenv()

def connect_to_db():
    """Establishes a connection to the MySQL database."""
    print("Attempting to connect to the database...")
    while True:
        try:
            conn = mysql.connector.connect(
                host=os.getenv("MYSQL_HOST"),
                user=os.getenv("MYSQL_USER"),
                password=os.getenv("MYSQL_PASSWORD"),
                database=os.getenv("MYSQL_DATABASE"),
                charset='utf8'
            )
            if conn.is_connected():
                print("Successfully connected to the database!")
                return conn
            else:
                print("Failed to establish a connection to the database.")
                return None
        except mysql.connector.Error as err:
            print(f"Error connecting to the database: {err}")
            print("Please check your database credentials, host, and port settings.")
            time.sleep(5)

def process_log_line(line):
    """
    Parses a single log line, extracting domain and IP from 'reply' entries.
    Handles both A (IPv4) and AAAA (IPv6) records.
    """
    # Pattern for reply with A or AAAA records
    match = re.search(r'reply (.*?) is (.*)$', line)
    if match:
        domain = match.group(1).strip()
        response_ip = match.group(2).strip()
        timestamp = datetime.now()
        
        # Check if the response is a CNAME
        if response_ip == '<CNAME>':
            # This is a CNAME, the next line will contain the actual IP
            return None
        
        return {
            'timestamp': timestamp,
            'query_type': 'reply', # We know this is a reply now
            'domain': domain,
            'source_ip': 'N/A', # We can't get this from 'reply' lines
            'response_ip': response_ip
        }
    return None

def insert_dns_record(conn, record):
    """Inserts a new DNS record into the database, avoiding duplicates."""
    cursor = None
    try:
        cursor = conn.cursor()
        
        # Check if a domain already exists in the table.
        sql_check = "SELECT EXISTS(SELECT 1 FROM dns_queries WHERE domain = %s LIMIT 1)"
        cursor.execute(sql_check, (record['domain'],))
        if cursor.fetchone()[0]:
            print(f"Domain '{record['domain']}' already exists. Skipping insert.")
            return
            
        sql = """
        INSERT INTO dns_queries (timestamp, query_type, domain, source_ip, response_ip)
        VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(sql, (
            record['timestamp'],
            record['query_type'],
            record['domain'],
            record['source_ip'],
            record['response_ip']
        ))
        conn.commit()
        print(f"Inserted new DNS reply: {record['domain']} -> {record['response_ip']}")
    except Exception as e:
        print(f"Error while inserting record: {e}")
        conn.rollback()
    finally:
        if cursor:
            cursor.close()

def main():
    log_file_path = "/var/log/dns/dns.log"
    conn = connect_to_db()

    if not conn:
        print("Failed to connect to the database. Exiting...")
        sys.exit(1)

    print(f"Starting to monitor the file {log_file_path} for 'reply' entries...")

    try:
        if not os.path.exists(log_file_path) or os.stat(log_file_path).st_size == 0:
            print("Log file is empty or does not exist. Waiting for new lines...")

        with open(log_file_path, 'r') as log_file:
            for line in tailer.follow(log_file):
                record = process_log_line(line)
                if record:
                    insert_dns_record(conn, record)

    except FileNotFoundError:
        print(f"Log file not found at {log_file_path}. Make sure the volume is mounted correctly.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if conn:
            conn.close()
            print("Database connection closed.")

if __name__ == "__main__":
    main()