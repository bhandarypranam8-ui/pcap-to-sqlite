import os
import sqlite3
from scapy.all import IP, TCP, UDP, rdpcap


def init_db(db_name="pcap_database.db"):
  """Initializes the SQLite database and creates the packets table."""
  conn = sqlite3.connect(db_name)
  cursor = conn.cursor()
  cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            length INTEGER
        )
    """)
  conn.commit()
  conn.close()
  print(f"[+] Database '{db_name}' initialized successfully.")


def parse_pcap_to_sqlite(pcap_file, db_name="pcap_database.db"):
  """Reads a PCAP file, extracts packet details, and saves them into SQLite."""
  if not os.path.exists(pcap_file):
    print(f"[-] Error: PCAP file '{pcap_file}' not found.")
    return

  print(f"[*] Reading packets from '{pcap_file}'...")
  packets = rdpcap(pcap_file)

  conn = sqlite3.connect(db_name)
  cursor = conn.cursor()

  inserted_count = 0
  for pkt in packets:
    # Check if the packet has an IP layer
    if IP in pkt:
      src_ip = pkt[IP].src
      dst_ip = pkt[IP].dst
      length = len(pkt)
      protocol_name = "IP"
      src_port = None
      dst_port = None

      # Check for TCP or UDP layers to extract ports
      if TCP in pkt:
        protocol_name = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
      elif UDP in pkt:
        protocol_name = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

      # Insert parsed data into database
      cursor.execute(
          """
            INSERT INTO packets (src_ip, dst_ip, protocol, src_port, dst_port,"
          " length)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
          (src_ip, dst_ip, protocol_name, src_port, dst_port, length),
      )
      inserted_count += 1

  conn.commit()
  conn.close()
  print(
      f"[+] Success! Stored {inserted_count} packets into the SQLite database."
  )


if __name__ == "__main__":
  # Database file name
  database_name = "pcap_database.db"

  # Replace with the path to your actual PCAP file (e.g., 'traffic.pcap')
  pcap_filename = "sample.pcap"

  # Initialize DB and run parser
  init_db(database_name)
  parse_pcap_to_sqlite(pcap_filename, database_name)
