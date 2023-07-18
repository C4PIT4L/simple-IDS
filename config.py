# config.py


# IDS configuration
IDS_ALERT_THRESHOLD = 5  # Number of suspicious activities before an alert is generated
SYN_FLOOD_THRESHOLD = 100  # Number of SYN packets before an alert is generated
SQL_INJECTION_THRESHOLD = 10  # Number of SQL injection attempts before an alert is generated
PORT_SCAN_THRESHOLD = 1000  # Number of packets to different ports before an alert is generated
PING_SWEEP_THRESHOLD = 100  # Number of ICMP echo requests to different IP addresses before an alert is generated
ARP_SPOOFING_THRESHOLD = 10  # Number of ARP responses from the same IP address before an alert is generated
DNS_TUNNELING_THRESHOLD = 100  # Number of DNS requests from the same IP address before an alert is generated
RST_THRESHOLD = 100  # Number of RST packets before an alert is generated
DDOS_THRESHOLD = 5000  # Number of packets to the same destination IP before an alert is generated
NULL_XMAS_FIN_SCAN_THRESHOLD = 10  # Number of Null, Xmas, or FIN scans from the same IP address before an alert is generated

# SQL injection patterns
SQL_INJECTION_PATTERNS = [
    '"; DROP TABLE',
    '"; SELECT * FROM',
    '"; INSERT INTO',
    '"; DELETE FROM',
    '"; UPDATE ',
    '"; UNION ALL SELECT',
    '--',
    "' OR '1'='1",
    "' OR 'x'='x",
    '" OR "x"="x',
    "' OR 1 --",
    "' OR a=a --",
    '" OR "a"="a',
    "' OR 1=1 --",
    "' OR 'a'='a",
    "'='",
    "' LIKE '",
    "' OR 'a'='a",
    "' OR 'a'='a' --",
    "' OR 'a'='a' #",
    "' OR 'a'='a'/*",
    "' OR 1=1 #",
    "' OR 1=1/*",
    "' OR 1=1 --",
    "' OR 1=1",
    "' OR 1=1 --",
    "' OR 1=1/*",
    "' OR a=a",
    "' OR a=a --",
    "' OR a=a/*",
    "' OR 'a'='a",
    "' OR 'a'='a' --",
    "' OR 'a'='a'/*",
    '" OR "a"="a',
    '" OR "a"="a" --',
    '" OR "a"="a"/*',
    "' OR 1 --",
    '" OR 1 --',
    "' OR 'a'='a",
    "' OR 'a'='a' --",
    "' OR 'a'='a' #",
    "' OR 'a'='a'/*",
    "' OR 'a'='a' --",
    '" OR "a"="a',
    '" OR "a"="a" --',
    '" OR "a"="a"/*',
    "' OR 1=1 --",
    "' OR 1=1/*",
    "' OR 1=1 --",
    "' OR 1=1/*",
    "' OR a=a",
    "' OR a=a --",
    "' OR a=a/*",
    "' OR 'a'='a",
    "' OR 'a'='a' --",
    "' OR 'a'='a'/*",
    "' OR 'a'='a' --",
    '" OR "a"="a',
    '" OR "a"="a" --',
    '" OR "a"="a"/*',
    "' OR 'a'='a",
    "' OR 'a'='a' --",
    "' OR 'a'='a'/*",
    "' OR 'a'='a' --",
    '" OR "a"="a',
    '" OR "a"="a" --',
    '" OR "a"="a"/*',
]
