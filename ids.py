# ids.py
from collections import Counter, defaultdict
from kamene.all import sniff
import utils
import config
from scapy.config import conf
from datetime import datetime, timedelta
from scapy.layers.http import HTTPRequest, HTTPResponse

rst_counter = Counter()
packet_counter = Counter()
syn_counter = Counter()
sql_injection_counter = Counter()
port_scan_counter = defaultdict(set)
ping_sweep_counter = Counter()
arp_spoofing_counter = Counter()
dns_tunneling_counter = Counter()
ddos_counter = Counter()
null_xmas_fin_scan_counter = Counter()
packet_time = defaultdict(lambda: datetime.now())
same_type_port_counter = defaultdict(int)
utils.setup_logging()

conf.ipv6_enabled = False


def handle_syn_flood(packet):
    try:
        if packet.haslayer('TCP') and packet['TCP'].flags == 'S':
            syn_counter[packet['IP'].src] += 1
            if syn_counter[packet['IP'].src] > config.SYN_FLOOD_THRESHOLD:
                generate_alert(packet, 'SYN flood attack detected')
    except Exception as e:
        utils.log_error(f"Error in handle_syn_flood: {str(e)}")


def handle_ddos(packet):
    try:
        if packet.haslayer('IP'):
            source_ip, dst_ip, proto = packet['IP'].src, packet['IP'].dst, packet['IP'].proto
            same_type_port_counter[(source_ip, dst_ip, proto)] += 1
            if same_type_port_counter[(source_ip, dst_ip, proto)] > config.DDOS_THRESHOLD:
                generate_alert(packet, 'DDOS attack detected')
    except Exception as e:
        utils.log_error(f"Error in handle_ddos: {str(e)}")


def handle_nmap_scan(packet):
    try:
        if packet.haslayer('TCP') and packet['TCP'].flags == 'R':
            rst_counter[packet['IP'].src] += 1
            if rst_counter[packet['IP'].src] > config.RST_THRESHOLD:
                generate_alert(packet, 'Possible nmap SYN scan detected')
    except Exception as e:
        utils.log_error(f"Error in handle_nmap_scan: {str(e)}")


def handle_sql_injection(packet):
    try:
        if packet.haslayer('TCP') and packet.haslayer('Raw'):
            for pattern in config.SQL_INJECTION_PATTERNS:
                if pattern in str(packet['Raw'].load):
                    sql_injection_counter[packet['IP'].src] += 1
                    if sql_injection_counter[packet['IP'].src] > config.SQL_INJECTION_THRESHOLD:
                        generate_alert(packet, 'SQL injection attack detected')
                    break
    except Exception as e:
        utils.log_error(f"Error in handle_sql_injection: {str(e)}")



def handle_scan_attack(packet):
    try:
        if packet.haslayer('TCP'):
            flags = packet['TCP'].flags
            if flags == 'F' or flags == 'FPU' or flags == '':  # FIN scan or Xmas scan or Null scan
                null_xmas_fin_scan_counter[packet['IP'].src] += 1
                if null_xmas_fin_scan_counter[packet['IP'].src] > config.NULL_XMAS_FIN_SCAN_THRESHOLD:
                    generate_alert(packet, 'Null, Xmas or FIN scanning attack detected')
    except Exception as e:
        utils.log_error(f"Error in handle_scan_attack: {str(e)}")


def handle_port_scan(packet):
    try:
        if packet.haslayer('TCP'):
            port_scan_counter[packet['IP'].src].add(packet['TCP'].dport)  # For TCP packets
            if len(port_scan_counter[packet['IP'].src]) > config.PORT_SCAN_THRESHOLD:
                generate_alert(packet, 'Port scanning attack detected')
        elif packet.haslayer('UDP'):
            port_scan_counter[packet['IP'].src].add(packet['UDP'].dport)  # For UDP packets
            if len(port_scan_counter[packet['IP'].src]) > config.PORT_SCAN_THRESHOLD:
                generate_alert(packet, 'Port scanning attack detected')
    except Exception as e:
        utils.log_error(f"Error in handle_port_scan: {str(e)}")


def handle_ping_sweep(packet):
    try:
        if packet.haslayer('ICMP') and packet['ICMP'].type == 8:  # ICMP echo request
            ping_sweep_counter[packet['IP'].src] += 1
            if ping_sweep_counter[packet['IP'].src] > config.PING_SWEEP_THRESHOLD:
                generate_alert(packet, 'Ping sweep attack detected')
    except Exception as e:
        utils.log_error(f"Error in handle_ping_sweep: {str(e)}")



def handle_arp_spoofing(packet):
    try:
        if packet.haslayer('ARP') and packet['ARP'].op == 2:  # ARP response
            arp_spoofing_counter[packet['ARP'].psrc] += 1
            if arp_spoofing_counter[packet['ARP'].psrc] > config.ARP_SPOOFING_THRESHOLD:
                generate_alert(packet, 'ARP spoofing attack detected')
    except Exception as e:
        utils.log_error(f"Error in handle_arp_spoofing: {str(e)}")


def handle_dns_tunneling(packet):
    try:
        if packet.haslayer('DNS'):
            dns_tunneling_counter[packet['IP'].src] += 1
            if dns_tunneling_counter[packet['IP'].src] > config.DNS_TUNNELING_THRESHOLD:
                generate_alert(packet, 'DNS tunneling attack detected')
    except Exception as e:
        utils.log_error(f"Error in handle_dns_tunneling: {str(e)}")

def handle_http(packet):
    try:
        if packet.haslayer(HTTPRequest):
            http_layer = packet.getlayer(HTTPRequest)
            print("\n\n[+] HTTP Request\n")
            print("Host:", http_layer.Host)
            print("Path:", http_layer.Path)
            print("Method:", http_layer.Method)
            print("Headers:", http_layer.fields)

        elif packet.haslayer(HTTPResponse):
            http_layer = packet.getlayer(HTTPResponse)
            print("\n\n[+] HTTP Response\n")
            print("Status Code:", http_layer.Status_Code)
            print("Status Phrase:", http_layer.Status_Phrase)
            print("Headers:", http_layer.fields)
            print("Server:", http_layer.Server)
            if "text/html" in http_layer.fields["Content-Type"]:
                print("Content:", http_layer.load.decode(errors="replace"))
    except Exception as e:
        utils.log_error(f"Error in handle_http: {str(e)}")


def packet_handler(packet):
    try:
        print(packet.summary())
        if packet.haslayer('IP'):
            source_ip = packet['IP'].src
            packet_counter[source_ip] += 1
            current_time = datetime.now()

            if packet_time[source_ip] + timedelta(minutes=1) < current_time:
                packet_time[source_ip] = current_time
                packet_counter[source_ip] = 0

            handle_syn_flood(packet)
            handle_ddos(packet)
            handle_nmap_scan(packet)
            handle_sql_injection(packet)
            handle_scan_attack(packet)
            handle_port_scan(packet)
            handle_ping_sweep(packet)
            handle_arp_spoofing(packet)
            handle_dns_tunneling(packet)
            handle_http(packet)
    except Exception as e:
        utils.log_error(f"Error in packet_handler: {str(e)}")


def generate_alert(packet, message):
    source_ip = packet['IP'].src
    destination_ip = packet['IP'].dst
    alert_message = f'{message} from {source_ip} to {destination_ip}'

    # Reset counters based on the type of alert
    if 'SYN flood attack detected' in message:
        syn_counter[packet['IP'].src] = 0
    elif 'SQL injection attack detected' in message:
        sql_injection_counter[packet['IP'].src] = 0
    elif 'Port scanning attack detected' in message:
        port_scan_counter[packet['IP'].src].clear()
    elif 'Ping sweep attack detected' in message:
        ping_sweep_counter[packet['IP'].src] = 0
    elif 'ARP spoofing attack detected' in message:
        arp_spoofing_counter[packet['ARP'].psrc] = 0
    elif 'DNS tunneling attack detected' in message:
        dns_tunneling_counter[packet['IP'].src] = 0
    elif 'Null, Xmas or FIN scanning attack detected' in message:
        null_xmas_fin_scan_counter[packet['IP'].src] = 0
    elif 'DDOS attack detected' in message:
        same_type_port_counter[(source_ip, packet['IP'].dst, packet['IP'].proto)] = 0

    utils.log_info(alert_message)
    utils.send_email_alert(alert_message)

    packet_counter[packet['IP'].src] = 0

def main():
    try:
        sniff(prn=packet_handler)
    except Exception as e:
        utils.log_error(f"Error in sniff: {str(e)}")

if __name__ == "__main__":
    main()