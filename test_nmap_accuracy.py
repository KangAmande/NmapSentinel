import nmap
import pytest

def test_nmap_detects_open_port():
    nm = nmap.PortScanner()
    target_ip = '127.0.0.1'
    target_port = '8080'

    print(f"Scanning {target_ip} for open port {target_port}...")
    nm.scan(target_ip, target_port, arguments='-sv')
    port_state = nm[target_ip]['tcp'][int(target_port)]['state']
    service_name = nm[target_ip]['tcp'][int(target_port)]['name']

    