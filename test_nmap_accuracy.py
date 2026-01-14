import nmap
import pytest

TARGET_IP = '127.0.0.1'
TARGET_PORT = '8080'

@pytest.fixture
def scanner():
    """Fixture to initialize the Nmap scanner for each test."""
    return nmap.PortScanner()

def test_nmap_detects_open_port(scanner):
    """
    AUDIT 1: Verify Nmap correctly sees the port as 'open'.
    Using '-sT -Pn' because Windows localhost can be tricky for raw packet scans.
    """
    print(f"\n[Testing] Auditing Nmap on {TARGET_IP}:{TARGET_PORT}...")
    
    # -sT: TCP Connect scan (reliable on Windows)
    # -Pn: Treat host as online (prevents Nmap from 'giving up' if ping fails)
    # -sV: Service Version detection
    scanner.scan(TARGET_IP, TARGET_PORT, arguments='-sT -Pn -sV')

    # Ensure the host exists in the results
    assert TARGET_IP in scanner.all_hosts(), "Host was not found in scan results!"
    
    # Get the reported state
    report = scanner[TARGET_IP]['tcp'][int(TARGET_PORT)]
    actual_state = report['state']

    print(f"[Result] Nmap reported state: {actual_state}")
    
    # Assertion
    assert actual_state == 'open', f"DEALBREAKER: Nmap missed an open port! Reported: {actual_state}"

def test_nmap_identifies_service_correctly(scanner):
    """
    AUDIT 2: Verify Nmap identifies the service as 'http'.
    """
    scanner.scan(TARGET_IP, TARGET_PORT, arguments='-sT -Pn -sV')
    
    service_name = scanner[TARGET_IP]['tcp'][int(TARGET_PORT)]['name']
    print(f"[Result] Nmap identified service as: {service_name}")

    assert 'http' in service_name, f"DEALBREAKER: Nmap misidentified the service! Found: {service_name}"