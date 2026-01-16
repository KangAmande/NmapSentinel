import nmap
import pytest

TARGET_IP = '127.0.0.1'
TARGET_PORT = '8080'
CLOSED_PORT = '9999'

@pytest.fixture
def scanner():
    """Fixture to initialize the Nmap scanner for each test."""
    return nmap.PortScanner()

def test_nse_http_title_extraction(scanner):
    """
    INTEL TEST: Can Nmap read the 'Welcome to nginx!' title?
    This tests Nmap's Scripting Engine (NSE) integration.
    """
    print("\n[Audit] Running NSE Script: http-title...")
    # --script=http-title asks Nmap to grab the HTML title
    scanner.scan(TARGET_IP, TARGET_PORT, arguments='-sT -Pn --script=http-title')
    
    # Access the script output from the scan results
    script_output = scanner[TARGET_IP]['tcp'][int(TARGET_PORT)]['script']['http-title']
    
    print(f"[Result] Nmap found page title: {script_output}")
    assert "Welcome to nginx!" in script_output

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

def test_nmap_reports_closed_port_correctly(scanner):
    """
    NEGATIVE TEST: Verify Nmap doesn't hallucinate. 
    It should report port 9999 as 'closed'.
    """
    print(f"\n[Audit] Checking closed port {CLOSED_PORT}...")
    scanner.scan(TARGET_IP, CLOSED_PORT, arguments='-sT -Pn')
    
    # If the port isn't in the results, it's effectively closed/filtered
    state = scanner[TARGET_IP]['tcp'][int(CLOSED_PORT)]['state']
    
    print(f"[Result] Nmap reported {CLOSED_PORT} as: {state}")
    assert state == 'closed' or state == 'filtered'

def test_nmap_identifies_service_correctly(scanner):
    """
    AUDIT 2: Verify Nmap identifies the service as 'http'.
    """
    scanner.scan(TARGET_IP, TARGET_PORT, arguments='-sT -Pn -sV')
    
    service_name = scanner[TARGET_IP]['tcp'][int(TARGET_PORT)]['name']
    print(f"[Result] Nmap identified service as: {service_name}")

    assert 'http' in service_name, f"DEALBREAKER: Nmap misidentified the service! Found: {service_name}"

def test_scan_speed_consistency(scanner):
    """
    STRESS TEST: Does 'Aggressive' mode (-T5) still get the right answer?
    Sometimes fast scans miss things.
    """
    print("\n[Audit] Running High-Speed Scan (-T5)...")
    scanner.scan(TARGET_IP, TARGET_PORT, arguments='-sT -Pn -T5')
    
    state = scanner[TARGET_IP]['tcp'][int(TARGET_PORT)]['state']
    assert state == 'open', "FAIL: High-speed scan caused Nmap to miss the port!"