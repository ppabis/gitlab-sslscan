import sys
import xml.etree.ElementTree as ET

def analyze_protocols(test):
    enabled = filter(lambda p: p.attrib.get('enabled') == "1", test.findall("protocol"))
    enabled = [f"{p.attrib.get('type')}{p.attrib.get('version')}" for p in enabled]
    for d in ["ssl2", "ssl3", "tls1.0", "tls1.1"]:
        if d in enabled:
            return False
    return True

def analyze_ciphers(test):
    ciphers = test.findall("cipher")
    weak = filter(lambda c: c.attrib.get("strength") not in ["strong", "acceptable"], ciphers)
    return len(list(weak)) == 0

def analyze(filename):
    results = {}
    with open(filename, "r") as f:
        et = ET.parse(f)
        tests = et.findall("ssltest")
        for test in tests:
            host = test.attrib.get("host")
            results[host] = analyze_protocols(test) and analyze_ciphers(test)
    
    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: analyze.py <results.xml>")
        sys.exit(1)
    results = analyze(sys.argv[1])
    exit_code = 0
    for host, passed in results.items():
        if not passed:
            exit_code = 1
            print(f"{host} FAIL.")
        else:
            print(f"{host} PASS.")
    sys.exit(exit_code)