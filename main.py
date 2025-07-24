import yaml
from hunter import eventlog_parser, detector, intel
import csv

def load_config(path='config.yaml'):
    with open(path) as f:
        return yaml.safe_load(f)

def main():
    config = load_config()
    api_key = config['api_keys']['abuseipdb']
    threshold = config['thresholds']['failed_logins']

    print(" Parsing failed login events...")
    failed_logins = eventlog_parser.get_failed_logins()

    print(" Detecting brute force attempts...")
    flagged_ips = detector.detect_brute_force(failed_logins, threshold)

    print(" Querying AbuseIPDB for flagged IPs...")
    report = []
    for ip, count in flagged_ips.items():
        score = intel.check_ip_abuseipdb(ip, api_key)
        report.append({'ip': ip, 'count': count, 'abuse_score': score})

    print("\n=== Report ===")
    for entry in report:
        print(f"IP: {entry['ip']}, Attempts: {entry['count']}, Abuse Score: {entry['abuse_score']}")

    # Save to CSV
    with open('hunt_report.csv', 'w', newline='') as csvfile:
        fieldnames = ['ip', 'count', 'abuse_score']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in report:
            writer.writerow(r)

    print("\nReport saved as hunt_report.csv")

if __name__ == "__main__":
    main()
