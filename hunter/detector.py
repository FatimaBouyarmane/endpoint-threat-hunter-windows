from collections import Counter

def detect_brute_force(failed_logins, threshold=5):
    ip_counts = Counter(f['ip'] for f in failed_logins if f['ip'])
    flagged = {ip: count for ip, count in ip_counts.items() if count >= threshold}
    return flagged
