import requests

def check_ip_abuseipdb(ip, api_key):
    url = f'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    resp = requests.get(url, headers=headers, params=params)
    if resp.status_code == 200:
        data = resp.json()
        abuse_confidence = data['data']['abuseConfidenceScore']
        return abuse_confidence
    return None
