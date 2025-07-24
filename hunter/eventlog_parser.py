import win32evtlog

def get_failed_logins(server='localhost', log_type='Security', max_events=20):
    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    failed_logins = []
    total_read = 0
    while total_read < max_events:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break
        for event in events:
            if event.EventID == 4625:  # Failed login
                print("Raw StringInserts:", event.StringInserts)  # print full details
                ip = None
                # Try safer IP extraction
                if event.StringInserts:
                    for item in event.StringInserts:
                        if item and item.count('.') == 3:  # crude IP check
                            ip = item
                            break
                failed_logins.append({
                    'time': event.TimeGenerated.Format(),
                    'account': event.StringInserts[5] if event.StringInserts and len(event.StringInserts) > 5 else '',
                    'ip': ip,
                    'message': event.StringInserts
                })
                total_read += 1
    return failed_logins
