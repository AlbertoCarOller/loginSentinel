from logsentinel.parser import parse_file # This function is necessary in this file

SCAN_THRESHOLD = 3 # This const is the min number of dangers

def detect_scanners(entries):
    """This function returns a filter list with dicts than contain info about the correct logs"""
    counts = {}

    for entry in entries:
        status = int(entry["status"])
        if status == 404:
            ip = entry["ip"]

            if ip in counts:
                counts[ip] += 1
            else:
                counts[ip] = 1

    return [{"type": "scan", "ip": ip, "count": count} for ip, count in counts.items() if count >= SCAN_THRESHOLD]