from logsentinel.parser import parse_file # This function is necessary in this file

SCAN_THRESHOLD = 3 # This const is the min number of '404'
BRUTE_FORCE_THRESHOLD = 3 # This const is the min number of brute force that allows
LOGIN_PATHS = ("/login", "/wp-login.php", "/admin/login") # This tuple contains the login´s paths

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

    return [{"type": "scan", "reason": "404 responses", "ip": ip, "count": count} for ip, count in counts.items() if count >= SCAN_THRESHOLD]

def detect_brute_force(entries):
    """This function returs a brute force's list"""
    counts = {}

    for entry in entries:
        status = int(entry["status"])
        path = entry["path"]
        method = entry["method"]
        if status == 401 and path in LOGIN_PATHS and method == "POST":
            ip = entry["ip"]

            if ip in counts:
                counts[ip] += 1
            else:
                counts[ip] = 1

    return [{"type": "brute_force", "reason": "failed logins", "ip": ip, "count": count} for ip, count in counts.items() if count >= BRUTE_FORCE_THRESHOLD]


def main():
    correct_logs, wrong_logs = parse_file("samples/access.log")
    alerts = detect_scanners(correct_logs)
    print(f"{len(correct_logs)} requests parsed, {len(wrong_logs)} unrecognized\n")

    for alert in alerts:
        print(f"[ALERT] {alert["type"]}   {alert["ip"]}   {alert["count"]} x 404")

    if wrong_logs:
        print(f"\n{len(alerts)} alert(s) found")
    else:
        print("No threats detected")

if __name__ == "__main__":
    main()