import re

# The string than it have the pattern of convencional log
REGEX = r'(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]*)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
# We compile the regex, it´s a pattern now
PATTERN = re.compile(REGEX)

def parse_line(line):
    """This function check the line, it retuns dict if the log is convencional, if not, it returs 'None'"""
    match = PATTERN.match(line)

    if match:
        return match.groupdict()

    return None

def main():
    """This function reads each line (logs)"""
    with open(encoding="utf-8", file="samples/access.log") as reader:
        for numero, line in enumerate(iterable=reader, start=1):
            result = parse_line(line.strip())
            print(f"[OK] {result.get("ip")}   {result.get("status")}   {result.get("method")}   {result.get("path")}" if result is not None else f"[WARN] Line {numero}: unrecognized format -> {line.strip()}")


# The program entry, it´s necessary because when we run the program (no imports), '__name__' takes this value
# '"__main__"' and the if is true, if another file imports 'parser' the name´s value will be the name of this file
if __name__ == "__main__":
    main()