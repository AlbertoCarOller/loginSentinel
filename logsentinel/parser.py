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

def parse_file(path):
    """This function reads the file and saves in two lists, in one saves the correct logs, in the other the wrong logs"""
    with open(encoding="utf-8", file=path) as reader:
        correct_logs = []
        wrong_logs = []
        
        for number, line in enumerate(iterable=reader, start=1):
            result = parse_line(line.strip())
            if result is not None:
                correct_logs.append(result)
            else:
                wrong_logs.append((number, line.strip()))

        return correct_logs, wrong_logs

def print_warnings(items):
    """This function print a list"""
    for number, line in items:
        print(f"[WARN] Line {number} -> {line}")

def main():
    correct_logs, wrong_logs = parse_file("samples/access.log")

    print(f"{len(correct_logs)} requests parsed, {len(wrong_logs)} unrecognized")
    print("Unrecognized:")
    print_warnings(wrong_logs)


# The program entry, it´s necessary because when we run the program (no imports), '__name__' takes this value
# '"__main__"' and the if is true, if another file imports 'parser' the name´s value will be the name of this file
if __name__ == "__main__":
    main()