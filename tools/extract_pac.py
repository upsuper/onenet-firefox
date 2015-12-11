#!/usr/bin/env python3

import re
import sys
import base64

_pac_line = re.compile(r"^var pac_(\S+) = '([a-zA-Z0-9+/]+=*)';$")
def parse_line(line):
    match = _pac_line.match(line)
    if not match:
        return None
    return (match.group(1), base64.b64decode(match.group(2)))

def extract_pac_files(source):
    for line in source:
        result = parse_line(line)
        if not result:
            continue
        name, data = result
        print("extract {}, length {} bytes".format(name, len(data)))
        with open('data/pac/' + name + '.pac', 'wb') as pac:
            pac.write(data)

def main():
    if not sys.argv[1]:
        print('Expect popup.js')
        exit(1)

    with open(sys.argv[1], 'r') as f:
        extract_pac_files(f)

if __name__ == '__main__':
    main()
