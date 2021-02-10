#!/usr/bin/env python3

import os
import sys
import subprocess

COLOR_GREEN='\033[0;32m'
COLOR_RED='\033[0;31m'
COLOR_OFF='\033[0m'

def get_test_list():
    tests = []
    for file_name in os.listdir("./bin"):
        if '.dSYM' in file_name:
            continue # skip Mac OS dSYM files
        tests.append(os.path.join("./bin", file_name))
    return tests

test_names = get_test_list()
tests_passed = 0
tests_ran = 0

def run_test(file_path):
    args = [file_path, str(tests_ran), str(len(test_names))]
    return subprocess.call(args)

print('Running Tests')

for file_path in test_names:
    sys.stdout.write('{}...'.format(file_path))
    errored = run_test(file_path)

    if not errored:
        sys.stdout.write('{}OK{}\n'.format(COLOR_GREEN, COLOR_OFF))
        tests_passed += 1
    else:
        sys.stdout.write('{}FAIL{}\n'.format(COLOR_RED, COLOR_OFF))

    tests_ran += 1

status = COLOR_GREEN

# check o see if any failed
all_passed = tests_passed == len(test_names)
if not all_passed:
    status = COLOR_RED

print(str(tests_ran) + " of " + str(len(test_names)) + " ran")
print(status + str(tests_passed) + " of " + str(len(test_names)) + " passed\033[0m")

if all_passed:
	exit(0)
else:
	exit(-1)
