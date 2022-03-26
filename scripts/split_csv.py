#! /usr/bin/env python3

import argparse
import csv
import os

parser = argparse.ArgumentParser("Split a given csv file into 90 MB parts")
parser.add_argument("filename")
args = parser.parse_args()

with open(args.filename) as orig_f:
    count = 0
    new_f = open(os.path.splitext(args.filename)[0] + f".{count}.csv", "w")
    for row in orig_f:
        new_f.write(row)
        if new_f.tell() > 90 * 1000 * 1000:
            new_f.close()
            count += 1
            new_f = open(os.path.splitext(args.filename)[0] + f".{count}.csv", "w")

os.remove(args.filename)
