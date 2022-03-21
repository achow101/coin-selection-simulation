#! /usr/bin/env python3

import argparse
import os

from glob import glob

parser = argparse.ArgumentParser("Collect all results for simulations in a folder into a markdown table")
parser.add_argument("directory")
args = parser.parse_args()

results = []
header = None
for res_file_path in glob(os.path.join(args.directory, "**/results.txt"), recursive=True):
    print(f"Fetching results from {res_file_path}")
    with open(res_file_path, "r") as f:
        prev_line = None
        for line in f:
            if "Scenario File" in line:
                if header is None:
                    header = line
                else:
                    assert line == header
            if "----END SIMULATION RESULTS----" in line:
                break
            prev_line = line
            if not prev_line:
                continue
        results.append(prev_line)

with open(os.path.join(args.directory, "results.md"), "w") as f:
    f.write(header)

    pipe_count = header.count("|") - 1
    table_split = "|---" * pipe_count + "|\n"

    f.write(table_split)

    for r in results:
        f.write(r)
