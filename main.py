#!/usr/bin/env python3

from __future__ import annotations

import socket
import multiprocessing as mp
import queue
import time
from typing import NoReturn
import subprocess
import sys
import struct
import functools
from dataclasses import dataclass
import dataclasses
import json
from collections import defaultdict

from flask import Flask
from flask_cors import CORS
from flask import request
import threading

MAX_STACKTRACE_DEPTH = 40

BUFFER_SIZE = 1024
SERVER_PORT = 7155
API_PORT = 7166

class Addr2Line:
    def __init__(self, prog_path: str) -> None:
        self.addr2line_proc = subprocess.Popen(
            ['addr2line', '-i', '-e', prog_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True
        )

    @functools.cache
    def get_src_code(self, addr: int) -> tuple[str, int]:
        assert self.addr2line_proc.poll() is None, 'addr2line_proc exited'
        self.addr2line_proc.stdin.write(f'{addr:x}\n')
        self.addr2line_proc.stdin.flush()

        src_code_location = self.addr2line_proc.stdout.readline()
        file, line_str = src_code_location.split(' ')[0].split(':')
        line = int(line_str)
        return file, line


class Program:
    def __init__(self, prog_path: str) -> None:
        self.prog_path = prog_path
        self.a2l = Addr2Line(self.prog_path)
    
    def function_addr_to_str(self, addr: int) -> str:
        return self.a2l.get_src_code(addr)


@dataclass
class StackReport:
    index: int
    stackDepth: int
    # in ns
    time: int
    func_name: str
    pc: int
    # note that stackpointer grows downwards
    sp: int
    # in bytes
    stack_size: int = 0


def pretty_print_ms(ms: int) -> str:
    # Constants for conversions
    ms_in_hour = 3600000
    ms_in_minute = 60000
    ms_in_second = 1000

    # Convert ms to hours, minutes, and seconds
    minutes = str((ms % ms_in_hour) // ms_in_minute)
    seconds = str((ms % ms_in_minute) // ms_in_second)
    milliseconds = str(ms % ms_in_second)

    # Create a pretty print string
    result = f"{minutes.zfill(2)}m:{seconds.zfill(2)}s:{milliseconds.zfill(3)}ms"
    return result


def get_plot(reports: list[StackReport]) -> str:
    if reports:
        # note that stackpointer grows downwards
        max_sp = max([r.sp for r in reports])
        for r in reports:
            r.stack_size = max_sp - r.sp

        data = [dataclasses.asdict(r) for r in reports]
    else:
        data = []
    
    tooltips = []
    for tooltip_name in ['index', 'stackDepth', 'time', 'stack_size']:
        tooltips.append({'field': tooltip_name, 'type': 'quantitative'})
    tooltips.append({'field': 'func_name', 'type': 'nominal'})

    return json.dumps({
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "data": {
            "values": data
        },
        "mark": "bar",
        "encoding": {
            "x": {"field": "index", "type": "nominal"},
            "y": {"field": "stack_size", "type": "quantitative"},
            "tooltip": tooltips,
        },
        "width": 1200,
        "height": 800
    })


def remove_duplicate_reports(reports: list[StackReport]) -> list[StackReport]:
    if not reports:
        return []

    ret = [reports[0]]

    prev_report = reports[0]
    stack: dict[int, StackReport] = defaultdict(int)
    stack[prev_report.stackDepth] = prev_report

    def get_stack_hash(s: dict[int, StackReport]) -> int:
        ret = []
        for i in range(MAX_STACKTRACE_DEPTH):
            if i in stack:
                ret.extend([stack[i].stackDepth, stack[i].pc, stack[i].sp])
        return hash(tuple(ret))

    previous_stackhashes: set[int] = set([get_stack_hash(stack)])

    for i in range(1, len(reports)):
        if reports[i].stackDepth < prev_report.stackDepth:
            for i in range(reports[i].stack_size + 1, MAX_STACKTRACE_DEPTH):
                if i in stack:
                    del stack[i]
        stack[reports[i].stackDepth] = reports[i]
    
        stackhash = get_stack_hash(stack)
        if stackhash not in previous_stackhashes:
            previous_stackhashes.add(stackhash)
            ret.append(reports[i])

    return ret


# TODO: use argparse later
if len(sys.argv) < 2:
    raise Exception('Missing argument to target executable. ./main.py path/to/target')

prog = Program(sys.argv[1])
reports: list[StackReport] = []

def main() -> NoReturn:
    new_cov_queue: mp.Queue[int] = mp.Queue()

    cov_receiver_proc = mp.Process(target=new_cov_receiver, args=(new_cov_queue,))
    cov_receiver_proc.start()

    threading.Thread(target=lambda: app.run(host='0.0.0.0', port=API_PORT, debug=True, use_reloader=False)).start()

    last_cov_receive_time = time.time()

    while True:
        try:
            stackDepth, timestamp, pc, sp = new_cov_queue.get(block=False)
            func_name = prog.function_addr_to_str(pc)
            reports.append(StackReport(len(reports) + 1, stackDepth, timestamp, func_name, pc, sp))
            print(f'[{stackDepth}]: {pretty_print_ms(timestamp)} {func_name=}, {pc=}, {sp=}')
        except queue.Empty:
            pass

        if last_cov_receive_time + 0.3 < time.time():
            time.sleep(0.1)

def new_cov_receiver(new_cov_queue: mp.Queue[tuple[int, str, int]]) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', SERVER_PORT))

    print('UDP Server started on port', SERVER_PORT)

    while True:
        message, _ = sock.recvfrom(BUFFER_SIZE)

        assert len(message) == 4 + 8 + 8 + 8

        stackDepth = struct.unpack('I', message[:4])[0]
        timestamp = struct.unpack('Q', message[4:12])[0]
        pc = struct.unpack('Q', message[12:20])[0]
        sp = struct.unpack('Q', message[20:28])[0]

        new_cov_queue.put((stackDepth, timestamp, pc, sp))


API_PORT = 7166

app = Flask(__name__)
CORS(app)


@app.route('/getPlot')
def getCoveredLines():
    unique_reports = remove_duplicate_reports(reports)

    plot_json = get_plot(unique_reports)
    return f"""\
<!doctype html>
<html>
  <head>
    <title>Stack Profile</title>
    <script src="https://cdn.jsdelivr.net/npm/vega@5.25.0"></script>
    <script src="https://cdn.jsdelivr.net/npm/vega-lite@5.16.3"></script>
    <script src="https://cdn.jsdelivr.net/npm/vega-embed@6.22.2"></script>
  </head>
  <body>
    <div id="vis"></div>
    <script type="text/javascript">
      var yourVlSpec = {plot_json}
      vegaEmbed('#vis', yourVlSpec);
    </script>
  </body>
</html>
"""


if __name__ == '__main__':
    raise SystemExit(main())

