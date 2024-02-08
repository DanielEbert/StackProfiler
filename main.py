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


BUFFER_SIZE = 1024
SERVER_PORT = 7155

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
    # note that stackpointer grows downwards
    max_sp = max([r.sp for r in reports])
    for r in reports:
        r.stack_size = max_sp - r.sp

    data = [dataclasses.asdict(r) for r in reports]

    return json.dumps({
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "data": {
            "values": data
        },
        "mark": "bar",
        "encoding": {
            "x": {"field": "index", "type": "nominal"},
            "y": {"field": "stack_size", "type": "quantitative"}
        }
    })


# TODO: use argparse later
if len(sys.argv) < 2:
    raise Exception('Missing argument to target executable. ./main.py path/to/target')

prog = Program(sys.argv[1])

def main() -> NoReturn:
    new_cov_queue: mp.Queue[int] = mp.Queue()

    cov_receiver_proc = mp.Process(target=new_cov_receiver, args=(new_cov_queue,))
    cov_receiver_proc.start()

    last_cov_receive_time = time.time()

    reports: list[StackReport] = []

    while True:
        try:
            stackDepth, timestamp, pc, sp = new_cov_queue.get(block=False)
            func_name = prog.function_addr_to_str(pc)
            reports.append(StackReport(len(reports) + 1, stackDepth, timestamp, func_name, pc, sp))
            print(f'[{stackDepth}]: {pretty_print_ms(timestamp)} {func_name=}, {pc=}, {sp=}')

            # TODO: do on http request
            with open('spec.json', 'w') as f:
                f.write(get_plot(reports))
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


if __name__ == '__main__':
    raise SystemExit(main())

