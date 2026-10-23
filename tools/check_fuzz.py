#!/usr/bin/env python3
"""Build and run bounded, sanitizer-instrumented libFuzzer campaigns."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import time


TARGETS = {"packet": 4096, "stun": 65536, "json": 16384,
           "policy": 16384, "derp": 16384, "disco": 1458}


def seeds(target):
    common_json = [b"{}", b"[]", b"null", b'{"x":[0,true,false,null,"\\ud83d\\ude03"]}',
                   b'{"Version":2}', b'{"x":-9223372036854775808}']
    if target == "json":
        return common_json
    if target == "policy":
        return [b"[]", b'[{}]', b'[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}]',
                b'[{"SrcIPs":["100.64.0.0/10","::/0"],"DstPorts":[{"IP":"100.64.0.1-100.64.0.8","Ports":{"First":80,"Last":443}}],"IPProto":[6,17]}]']
    if target == "stun":
        return [bytes.fromhex("0101000c2112a442") + bytes(12) + bytes.fromhex("002000080001a1475e12a443"),
                bytes.fromhex("002000080001a1475e12a443"), bytes.fromhex("000100082112a442") + bytes(20)]
    if target == "packet":
        return [bytes.fromhex("4500001c000000004011000064400001644000020001000200080000"),
                bytes(range(256))]
    if target == "disco":
        return [b"\x01\x00" + bytes(44), b"\x02\x04" + bytes(30),
                b"\x03\x00\x01\x00" + bytes(18), bytes(range(128))]
    return common_json + [b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n",
                          struct.pack("!BI", 0x12, 8) + bytes(8),
                          struct.pack("!BI", 4, 32) + bytes(32)]


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", type=Path, default=root / "build-fuzz")
    parser.add_argument("--targets", nargs="+", choices=TARGETS, default=list(TARGETS))
    parser.add_argument("--seconds", type=int, default=30, help="Wall-time budget per target")
    parser.add_argument("--runs", type=int, help="Iteration bound instead of the time budget")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    if args.seconds <= 0 or args.jobs <= 0 or (args.runs is not None and args.runs <= 0):
        parser.error("Budgets and jobs must be positive")
    compiler = shutil.which(args.cc)
    if not compiler:
        parser.error(f"Compiler not found: {args.cc}")
    build = args.build_root.resolve()
    build.mkdir(parents=True, exist_ok=True)
    library = build / "library"
    config = root / "profiles/full.h"
    with (build / "build.log").open("w") as log:
        subprocess.run(["cmake", "-S", str(root), "-B", str(library),
                        f"-DCMAKE_C_COMPILER={compiler}", "-DCMAKE_BUILD_TYPE=Debug",
                        "-DCMAKE_C_FLAGS=-O1 -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer",
                        f"-DTSC_CONFIG_HEADER={config}", "-DTSC_BUILD_TESTS=OFF",
                        "-DTSC_BUILD_EXAMPLES=OFF", "-DTSC_SANITIZERS=ON"],
                       stdout=log, stderr=subprocess.STDOUT, check=True)
        subprocess.run(["cmake", "--build", str(library), "--parallel", str(args.jobs)],
                       stdout=log, stderr=subprocess.STDOUT, check=True)
        for target in args.targets:
            directory = build / target
            (directory / "corpus").mkdir(parents=True, exist_ok=True)
            (directory / "artifacts").mkdir(exist_ok=True)
            for i, seed in enumerate(seeds(target)):
                (directory / "corpus" / f"seed-{i}").write_bytes(seed)
            dictionary = ["SrcIPs", "DstPorts", "IP", "Ports", "First", "Last", "IPProto",
                          "Version", "null", "true", "false", "100.64.0.0/10", "::/0"]
            (directory / "tokens.dict").write_text("\n".join(json.dumps(s) for s in dictionary) + "\n")
            subprocess.run([compiler, "-std=c11", "-g", "-O1", "-UNDEBUG",
                            "-fsanitize=fuzzer,address,undefined", "-fno-omit-frame-pointer",
                            f'-DTSC_CONFIG_HEADER="{config}"', "-I", str(root / "include"),
                            "-I", str(root / "src/control"), str(root / f"tests/fuzz/fuzz_{target}.c"),
                            str(library / "libtailscalec.a"), "-lssl", "-lcrypto", "-o",
                            str(directory / f"fuzz-{target}")],
                           stdout=log, stderr=subprocess.STDOUT, check=True)

    def campaign(target):
        directory = build / target
        command = [str(directory / f"fuzz-{target}"), str(directory / "corpus"),
                   f"-dict={directory / 'tokens.dict'}", f"-seed={args.seed}",
                   f"-max_len={TARGETS[target]}", "-timeout=5", "-rss_limit_mb=2048",
                   "-print_final_stats=1", f"-artifact_prefix={directory / 'artifacts'}/"]
        command.append(f"-runs={args.runs}" if args.runs is not None else f"-max_total_time={args.seconds}")
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1",
                   UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
        started = time.monotonic()
        with (directory / "fuzz.log").open("w") as log:
            try:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, env=env,
                                        timeout=None if args.runs is not None else args.seconds + 60)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = 124
        text = (directory / "fuzz.log").read_text(errors="replace")
        stats = {}
        for line in text.splitlines():
            if line.startswith("stat::"):
                key, _, value = line[6:].partition(":")
                stats[key.strip()] = value.strip()
        report = {"target": target, "returncode": code,
                  "elapsed_seconds": round(time.monotonic() - started, 2), "stats": stats,
                  "log": str(directory / "fuzz.log")}
        print(f"{target}: {'PASS' if code == 0 else 'FAIL'} ({stats.get('number_of_executed_units', '?')} inputs)", flush=True)
        return report

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        reports = list(pool.map(campaign, args.targets))
    (build / "summary.json").write_text(json.dumps(reports, indent=2) + "\n")
    if any(report["returncode"] for report in reports):
        raise SystemExit(f"A campaign failed; inspect {build / 'summary.json'} and target logs")
    print(f"All {len(reports)} fuzz campaigns passed; results: {build / 'summary.json'}")


if __name__ == "__main__":
    main()
