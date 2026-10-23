#!/usr/bin/env python3
"""Build/test feature profiles and audit code exclusion in each archive."""
import argparse
from pathlib import Path
import subprocess


def run(*args):
    subprocess.run([str(arg) for arg in args], check=True)


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", type=Path, default=root / "build-profiles")
    parser.add_argument("--sanitizers", action="store_true")
    args = parser.parse_args()
    for name, header, enabled in (
        ("default", root / "config.h", {"stun", "client", "udp", "tcp", "disco", "derp"}),
        ("client_lan", root / "profiles/client_lan.h", {"client", "udp", "disco"}),
        ("embedded_udp", root / "profiles/embedded_udp.h", {"client", "udp", "disco"}),
        ("client_plain", root / "profiles/client_plain.h", {"client", "udp"}),
        ("tcp_only", root / "profiles/tcp_only.h", {"client", "tcp"}),
        ("ipv4", root / "profiles/ipv4.h", {"stun"}),
        ("minimal", root / "profiles/minimal.h", set()),
    ):
        build = args.build_root.resolve() / name
        print(f"\nChecking {name}", flush=True)
        run("cmake", "-S", root, "-B", build, "-DCMAKE_BUILD_TYPE=MinSizeRel",
            f"-DTSC_CONFIG_HEADER={header}", "-DBUILD_TESTING=ON", "-DTSC_BUILD_TESTS=ON",
            f"-DTSC_SANITIZERS={'ON' if args.sanitizers else 'OFF'}")
        run("cmake", "--build", build, "--parallel", "4")
        run("ctest", "--test-dir", build, "--output-on-failure", "--parallel", "4")
        symbols = subprocess.check_output(
            ["nm", "-g", "--defined-only", str(build / "libtailscalec.a")], text=True)
        exported = {line.split()[-1] for line in symbols.splitlines()
                    if len(line.split()) == 3}
        for module, prefix in (("stun", "tsc_stun_"), ("client", "tsc_client_"),
                               ("udp", "tsc_udp_"), ("tcp", "tsc_tcp_"),
                               ("disco", "tsc_disco_"), ("derp", "tsc_derp_")):
            present = any(symbol.startswith(prefix) for symbol in exported)
            if present != (module in enabled):
                raise SystemExit(f"Unexpected {module} symbols in {name} configuration")
        unexpected = {symbol for symbol in exported
                      if not symbol.startswith(("tsc_", "_sub_", "__"))}
        if unexpected:
            raise SystemExit(f"Unnamespaced symbols in {name}: {sorted(unexpected)}")
        run(build / "memory-report")
    print("\nAll profiles passed; disabled modules have no exported code.")


if __name__ == "__main__":
    main()
