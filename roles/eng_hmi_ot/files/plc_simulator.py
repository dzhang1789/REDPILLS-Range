#!/usr/bin/env python3
"""
PLC Simulator — PULSE microgrid test range (Option A, single-VM)
================================================================
Runs four Modbus TCP servers in parallel threads, one per microgrid:
  MG1 (load)  port 502  unit 1
  MG2 (load)  port 503  unit 1
  MG3 (load)  port 504  unit 1
  MG4 (gen)   port 505  unit 1

Coil layout matches the attack/detection scripts exactly.

LOAD PLCs (MG1-3) coil map (unit 1):
  0  Main_Breaker_Closed   TRUE  = closed (normal)
  1  Load_Breaker_Closed   TRUE  = closed (normal)
  2  Bidder_Breaker_Closed TRUE  = closed (normal)
  3  Market_Control        FALSE = auto mode (normal)
  4  Main_Cmd_Input        TRUE  = close command
  5  Load_Cmd_Input        TRUE  = close command
  6  Bidder_Cmd_Input      TRUE  = close command

GEN PLC (MG4) coil map (unit 1):
  0  Main_Breaker_Closed   TRUE
  1  Gen_Online            TRUE
  2  Market_Control        FALSE
  3  Main_Cmd_Input        TRUE
  4  Gen_Cmd_Input         TRUE

MG4 holding registers (unit 1) — read by market attack / recon:
  1027  diesel_power_A  590 (kW per phase, realistic)
  1028  diesel_power_B  590
  1029  diesel_power_C  590
  1030..1035  wind/solar power (0 — diesel-only for simplicity)

Usage:
    python plc_simulator.py              # starts all four, Ctrl-C to stop
    python plc_simulator.py --verbose    # log every read/write
"""

import argparse
import logging
import signal
import sys
import threading
import time

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
from pymodbus.server import StartTcpServer

# ---------------------------------------------------------------------------
# Coil / register layout (mirrors attack script constants exactly)
# ---------------------------------------------------------------------------
LOAD_COILS_INIT = {
    # idx: initial value
    0: True,   # Main_Breaker_Closed
    1: True,   # Load_Breaker_Closed
    2: True,   # Bidder_Breaker_Closed
    3: False,  # Market_Control
    4: True,   # Main_Cmd_Input
    5: True,   # Load_Cmd_Input
    6: True,   # Bidder_Cmd_Input
}
GEN_COILS_INIT = {
    0: True,   # Main_Breaker_Closed
    1: True,   # Gen_Online
    2: False,  # Market_Control
    3: True,   # Main_Cmd_Input
    4: True,   # Gen_Cmd_Input
}

# MG4 holding registers (0-indexed; script uses 1027-1035, which are absolute Modbus addresses)
# pymodbus uses 0-based addressing internally; client sends address 1027 → index 1027
MG4_REGS = {
    1027: 590,  # diesel_power_A
    1028: 590,  # diesel_power_B
    1029: 590,  # diesel_power_C
    1030: 0,    # wind_power_A
    1031: 0,    # wind_power_B
    1032: 0,    # wind_power_C
    1033: 0,    # solar_power_A
    1034: 0,    # solar_power_B
    1035: 0,    # solar_power_C
}

# ---------------------------------------------------------------------------
# Build a datastore for one PLC
# ---------------------------------------------------------------------------
def _coil_block(coil_map, size=32):
    values = [False] * size
    for idx, val in coil_map.items():
        values[idx] = bool(val)
    # pymodbus coil block: address 0x00 maps to index 0
    return ModbusSequentialDataBlock(0x00, values)


def _register_block(reg_map, size=2048):
    values = [0] * size
    for addr, val in reg_map.items():
        if addr < size:
            values[addr] = int(val)
    return ModbusSequentialDataBlock(0x00, values)


def make_context(is_gen=False, reg_map=None):
    coil_map  = GEN_COILS_INIT if is_gen else LOAD_COILS_INIT
    hr_block  = _register_block(reg_map or {})
    ctx = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [False] * 32),   # discrete inputs
        co=_coil_block(coil_map),                        # coils (FC1/5)
        hr=hr_block,                                     # holding regs (FC3/6)
        ir=ModbusSequentialDataBlock(0, [0] * 32),       # input regs
    )
    return ModbusServerContext(slaves={1: ctx}, single=False)


# ---------------------------------------------------------------------------
# Launch one server in a thread
# ---------------------------------------------------------------------------
def _run_server(name, port, context, verbose):
    log = logging.getLogger(name)
    log.info("Starting %s on port %d", name, port)
    try:
        StartTcpServer(
            context=context,
            address=("0.0.0.0", port),
            # pymodbus 3.x: no framer kwarg needed for TCP
        )
    except Exception as exc:
        log.error("Server %s crashed: %s", name, exc)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="PULSE PLC simulator (4 microgrids)")
    ap.add_argument("--verbose", action="store_true", help="Debug logging")
    args = ap.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
        level=level,
    )
    # Quieten pymodbus internals unless --verbose
    if not args.verbose:
        logging.getLogger("pymodbus").setLevel(logging.WARNING)

    configs = [
        ("MG1-PLC", 502, make_context(is_gen=False)),
        ("MG2-PLC", 503, make_context(is_gen=False)),
        ("MG3-PLC", 504, make_context(is_gen=False)),
        ("MG4-PLC", 505, make_context(is_gen=True, reg_map=MG4_REGS)),
    ]

    threads = []
    for name, port, ctx in configs:
        t = threading.Thread(
            target=_run_server, args=(name, port, ctx, args.verbose),
            name=name, daemon=True,
        )
        t.start()
        threads.append(t)
        time.sleep(0.1)  # stagger startup

    print(f"[plc_simulator] MG1-4 PLCs running on ports 502-505 (unit 1). Ctrl-C to stop.")

    def _shutdown(sig, frame):
        print("\n[plc_simulator] Shutting down.")
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
