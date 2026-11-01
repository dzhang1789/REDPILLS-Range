#!/usr/bin/env python3
"""
SCADA Gateway Simulator — PULSE microgrid test range (Option A, single-VM)
==========================================================================
Runs one Modbus TCP server on port 5020, unit 10, holding the market registers
and shed coils the attack/detection scripts read and write.

Register layout (holding, unit 10) — mirrors scada_market_attack.py exactly:
  0   REG_ALLOC_MG1       50   (kW allocated to MG1 bidder)
  1   REG_ALLOC_MG2       50
  2   REG_ALLOC_MG3       50
  3   REG_ALLOC_MG4       50
  4   REG_BID_QTY_MG1     50
  5   REG_BID_QTY_MG2     50
  6   REG_BID_QTY_MG3     50
  7   REG_BID_QTY_MG4     50
  8   REG_CLEARING_PRICE  5200 ($52/MWh * 100, normal market)
  9   REG_SURPLUS         30
  10  REG_GENERATION      632
  11  REG_FIXED_MG1       0
  12  REG_FIXED_MG2       0
  13  REG_FIXED_MG3       0
  14  REG_FIXED_MG4       0

Coil layout (unit 10):
  0   COIL_BIDDER_SHED_MG1  FALSE
  1   COIL_BIDDER_SHED_MG2  FALSE
  2   COIL_BIDDER_SHED_MG3  FALSE
  3   COIL_BIDDER_SHED_MG4  FALSE
  4   COIL_OVERRIDE_MG1     TRUE  (normal — override is ON in normal operation)
  5   COIL_OVERRIDE_MG2     TRUE
  6   COIL_OVERRIDE_MG3     TRUE
  7   COIL_OVERRIDE_MG4     TRUE
  8   COIL_FIXED_SHED_MG1   FALSE
  9   COIL_FIXED_SHED_MG2   FALSE
  10  COIL_FIXED_SHED_MG3   FALSE
  11  COIL_FIXED_SHED_MG4   FALSE
  12  COIL_OPERATOR_MODE     FALSE

Usage:
    python gateway_simulator.py              # port 5020, Ctrl-C to stop
    python gateway_simulator.py --verbose
"""

import argparse
import logging
import signal
import sys
import time

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
from pymodbus.server import StartTcpServer

# ---------------------------------------------------------------------------
# Initial register values (normal/clean market state)
# ---------------------------------------------------------------------------
HOLDING_REGS = [0] * 64
HOLDING_REGS[0]  = 50    # alloc_mg1
HOLDING_REGS[1]  = 50    # alloc_mg2
HOLDING_REGS[2]  = 50    # alloc_mg3
HOLDING_REGS[3]  = 50    # alloc_mg4
HOLDING_REGS[4]  = 50    # bid_mg1
HOLDING_REGS[5]  = 50    # bid_mg2
HOLDING_REGS[6]  = 50    # bid_mg3
HOLDING_REGS[7]  = 50    # bid_mg4
HOLDING_REGS[8]  = 5200  # clearing_price ($52/MWh * 100)
HOLDING_REGS[9]  = 30    # surplus
HOLDING_REGS[10] = 632   # generation

# ---------------------------------------------------------------------------
# Initial coil values (normal/clean state)
# ---------------------------------------------------------------------------
COILS = [False] * 32
# bidder shed [0-3]: all off
# override [4-7]: all TRUE in normal operation (gateway recommending based on market)
COILS[4]  = True   # override MG1
COILS[5]  = True   # override MG2
COILS[6]  = True   # override MG3
COILS[7]  = True   # override MG4
# fixed shed [8-11]: all off
# operator_mode [12]: False


def make_context():
    slave = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [False] * 32),
        co=ModbusSequentialDataBlock(0x00, COILS),
        hr=ModbusSequentialDataBlock(0x00, HOLDING_REGS),
        ir=ModbusSequentialDataBlock(0, [0] * 32),
    )
    # unit 10 — attack scripts use GATEWAY_UNIT_ID = 10
    return ModbusServerContext(slaves={10: slave}, single=False)


def main():
    ap = argparse.ArgumentParser(description="PULSE SCADA gateway simulator")
    ap.add_argument("--port", type=int, default=5020)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [gateway] %(levelname)s %(message)s",
        level=level,
    )
    if not args.verbose:
        logging.getLogger("pymodbus").setLevel(logging.WARNING)

    print(f"[gateway_simulator] SCADA gateway on port {args.port} (unit 10). Ctrl-C to stop.")

    def _shutdown(sig, frame):
        print("\n[gateway_simulator] Shutting down.")
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    StartTcpServer(
        context=make_context(),
        address=("0.0.0.0", args.port),
    )


if __name__ == "__main__":
    main()
