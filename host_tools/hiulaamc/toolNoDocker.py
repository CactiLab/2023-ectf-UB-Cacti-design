# 2023 eCTF
# Kyle Scaplen
#
# (c) 2023 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2023 Embedded
# CTF (eCTF). This code is being provided only for educational purposes for the
# 2023 MITRE eCTF competition, and may not meet MITRE standards for quality.
# Use this code at your own risk!

#Modified by Hiu Laam Chau

import logging
from pathlib import Path
from serial import Serial
import sys
import asyncio

from ectf_tools.utils import run_shell, get_logger, SOCKET_BASE
from ectf_tools.subparsers import (
    SubparserUnlockTool,
    SubparserPairTool,
    SubparserEnableTool,
    SubparserPackageTool,
)
#from ectf_tools.build import ctb

#from host_tools import ctools


def unlock(
    car: str,
):

    print("unlock car: ", car)
    #open serial port. 
    ser = Serial(car, 115200, timeout=5)
    if not ser.is_open:
        print("opening port")
        ser.open()

    rev_car: bytes = b""
    rev_car = rev_car + ser.readline(None)
    # If no data receive, unlock failed
    if len(rev_car) == 0:
        print("Failed to unlock")
    # If data received, print out unlock message and features
    else:
        print(rev_car)
            
    if ser.is_open:
        ser.close()
    return 0


async def pair(
    unpaired_fob: str,
    paired_fob: str,
    pair_pin: str,
):
    print("Running pair tool")

    ser_unpaired = Serial(unpaired_fob, 115200, timeout=5)
    ser_paired = Serial(paired_fob, 115200, timeoout=5)

    if not ser_unpaired.is_open:
        ser_unpaired.open()
    if not ser_paired.is_open:
        ser_paired.open()
    
    ser_unpaired.write(b"pair\n")
    ser_paired.write(b"pair\n")

    pair_pin_bytes = str.encode(pair_pin + "\n")
    ser_paired.write(pair_pin_bytes)

    
    pair_check = ser_unpaired.readline(None)

    if len(pair_check) == 0:
        print("failed to pair")
    else:
        print(pair_check)

    if ser_unpaired.is_open:
        ser_unpaired.close()
    if  ser_paired.is_open:
        ser_paired.close()
    return 0


async def package(
    car_id: str,
    feature_number: int,
    package_name: str,
):
    print("Running package tool")

    car_id_len = len(car_id)
    car_id_pad = (8 - car_id_len) * "\0"

    package_message_bytes = (
        str.encode(car_id + car_id_pad)
        + feature_number.to_bytes(1, "little")
        + str.encode("\n")
    )

    with open(f"/package_dir/{package_name}", "wb") as fhandle:
        fhandle.write(package_message_bytes)
    
    print("Feature packaged")
    
    return 0


async def enable(
    fob: int,
    package_name: str,
):

    print("Running enable tool")

    ser_fob = Serial(fob, 115200, timeout=5)
    ser_fob.write(b"enable\n")
    message = ""

    with open(f"/package_dir/{package_name}", "rb") as fhandle:
        message = fhandle.read()

    ser_fob.write(message)

    enable_success = ser_fob.readline(None)
    if len(enable_success) == 0:
        print("failed to enable pacakge")
    else:
        print(enable_success)
    
    return 0

def main():
    car_id = "COM4"
    pair_fob = "COM3"
    unpair_fob = ""
    package_name = ""
    pin = ""
    feature_number = ""
    unlock(car_id)
    #pair(unpaired_fob=unpair_fob, pair_pin=pin, paired_fob=pair_fob)
    #package(package_name=package_name, car_id=car_id, feature_number=feature_number)
    #enable(pair_fob, package_name)

if __name__ == "__main__":
    main()
