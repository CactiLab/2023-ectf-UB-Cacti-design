#!/usr/bin/python3 -u

# @file gen_secret
# @author Jake Grycel
# @brief Example script to generate header containing secrets for the fob
# @date 2023
#
# This source file is part of an example system for MITRE's 2023 Embedded CTF (eCTF).
# This code is being provided only for educational purposes for the 2023 MITRE eCTF
# competition, and may not meet MITRE standards for quality. Use this code at your
# own risk!
#
# @copyright Copyright (c) 2023 The MITRE Corporation

# @file gen_secret.py
# @author Zheyuan Ma
# @brief Script to generate header and eeprom data for the fob
# @date 2023
#
# @copyright Copyright (c) 2023 UB Cacti Lab

import array
import argparse
from pathlib import Path
from mbedtls import pk
from mbedtls import hashlib

EEPROM_FEATURE_PUB_SIZE = 96
EEPROM_PAIRING_PUB_SIZE = 96
EEPROM_UNLOCK_PRIV_SIZE = 320
EEPROM_PAIRING_PRIV_SIZE = 320

EEPROM_FEATURE_PUB_LOC = 0x0
EEPROM_PAIRING_PUB_LOC = 0x60
EEPROM_UNLOCK_PRIV_LOC = 0xc0
EEPROM_PAIRING_PRIV_LOC = 0xc0

def generate_rsa_key_pair(key_size, public_key_file, private_key_file):
    # Create a new RSA context
    rsa = pk.RSA()

    # Generate a new RSA key pair with the specified key size
    rsa.generate(key_size, exponent=65537)

    # Save the public key to a file
    with open(public_key_file, "wb") as f:
        f.write(rsa.export_public_key(format="DER"))

    # Save the private key to a file
    with open(private_key_file, "wb") as f:
        f.write(rsa.export_key(format="DER"))


def generate_hashed_pin(pin, image_pairing_pub_key_data):
    m = hashlib.sha256(bytes(pin, 'utf-8') + image_pairing_pub_key_data)
    hash = m.digest()
    return array.array('B', hash)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int)
    parser.add_argument("--pair-pin", type=str)
    parser.add_argument("--feature-pub-file", type=Path, required=True)
    parser.add_argument("--pairing-pub-file", type=Path, required=True)
    parser.add_argument("--unlock-priv-file", type=Path)
    parser.add_argument("--pairing-priv-file", type=Path)
    parser.add_argument("--header-file", type=Path)
    parser.add_argument("--eeprom-file", type=Path, required=True)
    parser.add_argument("--paired", action="store_true")
    args = parser.parse_args()

    feature_pub_key_data = args.feature_pub_file.read_bytes()
    pairing_pub_key_data = args.pairing_pub_file.read_bytes()
    
    feature_pub_key_size = len(feature_pub_key_data)
    pairing_pub_key_size = len(pairing_pub_key_data)
    
    image_feature_pub_key_data = feature_pub_key_data.ljust(EEPROM_FEATURE_PUB_SIZE, b'\xff')
    image_pairing_pub_key_data = pairing_pub_key_data.ljust(EEPROM_PAIRING_PUB_SIZE, b'\xff')
    
    eeprom_data = image_feature_pub_key_data + image_pairing_pub_key_data

    if args.paired:
        unlock_priv_key_data = args.unlock_priv_file.read_bytes()
        unlock_priv_key_size = len(unlock_priv_key_data)
        image_unlock_priv_key_data = unlock_priv_key_data.ljust(EEPROM_UNLOCK_PRIV_SIZE, b'\xff')

        eeprom_data += image_unlock_priv_key_data
        
        arr = generate_hashed_pin(args.pair_pin, image_pairing_pub_key_data)

        # Paired, write the secrets to the header file
        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write('#include <stdint.h>\n\n')
            fp.write("#define PAIRED 1\n\n")
            fp.write('const uint8_t PAIRING_PIN_HASH[32] = {\n')
            for i in range(0, len(arr), 16):
                chunk = arr[i:i+16]
                hex_str = ', '.join([f'0x{b:02x}' for b in chunk])
                fp.write(f'    {hex_str},\n')
            fp.write('};\n\n')
            fp.write(f'#define CAR_ID {args.car_id}\n\n')
            fp.write(f"#define FEATURE_PUB_KEY_SIZE {feature_pub_key_size}\n")
            fp.write(f"#define PAIRING_PUB_KEY_SIZE {pairing_pub_key_size}\n")
            fp.write(f"#define UNLOCK_PRIV_KEY_SIZE {unlock_priv_key_size}\n")
            fp.write(f"#define PAIRING_PRIV_KEY_SIZE 0\n\n")
            fp.write("#endif // __FOB_SECRETS__\n")
    else:
        pairing_priv_key_data = args.pairing_priv_file.read_bytes()
        pairing_priv_key_size = len(pairing_priv_key_data)
        image_pairing_priv_key_data = pairing_priv_key_data.ljust(EEPROM_PAIRING_PRIV_SIZE, b'\xff')
        
        eeprom_data += image_pairing_priv_key_data
        
        # Unpaired, write default values to header file
        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write("#include <stdint.h>\n\n")
            fp.write("#define PAIRED 0\n")
            fp.write("const uint8_t PAIRING_PIN_HASH[32] = {0};\n\n")
            fp.write('#define CAR_ID 0\n')
            fp.write(f"#define FEATURE_PUB_KEY_SIZE {feature_pub_key_size}\n\n")
            fp.write(f"#define PAIRING_PUB_KEY_SIZE {pairing_pub_key_size}\n\n")
            fp.write(f"#define UNLOCK_PRIV_KEY_SIZE 0\n\n")
            fp.write(f"#define PAIRING_PRIV_KEY_SIZE {pairing_priv_key_size}\n\n")
            fp.write("#endif // __FOB_SECRETS__\n")

    # Write the key data to the EEPROM file
    args.eeprom_file.write_bytes(eeprom_data)
    
    
if __name__ == "__main__":
    main()
