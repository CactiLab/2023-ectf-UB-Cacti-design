#!/usr/bin/python3 -u

# @file gen_secret
# @author Jake Grycel
# @brief Example script to generate header containing secrets for the car
# @date 2023
#
# This source file is part of an example system for MITRE's 2023 Embedded CTF (eCTF).
# This code is being provided only for educational purposes for the 2023 MITRE eCTF
# competition,and may not meet MITRE standards for quality. Use this code at your
# own risk!
#
# @copyright Copyright (c) 2023 The MITRE Corporation

import argparse
from pathlib import Path
from mbedtls import pk

EEPROM_UNLOCK_PUB_SIZE = 96

EEPROM_UNLOCK_PUB_LOC = 0x0

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
        

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int, required=True)
    parser.add_argument("--unlock-priv-file", type=Path, required=True)
    parser.add_argument("--unlock-pub-file", type=Path, required=True)
    parser.add_argument("--header-file", type=Path, required=True)
    parser.add_argument("--eeprom-file", type=Path, required=True)
    args = parser.parse_args()

    # Generate a new RSA key pair if one doesn't exist
    if not args.unlock_pub_file.exists():
        generate_rsa_key_pair(512, args.unlock_pub_file, args.unlock_priv_file)

    pub_key_data = args.unlock_pub_file.read_bytes()
    pub_key_size = len(pub_key_data)
    
    # Pad the public key to the size of the EEPROM unlock public key
    image_pub_key_data = pub_key_data.ljust(EEPROM_UNLOCK_PUB_SIZE, b'\xff')
    
    # Write the public key data to the EEPROM file
    args.eeprom_file.write_bytes(image_pub_key_data)

    # Write to header file
    with open(args.header_file, "w") as fp:
        fp.write("#ifndef __CAR_SECRETS__\n")
        fp.write("#define __CAR_SECRETS__\n\n")
        fp.write(f"#define UNLOCK_PUB_KEY_SIZE {pub_key_size}\n\n")
        fp.write(f'#define CAR_ID "{args.car_id}"\n\n')
        fp.write('#define PASSWORD "unlock"\n\n')
        fp.write("#endif\n")


if __name__ == "__main__":
    main()
