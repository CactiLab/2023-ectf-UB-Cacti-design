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

import json
import argparse
from pathlib import Path
from mbedtls import pk

EEPROM_FEATURE_PUB_SIZE = 96
EEPROM_PAIRING_PUB_SIZE = 96
EEPROM_UNLOCK_PRIV_SIZE = 320
EEPROM_PAIRING_PRIV_SIZE = 320

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
    parser.add_argument("--car-id", type=int)
    parser.add_argument("--pair-pin", type=str)
    parser.add_argument("--feature-pub-file", type=Path, required=True)
    parser.add_argument("--pairing-pub-file", type=Path, required=True)
    parser.add_argument("--unlock-priv-file", type=Path)
    parser.add_argument("--pairing-priv-file", type=Path)
    parser.add_argument("--header-file", type=Path)
    parser.add_argument("--paired", action="store_true")
    args = parser.parse_args()

    feature_pub_key_data = args.feature_pub_file.read_bytes()
    pairing_pub_key_data = args.pairing_pub_file.read_bytes()
    
    feature_pub_key_size = len(feature_pub_key_data)
    pairing_pub_key_size = len(pairing_pub_key_data)
    
    image_feature_pub_key_data = feature_pub_key_data.ljust(EEPROM_FEATURE_PUB_SIZE, b'\xff')
    image_pairing_pub_key_data = pairing_pub_key_data.ljust(EEPROM_PAIRING_PUB_SIZE, b'\xff')

    if args.paired:
        unlock_priv_key_data = args.unlock_priv_file.read_bytes()
        unlock_priv_key_size = len(unlock_priv_key_data)
        image_unlock_priv_key_data = unlock_priv_key_data.ljust(EEPROM_UNLOCK_PRIV_SIZE, b'\xff')

        # Paired, write the secrets to the header file
        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write("#define PAIRED 1\n")
            fp.write(f'#define PAIR_PIN "{args.pair_pin}"\n')
            fp.write(f'#define CAR_ID "{args.car_id}"\n')
            # fp.write(f'#define CAR_SECRET "{car_secret}"\n\n')
            fp.write('#define PASSWORD "unlock"\n\n')
            fp.write("#endif\n")
    else:
        pairing_priv_key_data = args.pairing_priv_file.read_bytes()
        pairing_priv_key_size = len(pairing_priv_key_data)
        image_pairing_priv_key_data = pairing_priv_key_data.ljust(EEPROM_PAIRING_PRIV_SIZE, b'\xff')
        
        # Unpaired, write default values to header file
        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write("#define PAIRED 0\n")
            fp.write('#define PAIR_PIN "000000"\n')
            fp.write('#define CAR_ID "000000"\n')
            # fp.write('#define CAR_SECRET "000000"\n\n')
            fp.write('#define PASSWORD "unlock"\n\n')
            fp.write("#endif\n")


if __name__ == "__main__":
    main()
