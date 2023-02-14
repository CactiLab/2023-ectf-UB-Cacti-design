import os
import argparse
from mbedtls import pk

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate RSA key pairs and save as JSON")
    parser.add_argument("folder_path", type=str, help="Folder path to save key pairs JSON")

    args = parser.parse_args()
    generate_rsa_key_pair(512, 
                          os.path.join(args.folder_path, "feature_pub.der"),
                          os.path.join(args.folder_path, "feature_priv.der"))
    
    generate_rsa_key_pair(512, 
                          os.path.join(args.folder_path, "pairing_pub.der"),
                          os.path.join(args.folder_path, "pairing_priv.der"))
    