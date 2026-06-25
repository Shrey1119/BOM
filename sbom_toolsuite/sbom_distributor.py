import os
import sys
import json
import base64
import argparse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

def generate_keypair(keys_dir):
    """Generates an ECDSA (SEC P256) key pair if they do not exist."""
    os.makedirs(keys_dir, exist_ok=True)
    priv_path = os.path.join(keys_dir, "private_key.pem")
    pub_path = os.path.join(keys_dir, "public_key.pem")
    
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        print("Using existing ECDSA cryptographic keys.")
        # Load existing keys
        with open(priv_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(pub_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key
        
    print("Generating new ECDSA (NIST P-256) key pair...")
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    # Save private key
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    # Save public key
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
    print(f"Cryptographic keys saved to:\n  Private: {priv_path}\n  Public: {pub_path}")
    return private_key, public_key

def canonicalize_json(json_data):
    """Serializes JSON data into a deterministic, canonical byte representation for signing."""
    data_copy = json_data.copy()
    data_copy.pop("signature", None)
    
    canonical_str = json.dumps(data_copy, sort_keys=True, separators=(',', ':'))
    return canonical_str.encode('utf-8')

def sign_data(private_key, data_bytes):
    """Signs bytes using the ECDSA private key and returns base64 encoded signature."""
    signature = private_key.sign(data_bytes, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key, data_bytes, b64_signature):
    """Verifies an ECDSA signature."""
    signature = base64.b64decode(b64_signature.encode('utf-8'))
    try:
        public_key.verify(signature, data_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

def split_sbom(sbom_data):
    """Splits SBOM data into Public and Private variants."""
    public_sbom = json.loads(json.dumps(sbom_data))
    private_sbom = json.loads(json.dumps(sbom_data))
    
    # Public SBOM: Strip vulnerability details
    vulnerabilities_removed = public_sbom.pop("vulnerabilities", None)
    if vulnerabilities_removed is not None:
        print(f"Removed {len(vulnerabilities_removed)} vulnerability entries from the Public SBOM.")
    else:
        print("No vulnerability entries found to remove in Public SBOM.")
        
    # Filter out internal properties if present
    if "metadata" in public_sbom and "properties" in public_sbom["metadata"]:
        filtered_props = [
            p for p in public_sbom["metadata"]["properties"]
            if not p.get("name", "").startswith("internal:")
        ]
        public_sbom["metadata"]["properties"] = filtered_props
        
    return public_sbom, private_sbom

def embed_signature(sbom_json, signature_b64, public_key_pem):
    """Embeds signature metadata inside the CycloneDX SBOM structure."""
    sbom_signed = sbom_json.copy()
    
    # 1. Embed under the top-level 'signature' block
    sbom_signed["signature"] = {
        "algorithm": "ECDSA-SHA256",
        "value": signature_b64,
        "publicKey": public_key_pem.decode('utf-8').replace('\n', '\\n')
    }
    
    # 2. Also embed in metadata properties
    if "metadata" not in sbom_signed:
        sbom_signed["metadata"] = {}
    if "properties" not in sbom_signed["metadata"]:
        sbom_signed["metadata"]["properties"] = []
        
    sbom_signed["metadata"]["properties"] = [
        p for p in sbom_signed["metadata"]["properties"]
        if p.get("name") != "signature"
    ]
    
    sbom_signed["metadata"]["properties"].append({
        "name": "signature",
        "value": signature_b64
    })
    
    return sbom_signed

def main():
    parser = argparse.ArgumentParser(description="SBOM Split & Sign Distributor")
    parser.add_argument("--sbom", required=True, help="Path to the enriched/input CycloneDX JSON SBOM file")
    parser.add_argument("--keys-dir", default="keys", help="Directory containing or to save cryptographic keys")
    parser.add_argument("--output-dir", default=".", help="Directory to save the public/private output files")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.sbom):
        print(f"Error: Input SBOM file '{args.sbom}' does not exist.")
        sys.exit(1)
        
    # 1. Initialize keys
    private_key, public_key = generate_keypair(args.keys_dir)
    
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # 2. Load input SBOM
    with open(args.sbom, "r", encoding="utf-8") as f:
        sbom_data = json.load(f)
        
    # 3. Split the SBOM into Public and Private variants
    print("\nSplitting SBOM into Public and Private files...")
    public_sbom_raw, private_sbom_raw = split_sbom(sbom_data)
    
    # 4. Canonicalize JSON and sign both files
    print("\nCanonicalizing and generating signatures...")
    public_bytes = canonicalize_json(public_sbom_raw)
    private_bytes = canonicalize_json(private_sbom_raw)
    
    public_sig = sign_data(private_key, public_bytes)
    private_sig = sign_data(private_key, private_bytes)
    
    assert verify_signature(public_key, public_bytes, public_sig), "Verification of Public SBOM signature failed!"
    assert verify_signature(public_key, private_bytes, private_sig), "Verification of Private SBOM signature failed!"
    print("Signatures generated and verified successfully.")
    
    # 5. Embed signatures
    public_sbom_signed = embed_signature(public_sbom_raw, public_sig, pub_pem)
    private_sbom_signed = embed_signature(private_sbom_raw, private_sig, pub_pem)
    
    # 6. Save final output files and detached signatures
    os.makedirs(args.output_dir, exist_ok=True)
    
    public_json_path = os.path.join(args.output_dir, "sbom_public.json")
    public_sig_path = os.path.join(args.output_dir, "sbom_public.json.sig")
    private_json_path = os.path.join(args.output_dir, "sbom_private.json")
    private_sig_path = os.path.join(args.output_dir, "sbom_private.json.sig")
    
    with open(public_json_path, "w", encoding="utf-8") as f:
        json.dump(public_sbom_signed, f, indent=2)
    with open(private_json_path, "w", encoding="utf-8") as f:
        json.dump(private_sbom_signed, f, indent=2)
        
    with open(public_sig_path, "w", encoding="utf-8") as f:
        f.write(public_sig)
    with open(private_sig_path, "w", encoding="utf-8") as f:
        f.write(private_sig)
        
    print("\nDistribution and signing process completed successfully:")
    print(f"  Public SBOM:  {public_json_path}")
    print(f"  Detached Sig: {public_sig_path}")
    print(f"  Private SBOM: {private_json_path}")
    print(f"  Detached Sig: {private_sig_path}")
    print("All tasks completed.")

if __name__ == "__main__":
    main()
