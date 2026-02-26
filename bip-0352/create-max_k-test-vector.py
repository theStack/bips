#!/usr/bin/env python3
import hashlib
import json
from bitcoin_utils import COutPoint
from reference_unchecked import create_outputs, encode_silent_payment_address, generate_label, get_input_hash, scanning
from secp256k1 import ECKey, ECPubKey

K_max = 2324

# funding tx 
G = ECKey().set(1).get_pubkey()
funding_secret_key = ECKey().set(0x1337)
funding_public_key = funding_secret_key * G
funding_outpoint = COutPoint(hash=bytes.fromhex('3cde0e7ad8adf24a4e52fd18efafffb94f73f4c7facf2627a5b588ad1c9db87f')[::-1], n=0)

# generate keys, labels and addresses
scan_secret_key = ECKey().set(0xdead)
scan_public_key = scan_secret_key * G
spend_secret_key = ECKey().set(0xbeef)
spend_public_key = spend_secret_key * G
label_tweak = ECKey().set(generate_label(scan_secret_key, m=0))
label = label_tweak * G
labeled_spend_public_key = spend_public_key + label
unlabeled_address = encode_silent_payment_address(scan_public_key, spend_public_key, hrp="sp")
labeled_address = encode_silent_payment_address(scan_public_key, labeled_spend_public_key, hrp="sp")

print( "===========================================================================================")
print(f"  Scan secret key: {scan_secret_key.get_bytes().hex()}")
print(f"  Scan public key: {scan_public_key.get_bytes(False).hex()}")
print()
print(f" Spend secret key: {spend_secret_key.get_bytes().hex()}")
print(f" Spend public key: {spend_public_key.get_bytes(False).hex()}")
print()
print(f"Label tweak (m=0): {label_tweak.get_bytes().hex()}")
print(f"      Label (m=0): {label.get_bytes(False).hex()}")
print(f"Labeled spend key: {labeled_spend_public_key.get_bytes(False).hex()}")
print()
print(f"Unlabeled address: {unlabeled_address}")
print(f"  Labeled address: {labeled_address}")
print( "===========================================================================================")

# create outputs
recipients = [{
        "address": labeled_address,
        "scan_pub_key": scan_public_key.get_bytes(False).hex(),
        "spend_pub_key": labeled_spend_public_key.get_bytes(False).hex(),
    }] * (K_max + 1)
outputs = create_outputs([(funding_secret_key, False)], [funding_outpoint], recipients, hrp="sp")
print(f"-> Created {len(outputs)} outputs.")

# scan outputs to get tweaks
input_hash = get_input_hash([funding_outpoint], funding_public_key)
labels = {label.get_bytes(False).hex(): label_tweak.get_bytes().hex()}
outputs_pubkeys = [ECPubKey().set(bytes.fromhex(o)) for o in outputs]
scan_result = scanning(scan_secret_key, spend_public_key, funding_public_key, input_hash, outputs_pubkeys, labels)
print(f"-> Scanning yielded {len(scan_result)} results.")

# create test vector
v = {}
v["comment"] = f"Maximum per-group recipient limit K_max is exceeded ({K_max+1} matches): sending fails, receiver doesn't scan beyond limit"
vin = {
    "txid": "3cde0e7ad8adf24a4e52fd18efafffb94f73f4c7facf2627a5b588ad1c9db87f",
    "vout": 0,
    "scriptSig": "",
    "txinwitness": "01407ce01bc5ef2e4aae353e7f291fec32623d6a491b5421be6dccc70345f32ebae5baa6654c60c074e72da76fd06b343474370e56d3ec0413156ec6261757125ad4",
    "prevout": {
        "scriptPubKey": {"hex": "5120bca87f72e604e8850064552bedf380ca4584227057efe12a6cc238470658aaa3"}
    },
    "private_key": "0000000000000000000000000000000000000000000000000000000000001337"
}

# sending part
s_given = {}
s_given["vin"] = [vin]
s_given["recipients"] = recipients
s_expected = {}
s_expected["outputs"] = [[]]
s_expected["shared_secrets"] = [None]
s_expected["input_private_key_sum"] = funding_secret_key.get_bytes().hex()
s_expected["input_pub_keys"] = [funding_public_key.get_bytes(False).hex()]
v["sending"] = [{"given": s_given, "expected": s_expected}]

# receiving part
r_given = {}
r_given["vin"] = [vin]
r_given["outputs"] = outputs
r_given["key_material"] = {
    "scan_priv_key": scan_secret_key.get_bytes().hex(),
    "spend_priv_key": spend_secret_key.get_bytes().hex(),
}
r_given["labels"] = [0]
r_expected = {}
r_expected["addresses"] = [unlabeled_address, labeled_address]
r_expected["outputs"] = []
MSG = hashlib.sha256(b"message").digest()
AUX = hashlib.sha256(b"random auxiliary data").digest()
for sr in scan_result:
    o = {}
    o["priv_key_tweak"] = sr["priv_key_tweak"]
    o["pub_key"] = sr["pub_key"]
    full_private_key = spend_secret_key + ECKey().set(bytes.fromhex(sr["priv_key_tweak"]))
    if full_private_key.get_pubkey().get_y() % 2 != 0:
        full_private_key.negate()
    sig = full_private_key.sign_schnorr(MSG, AUX)
    o["signature"] = sig.hex()
    r_expected["outputs"].append(o)
r_expected["tweak"] = (ECKey().set(input_hash) * funding_public_key).get_bytes(False).hex()
r_expected["shared_secret"] = (input_hash * scan_secret_key * funding_public_key).get_bytes(False).hex()
r_expected["input_pub_key_sum"] = funding_public_key.get_bytes(False).hex()
v["receiving"] = [{"given": r_given, "expected": r_expected}]

# emit test vector as JSON file
test_vector_json = json.dumps([v], indent=4)
with open('max_k-test-vector.json', 'w') as f:
    f.write(test_vector_json)
