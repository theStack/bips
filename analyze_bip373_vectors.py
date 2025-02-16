#!/usr/bin/env python3
import base64

with open('bip-0373.mediawiki', 'r') as file:
    lines = list(file)

for i, line in enumerate(lines):
    if "Bytes in Hex:" in line:
        start_idx = line.find("<pre>") + 5
        end_idx = line.find("</pre>")
        psbt_bytes = bytes.fromhex(line[start_idx:end_idx])
        psbt_base64_expected = base64.b64encode(psbt_bytes).decode()

        i_below = i + 1
        while lines[i_below].find("Base64 String:") == -1:
            i_below += 1
        line_below = lines[i_below]
        start_idx = line_below.find("<pre>") + 5
        end_idx = line_below.find("</pre>")
        psbt_base64_actual = line_below[start_idx:end_idx]

        if psbt_base64_actual != psbt_base64_expected:
            test_case_str = lines[i-1].rstrip()
            print(f"!!! PSBT Bytes/Base64 mismatch for test vector '{test_case_str}' (lines {i+1}-{i_below+1}) !!!")
