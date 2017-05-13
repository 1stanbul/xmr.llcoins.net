# xmr.llcoins.net
XMR Tools Site Files

**Pages:**

1. addressgen.html -- provides a streamlined account generator, including two different methods of encryption
2. addresstests.html -- provides an more extensive amount of options for step-by-step private/public key/address generation and verification for several Cryptonote coins
3. checktx.html -- allows for the decoding of one-time-output keys of a particular transaction, associating them with their public account. This requires secret data (either the view private key, or the transaction private key) and an internet connection to MoneroBlocks to get the transaction data.
4. sign.html -- generates and verifies signatures on arbitrary data using one of your account private keys (spend key or view key)
5. slowhash.html -- generates the CryptoNight hash of hexadecimal input data; overall not too useful except for visually checking a block's PoW result
6. addressrcv.html -- provides a simple tool to recover a mnemonic if one or two words are missing, and address and checksum word is known.

Instructions for addressrcv.html
- Click clone or download on this repo and get the zip, you'll get the full site
- Extract to some folder and open addressrcv.html
- Open developer tab (ctrl+shift+i in Chrome) and go to console if you want to see progress. You need to do this BEFORE you click recover.
- Paste your address into 0. Target Address
- Type your mnemonic into 1., and write \<missing\> in place of the word(s) you lost.
- Click recover and let it work. It should complete in about 40min, and the <missing> will be replaced with the actual words!
