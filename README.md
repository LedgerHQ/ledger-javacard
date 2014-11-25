BTChip Java Card Bitcoin Hardware Wallet 
========================================

The following project is a proof of concept implementation of a Bitcoin Hardware Wallet tested on a real world Java Card platform (JCOP 2.4.2 R3, found in the Yubikey Neo) with no strings attached (no vendor NDA necessary as only standard Java Card features are used), protected against malware using a second factor validation of the transactions based on the isolation of the contact and contactless communication interfaces.

The provided implementation is not designed for production use - play with it at your own risks, we are not responsible if you lose epic amounts of coins, crash your Java Card, trigger a banking revolution or worse. It is mostly intended to draft new BTChip features and hopefully bring more secure bitcoin solutions to the market.

For any question, reach us at contact@btchip.com

Use cases
---------

To use this wallet, you need a computer (doh) and an NFC enabled phone supporting NFC Forum Type 4 tags (preferably natively or through a third party application).

When creating a transaction from your computer :
   * Plug your wallet into the computer
   * Enter your application PIN to unlock the wallet
   * Send the transaction to the wallet, it will be validated on the contact interface, and a virtual NFC Forum Type 4 tag will be created listing the transaction details, and a random transaction PIN. The tag content cannot be read from the contact interface. 
   * Tap the wallet on your NFC phone to check the transaction details and see your transaction PIN
   * Finally plug your wallet into the computer again, enter the transaction PIN and finalize the transaction

When creating a transaction from your smartphone :
   * Tap the wallet on your NFC phone
   * The transaction limits will be validated by the wallet (cumulative amount, maximum change, maximum fees) and directly signed


APDU specification
-------------------

This application follows the legacy BTChip specification available at https://ledgerhq.github.io/btchip-doc/bitcoin-technical-1.4.2.html with the following large modifications (and other subtle smaller modifications that you'll be delighted to discover in the source code) : 
   * The only supported APDUs are
     * GENERATE KEYPAIR (with no authorized address, derivation or private key signature support)
     * IMPORT PRIVATE KEY (with restrictions described below)
     * GET TRUSTED INPUT
     * UNTRUSTED HASH TRANSACTION INPUT START
     * UNTRUSTED HASH TRANSACTION INPUT FINALIZE (with no Transaction Authorization Data)
     * UNTRUSTED HASH SIGN (with the PIN replacing the Transaction Authorization Signature when used on the contact interface)
   * Operation modes are not supported (the application always works as described previously) 
   * Authorized addresses are not supported
   * Keysets are hardcoded - only the following two are available
     * 0x02 as "private key encryption"
     * 0x40 as "trusted input encryption"
   * A new SETUP APDU is added to provision the wallet PIN, create the default keysets and return the private key encryption value for paper storage and disaster recovery
   * A new UNLOCK APDU is added to unlock the wallet given its PIN
   * A new SET CONTACTLESS LIMIT APDU is added to provision the maximum cumulated output, maximum change amount, maximum fee amount enforced for a contactless transaction
   * A new GET CONTACTLESS LIMIT APDU is added to retrive the maximum cumulated output, maximum change amount, maximum fee amount enforced for a contactless transaction
   * A new key import method is used for IMPORT PRIVATE KEY and is the only one supported : prepare binary (P1 set to 20, masked with 80) which expects to receive the binary private key (32 bytes) followed by the binary public key component (65 bytes) as the Java Card API does not offer an API to work on the curve points 
   * The private key encoding format is different and includes the public key


Building the application
-------------------------

Refer to build.sh - you'll need to download a Java Card Classic development kit > 3.0.1, such as http://www.oracle.com/technetwork/java/javacard/downloads/index.html - or use the provided CAP file


Installing the application on a Yubikey Neo
--------------------------------------------

Supposing you're already familiar with applet installation procedures, 

   * Switch the Yubikey Neo to CCID mode
   * If you plan to test on a smartphone which does not support Mifare Classic (Broadcom NFC chipset), apply this patch to avoid any issue http://forum.yubico.com/viewtopic.php?p=3914#p3914
   * Delete the default NFC Forum Tag application d2760000850101 - WARNING by doing so you'll lose the ability to generate OTP codes with the Yubikey Neo on the contactless interface, as the default application cannot be reinstalled. If you want to keep it, you can skip this part, install the application with a different AID, and have a third party smartphone application query the tag.
   * Load the CAP file, package AID FF425443484950
   * Install the main application FF42544348495001 using the default instance AID, no specific parameters
   * Install the NFC Forum Tag application FF42544348495002 using the standard NFC Forum instance AID d2760000850101, no specific parameters

Licensing & begging
-------------------

This application is distributed under the GNU Affero General Public License version 3

Please contact us if you wish to reuse this code under a difference license at contact@btchip.com 

If you found this project useful, consider a donation to 1BTChip7VfTnrPra5jqci7ejnMguuHogTn which will be wisely used for our next secure bitcoin projects

APDU logs
----------

While waiting for a proper client implementation, the following APDUs describe the application setup and a new transaction reusing TX 523fe5bb34652dcef9269c1509cba952351dd681120353e2b6a327fcf4e5d877 as input on the contact interface, encoded as 

```
0100000001bee9c0533b3c277033771a20f88efd72a254ef2496485717b1d9a30be87f5f3c010000008a473044022071f36cbc2773965f515530c914d2b1df7bb5d783097beecfd847abe94305386502202ec7b3e92e44c449e5c467693e55d41ede02bdada4b01e103946c213055730ca014104d319771be64081d85d3c5b9f24ca3ffd4100b73f116fd82bdf8fc8ef385104d80dab84f8d0d00a3e8edbfcbc50e4081fff1427e12e19fe1f649a5a77b527a9f0ffffffff02801a0600000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88acd7042d0a090000001976a91472a5454371b5cee07f96dc4a85883a1c13f4de0288ac00000000
```

Select the application

```
=> 00 A4 04 00 08 FF 42 54 43 48 49 50 01
<= 90 00
```

Set up the application with PIN 12345678 - the application answers with the 3DES-2 private key encoding key for disaster recovery

```
=> E0 A0 00 00 08 31 32 33 34 35 36 37 38
<= xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx 90 00 
```

Enter the PIN

```
=> E0 A2 00 00 08 31 32 33 34 35 36 37 38
<= 90 00
```

Import an existing private key which was used for the transaction, using keyset 02 for encryption, keyset RFU for signature, RFU flag, default curve file RFU 

```
=> E0 20 A0 00 66 02 00 00 00 00 [private key on 32 bytes] 04 09 0B 15 BD E5 69 38 67 34 AB F2 A2 B9 9F 9C A6 A5 06 56 62 7E 77 DE 66 3C A7 32 57 02 76 99 86 CF 26 CC 9D D7 FD EA 0A F4 32 C8 E2 BE CC 86 7C 93 2E 1B 9D D7 42 F2 A1 08 99 7C 22 52 E2 BD EB 
<= 41 04 09 0B 15 BD E5 69 38 67 34 AB F2 A2 B9 9F 9C A6 A5 06 56 62 7E 77 DE 66 3C A7 32 57 02 76 99 86 CF 26 CC 9D D7 FD EA 0A F4 32 C8 E2 BE CC 86 7C 93 2E 1B 9D D7 42 F2 A1 08 99 7C 22 52 E2 BD EB 70 42 66 95 B6 6A 3F C3 4C 93 A6 A8 28 5D 7B 1F BA 20 20 4D BE 6C B9 BC F2 8F 0C BA 32 DA B9 BE F8 BE 94 D1 40 90 DE 7E C1 53 53 D1 FD 1B A8 07 32 72 64 9E 25 D5 AC 8F C8 D6 5E 79 AF 3A A4 5A 94 51 2F 75 CB 4D 68 05 31 2E 44 61 00 43 22 8D F9 F3 97 97 92 28 E4 7F 16 DD 67 CC B6 58 82 9A 63 D2 5A E3 9A 41 86 44 B2 9C 86 ED 60 CE 71 5E 98 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 90 00
```

Create a new fresh keypair for the change

```
=> E0 20 00 00 05 02 60 00 B1 C0
<= 41 04 F5 98 B2 E8 49 8D 99 8F 08 74 AD DB FC 89 05 F1 50 CB 2A F0 DE 0C 6A 80 05 9A 0C D0 16 84 61 F6 2F 92 78 C1 EE EC 80 75 26 5D CA 90 BD 9D E4 FA CC AB 44 A7 64 A8 3A 01 13 53 AF 8B 44 67 63 E2 70 EF 67 7A 9A E8 23 C4 2E A4 89 AB 57 B5 E4 83 9B D2 F4 3B BE 65 C2 C0 4F 40 34 D3 66 3D 65 BC CF D3 B4 3A B1 6F E0 55 E8 7F 2A 0B 9C 4F 90 EB 3F E1 E6 F3 97 51 6B 99 B0 FB 91 EC 1D 94 DD 22 0C 4D 08 E0 0F 3D 40 32 0B 10 F0 84 82 68 7F 93 2B 4B 41 9E 48 E4 46 3E C4 5E 16 17 BF 67 05 65 9E 49 A8 3F 61 74 B4 A9 27 17 F3 15 CA E5 CF 06 7D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 90 00
```

Get a trusted input (amount + prevout + signature) for the input to be used (transaction splitting is suboptimal and needs to be improved)

```
=> E0 42 00 00 0A 40 00 00 00 00 01 00 00 00 01
<= 90 00
=> E0 42 80 00 B3 BE E9 C0 53 3B 3C 27 70 33 77 1A 20 F8 8E FD 72 A2 54 EF 24 96 48 57 17 B1 D9 A3 0B E8 7F 5F 3C 01 00 00 00 8A 47 30 44 02 20 71 F3 6C BC 27 73 96 5F 51 55 30 C9 14 D2 B1 DF 7B B5 D7 83 09 7B EE CF D8 47 AB E9 43 05 38 65 02 20 2E C7 B3 E9 2E 44 C4 49 E5 C4 67 69 3E 55 D4 1E DE 02 BD AD A4 B0 1E 10 39 46 C2 13 05 57 30 CA 01 41 04 D3 19 77 1B E6 40 81 D8 5D 3C 5B 9F 24 CA 3F FD 41 00 B7 3F 11 6F D8 2B DF 8F C8 EF 38 51 04 D8 0D AB 84 F8 D0 D0 0A 3E 8E DB FC BC 50 E4 08 1F FF 14 27 E1 2E 19 FE 1F 64 9A 5A 77 B5 27 A9 F0 FF FF FF FF
<= 90 00
=> E0 42 80 00 01 02
<= 90 00
=> E0 42 80 00 22 80 1A 06 00 00 00 00 00 19 76 A9 14 72 A5 D7 5C 8D 2D 05 65 B6 56 A5 23 27 03 B1 67 D5 0D 5A 2B 88 AC
<= 90 00
=> E0 42 80 00 22 D7 04 2D 0A 09 00 00 00 19 76 A9 14 72 A5 45 43 71 B5 CE E0 7F 96 DC 4A 85 88 3A 1C 13 F4 DE 02 88 AC
<= 90 00
=> E0 42 80 00 04 00 00 00 00
<= 31 58 7D A4 77 D8 E5 F4 FC 27 A3 B6 E2 53 03 12 81 D6 1D 35 52 A9 CB 09 15 9C 26 F9 CE 2D 65 34 BB E5 3F 52 00 00 00 00 80 1A 06 00 00 00 00 00 11 1F 08 FC EA A1 57 A9 90 00 
``` 

Start encoding the transaction, sending 0.0025 BTC to 1BTChippcvEg44M1SkL5H8JfdVwTsv8AhP with 0.001 BTC fees

```
=> E0 44 00 00 07 00 01 01 00 00 00 01
<= 90 00
=> E0 44 80 00 3B 40 38 31 58 7D A4 77 D8 E5 F4 FC 27 A3 B6 E2 53 03 12 81 D6 1D 35 52 A9 CB 09 15 9C 26 F9 CE 2D 65 34 BB E5 3F 52 00 00 00 00 80 1A 06 00 00 00 00 00 11 1F 08 FC EA A1 57 A9 19
<= 90 00
=> E0 44 80 00 1D 76 A9 14 72 A5 D7 5C 8D 2D 05 65 B6 56 A5 23 27 03 B1 67 D5 0D 5A 2B 88 AC FF FF FF FF
<= 90 00
=> E0 46 02 00 A5 02 22 31 42 54 43 68 69 70 70 63 76 45 67 34 34 4D 31 53 6B 4C 35 48 38 4A 66 64 56 77 54 73 76 38 41 68 50 70 EF 67 7A 9A E8 23 C4 2E A4 89 AB 57 B5 E4 83 9B D2 F4 3B BE 65 C2 C0 4F 40 34 D3 66 3D 65 BC CF D3 B4 3A B1 6F E0 55 E8 7F 2A 0B 9C 4F 90 EB 3F E1 E6 F3 97 51 6B 99 B0 FB 91 EC 1D 94 DD 22 0C 4D 08 E0 0F 3D 40 32 0B 10 F0 84 82 68 7F 93 2B 4B 41 9E 48 E4 46 3E C4 5E 16 17 BF 67 05 65 9E 49 A8 3F 61 74 B4 A9 27 17 F3 15 CA E5 CF 06 7D 00 00 00 00 00 03 D0 90 00 00 00 00 00 01 86 A0
<= 45 02 90 D0 03 00 00 00 00 00 19 76 A9 14 72 A5 D7 5C 85 F0 D3 75 ED 4A 44 21 51 A6 17 9C 16 69 09 07 88 AC 50 C3 00 00 00 00 00 00 19 76 A9 14 F6 A8 6A 96 5F D4 9F A9 71 6C 96 9C FB 7C 72 0F C7 4E 57 82 88 AC 03 4E 46 43 90 00
```

Tap the tag on the phone, read on screen

```
Confirm transfer of 0.0025 BTC to 1BTChippcvEg44M1SkL5H8JfdVwTsv8AhP (fees 0.001 BTC,change 0.0005 BTC to 1PVCyxucVg1JUTFYDXvzpbCuA4uk564qTt) with PIN 2201
```

Finalize the transaction on the computer by entering the PIN (and reperforming the transaction from scratch, since the power was lost and Java Card hashes contexts cannot be persisted)

```
=> 00 A4 04 00 08 FF 42 54 43 48 49 50 01
<= 90 00
=> E0 44 00 80 05 01 00 00 00 01
<= 90 00
=> E0 44 80 80 3B 40 38 31 58 7D A4 77 D8 E5 F4 FC 27 A3 B6 E2 53 03 12 81 D6 1D 35 52 A9 CB 09 15 9C 26 F9 CE 2D 65 34 BB E5 3F 52 00 00 00 00 80 1A 06 00 00 00 00 00 11 1F 08 FC EA A1 57 A9 19
<= 90 00
=> E0 44 80 80 1D 76 A9 14 72 A5 D7 5C 8D 2D 05 65 B6 56 A5 23 27 03 B1 67 D5 0D 5A 2B 88 AC FF FF FF FF
<= 90 00
=> E0 46 02 00 A5 02 22 31 42 54 43 68 69 70 70 63 76 45 67 34 34 4D 31 53 6B 4C 35 48 38 4A 66 64 56 77 54 73 76 38 41 68 50 70 EF 67 7A 9A E8 23 C4 2E A4 89 AB 57 B5 E4 83 9B D2 F4 3B BE 65 C2 C0 4F 40 34 D3 66 3D 65 BC CF D3 B4 3A B1 6F E0 55 E8 7F 2A 0B 9C 4F 90 EB 3F E1 E6 F3 97 51 6B 99 B0 FB 91 EC 1D 94 DD 22 0C 4D 08 E0 0F 3D 40 32 0B 10 F0 84 82 68 7F 93 2B 4B 41 9E 48 E4 46 3E C4 5E 16 17 BF 67 05 65 9E 49 A8 3F 61 74 B4 A9 27 17 F3 15 CA E5 CF 06 7D 00 00 00 00 00 03 D0 90 00 00 00 00 00 01 86 A0
<= 45 02 90 D0 03 00 00 00 00 00 19 76 A9 14 72 A5 D7 5C 85 F0 D3 75 ED 4A 44 21 51 A6 17 9C 16 69 09 07 88 AC 50 C3 00 00 00 00 00 00 19 76 A9 14 F6 A8 6A 96 5F D4 9F A9 71 6C 96 9C FB 7C 72 0F C7 4E 57 82 88 AC 00 90 00
=> E0 48 00 00 7D 02 70 42 66 95 B6 6A 3F C3 4C 93 A6 A8 28 5D 7B 1F BA 20 20 4D BE 6C B9 BC F2 8F 0C BA 32 DA B9 BE F8 BE 94 D1 40 90 DE 7E C1 53 53 D1 FD 1B A8 07 32 72 64 9E 25 D5 AC 8F C8 D6 5E 79 AF 3A A4 5A 94 51 2F 75 CB 4D 68 05 31 2E 44 61 00 43 22 8D F9 F3 97 97 92 28 E4 7F 16 DD 67 CC B6 58 82 9A 63 D2 5A E3 9A 41 86 44 B2 9C 86 ED 60 CE 71 5E 98 00 04 32 32 30 31 00 00 00 00 01
<= [signature] 90 00
```

