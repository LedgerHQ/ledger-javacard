Ledger Wallet Java Card applet
===============================

This applet is an implementation of the Ledger Wallet Hardware Wallet described at https://ledgerhq.github.io/btchip-doc/bitcoin-technical.html and emulating an NFC Forum Type 4 tag to display the second factor.

It is compatible with the core API with a few limitations if not using a proprietary API to recover public keys - the public key cache needs to be provisioned from the client side

A demonstration of this application and workaround if no proprietary API is present is provided in the Python API available at https://github.com/LedgerHQ/btchip-python

A demonstration of Electrum integration with the standard Ledger Wallet Plug-in is also available at https://www.youtube.com/watch?v=Vq11XgLT1Dw

You can also check if your Java Card is supported and its performance with the Eligibility applet available at https://github.com/ledgerhq/ledger-javacard-eligibility

For any question or commercial licensing, reach us at hello@ledger.fr

