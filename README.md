Ledger Unplugged - Open Source Java Card applet
===============================================

# Overview

This applet is an implementation of the Ledger Wallet Hardware Wallet [specification](https://ledgerhq.github.io/btchip-doc/bitcoin-technical.html) emulating an NFC Forum Type 4 tag to display the second factor, with [specific extensions](https://ledgerhq.github.io/btchip-doc/bitcoin-javacard.html)

It is [compatible with the core API](https://ledgerhq.github.io/btchip-doc/bitcoin-javacard.html#_generic_apdus_support) with a few limitations if not using a proprietary API to recover public keys - the public key cache needs to be provisioned from the client side.

A demonstration of this application and workaround if no proprietary API is present is provided in the [Python API](https://github.com/LedgerHQ/btchip-python) and also in [Mycelium](https://github.com/mycelium-com/wallet)

Several other integration examples are provided on [Ledger Unplugged product page](https://www.ledgerwallet.com/products/6-ledger-unplugged)

Developers can also check if a Java Card platform is supported and its performance with the [Eligibility applet](https://github.com/ledgerhq/ledger-javacard-eligibility)

All applet code is provided under the [GNU Affero General Public License v3](http://www.gnu.org/licenses/agpl-3.0.html) - for any question or commercial licensing, reach us at hello@ledger.fr

# Differences with Ledger Unplugged commercial versions

[Ledger Unplugged](https://www.ledgerwallet.com/products/6-ledger-unplugged) sold by Ledger on the Fidesmo platform or [downloaded on a Fidesmo enabled device](https://play.google.com/store/apps/details?id=com.fidesmo.sec.android) includes an NXP implementation of the [ProprietaryAPI interface](https://github.com/LedgerHQ/ledger-javacard/blob/master/src/com/ledger/wallet/ProprietaryAPI.java) which is only available under NDA, providing better performance regarding the speed of cryptographic operations.

Users are free to switch between the commercial version and their own version compiled from those sources, after deleting it.

The commercial version is also provisioned with an attestation key pair signed by a shared Ledger public key (see below) allowing a third party to check for genuine applications.

# Building

Due to heavy optimizations using a C preprocessor, building is currently recommended on a Unix platform or with MinGW on Windows. Pre built files are provided for reference only.

If you don't need to rebuild the preprocessed files, you can use an automated build with Ant. Otherwise, keep reading. 

First download a recent Java Card SDK (at least 3.0.1) from [Oracle](http://www.oracle.com) and install it

Then choose a building script - if building for an NFC only platform, build-no-ndef.sh is recommended. If you wish to test the NDEF second factor (typically on a platform supporting both NFC and a different interface), you can use build.sh instead

Then modify the build script to point JCENV to the installation directory, and possibly the applet and ELF AIDs if necessary. For example Fidesmo mandates a [specific AID](https://developer.fidesmo.com/javacard) according to your account configuration. 

Finally run the build script to generate a loadable .cap file in the build/ directory

# Installing 

## Installing on a generic Java Card platform

Installation can be done using global platform tools such as [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) or [GPShell](http://sourceforge.net/p/globalplatform/wiki/Home/)

Specific optional installation parameters are described in the [Java Card application specification](https://ledgerhq.github.io/btchip-doc/bitcoin-javacard.html#_installation_parameters)

## Installing on a Fidesmo device

First you'll need to [register a Fidesmo account](https://developer.fidesmo.com/signup)

Then you can use [Fidesmo API](https://developer.fidesmo.com/api) to upload the generated CAP file, and create a recipe to install and delete the application 

You can use the following samples 

For the App Description 

	{
        	"name": "Ledger Unplugged Development",
        	"description": {
			"en": "Test Ledger Unplugged application"
        	}
	}


For a service recipe to install the application (without installation parameters), replacing with your AIDs, provided by Fidesmo

	{
  		"description": {
    	"title": "Install Ledger Unplugged",
    	"description": [{
      		"lang": "en",
	      "value": "Test Ledger Unplugged install"
    	  }
    	],
	  },
  		"actions": [
        {
            "endpoint": "/ccm/install",
            "content": {
                "executableLoadFile" : "a0000006170054bf6aa95001",
                "executableModule" : "a0000006170054bf6aa94901",
                "application" : "a0000006170054bf6aa94901"
            }
        }
	  ],
	  "successMessage": "Application was installed",
	  "failureMessage": "Application couldn't be installed"	  
	}

For a service recipe to delete the application

	{
  		"description": {
    		"title": "Delete Ledger Unplugged",
    		"description": [{
      			"lang": "en",
      			"value": "Delete Test Ledger Unplugged"
      		}
    	]
	  	},
  		"actions": [
    	    {
        	    "endpoint": "/ccm/delete",
            	"content": {
                	"application" : "a0000006170054bf6aa95001",
                	"withRelated" : true
            	}
        	}
  		],
  		"successMessage": "Application was deleted",
  		"failureMessage": "Application couldn't be deleted"
	}

# Personalizing

## Manual personalization 

To perform a manual personalization, you'll need at least to : 

  - Select the application AID
  - Issue a FACTORY INITIALIZE KEYCARD SEED command
  - Issue a SETUP command

## Personalization through Ledger Wallet Android application

You'll need to rebuild a version of [Ledger Wallet application](https://github.com/LedgerHQ/ledger-wallet-android) with [your specific AID](https://github.com/LedgerHQ/ledger-wallet-android/blob/master/app/src/main/scala/co/ledger/wallet/nfc/Unplugged.scala)

# Using the application

## Mycelium 

Mycelium supports natively custom built versions of the application - just specify your instance AID in the Settings menu on the Ledger options group.

# Ledger public key

Each unique attestation public key is signed by the following Ledger public key on SECp256k1 for official applications

	045f68bcd470ba883aa646d90fd8cfee7ac3208e3a1e926bd6895eba5ae22bcd96ddeba7dfe25c7cec546f0f425b9d737de47302bf604f33fa5097a9992b4baf06
