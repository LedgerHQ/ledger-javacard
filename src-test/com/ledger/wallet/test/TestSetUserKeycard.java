/*
*******************************************************************************    
*   Java Card Bitcoin Hardware Wallet
*   (c) 2015 Ledger
*   
*   This program is free software: you can redistribute it and/or modify
*   it under the terms of the GNU Affero General Public License as
*   published by the Free Software Foundation, either version 3 of the
*   License, or (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU Affero General Public License for more details.
*
*   You should have received a copy of the GNU Affero General Public License
*   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*******************************************************************************   
*/    

package com.ledger.wallet.test;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import junit.framework.TestCase;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.licel.jcardsim.utils.ByteUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import com.ledger.wallet.LedgerWalletApplet;
import com.btchip.BTChipDongle;
import com.btchip.BTChipConstants;
import com.btchip.BTChipException;
import com.btchip.BitcoinTransaction;

public class TestSetUserKeycard extends AbstractTest {

	public void testSetUserKeycard() throws BTChipException {
		byte[] newKeycard = new byte[16];
		for (byte i=0; i<16; i++) {
			newKeycard[i] = (byte)(i + (byte)0x20);
		}
		KeycardHelper keycardHelper = new KeycardHelper(DEFAULT_KEYCARD);
		KeycardHelper keycardHelperNew = new KeycardHelper(newKeycard);
		BTChipDongle dongle = prepareDongleRestoreTestnet(true);
		dongle.verifyPin(DEFAULT_PIN);
		byte[] challenge = dongle.setUserKeycard(DEFAULT_KEYCARD_ADDRESS_SIZE, newKeycard);
		dongle.confirmUserKeycard(keycardHelper.getPIN(challenge));
		challenge = dongle.setUserKeycard(DEFAULT_KEYCARD_ADDRESS_SIZE, DEFAULT_KEYCARD);
		dongle.confirmUserKeycard(keycardHelperNew.getPIN(challenge));
	}

}
