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

public class TestSignMessage extends AbstractTest {

	public static final String MSG = "Test Message";
	public static final byte[] EXPECTED_SIGNATURE = ByteUtil.byteArray("304402201ffa0304ea885f1fe955a39a392bbb1484ce094434dc7237a74245b5821e45b20220106f633fa68a18f21d5c3b130e9a5553fc231113b60db0a10d555cb95b11c946");

	public void testSignMessage() throws BTChipException {
		BTChipDongle dongle = prepareDongleRestoreTestnet(true);
		dongle.verifyPin(DEFAULT_PIN);
		dongle.signMessagePrepare("13'/0'/0'/0/42", MSG.getBytes());
		BTChipDongle.BTChipSignature signature = dongle.signMessageSign(null);		
		assertTrue(Arrays.equals(canonicalizeSignature(signature.getSignature()), EXPECTED_SIGNATURE));
	}

}
