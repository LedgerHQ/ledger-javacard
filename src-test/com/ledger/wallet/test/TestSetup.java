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

public class TestSetup extends AbstractTest {

	public static final String EXPECTED_ADDRESS_1 = "n4CYzppnrJViRcUrezwcSdwwGERAcHScQZ";
	public static final byte[] EXPECTED_PUBLIC_KEY_1 = ByteUtil.byteArray("04a44e52606aaafa575c3d9c2d09819ce885ab4066bb7d1e8d61acae24986ab4579b9fb5742b49fa3dcf508242ba31f01ee889072159cd6aff27048d7ba4e9e3f0");
	public static final byte[] EXPECTED_CHAINCODE_1 = ByteUtil.byteArray("80ecfe04ceeabc5745b0eeeb5b5f36d0f40119e18c865cf8d5a407bcb6e8b88c");

	public void testSetupRestoreTestnet() throws BTChipException {
		BTChipDongle dongle = prepareDongleRestoreTestnet(false);
		dongle.verifyPin(DEFAULT_PIN);
		BTChipDongle.BTChipPublicKey publicKey = dongle.getWalletPublicKey("");
		assertEquals(publicKey.getAddress(), EXPECTED_ADDRESS_1);
		assertTrue(Arrays.equals(publicKey.getPublicKey(), EXPECTED_PUBLIC_KEY_1));
		assertTrue(Arrays.equals(publicKey.getChainCode(), EXPECTED_CHAINCODE_1));	
	}
}
