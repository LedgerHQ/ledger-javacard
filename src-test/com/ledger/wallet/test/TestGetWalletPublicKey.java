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

public class TestGetWalletPublicKey extends AbstractTest {

	public static final String EXPECTED_ADDRESS_1 = "mtVeEwnNwH23GuURg2MzPmzKPGzzgTe4vx";
	public static final byte[] EXPECTED_PUBLIC_KEY_1 = ByteUtil.byteArray("0475e55e9edef059e186c27610c15c611921ebe82306013519c227c114a3baca01921e222b8bba28c142480edba7efd19e7d8e58140e1b0b358dcf1bb7e5ef7129");
	public static final byte[] EXPECTED_CHAINCODE_1 = ByteUtil.byteArray("363e279a6f13e362bdceb6bcd4335b687cc6fdd5a31b3513afe45381af745348");

	public void testGetWalletPublicKey() throws BTChipException {
		BTChipDongle dongle = prepareDongleRestoreTestnet(false);
		dongle.verifyPin(DEFAULT_PIN);
		BTChipDongle.BTChipPublicKey publicKey = dongle.getWalletPublicKey("44'/0'/0'/0/42");
		assertEquals(publicKey.getAddress(), EXPECTED_ADDRESS_1);
		assertTrue(Arrays.equals(publicKey.getPublicKey(), EXPECTED_PUBLIC_KEY_1));
		assertTrue(Arrays.equals(publicKey.getChainCode(), EXPECTED_CHAINCODE_1));	
	}

}
