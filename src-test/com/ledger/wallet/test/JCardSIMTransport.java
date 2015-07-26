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

import com.licel.jcardsim.utils.ByteUtil;
import com.licel.jcardsim.base.Simulator;

import com.btchip.comm.BTChipTransport;
import com.btchip.BTChipException;

public class JCardSIMTransport implements BTChipTransport {

	private Simulator simulator;
	private boolean debug;

	public JCardSIMTransport(Simulator simulator, boolean debug) {
		this.simulator = simulator;
		this.debug = debug;
	}

	public JCardSIMTransport(Simulator simulator) {
		this(simulator, false);
	}

	@Override
    public byte[] exchange(byte[] command) throws BTChipException {
    	try {
    		if (debug) {
    			System.out.println("=> " + ByteUtil.hexString(command));
    		}
    		byte[] result = simulator.transmitCommand(command);
    		if (debug) {
    			System.out.println("<= " + ByteUtil.hexString(result));
    		}    		
    		return result;
    	}
    	catch(Exception e) {
    		throw new BTChipException("Simulator exception", e);
    	}
    }

    @Override
	public void close() throws BTChipException {		
	}

	@Override
	public void setDebug(boolean debugFlag) {
		this.debug = debug;
	}
}
