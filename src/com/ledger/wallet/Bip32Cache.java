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

package com.ledger.wallet;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class Bip32Cache {
	
	private static final short CACHE_SIZE = (short)10;
	private static short lastIndex = (short)0;
	
	private byte[] privateComponent;
	private byte[] publicComponent;
	private byte[] path;
	private byte pathLength;
	private boolean hasPrivate;
	private boolean hasPublic;
	
	private static Bip32Cache[] cache = null;
	private static byte[] lastCacheIndex;
	
	private static final byte INDEX_NOT_AVAILABLE = (byte)0xff;
	
	public Bip32Cache() {
		privateComponent = new byte[64];
		publicComponent = new byte[65];
		path = new byte[40];
		lastCacheIndex = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_DESELECT);
	}
	
	public static void init() {
		cache = new Bip32Cache[CACHE_SIZE];
		for (short i=0; i<CACHE_SIZE; i++) {
			cache[i] = new Bip32Cache();
		}
	}
	
	private static Bip32Cache findFree() {
		Bip32Cache result = null;
		for (short i=0; i<CACHE_SIZE; i++) {
			if (cache[i].pathLength == 0) {
				result = cache[i];
				break;
			}
		}
		if (result == null) {
			lastIndex++;
			lastIndex %= CACHE_SIZE;
			result = cache[lastIndex];
		}
		// Recycle
		result.pathLength = (byte)0;
		result.hasPrivate = false;
		result.hasPublic = false;
		return result;
	}
		
	private static Bip32Cache findPath(byte[] path, short pathOffset, byte pathLength, boolean setLast) {
		for (short i=0; i<CACHE_SIZE; i++) {
			if ((cache[i].pathLength == pathLength) &&
				(Util.arrayCompare(path, pathOffset, cache[i].path, (short)0, (short)(pathLength * 4)) == 0)) {
					if (setLast) {
						lastCacheIndex[0] = (byte)i;
					}
					return cache[i];
			}
		}
		return null;
	}
	
	public static void storePrivate(byte[] path, short pathOffset, byte pathLength, byte[] privateComponent) {
		Bip32Cache cache = findPath(path, pathOffset, pathLength, false);
		if (!((cache != null) && cache.hasPrivate)) {
			if (cache == null) {
				cache = findFree();
			}
			cache.pathLength = pathLength;
			Util.arrayCopy(path, pathOffset, cache.path, (short)0, (short)(pathLength * 4));
			Util.arrayCopy(privateComponent, (short)0, cache.privateComponent, (short)0, (short)64);
			cache.hasPrivate = true;		
		}
	}
	
	public static void storePublic(byte[] path, short pathOffset, byte pathLength, byte[] publicComponent) {
		Bip32Cache cache = findPath(path, pathOffset, pathLength, false);
		if (!((cache != null) && cache.hasPublic)) {
			if (cache == null) {
				cache = findFree();
			}
			cache.pathLength = pathLength;
			Util.arrayCopy(path, pathOffset, cache.path, (short)0, (short)(pathLength * 4));
			Util.arrayCopy(publicComponent, (short)0, cache.publicComponent, (short)0, (short)65);
			cache.hasPublic = true;
		}		
	}
	
	public static byte copyPrivateBest(byte[] path, short pathOffset, byte pathLength, byte[] target, short targetOffset) {
		for (byte i=pathLength; i>0; i--) {
			Bip32Cache cache = findPath(path, pathOffset, i, false);
			if ((cache != null) && (cache.hasPrivate)) {
				Util.arrayCopyNonAtomic(cache.privateComponent, (short)0, target, targetOffset, (short)64);
				return i;
			}					
		}
		return (byte)0;
	}
	
	public static boolean setPublicIndex(byte[] path, short pathOffset, byte pathLength) {
		Bip32Cache cache = findPath(path, pathOffset, pathLength, true);
		if ((cache == null) || (!cache.hasPublic)) {
			lastCacheIndex[0] = INDEX_NOT_AVAILABLE;		
			return false;
		}		
		return true;		
	}
		
	public static boolean copyLastPublic(byte[] target, short targetOffset) {
		Bip32Cache lastCache;
		if (lastCacheIndex[0] == INDEX_NOT_AVAILABLE) {
			return false;
		}
		lastCache = cache[lastCacheIndex[0]];
		if (!lastCache.hasPublic) {
			return false;
		}
		Util.arrayCopyNonAtomic(lastCache.publicComponent, (short)0, target, targetOffset, (short)65);
		return false;
	}
	
}
