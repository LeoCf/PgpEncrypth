package com.exictos.acm.encryption.lib.PGP;

/**
 * @author LCamacho Factory Method returns encryptionMethod
 */

public final class EncryptionMethodFactory {

	/** Returns Encryption Method 
	 * @param aEncriptionConfiguration
	 * @return
	 */
	public static EncryptionMethod getEncryption(String aEncriptionMethod) {
		EncryptionMethod aEncryptionType = null;
		if(!(aEncriptionMethod == null))
		{  
		switch(aEncriptionMethod) {
			case "PGP" :  aEncryptionType =new PGPEncryptionMethod(PGPConfiguration.getPGPConfiguration());
			break;
			case "AES" : 
			break;
			default:
				aEncryptionType =new PGPEncryptionMethod(PGPConfiguration.getPGPConfiguration());
			}
		}
		return 	aEncryptionType;
	}
}
