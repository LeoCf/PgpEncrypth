package com.exictos.acm.encryption.lib.PGP;


/** 
 * @author LCamacho
 * Interface to specify the encription configuration for simetric encryption
 */
public interface EncriptionConfiguration {


	String getInputFilesFolderToEnc();

	void setInputFilesFolderToEnc(String inputFilesFolderToEnc);

	String getOutputFilesFolderEnc();

	void setOutputFilesFolderEnc(String outputFilesFolderEnc);

	String getOutFilesFolderDec();

	void setOutFilesFolderDec(String outFilesFolderDec);

	String getPublickKeyLocation();

	void setPublickKeyLocation(String publickKeyLocation);

	String getPrivateKeyLocation();

	void setPrivateKeyLocation(String privateKeyLocation);

	char[] getPassword();

	void setPassword(char[] password);

}