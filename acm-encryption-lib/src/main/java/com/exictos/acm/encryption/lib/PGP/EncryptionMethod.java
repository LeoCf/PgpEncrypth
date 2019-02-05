package com.exictos.acm.encryption.lib.PGP;
import java.io.File;

/**
 * @author LCamacho
 * Interface for Encryption Method 
 */
public interface EncryptionMethod  {

	 void encryptFile(File aFile,String outFilePutLocation,String aPublickKey) throws Exception;
	 void encryptFilesInFolder(String aFolderPath,String outPutFolderPath,String aPublickKey) throws Exception;
	 byte[] encryptObject(Object aGenericObject) throws Exception;
	 void deCrypthFile(File aFile,String outPutFileLocation,String publicKey) throws Exception;
	 void deCrypthFilesInFolder(String aFolderPath,String outPutFolderPath,String publicKey) throws Exception; 
	 Object deCrypthObject(byte[] aEncriptedObjectByte) throws Exception;

}


