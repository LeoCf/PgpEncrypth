package com.exictos.acm.encryption.lib.PGP;
import java.io.File;

import org.apache.log4j.BasicConfigurator;

public class TestePgpMain {

	/**
	 * @param args
	 * @throws Exception
	 */
	@SuppressWarnings("unused")
	public static void main(String[] args) throws Exception {

		BasicConfigurator.configure();
		
		final String inputFileLocation = "C:\\Users\\lcamacho\\Desktop\\acm\\Acm-FicheirosEnc\\ACM-Encrypth\\ficheirosAEncriptar\\CIEX_DESENCRIPTADO.txt";
		final String outputFileLocationEnc = "C:\\Users\\lcamacho\\Desktop\\acm\\Acm-FicheirosEnc\\ACM-Encrypth\\ficheirosEncriptados\\CIEX_DESENCRIPTADO.txt";
		final String inputFolderLocationToEncripth = "C:\\Users\\lcamacho\\Desktop\\acm\\Acm-FicheirosEnc\\ACM-Encrypth\\ficheirosAEncriptar\\";
		final String outputFolderLocationEncripted = "C:\\Users\\lcamacho\\Desktop\\acm\\Acm-FicheirosEnc\\ACM-Encrypth\\ficheirosEncriptados\\";
		final String outputFolderLocationDecripted = "C:\\Users\\lcamacho\\Desktop\\acm\\Acm-FicheirosEnc\\ACM-Encrypth\\ficheirosDesincriptados\\";
		final String privateKeyLocation = "C:\\Users\\lcamacho\\Desktop\\acm\\UAT\\private.gpg";
		final String publicKeyLocation = "C:\\Users\\lcamacho\\Desktop\\acm\\UAT\\publica.asc";

		EncriptionConfiguration aConfiguration = new PGPConfiguration.Builder(publicKeyLocation,privateKeyLocation,"leonel".toCharArray())
		.folderPathToFiles(inputFolderLocationToEncripth).folderPathToEncFiles(outputFolderLocationEncripted).folderPathToDecFiles(outputFolderLocationDecripted).build();
		
		
		EncryptionMethod aPGPEncriptionMethod = EncryptionMethodFactory.getEncryption("PGP");
		
		//Encriptar Ficheiros numa pasta
		//aPGPEncriptionMethod.encryptFilesInFolder(inputFolderLocationToEncripth,outputFolderLocationEncripted);
		
		//Desincriptar Ficheiros numa pasta
		//aPGPEncriptionMethod.deCrypthFilesInFolder(outputFolderLocationEncripted,outputFolderLocationDecripted);
		
		//Encriptar Ficheiro
		aPGPEncriptionMethod.encryptFile(new File(inputFileLocation),outputFileLocationEnc,publicKeyLocation);
		
		//Desincriptar Ficheiro
		aPGPEncriptionMethod.deCrypthFile(new File(outputFileLocationEnc+".gpg"),outputFileLocationEnc,publicKeyLocation);
		
	}

}
