package com.exictos.acm.encryption.lib.PGP;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

import org.apache.commons.io.FilenameUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.openpgp.PGPPublicKey;

/**
 * @author LCamacho Class that handles encryption call methods from PGPFile
 *         handler and PgpGericObject
 */
public class PGPEncryptionMethod implements EncryptionMethod {
	
	private  enum PGPSupportExtension{ GPG, ASC, PGP};
	private final static Logger log = Logger.getLogger(PGPEncryptionMethod.class);
	protected static final String ENCRYPTION_EXTENSION = ".gpg";
	private final String privateKeyPath;
	private final String publickKeyPath;
	private final char[] password;
	private String outputFilesFolderEnc;
	private String outFilesFolderDec;

	/**
	 * @param aEncriptionConfiguration
	 */
	public PGPEncryptionMethod(EncriptionConfiguration aEncriptionConfiguration) {
		this.outputFilesFolderEnc = aEncriptionConfiguration.getOutputFilesFolderEnc();
		this.outFilesFolderDec = aEncriptionConfiguration.getOutFilesFolderDec();
		this.publickKeyPath = aEncriptionConfiguration.getPublickKeyLocation();
		this.privateKeyPath = aEncriptionConfiguration.getPrivateKeyLocation();
		this.password = aEncriptionConfiguration.getPassword();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.exictos.acm.encryption.lib.PGP.EncryptionMethod#encryptFile(java.io.File)
	 * Encrypths a file
	 */
	public void encryptFile(File aFile, String outputUserFileLocation,String publicKeyPath) throws Exception {
		log.info("Started file encryption of file " + aFile.getName());
		FileInputStream publickKeyFile = new FileInputStream(verifyKeyPath(publicKeyPath));
		PGPPublicKey aPublicKey = PGP.readPublicKey(publickKeyFile);
		String outPutLocation = verifyInputFile(outputUserFileLocation);
		String fileExtension = "." + FilenameUtils.getExtension(aFile.getName());
		if (aFile.isFile()) {
			PGPFileHandler.encrypt(aFile.getAbsolutePath(), outPutLocation + fileExtension + ENCRYPTION_EXTENSION,
					aPublicKey, privateKeyPath, password, false, true);
			log.info("Finished file encryption of file " + aFile.getName());
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.exictos.acm.encryption.lib.PGP.EncryptionMethod#encryptFilesInFolder(java
	 * .lang.String) Encrypth Files in the FolderPath
	 */
	public void encryptFilesInFolder(String aFolderPathArgument, String outputFolderPathLocation,String publicKeyPath) throws Exception {
		log.info("Started folder content encryption for folder" + aFolderPathArgument);
		File[] aFileInputList = verifyFolder(new File(aFolderPathArgument));
		String outputLocation = choseFolderLocation(outputFilesFolderEnc, outputFolderPathLocation);
		FileInputStream publickKeyFile = new FileInputStream(verifyKeyPath(publicKeyPath));
		PGPPublicKey aPublicKey = PGP.readPublicKey(publickKeyFile);
		for (File aFile : aFileInputList) {
			if (aFile.isFile()) {
				PGPFileHandler.encrypt(aFile.getAbsolutePath(), outputLocation + aFile.getName() + ENCRYPTION_EXTENSION,
						aPublicKey, privateKeyPath, password, false, true);
			}
		}
		log.info("Finished folder content encryption for folder" + aFolderPathArgument);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.exictos.acm.encryption.lib.PGP.EncryptionMethod#encryptObject(java.lang.
	 * Object) Encrypth a generic Object return a byte[] with the encrypth object
	 * content
	 */
	public byte[] encryptObject(Object aGenericObject) throws Exception {
		log.info("Started object Encryption " + aGenericObject.getClass());
		FileInputStream publickKeyFile = new FileInputStream(this.publickKeyPath);
		PGPPublicKey aPublicKey = PGP.readPublicKey(publickKeyFile);
		return PGPGenericObjectHandler.encryptGenericObject(aGenericObject, aPublicKey, false, false);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.exictos.acm.encryption.lib.PGP.EncryptionMethod#deCrypthFile(java.io.
	 * File) Decrypths a specified aFile
	 */
	public void deCrypthFile(File aFile, String outPutFileLocation,String publicKeyLocation) throws Exception {
		log.info("Started file decryption of file " + aFile.getName());
		String outputLocation = verifyInputFile(outPutFileLocation);
		String inputFileLocation;
		String inputfileExtension;
		if (aFile.isFile()) {
			inputFileLocation = aFile.getName();
			inputFileLocation = inputFileLocation.substring(0, inputFileLocation.lastIndexOf('.'));
			inputfileExtension = FilenameUtils.getExtension(inputFileLocation);
			outputLocation = outputLocation + "." + inputfileExtension;
			InputStream aPublicKeyInputStream = new FileInputStream(publicKeyLocation);
			PGPFileHandler.decrypt(aFile.getAbsolutePath(), outputLocation, privateKeyPath, password,aPublicKeyInputStream);
			log.info("Ended file decryption of file " + aFile.getName());
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.exictos.acm.encryption.lib.PGP.EncryptionMethod#deCrypthFilesInFolder(
	 * java.lang.String) Decrypths files presente in the specified folder
	 */
	public void deCrypthFilesInFolder(String aFolderPathArgument, String userOutputFolderLocation, String publicKeyLocation) throws Exception {
		log.info("Started folder content decryption for folder" + aFolderPathArgument);
		File[] aFileList = verifyFolder(new File(aFolderPathArgument));
		String aDecFileName = choseFolderLocation(outFilesFolderDec, userOutputFolderLocation);
		String aOutputDecName;
		InputStream aPublicKeyInputStream = new FileInputStream(publicKeyLocation);
		for (File aFile : aFileList)
			if (aFile.isFile()) {
				aOutputDecName = aDecFileName.concat(aFile.getName());
				aOutputDecName = aOutputDecName.substring(0, aOutputDecName.lastIndexOf('.'));
				PGPFileHandler.decrypt(aFile.getAbsolutePath(), aOutputDecName, privateKeyPath, password,aPublicKeyInputStream);
			}
		log.info("Ended folder content decryption for folder" + aFolderPathArgument);
	}

	/*
	 * (non-Javadoc) Decrypth a generic Object, receives the decrypted object in
	 * bytes and output a object representing the decrypted object.
	 * 
	 * @see
	 * com.exictos.acm.encryption.lib.PGP.EncryptionMethod#deCrypthObject(byte[])
	 */
	public Object deCrypthObject(byte[] aEncriptedObjectByte) throws Exception {
		return PGPGenericObjectHandler.decryptGenericObject(aEncriptedObjectByte, privateKeyPath, password);
	}

	/**
	 * Choose folder Location depending on the user input
	 * 
	 * @param configPath
	 * @param userPath
	 * @return
	 */
	private String choseFolderLocation(String configPath, String userPath) {
		if (userPath.isEmpty() || userPath == null || userPath.length() < 3)
			return configPath;
		else
			return userPath;
	}

	/**
	 * Verify if provided file is a directory if a file is directory then returns a
	 * list of files
	 * 
	 * @param aFolder
	 * @return
	 */
	private File[] verifyFolder(File aFolder) {
		if (aFolder.isDirectory()) {
			return aFolder.listFiles();
		}
		return null;
	}
	
	
	/** Verify and removes file Extension from filePath
	 * @param aFilePath
	 * @return
	 */
	private String verifyInputFile(String aFilePath) {
		File aFile = new File(aFilePath);
		if (aFile.isAbsolute()) {
			return FilenameUtils.removeExtension(aFilePath);

		}
		return null;
	}
	
	
	
	/** Verifies if the key Path file has the correct extension
	 * @param aKeyPath
	 * @return
	 */
	private String verifyKeyPath(String aKeyPath) {
		File aFile = new File(aKeyPath);
		String aKeyExtension = FilenameUtils.getExtension(aFile.getName());
		if (!validateExtensions(aKeyExtension)) {
			aKeyPath = publickKeyPath;
		}
		return aKeyPath;
	}
	
	
	/** Validate Extensions wih the extensions specified in the enum 
	 * @param aExtension
	 * @return
	 */
	private Boolean validateExtensions(String aExtension) {
		boolean extensionVal = false;
		for(PGPSupportExtension supportedExtension : PGPSupportExtension.values()) {
			if((aExtension.equalsIgnoreCase(supportedExtension.toString())))
					extensionVal = true;
		}
			return extensionVal;
	}

}
