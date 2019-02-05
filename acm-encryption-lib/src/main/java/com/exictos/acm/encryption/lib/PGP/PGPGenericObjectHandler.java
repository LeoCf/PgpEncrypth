package com.exictos.acm.encryption.lib.PGP;



import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;
import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.util.io.Streams;
import org.springframework.stereotype.Component;

import com.exictos.acm.encryption.lib.Utils.EncryptionUtils;

/**
 * @author LCamacho Strategy to handle GenericObjectHandler, holds static methods to handle file encryption
 */
@Component
public final class PGPGenericObjectHandler extends PGP {
	
	private final static Logger log = Logger.getLogger(PGPGenericObjectHandler.class);

	private PGPGenericObjectHandler() {
		// No ar constructor private, this class is not suppossed to be initialized
	}
	
	
	
	/** Encrypth Generic Object 
	 * @param aObject, a object must
	 * @param pk a PGPPublicKey
	 * @param armor, ASCII Armor the encrypted Object 
	 * @param withIntegrityCheck
	 * @return
	 * @throws IOException
	 * @throws PGPException
	 * @throws NoSuchProviderException
	 */
	public static byte[] encryptGenericObject(Object aObject, PGPPublicKey pk, boolean armor,
			boolean withIntegrityCheck) throws IOException, PGPException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		byte[] aByteArrayToEncrypth = EncryptionUtils.serialize(aObject);
		String fileName = null;

		if (fileName == null) {
			fileName = PGPLiteralData.CONSOLE;
		}

		byte[] compressedData = compress(aByteArrayToEncrypth, fileName, CompressionAlgorithmTags.ZIP);

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		OutputStream out = bOut;
		if (armor) {
			out = new ArmoredOutputStream(out);
		}

		PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck)
						.setSecureRandom(new SecureRandom()).setProvider("BC"));
		encGen.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(pk));
		OutputStream encOut = encGen.open(out, compressedData.length);

		encOut.write(compressedData);
		encOut.close();
		
		if (armor) {
			out.close();
		}
		log.info("Finished Object Encryption");
		return bOut.toByteArray();

	}

	/**
	 * Method to Encrypth any object that can be convert to byte Array[]
	 * 
	 * @param aByteArrayToDEcrypth,
	 * @param keyIn,
	 * @param passwd
	 * @return
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
	public static Object decryptGenericObject(byte[] aByteArrayToDEcrypth, String keyIn, char[] passwd)
			throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		InputStream aPrivateKey = new FileInputStream(keyIn);
		JcaKeyFingerprintCalculator aJcaKeyFingerprintCalculator = new JcaKeyFingerprintCalculator();
		byte[] byteOutput = null;
		PGPObjectFactory pgpF = new PGPObjectFactory(aByteArrayToDEcrypth, new JcaKeyFingerprintCalculator());
		PGPEncryptedDataList enc;
		Object o = pgpF.nextObject();
		if (o instanceof PGPEncryptedDataList) {
			enc = (PGPEncryptedDataList) o;
		} else {
			enc = (PGPEncryptedDataList) pgpF.nextObject();
		}

		Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
		PGPPrivateKey sKey = null;
		PGPPublicKeyEncryptedData pbe = null;

		while (sKey == null && it.hasNext()) {
			pbe = it.next();

			sKey = findSecretKey(aPrivateKey, pbe.getKeyID(), passwd);
		}

		if (sKey == null) {
			throw new IllegalArgumentException("Secret key for message not found.");
		}

		InputStream clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));

		PGPObjectFactory plainFact = new PGPObjectFactory(clear, aJcaKeyFingerprintCalculator);

		Object message = plainFact.nextObject();

		if (message instanceof PGPCompressedData) {
			PGPCompressedData cData = (PGPCompressedData) message;
			PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream(), aJcaKeyFingerprintCalculator);

			message = pgpFact.nextObject();
		}

		if (message instanceof PGPLiteralData) {
			PGPLiteralData ld = (PGPLiteralData) message;
			byteOutput = (Streams.readAll(ld.getInputStream()));
		} else {
			if (message instanceof PGPOnePassSignatureList) {
				throw new PGPException("Encrypted message contains a signed message - not literal data.");
			} else {
				throw new PGPException("Message is not a simple encrypted file - type unknown.");
			}
		}
		
		Object aDecObject = EncryptionUtils.deserialize(byteOutput);
		log.info("Finished Object decryption");
		return aDecObject;
	}


}
