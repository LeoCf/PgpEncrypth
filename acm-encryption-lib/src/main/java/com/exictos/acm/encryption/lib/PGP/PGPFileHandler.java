package com.exictos.acm.encryption.lib.PGP;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;
import org.springframework.stereotype.Component;

import com.exictos.acm.encryption.lib.Utils.EncryptionUtils;

/**
 * @author LCamacho
 * 
 *         Strategy class to Handle Files using Ppg, only static methods
 */
@Component
public final class PGPFileHandler extends PGP {

	private final static Logger log = Logger.getLogger(PGPFileHandler.class);

	private PGPFileHandler() {
		// No ar constructor private, this class is not suppossed to be initialized
	}

	/**
	 * Encrypth the File,
	 * 
	 * @param       fileName, File to be encrypted
	 * @param       outputfileLocation, encrypted file location
	 * @param aKey
	 * @param armor , ASCII armor the encrypted file or not
	 * @param       withIntegrityCheck, encrypth with integrity check
	 * @throws IOException
	 * @throws NoSuchProviderException
	 */
	public static void encrypt(String fileName, String outputfileLocation, PGPPublicKey aKey, String privateKeyLocation,
			char[] pass, boolean armor, boolean withIntegrityCheck) throws IOException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		OutputStream aFileOutputStream = new FileOutputStream(new File(outputfileLocation));
		InputStream aPrivateKeyInputStream = new FileInputStream(new File(privateKeyLocation));

		if (armor) {
			log.info("Encrypting " + fileName + " with armor");
			aFileOutputStream = new ArmoredOutputStream(aFileOutputStream);
		}

		try {
			PGPCompressedDataGenerator compressDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);
			log.info("Using BC as provider");
			PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
					new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck)
							.setSecureRandom(new SecureRandom()).setProvider("BC"));
			encGen.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(aKey));
			OutputStream encOut = compressDataGenerator.open(aFileOutputStream);

			// Signature
			PGPSecretKey pgpSec = EncryptionUtils.readSecretKey(aPrivateKeyInputStream);
			PGPPrivateKey pgpPrivateKey = pgpSec
					.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
			PGPSignatureGenerator sGen = new PGPSignatureGenerator(
					new JcaPGPContentSignerBuilder(aKey.getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

			sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivateKey);

			Iterator<String> it = pgpSec.getPublicKey().getUserIDs();
			if (it.hasNext()) {
				PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

				spGen.setSignerUserID(false, (String) it.next());
				sGen.setHashedSubpackets(spGen.generate());
			}
			BCPGOutputStream bOut = new BCPGOutputStream(encOut);

			sGen.generateOnePassVersion(false).encode(bOut);

			File file = new File(fileName);
			FileInputStream fIn = new FileInputStream(fileName);
			PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
			OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY, file);
			int ch;

			while ((ch = fIn.read()) >= 0) {
				lOut.write(ch);
				sGen.update((byte) ch);
			}

			lGen.close();
			sGen.generate().encode(bOut);
			encGen.close();
			fIn.close();
			encOut.close();
			aFileOutputStream.close();

		} catch (PGPException e) {
			log.error("Error on encrypting file " + fileName, e);
			if (e.getUnderlyingException() != null) {
				e.getUnderlyingException().printStackTrace();
			}
		}
	}

	/**
	 * Decrypths the File passed
	 */
	/**
	 * @param                    aFileToDecrypt, filePath to the file to be
	 *                           decripted
	 * @param                    decFilePath, decriptedFile location
	 * @param privateKeyLocation
	 * @param passPhrase
	 * @throws IOException
	 * @throws NoSuchProviderException
	 * @throws PGPException
	 * @throws SignatureException
	 */
	@SuppressWarnings({ "resource", "unchecked" })
	public static void decrypt(String aFileToDecrypt, String decFilePath, String privateKeyLocation, char[] passPhrase,
			InputStream aPublicKey) throws IOException, NoSuchProviderException, PGPException, SignatureException {
		final JcaKeyFingerprintCalculator aJcaKeyFingerprintCalculator = new JcaKeyFingerprintCalculator();
		// Add BouncyCastle as security Provider
		Security.addProvider(new BouncyCastleProvider());

		// Conversões Necessarias para processamento futoro
		InputStream aPgpKey = new FileInputStream(privateKeyLocation);
		InputStream aFileToDecrypthStream = new FileInputStream(aFileToDecrypt);
		OutputStream aDecFilePath = new FileOutputStream(new File(decFilePath));
		
		
		// Inicio algoritmo para a desincriptaçao
		InputStream aBCPInput =  PGPUtil.getDecoderStream(aFileToDecrypthStream);

		PGPObjectFactory pgpF = new PGPObjectFactory(aBCPInput, aJcaKeyFingerprintCalculator);
		PGPEncryptedDataList enc;

		Object o = pgpF.nextObject();
		//
		// the first object might be a PGP marker packet.
		//
		if (o instanceof PGPEncryptedDataList) {
			enc = (PGPEncryptedDataList) o;
		} else {
			enc = (PGPEncryptedDataList) pgpF.nextObject();
		}

		//
		// find the secret key
		//
		Iterator<?> it = enc.getEncryptedDataObjects();
		PGPPrivateKey sKey = null;
		PGPPublicKeyEncryptedData pbe = null;
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(aPgpKey, aJcaKeyFingerprintCalculator);

		while (sKey == null && it.hasNext()) {
			pbe = (PGPPublicKeyEncryptedData) it.next();
			sKey = PGP.findSecretKey(aPgpKey, pbe.getKeyID(), passPhrase);
		}

		if (sKey == null) {
			throw new IllegalArgumentException("secret key for message not found.");
		}

		InputStream clear = pbe
				.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));

		PGPObjectFactory plainFact = new PGPObjectFactory(clear, aJcaKeyFingerprintCalculator);

		Object message = null;

		PGPOnePassSignatureList onePassSignatureList = null;
		PGPSignatureList signatureList = null;
		PGPCompressedData compressedData = null;

		message = plainFact.nextObject();
		ByteArrayOutputStream actualOutput = new ByteArrayOutputStream();

		while (message != null) {
			log.trace(message.toString());
			if (message instanceof PGPCompressedData) {
				compressedData = (PGPCompressedData) message;
				plainFact = new PGPObjectFactory(compressedData.getDataStream(), aJcaKeyFingerprintCalculator);
				message = plainFact.nextObject();
			}

			if (message instanceof PGPLiteralData) {
				// have to read it and keep it somewhere.
				Streams.pipeAll(((PGPLiteralData) message).getInputStream(), actualOutput);
			} else if (message instanceof PGPOnePassSignatureList) {
				onePassSignatureList = (PGPOnePassSignatureList) message;
			} else if (message instanceof PGPSignatureList) {
				signatureList = (PGPSignatureList) message;
			} else {
				throw new PGPException("message unknown message type.");
			}
			message = plainFact.nextObject();
		}
		actualOutput.close();
		PGPPublicKey publicKey = null;
		byte[] output = actualOutput.toByteArray();
		if (onePassSignatureList == null || signatureList == null) {
			throw new PGPException("Poor PGP. Signatures not found.");
		} else {

			for (int i = 0; i < onePassSignatureList.size(); i++) {
				PGPOnePassSignature ops = onePassSignatureList.get(0);
				log.trace("verifier : " + ops.getKeyID());
				PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(aPgpKey,
						aJcaKeyFingerprintCalculator);
				publicKey = pgpRing.getPublicKey(ops.getKeyID());
				if (publicKey != null) {
					ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
					ops.update(output);
					PGPSignature signature = signatureList.get(i);
					if (ops.verify(signature)) {
						Iterator<?> userIds = publicKey.getUserIDs();
						while (userIds.hasNext()) {
							String userId = (String) userIds.next();
							// log.trace("Signed by {}", userId);
						}
						log.trace("Signature verified");
					} else {
						throw new SignatureException("Signature verification failed");
					}
				}
			}

		}

		if (pbe.isIntegrityProtected() && !pbe.verify()) {
			throw new PGPException("Data is integrity protected but integrity is lost.");
		} else if (publicKey == null) {
			throw new SignatureException("Signature not found");
		} else {
			aDecFilePath.write(output);
			aDecFilePath.flush();
			aDecFilePath.close();
		}
	}
}
