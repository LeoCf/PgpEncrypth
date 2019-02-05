package com.exictos.acm.encryption.lib.PGP;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.util.Date;
import java.util.Iterator;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

/**
 * @author LCamacho Base Class that implements core features of Pgp Common to
 *         both FileHandler and GenericObjectHandler used for encryption and
 *         decryption of files or differente types of object (example strings,
 *         or other classes)
 * 
 */
public abstract class PGP {
	
	
	/**
	 * Reads the Publick key from an input, for example a File and returns it;
	 * 
	 * @param input
	 * @return
	 * @throws IOException
	 * @throws PGPException
	 */
	public static final PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException {

		try {

			PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
					org.bouncycastle.openpgp.PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
			PGPPublicKey pubKey = null;

			Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();
			while (keyRingIter.hasNext() && (pubKey == null)) {
				PGPPublicKeyRing keyRing = keyRingIter.next();

				Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
				while (keyIter.hasNext()) {
					PGPPublicKey key = keyIter.next();

					if (key.isEncryptionKey()) {
						pubKey = key;
						break;
					}
				}
			}

			if (pubKey != null) {
				return pubKey;
			} else {
				throw new IllegalArgumentException("Can't find encryption key in key ring.");
			}

		} finally {

			if (input != null) {
				input.close();
			}
		}

	}

	/**
	 * Find Secret Key from PGPRing Collection /**
	 * 
	 * @param pgpSec
	 * @param keyID
	 * @param pass
	 * @return
	 * @throws PGPException
	 * @throws NoSuchProviderException
	 */
	static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
			throws PGPException, NoSuchProviderException {
		PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

		if (pgpSecKey == null) {
			return null;
		}

		return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
	}

	/**
	 * Compress the data in the file, and returns the corresponding bytes
	 * @param fileName
	 * @param algorithm
	 * @return
	 * @throws IOException
	 */
	static byte[] compress(String fileName, int algorithm) throws IOException {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
		PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));
		comData.close();
		return bOut.toByteArray();
	}

	/**
	 * Find Secret Key from PGPRing Collection
	 * 
	 * @param input
	 * @return
	 * @throws IOException
	 * @throws PGPException
	 */
	static PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input),
				new JcaKeyFingerprintCalculator());

		Iterator<PGPSecretKeyRing> keyRingIter = pgpSec.getKeyRings();
		while (keyRingIter.hasNext()) {
			PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();

			Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
			while (keyIter.hasNext()) {
				PGPSecretKey key = (PGPSecretKey) keyIter.next();

				if (key.isSigningKey()) {
					return key;
				}
			}
		}

		throw new IllegalArgumentException("Can't find signing key in key ring.");
	}

	/**
	 * Load a secret key and find the private key in it
	 * 
	 * @param pgpSecKey
	 * @param pass
	 * @return
	 * @throws PGPException
	 */
	public static PGPPrivateKey findPrivateKey(PGPSecretKey pgpSecKey, char[] pass) throws PGPException {
		if (pgpSecKey == null)
			return null;

		PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
				.build(pass);
		return pgpSecKey.extractPrivateKey(decryptor);
	}

	/**Find the secretKey when a privatekey input is passed
	 * 
	 * @param keyIn
	 * @param keyID
	 * @param pass
	 * @return
	 * @throws IOException
	 * @throws PGPException
	 * @throws NoSuchProviderException
	 */
	static PGPPrivateKey findSecretKey(InputStream keyIn, long keyID, char[] pass)
			throws IOException, PGPException, NoSuchProviderException {
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(keyIn, new JcaKeyFingerprintCalculator());
		PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

		if (pgpSecKey == null) {
			return null;
		}

		return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
	}

	/**
	 * Compress the data in a Byte
	 * 
	 * @param clearData
	 * @param fileName
	 * @param algorithm
	 * @return
	 * @throws IOException
	 */
	protected static byte[] compress(byte[] clearData, String fileName, int algorithm) throws IOException {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
		OutputStream cos = comData.open(bOut);
		PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
		OutputStream pOut = lData.open(cos, 
				PGPLiteralData.BINARY, fileName, 
				clearData.length, 
				new Date() 
		);
		pOut.write(clearData);
		pOut.close();
		comData.close();
		return bOut.toByteArray();
	}

}
