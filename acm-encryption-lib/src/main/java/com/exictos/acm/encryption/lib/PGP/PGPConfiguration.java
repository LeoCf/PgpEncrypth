package com.exictos.acm.encryption.lib.PGP;

/**
 * @author LCamacho Class to generate the configuration to be used by the
 *         encriptionMethod This class is a singleton
 */
public class PGPConfiguration implements EncriptionConfiguration {

	private String inputFilesFolderToEnc;
	private String outputFilesFolderEnc;
	private String outFilesFolderDec;
	private String publickKeyLocation;
	private String privateKeyLocation;
	private char[] password;
	private static PGPConfiguration aSimetricEncriptionConfigurationSingleton = null;

	private PGPConfiguration(Builder encriptionConfigBuilder) {
		publickKeyLocation = encriptionConfigBuilder.publickKeyLocation;
		privateKeyLocation = encriptionConfigBuilder.privateKeyLocation;
		password = encriptionConfigBuilder.password;
		inputFilesFolderToEnc = encriptionConfigBuilder.inputFilesFolderToEnc;
		outputFilesFolderEnc = encriptionConfigBuilder.outputFilesFolderEnc;
		outFilesFolderDec = encriptionConfigBuilder.outFilesFolderDec;
	}

	/**
	 * @param encriptionConfigBuilder Constructor for the configurationClass
	 */
	public static PGPConfiguration setPGPConfiguration(Builder encriptionConfigBuilder) {
		if (aSimetricEncriptionConfigurationSingleton == null)
			aSimetricEncriptionConfigurationSingleton = new PGPConfiguration(encriptionConfigBuilder);
		return aSimetricEncriptionConfigurationSingleton;

	}

	public static PGPConfiguration getPGPConfiguration() {
		return aSimetricEncriptionConfigurationSingleton;
	}

	public String getInputFilesFolderToEnc() {
		return inputFilesFolderToEnc;
	}

	public void setInputFilesFolderToEnc(String inputFilesFolderToEnc) {
		this.inputFilesFolderToEnc = inputFilesFolderToEnc;
	}

	public String getOutputFilesFolderEnc() {
		return outputFilesFolderEnc;
	}

	public void setOutputFilesFolderEnc(String outputFilesFolderEnc) {
		this.outputFilesFolderEnc = outputFilesFolderEnc;
	}

	public String getOutFilesFolderDec() {
		return outFilesFolderDec;
	}

	public void setOutFilesFolderDec(String outFilesFolderDec) {
		this.outFilesFolderDec = outFilesFolderDec;
	}

	public String getPublickKeyLocation() {
		return publickKeyLocation;
	}

	public void setPublickKeyLocation(String publickKeyLocation) {
		this.publickKeyLocation = publickKeyLocation;
	}

	public String getPrivateKeyLocation() {
		return privateKeyLocation;
	}

	public void setPrivateKeyLocation(String privateKeyLocation) {
		this.privateKeyLocation = privateKeyLocation;
	}

	public char[] getPassword() {
		return password;
	}

	public void setPassword(char[] password) {
		this.password = password;
	}

	/**
	 * @author LCamacho Static build for encryption class
	 */
	public static class Builder {

		private String inputFilesFolderToEnc;
		private String outputFilesFolderEnc;
		private String outFilesFolderDec;
		private String publickKeyLocation;
		private String privateKeyLocation;
		private char[] password;

		public Builder(String aPublicKeyPath, String aPrivateKeyPath, char[] aPassword) {
			publickKeyLocation = aPublicKeyPath;
			privateKeyLocation = aPrivateKeyPath;
			password = aPassword;
		}

		public Builder folderPathToFiles(String path) {
			inputFilesFolderToEnc = path;
			return this;
		}

		public Builder folderPathToEncFiles(String path) {
			outputFilesFolderEnc = path;
			return this;
		}

		public Builder folderPathToDecFiles(String path) {
			outFilesFolderDec = path;
			return this;
		}

		public PGPConfiguration build() {
			return PGPConfiguration.setPGPConfiguration(this);
		}
	}
}
