package org.apache.shiro.spring.boot.utils;

import java.awt.List;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.Hex;

/**
 * 
 * 秘钥工具类
 */
public class SecretKeyUtils {

	/**
	 * AES算法
	 * java6支持56位密钥，bouncycastle支持64位
	 * */
	public final static String KEY_AES  = "AES";
	
	public final static String KEY_BASE64  = "Base64";
	
	public final static String KEY_DES  = "DES";
	
	public final static String KEY_DESEDE  = "DESede";
	/**
	 * RSA对称加密算法
	 */
	public final static String KEY_RSA  = "RSA";
	
	public final static String KEY_ECDSA  = "ECDSA";
	
	/** 密钥大小 */
	public static final int KEY_SIZE = 128;
	public static final int CACHE_SIZE = 1024;

	public static KeyPair genKeyPair(String algorithm) throws GeneralSecurityException {
		// 定义密钥长度1024位
		return SecretKeyUtils.genKeyPair(algorithm, CACHE_SIZE);
	}

	public static KeyPair genKeyPair(String algorithm, int keySize) throws GeneralSecurityException {
		// 通过KeyPairGenerator产生密钥,注意：这里的key是一对钥匙！！
		return SecretKeyUtils.genKeyPair(null, algorithm, keySize);
	}

	public static KeyPair genKeyPair(String seed, String algorithm, int keySize) throws GeneralSecurityException {
		// 产生一个密钥生成器KeyPairGenerator(顾名思义：一对钥匙生成器)
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(algorithm);
		// 初始化密钥生成器
		if (seed != null) {
			keyPairGen.initialize(keySize, SecretKeyUtils.genSecureRandom(seed));
		} else {
			keyPairGen.initialize(keySize);
		}
		// 通过KeyPairGenerator产生密钥,注意：这里的key是一对钥匙！！
		return keyPairGen.generateKeyPair();
	}

	public static PublicKey genPublicKey(String algorithm, byte[] pubKeyBytes) throws GeneralSecurityException {
		// 实例化秘钥工厂
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		// 构造X509EncodedKeySpec对象
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyBytes);
		// 取公钥匙对象
		return keyFactory.generatePublic(x509KeySpec);
	}

	public static PrivateKey genPrivateKey(String algorithm, byte[] prikeyBytes) throws GeneralSecurityException {
		// 实例化秘钥工厂
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		// 构造PKCS8EncodedKeySpec对象
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(prikeyBytes);
		// 取得私钥
		return keyFactory.generatePrivate(pkcs8KeySpec);
	}

	public static SecretKey genSecretKey(String key, String algorithm) throws GeneralSecurityException {
		return SecretKeyUtils.genSecretKey(key.getBytes(), algorithm);
	}

	public static SecretKey genSecretKey(byte[] key, String algorithm) throws GeneralSecurityException {
		return new SecretKeySpec(key, algorithm);
	}

	/**
	 * 
	 * <p>
	 * 根据秘钥种子生成随机密钥
	 * </p>
	 * @param seed 密钥种子
	 * @param algorithm 生成密匙的算法
	 * @param keySize  密匙长度
	 * @return 二进制密钥
	 * @throws GeneralSecurityException {@link GeneralSecurityException}
	 */
	public static SecretKey genSecretKey(String seed, String algorithm, int keySize) throws GeneralSecurityException {
		/*
		 * 如果要生成密钥，必须使用"真正的随机"数。 例如，在Random类中的常规的随机数发生器，是根据当前的日期和时间来产生随机数的，因此它不够随 机。
		 * 例如，假设计算机时钟可以精确到1/10秒，那么，每天最多存在864,000个种子。如果攻击者知道发布密钥的日期（通常可以由截止日期推算出 来），
		 * 那么就可以很容易地生成那一天所有可能的种子。 SecureRandom类产生的随机数，远比由Random类产生的那些数字安全得多。
		 * 你仍然需要提供一个种子，以便在一个随机点上开始生成数字 序列。 要这样做，最好的方法是从一个诸如白噪声发生器之类的硬件设备那里获取输入。
		 * 另一个合理的随机输入源是请用户在键盘上进行随心所欲的盲打，但是每次 敲击键盘只为随机种子提供1位或者2位。
		 * 一旦你在字节数组中收集到这种随机位后，就可以将它传递给setSeed方法或者构造器。
		 */
		// 实例化密钥生成器
		KeyGenerator keygen = KeyGenerator.getInstance(algorithm);
		if (null != seed) {
			// 初始化密钥生成器，AES要求密钥长度为128位、192位、256位；DES密匙长度为:56位，IDEA要求密钥长度为128位
			keygen.init(keySize, SecretKeyUtils.genSecureRandom(seed));
		} else {
			keygen.init(keySize);
		}
		// 生成密钥
		return keygen.generateKey();
	}

	public static SecretKey genSecretKey(String algorithm, int keysize) throws GeneralSecurityException {
		// 实例化密钥生成器
		KeyGenerator keygen = KeyGenerator.getInstance(algorithm);
		// 初始化密钥生成器
		keygen.init(keysize);
		// 产生密钥
		return keygen.generateKey();
	}

	public static SecretKey genSecretKey(String algorithm) throws GeneralSecurityException {
		// 初始化KeyGenerator
		KeyGenerator keygen = KeyGenerator.getInstance(algorithm);
		// 产生密钥
		return keygen.generateKey();
	}

	public static byte[] genBinarySecretKey(String seed, String algorithm, int keySize)
			throws GeneralSecurityException {
		// 获取二进制密钥编码形式
		return SecretKeyUtils.genSecretKey(seed, algorithm, keySize).getEncoded();
	}
 

	public static String genSecretKeyHex(String seed, String algorithm, int keySize) throws Exception {
		return Hex.encodeToString(SecretKeyUtils.genBinarySecretKey(seed, algorithm, keySize));
	}
 
	public static byte[] genBinarySecretKey(String algorithm) throws GeneralSecurityException {
		return SecretKeyUtils.genSecretKey(algorithm).getEncoded();
	}

	public static byte[] genBinarySecretKey(String algorithm, int keySize) throws GeneralSecurityException {
		return SecretKeyUtils.genBinarySecretKey(null, algorithm, keySize);
	}
 

	public static String genSecretKeyHex(String algorithm, int keySize) throws Exception {
		return Hex.encodeToString(SecretKeyUtils.genBinarySecretKey(algorithm, keySize));
	}

	public static String genSecretKeyBase64(String algorithm, int keySize) throws Exception {
		return Base64.encodeToString(SecretKeyUtils.genBinarySecretKey(algorithm, keySize));
	}

	/*
	 * 加密解密第一步：从一组固定的原始数据（也许是由口令或者随机击键产生的）来生成一个密钥
	 */
	public static SecretKey genSecretKey(KeySpec keySpec, String algorithm) throws GeneralSecurityException {
		// 生成指定秘密密钥算法的 SecretKeyFactory 对象。
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm);
		// 根据提供的密钥规范（密钥材料）生成 SecretKey 对象,利用密钥工厂把KeySpec转换成一个SecretKey对象
		return keyFactory.generateSecret(keySpec);
	}

	public static SecretKey genPBEKey(String password, String algorithm) throws GeneralSecurityException {
		return SecretKeyUtils.genPBEKey(password.toCharArray(), algorithm);
	}

	public static SecretKey genPBEKey(char[] password, String algorithm) throws GeneralSecurityException {
		// 实例化PBE密钥
		PBEKeySpec keySpec = new PBEKeySpec(password);
		// 生成密钥
		return SecretKeyUtils.genSecretKey(keySpec, algorithm);
	}

	public static SecretKey genDESKey(String key) throws GeneralSecurityException {
		return SecretKeyUtils.genDESKey(key.getBytes());
	}

	public static SecretKey genDESKey(byte[] key) throws GeneralSecurityException {
		// 实例化Des密钥
		DESKeySpec dks = new DESKeySpec(key);
		// 生成密钥
		return SecretKeyUtils.genSecretKey(dks, KEY_DES);
	}

	public static SecretKey genDESedeKey(String key) throws GeneralSecurityException {
		return SecretKeyUtils.genDESedeKey(key.getBytes());
	}

	public static SecretKey genDESedeKey(byte[] key) throws GeneralSecurityException {
		// 实例化Des密钥
		DESedeKeySpec dks = new DESedeKeySpec(key);
		// 生成密钥
		return SecretKeyUtils.genSecretKey(dks, KEY_DESEDE);
	}

	public static SecureRandom genSecureRandom() {
		return SecretKeyUtils.genSecureRandom(null);
	}

	public static SecureRandom genSecureRandom(String seed) {
		// 实例化安全随机数
		SecureRandom secureRandom;
		if (seed != null && !"".equals(seed)) {
			secureRandom = new SecureRandom(seed.getBytes());
		} else {
			secureRandom = new SecureRandom();
		}
		return secureRandom;
	}

	public static byte[] genRandomKey(int keysize) {
		// 生成随机数
		return SecretKeyUtils.genRandomKey(null, keysize);
	}

	public static byte[] genRandomKey(String seed, int keysize) {
		// 生成随机数
		return SecretKeyUtils.genSecureRandom(seed).generateSeed(keysize);
	}

	/*
	 * 从 *.key 文件中读取 SecretKey 对象
	 */
	public static SecretKey readKey(InputStream inStream) {
		SecretKey key = null;
		try {
			ObjectInputStream keyIn = new ObjectInputStream(inStream);
			// 读取SecretKey对象
			key = (SecretKey) keyIn.readObject();
			// 关闭输入流
			keyIn.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return key;
	}

	/*
	 * 将SecretKey 对象 写到 *.key 文件中
	 */
	public static void writeKey(Key key, OutputStream outStream) {
		try {
			ObjectOutputStream out = new ObjectOutputStream(outStream);
			out.writeObject(key);
			out.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) throws Exception {

		/*
		 * //AES要求密钥长度为128位、192位、256位；DES密匙长度为:56位 //生成AES密匙 Key key2 =
		 * SecretKeyUtils.genSecretKey(String.KEY_AES, 128); //保存AES密匙
		 * SecretKeyUtils.writeKey(key2, new FileOutputStream("D:/secret.key"));
		 */

		/*
		 * for (Provider p : Security.genProviders()) { //System.out.println(p); for
		 * (Map.Entry<Object, Object> entry : p.entrySet()) {
		 * System.out.println("\t"+entry.genKey()); } }
		 * 
		 * 公钥:
		 * MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJ2lJMMnKY/g8lufM/6SWFGjQ3j0F+bd1iAlRJb+7l2E
		 * JJjdWAw1pwoxUNVGN9sRd89tgALKD0R1dxESPHOxvBkCAwEAAQ==
		 * 
		 * 私钥:
		 * MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAnaUkwycpj+DyW58z/pJYUaNDePQX
		 * 5t3WICVElv7uXYQkmN1YDDWnCjFQ1UY32xF3z22AAsoPRHV3ERI8c7G8GQIDAQABAkBeQcyuRq8q
		 * ENS4BYOgFb5q6ZRBMKlN55vM0pulML4y+QxjU+k3wAs4DRqCS3KsNZvNbGZ+EVP1MaTkVGcKSdP1
		 * AiEAzT43tg76Kh7rW6PfJF8WLSsVCCdKORK1UIwvTsSCDc8CIQDEoYktcNCCKhz4z0nkldgoCtr2
		 * DEbZIyotAAbzGi+5lwIgPR2Iw1qkXYSFeu1KFe+Gj/6jLaFdda8/dHO55o+XVnsCIGU0z6p32ppk
		 * mqzl5J6nEa7qh3EFOKIim162GN2fqNjZAiA8BDdTl+wZ27S3dBJO803D0wn9BjSIY7CSnJrDrHF6
		 * LA==
		 *
		 */

		KeyPair key = SecretKeyUtils.genKeyPair("123456789456", KEY_RSA, 512);

		PublicKey pubKey = key.getPublic();
		String pub_key = Base64.encodeToString(pubKey.getEncoded());
		System.out.println("公钥: " + pub_key);

		PrivateKey priKey = key.getPrivate();
		String pri_key = Base64.encodeToString(priKey.getEncoded());
		System.out.println("私钥: " + pri_key);

		// System.out.println(Hex.encodeHexString(SecretKeyUtils.genRandomKey(32)));
	}

}
