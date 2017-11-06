/*
 * (C) Copyright 2017 Bluberrie Labs (http://bluberrie.io/).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package io.bluberrie.auth.simplauthservice;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.json.JSONObject;

import io.bluberrie.auth.simplauthservice.blobs.ErrorData;
import io.bluberrie.auth.simplauthservice.persist.SimpleUser;

public class Util {

	private static SecureRandom random = new SecureRandom();

	public static byte[] hashPassword( final char[] password, final byte[] salt, final int iterations, final int keyLength ) {

		try {
			SecretKeyFactory skf = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA512" );
			PBEKeySpec spec = new PBEKeySpec( password, salt, iterations, keyLength );
			SecretKey key = skf.generateSecret( spec );
			byte[] res = key.getEncoded( );
			return Base64.getEncoder().encode(res);

		} catch( NoSuchAlgorithmException | InvalidKeySpecException e ) {
			throw new RuntimeException( e );
		}
	}

	public static PrivateKey loadPrivateKey(KeyFactory factory, String filename) throws InvalidKeySpecException, FileNotFoundException, IOException {
		byte[] content = loadFile(filename).getContent();
		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
		return factory.generatePrivate(privKeySpec);
	}

	public static PublicKey loadPublicKey(KeyFactory factory, String filename) throws InvalidKeySpecException, FileNotFoundException, IOException {
		byte[] content = loadFile(filename).getContent();
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
		return factory.generatePublic(pubKeySpec);
	}

	private static PemObject loadFile(String filename) throws IOException {
		PemObject pemObject;

		PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(filename)));
		try {
			pemObject = pemReader.readPemObject();
		} finally {
			pemReader.close();
		}

		return pemObject;
	}

	public static boolean checkAccountLock (SimpleUser usr) {

		if (usr.isLocked()) {
			return true;
		}

		if (usr.isClosed()) {
			return true;
		}
		return false;


	}

	
	//format an error message as a JSON object in a Response 
	public static Response getError (String message, Status status) {

		return Response.status(status).entity(new ErrorData(message)).build();
	}

	public static String nextSessionId() {
		return new BigInteger(130, random).toString(32);
	}


}
