/**
 * 
 */
package mail;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;

import java.security.NoSuchAlgorithmException;

import java.security.SignatureException;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.NoSuchProviderException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.openssl.PasswordFinder;

/**
 * @author lardnerl
 * 
 */
public class Encryption {

	public static Message toEncrypt(Message newMessage, Session session) {

		try {

			MimeMessage body = (MimeMessage) newMessage;
			// Add BouncyCastle content handlers to command map
			MailcapCommandMap mailcap = (MailcapCommandMap) CommandMap
					.getDefaultCommandMap();

			mailcap.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
			mailcap.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
			mailcap.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
			mailcap.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
			mailcap.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

			CommandMap.setDefaultCommandMap(mailcap);

			Security.addProvider(new BouncyCastleProvider());

			File privateKey = new File("mykey.pem");
			KeyPair keyPair = readKeyPair(privateKey, "password".toCharArray());

			Signature signature = Signature
					.getInstance("SHA256WithRSAEncryption");
			signature.initSign(keyPair.getPrivate());
			signature.update(((String)body.getContent()).getBytes());
			byte[] signatureBytes = signature.sign();
			System.out.println(new String(Hex.encode(signatureBytes)));

			Signature verifier = Signature
					.getInstance("SHA256WithRSAEncryption");
			verifier.initVerify(keyPair.getPublic());
			verifier.update(((String)body.getContent()).getBytes());
			if (verifier.verify(signatureBytes)) {
				System.out.println("Signature is valid");
			} else {
				System.out.println("Signature is invalid");
			}

			// Sign the message

			MimeMessage signedMessage = new MimeMessage(session);

			// Set all original MIME headers in the signed message
			Enumeration<?> headers = body.getAllHeaderLines();
			while (headers.hasMoreElements()) {
				signedMessage.addHeaderLine((String) headers.nextElement());
			}

			// Set the content of the signed message
			signedMessage.setContent(body.getContent(),"Multipart");
//			signedMessage.saveChanges();

			// return the message
			return signedMessage;

			// } //catch (NoSuchProviderException ex) {
			// Logger.getLogger(Encryption.class.getName()).log(Level.SEVERE,
			// null, ex);
			// } catch (MessagingException e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MessagingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// return the message
		System.out.println("something went wrong with signing");
		return newMessage;
	}

	private static KeyPair readKeyPair(File privateKey, char[] keyPassword)
			throws IOException {
		FileReader fileReader = new FileReader(privateKey);
		PEMReader r = new PEMReader(fileReader, new DefaultPasswordFinder(
				keyPassword));
		try {
			return (KeyPair) r.readObject();
		} catch (IOException ex) {
			throw new IOException("The private key could not be decrypted", ex);
		} finally {
			r.close();
			fileReader.close();
		}
	}

	private static class DefaultPasswordFinder implements PasswordFinder {

		private final char[] password;

		private DefaultPasswordFinder(char[] password) {
			this.password = password;
		}

		@Override
		public char[] getPassword() {
			return Arrays.copyOf(password, password.length);
		}
	}

	public static void main(String[] args) throws Exception {
		// send(String smtpHost, int smtpPort, String fromAddress, String
		// toAddress, String subject, String content, String passwd)
		Properties props = System.getProperties();
		Session session = Session.getDefaultInstance(props, null);

		Address fromUser = new InternetAddress(
				"\"Eric H. Echidna\"<eric@bouncycastle.org>");
		Address toUser = new InternetAddress("example@bouncycastle.org");

		Message newMessage = new MimeMessage(session);
		newMessage.setFrom(fromUser);
		newMessage.setRecipient(Message.RecipientType.TO, toUser);
		newMessage.setSubject("example signed message");
		newMessage.setSentDate(new Date());
		newMessage.setText("Test message");
		newMessage = Encryption.toEncrypt(newMessage, session);

		//

		Message signedMessage = toEncrypt(newMessage, session);

	}
}
