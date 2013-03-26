/**
 * 
 */
package mail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.Message;
import javax.mail.Multipart;
import javax.mail.Part;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.mail.smime.validator.SignedMailValidator;
import org.bouncycastle.mail.smime.validator.SignedMailValidatorException;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;

/**
 * @author lardnerl
 * 
 */
public class Encryption {

	public static MimeMessage toEncrypt(String subject, String contents,
			String fromString, String toString, Session session) {

		try {
			InternetAddress from = new InternetAddress(fromString);
			InternetAddress to = new InternetAddress(toString);

			/* Update possible mail information */
			MailcapCommandMap mailcap = (MailcapCommandMap) CommandMap
					.getDefaultCommandMap();

			mailcap.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
			mailcap.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
			mailcap.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
			mailcap.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
			mailcap.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

			CommandMap.setDefaultCommandMap(mailcap);

			/* Add BC */
			Security.addProvider(new BouncyCastleProvider());

			/* Open the keystore */
			KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			keystore.load(new FileInputStream("keystore.ImportKey"),
					"pass".toCharArray());
			Certificate[] chain = keystore.getCertificateChain(fromString);
			Certificate[] chainEncr = keystore.getCertificateChain(toString);
			/* Get the private key to sign the message with */
			PrivateKey privateKey = (PrivateKey) keystore.getKey(fromString,
					"pass".toCharArray());
			if (privateKey == null) {
				throw new Exception("cannot find private key for alias: "
						+ fromString);
			}

			/* Create the message to sign and encrypt */

			MimeMessage body = new MimeMessage(session);
			body.setFrom(from);
			body.setRecipient(Message.RecipientType.TO, to);
			body.setSubject(subject);
			body.setContent(contents, "text/plain");
			body.saveChanges();

			/* Create the SMIMESignedGenerator */
			SMIMECapabilityVector capabilities = new SMIMECapabilityVector();
			capabilities.addCapability(SMIMECapability.dES_EDE3_CBC);
			capabilities.addCapability(SMIMECapability.rC2_CBC, 128);
			capabilities.addCapability(SMIMECapability.dES_CBC);

			ASN1EncodableVector attributes = new ASN1EncodableVector();
			attributes.add(new SMIMEEncryptionKeyPreferenceAttribute(
					new IssuerAndSerialNumber(new X500Name(
							((X509Certificate) chain[0]).getIssuerDN()
									.getName()), ((X509Certificate) chain[0])
							.getSerialNumber())));
			attributes.add(new SMIMECapabilitiesAttribute(capabilities));

			SMIMESignedGenerator signer = new SMIMESignedGenerator();
			signer.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder()
					.setProvider("BC")
					.setSignedAttributeGenerator(new AttributeTable(attributes))
					.build("DSA".equals(privateKey.getAlgorithm()) ? "SHA1withRSA"
							: "MD5withRSA", privateKey,
							(X509Certificate) chain[0]));

			/* Add the list of certs to the generator */
			List<Certificate> certList = new ArrayList<Certificate>();
			certList.add(chain[0]);
			Store certs = new JcaCertStore(certList);
			signer.addCertificates(certs);

			/* Sign the message */
			MimeMultipart mm = signer.generate(body, "BC");
			MimeMessage signedMessage = new MimeMessage(session);

			/* Set all original MIME headers in the signed message */
			Enumeration<?> headers = body.getAllHeaderLines();
			while (headers.hasMoreElements()) {
				signedMessage.addHeaderLine((String) headers.nextElement());
			}

			/* Set the content of the signed message */
			signedMessage.setContent(mm);
			signedMessage.saveChanges();

			/* Create the encrypter */
			SMIMEEnvelopedGenerator encrypter = new SMIMEEnvelopedGenerator();
			encrypter
					.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(
							(X509Certificate) chainEncr[0]).setProvider("BC"));

			/* Encrypt the message */
			MimeBodyPart encryptedPart = encrypter.generate(signedMessage,
					new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC)
							.setProvider("BC").build());

			/*
			 * Create a new MimeMessage that contains the encrypted and signed
			 * content
			 */
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			encryptedPart.writeTo(out);

			MimeMessage encryptedMessage = new MimeMessage(session,
					new ByteArrayInputStream(out.toByteArray()));

			/* Set all original MIME headers in the encrypted message */
			headers = body.getAllHeaderLines();
			while (headers.hasMoreElements()) {
				String headerLine = (String) headers.nextElement();
				/*
				 * Make sure not to override any content-* headers from the
				 * original message
				 */
				if (!Strings.toLowerCase(headerLine).startsWith("content-")) {
					encryptedMessage.addHeaderLine(headerLine);
				}
			}

			return encryptedMessage;
		} catch (SMIMEException ex) {
			ex.getUnderlyingException().printStackTrace(System.err);
			ex.printStackTrace(System.err);
		} catch (Exception ex) {
			ex.printStackTrace(System.err);
		}
		return null;
	}

	public static String toDecrypt(Message toDecrypt, Session session)
			throws Exception {
		/* Add BC */
		Security.addProvider(new BouncyCastleProvider());
		MimeMessage encryptedMessage = (MimeMessage) toDecrypt;

		String toString = encryptedMessage
				.getRecipients(Message.RecipientType.TO)[0].toString();
		String fromString = encryptedMessage.getFrom().toString();

		/* Open the keystore */
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(new FileInputStream("keystore.ImportKey"),
				"pass".toCharArray()); // /KEYSTORE
		keystore.getCertificateChain(fromString);

		/* Get the private key to decrypt the message with */
		PrivateKey privateKey = (PrivateKey) keystore.getKey(toString,
				"pass".toCharArray());
		if (privateKey == null) {
			throw new Exception("cannot find private key for alias: "
					+ toString);
		}

		X509Certificate cert = (X509Certificate) keystore
				.getCertificate(toString);
		cert.getPublicKey();

		/* Generate decryption information*/
		RecipientId recId = new JceKeyTransRecipientId(cert);

		SMIMEEnveloped m = new SMIMEEnveloped(encryptedMessage);

		RecipientInformationStore recipients = m.getRecipientInfos();
		RecipientInformation recipient = recipients.get(recId);
		/* Decrypt message*/
		MimeBodyPart res = SMIMEUtil.toMimeBodyPart(recipient
				.getContent(new JceKeyTransEnvelopedRecipient(privateKey)));
		/* produce decrypted message*/
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		res.writeTo(out);

		MimeMessage decryptedMessage = new MimeMessage(session,
				new ByteArrayInputStream(out.toByteArray()));
		/* Verify signature*/
		boolean signature = verifySignature(decryptedMessage, keystore);

		if (signature)
			return getMessageContent(decryptedMessage);
		else
			return "Signature Unverfied :: "
					+ getMessageContent(decryptedMessage);
	}

	private static boolean verifySignature(MimeMessage message,
			KeyStore keyStore) {
		try {
			/* Produce parameters for verfiying signature*/
			PKIXParameters pkixp = new PKIXParameters(keyStore);
			/*Verfiy signatrure*/
			new SignedMailValidator(message, pkixp);
		} catch (SignedMailValidatorException e) {
			return false;
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return false;
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			return false;
		}
		return true;

	}

	// Get a message's content.
	public static String getMessageContent(Message message) throws Exception {
		Object content = message.getContent();
		if (content instanceof Multipart) {
			StringBuffer messageContent = new StringBuffer();
			Multipart multipart = (Multipart) content;
			for (int i = 0; i < multipart.getCount(); i++) {
				Part part = (Part) multipart.getBodyPart(i);
				if (part.isMimeType("text/plain")) {
					messageContent.append(part.getContent().toString());
				}
			}
			return messageContent.toString();
		} else {
			return content.toString();
		}
	}

	
	/* For testing Encryption/decryption*/
	public static void main(String[] args) throws Exception {
		// send(String smtpHost, int smtpPort, String fromAddress, String
		// toAddress, String subject, String content, String passwd)
		Properties props = System.getProperties();
		Session session = Session.getDefaultInstance(props, null);

		MimeMessage newMessage = new MimeMessage(session);

		newMessage = Encryption.toEncrypt("example signed message",
				"Test message", "hughlardner@gmail.com",
				"hughlardner@gmail.com", session);

		//

		System.out.print(Encryption.toDecrypt(newMessage, session));

	}
}
