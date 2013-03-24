/**
 * 
 */
package otherClient;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
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
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSSignedData;
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
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;

/**
 * @author lardnerl
 * 
 */
public class Encryption {

	public static MimeMessage toEncrypt(String subject, String contents,
			InternetAddress from, InternetAddress to, Session session) {

		try {
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
					"importkey".toCharArray()); // /KEYSTORE
			// AND
			// PASSWORD
			Certificate[] chain = keystore.getCertificateChain("importkey"); // WHO
																				// IN
																				// KEYSTORE

			/* Get the private key to sign the message with */
			PrivateKey privateKey = (PrivateKey) keystore.getKey("importkey",
					"importkey".toCharArray());
			if (privateKey == null) {
				throw new Exception("cannot find private key for alias: "
						+ "importkey");
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
			List certList = new ArrayList();
			certList.add(chain[0]);
			Store certs = new JcaCertStore(certList);
			signer.addCertificates(certs);

			/* Sign the message */
			MimeMultipart mm = signer.generate(body, "BC");
			MimeMessage signedMessage = new MimeMessage(session);

			/* Set all original MIME headers in the signed message */
			Enumeration headers = body.getAllHeaderLines();
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
							(X509Certificate) chain[0]).setProvider("BC"));

			System.out.println(signedMessage.getContent());

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

	public static String toDecrypt(MimeMessage encryptedMessage, Session session)
			throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		/* Open the keystore */
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(new FileInputStream("keystore.ImportKey"),
				"importkey".toCharArray()); // /KEYSTORE
		// AND
		// PASSWORD
		Certificate[] chain = keystore.getCertificateChain("importkey"); // WHO
																			// IN
																			// KEYSTORE

		/* Get the private key to sign the message with */
		PrivateKey privateKey = (PrivateKey) keystore.getKey("importkey",
				"importkey".toCharArray());
		if (privateKey == null) {
			throw new Exception("cannot find private key for alias: "
					+ "importkey");
		}

		X509Certificate cert = (X509Certificate) keystore
				.getCertificate("importkey");
		PublicKey publicKey = cert.getPublicKey();

		RecipientId recId = new JceKeyTransRecipientId(cert);

		SMIMEEnveloped m = new SMIMEEnveloped(encryptedMessage);

		RecipientInformationStore recipients = m.getRecipientInfos();
		RecipientInformation recipient = recipients.get(recId);

		MimeBodyPart res = SMIMEUtil.toMimeBodyPart(recipient
				.getContent(new JceKeyTransEnvelopedRecipient(privateKey)));

		System.out.println("Message Contents");
		System.out.println("----------------");
		System.out.println(res.getContent());
		System.out.println(res.getContentType());
		
		MimeMessage signedPart = new MimeMessage(session);
		signedPart.setContent((Multipart) res.getContent());
		boolean signature = verifySignature(signedPart, keystore);
		MimeMultipart decryptedMessage = (MimeMultipart) res.getContent();
		
		StringBuffer messageContent = new StringBuffer();
		Multipart multipart = (Multipart) decryptedMessage;
		for (int i = 0; i < multipart.getCount(); i++) {
			Part part = (Part) multipart.getBodyPart(i);
			System.out.println(part.getContentType());
			if (part.isMimeType("text/plain")) {
				messageContent.append(part.getContent().toString());
			}
		}

		if(signature)
			return messageContent.toString();
		else
			return "Signature Unverfied :: " + messageContent.toString();
	}

	
	private static boolean verifySignature(MimeMessage message, KeyStore keyStore)
			throws Exception {
		
		System.out.print(message.getContentType());
		PKIXParameters pkixp = new PKIXParameters(keyStore);
		SignedMailValidator validator = new SignedMailValidator( message, pkixp);
		return false;

	}

	public static void main(String[] args) throws Exception {
		// send(String smtpHost, int smtpPort, String fromAddress, String
		// toAddress, String subject, String content, String passwd)
		Properties props = System.getProperties();
		Session session = Session.getDefaultInstance(props, null);

		InternetAddress fromUser = new InternetAddress("hughlardner@gmail.com");
		InternetAddress toUser = new InternetAddress("hughlardner@gmail.com");

		MimeMessage newMessage = new MimeMessage(session);

		newMessage = Encryption.toEncrypt("example signed message",
				"Test message", fromUser, toUser, session);

		//

		System.out.print(Encryption.toDecrypt(newMessage, session));

	}
}
