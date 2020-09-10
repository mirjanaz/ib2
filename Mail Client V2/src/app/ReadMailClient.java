package app;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.keyresolver.implementations.RSAKeyValueResolver;
import org.apache.xml.security.keys.keyresolver.implementations.X509CertificateResolver;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import model.keystore.KeyStoreReader;
import model.keystore.IssuerData;
import support.MailHelper;
import support.MailReader;
import util.Base64;
public class ReadMailClient extends MailClient {

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;
	
	private static final String KEY_STORE_FILE = "./data/korisnikb.jks";
	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	private static final String KEY_STORE_PASS = "1234";
	private static final String KEY_STORE_ALIAS = "korisnikb";
	private static final String KEY_STORE_PASS_FOR_PRIVATE_KEY = "1234";

	
	static {
		//staticka inicijalizacija
        Security.addProvider(new BouncyCastleProvider());
        org.apache.xml.security.Init.init();
	}
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, MessagingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        
		
		
		// Build a new authorized API client service.
        Gmail service = getGmailService();
        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
        
        String user = "me";
        String query = "is:unread label:INBOX";
      //Izlistava prve PS mejlove prve stranice.
        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
        for(int i=0; i<messages.size(); i++) {
        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
        	
        	MimeMessage mimeMessage;
			try {
				
				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
				
				System.out.println("\n Message number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");
				
				mimeMessages.add(mimeMessage);
	        
			} catch (MessagingException e) {
				e.printStackTrace();
			}	
        }
      //biranje mejla 
        System.out.println("Select a message to decrypt:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	        
	    String answerStr = reader.readLine();
	    Integer answer = Integer.parseInt(answerStr);
	    
		MimeMessage chosenMessage = mimeMessages.get(answer);
	  /*  
        //TODO: Decrypt a message and decompress it. The private key is stored in a file.
		Cipher aesCipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
	//	 SecretKey secretKey = new SecretKeySpec(JavaUtils.getBytesFromFile(KEY_FILE), "AES");
		//uyimamo poruku
		String str = MailHelper.getText(chosenMessage);
		//uzima se txt
		MailBody mb=new MailBody(str);
		String secretKeyStr =mb.getEncKey();
		KeyStore ks=KeyStoreReader.readKeyStore(KEY_STORE_FILE,KEY_STORE_PASS.toCharArray());
		
		// preuzimanje privatnog kljuca iz KeyStore-a za zeljeni alias
		PrivateKey privateKey = KeyStoreReader.getPrivateKeyFromKeyStore(ks, KEY_STORE_ALIAS, KEY_STORE_PASS_FOR_PRIVATE_KEY.toCharArray());
		
		
		try {
			
			//Postavljamo providera, jer treba za RSA Enkripciji/Dekripciju
			Security.addProvider(new BouncyCastleProvider());
			Cipher rsaCipherEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
			
			rsaCipherEnc.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] secrectKeyByte= rsaCipherEnc.doFinal(Base64.decode(secretKeyStr));
			SecretKey secretKey=new SecretKeySpec(secrectKeyByte,"AES");
			
			String iv1Str=mb.getIV1();
//			byte[] iv1 = JavaUtils.getBytesFromFile(IV1_FILE);
			
			//vektor 1 koristimo jer nam treba za dekriptovanje tela poruke a iv 2 za subject
			
			IvParameterSpec ivParameterSpec1 = new IvParameterSpec(Base64.decode(iv1Str));
			aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec1);
			
		
			
			
			
			byte[] teloEN= Base64.decode(mb.getEncMessage());
			
			String receivedBodyTxt = new String(aesCipherDec.doFinal(teloEN));
			String decompressedBodyText = GzipUtil.decompress(Base64.decode(receivedBodyTxt));
			System.out.println("Body text: " + decompressedBodyText);
			
			
			//byte[] iv2 = JavaUtils.getBytesFromFile(IV2_FILE);
			String iv2Str=mb.getIV2();
			IvParameterSpec ivParameterSpec2 = new IvParameterSpec(Base64.decode(iv2Str));
			
			//inicijalizacija za dekriptovanje
			aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec2);
			
			//dekompresovanje i dekriptovanje subject-a
			String decryptedSubjectTxt = new String(aesCipherDec.doFinal(Base64.decode(chosenMessage.getSubject())));
			String decompressedSubjectTxt = GzipUtil.decompress(Base64.decode(decryptedSubjectTxt));
			System.out.println("Subject text: " + new String(decompressedSubjectTxt));
			
			
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// TODO: handle exception
			e.printStackTrace();
		}
	*/	
		
	 //Izvlacenje teksta mejla koji je u String formatu
	String xmlAsString = MailHelper.getText(chosenMessage);
	
	//kreiranje XML dokumenta na osnovu stringa
	Document doc = createXMlDocument(xmlAsString);
	
	//>>>>>>>>>.
	// citanje keystore-a kako bi se izvukao sertifikat korisnika B
	// i kako bi se dobio njegov tajni kljuc
	PrivateKey prvateKey = readPrivateKey();
				
	//dekriptovanje dokumenta
	System.out.println("Decrypting....");
	Document doc2 = decrypt(doc, prvateKey);
	
	System.out.println("Decryption done");
	System.out.println("Body text: " + doc.getElementsByTagName("mail").item(0).getTextContent());
	
	
	//proveravanje potpisa
	boolean res = verifySignature(doc);
	System.out.println("Verification = " + res);
	//>>>>>>>
}
	// DEKRIPTOVANJE DOKUMENTA
		private static Document decrypt(Document doc, PrivateKey privateKey) {
			
			try {
				//cipher za dekritpovanje XML-a
				XMLCipher xmlCipher = XMLCipher.getInstance();
				//inicijalizacija za dekriptovanje
				xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
				//postavlja se kljuc za dekriptovanje tajnog kljuca
				xmlCipher.setKEK(privateKey);
				
				//trazi se prvi EncryptedData element
				NodeList encDataList = doc.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedData");
				Element encData = (Element) encDataList.item(0);
				
				//dekriptuje se
				//pri cemu se prvo dekriptuje tajni kljuc, pa onda tim tajnim kljucem podaci
				xmlCipher.doFinal(doc, encData); 
				
				return doc;
			} catch (XMLEncryptionException e) {
				e.printStackTrace();
				return null;
			} catch (Exception e) {
				e.printStackTrace();
				return null;
			}
		}
		private static PrivateKey readPrivateKey() {
			// Privatan kljuc KORISNIK B
			try {
				//kreiramo instancu KeyStore
				KeyStore ks = KeyStore.getInstance("JKS", "SUN");
				
				//ucitavamo podatke
				BufferedInputStream in = new BufferedInputStream(new FileInputStream(KEY_STORE_FILE));
				ks.load(in, "1234".toCharArray());
				
				if(ks.isKeyEntry("korisnikb")) {
					PrivateKey pk = (PrivateKey) ks.getKey("korisnikb", "1234".toCharArray());
					return pk;
				}
				else
					return null;
				
			} catch (KeyStoreException e) {
				e.printStackTrace();
				return null;
			} catch (NoSuchProviderException e) {
				e.printStackTrace();
				return null;
			} catch (FileNotFoundException e) {
				e.printStackTrace();
				return null;
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				return null;
			} catch (CertificateException e) {
				e.printStackTrace();
				return null;
			} catch (IOException e) {
				e.printStackTrace();
				return null;
			} catch (UnrecoverableKeyException e) {
				e.printStackTrace();
				return null;
			} 
		}
		// PROVERAVANJE POTPISA POMOCU SERTIFIKATA KORISNIKA A
		private static boolean verifySignature(Document doc) {
			
			try {
				//Pronalazi se prvi Signature element 
				NodeList signatures = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
				Element signatureEl = (Element) signatures.item(0);
				
				//kreira se signature objekat od elementa
				XMLSignature signature = new XMLSignature(signatureEl, null);
				
				//preuzima se key info
				KeyInfo keyInfo = signature.getKeyInfo();
				
				//ako postoji
				if(keyInfo != null) {
					//registruju se resolver-i za javni kljuc i sertifikat
					keyInfo.registerInternalKeyResolver(new RSAKeyValueResolver());
				    keyInfo.registerInternalKeyResolver(new X509CertificateResolver());
				    
				    //ako sadrzi sertifikat
				    if(keyInfo.containsX509Data() && keyInfo.itemX509Data(0).containsCertificate()) { 
				        Certificate cert = keyInfo.itemX509Data(0).itemCertificate(0).getX509Certificate();
				        
				        //ako postoji sertifikat, provera potpisa
				        if(cert != null) 
				        	return signature.checkSignatureValue((X509Certificate) cert);
				        else
				        	return false;
				    }
				    else
				    	return false;
				}
				else
					return false;
			
			} catch (XMLSignatureException e) {
				e.printStackTrace();
				return false;
			} catch (XMLSecurityException e) {
				e.printStackTrace();
				return false;
			}
		}

//prebacivanje u String format
private static String xmlUString(Document doc) throws TransformerException{
	TransformerFactory tf = TransformerFactory.newInstance();
	Transformer transformer = tf.newTransformer();
	transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
	StringWriter writer = new StringWriter();
	transformer.transform(new DOMSource(doc), new StreamResult(writer));
	String output = writer.getBuffer().toString().replaceAll("\n|\r", "");
	
	return output;
}

//kreiranje xml dokumenta
private static Document createXMlDocument(String xmlUString){
	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();  
	factory.setNamespaceAware(true);
	DocumentBuilder builder;  
	Document doc = null;
	try {  
	    builder = factory.newDocumentBuilder();  
	    doc = builder.parse(new InputSource(new StringReader(xmlUString)));  
	} catch (Exception e) {  
	    e.printStackTrace();  
	} 
	return doc;
}
	
}
