package util;

import java.io.File;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class cuvanjeXML {
	
	
	public static void cuvanjeXMLa (String zaglavlje, String sms){
		
		String putanja = "./data/email.xml";
		try {
			DocumentBuilderFactory df= DocumentBuilderFactory.newInstance();
		    DocumentBuilder db = df.newDocumentBuilder();
		    Document doc = db.newDocument();
		    Element rootElement = doc.createElement("Mejl");
		    doc.appendChild(rootElement);
		   
		    Element zg = doc.createElement("subject");
		    zg.appendChild(doc.createTextNode(zaglavlje));
		    rootElement.appendChild(zg);
		    
		    Element pr = doc.createElement("body");
		    pr.appendChild(doc.createTextNode(sms));
		    rootElement.appendChild(pr);
		    
		    
		    TransformerFactory tF = TransformerFactory.newInstance();
		    Transformer transformer = tF.newTransformer();
		    DOMSource source = new DOMSource(doc);
		    StreamResult result = new StreamResult(new File(putanja));
		    transformer.transform(source, result);
		    System.out.println("Sacuvan");
			
			
		} catch (Exception e) {
			e.printStackTrace();
			xmlFile = null;
			
		}
		
		
	}
	

}
