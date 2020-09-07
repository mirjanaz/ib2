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

public class KreiranjeXML {
	String putanja = "C:/Users/mirja/git/IB-projekat/Mail Client V2/data";
	public String getPutanju(){
		return putanja;
	}
	public File cuvanjeMejlaXML(String primaoc,String zaglavlje, String sms){
		File xmlFile = null;
		
		try {
			DocumentBuilderFactory df= DocumentBuilderFactory.newInstance();
		    DocumentBuilder db = df.newDocumentBuilder();
		    Document doc = db.newDocument();
		    Element rootElement = doc.createElement("Mejl");
		    doc.appendChild(rootElement);
		   
		    Element p = doc.createElement("Primaoc");
		    p.appendChild(doc.createTextNode(primaoc));
		    rootElement.appendChild(p);
		    
		    Element zg = doc.createElement("Zaglavlje");
		    zg.appendChild(doc.createTextNode(zaglavlje));
		    rootElement.appendChild(zg);
		    
		    Element pr = doc.createElement("Porukica");
		    pr.appendChild(doc.createTextNode(sms));
		    rootElement.appendChild(pr);
		    
		    
		    TransformerFactory tF = TransformerFactory.newInstance();
		    Transformer transformer = tF.newTransformer();
		    DOMSource source = new DOMSource(doc);
		    StreamResult result = new StreamResult(new File(putanja +"mejlXML.xml"));
		    transformer.transform(source, result);
		    System.out.println("Sacuvan");
			
			xmlFile= new File(putanja+"mejlXML.xml");
		} catch (Exception e) {
			e.printStackTrace();
			xmlFile = null;
			
		}
		return xmlFile;
		
	}
	

}
