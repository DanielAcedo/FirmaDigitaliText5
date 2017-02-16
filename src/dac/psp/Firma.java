package dac.psp;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Scanner;

import org.bouncycastle.crypto.tls.DigestAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;

public class Firma {

	private static final String rutaCertificado = "cert/certificado.p12";
	private static final String password = "";
	private static final String SRC = "doc/documento.pdf";
	private static final String DEST = SRC.substring(0,  SRC.lastIndexOf('.')) + "_signed.pdf";
	
	public static void main(String[] args) throws FileNotFoundException, IOException, GeneralSecurityException, DocumentException {
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		
		/*String password;
		
		System.out.println("Introduce tu contraseña");
		Scanner scanner = new Scanner(System.in);
		password = scanner.nextLine();
		scanner.close();*/
		
		//KeyStore kStore = KeyStore.getInstance("pkcs12",provider.getName());
		KeyStore kStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		kStore.load(new FileInputStream(rutaCertificado), password.toCharArray());
		String alias = (String)kStore.aliases().nextElement();
		
		System.out.println("Alias: "+alias);
		
		PrivateKey pk = (PrivateKey)kStore.getKey(alias, password.toCharArray());
		
		System.out.println("Clave: "+pk.getAlgorithm()+" formato: "+pk.getFormat());
		
		Certificate[] chain = kStore.getCertificateChain(alias);
		
		Firma app = new Firma();
		app.sign(SRC, DEST, chain, pk, DigestAlgorithms.SHA256, 
				provider.getName(), CryptoStandard.CMS, "Test de firma", "Malaga", null, null, null, 0);
		
	}
	
	public void sign(String src, String dest, Certificate[] chain, PrivateKey pk,
			String digestAlgorithm, String provider, CryptoStandard cms, String reason, String location,
			Collection<CrlClient> crlList, OcspClient ocspClient,
			TSAClient tsaClient, int estimatedSize) throws GeneralSecurityException, IOException, DocumentException{
		
		//Creamos el lector de pdf y el sello
		PdfReader reader = new PdfReader(src);
		FileOutputStream os = new FileOutputStream(dest);
		
		PdfStamper sello = PdfStamper.createSignature(reader, os, '\0');
		
		//Creamos el sello y su localización
		PdfSignatureAppearance appearance = sello.getSignatureAppearance();
		appearance.setReason(reason);
		appearance.setLocation(location);
		appearance.setVisibleSignature(new Rectangle(36, 748, 144, 786), 1, "sig");
		
		//Creamos la firma
		ExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
		
		ExternalDigest digest = new BouncyCastleDigest();
		MakeSignature.signDetached(appearance, digest, pks, chain, crlList, ocspClient, tsaClient, estimatedSize, cms);
	}
	

}
