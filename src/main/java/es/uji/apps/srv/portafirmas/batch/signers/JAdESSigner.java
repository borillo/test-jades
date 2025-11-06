package es.uji.apps.srv.portafirmas.batch.signers;

import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.JKSSignatureToken;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore.PasswordProtection;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.UUID;

public class JAdESSigner implements Signer {
    private final String keyStoreType;
    private final String keyStorePath;
    private final String keyStorePassoword;

    private X509Certificate certificate;
    private PrivateKey privateKey;

    public JAdESSigner(String keyStoreType, String keyStorePath, String keyStorePassoword) throws Exception {
        this.keyStoreType = keyStoreType;
        this.keyStorePath = keyStorePath;
        this.keyStorePassoword = keyStorePassoword;
    }

    public byte[] sign(String content) throws Exception {
        try (SignatureTokenConnection signingToken = createSignatureTokenConnection(keyStoreType, keyStorePath, keyStorePassoword)) {
            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);
            JAdESSignatureParameters signatureParameters = createSignatureParameters(privateKey);

            CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
            certificateVerifier.setCheckRevocationForUntrustedChains(true);
            certificateVerifier.setCrlSource(new OnlineCRLSource());
            certificateVerifier.setOcspSource(new OnlineOCSPSource());
            certificateVerifier.setAIASource(new DefaultAIASource());
            certificateVerifier.setTrustedCertSources(new CommonTrustedCertificateSource());

            JAdESService jadesService = new JAdESService(certificateVerifier);

            OnlineTSPSource tspSource = new OnlineTSPSource("http://tss.accv.es:8318/tsa");
            jadesService.setTspSource(tspSource);

            DSSDocument documentToSign = new InMemoryDocument(content.getBytes(), UUID.randomUUID() + ".json", MimeTypeEnum.JSON);
            ToBeSigned dataToSign = jadesService.getDataToSign(documentToSign, signatureParameters);

            SignatureValue signatureValue = signingToken.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedDocument = jadesService.signDocument(documentToSign, signatureParameters, signatureValue);

            return DSSUtils.toByteArray(signedDocument);
        }
    }

    private SignatureTokenConnection createSignatureTokenConnection(String keyStoreType, String keyStorePath, String keyStorePassoword) throws IOException {
        InputStream inputStream = Files.newInputStream(Paths.get(keyStorePath));
        PasswordProtection passwordProtection = new PasswordProtection(keyStorePassoword.toCharArray());

        if ("JKS".equals(keyStoreType)) {
            return new JKSSignatureToken(inputStream, passwordProtection);
        } else if ("PKCS12".equals(keyStoreType)) {
            return new Pkcs12SignatureToken(inputStream, passwordProtection);
        } else {
            throw new IllegalArgumentException("Unsupported keystore type: " + keyStoreType);
        }
    }

    private JAdESSignatureParameters createSignatureParameters(DSSPrivateKeyEntry privateKey) {
        JAdESSignatureParameters parameters = new JAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LTA);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        parameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSigningCertificate(privateKey.getCertificate());
        parameters.setCertificateChain(privateKey.getCertificateChain());

        parameters.bLevel().setSigningDate(new Date());

        parameters.setBase64UrlEncodedPayload(false);
        parameters.setIncludeCertificateChain(true);
        parameters.setIncludeSignatureType(true);
        parameters.setIncludeKeyIdentifier(true);
        parameters.setBase64UrlEncodedPayload(false);
        parameters.setBase64UrlEncodedEtsiUComponents(true);
        parameters.setGenerateTBSWithoutCertificate(false);
        parameters.setIncludeCertificateChain(true);

        return parameters;
    }
}
