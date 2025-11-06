package es.uji.apps.srv.portafirmas.batch;

import es.uji.apps.srv.portafirmas.batch.signers.JAdESSigner;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class JAdESTest {
    private static final String DOCUMENT_TO_SIGN_DATA = "{\"a\":1}";

    public static byte[] inputStreamToByteArray(InputStream in) throws IOException {
        byte[] buffer = new byte[2048];
        int length = 0;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        while ((length = in.read(buffer)) >= 0) {
            baos.write(buffer, 0, length);
        }

        return baos.toByteArray();
    }

    @Test
    public void jadesSignAdVerify() throws Exception {
        String id = UUID.randomUUID().toString();

        String keyStoreType = "PKCS12";
        String keyStorePath = "/etc/uji/srv/portafirmas-batch/eujier.p12";
        String keyStorePassword = "axJSyXkY";

        JAdESSigner signer = new JAdESSigner(keyStoreType, keyStorePath, keyStorePassword);
        byte[] signedData = signer.sign(DOCUMENT_TO_SIGN_DATA);

        dumpFile(id, signedData);

        DSSDocument signedDocument = new InMemoryDocument(signedData, "/tmp/" + id + ".json");
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);

        CommonCertificateVerifier certificateVerifier = createCertificateVerifier(keyStoreType, keyStorePath, keyStorePassword);
        validator.setCertificateVerifier(certificateVerifier);

        Reports reports = validator.validateDocument();
        processValidationResults(reports);
    }

    @Test
    public void verifiyFromFile() throws Exception {
        String keyStoreType = "PKCS12";
        String keyStorePath = "/etc/uji/srv/portafirmas-batch/eujier.p12";
        String keyStorePassword = "axJSyXkY";

        byte[] signedData = inputStreamToByteArray(new FileInputStream("/tmp/out2.json"));

        DSSDocument signedDocument = new InMemoryDocument(signedData, "out.json");
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);

        CommonCertificateVerifier certificateVerifier = createCertificateVerifier(keyStoreType, keyStorePath, keyStorePassword);
        validator.setCertificateVerifier(certificateVerifier);

        Reports reports = validator.validateDocument();
        processValidationResults(reports);
    }

    @Test
    public void signFromFile() throws Exception {
        String keyStoreType = "PKCS12";
        String keyStorePath = "/etc/uji/eujier.p12";
        String keyStorePassword = "axJSyXkY";
        String signedFileName = "signed.json";

        byte[] data = readFile("tosign.json");

        JAdESSigner signer = new JAdESSigner(keyStoreType, keyStorePath, keyStorePassword);
        byte[] signedData = signer.sign(new String(data));

        dumpFile(signedFileName, signedData);

        DSSDocument signedDocument = new InMemoryDocument(signedData, signedFileName);
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);

        CommonCertificateVerifier certificateVerifier = createCertificateVerifier(keyStoreType, keyStorePath, keyStorePassword);
        validator.setCertificateVerifier(certificateVerifier);

        Reports reports = validator.validateDocument();
        processValidationResults(reports);
    }

    private byte[] readFile(String fileName) throws IOException {
        InputStream resourceStream = getClass().getClassLoader().getResourceAsStream(fileName);
        return inputStreamToByteArray(resourceStream);
    }

    private CommonCertificateVerifier createCertificateVerifier(String keystoreType, String keystorePath, String keystorePassword) throws Exception {
        KeyStoreCertificateSource keystoreCertSource = new KeyStoreCertificateSource(
                Files.newInputStream(Paths.get(keystorePath)),
                keystoreType,
                keystorePassword.toCharArray()
        );

        CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
        trustedCertSource.importAsTrusted(keystoreCertSource);

        CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        certificateVerifier.setCheckRevocationForUntrustedChains(false);
        certificateVerifier.setAlertOnMissingRevocationData(new LogOnStatusAlert());
        certificateVerifier.setAlertOnUncoveredPOE(new LogOnStatusAlert());
        certificateVerifier.setAlertOnInvalidTimestamp(new LogOnStatusAlert());
        certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new LogOnStatusAlert());
        certificateVerifier.addTrustedCertSources(trustedCertSource);

        return certificateVerifier;
    }

    private void processValidationResults(Reports reports) {
        SimpleReport simpleReport = reports.getSimpleReport();
        DetailedReport detailedReport = reports.getDetailedReport();
        DiagnosticData diagnosticData = reports.getDiagnosticData();

        showGeneralInfo(simpleReport, diagnosticData);

        List<String> signatureIds = simpleReport.getSignatureIdList();

        if (signatureIds.isEmpty()) {
            System.out.println("❌ NO SE ENCONTRARON FIRMAS en el documento");
            return;
        }

        System.out.println("📝 FIRMAS ENCONTRADAS: " + signatureIds.size());
        System.out.println();

        for (int i = 0; i < signatureIds.size(); i++) {
            String signatureId = signatureIds.get(i);
            System.out.println("--- FIRMA " + (i + 1) + " ---");
            validateIndividualSignature(signatureId, simpleReport, detailedReport, diagnosticData);
            System.out.println();
        }

        showFinalSummary(simpleReport);
    }

    private void showGeneralInfo(SimpleReport simpleReport, DiagnosticData diagnosticData) {
        System.out.println("📄 INFORMACIÓN DEL DOCUMENTO:");
        System.out.println("   Nombre: " + (simpleReport.getDocumentFilename() != null ?
                simpleReport.getDocumentFilename() : "No especificado"));
        System.out.println("   Fecha de validación: " + simpleReport.getValidationTime());
        System.out.println("   Total de firmas: " + simpleReport.getSignaturesCount());
        System.out.println("   Firmas válidas: " + simpleReport.getValidSignaturesCount());
        System.out.println();
    }

    private void validateIndividualSignature(String signatureId, SimpleReport simpleReport,
                                             DetailedReport detailedReport, DiagnosticData diagnosticData) {

        Indication indication = simpleReport.getIndication(signatureId);
        SubIndication subIndication = simpleReport.getSubIndication(signatureId);
        boolean isValid = simpleReport.isValid(signatureId);

        System.out.println("🔍 ID de Firma: " + signatureId);
        System.out.println("📋 Estado: " + (isValid ? "✅ VÁLIDA" : "❌ INVÁLIDA"));
        System.out.println("📊 Indicación: " + indication);

        if (subIndication != null) {
            System.out.println("📊 Sub-indicación: " + subIndication);
        }

        showSignatureDetails(signatureId, simpleReport, diagnosticData);

        if (!isValid) {
            showValidationIssues(signatureId, simpleReport);
        }
    }

    private void showSignatureDetails(String signatureId, SimpleReport simpleReport, DiagnosticData diagnosticData) {
        String signedBy = simpleReport.getSignedBy(signatureId);
        if (signedBy != null && !signedBy.isEmpty()) {
            System.out.println("👤 Firmado por: " + signedBy);
        }

        System.out.println("📝 Formato: " + simpleReport.getSignatureFormat(signatureId));
        System.out.println("🏆 Calificación: " + simpleReport.getSignatureQualification(signatureId));

        Date signingTime = simpleReport.getSigningTime(signatureId);
        if (signingTime != null) {
            System.out.println("📅 Fecha de firma: " + signingTime);
        }

        Date bestSignatureTime = simpleReport.getBestSignatureTime(signatureId);
        if (bestSignatureTime != null) {
            System.out.println("📅 Mejor tiempo de firma: " + bestSignatureTime);
        }

        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(signatureId);
        if (signatureWrapper != null) {
            System.out.println("🔐 Algoritmo de firma: " + signatureWrapper.getSignatureAlgorithm());
            System.out.println("🔐 Algoritmo de digest: " + signatureWrapper.getDigestAlgorithm());
        }
    }

    private void showValidationIssues(String signatureId, SimpleReport simpleReport) {
        System.out.println();
        System.out.println("⚠️  PROBLEMAS DE VALIDACIÓN:");

        List<Message> adesErrors = simpleReport.getAdESValidationErrors(signatureId);
        if (!adesErrors.isEmpty()) {
            System.out.println("   🔴 Errores AdES:");
            for (Message error : adesErrors) {
                System.out.println("      - " + error.getValue());
            }
        }

        List<Message> adesWarnings = simpleReport.getAdESValidationWarnings(signatureId);
        if (!adesWarnings.isEmpty()) {
            System.out.println("   🟡 Advertencias AdES:");
            for (Message warning : adesWarnings) {
                System.out.println("      - " + warning.getValue());
            }
        }

        List<Message> qualificationErrors = simpleReport.getQualificationErrors(signatureId);
        if (!qualificationErrors.isEmpty()) {
            System.out.println("   🔴 Errores de Calificación:");
            for (Message error : qualificationErrors) {
                System.out.println("      - " + error.getValue());
            }
        }

        List<Message> qualificationWarnings = simpleReport.getQualificationWarnings(signatureId);
        if (!qualificationWarnings.isEmpty()) {
            System.out.println("   🟡 Advertencias de Calificación:");
            for (Message warning : qualificationWarnings) {
                System.out.println("      - " + warning.getValue());
            }
        }
    }

    private void showFinalSummary(SimpleReport simpleReport) {
        System.out.println("=== RESUMEN FINAL ===");

        int totalSignatures = simpleReport.getSignaturesCount();
        int validSignatures = simpleReport.getValidSignaturesCount();
        int invalidSignatures = totalSignatures - validSignatures;

        System.out.println("📊 Total de firmas: " + totalSignatures);
        System.out.println("✅ Firmas válidas: " + validSignatures);
        System.out.println("❌ Firmas inválidas: " + invalidSignatures);

        if (validSignatures == totalSignatures && totalSignatures > 0) {
            System.out.println();
            System.out.println("🎉 ¡TODAS LAS FIRMAS SON VÁLIDAS!");
        } else if (validSignatures > 0) {
            System.out.println();
            System.out.println("⚠️  VALIDACIÓN PARCIAL: Algunas firmas son válidas, otras no.");
        } else {
            System.out.println();
            System.out.println("❌ VALIDACIÓN FALLIDA: Ninguna firma es válida.");
        }

        System.out.println("======================");
    }

    private static void dumpFile(String fileName, byte[] signedData) throws IOException, URISyntaxException {
        URL resourceUrl = JAdESSigner.class.getClassLoader().getResource("tosign.json");
        File file = new File(resourceUrl.getPath());

        FileOutputStream fos = new FileOutputStream(file.getParentFile().getAbsolutePath() + "/" + fileName);
        fos.write(signedData);
        fos.close();
    }
}