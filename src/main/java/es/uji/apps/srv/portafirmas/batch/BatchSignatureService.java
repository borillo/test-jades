package es.uji.apps.srv.portafirmas.batch;

import es.uji.apps.srv.portafirmas.batch.model.SignService;
import es.uji.apps.srv.portafirmas.batch.signers.JAdESSigner;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class BatchSignatureService {
    public static void main() {
        SignService signService = new SignService(new JAdESSigner("", "", ""));
        byte[] signedDocument = signService.sign("{\"a\":1}");

	FileOutputStream fos = new FileOutputStream("/tmp/signed.json");
	fos.write(signedDocument);
	fos.flush();
	fos.close();
    }
}
