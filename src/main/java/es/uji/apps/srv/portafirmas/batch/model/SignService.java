package es.uji.apps.srv.portafirmas.batch.model;

import es.uji.apps.srv.portafirmas.batch.signers.Signer;

import java.io.FileOutputStream;
import java.util.List;

public class SignService {
    private Signer signer;

    public SignService(Signer signer) {
        this.signer = signer;
    }

    public Firma sign(String content) throws Exception {
        return signer.sign(content);
    }
}
