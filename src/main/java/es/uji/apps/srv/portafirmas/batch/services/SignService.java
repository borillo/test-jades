package es.uji.apps.srv.portafirmas.batch.services;

import es.uji.apps.srv.portafirmas.batch.signers.Signer;

public class SignService {
    private Signer signer;

    public SignService(Signer signer) {
        this.signer = signer;
    }

    public byte[] sign(String content) throws Exception {
        return signer.sign(content);
    }
}
