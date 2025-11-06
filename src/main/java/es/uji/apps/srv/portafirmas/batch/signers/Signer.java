package es.uji.apps.srv.portafirmas.batch.signers;

public interface Signer {
    byte[] sign(String content) throws Exception;
}
