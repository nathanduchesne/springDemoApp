package ch.epfl.myapplication;

import android.util.Log;

public class HelloWorld {

    public static void main() {
        int nbRecipientAttributes = 2;
        int nbIssuerAttributes = 5;
        initCurve();
        byte[] keys = keygenJava(nbIssuerAttributes+nbRecipientAttributes);
        byte[] publicKey = getPublicKeyJava(keys);
        byte[] privateKey = getPrivateKeyJava(keys);

        byte[] recipientAttributes = getAttributesJava(nbRecipientAttributes);
        byte[] recipientCommitment = getUserCommitmentJava(publicKey, recipientAttributes, nbRecipientAttributes, nbIssuerAttributes);
        byte[] recipientCommitmentForIssuer = removeBlindingFactorJava(recipientCommitment, nbRecipientAttributes);

        String validPK = verifyUserCommitmentJava(recipientCommitmentForIssuer, publicKey, nbRecipientAttributes, nbIssuerAttributes);
        if (validPK.equals("True")) {
            byte[] issuerAttributes = getAttributesJava(nbIssuerAttributes);
            byte[] credential = issuerSigningJava(publicKey, privateKey, recipientCommitmentForIssuer, nbIssuerAttributes, issuerAttributes, nbRecipientAttributes);

            byte[] realCredential = unblindSignatureJava(credential, recipientCommitment, recipientAttributes, nbIssuerAttributes, nbRecipientAttributes);
            byte[] epoch = getEpochJava();
            byte[] disclosureProofRecipient = getDisclosureProofJava(publicKey, nbIssuerAttributes, nbRecipientAttributes, realCredential, epoch);
            System.out.println("Disclosure proof for issuer is with length "+disclosureProofRecipient.length);
            byte[] disclosureProofForIssuer = getProofOfDisclosureForVerifierJava(disclosureProofRecipient, nbRecipientAttributes, nbIssuerAttributes, epoch);
            System.out.println("Disclosure proof for issuer is with length "+disclosureProofForIssuer.length);

            byte[] alreadySeenCredentials = getAlreadySeenCredentialsJava();
            String validDisclosure = verifyDisclosureProofJava(disclosureProofForIssuer, publicKey, alreadySeenCredentials);
            if (validDisclosure.equals("True")) {
                byte[] blacklist = getServiceProviderRevocatedValuesJava(10);
                byte[] blacklistedPowers = getBlacklistedPowersJava(10);

                byte[] tokenAndRevVal = getTokenAndRevocationValueJava(disclosureProofRecipient, realCredential, nbIssuerAttributes);
                byte[] blacProver = getProverProtocolJava(blacklist, blacklistedPowers, tokenAndRevVal);
                String validBLACProof = getVerifierProtocolJava(blacProver, blacklist, blacklistedPowers);
                if (validBLACProof.equals("True")) {
                    Log.e("testing", "success in protocol!");
                }

            }
        }



}
    public static native String hello(String input);

    public static native void testerExternalMain();

    public static native void initCurve();

    public static native String ReturnSerializedGroup();

    public static native byte[] getGenerator();

    public static native byte[] getPublicKey();

    public static native String returnPublicKeyAndCompare(byte[] pkProto);

    public static native String convertSerializedToGroupElementAndCompare(byte[] group_element);

    public static native byte[] keygenJava(int nbr_attributes);

    public static native byte[] getPublicKeyJava(byte[] keys);

    public static native byte[] getPrivateKeyJava(byte[] keys);

    public static native byte[] getAttributesJava(int nb_recipient_attributes);

    public static native byte[] getUserCommitmentJava(byte[] issuer_pk, byte[] recipient_attributes, int nb_recipient_attributes, int nb_issuer_attributes);

    public static native String verifyUserCommitmentJava(byte[] non_interactive_pk, byte[] issuer_pk, int nb_recipient_attributes, int nb_issuer_attributes);

    public static native byte[] issuerSigningJava(byte[] issuer_pk, byte[] issuer_sk, byte[] proof_knowledge, int nb_issuer_attributes, byte[] issuer_attributes, int nb_recipient_attributes);

    public static native byte[] removeBlindingFactorJava(byte[] proof_with_blinding, int nbRecipientAttributes);

    public static native byte[] unblindSignatureJava(byte[] issuer_signature, byte[] commitment_with_blinding_factor, byte[] recipient_attributes, int nb_issuer_attributes, int nb_recipient_attributes);

    public static native byte[] getDisclosureProofJava(byte[] issuer_pk, int nb_issuer_attributes, int nb_recipient_attributes, byte[] credential, byte[] epoch);

    public static native byte[] getEpochJava();

    public static native byte[] getProofOfDisclosureForVerifierJava(byte[] proof_of_disclosure_for_recipient, int nb_recipient_attributes, int nb_issuer_attributes, byte[] epoch);

    public static native String verifyDisclosureProofJava(byte[] verifier_disclosure_proof, byte[] issuer_pk, byte[] already_seen_credentials);

    public static native byte[] getAlreadySeenCredentialsJava();

    public static native byte[] getServiceProviderRevocatedValuesJava(int nbr_tokens);

    public static native byte[] getTokenAndRevocationValueJava(byte[] disclosure_proof_recipient, byte[] credential_attributes, int nb_issuer_attributes);

    public static native byte[] getProverProtocolJava(byte[] revocated_values, byte[] powers_for_blacklisted_elements, byte[] token_and_revocation_value);

    public static native byte[] getBlacklistedPowersJava(int nbr_tokens);

    public static native String getVerifierProtocolJava(byte[] prover_protocol, byte[] blacklist, byte[] powers_for_blacklist);

    public static native String basicBenchmark();


    static {
        // This actually loads the shared object that we'll be creating.
        // The actual location of the .so or .dll may differ based on your
        // platform.
        System.loadLibrary("test_package");
    }
}
