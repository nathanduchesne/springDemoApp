package ch.epfl.myapplication;

import static ch.epfl.myapplication.HelloWorld.*;

import androidx.appcompat.app.AppCompatActivity;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSocket;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.UUID;

public class StationProtocol extends AppCompatActivity {
    BluetoothAdapter bluetooth;
    String BT_NAME = "BLUETOOTH_CONNECTION_FOR_THE_APP";
    UUID BT_UUID = UUID.fromString("c9916d86-1653-4f14-b7f1-075f0b39af39");
    TextView stationText;
    BT_Thread thread;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_station_protocol);
        bluetooth = BluetoothAdapter.getDefaultAdapter();
        stationText = findViewById(R.id.issuerText);
        thread = new BT_Thread();
        thread.setPriority(Thread.MAX_PRIORITY);
        thread.start();
    }

    @Override
    protected void onDestroy() {
        thread.interrupt();
        super.onDestroy();
    }

    private class BT_Thread extends Thread {
        public BluetoothServerSocket serverSocket;
        public BluetoothSocket recipientSocket;
        InputStream mmInStream;
        OutputStream mmOutStream;
        byte[] mmBuffer = new byte[4096];
        public void run() {
            try {
                Log.e("bla", "before getting socket");
                serverSocket = bluetooth.listenUsingRfcommWithServiceRecord(BT_NAME, BT_UUID);
                Log.e("bla", "got server socket");
                recipientSocket = serverSocket.accept();
                Log.e("bla", "accepted connection");
                mmInStream = recipientSocket.getInputStream();
                Log.e("bla", "finished init in streams no prob");
                mmOutStream = recipientSocket.getOutputStream();
                Log.e("bla", "finished init streams no prob");
                serverSocket.close();
                Log.e("bla", "finished init no prob");
            } catch (IOException e) {
                Log.e("bla", "error while init smth");
                e.printStackTrace();
                return;
            }
            //HelloWorld.main();
            startProtocol();
        }

        /*
    Starts the protocol run from the station side
     */
        private void startProtocol() {
            Log.e("startProtoIssuer", "started protocol");
            int nbRecipientAttributes = 2;
            int nbIssuerAttributes = 5;
            initCurve();
            byte[] keys = keygenJava(nbIssuerAttributes+nbRecipientAttributes);
            byte[] publicKey = getPublicKeyJava(keys);
            byte[] privateKey = getPrivateKeyJava(keys);
            try {
                mmOutStream.write(publicKey);
                Log.e("startProtoIssuer", "sent public key");
            }
            catch (IOException e) {
                //stationText.setText("Failed to send public key..");
            }

            boolean waitingForPK = true;
            byte[] PK = null;
            while (waitingForPK) {
                try {
                    // Wait for commitment and PK
                    int numBytes = mmInStream.read(mmBuffer);
                    // Send the obtained bytes to the UI activity.
                    PK = Arrays.copyOf(mmBuffer, numBytes);
                    waitingForPK = false;
                } catch (IOException e) {
                    waitingForPK = true;

                }
            }
            Log.e("startProtoIssuer", "got pk");
            String validPK = verifyUserCommitmentJava(PK, publicKey, nbRecipientAttributes, nbIssuerAttributes);

            try {
                if (validPK.equals("True")) {
                    byte[] issuerAttributes = getAttributesJava(nbIssuerAttributes);
                    byte[] credential = issuerSigningJava(publicKey, privateKey, PK, nbIssuerAttributes, issuerAttributes, nbRecipientAttributes);
                    mmOutStream.write(credential);
                    Log.e("startProtoIssuer", "sent credential");
                    System.out.println("Valid proof of knowledge!");
                }
                else {
                    mmOutStream.write(new byte[1]);
                    Log.e("startProtoIssuer", "sent shit because proto is invalid");
                    System.out.println("Invalid proof of knowledge!");
                    return;
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            Log.e("startProtoIssuer", "waiting for disclosure");
            byte[] disclosureProof = null;
            boolean waitingForDisclosure = true;
            while (waitingForDisclosure) {
                try {
                    int numBytes = mmInStream.read(mmBuffer);
                    System.out.println("proof is bytes long: "+numBytes);
                    // Send the obtained bytes to the UI activity.
                    disclosureProof = Arrays.copyOf(mmBuffer, numBytes);
                    Log.e("startProtoIssuer", "got disclosure");
                    waitingForDisclosure = false;
                } catch (IOException e) {
                    waitingForDisclosure = true;

                }
            }
            byte[] alreadySeenCredentials = getAlreadySeenCredentialsJava();
            Log.e("startProtoIssuer", "got pseudo list");
            dumpStack();
            String validDisclosure = verifyDisclosureProofJava(disclosureProof, publicKey, alreadySeenCredentials);
            dumpStack();
            Log.e("startProtoIssuer", "got verification of disclosure proof");
            byte[] blacklist = null;
            try {
                if (validDisclosure.equals("True")) {
                    Log.e("startProtoIssuer", "sent validation of disclosure");
                    blacklist = getServiceProviderRevocatedValuesJava(10);
                    mmOutStream.write(blacklist);
                }
                else {
                    mmOutStream.write(new byte[1]);
                    return;
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

            boolean waitingForConfirmation = true;
            while (waitingForConfirmation) {
                try {
                    // Wait for commitment and PK
                    int numBytes = mmInStream.read(mmBuffer);
                    if (numBytes == 1) {
                        waitingForConfirmation = false;
                    }
                } catch (IOException e) {
                    waitingForConfirmation = true;

                }
            }
            byte[] blacklistedPowers = getBlacklistedPowersJava(10);
            try {
                mmOutStream.write(blacklistedPowers);
            }
            catch (IOException e){

            }
            boolean waitingForBLAC = true;
            byte[] blacProof = null;
            while (waitingForBLAC) {
                try {
                    // Wait for commitment and PK
                    int numBytes = mmInStream.read(mmBuffer);

                    blacProof = Arrays.copyOf(mmBuffer, numBytes);
                    waitingForBLAC = false;
                } catch (IOException e) {
                    waitingForBLAC = true;

                }
            }
            String validBLACProof = getVerifierProtocolJava(blacProof, blacklist, blacklistedPowers);
            try {
                if (validBLACProof.equals("True")) {
                    mmOutStream.write(new byte[2]);
                    Log.e("issuerOut", "letsgooo all works");
                    //stationText.setText("All good!");
                }
                else {
                    mmOutStream.write(new byte[1]);
                    //stationText.setText("Recipient was in blacklist!");
                }
            }
            catch (IOException e) {

            }
        }

    }


}