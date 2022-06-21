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
    String BT_NAME = "BLUETOOTH_CONNECTION_FOR_THE_APP";
    UUID BT_UUID = UUID.fromString("c9916d86-1653-4f14-b7f1-075f0b39af39");
    TextView stationText;
    BT_Thread thread;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_station_protocol);
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
        BluetoothAdapter bluetooth;
        public BluetoothServerSocket serverSocket;
        public BluetoothSocket recipientSocket;
        InputStream mmInStream;
        OutputStream mmOutStream;
        byte[] mmBuffer = new byte[4096];
        public void run() {
            try {
                bluetooth = BluetoothAdapter.getDefaultAdapter();
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
            HelloWorld.main();
            startProtocol();
        }

        private byte[] listen() {
            try {
                // Wait for commitment and PK
                int numBytes = mmInStream.read(mmBuffer);
                return Arrays.copyOf(mmBuffer, numBytes);
            } catch (IOException e) {
                return null;
            }
        }

        private void write(byte[] content) {
            try {
                mmOutStream.write(content);
            }
            catch (IOException e) {
            }
        }

        private void startProtocol2() {
            write(new byte[2500]);
            Log.e("tester", "sent first");

            byte[] res2 = listen();
            Log.e("tester", "received first");
            write(multiplyArray(res2));
            Log.e("tester", "sent second");

            byte[] res3 = listen();
            Log.e("tester", "received second");
            write(multiplyArray(res3));
            Log.e("tester", "sent third");

            byte[] finalRes = listen();
            byte[] oups = multiplyArray(finalRes);
            System.out.println(oups.length);
            Log.e("tester", "finished");
        }


        private byte[] multiplyArray(byte[] array) {
            byte[] result = new byte[array.length];
            for (int i = 0; i < array.length; i++) {
                result[i] = (byte)(array[i] + array[i]);
            }
            return result;
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
            write(publicKey);

            byte[] PK = listen();
            String validPK = verifyUserCommitmentJava(PK, publicKey, nbRecipientAttributes, nbIssuerAttributes);
            if (validPK.equals("True")) {
                byte[] issuerAttributes = getAttributesJava(nbIssuerAttributes);
                byte[] credential = issuerSigningJava(publicKey, privateKey, PK, nbIssuerAttributes, issuerAttributes, nbRecipientAttributes);
                write(credential);
            }
            else {
                write(new byte[1]);
            }

            Log.e("startProtoIssuer", "waiting for disclosure");
            byte[] disclosureProof = listen();
            byte[] alreadySeenCredentials = getAlreadySeenCredentialsJava();
            Log.e("startProtoIssuer", "got pseudo list");
            String validDisclosure = verifyDisclosureProofJava(disclosureProof, publicKey, alreadySeenCredentials);
            Log.e("startProtoIssuer", "verified disclosure");
            byte[] blacklist;
            if (validDisclosure.equals("True")) {
                blacklist = getServiceProviderRevocatedValuesJava(10);
                write(blacklist);
            }
            else {
                write(new byte[1]);
                return;
            }
            Log.e("startProtoIssuer", "wrote blacklist");

            byte[] confirmation = listen();
            if (confirmation.length != 1) {
                return;
            }
            byte[] blacklistedPowers = getBlacklistedPowersJava(10);
            write(blacklistedPowers);

            byte[] blacProof = listen();

            String validBLACProof = getVerifierProtocolJava(blacProof, blacklist, blacklistedPowers);
            if (validBLACProof.equals("True")) {
                write(new byte[2]);
                Log.e("issuerOut", "letsgooo all works");
            }
            else {
                write(new byte[1]);
                Log.e("issuerOut", "blac failed");
            }
        }

    }


}