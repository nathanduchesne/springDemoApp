package ch.epfl.myapplication;

import static ch.epfl.myapplication.HelloWorld.*;

import androidx.appcompat.app.AppCompatActivity;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSocket;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
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
    Button distribAgainButton;
    BT_Thread thread;
    int MAX_MTU_SIZE = 990;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        setTheme(R.style.AppTheme_NoActionBar);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_station_protocol);
        stationText = findViewById(R.id.textViewStation);
        distribAgainButton = findViewById(R.id.buttonInStation);
        distribAgainButton.setVisibility(View.GONE);
        thread = new BT_Thread();
        thread.setPriority(Thread.MAX_PRIORITY);
        thread.start();
        distribAgainButton.setOnClickListener(l -> {
            distribAgainButton.setEnabled(false);
            thread.secondPart();
            distribAgainButton.setVisibility(View.GONE);
        });
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
        byte[] initialDisclosure;
        byte[] publicKey;
        byte[] newListOfCredentials;
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
            //HelloWorld.main();
            startProtocol();
        }

        private byte[] listen() {
            byte[] result;
            try {
                int numBytes = mmInStream.read(mmBuffer);
                result =  Arrays.copyOf(mmBuffer, numBytes);
                while (numBytes == MAX_MTU_SIZE) {
                    numBytes = mmInStream.read(mmBuffer);
                    byte[] tmp = Arrays.copyOf(mmBuffer, numBytes);
                    byte[] dst = new byte[result.length + numBytes];
                    System.arraycopy(result, 0, dst, 0, result.length);
                    System.arraycopy(tmp, 0, dst, result.length, numBytes);
                    result = dst;
                }
            } catch (IOException e) {
                return null;
            }
            return result;
        }

        private void write(byte[] content) {
            try {
                mmOutStream.write(content);
            }
            catch (IOException e) {
            }
        }

        public void secondPart(){
            byte[] resultSecondDisclosure = verifyDisclosureProofJava(initialDisclosure, publicKey, newListOfCredentials);
            String isValidSecondDisclosure = isDisclosureProofValidJava(resultSecondDisclosure);
            if (isValidSecondDisclosure.equals("True")) {
                write(new byte[2]);
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        stationText.setText("This user is valid.");
                    }
                });
            }
            else {
                write(new byte[1]);
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        stationText.setText("This credential has already been seen in the domain..");
                    }
                });
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
            int nbRecipientAttributes = 5;
            int nbIssuerAttributes = 5;
            initCurve();
            byte[] keys = keygenJava(nbIssuerAttributes+nbRecipientAttributes);
            byte[] publicKey = getPublicKeyJava(keys);
            this.publicKey = publicKey;
            System.out.println("public key in station is "+publicKey.length);
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
            initialDisclosure = disclosureProof;
            System.out.println("Size of disclosure proof in verifier is "+disclosureProof.length);
            byte[] alreadySeenCredentials = getAlreadySeenCredentialsJava();
            Log.e("startProtoIssuer", "got pseudo list");
            byte[] resultDisclosure = verifyDisclosureProofJava(disclosureProof, publicKey, alreadySeenCredentials);
            String isValidDisclosure = isDisclosureProofValidJava(resultDisclosure);
            Log.e("startProtoIssuer", "verified disclosure");
            byte[] blacklist;
            if (isValidDisclosure.equals("True")) {
                byte[] newAlreadySeenValues = getNewAlreadySeenCredentialsJava(resultDisclosure);
                newListOfCredentials = newAlreadySeenValues;
                byte[] verifyAgain = verifyDisclosureProofJava(disclosureProof, publicKey, newAlreadySeenValues);
                String validVerifyAgain = isDisclosureProofValidJava(verifyAgain);
                if (validVerifyAgain.equals("False")) {
                    Log.e("tag", "Since the domain-specific pseudo was added to the list of previously seen, double-spending has been detected!");
                }
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
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        stationText.setText("The recipient has succeeded in showing their credential");
                        distribAgainButton.setVisibility(View.VISIBLE);
                    }
                });
            }
            else {
                write(new byte[1]);
                Log.e("issuerOut", "blac failed");
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        stationText.setText("The recipient has failed in showing their credential");
                    }
                });
            }
        }

    }


}