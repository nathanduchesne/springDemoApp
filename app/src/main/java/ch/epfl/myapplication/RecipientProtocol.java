package ch.epfl.myapplication;

import static ch.epfl.myapplication.HelloWorld.*;

import androidx.appcompat.app.AppCompatActivity;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothSocket;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Set;
import java.util.UUID;

public class RecipientProtocol extends AppCompatActivity {
    BluetoothAdapter bluetoothAdapter;
    UUID BT_UUID = UUID.fromString("c9916d86-1653-4f14-b7f1-075f0b39af39");
    TextView recipientText;
    ClientBT_Thread thread;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_recipient_protocol);
        bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        recipientText = findViewById(R.id.textViewRecipient);

        Set<BluetoothDevice> pairedDevices = bluetoothAdapter.getBondedDevices();

        if (pairedDevices.size() == 1) {
            // Only works with one device to disable thread running protocol from being overwritten.
            for (BluetoothDevice device : pairedDevices) {
                String deviceName = device.getName();
                String deviceHardwareAddress = device.getAddress(); // MAC address
                System.out.println("Device name is: "+deviceName+" and MAC address is: "+deviceHardwareAddress);
                thread = new ClientBT_Thread(device);
                recipientText.setText("Connected to "+deviceName);
                thread.setPriority(Thread.MAX_PRIORITY);
                thread.start();
            }
        }

    }

    @Override
    protected void onDestroy() {
        thread.interrupt();
        super.onDestroy();
    }

    private class ClientBT_Thread extends Thread {
        BluetoothDevice device;
        InputStream mmInStream;
        OutputStream mmOutStream;
        byte[] mmBuffer = new byte[4096];
        public ClientBT_Thread(BluetoothDevice dev) {
            device = dev;
        }
        public void run() {
            try {
                BluetoothSocket serverSocket = device.createRfcommSocketToServiceRecord(BT_UUID);
                serverSocket.connect();
                Log.e("protocol", "successfully connected to the other phone socket");
                mmInStream = serverSocket.getInputStream();
                Log.e("protocol", "got input stream");
                mmOutStream = serverSocket.getOutputStream();
                Log.e("protocol", "got output stream");

            } catch (IOException e) {
                e.printStackTrace();
            }

            startProtocol();
        }
        /*
    Starts the protocol run from the recipient side
     */
        private void startProtocol() {
            System.out.println(Runtime.getRuntime().freeMemory());
            int nbRecipientAttributes = 2;
            int nbIssuerAttributes = 5;
            initCurve();
            boolean waitingForKeys = true;
            byte[] publicKey = null;
            while (waitingForKeys) {
                try {
                    // Wait for keygen
                    int numBytes = mmInStream.read(mmBuffer);
                    System.out.println("numBytes is "+numBytes);
                    // Send the obtained bytes to the UI activity.
                    publicKey = Arrays.copyOf(mmBuffer, numBytes);
                    waitingForKeys = false;
                } catch (IOException e) {
                    waitingForKeys = true;

                }
            }
            System.out.println(Runtime.getRuntime().freeMemory());
            System.out.println("isWaitingForKeys is"+waitingForKeys);
            Log.e("protocol", "got public key");
            byte[] recipientAttributes = getAttributesJava(nbRecipientAttributes);
            Log.e("protocol", "got recip attributes");
            dumpStack();
            System.out.println(Runtime.getRuntime().freeMemory());
            byte[] recipientCommitment = getUserCommitmentJava(publicKey, recipientAttributes, nbRecipientAttributes, nbIssuerAttributes);
            Log.e("protocol", "got recip pk");
            System.out.println(Runtime.getRuntime().freeMemory());
            byte[] recipientCommitmentForIssuer = removeBlindingFactorJava(recipientCommitment, nbRecipientAttributes);
            Log.e("protocol", "got recip pk for issuer");
            System.out.println(Runtime.getRuntime().freeMemory());
            try {
                mmOutStream.write(recipientCommitmentForIssuer);
                Log.e("protocol", "sent commitment");
            } catch (IOException e) {
                Log.e("protocol", "commitment failed to send");
                System.out.println("exception while sending commitment");
            }
            //Wait for signature and credentials
            byte[] blindCredential = null;
            boolean waitingForCredential = true;
            while (waitingForCredential) {
                try {
                    // Wait for keygen
                    int numBytes = mmInStream.read(mmBuffer);
                    System.out.println("numBytes is "+numBytes);

                    //If byte[] is of size 1, it means something failed
                    if (numBytes == 1) {
                        Log.e("protocol", "issuance failed");
                        return;
                    }
                    blindCredential = Arrays.copyOf(mmBuffer, numBytes);
                    waitingForCredential = false;
                } catch (IOException e) {
                    waitingForCredential = true;

                }
            }
            System.out.println("waitingCredential is"+waitingForCredential);

            byte[] realCredential = unblindSignatureJava(blindCredential, recipientCommitment, recipientAttributes, nbIssuerAttributes, nbRecipientAttributes);
            Log.e("protocol", "got credential");
            byte[] epoch = getEpochJava();
            Log.e("protocol", "got epoch");
            byte[] disclosureProofRecipient = getDisclosureProofJava(publicKey, nbIssuerAttributes, nbRecipientAttributes, realCredential, epoch);
            System.out.println("Disclosure proof for recip is with length "+disclosureProofRecipient.length);
            dumpStack();
            for (int i = 0; i < disclosureProofRecipient.length; i++){
                System.out.print(disclosureProofRecipient[i]);
            }
            System.out.println();
            byte[] disclosureProofForIssuer = getProofOfDisclosureForVerifierJava(disclosureProofRecipient, nbRecipientAttributes, nbIssuerAttributes, epoch);
            System.out.println("Disclosure proof for issuer is with length "+disclosureProofForIssuer.length);
            for (int i = 0; i < disclosureProofForIssuer.length; i++){
                System.out.print(disclosureProofForIssuer[i]);
            }
            System.out.flush();
            try {
                mmOutStream.write(disclosureProofForIssuer);
                Log.e("protocol", "sent disclosure proof");
            } catch (IOException e) {
                System.out.println("error while sending credential");
                Log.e("protocol", "error during disclosure");
            }
            byte[] blacklist = null;
            boolean waitingForBlacklist = true;
            while(waitingForBlacklist) {
                try {
                    int numBytes = mmInStream.read(mmBuffer);
                    System.out.println("numBytes is "+numBytes);
                    if (numBytes == 1){
                        Log.e("protocol", "byte array is of size 1");
                        //recipientText.setText("Distribution failed...");
                        return;
                    }
                    blacklist = Arrays.copyOf(mmBuffer, numBytes);
                    waitingForBlacklist = false;
                }
                catch (IOException e){
                    waitingForBlacklist = true;
                }
            }
            //Waiting for powers
            try {
                mmOutStream.write(new byte[1]);
                Log.e("protocol", "sent waiting for powers");
            } catch (IOException e) {

            }
            byte[] blacklistPowers = null;
            boolean waitingForBlacklistPowers = true;
            while(waitingForBlacklistPowers) {
                try {
                    int numBytes = mmInStream.read(mmBuffer);

                    blacklistPowers = Arrays.copyOf(mmBuffer, numBytes);
                    waitingForBlacklistPowers = false;
                }
                catch (IOException e){
                    waitingForBlacklistPowers = true;

                }
            }
            Log.e("protocol", "got blacklist powers");
            byte[] tokenAndRevVal = getTokenAndRevocationValueJava(disclosureProofRecipient, realCredential, nbIssuerAttributes);
            byte[] blacProver = getProverProtocolJava(blacklist, blacklistPowers, tokenAndRevVal);
            try {
                mmOutStream.write(blacProver);
            } catch (IOException e) {

            }
            //Wait for station result
            boolean waitingForResult = true;
            while(waitingForResult) {
                try {
                    int numBytes = mmInStream.read(mmBuffer);
                    System.out.println("numBytes is "+numBytes);

                    if (numBytes == 2) {
                        Log.e("protocol", "Success!!!!!");
                        //recipientText.setText("Successful protocol!");
                    }
                    else {
                        //recipientText.setText("Credential was found in blacklist");
                    }
                    waitingForResult = false;
                }
                catch (IOException e) {
                    waitingForResult = true;

                }
            }
        }
    }

}