package ch.epfl.myapplication;

import android.annotation.SuppressLint;
import android.bluetooth.BluetoothSocket;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import android.widget.TextView;

import androidx.core.app.ActivityCompat;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class MyBluetoothService {
    static final int STATE_LISTENING = 1;
    static final int STATE_CONNECTING = 2;
    static final int STATE_CONNECTED = 3;
    static final int STATE_CONNECTION_FAILED = 4;
    static final int STATE_MESSAGE_RECEIVED = 5;
    private static final String TAG = "MY_APP_DEBUG_TAG";

    private Handler handler = initHandler(); // handler that gets info from Bluetooth service

    // Defines several constants used when transmitting messages between the
    // service and the UI.
    private interface MessageConstants {
        public static final int MESSAGE_READ = 0;
        public static final int MESSAGE_WRITE = 1;
        public static final int MESSAGE_TOAST = 2;

        // ... (Add other message types here as needed.)
    }

    private class ConnectedThread extends Thread {
        private final BluetoothSocket mmSocket;
        private final InputStream mmInStream;
        private final OutputStream mmOutStream;
        private byte[] mmBuffer; // mmBuffer store for the stream

        public ConnectedThread(BluetoothSocket socket) {
            mmSocket = socket;
            InputStream tmpIn = null;
            OutputStream tmpOut = null;

            // Get the input and output streams; using temp objects because
            // member streams are final.
            try {
                tmpIn = socket.getInputStream();
            } catch (IOException e) {
                Log.e(TAG, "Error occurred when creating input stream", e);
            }
            try {
                tmpOut = socket.getOutputStream();
            } catch (IOException e) {
                Log.e(TAG, "Error occurred when creating output stream", e);
            }

            mmInStream = tmpIn;
            mmOutStream = tmpOut;
        }

        public void run() {
            mmBuffer = new byte[1024];
            int numBytes; // bytes returned from read()

            // Keep listening to the InputStream until an exception occurs.
            while (true) {
                try {
                    // Read from the InputStream.
                    numBytes = mmInStream.read(mmBuffer);
                    // Send the obtained bytes to the UI activity.
                    Message readMsg = handler.obtainMessage(
                            MessageConstants.MESSAGE_READ, numBytes, -1,
                            mmBuffer);
                    readMsg.sendToTarget();
                } catch (IOException e) {
                    Log.d(TAG, "Input stream was disconnected", e);
                    break;
                }
            }
        }

        // Call this from the main activity to send data to the remote device.
        public void write(byte[] bytes) {
            try {
                mmOutStream.write(bytes);

                // Share the sent message with the UI activity.
                Message writtenMsg = handler.obtainMessage(
                        MessageConstants.MESSAGE_WRITE, -1, -1, mmBuffer);
                writtenMsg.sendToTarget();
            } catch (IOException e) {
                Log.e(TAG, "Error occurred when sending data", e);

                // Send a failure message back to the activity.
                Message writeErrorMsg =
                        handler.obtainMessage(MessageConstants.MESSAGE_TOAST);
                Bundle bundle = new Bundle();
                bundle.putString("toast",
                        "Couldn't send data to the other device");
                writeErrorMsg.setData(bundle);
                handler.sendMessage(writeErrorMsg);
            }
        }

        // Call this method from the main activity to shut down the connection.
        public void cancel() {
            try {
                mmSocket.close();
            } catch (IOException e) {
                Log.e(TAG, "Could not close the connect socket", e);
            }
        }
    }

    private Handler initHandler() {
        return new Handler(new Handler.Callback() {
            @SuppressLint("SetTextI18n")
            @Override
            public boolean handleMessage(Message msg) {

                // Handler : UI Thread ile haberle??meyi sa??layan bir s??n??ft??r.
                switch (msg.what) {

                    // what : kullan??c?? tan??ml?? mesaj kodudur.
                    // Bu mesaj??n neyle ilgili oldu??una kullan??c?? karar verebilir.
                    // int tipinde tan??mlan??r.

                    // STATE_LISTENING de??eriyse
                    case STATE_LISTENING:

                    // STATE_CONNECTING de??eriyse
                    case STATE_CONNECTING:

                        break;

                    // STATE_CONNECTED de??eriyse
                    case STATE_CONNECTED:
                        break;

                    // STATE_CONNECTION_FAILED de??eriyse
                    case STATE_CONNECTION_FAILED:

                        // Connection Failed texti yaz
                        break;

                    // STATE_MESSAGE_RECEIVED de??eriyse
                    case STATE_MESSAGE_RECEIVED:

                        // readBuffer de??i??keni mesaj objesini al
                        byte[] readBuffer = (byte[]) msg.obj;

                        // tempMessage de??i??kine de??erler i??leniyor
                        String tempMessage = new String(readBuffer, 0, msg.arg1);

                        // i??lemi bitir.
                        break;
                }
                // de??eri true d??nd??r
                return true;
            }
        });
    }
}
