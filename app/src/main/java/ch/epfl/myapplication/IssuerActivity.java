package ch.epfl.myapplication;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;

public class IssuerActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        setTheme(R.style.AppTheme_NoActionBar);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_issuer);
        TextView recipientText = findViewById(R.id.issuerText);
        Button issuerButton = findViewById(R.id.buttonIssuerProtocol);
        issuerButton.setEnabled(false);
        issuerButton.setOnClickListener(l -> {
            Intent stationProtocolIntent = new Intent(getApplicationContext(), StationProtocol.class);
            startActivity(stationProtocolIntent);
        });

        Intent discoverableIntent = new Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE);
        discoverableIntent.putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, 300);
        ActivityResultLauncher<Intent> bluetoothAdvertiseLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() != Activity.RESULT_CANCELED) {
                        recipientText.setText("Currently advertising my BT for recipient");
                        issuerButton.setEnabled(true);

                    }
                    else {
                        recipientText.setText("Press back, then Issuer again..");
                    }
                });
        bluetoothAdvertiseLauncher.launch(discoverableIntent);
    }
}