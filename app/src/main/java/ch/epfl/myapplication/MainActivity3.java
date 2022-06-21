package ch.epfl.myapplication;

import android.app.ProgressDialog;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.recyclerview.widget.LinearLayoutManager;

import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.snackbar.Snackbar;

import ch.epfl.myapplication.bluetooth.BluetoothController;
import ch.epfl.myapplication.view.DeviceRecyclerViewAdapter;
import ch.epfl.myapplication.view.ListInteractionListener;
import ch.epfl.myapplication.view.RecyclerViewProgressEmptySupport;


/**
 * Main Activity of this application.
 *
 * @author Donato Rimenti
 */
public class MainActivity3 extends AppCompatActivity implements ListInteractionListener<BluetoothDevice> {

    /**
     * Tag string used for logging.
     */
    private static final String TAG = "MainActivity";

    /**
     * The controller for Bluetooth functionalities.
     */
    private BluetoothController bluetooth;

    /**
     * The Bluetooth discovery button.
     */
    private FloatingActionButton fab;

    /**
     * Progress dialog shown during the pairing process.
     */
    private ProgressDialog bondingProgressDialog;

    /**
     * Adapter for the recycler view.
     */
    private DeviceRecyclerViewAdapter recyclerViewAdapter;

    private RecyclerViewProgressEmptySupport recyclerView;

    private LinearLayout adContainer;

    /**
     * {@inheritDoc}
     */
    @Override
    protected void onCreate(Bundle savedInstanceState) {

        // Changes the theme back from the splashscreen. It's very important that this is called
        // BEFORE onCreate.
        //SystemClock.sleep(500);
        setTheme(R.style.AppTheme_NoActionBar);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);


        // Sets up the RecyclerView.
        this.recyclerViewAdapter = new DeviceRecyclerViewAdapter(this);
        this.recyclerView = (RecyclerViewProgressEmptySupport) findViewById(R.id.list);
        this.recyclerView.setLayoutManager(new LinearLayoutManager(this));

        // Sets the view to show when the dataset is empty. IMPORTANT : this method must be called
        // before recyclerView.setAdapter().
        View emptyView = findViewById(R.id.empty_list);
        this.recyclerView.setEmptyView(emptyView);

        // Sets the view to show during progress.
        ProgressBar progressBar = (ProgressBar) findViewById(R.id.progressBar);
        this.recyclerView.setProgressView(progressBar);

        this.recyclerView.setAdapter(recyclerViewAdapter);

        // [#11] Ensures that the Bluetooth is available on this device before proceeding.
        boolean hasBluetooth = getPackageManager().hasSystemFeature(PackageManager.FEATURE_BLUETOOTH);
        if (!hasBluetooth) {
            AlertDialog dialog = new AlertDialog.Builder(MainActivity3.this).create();
            dialog.setTitle(getString(R.string.bluetooth_not_available_title));
            dialog.setMessage(getString(R.string.bluetooth_not_available_message));
            dialog.setButton(AlertDialog.BUTTON_NEUTRAL, "OK",
                    new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            // Closes the dialog and terminates the activity.
                            dialog.dismiss();
                            MainActivity3.this.finish();
                        }
                    });
            dialog.setCancelable(false);
            dialog.show();
        }

        // Sets up the bluetooth controller.
        this.bluetooth = new BluetoothController(this, ((BluetoothManager)getApplicationContext().getSystemService(Context.BLUETOOTH_SERVICE)).getAdapter(),  recyclerViewAdapter);

        fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                // If the bluetooth is not enabled, turns it on.
                if (!bluetooth.isBluetoothEnabled()) {
                    Snackbar.make(view, R.string.enabling_bluetooth, Snackbar.LENGTH_SHORT).show();
                    bluetooth.turnOnBluetoothAndScheduleDiscovery();
                }
                Intent recipientProtocolIntent = new Intent(getApplicationContext(), RecipientProtocol.class);
                startActivity(recipientProtocolIntent);
            }
        });
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_about) {
            showAbout();
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    /**
     * Creates the about popup.
     */
    private void showAbout() {
        // Inflate the about message contents
        View messageView = getLayoutInflater().inflate(R.layout.about, null, false);

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setIcon(R.mipmap.ic_launcher);
        builder.setTitle(R.string.app_name);
        builder.setView(messageView);
        builder.create();
        builder.show();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void onItemClick(BluetoothDevice device) {
        Log.d(TAG, "Item clicked : " + BluetoothController.deviceToString(device));
        if (bluetooth.isAlreadyPaired(device)) {
            Log.d(TAG, "Device already paired!");
            Toast.makeText(this, R.string.device_already_paired, Toast.LENGTH_SHORT).show();
        } else {
            Log.d(TAG, "Device not paired. Pairing.");
            boolean outcome = bluetooth.pair(device);

            // Prints a message to the user.
            String deviceName = BluetoothController.getDeviceName(device);
            if (outcome) {
                // The pairing has started, shows a progress dialog.
                Log.d(TAG, "Showing pairing dialog");
                bondingProgressDialog = ProgressDialog.show(this, "", "Pairing with device " + deviceName + "...", true, false);
            } else {
                Log.d(TAG, "Error while pairing with device " + deviceName + "!");
                Toast.makeText(this, "Error while pairing with device " + deviceName + "!", Toast.LENGTH_SHORT).show();
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void startLoading() {
        this.recyclerView.startLoading();

        // Changes the button icon.
        this.fab.setImageResource(R.drawable.ic_bluetooth_searching_white_24dp);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void endLoading(boolean partialResults) {
        this.recyclerView.endLoading();

        // If discovery has ended, changes the button icon.
        if (!partialResults) {
            fab.setImageResource(R.drawable.ic_bluetooth_white_24dp);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void endLoadingWithDialog(boolean error, BluetoothDevice device) {
        if (this.bondingProgressDialog != null) {
            View view = findViewById(R.id.main_content);
            String message;
            String deviceName = BluetoothController.getDeviceName(device);

            // Gets the message to print.
            if (error) {
                message = "Failed pairing with device " + deviceName + "!";
            } else {
                message = "Succesfully paired with device " + deviceName + "!";
            }

            // Dismisses the progress dialog and prints a message to the user.
            this.bondingProgressDialog.dismiss();
            Snackbar.make(view, message, Snackbar.LENGTH_SHORT).show();

            // Cleans up state.
            this.bondingProgressDialog = null;
        }

    }






    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
    }



}