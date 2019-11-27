package com.skjolberg.mifare.desfiretooltest;

import static com.github.skjolber.desfire.libfreefare.MifareDesfire.*;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.widget.TextView;
import android.widget.Toast;

import com.github.skjolber.desfire.ev1.model.DesfireApplication;
import com.github.skjolber.desfire.ev1.model.DesfireApplicationId;
import com.github.skjolber.desfire.ev1.model.DesfireApplicationKey;
import com.github.skjolber.desfire.ev1.model.DesfireApplicationKeySettings;
import com.github.skjolber.desfire.ev1.model.DesfireTag;
import com.github.skjolber.desfire.ev1.model.VersionInfo;
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepAdapter;
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepWrapper;
import com.github.skjolber.desfire.ev1.model.command.Utils;
import com.github.skjolber.desfire.ev1.model.file.DesfireFile;
import com.github.skjolber.desfire.ev1.model.file.RecordDesfireFile;
import com.github.skjolber.desfire.ev1.model.file.StandardDesfireFile;
import com.github.skjolber.desfire.ev1.model.file.ValueDesfireFile;
import com.github.skjolber.desfire.ev1.model.key.Desfire3DESKey;
import com.github.skjolber.desfire.ev1.model.key.Desfire3K3DESKey;
import com.github.skjolber.desfire.ev1.model.key.DesfireAESKey;
import com.github.skjolber.desfire.ev1.model.key.DesfireDESKey;
import com.github.skjolber.desfire.ev1.model.key.DesfireKey;
import com.github.skjolber.desfire.ev1.model.key.DesfireKeyType;
import com.github.skjolber.desfire.libfreefare.MifareDESFireKey;
import com.github.skjolber.desfire.libfreefare.MifareDesfireKey;
import com.github.skjolber.desfire.libfreefare.MifareTag;

import com.skjolberg.mifare.desfiretooltest.filelist.ApplicationDetailFile;

import com.skjolberg.mifare.desfiretooltest.keys.DataSource;

@SuppressLint("ResourceAsColor")
public class MainActivity extends Activity implements NfcAdapter.ReaderCallback {

    private static final String ACTION_NFC_SETTINGS = "android.settings.NFC_SETTINGS";
    TextView textView;
    private static final String TAG = MainActivity.class.getName();

    private interface OnKeyListener {
        void onKey(DesfireKey key);
    }

    private NfcAdapter nfcAdapter;
    private List<DesfireApplication> applications;

    private DesfireApplication application;

    private DesfireApplicationKey authenticatedKey;

    private MifareTag tag;
    private DesfireTag desfireTag;
    private DefaultIsoDepAdapter defaultIsoDepAdapter;
    private TagPresenceScanner tagPresenceScanner;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        textView = findViewById(R.id.tvNfcData);

        // Check for available NFC Adapter
        PackageManager pm = getPackageManager();
        if (pm.hasSystemFeature(PackageManager.FEATURE_NFC) && NfcAdapter.getDefaultAdapter(this) != null) {
            Log.d(TAG, "NFC feature found");

            nfcAdapter = NfcAdapter.getDefaultAdapter(this);
            if (!nfcAdapter.isEnabled()) {
                startNfcSettingsActivity();

            }


            tagPresenceScanner = new TagPresenceScanner(this);
        } else {
            Log.d(TAG, "NFC feature not found");

            showToast(R.string.nfcNotAvailableMessage);

            finish();
        }

    }

    @Override
    public void onResume() {
        super.onResume();

        nfcAdapter.enableReaderMode(this, this, NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_NFC_B | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null);
    }

    @Override
    public void onPause() {
        super.onPause();

        nfcAdapter.disableReaderMode(this);

        tagPresenceScanner.pause();
    }




    @Override
    public void onTagDiscovered(Tag nfc) {
        IsoDep isoDep = IsoDep.get(nfc);


        DefaultIsoDepWrapper isoDepWrapper = new DefaultIsoDepWrapper(isoDep);

        defaultIsoDepAdapter = new DefaultIsoDepAdapter(isoDepWrapper, false);

        try {
            isoDep.connect();


            tag = mifare_desfire_tag_new();
            tag.setActive(1);
            tag.setIo(defaultIsoDepAdapter);

            desfireTag = new DesfireTag();

            VersionInfo versionInfo = mifare_desfire_get_version(tag);

            List<DesfireApplicationId> aids = mifare_desfire_get_application_ids(tag);
            if (aids != null) {
                Log.d(TAG, "Found applications " + aids.size());

                aids.add(0, new DesfireApplicationId()); // add default

                // 			DesfireApplicationKeySettings desfireApplicationKeySettings = mifare_desfire_get_key_settings(tag);
                applications = new ArrayList<DesfireApplication>();

                for (DesfireApplicationId aid : aids) {
                    DesfireApplication desfireApplication = new DesfireApplication();
                    desfireApplication.setId(aid.getId());

                    applications.add(desfireApplication);

                    Log.d(TAG, "Found application " + aid);

                    if (mifare_desfire_select_application(tag, aid) == 0) {
                        Log.d(TAG, "Selected application " + aid.toString());

                        desfireApplication.setKeySettings(mifare_desfire_get_key_settings(tag));

                        DesfireApplicationKeySettings keySettings = desfireApplication.getKeySettings();

                        Log.d(TAG, keySettings.toString());
                    }
                }

                desfireTag.setApplications(applications);

                showApplicationFragment(applications);

                tagPresenceScanner.resumeDelayed();
            } else {
                Log.d(TAG, "Did not find any applications");
            }
        } catch (Exception e) {
            Log.d(TAG, "Problem running commands", e);
        } finally {

        }
    }

    @Override
    public void onBackPressed() {
        super.onBackPressed();
    }


    private void showApplicationFragment(final List<DesfireApplication> applications) {
        Log.d(TAG, "showApplicationFragment");

        int position = 1;

        application = applications.get(position);

        Log.d(TAG, "Click on application " + application.getIdString());

        MainActivity.this.authenticatedKey = null;

        try {
            if (tag.getSelectedApplication() != application.getIdInt()) {

                if (!isConnected()) {
                    Log.d(TAG, "Tag lost wanting to change application");

                    onTagLost();

                    return;
                }

                try {
                    if (mifare_desfire_select_application(tag, new DesfireApplicationId(application.getId())) != 0) {
                        Log.d(TAG, "Unable to select application");
                    }
                } catch (Exception e) {
                    Log.d(TAG, "Problem selecting app " + application.getIdString(), e);

                    return;
                }
            }

            if (!application.hasKeys()) {
                if (!isConnected()) {
                    Log.d(TAG, "Tag lost wanting to get keys");

                    onTagLost();

                    return;
                }

                Log.d(TAG, "Get application keys");
                DesfireKeyType type = application.getKeySettings().getType();
                for (int i = 0; i < application.getKeySettings().getMaxKeys(); i++) {

                    try {
                        byte version = mifare_desfire_get_key_version(tag, (byte) i);

                        application.add(new DesfireApplicationKey(i, DesfireKey.newInstance(type, version)));
                    } catch (IllegalArgumentException e) {
                        // assume no key set
                    }
                }
            } else {
                Log.d(TAG, "Already read key versions");
            }

            if (application.getIdInt() != 0) {

                if (!application.hasFiles()) {
                    if (!isConnected()) {
                        Log.d(TAG, "Tag lost wanting to read application files");

                        onTagLost();

                        return;
                    }

                    readApplicationFiles();
                } else {
                    Log.d(TAG, "Already read file settings");
                }

            }

            showApplicationFragment();

        } catch (Exception e) {
            Log.d(TAG, "Problem selecting app " + application.getIdString(), e);
        }


    }

    private boolean readApplicationFiles() throws Exception {
        Log.d(TAG, "Get application files");

        DesfireApplicationKeySettings keySettings = application.getKeySettings();

        Log.d(TAG, keySettings.toString());

        if (keySettings.isRequiresMasterKeyForDirectoryList()) {
            final List<DesfireApplicationKey> keys = application.getKeys();

            final DesfireApplicationKey root = keys.get(0);

            showKeySelector(keySettings.getType(), new OnKeyListener() {

                @Override
                public void onKey(DesfireKey key) {
                    if (!isConnected()) {
                        Log.d(TAG, "Tag lost wanting to select application");

                        onTagLost();

                        return;
                    }

                    try {
                        DesfireApplicationKey clone = new DesfireApplicationKey(root.getIndex(), key);

                        if (authenticate(clone)) {
                            MainActivity.this.authenticatedKey = clone;

                            readApplicationFiles();

                            showApplicationFragment();

                            showToast(R.string.applicationAuthenticatedSuccess);
                        } else {
                            showToast(R.string.applicationAuthenticatedFail);
                        }

                    } catch (Exception e) {
                        Log.d(TAG, "Unable to authenticate", e);

                        showToast(R.string.applicationAuthenticatedFail);
                    }

                }
            });

        } else {
            Log.d(TAG, "Can list files");
        }

        Log.d(TAG, "Get files ids");
        byte[] ids = mifare_desfire_get_file_ids(tag);

        if (ids != null) {
            Log.d(TAG, "Got " + ids.length + " files");

            for (int i = 0; i < ids.length; i++) {
                DesfireFile settings = mifare_desfire_get_file_settings(tag, ids[i]);

                Log.d(TAG, "File setting " + i + ": " + settings);

                application.add(settings);
            }
        } else {
            Log.d(TAG, "Unable to get files ids");
        }

        return true;
    }

    protected void onTagLost() {

            Toast.makeText(this, "tag lost", Toast.LENGTH_SHORT).show();


        //showShortToast(R.string.tagStatusLost);

    }


    private void showApplicationFragment() {
        Log.d(TAG, "showApplicationFragment");


        ApplicationDetailFile file = new ApplicationDetailFile("File 0x1", "Standard file, open comms.", application.getFiles().get(0), "R1 W2 RW2 C0");

        final DesfireFile desfireFile = file.getFile();

        Log.d(TAG, "Select file " + desfireFile);

        if (desfireFile.isContent()) {
            Log.d(TAG, "Already read file content");


            return;
        }

        if (!isConnected()) {
            onTagLost();

            return;
        }

        if (!desfireFile.isFreeReadWriteAccess()) {
            if (authenticatedKey != null) {
                Log.d(TAG, "Already authenticated using key " + authenticatedKey.getIndex());

                if (desfireFile.freeReadAccess() || desfireFile.isReadAccess(authenticatedKey.getIndex())) {
                    Log.d(TAG, "Already authenticated with read file access");

                    if (!desfireFile.freeReadAccess()) {
                        try {
                            if (authenticate(authenticatedKey)) {
                                readFile(desfireFile);
                            }
                        } catch (Exception e) {
                            Log.d(TAG, "Unable to authenticate", e);

                            showToast(R.string.applicationAuthenticatedFail);
                        }
                    } else {
                        readFile(desfireFile);
                    }


                    return;
                }
            }


            if (!isConnected()) {
                onTagLost();

                return;
            }
            final String access = "R";

            final DesfireApplicationKey desfire = application.getKeys().get(1);

            DesfireKey key = desfireKey(application.getKeySettings().getType());


            try {
                DesfireApplicationKey clone = new DesfireApplicationKey(desfire.getIndex(), key);

                if (authenticate(clone)) {
                    MainActivity.this.authenticatedKey = clone;

                    if (desfireFile.freeReadAccess() || access.contains("R")) {
                        readFile(desfireFile);
                    }


                    showToast(R.string.applicationAuthenticatedSuccess);
                } else {
                    showToast(R.string.applicationAuthenticatedFail);
                }

            } catch (Exception e) {
                Log.d(TAG, "Unable to authenticate", e);

                showToast(R.string.applicationAuthenticatedFail);
            }


        } else {
            try {
                readFile(desfireFile);

            } catch (Exception e) {
                Log.d(TAG, "Problem reading file", e);
            }

        }

    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.main, menu);

        return true;
    }


    private boolean authenticate(DesfireApplicationKey desfireApplicationKey) throws Exception {

        DesfireKey key = desfireApplicationKey.getDesfireKey();

        Log.d(TAG, "Authenticate key " + (byte) desfireApplicationKey.getIndex());

        /* Authenticate with this key */
        switch (key.getType()) {
            case AES: {

                DesfireAESKey aesKey = (DesfireAESKey) key;

                MifareDESFireKey mifareDESFireKey = MifareDesfireKey.mifare_desfire_aes_key_new_with_version(aesKey.getValue(), (byte) key.getVersion());

                int result = mifare_desfire_authenticate_aes(tag, (byte) desfireApplicationKey.getIndex(), mifareDESFireKey);

                if (result == 0) {
                    Log.d(TAG, "Authenticated AES using key " + key.getName() + " index " + (byte) desfireApplicationKey.getIndex());

                    return true;
                } else {
                    Log.d(TAG, "Unable to authenticate AES using key " + key.getName());
                }

                break;
            }
            case TKTDES: {

                Desfire3K3DESKey desfire3k3desKey = (Desfire3K3DESKey) key;

                MifareDESFireKey mifareDESFireKey = MifareDesfireKey.mifare_desfire_3k3des_key_new(desfire3k3desKey.getValue());

                int result = mifare_desfire_authenticate_iso(tag, (byte) desfireApplicationKey.getIndex(), mifareDESFireKey);

                if (result == 0) {
                    Log.d(TAG, "Authenticated 3K3DES using key " + key.getName());

                    return true;
                } else {
                    Log.d(TAG, "Unable to authenticate 3K3DES using key " + key.getName());
                }

                break;
            }
            case TDES: {

                Desfire3DESKey desfire3desKey = (Desfire3DESKey) key;

                MifareDESFireKey mifareDESFireKey = MifareDesfireKey.mifare_desfire_3des_key_new(desfire3desKey.getValue());

                MifareDesfireKey.mifare_desfire_key_set_version(mifareDESFireKey, (byte) desfire3desKey.getVersion());

                int result = mifare_desfire_authenticate(tag, (byte) desfireApplicationKey.getIndex(), mifareDESFireKey);

                if (result == 0) {
                    Log.d(TAG, "Authenticated 3DES using key " + key.getName());

                    return true;
                } else {
                    Log.d(TAG, "Unable to authenticate 3DES using key " + key.getName());
                }

                break;
            }
            case DES: {

                DesfireDESKey desfireDesKey = (DesfireDESKey) key;

                MifareDESFireKey mifareDESFireKey = MifareDesfireKey.mifare_desfire_des_key_new(desfireDesKey.getValue());

                MifareDesfireKey.mifare_desfire_key_set_version(mifareDESFireKey, (byte) desfireDesKey.getVersion());

                int result = mifare_desfire_authenticate(tag, (byte) desfireApplicationKey.getIndex(), mifareDESFireKey);

                if (result == 0) {
                    Log.d(TAG, "Authenticated DES using key " + key.getName());

                    return true;
                } else {
                    Log.d(TAG, "Unable to authenticate DES using key " + key.getName());
                }

                break;
            }
        }
        return false;
    }


    private void showKeySelector(DesfireKeyType type, final OnKeyListener listener) {
        MainApplication application = MainApplication.getInstance();

        DataSource dataSource = application.getDataSource();

        final List<DesfireKey> keys;
        if (type == DesfireKeyType.TDES || type == DesfireKeyType.DES) {
            keys = new ArrayList<>();

            keys.addAll(dataSource.getKeys(DesfireKeyType.DES));
            keys.addAll(dataSource.getKeys(DesfireKeyType.TKTDES));
        } else {
            keys = dataSource.getKeys(type);
        }


    }

    private DesfireKey desfireKey(DesfireKeyType type) {
        MainApplication application = MainApplication.getInstance();

        DataSource dataSource = application.getDataSource();

        final List<DesfireKey> keys;
        if (type == DesfireKeyType.TDES || type == DesfireKeyType.DES) {
            keys = new ArrayList<>();

            keys.addAll(dataSource.getKeys(DesfireKeyType.DES));
            keys.addAll(dataSource.getKeys(DesfireKeyType.TKTDES));
        } else {
            keys = dataSource.getKeys(type);
        }

        if (!keys.isEmpty()) {
            String names[] = new String[keys.size()];
            for (int i = 0; i < names.length; i++) {
                names[i] = getString(R.string.applicationAuthenticateKeyNameVersion, keys.get(i).getName(), keys.get(i).getVersionAsHexString());
            }
            DesfireKey key = keys.get(0);

            return key;

        } else {
            Log.d(TAG, "No " + type + " keys found");
        }

        return null;
    }

    public void showToast(int resource, Object... args) {
        Toast.makeText(getApplicationContext(), getString(resource, args), Toast.LENGTH_LONG).show();
    }

    public void showToast(int resource) {
        Toast.makeText(getApplicationContext(), getString(resource), Toast.LENGTH_LONG).show();
    }

    public void showShortToast(int resource) {
        Toast.makeText(getApplicationContext(), getString(resource), Toast.LENGTH_SHORT).show();
    }


    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
    }


    private void readFile(final DesfireFile desfireFile) {

        Log.d(TAG, "Read file access");
        if (desfireFile instanceof StandardDesfireFile) {
            try {
                StandardDesfireFile standardDesfireFile = (StandardDesfireFile) desfireFile;

                if (!standardDesfireFile.isData()) {
                    Log.d(TAG, "Read data from file " + Integer.toHexString(desfireFile.getId()));

                    byte[] data = mifare_desfire_read_data(tag, (byte) desfireFile.getId(), 0, 0);

                    Log.d(TAG, "Read data length " + data.length);
                    String str = new String(data);
                    String arr[] = str.split("\n");
                    final StringBuilder builder = new StringBuilder();
                    HashMap<String, String> map = new HashMap<>();
                    for (int i = 0; i < arr.length; i++) {
                        if (i == arr.length - 2) {
                            break;
                        }
                        builder.append(arr[i]).append("\n");
                        if (arr[i].contains(":")) {
                            String splitArr[] = arr[i].split(":");
                            map.put(splitArr[0], splitArr[1]);
                        }
                    }
                    Log.e("data", builder.toString());
                    //Toast.makeText(this, "" + str, Toast.LENGTH_SHORT).show();
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            textView.setText(builder.toString());
                        }
                    });
                    // standardDesfireFile.setData(data);
                }
            } catch (Exception e) {
                Log.d(TAG, "Problem reading file", e);
            }
        } else if (desfireFile instanceof ValueDesfireFile) {
            try {
                ValueDesfireFile valueDesfireFile = (ValueDesfireFile) desfireFile;

                if (!valueDesfireFile.isValue()) {
                    Log.d(TAG, "Read value from file " + Integer.toHexString(desfireFile.getId()));

                    Integer value = mifare_desfire_get_value(tag, (byte) desfireFile.getId());

                    Log.d(TAG, "Read value " + value);

                    valueDesfireFile.setValue(value);
                }
            } catch (Exception e) {
                Log.d(TAG, "Problem reading file", e);
            }
        } else if (desfireFile instanceof RecordDesfireFile) {
            try {
                RecordDesfireFile recordDesfireFile = (RecordDesfireFile) desfireFile;

                if (!recordDesfireFile.isRecords()) {
                    Log.d(TAG, "Read records from file " + Integer.toHexString(desfireFile.getId()));

                    byte[] records = mifare_desfire_read_records(tag, (byte) desfireFile.getId(), 0, recordDesfireFile.getCurrentRecords());

                    Log.d(TAG, "Read " + recordDesfireFile.getCurrentRecords() + " records " + Utils.getHexString(records));

                    recordDesfireFile.setRecords(records);
                }
            } catch (Exception e) {
                Log.d(TAG, "Problem reading record file", e);
            }
        }
    }


    private boolean isConnected() {
        MifareTag tag = this.tag;

        if (tag != null) {
            DefaultIsoDepWrapper wrapper = (DefaultIsoDepWrapper) tag.getIo().getIsoDepWrapper();

            return wrapper.getIsoDep().isConnected();
        }
        return false;
    }

    /**
     * Launch an activity for NFC (or wireless) settings, so that the user might enable or disable nfc
     */


    protected void startNfcSettingsActivity() {
        if (android.os.Build.VERSION.SDK_INT >= 16) {
            startActivity(new Intent(ACTION_NFC_SETTINGS)); // android.provider.Settings.ACTION_NFC_SETTINGS
        } else {
            startActivity(new Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS));
        }
    }

    protected static class TagPresenceScanner extends Handler {

        private static final long TAG_RESCAN_INTERVAL_MS = 1000;

        private WeakReference<MainActivity> activityReference;

        public TagPresenceScanner(MainActivity activity) {
            this.activityReference = new WeakReference<MainActivity>(activity);
        }

        void resume() {
            synchronized (this) {
                if (!hasMessages(0)) {
                    sendEmptyMessage(0);
                }
            }
        }


        public void resumeDelayed() {
            synchronized (this) {
                if (!hasMessages(0)) {
                    sendEmptyMessageDelayed(0, TAG_RESCAN_INTERVAL_MS);
                }
            }
        }

        public void pause() {
            synchronized (this) {
                removeMessages(0);
            }
        }

        @Override
        public void handleMessage(android.os.Message msg) {
            //Log.v(TAG, "Handle message");

            MainActivity activity = activityReference.get();
            if (activity != null) {
                if (activity.isConnected()) {
                    resumeDelayed();
                } else {
                    activity.onTagLost();

                    pause();
                }
            }
        }
    }
}
