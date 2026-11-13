package xyz.bohesama.tapunlock;

import android.Manifest;
import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertisingSet;
import android.bluetooth.le.AdvertisingSetCallback;
import android.bluetooth.le.AdvertisingSetParameters;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.Toast;

import java.util.List;

public class TapActivity extends Activity {
    private static final String TAG = "TapUnlock";
    private static final long SCAN_TIMEOUT_MS = 4000;
    private static final int ADVERTISE_DURATION_10MS = 300;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private BluetoothLeScanner scanner;
    private BluetoothLeAdvertiser advertiser;
    private boolean scanning;
    private boolean advertising;

    private final ScanCallback scanCallback = new ScanCallback() {
        @Override
        public void onScanResult(int callbackType, ScanResult result) {
            if (!scanning || result.getScanRecord() == null) return;
            byte[] nonce = Protocol.nonceFromChallenge(
                    result.getScanRecord().getManufacturerSpecificData(Protocol.COMPANY_ID));
            if (nonce == null) return;
            stopScan();
            respond(nonce);
        }

        @Override
        public void onScanFailed(int errorCode) {
            scanning = false;
            fail("蓝牙扫描失败（" + errorCode + "）");
        }
    };

    private final AdvertisingSetCallback advertiseCallback = new AdvertisingSetCallback() {
        @Override
        public void onAdvertisingSetStarted(AdvertisingSet set, int txPower, int status) {
            if (status != AdvertisingSetCallback.ADVERTISE_SUCCESS) {
                advertising = false;
                fail("蓝牙广播失败（" + status + "）");
                return;
            }
            Toast.makeText(TapActivity.this, "已发送确认", Toast.LENGTH_SHORT).show();
            handler.postDelayed(TapActivity.this::finish, ADVERTISE_DURATION_10MS * 10L + 500);
        }

        @Override
        public void onAdvertisingEnabled(AdvertisingSet set, boolean enable, int status) {
            if (!enable) finish();
        }

        @Override
        public void onAdvertisingSetStopped(AdvertisingSet set) {
            advertising = false;
            finish();
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED
                || checkSelfPermission(Manifest.permission.BLUETOOTH_ADVERTISE) != PackageManager.PERMISSION_GRANTED) {
            fail("请先打开 Tap Unlock 授予蓝牙权限");
            return;
        }
        BluetoothAdapter adapter = getSystemService(BluetoothManager.class).getAdapter();
        if (adapter == null || !adapter.isEnabled()) {
            fail("蓝牙未开启");
            return;
        }
        scanner = adapter.getBluetoothLeScanner();
        advertiser = adapter.getBluetoothLeAdvertiser();
        if (scanner == null || advertiser == null) {
            fail("蓝牙不可用");
            return;
        }
        ScanFilter filter = new ScanFilter.Builder()
                .setManufacturerData(Protocol.COMPANY_ID, Protocol.CHALLENGE_PREFIX, Protocol.CHALLENGE_MASK)
                .build();
        ScanSettings settings = new ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .setLegacy(false)
                .build();
        scanning = true;
        scanner.startScan(List.of(filter), settings, scanCallback);
        handler.postDelayed(() -> {
            if (scanning) {
                stopScan();
                fail("附近没有等待确认的电脑");
            }
        }, SCAN_TIMEOUT_MS);
    }

    private void respond(byte[] nonce) {
        byte[] payload;
        try {
            payload = Protocol.response(nonce, Keys.sign(Protocol.signedMessage(nonce)));
        } catch (Exception e) {
            Log.e(TAG, "sign failed", e);
            fail("签名失败：" + e.getMessage());
            return;
        }
        AdvertisingSetParameters parameters = new AdvertisingSetParameters.Builder()
                .setLegacyMode(false)
                .setConnectable(false)
                .setScannable(false)
                .setInterval(AdvertisingSetParameters.INTERVAL_MIN)
                .setTxPowerLevel(AdvertisingSetParameters.TX_POWER_MEDIUM)
                .setPrimaryPhy(BluetoothDevice.PHY_LE_1M)
                .setSecondaryPhy(BluetoothDevice.PHY_LE_1M)
                .build();
        AdvertiseData data = new AdvertiseData.Builder()
                .addManufacturerData(Protocol.COMPANY_ID, payload)
                .build();
        advertising = true;
        advertiser.startAdvertisingSet(parameters, data, null, null, null,
                ADVERTISE_DURATION_10MS, 0, advertiseCallback);
    }

    private void stopScan() {
        if (!scanning) return;
        scanning = false;
        try {
            scanner.stopScan(scanCallback);
        } catch (RuntimeException e) {
            Log.w(TAG, "stopScan", e);
        }
    }

    private void fail(String message) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
        finish();
    }

    @Override
    protected void onDestroy() {
        handler.removeCallbacksAndMessages(null);
        stopScan();
        if (advertising) {
            advertising = false;
            try {
                advertiser.stopAdvertisingSet(advertiseCallback);
            } catch (RuntimeException e) {
                Log.w(TAG, "stopAdvertisingSet", e);
            }
        }
        super.onDestroy();
    }
}
