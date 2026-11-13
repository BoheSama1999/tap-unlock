package xyz.bohesama.tapunlock;

import android.Manifest;
import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity {
    private static final int REQUEST_BLUETOOTH = 1;

    private TextView status;
    private String publicKeyPem = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        int pad = (int) (20 * getResources().getDisplayMetrics().density);

        LinearLayout column = new LinearLayout(this);
        column.setOrientation(LinearLayout.VERTICAL);
        column.setPadding(pad, pad * 3, pad, pad);

        status = new TextView(this);
        status.setTextSize(16);
        column.addView(status);

        TextView key = new TextView(this);
        key.setTextIsSelectable(true);
        key.setTypeface(android.graphics.Typeface.MONOSPACE);
        key.setPadding(0, pad, 0, pad);
        column.addView(key);

        Button copy = new Button(this);
        copy.setText("复制公钥");
        copy.setOnClickListener(v -> {
            getSystemService(ClipboardManager.class)
                    .setPrimaryClip(ClipData.newPlainText("tap-unlock public key", publicKeyPem));
            Toast.makeText(this, "已复制", Toast.LENGTH_SHORT).show();
        });
        column.addView(copy);

        Button share = new Button(this);
        share.setText("分享公钥");
        share.setOnClickListener(v -> startActivity(Intent.createChooser(
                new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, publicKeyPem),
                "分享公钥")));
        column.addView(share);

        Button test = new Button(this);
        test.setText("不用贴片，直接发送一次");
        test.setOnClickListener(v -> startActivity(new Intent(this, TapActivity.class)));
        column.addView(test);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(column, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        setContentView(scroll);

        try {
            publicKeyPem = Keys.pem(Keys.ensure());
            key.setText(publicKeyPem);
        } catch (Exception e) {
            key.setText("生成密钥失败：" + e);
        }
        requestPermissions(new String[]{
                Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_ADVERTISE}, REQUEST_BLUETOOTH);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshStatus();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        refreshStatus();
    }

    private void refreshStatus() {
        boolean bluetooth = checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN) == PackageManager.PERMISSION_GRANTED
                && checkSelfPermission(Manifest.permission.BLUETOOTH_ADVERTISE) == PackageManager.PERMISSION_GRANTED;
        NfcAdapter nfc = NfcAdapter.getDefaultAdapter(this);
        status.setText("蓝牙权限：" + (bluetooth ? "已授予" : "未授予")
                + "\nNFC：" + (nfc == null ? "不支持" : nfc.isEnabled() ? "已开启" : "未开启")
                + "\n\n把下面的公钥放到电脑 /etc/tap-unlock/keys/ 下（.pem 结尾）。"
                + "\n\n贴片依次写入两条记录（顺序不能反）："
                + "\n1. URI：nekotype://unlock"
                + "\n2. 应用程序记录（AAR）：" + getPackageName()
                + "\n只写 URI 时系统会先弹窗确认，加上 AAR 后直接打开。");
    }
}
