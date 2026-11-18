# Tap Unlock

用手机碰一下 NFC 贴片，就能解锁 Linux 桌面的锁屏，或者放行一次 sudo / pkexec。
手机和电脑之间只走 BLE 广播，不需要 Wi-Fi、网络，也不需要配对。

## 工作原理

1. 电脑处于锁屏状态，或者有 sudo / pkexec 正在等待认证时，守护进程 `tapunlockd` 会做两件事：
   用 BLE 广播一个 16 字节的随机挑战值（每 100 ms 一次，每 30 秒换一次），同时开启 LE 扫描。
2. 贴片里写的是 `nekotype://unlock`。手机碰到贴片后，系统直接拉起 App。App 扫描到挑战值，
   用 Android Keystore 里的 P-256 私钥对 `"tap-unlock/v1\0" || nonce` 做 ECDSA-SHA256 签名，
   再用扩展广播把签名发出去，持续 3 秒。
3. 电脑用 `/etc/tap-unlock/keys/*.pem` 里的公钥验签。验签通过后：
   - 如果在锁屏：调用 logind `UnlockSession`；
   - 如果正好只有一个 sudo / pkexec 在等待：放行它；
   - 如果同时有多个在等待：全部拒绝，各自回到输入密码。

### 防重放

电脑只接受针对**它当前正在广播的随机数**的签名，而且一个随机数一旦验签成功就立即作废。
所以抓下来的响应包没法再用第二次。上一个随机数在换新之后只保留 5 秒宽限期，
超过宽限期、或者守护进程重启之后，旧响应一律无效。

### 帧格式（manufacturer data，company ID 0xFFFF）

| 方向 | 内容 |
|---|---|
| 电脑 → 手机（传统广播） | `"NK"` `01` `01` `nonce[16]` |
| 手机 → 电脑（扩展广播） | `"NK"` `01` `02` `nonce[0:4]` `DER 签名` |

## 安全边界

- 守护进程以无特权的系统用户 `tapunlock` 运行，带 systemd 沙箱（只允许 AF_UNIX 套接字，没有任何 capability）。
  解锁屏幕的权限由一条 polkit 规则单独授予这个用户。
- PAM 那一行是 `sufficient` + 自带的 `pam_tapunlock.so`：它在等手机的同时就弹出密码提示，
  先贴手机就直接放行，先输完密码就交给后面的 `pam_unix` 照常校验（失败计数照旧）。
  守护进程的套接字只接受 uid 0 的连接，模块也只认 `tapunlock` 用户开的套接字，
  普通进程无法伪造认证请求或放行结果。守护进程没运行、蓝牙关闭或者超时，都只剩密码这一条路。
- 锁屏状态下碰手机只会解锁屏幕，不会顺带放行任何 sudo / pkexec。
- 私钥生成在手机的 TEE 里，不能导出（`setUnlockedDeviceRequired`），电脑上只存公钥。
- 不能防的情况：手机丢失并且已被解锁；有人在你本人碰贴片的同时做实时中继。

## 电脑端安装

依赖：`python`、`python-dbus`、`python-gobject`、`python-cryptography`、`bluez`、`polkit`，
以及编译 PAM 模块用的 `gcc` 和 `pam`（头文件）。

```sh
sudo ./install.sh <桌面用户名>
# 把手机 App 里复制的公钥存成 .pem 文件
wl-paste | sudo tee /etc/tap-unlock/keys/phone.pem
```

`/etc/tap-unlock/tap-unlock.conf` 里可以改等待手机的时间（`TAPUNLOCK_WAIT`，默认 20 秒；
只影响手机这一路，密码随时可以输）。
卸载用 `sudo ./uninstall.sh`。

## 手机 App

```sh
android/build.sh        # 需要 Android SDK build-tools + platform，输出 android/build/tap-unlock.apk
```

- 要求 Android 12 及以上，手机需要支持 NFC 和 LE 扩展广播。
- 第一次打开时授予「附近设备」权限，然后复制或分享公钥。
- 用 NFC Tools 之类的工具往贴片依次写入两条记录，顺序不能反：
  1. URI 记录：`nekotype://unlock`；
  2. 应用程序记录（AAR，`android.com:pkg`）：`xyz.bohesama.tapunlock`。

  只写 URI 时，系统的 NFC 服务会先弹窗问「是否打开应用处理卡片」（HyperOS、Android 15 及以上都会这样）。
  有了 AAR，系统就跳过确认直接拉起 App。两条记录在 NTAG213 及以上的贴片里都放得下。
- 签名 keystore 会自动生成在 `~/.android/tap-unlock.jks`，不进 git。

## 测试

```sh
python3 -m unittest discover -s tests
```
