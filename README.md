# paypal android prod mitm

Decrypt `com.paypal.android.p2pmobile` 8.107.0 traffic (including `api-m.paypal.com`) in Burp on a
rooted device. Tested on a OnePlus 6T, Android 10.

## how it works

Frida can't attach (the app runs a self-ptrace watchdog), so the gadget goes in-process via Zygisk.
The app's RASP scans `/proc/self/task/*/comm` for Frida's thread names, so the gadget's threads are
renamed (stealth gadget). A Tap-to-Pay payment SDK (Thales) kills the gadget ~4s after a startup
inject, so injection is delayed 12s and you tap past the "use browser" gate by hand in that window.
Root/hook detection is handled with the Magisk DenyList + Shamiko. Then `ssl-killer` unpins
OkHttp/TrustKit/Conscrypt and Burp's CA goes in as a system CA. Re-signing/static patching does not
work (DexGuard tamper check kills a re-signed APK at startup), so this is all runtime - nothing on
disk is modified.

## one-time setup

1. Magisk + Zygisk + Shamiko. Deny root to all of the app's processes.
2. ZygiskFrida (lico-n), patched so it stops remapping the gadget:
   ```
   python3 tools/patch_zygiskfrida_remap.py <module>/zygisk/arm64-v8a.so out.so
   ```
   Replace the module's `zygisk/arm64-v8a.so` with `out.so`, reboot.
3. Burp CA as a system CA:
   ```
   openssl x509 -inform der -subject_hash_old -in burp.der | head -1   # -> e.g. 9a5ba575
   ```
   Drop `9a5ba575.0` (the pem is here) into `/system/etc/security/cacerts` via a Magisk cacerts overlay.
4. Match Frida to the gadget: `pip install frida==17.9.8` (the gadget here is 17.9.8). For a different
   Frida, build a matching gadget:
   ```
   python3 tools/make_stealth_gadget.py frida-gadget-<ver>-android-arm64.so stealth-gadget-<ver>.so
   ```
5. Burp listening on your LAN IP, phone on the same network. Set the WiFi network's **Proxy to
   None** - this script drives the proxy over adb (`settings global http_proxy`); a proxy also set
   at the WiFi-network level fights that and leaves the app with "no internet".

## run

```
./mitm.sh login          # proxy + gadget off, sign in on the phone
./mitm.sh go [ip:port]   # late-inject + unpin + proxy on (default 192.168.1.88:8888)
./mitm.sh rst            # rst direct sockets if api-m clings to a direct connection
```

`go` stages the gadget, turns on 12s late injection, and stops the app. Open PayPal, tap into a
feature fast to dodge the "use browser" window, and at 12s the gadget injects, the unpinner attaches,
and the proxy flips to Burp. `api-m` only fires on real actions (pull-to-refresh, opening a
transaction), not on cached screens.

Override with env vars: `BURP=ip:port DELAY=12000 ANDROID_SERIAL=serial GADGET=/path/to.so`.

## notes

- Windowed: the RASP eventually drops the gadget connection (the app keeps running, Frida detaches). Re-run `go`.
- The magnes risk SDK uses its own pinned channel to a CDN and stays opaque.
- A `pm clear` or reinstall wipes the staged gadget; `go` re-stages it.
- The gadget is staged in `/data/local/tmp/re.zyg.fri/libgadget.so` and listens on **:47000**. Newer
  PayPal installs get per-app SELinux MLS categories on `app_data_file` that block even root from
  writing the gadget into `/data/data/<pkg>/files`, so it lives under `/data/local/tmp` instead.
- `rst` runs iptables via `su -mm` (mount-master namespace); plain `su -c` can't see the netfilter tables.

## files

```
mitm.sh                          login / go / rst
frida/paypal-ssl-killer.js       pinning bypass (OkHttp/TrustKit/Conscrypt/SSLContext)
frida/apim-trust.js              trust-all for the early api-m client
frida/paypal-anti-detect.js      native anti-detect (only for at-spawn injection)
frida/paypal-rasp-bypass.js      rasp verdict bypass
tools/make_stealth_gadget.py     rename frida thread names in a stock gadget
tools/patch_zygiskfrida_remap.py nop the gadget remap in zygiskfrida
stealth-gadget-17.9.8.so         prebuilt stealth gadget
burp.der / burp.pem / 9a5ba575.0 burp ca (der, pem, android system-cert hash)
```
