#!/usr/bin/env bash
# paypal production mitm on a rooted phone. gets com.paypal.android.p2pmobile traffic
# (incl. api-m.paypal.com) decrypting in burp.
#
# the catch on this build: the thales tap-to-pay sdk has anti-frida that kills the gadget
# ~4s after it loads at startup. we inject the gadget late instead, AFTER you tap past the
# "use browser" startup gate by hand. thales only checks at startup, so a late gadget lives.
#
#   ./mitm.sh login          # proxy + gadget off, so you can sign in
#   ./mitm.sh go             # late-inject + unpin + proxy on
#   ./mitm.sh rst            # rst direct sockets so api-m stops clinging to a direct conn
#
# device-agnostic. override anything with env vars or the second arg:
#   BURP=10.0.0.5:8080 ./mitm.sh go        # or:  ./mitm.sh go 10.0.0.5:8080
#   DELAY=15000 ./mitm.sh go               # bump the dodge window on a slow device
#   ANDROID_SERIAL=<serial> ./mitm.sh go   # pick a device when several are attached
#   GADGET=/path/to/stealth-gadget.so ./mitm.sh go
#
# one-time setup is in README.md.
#
# IMPORTANT (learned the hard way, 2026-07-05):
#  - the WiFi network must have Proxy=None. this script drives the proxy via adb
#    `settings global http_proxy`; a proxy ALSO set at the WiFi-network level fights that and
#    leaves the app with "no internet".
#  - the gadget is staged in /data/local/tmp/re.zyg.fri and listens on :47000. newer PayPal
#    installs get per-app SELinux MLS categories on their app_data_file that block even root
#    from writing the gadget into /data/data/<pkg>/files, so we stage under /data/local/tmp.
#  - `rst` uses `su -mm` (mount-master ns) or iptables can't see the netfilter tables.

set -uo pipefail
pkg=com.paypal.android.p2pmobile
appdir=/data/data/$pkg
here="$(cd "$(dirname "$0")" && pwd)"

burp="${BURP:-${2:-192.168.1.88:8888}}"   # your burp listener (lan ip), override freely
port="${PORT:-47000}"                      # gadget listens here (matches libgadget.config.so)
delay="${DELAY:-12000}"                    # inject this many ms in, after you dodge the gate
ssl="$here/frida/paypal-ssl-killer.js"
apim="$here/frida/apim-trust.js"

su(){ adb shell su -c "$*"; }
sum(){ adb shell su -mm -c "$*"; }   # mount-master ns: required for iptables/netfilter under magisk
zdir=/data/local/tmp/re.zyg.fri      # zygiskfrida watch dir; gadget staged HERE (app data dir now MLS-blocks root writes)
note(){ printf '\n>> %s\n' "$*"; }

# the gadget must match the frida cli version. find stealth-gadget-<ver>.so for the installed frida.
pick_gadget(){
  local fv g
  fv="$(frida --version 2>/dev/null)"
  g="${GADGET:-$here/stealth-gadget-$fv.so}"
  if [ -f "$g" ]; then echo "$g"; return; fi
  g="$(ls "$here"/stealth-gadget-*.so 2>/dev/null | head -1)"
  if [ -z "$g" ]; then
    echo "no stealth gadget in $here" >&2
    echo "build one for your frida ($fv): python3 tools/make_stealth_gadget.py frida-gadget-$fv-android-arm64.so stealth-gadget-$fv.so" >&2
    exit 1
  fi
  case "$g" in
    *"-$fv.so") ;;
    *) echo "WARN: frida cli is $fv but the gadget is $(basename "$g"). they must match." >&2
       echo "      fix: pip install frida==<gadget version>, or build a $fv gadget." >&2 ;;
  esac
  echo "$g"
}

push_config(){ # $1 = true|false
  printf '{ "targets": [ { "app_name": "%s", "enabled": %s, "start_up_delay_ms": %s, "injected_libraries": [ { "path": "%s/libgadget.so" } ], "child_gating": { "enabled": false, "mode": "freeze", "injected_libraries": [] } } ] }' \
    "$pkg" "$1" "$delay" "$zdir" > /tmp/_zf.json
  adb push /tmp/_zf.json /data/local/tmp/_zf.json >/dev/null
  su "cp /data/local/tmp/_zf.json $zdir/config.json"
}

stage_gadget(){
  local g; g="$(pick_gadget)" || exit 1
  echo "gadget: $(basename "$g")"
  adb push "$g" /data/local/tmp/_g.so >/dev/null
  printf '{ "interaction": { "type": "listen", "address": "127.0.0.1", "port": %s, "on_load": "resume" } }' "$port" > /tmp/_g.config.so
  adb push /tmp/_g.config.so /data/local/tmp/_g.config.so >/dev/null
  # stage into the zygiskfrida watch dir, NOT the app's data dir. newer installs get per-app
  # SELinux MLS categories on app_data_file that block even root (magisk:s0) from writing content
  # there; /data/local/tmp has no such block and the injector reads it in its privileged
  # (pre-app-domain) context. label it system_file to match the working June setup.
  su "mkdir -p $zdir;
      cp /data/local/tmp/_g.so $zdir/libgadget.so;
      cp /data/local/tmp/_g.config.so $zdir/libgadget.config.so;
      chmod 644 $zdir/libgadget.so $zdir/libgadget.config.so;
      chcon u:object_r:system_file:s0 $zdir/libgadget.so $zdir/libgadget.config.so 2>/dev/null"
}

adb get-state >/dev/null 2>&1 || { echo "no adb device. connect one (or set ANDROID_SERIAL)."; exit 1; }

case "${1:-}" in
login)
  note "clean state for sign-in (proxy off, gadget off)"
  adb shell settings put global http_proxy :0 >/dev/null
  push_config false
  su "am force-stop $pkg"
  echo "open paypal and sign in. if the 'use browser' window shows, tap into a feature to get past it."
  echo "once you're in, run: ./mitm.sh go"
  ;;
go)
  command -v frida >/dev/null || { echo "frida cli not on PATH (pip install frida-tools)"; exit 1; }
  echo "frida cli: $(frida --version)"
  note "staging stealth gadget + enabling late injection (${delay}ms)"
  stage_gadget
  push_config true
  adb shell settings put global http_proxy :0 >/dev/null
  su "am force-stop $pkg"
  cat <<EOF

  on the phone now:
   1. open paypal (lands on home, session is saved)
   2. immediately tap into a feature to dodge the "use browser" window
   3. keep tapping around, stay in the app
  the gadget injects at +$((delay/1000))s, after you've dodged the gate, so it survives.

EOF
  adb forward tcp:$port tcp:$port >/dev/null 2>&1
  note "waiting for the gadget on :$port ..."
  up=
  for i in $(seq 1 40); do frida-ps -H 127.0.0.1:$port >/dev/null 2>&1 && { up=1; break; }; sleep 1; done
  [ -n "$up" ] || { echo "gadget never came up. crashed before you dodged? re-run ./mitm.sh go"; exit 1; }
  note "gadget up. proxy -> $burp. attaching unpinner"
  adb shell settings put global http_proxy "$burp" >/dev/null
  echo
  echo "navigate the app -> api-m.paypal.com decrypts in burp."
  echo "api-m only fires on real actions (pull-to-refresh, open a transaction), not cached screens."
  echo "if api-m hides on a direct connection, run ./mitm.sh rst in another terminal."
  echo "if capture stops (rasp closes the gadget connection), re-run ./mitm.sh go."
  echo
  exec frida -H 127.0.0.1:$port Gadget -l "$ssl" -l "$apim"
  ;;
rst)
  note "rst direct :443 sockets (re-route reused connections through burp)"
  sum "iptables -I OUTPUT -p tcp --dport 443 -j REJECT --reject-with tcp-reset; sleep 2; iptables -D OUTPUT -p tcp --dport 443 -j REJECT --reject-with tcp-reset"
  echo "done. pull-to-refresh in the app and api-m should appear in burp."
  ;;
*)
  echo "usage: $0 {login|go|rst} [burp_ip:port]"
  echo "  login          proxy + gadget off, sign in on the phone"
  echo "  go [ip:port]   late-inject + unpin + proxy on (default 192.168.1.88:8888)"
  echo "  rst            rst direct sockets so api-m re-routes through burp"
  echo
  echo "env overrides: BURP=ip:port  PORT=47000  DELAY=12000  GADGET=/path/to.so  ANDROID_SERIAL=serial"
  exit 1
  ;;
esac
