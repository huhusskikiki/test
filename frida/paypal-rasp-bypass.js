// kill paypal's RASP verdicts (sspog) + 3ds SecurityCheck on the main process.
// sspog runs its checks in isolated processes and the app reads the verdict over
// AIDL, so we force the verdict methods to "clean" where the app acts on them.
// load before the ssl killer.
'use strict';
var TAG = '[rasp] ';
function log(m) { console.log(TAG + m); }

/* ---- classify a threat method name -> the SAFE boolean to force ---- */
// "detected/present/attached/rooted/hooked" => false ; "integrity/ok/trusted/valid" => true
var BAD = /(magisk|frida|hook|root|tamper|debugg|emulat|xposed|cydia|substrate|riru|zygisk|jailbreak|instrument|injected|patched|repackag)/i;
var GOOD = /(integrity|trusted|verified|valid|genuine|secure)/i;
var IS_PRED = /^(is|has|check|detect|verify|are|should)/i;
function safeValueFor(method) {
  if (GOOD.test(method) && !BAD.test(method)) return true;   // isBasicIntegrity -> true
  return false;                                              // isMagiskDetected -> false
}

Java.perform(function () {

  /* 1a) EXPLICIT detection-class hooks (safe per-class reflection). Replaces the whole-app
   *     Java.enumerateMethods scan below, which SIGSEGV'd in gum-js-loop at the gadget's very-early
   *     injection point (ART still initializing). These are the real detectors seen in this build. */
  [['com.paypal.android.p2pmobile.common.app.HookDetectionHandler', /hook/i],
   ['com.paypal.android.p2pmobile.common.app.RootDetectionHandler', /root/i],
   ['com.paypal.lighthouse.fpti.helper.SendEventHelper', /emulator/i],
   ['com.paypal.lighthouse.utility.DeviceInfo', /emulator|root/i],
   ['com.paypal.android.p2pmobile.instore.fi.InStoreFISetUpInitArgs', /root/i],
   ['com.paypal.android.p2pmobile.instore.fi.InstoreFISetup', /root/i],
   ['com.paypal.android.p2pmobile.qrcode.Qrcode', /root/i]
  ].forEach(function (d) {
    try {
      var C = Java.use(d[0]);
      C.class.getDeclaredMethods().forEach(function (jm) {
        var mn = jm.getName();
        if (!d[1].test(mn)) return;
        try {
          C[mn].overloads.forEach(function (ov) {
            if (ov.returnType && ov.returnType.className === 'boolean')
              ov.implementation = function () { return false; };
          });
          log('detector ' + d[0].substring(d[0].lastIndexOf('.') + 1) + '.' + mn + ' -> false');
        } catch (e) {}
      });
    } catch (e) {}
  });

  /* 1) OBFUSCATION-RESISTANT: scan loaded app classes for boolean threat methods by NAME */
  // PRECISE detection patterns. Broad ones (*Hook*, *isRoot*, *Tamper*, *Integrity*, *Instrument*)
  // matched framework methods (ConstraintWidget.isRoot, Node.isRoot, kotlin FqName.isRoot,
  // Firebase CycleDetector.isRoot, Play-Integrity, FundingInstrument) - forcing those CRASHED the app.
  var patterns = ['*!*Magisk*/u', '*!*Frida*/u', '*!*Xposed*/u', '*!*RootDetect*/u',
                  '*!*isDeviceRooted*/u', '*!*isRooted*/u', '*!*HookDetect*/u',
                  '*!*isDebuggerAttached*/u', '*!*isEmulator*/u', '*!*EmulatorDetect*/u',
                  '*!*isProbablyAnEmulator*/u'];
  // Never override methods on framework/runtime classes - they use isRoot()/etc. for unrelated reasons.
  var SKIP_PKG = /^(kotlin|kotlinx|java\.|javax\.|android\.|androidx|com\.google|com\.android|dalvik|sun\.|org\.chromium|org\.json|okhttp|okio|retrofit)/;
  // Deferred to the next tick: enumerateMethods over every app class is slow and would otherwise
  // exceed the gadget's script-load timeout. setTimeout(0) lets load finish; the scan runs right after.
  // The explicit AIDL/SecurityCheck/sspog hooks below stay synchronous so they install immediately.
  setTimeout(function () {
  var hooked = {}, nOverridden = 0;
  patterns.forEach(function (q) {
    var groups = [];  // DISABLED: Java.enumerateMethods SIGSEGV'd in gum-js-loop at early gadget inject.
    // (Explicit detector hooks above cover the real checks; whole-app enumeration is unsafe this early.)
    (groups || []).forEach(function (g) {
      // use the group's own classloader so DexGuard app classes resolve reliably
      var factory;
      try { factory = g.loader ? Java.ClassFactory.get(g.loader) : Java; } catch (e) { factory = Java; }
      (g.classes || []).forEach(function (cls) {
        if (SKIP_PKG.test(cls.name)) return;   // skip framework/runtime classes (crash guard)
        (cls.methods || []).forEach(function (mname) {
          var key = cls.name + '.' + mname;
          if (hooked[key]) return;
          try {
            var C = factory.use(cls.name);
            if (!C[mname]) return;
            hooked[key] = true;
            var did = false;
            C[mname].overloads.forEach(function (ov) {
              // only override boolean predicates; skip logic/getter methods entirely
              var rt = ov.returnType && ov.returnType.className;
              if (rt !== 'boolean') return;
              if (!IS_PRED.test(mname)) return;
              var val = safeValueFor(mname);
              ov.implementation = function () { return val; };
              did = true;
            });
            if (did) { nOverridden++; log('neutralized ' + key + ' -> ' + safeValueFor(mname)); }
          } catch (e) {}
        });
      });
    });
  });
  log('threat method-name scan complete (' + nOverridden + ' booleans overridden)');
  }, 0);

  /* 2) EXPLICIT sspog verdict surface (main-side) */
  // native magisk check, if ever invoked in this process
  try {
    var NS = Java.use('sspog.internal.SSPOGIsolatedNativeService');
    ['isMagiskPresentNative', 'isMagiskNativelyDetected'].forEach(function (m) {
      if (NS[m]) NS[m].overloads.forEach(function (ov) { ov.implementation = function () { return false; }; });
    });
    log('sspog.SSPOGIsolatedNativeService magisk checks -> false');
  } catch (e) {}
  // AIDL verdicts - EXPLICIT, validated against decompiled interface (single boolean method each):
  //   IIsolatedNativeVerifyingProcess.isMagiskNativelyDetected()Z
  //   IIsolatedVerifyingProcess.isMagiskDetected()Z
  // Hook the $Stub$Proxy (what the main process holds) so the Binder transact to the
  // isolated process is short-circuited and the verdict is always "clean".
  [['sspog.internal.IIsolatedNativeVerifyingProcess$Stub$Proxy', 'isMagiskNativelyDetected'],
   ['sspog.internal.IIsolatedVerifyingProcess$Stub$Proxy', 'isMagiskDetected']
  ].forEach(function (pair) {
    try {
      var C = Java.use(pair[0]);
      C[pair[1]].implementation = function () { return false; };
      log('AIDL verdict ' + pair[0].split('.').pop() + '.' + pair[1] + ' -> false');
    } catch (e) {}
  });
  // ...and a reflective sweep as backstop (covers any extra boolean verdicts added later)
  ['sspog.internal.IIsolatedNativeVerifyingProcess$Stub$Proxy',
   'sspog.internal.IIsolatedVerifyingProcess$Stub$Proxy'].forEach(function (cn) {
    try {
      var P = Java.use(cn);
      P.class.getDeclaredMethods().forEach(function (jm) {
        var mn = jm.getName();
        try {
          P[mn].overloads.forEach(function (ov) {
            if (ov.returnType && ov.returnType.className === 'boolean')
              ov.implementation = function () { return false; };
          });
        } catch (e) {}
      });
      log('AIDL proxy boolean verdicts -> false: ' + cn);
    } catch (e) {}
  });

  /* 3) 3DS SecurityCheck */
  try {
    var SC = Java.use('com.paypal.android.threeds.security.SecurityCheck');
    SC.class.getDeclaredMethods().forEach(function (jm) {
      var mn = jm.getName();
      try {
        SC[mn].overloads.forEach(function (ov) {
          if (ov.returnType && ov.returnType.className === 'boolean' && IS_PRED.test(mn))
            ov.implementation = function () { return safeValueFor(mn); };
        });
      } catch (e) {}
    });
    log('threeds SecurityCheck booleans neutralized');
  } catch (e) {}

  /* 4) Common platform debugger checks */
  try {
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function () { return false; };
  } catch (e) {}
  try {
    var AppInfo = Java.use('android.content.pm.ApplicationInfo');
    // some checks read FLAG_DEBUGGABLE on self; leave app's real flag, this is just a guard
  } catch (e) {}

  log('RASP verdict bypass installed (main process).');
});

/* ---- 5) NATIVE: if running IN / attached to the native isolated process, kill the magisk export ---- */
try {
  var sym = Module.findExportByName('libzfcddc.so',
              'Java_sspog_internal_SSPOGIsolatedNativeService_isMagiskPresentNative');
  if (sym) {
    // JNI signature: jboolean (*)(JNIEnv*, jobject)  -> return JNI_FALSE (0)
    Interceptor.replace(sym, new NativeCallback(function () { return 0; }, 'int', ['pointer', 'pointer']));
    log('native isMagiskPresentNative -> JNI_FALSE (in this process)');
  }
} catch (e) {}
