// hide frida/root from the app's own scans. load first.
// strstr/strcmp/fopen(/proc/maps)/ptrace natively + a few java su-path checks.
// only safe at spawn - the native libc hooks can crash if installed mid-run.
'use strict';
var TAG = '[anti-detect] ';
function log(m) { console.log(TAG + m); }

// Frida-17-safe export resolver (works on 16 and 17).
function findExp(modName, sym) {
  try { if (typeof Module.findExportByName === 'function') { var a = Module.findExportByName(modName, sym); if (a) return a; } } catch (e) {}
  try {
    if (modName && typeof Process.findModuleByName === 'function') {
      var m = Process.findModuleByName(modName);
      if (m && typeof m.findExportByName === 'function') { var b = m.findExportByName(sym); if (b) return b; }
    }
  } catch (e) {}
  try { if (typeof Module.findGlobalExportByName === 'function') { var c = Module.findGlobalExportByName(sym); if (c) return c; } } catch (e) {}
  try { if (typeof Module.getGlobalExportByName === 'function') return Module.getGlobalExportByName(sym); } catch (e) {}
  return null;
}

// 0a) PRODUCTION RASP-in-ContentProviders (NO whack-a-mole). DexGuard injects an emulator check into many
//     providers' onCreate that throws RuntimeException(<numeric verdict>, e.g. 254448920) during
//     installContentProviders -> app dies on the MAIN thread. (Hooking ContentProvider.attachInfo fails - the
//     provider overrides attachInfo + calls super, and frida doesn't intercept invoke-super.) Instead hook the
//     FRAMEWORK android.app.ActivityThread.installProvider (a normal method, zygote-loaded, reliably hooked) -
//     it wraps each provider's attachInfo and rethrows "Unable to get provider ..." on failure. Catch that and
//     return null -> installContentProviders simply skips the poisoned provider -> app boots. One hook, all.
Java.perform(function () {
  function isProviderRasp(e) {
    try {
      var m = e.getMessage();
      if (m !== null && ('' + m).indexOf('Unable to get provider') >= 0) return true;
      var c = (e.getCause ? e.getCause() : null);
      if (c) { var cm = c.getMessage(); if (cm !== null && /^\d{5,}$/.test('' + cm)) return true; }
    } catch (x) {}
    return false;
  }
  try {
    var AT = Java.use('android.app.ActivityThread');
    AT.installProvider.overloads.forEach(function (ov) {
      ov.implementation = function () {
        try { return this.installProvider.apply(this, arguments); }
        catch (e) {
          if (isProviderRasp(e)) { console.log(TAG + 'skipped RASP-poisoned provider (' + e.getMessage() + ')'); return null; }
          throw e;
        }
      };
    });
    log('ActivityThread.installProvider wrapped - RASP provider-skip guard (one hook covers all providers)');
  } catch (e) { log('installProvider guard err: ' + e); }
});

// 0) EARLIEST: swallow PayPal's startup integrity-verifier crash. AppVerifierInitializer launches a
//    coroutine on Dispatchers.IO that throws RuntimeException(<code>) when it dislikes the environment
//    (emulator) -> uncaught -> app dies. It runs too early for method hooks to reliably beat, so install
//    a custom default uncaught-exception handler that drops ONLY that crash and delegates everything else.
//    Installed first (anti-detect loads first) to maximize the chance it's set before the verifier throws.
Java.perform(function () {
  try {
    var T = Java.use('java.lang.Thread');
    var prev = T.getDefaultUncaughtExceptionHandler();
    var UEH = Java.registerClass({
      name: 'org.bypass.AppVerifierUEH',
      implements: [Java.use('java.lang.Thread$UncaughtExceptionHandler')],
      methods: {
        uncaughtException: function (thr, ex) {
          try {
            var fr = ex.getStackTrace();
            for (var i = 0; i < fr.length; i++) {
              if (('' + fr[i].getClassName()).indexOf('AppVerifierInitializer') >= 0) {
                console.log(TAG + 'swallowed AppVerifier crash: ' + ex.toString());
                return;
              }
            }
          } catch (e) {}
          if (prev) { try { prev.uncaughtException(thr, ex); } catch (e) {} }
        }
      }
    });
    T.setDefaultUncaughtExceptionHandler(UEH.$new());
    log('default uncaught-exception handler installed (AppVerifier crash backstop)');
  } catch (e) { log('UEH install err: ' + e); }
});

// 1) Native string probes: strstr -> NULL(0)="not found"; strcmp/strcasecmp -> 1="not equal".
var TOKENS = ['frida', 'gum-js-loop', 'gmain', 'linjector', 'frida-server', 'frida-agent',
              're.frida', '/data/local/tmp', 'magisk', 'supersu', 'xposed', 'libfrida'];
[['strstr', ptr(0)], ['strcmp', ptr(1)], ['strcasecmp', ptr(1)]].forEach(function (entry) {
  var sym = entry[0], safeRet = entry[1];
  var p = findExp('libc.so', sym) || findExp(null, sym);
  if (!p) return;
  try {
    Interceptor.attach(p, {
      onEnter: function (a) {
        try {
          var hay = a[0].readCString(), nee = a[1].readCString();
          var s = ((hay || '') + ' ' + (nee || '')).toLowerCase();
          for (var i = 0; i < TOKENS.length; i++) {
            if (s.indexOf(TOKENS[i]) >= 0) { this.spoof = true; break; }
          }
        } catch (e) {}
      },
      onLeave: function (r) { if (this.spoof) r.replace(safeRet); }
    });
  } catch (e) {}
});

// 2) fopen on /proc maps|status (RASP scans for frida ranges) -> /dev/null
var fopen = findExp('libc.so', 'fopen') || findExp(null, 'fopen');
if (fopen) {
  try {
    Interceptor.attach(fopen, {
      onEnter: function (a) {
        try {
          var path = a[0].readCString() || '';
          if (path.indexOf('/proc/') >= 0 && (path.indexOf('maps') >= 0 || path.indexOf('status') >= 0)) {
            this.redir = Memory.allocUtf8String('/dev/null');
            a[0] = this.redir;
          }
        } catch (e) {}
      }
    });
    log('fopen /proc maps|status -> /dev/null');
  } catch (e) {}
}

// 3) ptrace(PTRACE_TRACEME) anti-debug -> no-op success
var ptrace = findExp(null, 'ptrace');
if (ptrace) {
  try {
    Interceptor.replace(ptrace, new NativeCallback(function () { return 0; }, 'long',
      ['int', 'int', 'pointer', 'pointer']));
    log('ptrace neutralized');
  } catch (e) {}
}

// 4) Java-side su-path probes
Java.perform(function () {
  try {
    var F = Java.use('java.io.File');
    var paths = ['/system/bin/su', '/system/xbin/su', '/sbin/su', '/su/bin/su',
                 '/data/local/tmp/frida-server', '/system/app/Superuser.apk'];
    F.exists.implementation = function () {
      try { var p = this.getAbsolutePath(); if (paths.indexOf(p) >= 0) return false; } catch (e) {}
      return this.exists.call(this);
    };
    log('java File.exists su-path probes spoofed');
  } catch (e) {}
});

log('starter anti-detection installed.');
