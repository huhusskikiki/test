// pinning bypass for com.paypal.android.p2pmobile
// trustkit + okhttp CertificatePinner + conscrypt + the app's own pin switches.
// load at spawn for emulator/beta, or attach to the gadget on a real device.
'use strict';
function log(m) { console.log('[ssl] ' + m); }

// resolve a class across all classloaders. paypal.oslo.* and the cronet transport
// live in their own loader so plain Java.use throws.
var loaders = null;
function use(name) {
  try { return Java.use(name); } catch (e) {}
  if (loaders === null) {
    loaders = [];
    Java.enumerateClassLoaders({ onMatch: function (l) { try { loaders.push(Java.ClassFactory.get(l)); } catch (e) {} }, onComplete: function () {} });
  }
  for (var i = 0; i < loaders.length; i++) { try { return loaders[i].use(name); } catch (e) {} }
  return null;
}

Java.perform(function () {

  // permissive trustmanager for any new SSLContext
  try {
    var TM = Java.registerClass({
      name: 'org.bypass.TrustAll',
      implements: [Java.use('javax.net.ssl.X509TrustManager')],
      methods: {
        checkClientTrusted: function () {},
        checkServerTrusted: function () {},
        getAcceptedIssuers: function () { return Java.array('java.security.cert.X509Certificate', []); }
      }
    });
    var Ctx = Java.use('javax.net.ssl.SSLContext');
    var init = Ctx.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
    init.implementation = function (km, tm, sr) { init.call(this, km, [TM.$new()], sr); };
    log('SSLContext.init');
  } catch (e) {}

  // okhttp. the connection path goes through check$okhttp, not just check()
  try {
    var CP = Java.use('okhttp3.CertificatePinner');
    CP.check.overloads.forEach(function (o) { o.implementation = function () {}; });
    if (CP['check$okhttp']) CP['check$okhttp'].overloads.forEach(function (o) { o.implementation = function () {}; });
    log('okhttp CertificatePinner');
  } catch (e) {}

  // trustkit
  ['com.datatheorem.android.trustkit.pinning.PinningTrustManager',
   'com.datatheorem.android.trustkit.pinning.OkHttpRootTrustManager'].forEach(function (cn) {
    try {
      var C = Java.use(cn);
      C.checkServerTrusted.overloads.forEach(function (o) { o.implementation = function () {}; });
      log('trustkit ' + cn.split('.').pop());
    } catch (e) {}
  });

  // conscrypt (also covers the NSC pin-set)
  try {
    var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    if (TMI.verifyChain) TMI.verifyChain.overloads.forEach(function (o) { o.implementation = function () { return arguments[0]; }; });
    if (TMI.checkTrustedRecursive) TMI.checkTrustedRecursive.overloads.forEach(function (o) { o.implementation = function () { return Java.use('java.util.ArrayList').$new(); }; });
    log('conscrypt TrustManagerImpl');
  } catch (e) {}

  // stop cronet pins being registered at all
  ['org.chromium.net.CronetEngine$Builder', 'org.chromium.net.ExperimentalCronetEngine$Builder'].forEach(function (cn) {
    try {
      var B = Java.use(cn);
      if (B.addPublicKeyPins) B.addPublicKeyPins.overloads.forEach(function (o) { o.implementation = function () { return this; }; });
      if (B.setExperimentalOptions) B.setExperimentalOptions.implementation = function () { return this; };
    } catch (e) {}
  });

  // paypal's own pin store
  try {
    var P = use('com.paypal.oslo.core.network.http.CertificatePins');
    if (P && P.getALL_PINS) { P.getALL_PINS.implementation = function () { return Java.use('java.util.Collections').emptySet(); }; log('CertificatePins -> empty'); }
  } catch (e) {}

  // startup verifier throws RuntimeException on "non-genuine" env (emulator). kill the coroutine + launcher.
  try {
    var AVI = use('com.paypal.oslo.core.startup.AppVerifierInitializer');
    if (AVI && AVI.create) AVI.create.overloads.forEach(function (o) { o.implementation = function () { return null; }; });
    var AVI1 = use('com.paypal.oslo.core.startup.AppVerifierInitializer$create$1');
    if (AVI1 && AVI1.invokeSuspend) { var U = Java.use('kotlin.Unit').INSTANCE.value; AVI1.invokeSuspend.implementation = function () { return U; }; }
    log('AppVerifier off');
  } catch (e) {}

  // the app's own pinning toggles
  try {
    var AHC = use('com.paypal.oslo.app.config.AppHttpConfig');
    if (AHC && AHC.getPinSslCert) { AHC.getPinSslCert.implementation = function () { return false; }; log('AppHttpConfig.getPinSslCert -> false'); }
  } catch (e) {}
  try {
    var CF = use('com.paypal.oslo.core.network.http.cronet.CronetEngineFactoryImpl');
    if (CF && CF['configureSslPinning$http_release']) CF['configureSslPinning$http_release'].implementation = function () {};
    if (CF && CF.createEngine) CF.createEngine.overloads.forEach(function (o) {
      o.implementation = function (ctx, enablePin, verify, cache) { return o.call(this, ctx, false, false, cache); };
    });
    log('cronet factory pinning off');
  } catch (e) {}

  // beta (9.x) routes api-m through cronet's okhttp interceptor. force it to pass through to plain okhttp.
  // production 8.107 is okhttp-only so this just won't resolve there - that's fine.
  try {
    var CI = use('com.google.net.cronet.okhttptransport.CronetInterceptor');
    if (CI && CI.intercept) { CI.intercept.implementation = function (chain) { return chain.proceed(chain.request()); }; log('cronet interceptor -> passthrough'); }
  } catch (e) {}

  try {
    var OHV = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
    if (OHV.verify) OHV.verify.overloads.forEach(function (o) { if (o.returnType && o.returnType.className === 'boolean') o.implementation = function () { return true; }; });
  } catch (e) {}

  log('done');
});
