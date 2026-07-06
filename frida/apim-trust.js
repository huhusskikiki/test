// only needed if the proxy CA isn't a system CA.
// api-m's TLS client is built early and rejects the proxy cert at the CA-trust layer
// (TLS alert "certificate unknown"), separate from pinning. hook checkServerTrusted
// at class level so it accepts on the already-built instance, per handshake.
'use strict';
function log(m) { console.log('[apim] ' + m); }

Java.perform(function () {
  var Arrays = Java.use('java.util.Arrays');

  function accept(cn) {
    try {
      var C = Java.use(cn);
      if (!C.checkServerTrusted) return;
      C.checkServerTrusted.overloads.forEach(function (o) {
        var rt = (o.returnType && o.returnType.className) || 'void';
        o.implementation = function () {
          if (rt === 'java.util.List') { try { return Arrays.asList(arguments[0]); } catch (e) { return Arrays.asList([]); } }
          return; // void: just don't throw
        };
      });
      log(cn.split('.').pop());
    } catch (e) {}
  }

  ['com.android.org.conscrypt.TrustManagerImpl',
   'android.security.net.config.NetworkSecurityTrustManager',
   'android.security.net.config.RootTrustManager'].forEach(accept);

  try {
    var Ext = Java.use('android.net.http.X509TrustManagerExtensions');
    Ext.checkServerTrusted.overloads.forEach(function (o) { o.implementation = function () { try { return Arrays.asList(arguments[0]); } catch (e) { return Arrays.asList([]); } }; });
    log('X509TrustManagerExtensions');
  } catch (e) {}
});
