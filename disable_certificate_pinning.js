var SSL_CTX_set_custom_verify_symbol = Module.findExportByName('libboringssl.dylib', 'SSL_CTX_set_custom_verify');
var BORINGSSL_CONTEXT_set_verify_mode_symbol = Module.findExportByName('libboringssl.dylib', 'boringssl_context_set_verify_mode');

var SSL_VERIFY_NONE = 0;

if (SSL_CTX_set_custom_verify_symbol) {
  var SSL_CTX_set_custom_verify = new NativeFunction(SSL_CTX_set_custom_verify_symbol, 'void', ['pointer', 'int', 'pointer']);
  Interceptor.replace(
      SSL_CTX_set_custom_verify_symbol,
      new NativeCallback(function(ctx, mode, callback) {
        SSL_CTX_set_custom_verify(ctx, SSL_VERIFY_NONE, callback)
      }, 'void', ['pointer', 'int', 'pointer']));
}

if (BORINGSSL_CONTEXT_set_verify_mode_symbol) {
  var BORINGSSL_CONTEXT_set_verify_mode = new NativeFunction(BORINGSSL_CONTEXT_set_verify_mode_symbol, 'int', ['pointer', 'int']);
  Interceptor.replace(
      BORINGSSL_CONTEXT_set_verify_mode_symbol,
      new NativeCallback(function(context, mode) {
        return BORINGSSL_CONTEXT_set_verify_mode(context, SSL_VERIFY_NONE);
      }, 'int', ['pointer', 'int']));
}