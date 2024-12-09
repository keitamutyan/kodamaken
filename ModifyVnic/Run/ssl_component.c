#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

void InitializeSSL(){
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
}

void DestroySSL(){
  ERR_free_strings();
  EVP_cleanup();
}

void ShutdownSSL(SSL *ssl){
  SSL_shutdown(ssl);
  SSL_free(ssl);
}
