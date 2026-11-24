#ifndef SDS_HTTP_RS_FFI_H
#define SDS_HTTP_RS_FFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SdsHttpServer SdsHttpServer;
typedef struct SdsHttpClient SdsHttpClient;
typedef struct SdsHttpResponseSender SdsHttpResponseSender;

typedef struct {
  uint8_t *data;
  size_t len;
  size_t cap;
} SdsHttpBytes;

typedef struct {
  const uint8_t *name;
  size_t name_len;
  const uint8_t *value;
  size_t value_len;
} SdsHttpHeaderRef;

typedef struct {
  SdsHttpBytes name;
  SdsHttpBytes value;
} SdsHttpHeaderOwned;

typedef struct {
  SdsHttpHeaderOwned *items;
  size_t len;
  size_t cap;
} SdsHttpHeaderVec;

typedef enum {
  SDS_HTTP_ERR_NONE = 0,
  SDS_HTTP_ERR_OPERATION_ABORTED = 1,
  SDS_HTTP_ERR_EOF = 2,
  SDS_HTTP_ERR_PROTOCOL = 3,
  SDS_HTTP_ERR_MESSAGE_SIZE = 4,
  SDS_HTTP_ERR_TIMED_OUT = 5,
  SDS_HTTP_ERR_TLS = 6,
  SDS_HTTP_ERR_IO = 7,
} SdsHttpErrorKind;

typedef struct {
  const uint8_t *method;
  size_t method_len;
  const uint8_t *path;
  size_t path_len;
  const uint8_t *query_string;
  size_t query_string_len;
  const uint8_t *http_version;
  size_t http_version_len;
  const uint8_t *raw_header;
  size_t raw_header_len;
  const SdsHttpHeaderRef *headers;
  size_t header_count;
  const uint8_t *local_addr;
  size_t local_addr_len;
  uint16_t local_port;
  const uint8_t *remote_addr;
  size_t remote_addr_len;
  uint16_t remote_port;
} SdsHttpRequestHead;

typedef struct {
  uint16_t port;
  size_t thread_pool_size;
  int64_t timeout_request_secs;
  int64_t timeout_content_secs;
  size_t max_request_streambuf_size;
  size_t max_request_header_size;
  const char *address;
  bool reuse_address;
  bool fast_open;
  bool is_https;
  const char *cert_file;
  const char *key_file;
  const char *verify_file;
  bool require_client_cert;
} SdsHttpServerConfig;

typedef struct {
  void *user_data;
  void (*on_bound)(void *user_data, uint16_t port);
  void *(*create_connection)(
    void *user_data,
    uint64_t connection_id,
    const uint8_t *local_addr,
    size_t local_addr_len,
    uint16_t local_port,
    const uint8_t *remote_addr,
    size_t remote_addr_len,
    uint16_t remote_port
  );
  void (*drop_connection)(void *user_data, void *cxx_conn);
  bool (*on_connection_accepted)(void *user_data, void *cxx_conn);
  bool (*on_verify_client)(void *user_data, uint64_t connection_id, const uint8_t *cert_der, size_t cert_der_len);
  void (*on_verify_failed)(void *user_data, void *cxx_conn, SdsHttpResponseSender *resp_sender);
  bool (*on_connection_authenticated)(void *user_data, void *cxx_conn);
  void *(*create_request)(void *user_data, void *cxx_conn, const SdsHttpRequestHead *head);
  void (*drop_request)(void *user_data, void *cxx_req);
  bool (*on_request_header)(void *user_data, void *cxx_req);
  void (*attach_request_body)(void *user_data, void *cxx_req, const uint8_t *body, size_t body_len);
  void (*dispatch_request)(void *user_data, void *cxx_req, SdsHttpResponseSender *resp_sender);
  void (*on_error)(
    void *user_data,
    void *cxx_conn,
    void *cxx_req,
    SdsHttpErrorKind kind,
    const uint8_t *msg,
    size_t msg_len
  );
} SdsHttpServerCallbacks;

typedef struct {
  const char *host;
  uint16_t port;
  uint16_t default_port;
  bool is_https;
  bool verify_certificate;
  const char *cert_file;
  const char *key_file;
  const char *verify_file;
} SdsHttpClientConfig;

typedef struct {
  bool ok;
  SdsHttpErrorKind error_kind;
  SdsHttpBytes error_message;
  SdsHttpBytes http_version;
  SdsHttpBytes status_code;
  SdsHttpHeaderVec headers;
  SdsHttpBytes body;
} SdsHttpClientResponse;

void sds_http_bytes_free(SdsHttpBytes buf);
void sds_http_header_vec_free(SdsHttpHeaderVec vec);

bool sds_http_has_canonical_header_lines(const uint8_t *raw, size_t raw_len);
bool sds_http_validate_request_framing(
  const uint8_t *raw,
  size_t raw_len,
  const SdsHttpHeaderRef *headers,
  size_t header_count,
  size_t max_body_size,
  size_t *out_content_length
);

SdsHttpBytes sds_http_base64_encode(const uint8_t *data, size_t len);
SdsHttpBytes sds_http_base64_decode(const uint8_t *data, size_t len);
SdsHttpBytes sds_http_percent_encode(const uint8_t *data, size_t len);
SdsHttpBytes sds_http_percent_decode(const uint8_t *data, size_t len);
SdsHttpHeaderVec sds_http_parse_query_string(const uint8_t *data, size_t len);

SdsHttpServer *sds_http_server_create(
  const SdsHttpServerConfig *config,
  const SdsHttpServerCallbacks *callbacks,
  SdsHttpBytes *out_error
);
bool sds_http_server_start(SdsHttpServer *server, SdsHttpBytes *out_error);
void sds_http_server_stop(SdsHttpServer *server);
void sds_http_server_destroy(SdsHttpServer *server);

void sds_http_response_send(
  SdsHttpResponseSender *sender,
  const uint8_t *data,
  size_t len,
  bool close_connection
);
void sds_http_response_abort(SdsHttpResponseSender *sender);

SdsHttpClient *sds_http_client_create(const SdsHttpClientConfig *config, SdsHttpBytes *out_error);
void sds_http_client_stop(SdsHttpClient *client);
void sds_http_client_destroy(SdsHttpClient *client);
SdsHttpClientResponse sds_http_client_request(
  SdsHttpClient *client,
  const uint8_t *method,
  size_t method_len,
  const uint8_t *path,
  size_t path_len,
  const SdsHttpHeaderRef *headers,
  size_t header_count,
  const uint8_t *body,
  size_t body_len,
  int64_t timeout_secs,
  int64_t timeout_connect_secs,
  size_t max_response_bytes
);
void sds_http_client_response_free(SdsHttpClientResponse resp);

#ifdef __cplusplus
}
#endif

#endif
