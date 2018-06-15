/* Simple HTTP server for ESP32.
 * Copyright Ivan Grokhotkov, 2017.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <http_server.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/lock.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "rom/queue.h"
#include "driver/gpio.h"

#include "esp_log.h"

#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/api.h"

#include "http_parser.h"
#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/ssl_ticket.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#define HTTP_PARSE_BUF_MAX_LEN 256

#define MBEDTLS_EXAMPLE_RECV_BUF_LEN 1024

typedef enum {
    HTTP_PARSING_URI,                //!< HTTP_PARSING_URI
    HTTP_PARSING_HEADER_NAME,        //!< HTTP_PARSING_HEADER_NAME
    HTTP_PARSING_HEADER_VALUE,       //!< HTTP_PARSING_HEADER_VALUE
    HTTP_PARSING_REQUEST_BODY,       //!< HTTP_PARSING_REQUEST_BODY
    HTTP_REQUEST_DONE,               //!< HTTP_REQUEST_DONE
    HTTP_COLLECTING_RESPONSE_HEADERS,//!< HTTP_COLLECTING_RESPONSE_HEADERS
    HTTP_SENDING_RESPONSE_BODY,      //!< HTTP_SENDING_RESPONSE_BODY
    HTTP_DONE,                       //!< HTTP_DONE
} http_state_t;

typedef struct http_header_t {
    char* name;
    char* value;
    SLIST_ENTRY(http_header_t) list_entry;
} http_header_t;

typedef SLIST_HEAD(http_header_list_t, http_header_t) http_header_list_t;

typedef struct {
    http_handler_fn_t cb;
    void* ctx;
} http_form_handler_t;

typedef struct http_handler_t{
    char* uri_pattern;
    int method;
    int events;
    http_handler_fn_t cb;
    void* ctx;
    SLIST_ENTRY(http_handler_t) list_entry;
} http_handler_t;


struct http_context_ {
    http_server_t server;
    http_state_t state;
    int event;
    char* uri;
    char parse_buffer[HTTP_PARSE_BUF_MAX_LEN];
    char* request_header_tmp;
    http_parser parser;
    http_header_list_t request_headers;
    int response_code;
    http_header_list_t response_headers;
    size_t expected_response_size;
    size_t accumulated_response_size;
    http_handler_t* handler;
    const char* data_ptr;
    size_t data_size;
    http_header_list_t request_args;
#ifdef HTTPS_SERVER
    mbedtls_ssl_context *ssl_conn;
    mbedtls_net_context *client_fd;
#else
    struct netconn *conn;
#endif
};

struct http_server_context_ {
	int port;
    TaskHandle_t task;
	EventGroupHandle_t start_done;
    err_t server_task_err;
    SLIST_HEAD(, http_handler_t) handlers;
    _lock_t handlers_lock;
    struct http_context_ connection_context;
#ifdef HTTPS_SERVER
    mbedtls_net_context *listen_fd;
    mbedtls_entropy_context *entropy;
	mbedtls_ctr_drbg_context *ctr_drbg;
	mbedtls_ssl_config *conf;
	mbedtls_x509_crt *srvcert;
	mbedtls_pk_context *pkey;
	mbedtls_ssl_cache_context *cache;
    mbedtls_ssl_ticket_context *ticket_ctx;
#else
    struct netconn* server_conn;
#endif
};

static const char* http_response_code_to_str(int code);
static esp_err_t add_keyval_pair(http_header_list_t *list, const char* name, const char* val);

static const char* TAG = "http_server";


esp_err_t http_register_handler(http_server_t server,
        const char* uri_pattern, int method,
        int events, http_handler_fn_t callback, void* callback_arg)
{
    http_handler_t* new_handler = (http_handler_t*) calloc(1, sizeof(*new_handler));
    if (new_handler == NULL) {
        return ESP_ERR_NO_MEM;
    }

    new_handler->uri_pattern = strdup(uri_pattern);
    new_handler->cb = callback;
    new_handler->ctx = callback_arg;
    new_handler->method = method;
    new_handler->events = events;

    _lock_acquire(&server->handlers_lock);
    /* FIXME: Handlers will be checked in the reverse order */
    SLIST_INSERT_HEAD(&server->handlers, new_handler, list_entry);
    _lock_release(&server->handlers_lock);
    return ESP_OK;
}

static http_handler_t* http_find_handler(http_server_t server, const char* uri, int method)
{
    http_handler_t* it;
    _lock_acquire(&server->handlers_lock);
    SLIST_FOREACH(it, &server->handlers, list_entry) {
        if (strcasecmp(uri, it->uri_pattern) == 0
            && method == it->method) {
            break;
        }
    }
    _lock_release(&server->handlers_lock);
    return it;
}

static int append_parse_buffer(http_context_t ctx, const char* at, size_t length)
{
    if (length > HTTP_PARSE_BUF_MAX_LEN - strlen(ctx->parse_buffer) - 1) {
        ESP_LOGW(TAG, "%s: len=%d > %d", __func__, length, HTTP_PARSE_BUF_MAX_LEN - strlen(ctx->parse_buffer) - 1);
        return 1;
    }
    strncat(ctx->parse_buffer, at, length);
    ESP_LOGV(TAG, "%s: len=%d, '%s'", __func__, length, ctx->parse_buffer);
    return 0;
}

static void clear_parse_buffer(http_context_t ctx)
{
#ifdef NDEBUG
    ctx->parse_buffer[0] = 0;
#else
    memset(ctx->parse_buffer, 0, sizeof(ctx->parse_buffer));
#endif
}

static void header_name_done(http_context_t ctx)
{
    ctx->request_header_tmp = strdup(ctx->parse_buffer);
    clear_parse_buffer(ctx);
}

static void header_value_done(http_context_t ctx)
{
    const char* value = ctx->parse_buffer;
    const char* name = ctx->request_header_tmp;
    ESP_LOGI(TAG, "Got header: '%s': '%s'", name, value);
    add_keyval_pair(&ctx->request_headers, name, value);
    free(ctx->request_header_tmp);
    ctx->request_header_tmp = NULL;
    clear_parse_buffer(ctx);
}

static int http_url_cb(http_parser* parser, const char *at, size_t length)
{
    ESP_LOGD(TAG, "Called %s", __func__);
    http_context_t ctx = (http_context_t) parser->data;
    return append_parse_buffer(ctx, at, length);
}

static bool invoke_handler(http_context_t ctx, int event)
{
    if (ctx->handler && (ctx->handler->events & event) != 0) {
        ctx->event = event;
        (*ctx->handler->cb)(ctx, ctx->handler->ctx);
        ctx->event = 0;
        return true;
    }
    return false;
}


static int http_headers_done_cb(http_parser* parser)
{
    ESP_LOGD(TAG, "Called %s", __func__);
    http_context_t ctx = (http_context_t) parser->data;
    if (ctx->state == HTTP_PARSING_HEADER_VALUE) {
        header_value_done(ctx);
    }
    invoke_handler(ctx, HTTP_HANDLE_HEADERS);
    ctx->state = HTTP_PARSING_REQUEST_BODY;
    return 0;
}

static int parse_hex_digit(char hex)
{
    switch (hex) {
        case '0' ... '9': return hex - '0';
        case 'a' ... 'f': return hex - 'a' + 0xa;
        case 'A' ... 'F': return hex - 'A' + 0xA;
        default:
            return -1;
    }
}

static char* urldecode(const char* str, size_t len)
{
    ESP_LOGV(TAG, "urldecode: '%.*s'", len, str);

    const char* end = str + len;
    char* out = calloc(1, len + 1);
    char* p_out = out;
    while (str != end) {
        char c = *str++;
        if (c != '%') {
            *p_out = c;
        } else {
            if (str + 2 > end) {
                /* Unexpected end of string */
                return NULL;
            }
            int high = parse_hex_digit(*str++);
            int low = parse_hex_digit(*str++);
            if (high == -1 || low == -1) {
                /* Unexpected character */
                return NULL;
            }
            *p_out = high * 16 + low;
        }
        ++p_out;
    }
    *p_out = 0;
    ESP_LOGV(TAG, "urldecode result: '%s'", out);
    return out;
}

static void parse_urlencoded_args(http_context_t ctx, const char* str, size_t len)
{
    const char* end = str + len;
    const int READING_KEY = 1;
    const int READING_VAL = 2;
    int state = READING_KEY;
    const char* token_start = str;
    char* key = NULL;
    char* value = NULL;
    for (const char* pos = str; pos < end; ++pos) {
        char c = *pos;
        if (c == '=' && state == READING_KEY) {
            key = urldecode(token_start, pos - token_start);
            state = READING_VAL;
            token_start = pos + 1;
        } else if (c == '&' && state == READING_VAL) {
            value = urldecode(token_start, pos - token_start);
            state = READING_KEY;
            token_start = pos + 1;
            ESP_LOGI(TAG, "Got request argument, '%s': '%s'", key, value);
            add_keyval_pair(&ctx->request_args, key, value);
            free(key);
            key = NULL;
            free(value);
            value = NULL;
        }
    }
    if (state == READING_VAL) {
        value = urldecode(token_start, end - token_start);
        ESP_LOGI(TAG, "Got request argument, '%s': '%s'", key, value);
        add_keyval_pair(&ctx->request_args, key, value);
        free(key);
        key = NULL;
        free(value);
        value = NULL;
    }
}

static void uri_done(http_context_t ctx)
{
    /* Check for query argument string */
    char* query_str = strchr(ctx->parse_buffer, '?');
    if (query_str != NULL) {
        *query_str = 0;
        ++query_str;
    }
    ctx->uri = strdup(ctx->parse_buffer);
    ESP_LOGI(TAG, "Got URI: '%s'", ctx->uri);
    if (query_str) {
        parse_urlencoded_args(ctx, query_str, strlen(query_str));
    }

    ctx->handler = http_find_handler(ctx->server, ctx->uri, (int) ctx->parser.method);
    invoke_handler(ctx, HTTP_HANDLE_URI);
    clear_parse_buffer(ctx);
}


static int http_header_name_cb(http_parser* parser, const char *at, size_t length)
{
    ESP_LOGD(TAG, "Called %s", __func__);
    http_context_t ctx = (http_context_t) parser->data;
    if (ctx->state == HTTP_PARSING_URI) {
        uri_done(ctx);
        ctx->state = HTTP_PARSING_HEADER_NAME;
    } else if (ctx->state == HTTP_PARSING_HEADER_VALUE) {
        header_value_done(ctx);
        ctx->state = HTTP_PARSING_HEADER_NAME;
    }
    return append_parse_buffer(ctx, at, length);
}

static int http_header_value_cb(http_parser* parser, const char *at, size_t length)
{
    ESP_LOGD(TAG, "Called %s", __func__);
    http_context_t ctx = (http_context_t) parser->data;
    if (ctx->state == HTTP_PARSING_HEADER_NAME) {
        header_name_done(ctx);
        ctx->state = HTTP_PARSING_HEADER_VALUE;
    }
    return append_parse_buffer(ctx, at, length);
}

static int http_body_cb(http_parser* parser, const char *at, size_t length)
{
    ESP_LOGD(TAG, "Called %s", __func__);
    http_context_t ctx = (http_context_t) parser->data;
    ctx->data_ptr = at;
    ctx->data_size = length;
    invoke_handler(ctx, HTTP_HANDLE_DATA);
    ctx->data_ptr = NULL;
    ctx->data_size = 0;
    return 0;
}

static int http_message_done_cb(http_parser* parser)
{
    ESP_LOGD(TAG, "Called %s", __func__);
    http_context_t ctx = (http_context_t) parser->data;
    ctx->state = HTTP_REQUEST_DONE;
    return 0;
}

const char* http_request_get_header(http_context_t ctx, const char* name)
{
    http_header_t* it;
    SLIST_FOREACH(it, &ctx->request_headers, list_entry) {
        if (strcasecmp(name, it->name) == 0) {
            return it->value;
        }
    }
    return NULL;
}

int http_request_get_event(http_context_t ctx)
{
    return ctx->event;
}

const char* http_request_get_uri(http_context_t ctx)
{
    return ctx->uri;
}

int http_request_get_method(http_context_t ctx)
{
    return (int) ctx->parser.method;
}

const char* http_request_get_arg_value(http_context_t ctx, const char* name)
{
    http_header_t* it;
    SLIST_FOREACH(it, &ctx->request_args, list_entry) {
        ESP_LOGI(TAG, "Key %s: %s", it->name, it->value);
        if (strcasecmp(name, it->name) == 0) {
            return it->value;
        }
    }
    return NULL;
}

esp_err_t http_request_get_data(http_context_t ctx, const char** out_data_ptr, size_t* out_size)
{
    if (ctx->event != HTTP_HANDLE_DATA) {
        return ESP_ERR_INVALID_STATE;
    }
    *out_data_ptr = ctx->data_ptr;
    *out_size = ctx->data_size;
    return ESP_OK;
}

static void form_data_handler_cb(http_context_t http_ctx, void* ctx)
{
    http_form_handler_t* form_ctx = (http_form_handler_t*) ctx;
    int event = http_request_get_event(http_ctx);
    if (event != HTTP_HANDLE_DATA) {
        (*form_ctx->cb)(http_ctx, form_ctx->ctx);
    } else {
        const char* str;
        size_t len;
        http_request_get_data(http_ctx, &str, &len);
        parse_urlencoded_args(http_ctx, str, len);
    }
}

esp_err_t http_register_form_handler(http_server_t server, const char* uri_pattern, int method,
                                    int events, http_handler_fn_t callback, void* callback_arg)
{
    http_form_handler_t* inner_handler = calloc(1, sizeof(*inner_handler));
    if (inner_handler == NULL) {
        return ESP_ERR_NO_MEM;
    }

    inner_handler->cb = callback;
    inner_handler->ctx = callback_arg;

    esp_err_t res = http_register_handler(server, uri_pattern, method,
            events | HTTP_HANDLE_DATA, &form_data_handler_cb, inner_handler);
    if (res != ESP_OK) {
        free(inner_handler);
    }
    return res;
}


static esp_err_t lwip_err_to_esp_err(err_t e)
{
    switch (e) {
        case ERR_OK: return ESP_OK;
        case ERR_MEM: return ESP_ERR_NO_MEM;
        case ERR_TIMEOUT: return ESP_ERR_TIMEOUT;
        default:
            return ESP_FAIL;
    }
}

static void headers_list_clear(http_header_list_t* list)
{
    http_header_t  *it, *next;
    SLIST_FOREACH_SAFE(it, list, list_entry, next) {
        SLIST_REMOVE(list, it, http_header_t, list_entry);
        free(it); /* frees memory allocated for header, name, and value */
    }
}

static esp_err_t http_add_content_length_header(http_context_t http_ctx, size_t value)
{
    char size_str[11];
    itoa(value, size_str, 10);
    return http_response_set_header(http_ctx, "Content-length", size_str);
}

static esp_err_t http_send_response_headers(http_context_t http_ctx)
{
    assert(http_ctx->state == HTTP_COLLECTING_RESPONSE_HEADERS);

    /* Calculate total size of all the headers, allocate a buffer */
    size_t total_headers_size = 0;

    /* response_code may be == 0, if we are sending headers for multipart
     * response part. In this case, don't send the response code line.
     */
    if (http_ctx->response_code > 0) {
        total_headers_size += 16 /* HTTP/1.1, code, CRLF */
                + strlen(http_response_code_to_str(http_ctx->response_code));
    }
    http_header_t* it;
    SLIST_FOREACH(it, &http_ctx->response_headers, list_entry) {
        total_headers_size += strlen(it->name) + strlen(it->value) + 4 /* ": ", CRLF */;
    }
    total_headers_size += 3; /* Final CRLF, '\0' terminator */
    char* headers_buf = calloc(1, total_headers_size);
    if (headers_buf == NULL) {
        return ESP_ERR_NO_MEM;
    }
    /* Write response */
    size_t buf_size = total_headers_size;
    char* buf_ptr = headers_buf;
    int len;
    if (http_ctx->response_code > 0) {
        len = snprintf(buf_ptr, buf_size, "HTTP/1.1 %d %s\r\n",
                http_ctx->response_code, http_response_code_to_str(http_ctx->response_code));
        assert(len < buf_size);
        buf_size -= len;
        buf_ptr += len;
    }

    /* Write response headers */
    SLIST_FOREACH(it, &http_ctx->response_headers, list_entry) {
        len = snprintf(buf_ptr, buf_size, "%s: %s\r\n", it->name, it->value);
        assert(len < buf_size);
        buf_size -= len;
        buf_ptr += len;
    }

    /* Final CRLF */
    len = snprintf(buf_ptr, buf_size, "\r\n");
    assert(len < buf_size);
    buf_size -= len;
    buf_ptr += len;

    headers_list_clear(&http_ctx->response_headers);

#ifdef HTTPS_SERVER
    int ret;
    int actual_len;
    ESP_LOGI(TAG, "Writing response headers..." );

    len = strlen(headers_buf);
    actual_len = 0;
    ret = 0;
	do
	{
		len = len - ret;
		ret = mbedtls_ssl_write( http_ctx->ssl_conn, ((const unsigned char *)headers_buf + ret), len);
		if( ret == MBEDTLS_ERR_NET_CONN_RESET )
		{
			ESP_LOGE(TAG, "ERROR: peer closed the connection\n\n" );
			//FIXME: reset connection
			//goto reset;
		}

		if( ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
		{
			ESP_LOGE(TAG, "ERROR: mbedtls_ssl_write returned %d\n\n", ret );
			break;
			//FIXME: close connection
			//goto exit;
		}
		if (ret > 0)
			actual_len += ret;
	}while( ret < 0 || ret < len );

	ESP_LOGI(TAG, "%d bytes written:\n%s", actual_len, (char *)headers_buf);
    free(headers_buf);
    http_ctx->state = HTTP_SENDING_RESPONSE_BODY;
	//FIXME: check return code from mbedTLS
	return ESP_OK;
#else
    err_t err = netconn_write(http_ctx->conn, headers_buf, strlen(headers_buf), NETCONN_COPY);
    free(headers_buf);

    http_ctx->state = HTTP_SENDING_RESPONSE_BODY;

    return lwip_err_to_esp_err(err);
#endif
}

/* Common function called by http_response_begin and http_response_begin_multipart */
static esp_err_t http_response_begin_common(http_context_t http_ctx, const char* content_type, size_t response_size)
{
    esp_err_t err = http_response_set_header(http_ctx, "Content-type", content_type);
    if (err != ESP_OK) {
        return err;
    }
    http_ctx->expected_response_size = response_size;
    http_ctx->accumulated_response_size = 0;
    if (response_size != HTTP_RESPONSE_SIZE_UNKNOWN) {
        err = http_add_content_length_header(http_ctx, response_size);
        if (err != ESP_OK) {
            return err;
        }
    }
    return ESP_OK;
}

esp_err_t http_response_begin(http_context_t http_ctx, int code, const char* content_type, size_t response_size)
{
    if (http_ctx->state != HTTP_COLLECTING_RESPONSE_HEADERS) {
        return ESP_ERR_INVALID_STATE;
    }
    http_ctx->response_code = code;
    return http_response_begin_common(http_ctx, content_type, response_size);
}

esp_err_t http_response_write(http_context_t http_ctx, const http_buffer_t* buffer)
{
	size_t len;
	int ret;
	esp_err_t err;
    if (http_ctx->state == HTTP_COLLECTING_RESPONSE_HEADERS) {
        err = http_send_response_headers(http_ctx);
        if (err != ESP_OK) {
        	ESP_LOGE(TAG, "ERROR: in http_send_response_headers function...");
            return err;
        }
    }
	len = buffer->size ? buffer->size : strlen((const char*) buffer->data);
#ifdef HTTPS_SERVER
    ESP_LOGI(TAG, "Writing to client:" );
    ret = 0;
    do
	{
    	len = len - ret;
    	ret = mbedtls_ssl_write( http_ctx->ssl_conn, (buffer->data + ret), len);
		if( ret == MBEDTLS_ERR_NET_CONN_RESET )
		{
			ESP_LOGE(TAG, "ERROR: peer closed the connection\n\n" );
		    //FIXME: reset connection
			//goto reset;
		}

		if( ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
		{
			ESP_LOGE(TAG, "ERROR: mbedtls_ssl_write returned %d\n\n", ret );
			break;
			//FIXME: close connection
			//goto exit;
		}
		if (ret > 0)
			http_ctx->accumulated_response_size += ret;
	}while( ret < 0 || ret < len );

	ESP_LOGI(TAG, "%d bytes written:%s", http_ctx->accumulated_response_size, (char *)buffer->data);
	return ret;
#else
	const int flag = buffer->data_is_persistent ? NETCONN_NOCOPY : NETCONN_COPY;
	err_t rc = netconn_write(http_ctx->conn, buffer->data, len, flag);
    if (rc != ESP_OK) {
        ESP_LOGD(TAG, "netconn_write rc=%d", rc);
    } else {
        http_ctx->accumulated_response_size += len;
    }
    return lwip_err_to_esp_err(rc);
#endif
}


esp_err_t http_response_end(http_context_t http_ctx)
{
    size_t expected = http_ctx->expected_response_size;
    size_t actual = http_ctx->accumulated_response_size;
    if (expected != HTTP_RESPONSE_SIZE_UNKNOWN && expected != actual) {
        ESP_LOGW(TAG, "Expected response size: %d, actual: %d", expected, actual);
    }
    http_ctx->state = HTTP_DONE;
    return ESP_OK;
}

esp_err_t http_response_begin_multipart(http_context_t http_ctx, const char* content_type, size_t response_size)
{
    if (http_ctx->state == HTTP_COLLECTING_RESPONSE_HEADERS) {
        http_send_response_headers(http_ctx);
        http_ctx->response_code = 0;
    }
    http_ctx->state = HTTP_COLLECTING_RESPONSE_HEADERS;
    return http_response_begin_common(http_ctx, content_type, response_size);
}

esp_err_t http_response_end_multipart(http_context_t http_ctx, const char* boundary)
{
    size_t expected = http_ctx->expected_response_size;
    size_t actual = http_ctx->accumulated_response_size;
    if (expected != HTTP_RESPONSE_SIZE_UNKNOWN && expected != actual) {
        ESP_LOGW(TAG, "Expected response size: %d, actual: %d", expected, actual);
    }
    /* reset expected_response_size so that http_response_end doesn't complain */
    http_ctx->expected_response_size = HTTP_RESPONSE_SIZE_UNKNOWN;

    const http_buffer_t buf = { .data = boundary };
    esp_err_t ret = http_response_write(http_ctx, &buf);
    http_ctx->state = HTTP_COLLECTING_RESPONSE_HEADERS;
    return ret;
}

static esp_err_t add_keyval_pair(http_header_list_t *list, const char* name, const char* val)
{
    size_t name_len = strlen(name) + 1;
    size_t val_len = strlen(val) + 1;
    /* Allocate memory for the structure, name, and value, in one go */
    size_t buf_len = sizeof(http_header_t) + name_len + val_len;
    char* buf = (char*) calloc(1, buf_len);
    if (buf == NULL) {
        return ESP_ERR_NO_MEM;
    }
    http_header_t* new_header = (http_header_t*) buf;
    new_header->name = buf + sizeof(http_header_t);
    new_header->value = new_header->name + name_len;
    strcpy(new_header->name, name);
    strcpy(new_header->value, val);
    SLIST_INSERT_HEAD(list, new_header, list_entry);
    return ESP_OK;
}

esp_err_t http_response_set_header(http_context_t http_ctx, const char* name, const char* val)
{
    return add_keyval_pair(&http_ctx->response_headers, name, val);
}


static void http_send_not_found_response(http_context_t http_ctx)
{
    ESP_LOGD(TAG, "Called %s", __func__);
	http_response_begin(http_ctx, 404, "text/plain", HTTP_RESPONSE_SIZE_UNKNOWN);
    const http_buffer_t buf = {
            .data = "Not found",
            .data_is_persistent = true
    };
	ESP_LOGD(TAG, "Calling http_response_write function...");
    http_response_write(http_ctx, &buf);
	ESP_LOGD(TAG, "Calling http_response_end function...");
    http_response_end(http_ctx);
}


static const char* http_response_code_to_str(int code)
{
    switch (code) {
        case 200: return "OK";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 400: return "Bad Request";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 500: return "Internal Server Error";
        default:  return "";
      }
}


static void http_handle_connection(http_server_t server, void *arg_conn)
{
	unsigned char *buf;
    /* Single threaded server, one context only */
    http_context_t ctx = &server->connection_context;

    /* Initialize context */
    ctx->state = HTTP_PARSING_URI;
#ifdef HTTPS_SERVER
#else
    struct netbuf *inbuf = NULL;
	u16_t buflen;
	err_t err = ERR_OK;
    ctx->conn = (struct netconn *)arg_conn;
#endif
    http_parser_init(&ctx->parser, HTTP_REQUEST);
    ctx->parser.data = ctx;
    ctx->server = server;

    const http_parser_settings parser_settings = {
            .on_url = &http_url_cb,
            .on_headers_complete = &http_headers_done_cb,
            .on_header_field = &http_header_name_cb,
            .on_header_value = &http_header_value_cb,
            .on_body = &http_body_cb,
            .on_message_complete = &http_message_done_cb
    };

#ifdef HTTPS_SERVER
    int ret;
    size_t parsed_bytes = 0;
    /*
	 * 6. Read the HTTP Request
	 */

	ret = 0;
	while (ctx->state != HTTP_REQUEST_DONE) {
    	ESP_LOGV(TAG, "Reading from client..." );
		buf = malloc(sizeof(char)*MBEDTLS_EXAMPLE_RECV_BUF_LEN);
		memset( buf, 0, sizeof(char)*MBEDTLS_EXAMPLE_RECV_BUF_LEN);
		//FIXME: add support for buffer > MBEDTLS_EXAMPLE_RECV_BUF_LEN
		ret = mbedtls_ssl_read( server->connection_context.ssl_conn, buf, MBEDTLS_EXAMPLE_RECV_BUF_LEN);

		if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
			continue;

		if( ret <= 0 )
		{
			switch( ret )
			{
				case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
					ESP_LOGW(TAG, "Error: connection was closed gracefully" );
					break;

				case MBEDTLS_ERR_NET_CONN_RESET:
					ESP_LOGW(TAG, "Error: connection was reset by peer" );
					break;

				default:
					ESP_LOGW(TAG, "Error: mbedtls_ssl_read returned -0x%x\n", -ret );
					break;
			}

			break;
		}

		ESP_LOGD(TAG, "%d bytes read: \n%s", ret, (char *) buf );

    	ESP_LOGI(TAG, "Calling http_parser_execute...");
		parsed_bytes = http_parser_execute(&ctx->parser, &parser_settings, (char *)buf, ret);
	}
	ESP_LOGD(TAG, "Read looping return: %d", parsed_bytes);

#else //HTPPS SERVER OFF
	while (ctx->state != HTTP_REQUEST_DONE) {
		err = netconn_recv(ctx->conn, &inbuf);
		if (err != ERR_OK) {
			break;
		}

		err = netbuf_data(inbuf, (void**) &buf, &buflen);
		if (err != ERR_OK) {
			break;
		}

		size_t parsed_bytes = http_parser_execute(&ctx->parser, &parser_settings, (char *)buf, buflen);
		if (parsed_bytes < buflen) {
			break;
		}
	}
#endif

#ifdef HTTPS_SERVER
    if (ret > 0) {
        ctx->state = HTTP_COLLECTING_RESPONSE_HEADERS;
        if (ctx->handler == NULL) {
        	ESP_LOGD(TAG, "No registered Handler!");
			http_send_not_found_response(ctx);

        } else {
        	ESP_LOGD(TAG, "Registered Handler Found!");
			invoke_handler(ctx, HTTP_HANDLE_RESPONSE);
        }
    }
#else
    if (err == ERR_OK) {
		ctx->state = HTTP_COLLECTING_RESPONSE_HEADERS;
		if (ctx->handler == NULL) {
        	ESP_LOGD(TAG, "No registered Handler!");
			http_send_not_found_response(ctx);
		} else {
        	ESP_LOGD(TAG, "Registered Handler Found!");
			invoke_handler(ctx, HTTP_HANDLE_RESPONSE);
		}
	}
#endif

    headers_list_clear(&ctx->request_headers);
    headers_list_clear(&ctx->request_args);
    free(ctx->uri);
    ctx->uri = NULL;
    ctx->handler = NULL;

#ifdef HTTPS_SERVER
	ESP_LOGI(TAG, "Closing the connection..." );
	while( ( ret = mbedtls_ssl_close_notify( server->connection_context.ssl_conn) ) < 0 )
	{
		if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
			ret != MBEDTLS_ERR_SSL_WANT_WRITE )
		{
			ESP_LOGI(TAG, "ERROR: mbedtls_ssl_close_notify returned %d\n\n", ret );
			break;
			//FIXME: Reset connection
			//goto reset;
		}
	}
	ESP_LOGI(TAG, "OK");
#else
    if (err != ERR_CLSD) {
        netconn_close(ctx->conn);
    }
    if (inbuf) {
        netbuf_delete(inbuf);
    }
#endif
}


static void http_server(void *arg)
{
	uint8_t bits;
    http_server_t ctx = (http_server_t) arg;
    do{
		ESP_LOGV(TAG, "Checking Server Status...");
		bits = xEventGroupWaitBits(ctx->start_done, SERVER_STARTED_BIT | SERVER_DONE_BIT, 0, pdTRUE, 1000 / portTICK_PERIOD_MS);

		//If server had already been successfully started but it has crashed,
		if ((bits & SERVER_STARTED_BIT) && (bits & SERVER_DONE_BIT)) {
			ESP_LOGE(TAG, "Server has closed. Restarting server...");
			xEventGroupClearBits(ctx->start_done, SERVER_STARTED_BIT | SERVER_DONE_BIT);
			memset(&(ctx->connection_context), 0, sizeof(*ctx) - (size_t)((int)&(ctx->connection_context) - (int)ctx) );
			bits = pdFALSE;
		}

		//If server has not successfully been started yet,
	    if (!(bits & SERVER_STARTED_BIT)) {
		#ifdef HTTPS_SERVER
			char *error_buf;
			ESP_LOGV(TAG, "Declaring local mbedTLS context on task...");
			int ret;
			mbedtls_net_context listen_fd;
			mbedtls_net_context client_fd;
			mbedtls_entropy_context entropy;
			mbedtls_ctr_drbg_context ctr_drbg;
			mbedtls_ssl_context ssl_conn;
			mbedtls_ssl_config conf;
			mbedtls_x509_crt srvcert;
			mbedtls_pk_context pkey;
		#if defined(MBEDTLS_SSL_CACHE_C)
			mbedtls_ssl_cache_context cache;
			(ctx->cache) = &cache;
		#endif
		#if defined(MBEDTLS_SSL_SESSION_TICKETS)
		    mbedtls_ssl_ticket_context ticket_ctx;
		    (ctx->ticket_ctx) = &ticket_ctx;
		#endif
			(ctx->listen_fd) = &listen_fd;
			(ctx->connection_context.client_fd) = &client_fd;
			(ctx->entropy) = &entropy;
			(ctx->ctr_drbg) = &ctr_drbg;
			(ctx->connection_context.ssl_conn) = &ssl_conn;
			(ctx->conf) = &conf;
			(ctx->srvcert) = &srvcert;
			(ctx->pkey) = &pkey;

			ESP_LOGV(TAG, "Reading Root CA certificate......");
			extern const unsigned char rootcacert_pem_start[] asm("_binary_rootCertificate_pem_start");
			extern const unsigned char rootcacert_pem_end[]   asm("_binary_rootCertificate_pem_end");
			const unsigned int rootcacert_pem_bytes = rootcacert_pem_end - rootcacert_pem_start;

			/*
			ESP_LOGV(TAG, "Reading Intermediate CA certificate......");
			extern const unsigned char intermediatecacert_pem_start[] asm("_binary_intermediatecacert_pem_start");
			extern const unsigned char intermediatecacert_pem_end[]   asm("_binary_intermediatecacert_pem_end");
			const unsigned int intermediatecacert_pem_bytes = intermediatecacert_pem_end - intermediatecacert_pem_start;
			*/

			ESP_LOGV(TAG, "Reading Server certificate......");
			extern const unsigned char servercert_pem_start[] asm("_binary_esp32Certificate_pem_start");
			extern const unsigned char servercert_pem_end[]   asm("_binary_esp32Certificate_pem_end");
			const unsigned int servercert_pem_bytes = servercert_pem_end - servercert_pem_start;

			ESP_LOGV(TAG, "Reading Server Private Key......");
			extern const unsigned char serverprvtkey_pem_start[] asm("_binary_esp32_key_pem_start");
			extern const unsigned char serverprvtkey_pem_end[]   asm("_binary_esp32_key_pem_end");
			const unsigned int serverprvtkey_pem_bytes = serverprvtkey_pem_end - serverprvtkey_pem_start;

			ESP_LOGV(TAG, "Setting server_fd......");
			mbedtls_net_init( ctx->listen_fd );
			ESP_LOGV(TAG, "OK");

			ESP_LOGV(TAG, "Setting client fd......");
			mbedtls_net_init( ctx->connection_context.client_fd );
			ESP_LOGV(TAG, "OK");

			ESP_LOGV(TAG, "SSL server context create ......");
			mbedtls_ssl_init( ctx->connection_context.ssl_conn );
			ESP_LOGV(TAG, "OK");

			ESP_LOGV(TAG, "SSL conf context create ......");
			mbedtls_ssl_config_init( ctx->conf );
			ESP_LOGV(TAG, "OK");

#if defined(MBEDTLS_SSL_CACHE_C)
			mbedtls_ssl_cache_init( ctx->cache );
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
			mbedtls_ssl_ticket_init( ctx->ticket_ctx );
#endif
			mbedtls_x509_crt_init( ctx->srvcert );
			mbedtls_pk_init( ctx->pkey );
			mbedtls_entropy_init( ctx->entropy );
			mbedtls_ctr_drbg_init( ctx->ctr_drbg );

			/*
			 * 1. Load the certificates and private RSA key
			 */
			ESP_LOGD(TAG, "Loading the server cert. and key..." );
			/*
			 * This demonstration program uses embedded test certificates.
			 * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
			 * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
			 */
			ESP_LOGV(TAG, "SSL server context set own certification......");
			ESP_LOGV(TAG, "Parsing test srv_crt......");
			ret = mbedtls_x509_crt_parse( ctx->srvcert, (const unsigned char *) servercert_pem_start,
						servercert_pem_bytes );
			if( ret != ERR_OK )
			{
				ESP_LOGE(TAG, "ERROR: mbedtls_x509_crt_parse returned %d", ret );
				goto exit;
			}
			ESP_LOGV(TAG, "OK");

			/*
			ESP_LOGV(TAG, "Parsing Intermediate CA crt......");
			ret = mbedtls_x509_crt_parse( ctx->srvcert, (const unsigned char *) intermediatecacert_pem_start,
						intermediatecacert_pem_bytes );
			if( ret != ERR_OK )
			{
				ESP_LOGE(TAG, "ERROR: mbedtls_x509_crt_parse returned %d", ret );
				goto exit;
			}
			ESP_LOGV(TAG, "OK");
			*/

			ESP_LOGV(TAG, "Parsing Root CA crt......");
			ret = mbedtls_x509_crt_parse( ctx->srvcert, (const unsigned char *) rootcacert_pem_start,
						rootcacert_pem_bytes );
			if( ret != ERR_OK )
			{
				ESP_LOGE(TAG, "ERROR: mbedtls_x509_crt_parse returned %d", ret );
				goto exit;
			}
			ESP_LOGV(TAG, "OK");


			ESP_LOGV(TAG, "SSL server context set private key......");
			ret =  mbedtls_pk_parse_key( ctx->pkey, (const unsigned char *) serverprvtkey_pem_start,
									serverprvtkey_pem_bytes, NULL, 0 );
			if( ret != ERR_OK )
			{
				ESP_LOGE(TAG, "ERROR: mbedtls_pk_parse_key returned %d", ret );
				goto exit;
			}
			ESP_LOGV(TAG, "OK");

			/*
			 * 3. Seed the RNG
			 */
			ESP_LOGV(TAG, "Seeding the random number generator..." );
			if( ( ret = mbedtls_ctr_drbg_seed( ctx->ctr_drbg, mbedtls_entropy_func, ctx->entropy,
									   (const unsigned char *) TAG,
									   strlen( TAG ) ) ) != 0 )
			{
				ESP_LOGE(TAG, "ERROR: mbedtls_ctr_drbg_seed returned %d", ret );
				goto exit;
			}
			ESP_LOGV(TAG, "OK");

			/*
			 * 2. Setup the listening TCP socket
			 */
			char *port = malloc(sizeof(char) * 6);
			ESP_LOGV(TAG, "SSL server socket bind at localhost: %s ......", itoa(ctx->port, port,10));
			if( ( ret = mbedtls_net_bind( ctx->listen_fd, NULL, itoa(ctx->port, port,10), MBEDTLS_NET_PROTO_TCP ) ) != 0 )
			{
				ESP_LOGE(TAG, "ERROR: mbedtls_net_bind returned %d", ret );
				goto exit;
			}
			free(port);
			ESP_LOGV(TAG, "OK");


			/*
			 * 4. Setup stuff
			 */
			ESP_LOGV(TAG, "Setting up the SSL conf data...." );
	#ifdef CONFIG_MBEDTLS_DEBUG
			mbedtls_esp_enable_debug_log(ctx->conf, 4);
	#endif
			if( ( ret = mbedtls_ssl_config_defaults( ctx->conf,
							MBEDTLS_SSL_IS_SERVER,
							MBEDTLS_SSL_TRANSPORT_STREAM,
							MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
			{
				ESP_LOGE(TAG, "ERROR: mbedtls_ssl_config_defaults returned %d", ret );
				goto exit;
			}

			mbedtls_ssl_conf_rng( ctx->conf, mbedtls_ctr_drbg_random, ctx->ctr_drbg );

#if defined(MBEDTLS_SSL_CACHE_C)
			mbedtls_ssl_conf_session_cache( ctx->conf, ctx->cache,
										   mbedtls_ssl_cache_get,
										   mbedtls_ssl_cache_set );
#endif

			ESP_LOGV(TAG, "Setting up the SSL Session Tickets...." );
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
			if( ( ret = mbedtls_ssl_ticket_setup( ctx->ticket_ctx ,
								mbedtls_ctr_drbg_random, &ctr_drbg,
								MBEDTLS_CIPHER_AES_256_GCM,
								86400 ) ) != 0 )
			{
				ESP_LOGE(TAG, "ERROR: mbedtls_ssl_ticket_setup returned %d", ret );
				goto exit;
			}

			mbedtls_ssl_conf_session_tickets_cb( &conf,
					mbedtls_ssl_ticket_write,
					mbedtls_ssl_ticket_parse,
					ctx->ticket_ctx );
#endif

			mbedtls_ssl_conf_ca_chain( ctx->conf, (*ctx->srvcert).next, NULL );
			if( ( ret = mbedtls_ssl_conf_own_cert( ctx->conf, ctx->srvcert, ctx->pkey ) ) != 0 )
			{
				ESP_LOGE(TAG, "ERROR: mbedtls_ssl_conf_own_cert returned %d", ret );
				goto exit;
			}

			if( ( ret = mbedtls_ssl_setup( ctx->connection_context.ssl_conn, ctx->conf ) ) != 0 )
			{
				ESP_LOGE(TAG, "ERROR: mbedtls_ssl_setup returned %d", ret );
				goto exit;
			}
			ESP_LOGV(TAG, "OK");

			xEventGroupSetBits(ctx->start_done, SERVER_STARTED_BIT);
reset:
			ESP_LOGI(TAG, "Clearing SERVER_PROCESSING_REQUEST bit...");
			xEventGroupClearBits(ctx->start_done, SERVER_PROCESSING_REQUEST);
			ESP_LOGI(TAG, "mbedTLS HTTPS server is running! Waiting for new connection...");
			do {
				mbedtls_net_free( ctx->connection_context.client_fd );

				mbedtls_ssl_session_reset( ctx->connection_context.ssl_conn );
				/*
				 * 3. Wait until a client connects
				 */
				ESP_LOGV(TAG, "Wait until a client connects..." );
				if( ( ret = mbedtls_net_accept( ctx->listen_fd, ctx->connection_context.client_fd,
												NULL, 0, NULL ) ) != 0 )
				{
					ESP_LOGE(TAG, "ERROR: mbedtls_net_accept returned %d", ret );
					goto exit;
				}
				ESP_LOGI(TAG, "Setting SERVER_PROCESSING_REQUEST bit...");
				xEventGroupSetBits(ctx->start_done, SERVER_PROCESSING_REQUEST);
				mbedtls_ssl_set_bio( ctx->connection_context.ssl_conn, ctx->connection_context.client_fd, mbedtls_net_send, mbedtls_net_recv, NULL );
				ESP_LOGV(TAG, "OK");

				/*
				 * 5. Handshake
				 */
				ESP_LOGV(TAG, "Performing the SSL/TLS handshake..." );
				while( ( ret = mbedtls_ssl_handshake( ctx->connection_context.ssl_conn ) ) != ERR_OK )
				{
					if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
					{
						ESP_LOGE(TAG, "ERROR: bedtls_ssl_handshake returned %d", ret );
						goto reset;
					}
				}
				ESP_LOGV(TAG, "OK");
				ESP_LOGV(TAG, "Handling connection..." );
				if (ret == ERR_OK) {
					http_handle_connection(ctx, NULL);
				}
				ESP_LOGI(TAG, "Clearing SERVER_PROCESSING_REQUEST bit...");
				xEventGroupClearBits(ctx->start_done, SERVER_PROCESSING_REQUEST);
				ESP_LOGV(TAG, "OK");
			} while (ret == ERR_OK);

exit:
			if (ret != ERR_OK) {
				error_buf = malloc(sizeof(char)*ERROR_BUF_LENGTH);
				mbedtls_strerror( ret, error_buf, sizeof(char)*ERROR_BUF_LENGTH );
				ESP_LOGE(TAG, "Error %d: %s", ret, error_buf );
				free(error_buf);

				//Set SERVER_DONE_BIT and save error at http_server_t struct
				ctx->server_task_err = ret;
				xEventGroupSetBits(ctx->start_done, SERVER_DONE_BIT);
				ESP_LOGI(TAG, "Clearing SERVER_PROCESSING_REQUEST bit...");
				xEventGroupClearBits(ctx->start_done, SERVER_PROCESSING_REQUEST);
			}

			mbedtls_net_free( ctx->connection_context.client_fd );
			mbedtls_net_free( ctx->listen_fd );
			mbedtls_x509_crt_free( ctx->srvcert );
			mbedtls_pk_free( ctx->pkey );
			mbedtls_ssl_free( ctx->connection_context.ssl_conn );
			mbedtls_ssl_config_free( ctx->conf );
#if defined(MBEDTLS_SSL_CACHE_C)
			mbedtls_ssl_cache_free( ctx->cache );
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
			mbedtls_ssl_ticket_free( ctx->ticket_ctx );
#endif
			mbedtls_ctr_drbg_free( ctx->ctr_drbg );
			mbedtls_entropy_free( ctx->entropy );
#else
			struct netconn *client_conn;
			err_t err;
			ctx->server_conn = netconn_new(NETCONN_TCP);
			if (ctx->server_conn == NULL) {
				err = ERR_MEM;
				goto out;
			}

			err = netconn_bind(ctx->server_conn, NULL, ctx->port);
			if (err != ERR_OK) {
				goto out;
			}

			err = netconn_listen(ctx->server_conn);
			if (err != ERR_OK) {
				goto out;
			}
			xEventGroupSetBits(ctx->start_done, SERVER_STARTED_BIT);

			do {
				err = netconn_accept(ctx->server_conn, &client_conn);
				if (err == ERR_OK) {
					ESP_LOGI(TAG, "Setting SERVER_PROCESSING_REQUEST bit...");
					xEventGroupSetBits(ctx->start_done, SERVER_PROCESSING_REQUEST);
					http_handle_connection(ctx, client_conn);
					netconn_delete(client_conn);
					ESP_LOGI(TAG, "Clearing SERVER_PROCESSING_REQUEST bit...");
					xEventGroupClearBits(ctx->start_done, SERVER_PROCESSING_REQUEST);
				}
			} while (err == ERR_OK);
		out:
			if (ctx->server_conn) {
				netconn_close(ctx->server_conn);
				netconn_delete(ctx->server_conn);
			}
			if (err != ERR_OK) {
				ctx->server_task_err = err;
				ESP_LOGI(TAG, "Clearing SERVER_PROCESSING_REQUEST bit...");
				xEventGroupClearBits(ctx->start_done, SERVER_PROCESSING_REQUEST);
				xEventGroupSetBits(ctx->start_done, SERVER_DONE_BIT);
			}
			vTaskDelete(NULL);
	#endif
	    }
    }while(1);
}

esp_err_t http_server_start(const http_server_options_t* options, http_server_t* out_server)
{
    http_server_t ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return ESP_ERR_NO_MEM;
    }

    ctx->port = options->port;
    ctx->start_done = xEventGroupCreate();
    if (ctx->start_done == NULL) {
        free(ctx);
        return ESP_ERR_NO_MEM;
    }

	//Start http_server task if it had not been started before
	ESP_LOGV(TAG, "Creating http_server task...");
	int ret = xTaskCreatePinnedToCore(&http_server, "http_server",
			options->task_stack_size, ctx,
			options->task_priority,
			&ctx->task,
			options->task_affinity);
	if (ret != pdPASS) {
		vEventGroupDelete(ctx->start_done);
		free(ctx);
		return ESP_ERR_NO_MEM;
	}
	ESP_LOGI(TAG, "http_server task has been created!");

	//Check server status by checking SERVER_STARTED_BIT (it server has been succesfully started) or SERVER_DONE_BIT (if it has crashed)
    ESP_LOGV(TAG, "Checking server status...");
    xEventGroupWaitBits(ctx->start_done, SERVER_STARTED_BIT, 0, 0, portMAX_DELAY);
    ESP_LOGI(TAG, "Server started!");
	*out_server = ctx;
	return ESP_OK;
}

esp_err_t http_server_stop(http_server_t server)
{
    /* FIXME: figure out a thread safe way to do this */
#ifdef HTTPS_SERVER
	/* FIXME: Add function to stop HTTPS */
#else
	netconn_close(server->server_conn);
#endif
    xEventGroupWaitBits(server->start_done, SERVER_DONE_BIT, 0, 0, portMAX_DELAY);
    free(server);
    return ESP_OK;
}

static void cb_GET_method(http_context_t http_ctx, void* ctx)
{
    size_t response_size = strlen(index_html);
    http_response_begin(http_ctx, 200, "text/html", response_size);
    http_buffer_t http_index_html = { .data = index_html };
    http_response_write(http_ctx, &http_index_html);
    http_response_end(http_ctx);
}

esp_err_t simple_GET_method_example(void)
{
	http_server_t server;
#ifdef HTTPS_SERVER
	http_server_options_t http_options = HTTPS_SERVER_OPTIONS_DEFAULT();
#else
	http_server_options_t http_options = HTTP_SERVER_OPTIONS_DEFAULT();
#endif
	esp_err_t res;

	ESP_LOGI(TAG, "Creating Example Server!");
	ESP_ERROR_CHECK( res =  http_server_start(&http_options, &server) );
	if (res != ESP_OK) {
		return res;
	}
	ESP_LOGV(TAG, "OK");

	ESP_LOGI(TAG, "Registering Handler!");
	ESP_ERROR_CHECK( res = http_register_handler(server, "/", HTTP_GET, HTTP_HANDLE_RESPONSE, &cb_GET_method, NULL) );
	if (res != ESP_OK) {
		return res;
	}
	ESP_LOGV(TAG, "OK");

	return res;
}

static void cb_POST_method(http_context_t http_ctx, void* ctx)
{
	const char* post_data;

	ESP_LOGI(TAG, "Received data from POST method...");

	/*Receiving key from POST*/
	post_data = http_request_get_arg_value(http_ctx, "key");
	if(post_data!=NULL){
		ESP_LOGI(TAG, "Received %d bytes corresponding to the 'key': %s", strlen(post_data), post_data);
	}else{
		ESP_LOGI(TAG, "Received NULL from POST method");
	}

	size_t response_size = strlen(response_OK);
	http_response_begin(http_ctx, 201, "text/plain", response_size);
	http_buffer_t http_response_OK = { .data = response_OK };
	http_response_write(http_ctx, &http_response_OK);
	http_response_end(http_ctx);
}

esp_err_t simple_POST_method_example(void)
{
	http_server_t server;
#ifdef HTTPS_SERVER
	http_server_options_t http_options = HTTPS_SERVER_OPTIONS_DEFAULT();
#else
	http_server_options_t http_options = HTTP_SERVER_OPTIONS_DEFAULT();
#endif
	esp_err_t res;

	ESP_ERROR_CHECK( res = http_server_start(&http_options, &server) );
	if (res != ESP_OK) {
		return res;
	}

	ESP_ERROR_CHECK( res = http_register_form_handler(server, "/", HTTP_POST, HTTP_HANDLE_RESPONSE, &cb_POST_method, NULL) );
	if (res != ESP_OK) {
		return res;
	}

	return res;
}

/**
  * @brief     	Check if a request is being attended and returns it
  *
  * @param		Current HTTP(S) server context
  *
  * @return 	a uint8_t variable indicating if server is processing any request
  */
uint8_t check_processing_request(http_server_t server)
{
    if(xEventGroupWaitBits(server->start_done, SERVER_PROCESSING_REQUEST, 0, 0, 0) & SERVER_PROCESSING_REQUEST)			//If a request was not finished properly, returns an error
    {
    	ESP_LOGI(TAG, "Processing Server Request");
    	return true;
    }else
    {
    	ESP_LOGI(TAG, "No Server Request");
    	return false;
    }
}
