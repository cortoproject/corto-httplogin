/* This is a managed file. Do not delete this comment. */

#include <corto/httplogin/httplogin.h>

int16_t httplogin_service_construct(
    httplogin_service this)
{
    /* First construct service, so we have a reference to the HTTP server */
    if (httpserver_Service_construct(this)) {
        goto error;
    }

    /* Register service as infrastructure service, so pre & post hook get
     * executed. */
    httpserver_HTTP_add_infra_service(
        httpserver_Service(this)->server, this);

    return 0;
error:
    return -1;
}

corto_string httplogin_service_login(
    httplogin_service this,
    httpserver_HTTP_Request *request,
    httplogin_login *data)
{
    const char *username = httpserver_HTTP_Request_getVar(request, "username");
    const char *password = httpserver_HTTP_Request_getVar(request, "password");

    if (!username) {
        httpserver_HTTP_Request_badRequest(request, "No username provided");
        return NULL;
    }

    const char *session_id = corto_login(username, password);
    if (!session_id) {
        httpserver_HTTP_Request_badRequest(request, "Invalid login");
        return NULL;
    }

    /* Set session-id in cookie on the client */
    httpserver_HTTP_Request_setCookie(request, "session-id", session_id);

    return corto_strdup("Login success");
}

corto_string httplogin_service_logout(
    httplogin_service this,
    httpserver_HTTP_Request *request,
    httplogin_logout *data)
{
    const char *session_id = httpserver_HTTP_Request_getVar(
        request, "session_id");

    if (!session_id || !session_id[0]) {
        session_id = httpserver_HTTP_Request_getCookie(request, "session-id");
    }

    httpserver_HTTP_Request_setCookie(request, "session-id", "");

    corto_logout(session_id);

    return corto_strdup("Logout success");
}

typedef struct httplogin_session_ctx {
    const char *cur_session;
    const char *prev_session;
    bool is_guest;
} httplogin_session_ctx;

uintptr_t httplogin_service_on_pre_request(
    httplogin_service this,
    httpserver_HTTP_Connection c,
    httpserver_HTTP_Request *r)
{
    const char *session_id = httpserver_HTTP_Request_getVar(
        r, "session_id");

    bool is_guest = false;

    if (!session_id || !session_id[0]) {
        session_id = httpserver_HTTP_Request_getCookie(r, "session-id");
    }

    if ((!session_id || !session_id[0]) && this->enable_guest) {
        session_id = corto_login("guest", "");
        if (!session_id) {
            corto_error("login-pre-request: guest account not found");
        } else {
            corto_ok("login-pre-request: logged in as guest");
            is_guest = true;
        }
    }

    if (session_id && session_id[0]) {
        httplogin_session_ctx *ctx = corto_alloc(sizeof(httplogin_session_ctx));
        ctx->cur_session = session_id;
        ctx->prev_session = corto_set_session(session_id);
        ctx->is_guest = is_guest;
        corto_ok("login-pre-request: set session to '%s'", session_id);
        return (uintptr_t)ctx;
    } else {
        return 0;
    }
}

void httplogin_service_on_post_request(
    httplogin_service this,
    httpserver_HTTP_Connection c,
    httpserver_HTTP_Request *r,
    uintptr_t ctx)
{
    httplogin_session_ctx *data = (httplogin_session_ctx*)ctx;

    /* If this was a guest login, logout session */
    if (data) {
        if (data->is_guest) {
            corto_ok("login-pre-request: logging out guest session");
            corto_logout(data->cur_session);
        }

        corto_ok("login-pre-request: restore session to '%s'", data->prev_session);
        corto_set_session(data->prev_session);

        free(data);
    }
}
