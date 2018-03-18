/* This is a managed file. Do not delete this comment. */

#include <corto/httplogin/httplogin.h>

corto_string httplogin_service_login(
    httplogin_service this,
    httpserver_HTTP_Request *request,
    httplogin_login *data)
{
    const char *username = httpserver_HTTP_Request_getVar(request, "username");
    const char *password = httpserver_HTTP_Request_getVar(request, "password");

    if (!username) {
        httpserver_HTTP_Request_badRequest(request, "no username provided");
        return NULL;
    }

    const char *session_id = corto_login(username, password);
    if (!session_id) {
        httpserver_HTTP_Request_badRequest(request, "invalid login");
    }

    /* Set session-id in cookie on the client */
    httpserver_HTTP_Request_setCookie(request, "session-id", session_id);

    return "Success";
}

corto_string httplogin_service_logout(
    httplogin_service this,
    httpserver_HTTP_Request *request,
    httplogin_logout *data)
{
    const char *session_id = httpserver_HTTP_Request_getVar(request, "session_id");
    if (!session_id) {
        session_id = httpserver_HTTP_Request_getCookie(request, "session-id");
    }

    httpserver_HTTP_Request_setCookie(request, "session-id", NULL);

    corto_logout(session_id);

    return "Success";
}
