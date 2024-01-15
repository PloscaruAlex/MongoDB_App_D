import std.conv;
import std.digest;
import std.digest.sha;
import std.stdio;

import vibe.d;
import vibe.web.auth;

import db_conn;

static struct AuthInfo
{
@safe:
    string userEmail;
}

@path("api/v1")
@requiresAuth
interface VirusTotalAPIRoot
{
    // Users management
    @noAuth
    @method(HTTPMethod.POST)
    @path("signup")
    Json addUser(string userEmail, string username, string password, string name = "", string desc = "");

    @noAuth
    @method(HTTPMethod.POST)
    @path("login")
    Json authUser(string userEmail, string password);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_user")
    Json deleteUser(string userEmail);

    // URLs management
    @anyAuth
    @method(HTTPMethod.POST)
    @path("add_url") // the path could also be "/url/add", thus defining the url "namespace" in the URL
    Json addUrl(string userEmail, string urlAddress);

    @noAuth
    @method(HTTPMethod.GET)
    @path("url_info")
    Json getUrlInfo(string urlAddress);

    @noAuth
    @method(HTTPMethod.GET)
    @path ("user_urls")
    Json getUserUrls(string userEmail);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_url")
    Json deleteUrl(string userEmail, string urlAddress);

    // Files management
    @anyAuth
    @method(HTTPMethod.POST)
    @path("add_file")
    Json addFile(string userEmail, immutable ubyte[] binData, string fileName);

    @noAuth
    @method(HTTPMethod.GET)
    @path("file_info")
    Json getFileInfo(string fileSHA512Digest);

    @noAuth
    @method(HTTPMethod.GET)
    @path("user_files")
    Json getUserFiles(string userEmail);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_file")
    Json deleteFile(string userEmail, string fileSHA512Digest);
}

class VirusTotalAPI : VirusTotalAPIRoot
{
    this(DBConnection dbClient)
    {
        this.dbClient = dbClient;
    }

    @noRoute AuthInfo authenticate(scope HTTPServerRequest req, scope HTTPServerResponse res)
    {
        // If "userEmail" is not present, an error 500 (ISE) will be returned
        string userEmail = req.json["userEmail"].get!string;
        string userAccessToken = dbClient.getUserAccessToken(userEmail);
        // Use headers.get to check if key exists
        string headerAccessToken = req.headers.get("AccessToken");
        if (headerAccessToken && headerAccessToken == userAccessToken)
            return AuthInfo(userEmail);
        throw new HTTPStatusException(HTTPStatus.unauthorized);
    }

override:

    Json addUser(string userEmail, string username, string password, string name = "", string desc = "")
    {
        // TODO

        DBConnection.UserRet u = dbClient.addUser(userEmail, username, password, name, desc);
        if (u == DBConnection.UserRet.ERR_NULL_PASS || u == DBConnection.UserRet.ERR_INVALID_EMAIL) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "Null pass or invalid email");
        }
        if (u == DBConnection.UserRet.ERR_USER_EXISTS) {
            throw new HTTPStatusException(HTTPStatus.unauthorized, "User already exists");
        }

        return serializeToJson("Congratulations! You added an user.");
    }

    Json authUser(string userEmail, string password)
    {
        // TODO

        DBConnection.UserRet u = dbClient.authUser(userEmail, password);
        if (u == DBConnection.UserRet.ERR_NULL_PASS || u == DBConnection.UserRet.ERR_INVALID_EMAIL) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "Null pass or invalid email");
        }

        if (u == DBConnection.UserRet.ERR_WRONG_USER || u == DBConnection.UserRet.ERR_WRONG_PASS) {
            throw new HTTPStatusException(HTTPStatus.unauthorized, "Wrong user or pass");
        }

        Json j = Json(["AccessToken": Json(dbClient.generateUserAccessToken(userEmail))]);
        return j;
    }

    Json deleteUser(string userEmail)
    {
        // TODO

        DBConnection.UserRet u = dbClient.deleteUser(userEmail);
        if (u == DBConnection.UserRet.ERR_INVALID_EMAIL) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "Invalid email");
        }

        return  serializeToJson("User deleted");
    }

    // URLs management

    Json addUrl(string userEmail, string urlAddress)
    {
        // TODO
        DBConnection.UrlRet u = dbClient.addUrl(userEmail, urlAddress);
        if (u == DBConnection.UrlRet.ERR_EMPTY_URL) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "Empty url");
        }

        return serializeToJson("Added url");
    }

    Json deleteUrl(string userEmail, string urlAddress)
    {
        // TODO
        if (urlAddress.length == 0) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "Empty url");
        }
        dbClient.deleteUrl(userEmail, urlAddress);

        return serializeToJson("Deleted url");
    }

    Json getUrlInfo(string urlAddress)
    {
        // TODO
        auto url = dbClient.getUrl(urlAddress);
        if (url.length == 0) {
            throw new HTTPStatusException(HTTPStatus.notFound, "Url not found");
        }
        
        return serializeToJson(url);
    }

    Json getUserUrls(string userEmail)
    {
        // TODO
        DBConnection.Url[] urls = dbClient.getUrls(userEmail);

        return serializeToJson(urls);
    }

    // Files management

    Json addFile(string userEmail, immutable ubyte[] binData, string fileName)
    {
        // TODO
        DBConnection.FileRet f = dbClient.addFile(userEmail, binData, fileName);
        if (f == DBConnection.FileRet.ERR_EMPTY_FILE) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "File empty");
        }

        return serializeToJson("File added");
    }

    Json getFileInfo(string fileSHA512Digest)
    {
        // TODO
        auto file = dbClient.getFile(fileSHA512Digest);
        if (file.length == 0) {
            throw new HTTPStatusException(HTTPStatus.notFound, "File not found");
        }

        return serializeToJson(file);
    }

    Json getUserFiles(string userEmail)
    {
        // TODO
        DBConnection.File[] files = dbClient.getFiles(userEmail);

        return serializeToJson(files);
    }

    Json deleteFile(string userEmail, string fileSHA512Digest)
    {
        // TODO
        if (fileSHA512Digest.length == 0) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "Digest empty");
        }

        dbClient.deleteFile(userEmail, fileSHA512Digest);
        return serializeToJson("File deleted");
    }

private:
    DBConnection dbClient;
}
