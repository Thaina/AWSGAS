function InvokeLambda(access_key, secret_key, func, data, query, headers) {
    var path = "/2015-03-31/functions/" + func + "/invocations";
    if (!query)
        query = "";

    if (!headers)
        headers = {};
    if (!headers["x-amz-invocation-type"])
        headers["x-amz-invocation-type"] = "RequestResponse";

    return AWS(access_key, secret_key, "POST", "lambda",
        "ap-northeast-1", "/2015-03-31/functions/" + func + "/invocations",
        query, headers, JSON.stringify(data));
}

function AWS(access_key, secret_key, method, service, region, path, query, headers, payload) {

    var date = new Date();
    var dateStamp = Utilities.formatDate(date, "GMT", "yyyyMMdd");

    if (!headers)
        headers = {};

    headers["host"] = service + "." + region + ".amazonaws.com";
    if (!headers["content-type"])
        headers["content-type"] = "application/x-amz-json-1.0";
    headers["x-amz-date"] = dateStamp + "T" + Utilities.formatDate(date, "GMT", "HHmmss") + "Z";

    var headerKeys = Object.keys(headers).sort(function(l, r) {
        return l.localeCompare(r);
    });
    var canonical_headers = headerKeys.filter(function(key) {
        return key == "content-type" || key == "host" || key.indexOf("x-amz-") == 0;
    }).map(function(key) {
        return key + ":" + headers[key] + "\n";
    }).join("");

    var signed_headers = headerKeys.join(";");

    var signing_key = [dateStamp, region, service, "aws4_request"].reduce(Compute, ByteToHex(ToByte("AWS4" + secret_key)));

    var canonical_request = method + '\n' + path + '\n' + query + '\n' + canonical_headers + '\n' + signed_headers + '\n' + ByteToHex(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, payload));

    Logger.log("\n" + canonical_request + "\n");

    var algorithm = 'AWS4-HMAC-SHA256'
    var credential_scope = dateStamp + '/' + region + '/' + service + '/' + 'aws4_request'
    var string_to_sign = algorithm + '\n' + headers["x-amz-date"] + '\n' + credential_scope + '\n' + ByteToHex(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, canonical_request));
    Logger.log("\n" + string_to_sign + "\n");

    headers["Authorization"] = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + Compute(signing_key, string_to_sign)

    Logger.log("Authorization\n" + headers["Authorization"]);
    var url = "https://" + headers["host"] + path;
    delete headers["host"];

    return UrlFetchApp.fetch(url, {
        method: method,
        payload: payload,
        headers: headers,
        muteHttpExceptions: true
    });
}

function ToByte(s) {
    var arr = s.split("");
    for (var i in arr)
        arr[i] = s.charCodeAt(i);
    return arr;
}

function ByteToHex(arr) {
    return arr.map(function(b) {
        var res = (b >= 0 ? b : (256 + b)).toString(16);
        return res.length < 2 ? "0" + res : res;
    }).join("");
}

function Compute(key, value) {
    var sha = new jsSHA("SHA-256", "TEXT");
    sha.setHMACKey(key, "HEX");
    sha.update(value);
    return sha.getHMAC("HEX");
}
