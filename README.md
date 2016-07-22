# Cipher-Log #

Add encrypted logs to the disk.

### Configuration

Configuration of this plugin is easy to use. You can easily add it on the top of your API by executing the following request on your Kong server:

```sh
$ curl -X POST http://kong:8001/apis/{api}/plugins \
    --data "name=cipher-log" \
    --data "config.path=/tmp/file.log"
    --data "cipher_tech=blowfish"
    --data "total_encrypt=request.headers,api.id"
    --data "partial_encrypt=request.request_uri:%%d%+"
    --data "key_path=/path/to/your/key"
```
**api**: The **id** or **name** of the API that this plugin configuration will target

| Form Parameter| Description           | 
| ------------- |:-------------:| 
| name          | The name of the plugin in this case is, **cipher-log** | 
| config.path   | The file path of the output log file. The plugin will create the file if it doesn't exist yet. Make sure Kong has write permissions to this file.      |  
| cipher_tech | The encryption algorithm to be used for encryption. The encrypted data is then base64 encoded. Currently the plugin supports the following encryption algorithms: AES128, AES192, AES256, Blowfish, DES, DES3, Twofish.|
| total_encrypt | The json properties that need to be totally encrypted are listed here separated by comma(,). To move into the hierarchy of the properties we can use '.' and thus encrypt that particular sub-property. Encryption of the whole object is also passible. |
| partial_encrypt | The json properties that need to be partially encrypted are listed here separated by comma(,). You can specify the property and the Regular Expression (separated by :) to encrypt a specific portion only.|
| key_path | The path to the key is specified here and should be kept save. Length of the key should be in accordance with the encryption algorithm used.  Make sure Kong has read permissions to this file.|
| key_path_gen | The path to the file containing an auto-generated key is specified here in case the *key_path* has not been specified. The key should be key kept safe.|

### Log Format

Every request will be logged separately in a JSON object separated by a new line *\n*, with the following format:

```sh
{
    "request": {
        "method": "GET",
        "uri": "/get",
        "size": "75",
        "request_uri": "http://httpbin.org:8000/get",
        "querystring": {},
        "headers": {
            "accept": "*/*",
            "host": "httpbin.org",
            "user-agent": "curl/7.37.1"
        }
    },
    "response": {
        "status": 200,
        "size": "434",
        "headers": {
            "Content-Length": "197",
            "via": "kong/0.3.0",
            "Connection": "close",
            "access-control-allow-credentials": "true",
            "Content-Type": "application/json",
            "server": "nginx",
            "access-control-allow-origin": "*"
        }
    },
    "authenticated_entity": {
        "consumer_id": "80f74eef-31b8-45d5-c525-ae532297ea8e",
        "created_at":   1437643103000,
        "id": "eaa330c0-4cff-47f5-c79e-b2e4f355207e",
        "key": "2b64e2f0193851d4135a2e885cd08a65"
    },
    "api": {
        "request_host": "test.com",
        "upstream_url": "http://mockbin.org/",
        "created_at": 1432855823000,
        "name": "test.com",
        "id": "fbaf95a1-cd04-4bf6-cb73-6cb3285fef58"
    },
    "latencies": {
        "proxy": 1430,
        "kong": 9,
        "request": 1921
    },
    "started_at": 1433209822425,
    "client_ip": "127.0.0.1"
}
```
A few considerations on the above JSON object:

1. **request contains properties about the request sent by the client
2. **response contains properties about the response sent to the client
3. **api contains Kong properties about the specific API requested
4. **authenticated_entity contains Kong properties about the authenticated consumer (if an authentication plugin has been enabled)
5. **latencies contains some data about the latencies involved:
> 1. **proxy is the time it took for the final service to process the request
> 2. **kong is the internal Kong latency that it took to run all the plugins
> 3. **request is the time elapsed between the first bytes were read from the client and after the last bytes were sent to the client. Useful for detecting slow clients.

### Kong Process Errors

This logging plugin will only log HTTP request and response data. If you are looking for the Kong process error file (which is the nginx error file), then you can find it at the following path: **{[nginx_working_dir](https://getkong.org/docs/0.8.x/configuration/#nginx_working_dir)}/logs/error.log**