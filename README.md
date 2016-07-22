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
| zebra stripes | are neat      |