# README #

The plugin currently expects 2 parameters
> 1. path : The location of the file where we expect to keep our file-logs
> 2. cipher : This is an array. All the properties that we want to encrypt can be passed here.

Future goals
> 1. If someone passes header of the property(for example, request), the whole block is encrypted.
> 2. A specific sub-property can be written as request.size and thus size property of request block will only be encrypted.
> 3. Partial encryption using regex.