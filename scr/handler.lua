-- Copyright (C) Mashape, Inc.
local ffi = require "ffi"
local cjson = require "cjson"
local system_constants = require "lua_system_constants"
local basic_serializer = require "kong.plugins.log-serializers.basic"
local BasePlugin = require "kong.plugins.base_plugin"
local stringy = require "stringy"
local base64 = require "resty.nettle.base64"
local IO = require "kong.tools.io"
local UTILS = require "kong.tools.utils"

local ngx_timer = ngx.timer.at
local string_len = string.len
local O_CREAT = system_constants.O_CREAT()
local O_WRONLY = system_constants.O_WRONLY()
local O_APPEND = system_constants.O_APPEND()
local S_IRUSR = system_constants.S_IRUSR()
local S_IWUSR = system_constants.S_IWUSR()
local S_IRGRP = system_constants.S_IRGRP()
local S_IROTH = system_constants.S_IROTH()

local oflags = bit.bor(O_WRONLY, O_CREAT, O_APPEND)
local mode = bit.bor(S_IRUSR, S_IWUSR, S_IRGRP, S_IROTH)

ffi.cdef[[
int open(char * filename, int flags, int mode);
int write(int fd, void * ptr, int numbytes);
char *strerror(int errnum);
]]

-- fd tracking utility functions
local file_descriptors = {}

--[[
	Default values to variables.
]]--
local key = "testtesttesttest"
local algo = "blowfish"
local found = false

local function get_fd(conf_path)
  return file_descriptors[conf_path]
end

local function set_fd(conf_path, file_descriptor)
  file_descriptors[conf_path] = file_descriptor
end

local function string_to_char(str)
  return ffi.cast("uint8_t*", str)
end

-- iter : Function will take string array as a parameter which contains ':' in each string. 
-- It will return two string separated by ':' at a time.
-- Used to iterate all the string passed in partial_encrypt in log function.
-- @param `config_array` array whose strings need to be separated.
local function iter(config_array)
  return function(config_array, i, previous_name, previous_value)
    i = i + 1
    local current_pair = config_array[i]
    if current_pair == nil then -- n + 1
      return nil
    end
    local current_name, current_value = unpack(stringy.split(current_pair, ":"))
    return i, current_name, current_value  
  end, config_array, 0
end

-- split : Function will split a string conatining ".".
-- It will return a string array.
-- Used to split key name in total_encrypt and partial_encrypt.
-- @param `inputstr` string which we need to split.
function split(inputstr)
        local t={} ; i=1
        for str in string.gmatch(inputstr, "([^.]+)") do
                t[i] = str
                i = i + 1
        end
        return t
end

-- has_value : Function will delete a table entry if similar data is present in another table
-- It will not return anything
-- Used to delete redundancy data between total_encrypt and partial_encrypt.
-- @param `table` partial_encrypt table
-- @param `val` string to match
function has_value(table, val)
    for index, value in ipairs (table) do
        if string.match(value, val) then
	    ngx.log(ngx.ERR, "[cipher-log] failure", " Partial encryption of the field " .. table[index] .. " has been ignored due to redundancy.")
	    --array entry will be deleted.
	    table[index] = nil
        end
    end
end

-- encryptBlowfish : Function will encrypt data if cipher_tech is blowfish
-- It will return cipher_text
-- Used to encrypt data using Blowfish which is then Base64 encoded.
-- @param `plaintext` string to encrypt.
local function encryptBlowfish(plaintext)
        local blowfish = require "resty.nettle.blowfish"
	local bf = blowfish.new(key)
	if type(plaintext) ~= "string" then
        	plaintext = tostring(plaintext)
        end
        return base64.encode(bf:encrypt(plaintext))
end

-- encryptAES : Function will encrypt data if cipher_tech is aes128 or aes192 or aes256
-- It will return cipher_text
-- Used to encrypt data using AES which is then Base64 encoded.
-- @param `plaintext` string to encrypt.
local function encryptAES(plaintext)
        local aes = require "resty.nettle.aes"
        local ae = aes.new(key)
        if type(plaintext) ~= "string" then
                plaintext = tostring(plaintext)
        end
        return base64.encode(ae:encrypt(plaintext))
end

-- encryptDES : Function will encrypt data if cipher_tech is des or des3
-- It will return cipher_text
-- Used to encrypt data using DES which is then Base64 encoded.
-- @param `plaintext` string to encrypt.
local function encryptDES(plaintext)
        local des = require "resty.nettle.des"
        local de = des.new(key)
        if type(plaintext) ~= "string" then
                plaintext = tostring(plaintext)
        end
        return base64.encode(de:encrypt(plaintext))
end

-- encryptTwofish : Function will encrypt data if cipher_tech is twofish128 or twofish192 or twofish256
-- It will return cipher_text
-- Used to encrypt data using Twofish which is then Base64 encoded.
-- @param `plaintext` string to encrypt.
local function encryptTwofish(plaintext)
        local twofish = require "resty.nettle.twofish"
        local tf = twofish.new(key)
        if type(plaintext) ~= "string" then
                plaintext = tostring(plaintext)
        end
        return base64.encode(tf:encrypt(plaintext))
end

-- encrypt : Function will call respective encrypting method based on cipher_tech
-- Used to encrypt data in expore or explore_partial function
-- @param `text` string to encrypt.
local function encrypt(text)
  
  if algo == "aes128" or algo == "aes192" or algo == "aes256" then
  	return encryptAES(text)
  elseif algo == "blowfish" then
        return encryptBlowfish(text)
  elseif algo == "des" or algo == "des3" then
        return encryptDES(text)
  elseif algo == "twofish128" or algo == "twofish192" or algo == "twofish256" then
        return encryptTwofish(text)
  else
        return encryptBlowfish(text)
  end
end

-- encryptAll : Function will encrypt all the values
-- Used to encrypt all the data in array
-- @param `message` string array to encrypt.
local function encryptAll(message)
	for key, value in pairs(message) do
                        message[key] = encrypt(message[key])
                        found = true
        end
end

-- explore : Function will find data to be encrypted
-- Used to find data to be encrypted and call then encryption function
-- @param `message` string array having json data.
-- @param `array` string array returned by calling split function on key name string(s).
-- @param `index` part of the array that we need to find. 
local function explore(message, array, index)
  for key, value in pairs(message) do
  	if type(value) ~= "table" then
		--if key has the name with the string we are searching for and there is no sub-object that we want to encrypt.
		if key == array[index] and index == table.getn(array) then
			message[key] = encrypt(message[key])
			found = true
		end
        else
		--if key has the name with the string we are searching for.
		if key == array[index] then
		   --there is a sub-object after matching its super object, we move to the next.
    	           if index < table.getn(array) then
			 explore(value, array, index + 1)
		   --If super object matches and there is no more data to match, we encrypt the whole object. 
		   elseif index == table.getn(array) then
			 encryptAll(value)			
		   end
		else
		    --If find object in the sub-object
		    explore(value, array, index)
		end
        end
  end
end

-- explore_partial : Function will find data to be encrypted (for partial_encrypt array)
-- Used to find data to be encrypted and call then encryption function
-- @param `message` string array having json data.
-- @param `array` string array returned by calling split function on key name string(s).
-- @param `index` part of the array that we need to find.
-- @param `regex` regular expression to find exact string to encrypt
local function explore_partial(message, array, index, regex)
  for key, value in pairs(message) do
        if type(value) ~= "table" then
		--if key has the name with the string we are searching for and there is no sub-object that we want to encrypt.
                if key == array[index] and index == table.getn(array) then
                        local whole_text = message[key]
                        local result = whole_text
			local count = 0
			if not regex then
				gx.log(ngx.ERR, "[cipher-log] failure", " The regex has not been specified.")
			else
				for word in string.gmatch(whole_text, regex) do
					count = count + 1
					--text is surrounded by delimiters.
					local encrypt = "#$" .. encrypt(word) .. "$#"
                        		result = string.gsub(result, word, encrypt)
				end
			end
			--if regex gives no string.
			if count == 0 then
				ngx.log(ngx.ERR, "[cipher-log] failure", " The regex [" .. regex .. "] did not yield any results for the specified property - " .. key)
			end
                        message[key] = result
                        found = true
                end
        else
		--if key has the name with the string we are searching for.
                if key == array[index] then
                   --there is a sub-object after matching its super object, we move to the next.
		   if index < table.getn(array) then
                         explore_partial(value, array, index + 1, regex)
                   --If super object matches and there is no more data to match, error issued.
                   elseif index == table.getn(array) then
                         ngx.log(ngx.ERR, "[cipher-log] failure", "Partial encryption cannot be applied to " .. array[index])
                   end
                else
		    --If find object in the sub-object
                    explore_partial(value, array, index, regex)
                end
        end
  end
end


-- Log to a file. Function used as callback from an nginx timer.
-- @param `premature` see OpenResty `ngx.timer.at()`
-- @param `conf`     Configuration table, holds http endpoint details
-- @param `message`  Message to be logged
local function log(premature, conf, message)
  if premature then return end

  local total = conf.total_encrypt
  local partial = conf.partial_encrypt  
 
  --remove redundancy
  for z = 1, table.getn(total) do
	has_value(partial, total[z])	
  end
  
  --check total table
  for z = 1, table.getn(total) do   
	found = false
	explore(message, split(total[z]), 1)
	if found == false then
		ngx.log(ngx.ERR, "[cipher-log] failure", "The property " .. total[z] .. " was not found. This could be a spelling error too.")
	end
  end
  
  --check partial table
  for _, name, value in iter(partial) do
        found = false
        explore_partial(message, split(name), 1, value)
        if found == false then
                ngx.log(ngx.ERR, "[cipher-log] failure", "The property " .. name .. " was not found. This could be a spelling error too.")
        end
  end

  --lua table to json conversion
  local msg = cjson.encode(message).."\n"

  local fd = get_fd(conf.path)
  if not fd then
    fd = ffi.C.open(string_to_char(conf.path), oflags, mode)
    if fd < 0 then
      local errno = ffi.errno()
      ngx.log(ngx.ERR, "[cipher-log] failed to open the file: ", ffi.string(ffi.C.strerror(errno)))
    else
      --algo and key are configured once
      algo = conf.cipher_tech
      local file
      if conf.key_path_gen then
          file = io.open(conf.key_path_gen, "r")
      else
          file = io.open(conf.key_path, "r")
      end
      key = file:read()
      set_fd(conf.path, fd)
    end
  end

-- To be made configuarable
--Log rolling done when 10Mb has been logged
  local max_size = 1024 * 1024 * 10
  local size = IO.file_size(conf.path)
  if size > max_size then
	--find directory
        local directory_path = string.sub(conf.path, 0, string.find(conf.path, "/[^/]*$"))
	--find file name
	local file_path = string.sub(conf.path, string.find(conf.path, "/[^/]*$") + 1, #conf.path)
	--construct new file name
	local new_file_name = string.sub(file_path, 0, string.find(file_path, ".[^.]*$") - 1) .. "_" .. os.time() .. string.sub(file_path, string.find(file_path, ".[^.]*$"), #file_path) 
	--construct new file path
	local new_file_path = directory_path .. new_file_name
	--creating new file
	os.execute("touch " .. new_file_path)
	--writing old logs in the new file
	local file_old = io.open(conf.path, "r")
	local file_new = io.open(new_file_path, "a")
	file_new:write(file_old:read("*a"))
	file_old:close()
	file_new:close()
	--deleting old logs
	os.execute("echo -n > " .. conf.path)
  end
  ffi.C.write(fd, string_to_char(msg), string_len(msg))
end

local CipherLogHandler = BasePlugin:extend()

CipherLogHandler.PRIORITY = 1

function CipherLogHandler:new()
  CipherLogHandler.super.new(self, "cipher-log")
end

function CipherLogHandler:log(conf)
  CipherLogHandler.super.log(self)
  local message = basic_serializer.serialize(ngx)

  local ok, err = ngx_timer(0, log, conf, message)
  if not ok then
    ngx.log(ngx.ERR, "[cipher-log] failed to create timer: ", err)
  end

end

return CipherLogHandler
