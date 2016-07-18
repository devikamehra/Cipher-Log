-- Copyright (C) Mashape, Inc.
local ffi = require "ffi"
local cjson = require "cjson"
local system_constants = require "lua_system_constants"
local basic_serializer = require "kong.plugins.log-serializers.basic"
local BasePlugin = require "kong.plugins.base_plugin"
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

local key = "testtesttesttest"
local key1 = "testtest"

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

function split(inputstr)
        local t={} ; i=1
        for str in string.gmatch(inputstr, "([^.]+)") do
                t[i] = str
                i = i + 1
        end
        return t
end

local function encryptBlowfish(plaintext)
        local blowfish = require "resty.nettle.blowfish"
	local bf = blowfish.new(key)
	if type(plaintext) ~= "string" then
        	plaintext = tostring(plaintext)
        end
        return base64.encode(bf:encrypt(plaintext))
end

local function encryptAES(plaintext)
        local aes = require "resty.nettle.aes"
        local ae = aes.new(key)
        if type(plaintext) ~= "string" then
                plaintext = tostring(plaintext)
        end
        return base64.encode(ae:encrypt(plaintext))
end

local function encryptDES(plaintext)
        local des = require "resty.nettle.des"
        local de = des.new(key1)
        if type(plaintext) ~= "string" then
                plaintext = tostring(plaintext)
        end
        return base64.encode(de:encrypt(plaintext))
end

local function encryptTwofish(plaintext)
        local twofish = require "resty.nettle.twofish"
        local tf = twofish.new(key)
        if type(plaintext) ~= "string" then
                plaintext = tostring(plaintext)
        end
        return base64.encode(tf:encrypt(plaintext))
end

local function encrypt(text)
  
  if algo == "aes128" or algo == "aes192" or algo == "aes256" then
  	return encryptAES(text)
  elseif algo == "blowfish" then
        return encryptBlowfish(text)
  elseif algo == "des" or algo == "des3" then
        return encryptDES(text)
  elseif algo == "twofish" then
        return encryptTwofish(text)
  else
        return encryptBlowfish(text)
  end
end

local function encryptAll(message)
	for key, value in pairs(message) do
                        message[key] = encrypt(message[key])
                        found = true
        end
end

local function explore(message, array, index)
  for key, value in pairs(message) do
  	if type(value) ~= "table" then
		if key == array[index] and index == table.getn(array) then
			message[key] = encrypt(message[key])

			found = true
		end
        else
		if key == array[index] then
    	           if index < table.getn(array) then
			 explore(value, array, index + 1)
		   elseif index == table.getn(array) then
			 encryptAll(value)			
		   end
		else
		    explore(value, array, index)
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

  algo = conf.cipher_tech
  
  ngx.log(ngx.ERR, "[cipher-log] failure", UTILS.get_hostname())
 
  local file_content = IO.read_file(conf.key_path)
  local file = io.open(conf.key_path, "r")
  if file ~= nil then
  	key = file:read()
	ngx.log(ngx.ERR, "[cipher-log] failure", key .. #key)
  else 
  	key = UTILS.random_string()
  end

  local y = conf.total_encrypt
  for z = 1, table.getn(y) do   
	found = false
	explore(message, split(y[z]), 1)
	if found == false then
		ngx.log(ngx.ERR, "[cipher-log] failure", "The property " .. y[z] .. " was not found. This could be a spelling error too.")
	end
  end

  local msg = cjson.encode(message).."\n"

  local fd = get_fd(conf.path)
  if not fd then
    fd = ffi.C.open(string_to_char(conf.path), oflags, mode)
    if fd < 0 then
      local errno = ffi.errno()
      ngx.log(ngx.ERR, "[cipher-log] failed to open the file: ", ffi.string(ffi.C.strerror(errno)))
    else
      set_fd(conf.path, fd)
    end
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
