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

function split(inputstr)
        local t={} ; i=1
        for str in string.gmatch(inputstr, "([^.]+)") do
                t[i] = str
                i = i + 1
        end
        return t
end

function has_value (table, val)
    for index, value in ipairs (table) do
        if string.match(value, val) then
	    ngx.log(ngx.ERR, "[cipher-log] failure", " Partial encryption of the field " .. table[index] .. " has been ignored due to duplicacy.")
	    table[index] = nil
        end
    end
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
        local de = des.new(key)
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
  elseif algo == "twofish128" or algo == "twofish192" or algo == "twofish256" then
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

local function explore_partial(message, array, index, regex)
  for key, value in pairs(message) do
        if type(value) ~= "table" then
                if key == array[index] and index == table.getn(array) then
                        local whole_text = message[key]
                        local result = whole_text
			local count = 0
			for word in string.gmatch(whole_text, regex) do
				count = count + 1
				local encrypt = "#$" .. encrypt(word) .. "$#"
                        	result = string.gsub(result, word, encrypt)
			end
			if count == 0 then
				ngx.log(ngx.ERR, "[cipher-log] failure", " The regex [" .. regex .. "] did not yield any results for the specified property - " .. key)
			end
                        message[key] = result
                        found = true
                end
        else
                if key == array[index] then
                   if index < table.getn(array) then
                         explore_partial(value, array, index + 1, regex)
                   elseif index == table.getn(array) then
                         ngx.log(ngx.ERR, "[cipher-log] failure", "Partial encryption cannot be applied to " .. array[index])
                   end
                else
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

  for z = 1, table.getn(total) do
	has_value(partial, total[z])	
  end

  for z = 1, table.getn(total) do   
	found = false
	explore(message, split(total[z]), 1)
	if found == false then
		ngx.log(ngx.ERR, "[cipher-log] failure", "The property " .. total[z] .. " was not found. This could be a spelling error too.")
	end
  end

  for _, name, value in iter(partial) do
        found = false
        explore_partial(message, split(name), 1, value)
        if found == false then
                ngx.log(ngx.ERR, "[cipher-log] failure", "The property " .. name .. " was not found. This could be a spelling error too.")
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
  local max_size = 1024 * 1024
  local file = io.open(conf.path, "a")
  file:seek("set", 0)
  local size = IO.file_size(conf.path)
  if size > max_size then
  	IO.os_execute("echo -n > " .. conf.path)
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
