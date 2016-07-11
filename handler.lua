-- Copyright (C) Mashape, Inc.
local ffi = require "ffi"
local cjson = require "cjson"
local system_constants = require "lua_system_constants"
local basic_serializer = require "kong.plugins.log-serializers.basic"
local BasePlugin = require "kong.plugins.base_plugin"
local blowfish = require "resty.nettle.blowfish"

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

local bf = blowfish.new("testtesttesttest")

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

local function changeLog(conf, message, str)
  ngx.log(ngx.ERR, "[file-log] success", str)
  local string
  for key, value in pairs(message) do
	if type(value) == "string" then
		ngx.log(ngx.ERR, "[cipher-log] success", value)
	end
  end
  ngx.log(ngx.ERR, "[cipher-log] success", string)
end

local function explore(conf, message, str)
  for key, value in pairs(message) do
  	if type(value) ~= "table" then
		if key == str then
			local plaintext = message[key]
			if type(plaintext) ~= "string" then
                        	plaintext = tostring(plaintext)
                	end
			message[key] = bf:encrypt(plaintext)
			found = true
		end
        else
                explore(conf, value, str)
        end
  end
end
-- Log to a file. Function used as callback from an nginx timer.
-- @param `premature` see OpenResty `ngx.timer.at()`
-- @param `conf`     Configuration table, holds http endpoint details
-- @param `message`  Message to be logged
local function log(premature, conf, message)
  if premature then return end

  local y = conf.cipher
  for z = 1, table.getn(y) do   
	found = false
	explore(conf, message, y[z])
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
