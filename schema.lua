local IO = require "kong.tools.io"
local Errors = require "kong.dao.errors"
local utils = require "kong.tools.utils"

local ALLOWED_ENCRYPTION_TECHNIQUE = { "aes128", "aes192", "aes256", "blowfish", "des", "des3", "twofish" }

local function validate_file(value)
  local exists = IO.file_exists(value)
  if not os.execute("touch "..value) == 0 then
    return false, "Cannot create a file in the path specified. Make sure the path is valid, and Kong has the right permissions"
  end

  if not exists then
    os.remove(value) -- Remove the created file if it didn't exist before
  end

  return true
end

local function validate_key_file(value) 
   if value ~= "" then
   	local file = IO.read_file(value)
	if file == nil then 
		return false, "Cannot find a file with the key in the path specified. Make sure the path is valid, and Kong has the right permissions" 
   	end
   end
   return true
end

local function create_key_file(value)
  local exists = IO.file_exists(value)
  if not os.execute("touch "..value) == 0 then
    return false, "Cannot create a file in the path " .. value .. ". Make sure Kong has the right permissions to create an file for storing key."
  end
  return true
end

return {
  fields = {
    path = { required = true, type = "string", func = validate_file },
    cipher_tech = { type = "string", enum = ALLOWED_ENCRYPTION_TECHNIQUE, default = "blowfish" },
    total_encrypt = { type = "array", default = {}},
    partial_encrypt = {type = "array", default={}},    
    key_path = { type = "string", func = validate_key_file, default = ""}
  },
  self_check = function(schema, plugin_t, dao, is_update)
	if plugin_t.key_path ~= "" then  	
		--Extra 1 character in each test condition is added for the null character.
		if plugin_t.cipher_tech == "aes256" and #IO.read_file(plugin_t.key_path) ~= 33 then
                        return false, Errors.schema "While using AES256 Encryption, key length of 32 is required."
		elseif plugin_t.cipher_tech == "aes192" and #IO.read_file(plugin_t.key_path) ~= 25 then
                        return false, Errors.schema "While using AES192 Encryption, key length of 24 is required."
		elseif plugin_t.cipher_tech == "aes128" and #IO.read_file(plugin_t.key_path) ~= 17 then
                        return false, Errors.schema "While using AES128 Encryption, key length of 16 is required."
		elseif plugin_t.cipher_tech == "des" and #IO.read_file(plugin_t.key_path) ~= 9 then
			return false, Errors.schema "While using DES Encryption, key length of 8 is required."
		elseif plugin_t.cipher_tech == "des3" and #IO.read_file(plugin_t.key_path) ~= 25 then
                	return false, Errors.schema "While using DES3 Encryption, key length of 24 is required."
		end
	else
		local name_of_file = "/tmp/cipher_log_key_" .. utils.get_hostname()
		create_key_file(name_of_file)
 		local file = io.open(name_of_file, "w+")
		local key = utils.random_string()
		if plugin_t.cipher_tech == "aes192" or plugin_t.cipher_tech == "des3" then
			file:write(string.sub(key, 1, 24))
		elseif plugin_t.cipher_tech == "aes128" then
			file:write(string.sub(key, 1, 16))
		elseif plugin_t.cipher_tech == "des" then
			file:write(string.sub(key, 1, 8))
		else
			file:write(key)
		end
		file:close()
	end
	return true
  end
}
