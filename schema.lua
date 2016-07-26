local IO = require "kong.tools.io"
local Errors = require "kong.dao.errors"
local utils = require "kong.tools.utils"
local timestamp = require "kong.tools.timestamp"

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
		if os.execute( "cd " .. value ) == 0 then
			return true, "Creating key in specified path."
		end
		return false, "Cannot find a file with the key in the path specified. Make sure the path is valid, and Kong has the right permissions"
   	end
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
		local path = plugin_t.key_path

		if os.execute( "cd " .. path ) == 0 then
			local name_of_file = "cipher_log_key_" .. os.time()
        
                	if not os.execute("cd " .. path) == 0 then
                      		return false, "Cannot create a file in the path "..path..". Make sure Kong has the right permissions to create an file for storing key."
                	else
				os.execute("touch " .. name_of_file)
			end
			if string.find(path, "/", #path) then			
				path = path .. name_of_file
			else
				path = path .. "/" .. name_of_file
			end
                	local file = io.open(path, "w+")
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
                	plugin_t.key_path_gen = path
		else	
		
			--Extra 1 character in each test condition is added for the null character.
			if plugin_t.cipher_tech == "aes256" and #IO.read_file(path) ~= 33 then
                        	return false, Errors.schema "While using AES256 Encryption, key length of 32 is required."
			elseif plugin_t.cipher_tech == "aes192" and #IO.read_file(path) ~= 25 then
                        	return false, Errors.schema "While using AES192 Encryption, key length of 24 is required."
			elseif plugin_t.cipher_tech == "aes128" and #IO.read_file(path) ~= 17 then
                        	return false, Errors.schema "While using AES128 Encryption, key length of 16 is required."
			elseif plugin_t.cipher_tech == "des" and #IO.read_file(path) ~= 9 then
				return false, Errors.schema "While using DES Encryption, key length of 8 is required."
			elseif plugin_t.cipher_tech == "des3" and #IO.read_file(path) ~= 25 then
                		return false, Errors.schema "While using DES3 Encryption, key length of 24 is required."
			end
		end
	else
		if utils.table_size(plugin_t.total_encrypt) > 0 or utils.table_size(plugin_t.partial_encrypt) > 0 then
			return false, Errors.schema "Key path is mandatory for encryption. Specify the path of a directory to save an auto-generated key or specify the key path."
		end
--[[
		local a = os.execute("cd ../../cipher_log_keys")
		if a ~= 0 then
     			os.execute("mkdir ../../cipher_log_keys")
		end
		local exists = IO.file_exists("/cipher_log_keys")
		if not os.execute("cd ../../cipher_log_keys") == 0 then
			os.execute("mkdir ../../cipher_log_keys/")
		end

		if not exists then
       			 return false, "Error"
			--os.execute("mkdir ".."../../cipher_log/")
		else
			return false, "Error_1"
  		end

		local name_of_file = "../../cipher_log_keys/key_" .. os.clock()
	
 		if not os.execute("touch " .. name_of_file) == 0 then
   		      return false, "Cannot create a file in the path " .. name_of_file .. ". Make sure Kong has the right permissions to create an file for storing key."
  		end
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
		plugin_t.key_path_gen = name_of_file
]]--
	end
	
	return true
  end
}
