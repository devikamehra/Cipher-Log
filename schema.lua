local IO = require "kong.tools.io"

local ALLOWED_ENCRYPTION_TECHNIQUE = { "aes", "blowfish", "des", "twofish" }

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
  local exists = IO.file_exists(value)
  if not os.execute("touch "..value) == 0 then
    return false, "Cannot read the key file in the path specified. Make sure the path is valid, and Kong has the right permissions"
  end
  return true
end

return {
  fields = {
    path = { required = true, type = "string", func = validate_file },
    cipher_tech = { type = "string", enum = ALLOWED_ENCRYPTION_TECHNIQUE, default = "blowfish" },
    total_encrypt = { type = "array", default = {}},
    key_path = { type = "string", func = validate_key_file }
  },
  self_check = function(schema, plugin_t, dao, is_update)
  	return true
  end
}
