# frozen_string_literal: true

class ValidateEnable
  def initialize(opts = {})
    @opts = opts
  end

  def valid_value?(val)
    return true if !SiteSetting.enable_roblox_logins?

    !val.empty?
  end

  def error_message
    I18n.t('discourse_roblox_auth.errors.cannot_remove')
  end
end