# frozen_string_literal: true

# name: discourse-roblox-auth
# about: Allows users to sign in with their Roblox account
# version: 0.0.1
# author: Wolftallemo
# url: https://github.com/Regalijan/discourse-roblox-auth

enabled_site_setting :enable_roblox_logins

require 'base64'
require 'net/http'
require_relative 'lib/validators/EnableRobloxOpenCloudOAuth'

class RobloxAuthenticator < Auth::ManagedAuthenticator
  class RobloxStrategy < OmniAuth::Strategies::OAuth2
    option :name, 'roblox'
    option :scope, 'openid profile'

    option :client_options,
           site: 'https://apis.roblox.com/oauth/v1/',
           authorize_url: 'authorize',
           token_url: 'token'

    option :authorize_options, %i[scope]

    uid { raw_info['sub'] }

    info do
      {
        name: raw_info['nickname'],
        image: raw_info['picture']
      }
    end

    def callback_url
      full_host + script_name + callback_path
    end

    def raw_info
      @raw_info ||= JSON.parse(
        Base64.urlsafe_decode64(
          access_token['id_token'].split('.')[1]
        )
      )
    end
  end

  def name
    'roblox'
  end

  def enabled?
    SiteSetting.enable_roblox_logins?
  end

  def register_middleware(omniauth)
    omniauth.provider RobloxStrategy,
                      setup: lambda { |env|
                        strategy = env['omniauth.strategy']
                        strategy.options[:client_id] = SiteSetting.roblox_client_id
                        strategy.options[:client_secret] = SiteSetting.roblox_secret
                      }
  end
end

auth_provider authenticator: RobloxAuthenticator.new
