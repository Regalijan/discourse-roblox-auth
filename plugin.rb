# frozen_string_literal: true

# name: discourse-roblox-auth
# about: Allows users to sign in with their Roblox account
# version: 0.0.1
# author: Wolftallemo
# url: https://github.com/Wolftallemo/discourse-roblox-auth

enabled_site_setting :enable_roblox_logins

require 'base64'
require 'net/http'
require_relative 'lib/validators/EnableRobloxOpenCloudOAuth'

class Auth::RobloxAuthenticator < Auth::ManagedAuthenticator
  class RobloxStrategy < OmniAuth::Strategies::OAuth2
    option :name, 'roblox'
    option :scope, 'openid profile email'

    option :client_options,
           site: 'https://apis.roblox.com/oauth/',
           authorize_url: 'https://authorize.roblox.com/',
           token_url: 'https://apis.roblox.com/oauth/v1/token'

    option :authorize_options, 'scope'

    uid { raw_info['sub'] }

    info do
      {
        name: raw_info['nickname'],
        email: "#{SecureRandom.hex(24)}@notreal.invalid",
        image: retrieve_image
      }
    end

    def callback_url
      full_host + script_name + callback_path
    end

    def retrieve_image
      uri = URI('https://thumbnails.roblox.com/v1/users/avatar-headshot')
      uri.query = URI.encode_www_form({
                                        userIds: raw_info['sub'],
                                        size: '720x720',
                                        format: 'Png',
                                        isCircular: 'false'
                                      })

      res = Net::HTTP.get_response(uri)

      return nil unless res.is_a?(Net::HTTPSuccess)

      JSON.parse(res.body).data.first.imageUrl
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
