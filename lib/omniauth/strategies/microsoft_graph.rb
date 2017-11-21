require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class MicrosoftGraph < OmniAuth::Strategies::OAuth2

      option :name, :microsoft_graph

      option :client_options, {
        site:          'https://login.microsoftonline.com/',
        token_url:     'common/oauth2/v2.0/token',
        authorize_url: 'common/oauth2/v2.0/authorize'
      }

      option :authorize_params, {
      }

      option :scope, "https://graph.microsoft.com/User.Read"

      option :request_chat_access_token, false

      uid { raw_info["id"] }

      info do
        {
          'email' => raw_info["mail"],
          'first_name' => raw_info["givenName"],
          'last_name' => raw_info["surname"],
          'name' => [raw_info["givenName"], raw_info["surname"]].join(' '),
          'nickname' => raw_info["displayName"],
          'org_info' => org_info,
          'org_display_name' => org_info["value"].blank? ? nil : org_info["value"][0]["displayName"],
          'org_id' => org_info["value"].blank? ? nil : org_info["value"][0]["id"],
          'chat_access_token' => options[:request_chat_access_token] ? chat_access_token['access_token'] : nil,
          'chat_access_token_expires_in' => options[:request_chat_access_token] ? chat_access_token['expires_in'] : nil,
        }
      end

      extra do
        {
          'raw_info' => raw_info,
          'params' => access_token.params
        }
      end

      def raw_info
        @raw_info ||= access_token.get('https://graph.microsoft.com/v1.0/me').parsed
      end

      def org_info
        @org_info ||= access_token.get('https://graph.microsoft.com/v1.0/organization?$select=id,displayName').parsed
      end

      def chat_access_token
        @chat_access_token ||= begin
          response = RestClient.post(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            {
              client_id: options.client_id,
              client_secret: options.client_secret,
              grant_type: "client_credentials",
              # scope: "https://graph.microsoft.com/.default",
              scope: "https://api.botframework.com/.default",
            }
          )
          raise ::OAuth2::Error.new(response) if response.code != 200
          JSON.parse(response.body)
        end
      end

      def callback_url
        options[:callback_url] || full_host + script_name + callback_path
      end
    end
  end
end
