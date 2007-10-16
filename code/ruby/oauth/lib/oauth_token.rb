module OAuth
  class Token
    attr_accessor :token, :secret

    def initialize(token, secret)
      @token = token
      @secret = secret
    end
  end
end
