module OAuth
  module Signature
    def self.available_methods
      @available_methods ||= {}
    end

    def self.sign(request)
      klass = available_methods[request.signature_method.downcase]
      raise UnknownSignatureMethod, request.signature_method unless klass
      klass.new(request).signature
    end

    class UnknownSignatureMethod < Exception; end
  end
end
