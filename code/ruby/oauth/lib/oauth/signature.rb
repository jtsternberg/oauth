module OAuth
  module Signature
    def self.available_methods
      @available_methods ||= {}
    end

    def self.sign(request, &block)
      klass = available_methods[request.signature_method.downcase]
      raise UnknownSignatureMethod, request.signature_method unless klass
      klass.new(request, &block).signature
    end

    def self.verify(request, &block)
      self.sign(request, &block).verify
    end

    class UnknownSignatureMethod < Exception; end
  end
end
