module OAuth
  module Signature
    def self.available_methods
      @available_methods ||= {}
    end

    def self.build(request, &block)
      request = OAuth::RequestProxy.proxy(request)
      klass = available_methods[request.signature_method.downcase]
      raise UnknownSignatureMethod, request.signature_method unless klass
      klass.new(request, &block)
    end

    def self.sign(request, &block)
      self.build(request, &block).signature
    end

    def self.verify(request, &block)
      self.build(request, &block).verify
    end

    class UnknownSignatureMethod < Exception; end
  end
end
