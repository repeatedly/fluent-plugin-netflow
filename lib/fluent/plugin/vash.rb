module Fluent
  module Plugin
    class NetflowParser < Parser
      # https://gist.github.com/joshaven/184837
      class Vash < Hash
        def initialize(constructor = {})
          @register ||= {}
          if constructor.is_a?(Hash)
            super()
            merge(constructor)
          else
            super(constructor)
          end
        end

        alias_method :regular_writer, :[]= unless method_defined?(:regular_writer)
        alias_method :regular_reader, :[] unless method_defined?(:regular_reader)

        def [](key)
          sterilize(key)
          clear(key) if expired?(key)
          regular_reader(key)
        end

        def []=(key, *args)
          if args.length == 2
            value, ttl = args[1], args[0]
          elsif args.length == 1
            value, ttl = args[0], 60
          else
            raise ArgumentError, "Wrong number of arguments, expected 2 or 3, received: #{args.length+1}\n"+
              "Example Usage:  volatile_hash[:key]=value OR volatile_hash[:key, ttl]=value"
          end
          sterilize(key)
          ttl(key, ttl)
          regular_writer(key, value)
        end

        def merge(hsh)
          hsh.map {|key,value| self[sterile(key)] = hsh[key]}
          self
        end

        def cleanup!
          now = Time.now.to_i
          @register.map {|k,v| clear(k) if v < now}
        end

        def clear(key)
          sterilize(key)
          @register.delete key
          self.delete key
        end

        private

        def expired?(key)
          Time.now.to_i > @register[key].to_i
        end

        def ttl(key, secs=60)
          @register[key] = Time.now.to_i + secs.to_i
        end

        def sterile(key)
          String === key ? key.chomp('!').chomp('=') : key.to_s.chomp('!').chomp('=').to_sym
        end

        def sterilize(key)
          key = sterile(key)
        end
      end
    end
  end
end
