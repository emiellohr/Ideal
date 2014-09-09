module Ideal

  class Merchant
    # Returns the current acquirer used
    attr_reader :acquirer

    # Holds the environment in which the run (default is test)
    attr_accessor :environment

    # Holds the global iDEAL merchant id. Make sure to use a string with
    # leading zeroes if needed.
    attr_accessor :merchant_id

    # Holds the passphrase that should be used for the merchant private_key.
    attr_accessor :passphrase

    # Holds the test and production urls for your iDeal acquirer.
    attr_accessor :live_url, :test_url

    # Returns the merchant `subID' being used for this Gateway instance.
    # Defaults to 0.
    attr_reader :sub_id

    # Initializes a new Gateway instance.
    #
    # You can optionally specify <tt>:sub_id</tt>. Defaults to 0.
    def initialize(options = {})
      @sub_id = options[:sub_id] || 0
      # Environment defaults to test
      @environment = :test
    end

    # Loads the global merchant private_key from disk.
    def private_key_file=(pkey_file)
      self.private_key = File.read(pkey_file)
    end

    # Instantiates and assings a OpenSSL::PKey::RSA instance with the
    # provided private key data.
    def private_key=(pkey_data)
      @private_key = OpenSSL::PKey::RSA.new(pkey_data, passphrase)
    end

    # Returns the global merchant private_certificate.
    def private_key
      @private_key
    end

    # Loads the global merchant private_certificate from disk.
    def private_certificate_file=(certificate_file)
      self.private_certificate = File.read(certificate_file)
    end

    # Instantiates and assings a OpenSSL::X509::Certificate instance with the
    # provided private certificate data.
    def private_certificate=(certificate_data)
      @private_certificate = OpenSSL::X509::Certificate.new(certificate_data)
    end

    # Returns the global merchant private_certificate.
    def private_certificate
      @private_certificate
    end

    # Set the correct acquirer url based on the specific Bank
    # Currently supported arguments: :ing, :rabobank, :abnamro
    #
    # Ideal::Gateway.acquirer = :ing
    def acquirer=(acquirer)
      @acquirer = acquirer.to_s
      if Ideal::Gateway.acquirers.include?(@acquirer)
        Ideal::Gateway.acquirers[@acquirer].each do |attr, value|
          send("#{attr}=", value)
        end
      else
        raise ArgumentError, "Unknown acquirer `#{acquirer}', please choose one of: #{Ideal::Gateway.acquirers.keys.join(', ')}"
      end
    end

    # Returns the endpoint for the request.
    #
    # Automatically uses test or live URLs based on the configuration.
    def request_url
      self.send("#{environment}_url")
    end

  end
end