# encoding: utf-8

require File.expand_path('../helper', __FILE__)

module IdealTestCases

  class ClassMethodsTest < Test::Unit::TestCase
    def setup
      @merchant = Ideal::Merchant.new.tap do |m|
        m.acquirer = :rabobank
        m.merchant_id = '123456789'
        m.passphrase = 'passphrase'
        m.private_key = PRIVATE_KEY
        m.private_certificate = PRIVATE_CERTIFICATE
      end
      Ideal::Gateway.add_merchant('test', @merchant)
      @gateway = Ideal::Gateway.new('test')
    end

    def test_merchant_id
      assert_equal @merchant.merchant_id, '123456789'
    end

    def test_verify_live_url_for_ing
      @merchant.acquirer = :ing
      assert_equal 'https://ideal.secure-ing.com/ideal/iDEALv3', @merchant.live_url
    end

    def test_verify_live_url_for_rabobank
      @merchant.acquirer = :rabobank
      assert_equal 'https://ideal.rabobank.nl/ideal/iDEALv3', @merchant.live_url
    end

    def test_verify_live_urls_for_abnamro
      @merchant.acquirer = :abnamro
      assert_equal 'https://abnamro.ideal-payment.de/ideal/iDEALv3', @merchant.live_url
    end

    def test_does_not_allow_configuration_of_unknown_acquirers
      assert_raise(ArgumentError) do
        @merchant.acquirer = :unknown
      end
    end

    def test_acquirers
      assert_equal 'https://ideal.rabobank.nl/ideal/iDEALv3', Ideal::Gateway.acquirers['rabobank']['live_url']
      assert_equal 'https://ideal.secure-ing.com/ideal/iDEALv3', Ideal::Gateway.acquirers['ing']['live_url']
      assert_equal 'https://abnamro.ideal-payment.de/ideal/iDEALv3', Ideal::Gateway.acquirers['abnamro']['live_url']
    end

    def test_private_certificate_returns_a_loaded_Certificate_instance
      assert_equal @merchant.private_certificate.to_text,
        OpenSSL::X509::Certificate.new(PRIVATE_CERTIFICATE).to_text
    end

    def test_private_key_returns_a_loaded_PKey_RSA_instance
      assert_equal @merchant.private_key.to_text,
        OpenSSL::PKey::RSA.new(PRIVATE_KEY, @merchant.passphrase).to_text
    end

    def test_optional_initialization_options
      assert_equal 0, Ideal::Merchant.new().sub_id
      assert_equal 1, Ideal::Merchant.new(:sub_id => 1).sub_id
    end


  end

  ###
  #
  # Fixture data
  #

  PRIVATE_CERTIFICATE = %{-----BEGIN CERTIFICATE-----
MIIC+zCCAmSgAwIBAgIJALVAygHjnd8ZMA0GCSqGSIb3DQEBBQUAMF0xCzAJBgNV
BAYTAk5MMRYwFAYDVQQIEw1Ob29yZC1Ib2xsYW5kMRIwEAYDVQQHEwlBbXN0ZXJk
YW0xIjAgBgNVBAoTGWlERUFMIEFjdGl2ZU1lcmNoYW50IFRlc3QwHhcNMDkwMTMw
MTMxNzQ5WhcNMjQxMjExMDM1MjI5WjBdMQswCQYDVQQGEwJOTDEWMBQGA1UECBMN
Tm9vcmQtSG9sbGFuZDESMBAGA1UEBxMJQW1zdGVyZGFtMSIwIAYDVQQKExlpREVB
TCBBY3RpdmVNZXJjaGFudCBUZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQDmBpi+RVvZBA01kdP5lV5bDzu6Jp1zy78qhxxwlG8WMdUh0Qtg0kkYmeThFPoh
2c3BYuFQ+AA6f1R0Spb+hTNrBxkZaRnHCfMMD9LXquFjJ/lvSGnwkjvBmGzyTPZ1
LIunpejm8hH0MJPqpp5AIeXjp1mv7BXA9y0FqObrrLAPaQIDAQABo4HCMIG/MB0G
A1UdDgQWBBTLqGWJt5+Ri6vrOpqGZhINbRtXczCBjwYDVR0jBIGHMIGEgBTLqGWJ
t5+Ri6vrOpqGZhINbRtXc6FhpF8wXTELMAkGA1UEBhMCTkwxFjAUBgNVBAgTDU5v
b3JkLUhvbGxhbmQxEjAQBgNVBAcTCUFtc3RlcmRhbTEiMCAGA1UEChMZaURFQUwg
QWN0aXZlTWVyY2hhbnQgVGVzdIIJALVAygHjnd8ZMAwGA1UdEwQFMAMBAf8wDQYJ
KoZIhvcNAQEFBQADgYEAGtgkmME9tgaxJIU3T7v1/xbKr6A/iwmt3sCmfJEl4Pty
aUGaHFy1KB7xmkna8gomxMWL2zZkdv4t1iGeuVCl9n77SL3MzapotdeNNqahblcN
RBshYCpWpsQQPF45/R5Xp7rXWWsjxgip7qTBNpgTx+Z/VKQpuQsFjYCYq4UCf2Y=
-----END CERTIFICATE-----}

  PRIVATE_KEY = %{-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDmBpi+RVvZBA01kdP5lV5bDzu6Jp1zy78qhxxwlG8WMdUh0Qtg
0kkYmeThFPoh2c3BYuFQ+AA6f1R0Spb+hTNrBxkZaRnHCfMMD9LXquFjJ/lvSGnw
kjvBmGzyTPZ1LIunpejm8hH0MJPqpp5AIeXjp1mv7BXA9y0FqObrrLAPaQIDAQAB
AoGAfkccz0ewVoDc5424+wk/FWpVdaoBQjKWLbiiqkMygNK2mKv0PSD0M+c4OUCU
2MSDKikoXJTpOzPvny/bmLpzMMGn9YJiWEQ5WdaTdppffdylfGPBZXZkt5M9nxJA
NL3fPT79R79mkCF8cgNUbLtNL4woSoFKwRHDU2CGvtTbxqkCQQD+TY1sGJv1VTQi
MYYx3FlEOqw3jp/2q7QluTDDGmvmVOSFnAPfmX0rKEtnBmG4ID7IaG+IQFthDudL
3trqGQdTAkEA54+RxyCZiXDfkh23cD0QaApZaBuk6cKkx6qeFxeg1T+/idGgtWJI
Qg3i9fHzOIFUXwk51R3xh5IimvMJZ9Ii0wJAb7yrsx9tB3MUoSGZkTb8kholqZOl
fcEcOqcQYemuF1qdvoc6vHi4osnlt7L6JOkmLPCWcQu2GwNtZczZ65pruQJBAJ3p
vbtzUuF01TKbC18Cda7N5/zkZUl5ENCNXTRYS7lBuQhuqc8okChjufSJpJlTMUuC
Sis5OV5/3ROYTEC+ADsCQCwq6VQ1kXRrM+3tkMwi2rZi73dsFVuFx8crlBOmvhkD
U7Ar9bW13qhBeH9px8RCRDMWTGQcxY/C/TEQc/qvhkI=
-----END RSA PRIVATE KEY-----}

end