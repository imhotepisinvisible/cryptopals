require 'sinatra'
require 'digest/sha1'

Key = SecureRandom.random_bytes 16

class String
  def xor_with(other_string)
    self.bytes.zip(other_string.bytes).map { |(a,b)| a ^ b }.pack('c*')
  end

  def insecure_compare(other_string)
    self.bytes.zip(other_string.bytes).each do |a, b|
      if a != b
        return false
      end
      sleep 0.005
    end
    return true
  end
end

def bin_to_hex(s)
  s.unpack('H*').first
end

def hex_to_bin(s)
  s.scan(/../).map { |x| x.hex }.pack('c*')
end

get '/test' do
  file = params['file']
  hmac = params['signature']
  if file.nil? || hmac.nil?
    status 404
  else
    # Generate HMAC for file
    zeros = Array.new(64 - Key.length, 0).pack("c*")
    hmac_key = Key + zeros
    o_key_pad = Array.new(64, 0x5c).pack("c*").xor_with(hmac_key)
    i_key_pad = Array.new(64, 0x36).pack("c*").xor_with(hmac_key)
    inner = Digest::SHA1.digest i_key_pad + file
    generated_hmac = Digest::SHA1.digest o_key_pad + inner
    # Compare HMAC with provided signature
    if generated_hmac.insecure_compare(hex_to_bin(hmac))
      status 200
    else
      status 500
    end
  end
end
