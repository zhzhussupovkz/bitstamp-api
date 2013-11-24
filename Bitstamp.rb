=begin
/*

The MIT License (MIT)

Copyright (c) 2013 Zhussupov Zhassulan zhzhussupovkz@gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
=end

require 'net/http'
require 'net/https'
require 'json'
require 'openssl'
require 'base64'

class Bitstamp

  def initialize client_id, api_key, secret
    @api_url = 'https://www.bitstamp.net/api/'
    @client_id, @api_key, @secret = client_id, api_key, secret
  end

  #send public request to the server
  def public_request method, params = nil
    if params.nil?
      params = ''
    else
      params = URI.escape(params.collect{ |k,v| "#{k}=#{v}"}.join('&'))
    end
    url = @api_url + method + '/?' + params
    raise ArgumentError if not url.is_a? String
    uri = URI.parse url
    http = Net::HTTP.new uri.host, uri.port
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    req = Net::HTTP::Get.new uri.path
    res = http.request req
    data = res.body
    if not data.is_a? String or not data.is_json?
      raise RuntimeError, "Server returned invalid data."
    end
    result = JSON.parse data
  end

  #send private request to the server
  def private_request method, params = {}
    nonce = Time.now.to_i.to_s
    message = nonce + @client_id.to_s + @api_key
    sha256 = OpenSSL::Digest::SHA256.new
    hash = OpenSSL::HMAC.digest(sha256, @secret, message)
    signature = Base64.encode64(hash).chomp.gsub("\n",'')
    required = { 'key' => @api_key, 'nonce' => nonce, 'signature' => signature }
    params = required.merge(params)
    url = @api_url + method
    raise ArgumentError if not url.is_a? String
    uri = URI.parse url
    http = Net::HTTP.new uri.host, uri.port
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    req = Net::HTTP::Post.new(uri.path)
    req.set_form_data params
    res = http.request req
    data = res.body
    if not data.is_a? String or not data.is_json?
      raise RuntimeError, "Server returned invalid data."
    end
    result = JSON.parse data
  end

  #################################### PUBLIC ###################################
  ############### ticker ####################
  #Returns JSON dictionary:
    #last - last BTC price
    #high - last 24 hours price high
    #low - last 24 hours price low
    #volume - last 24 hours volume
    #bid - highest buy order
    #ask - lowest sell order
  def ticker
    public_request 'ticker'
  end

  ############### order book ###############
  #Returns JSON dictionary with "bids" and "asks". 
  #Each is a list of open orders and each order is 
  #represented as a list of price and amount.
  #Params:
    #group - group orders with the same price (0 - false; 1 - true). Default: 1
  def order_book group = true
    params = { 'group' => group }
    public_request 'order_book', params
  end

  ############### transactions ###############
  #Returns descending JSON list of transactions. Every transaction (dictionary) contains:
    #date - unix timestamp date and time
    #tid - transaction id
    #price - BTC price
    #amount - BTC amount
  #Params:
    #time - time frame for transaction export ("minute" - 1 minute, "hour" - 1 hour, "day" - 1 day). Default: hour.
  def transactions time = "hour"
    params = { 'hour' => time }
    public_request 'transactions', params
  end

  #################################### PRIVATE ###################################
  ############## balance ################
  #Returns JSON dictionary:
    #usd_balance - USD balance
    #btc_balance - BTC balance
    #usd_reserved - USD reserved in open orders
    #btc_reserved - BTC reserved in open orders
    #usd_available- USD available for trading
    #btc_available - BTC available for trading
    #fee - customer trading fee
  def balance
    private_request 'balance'
  end

  ############## user transactions ################
  #Returns descending JSON list of transactions. Every transaction (dictionary) contains:
    #datetime - date and time
    #id - transaction id
    #type - transaction type (0 - deposit; 1 - withdrawal; 2 - market trade)
    #usd - USD amount
    #btc - BTC amount
    #fee - transaction fee
    #order_id - executed order id
  #Params:
    #offset - skip that many transactions before beginning to return results. Default: 0.
    #limit - limit result to that many transactions. Default: 100.
    #sort - sorting by date and time (asc - ascending; desc - descending). Default: desc.
  def user_transactions params = { 'offset' => 0, 'limit' => 100, 'sort' => 'desc' }
    private_request 'user_transactions', params
  end

  ############## open orders #############
  #Returns JSON list of open orders. Each order is represented as dictionary:
    #id - order id
    #datetime - date and time
    #type - buy or sell (0 - buy; 1 - sell)
    #price - price
    #amount - amount
  def open_orders
    private_request 'open_orders'
  end

  ############## cancel order ############
  #Returns 'true' if order has been found and canceled.
  #Params:
    #id - order ID
  def cancel_order order_id
    private_request 'cancel_order'
  end

  ############ buy limit order #############
  #Returns JSON dictionary representing order:
    #    id - order id
    #datetime - date and time
    #type - buy or sell (0 - buy; 1 - sell)
    #price - price
    #amount - amount
  #Params:
    #amount - amount
    #price - price
  def buy params
    private_request 'buy', params
  end

  ############ sell limit order #############
  #Returns JSON dictionary representing order:
    #    id - order id
    #datetime - date and time
    #type - buy or sell (0 - buy; 1 - sell)
    #price - price
    #amount - amount
  #Params:
    #amount - amount
    #price - price
  def sell params
    private_request 'sell', params
  end

  ############ check bitstamp code #############
  #Returns JSON dictionary containing USD and BTC amount included in given bitstamp code.
  #Params:
    #code - Bitstamp code to redeem
  def check_code params
    private_request 'check_code', params
  end

  ############ check bitstamp code #############
  #Returns JSON dictionary containing USD and BTC amount included in given bitstamp code.
  #Params:
    #code - Bitstamp code to check
  def redeem_code params
    private_request 'redeem_code', params
  end

  ############ withdrawal requests #############
  #Returns JSON list of withdrawal requests. Each request is represented as dictionary:
    #id - order id
    #datetime - date and time
    #type - (0 - SEPA; 1 - bitcoin; 2 - WIRE transfer; 3 and 4 - bitstamp code; 5 - Mt.Gox code)
    #amount - amount
    #status - (0 - open; 1 - in process; 2 - finished; 3 - canceled; 4 - failed)
    #data - additional withdrawal request data (Mt.Gox code, etc.)
  def withdrawal_requests
    private_request 'withdrawal_requests'
  end

  ############ bitcoin withdrawal #############
  #Returns true if successful.
  #Params:
    #amount - bitcoin amount
    #address - bitcoin address
  def bitcoin_withdrawal params
    private_request 'bitcoin_withdrawal', params
  end

  ############ bitcoin deposit address #############
  #Returns your bitcoin deposit address.
  def bitcoin_deposit_address
    private_request 'bitcoin_deposit_address'
  end

  ############ unconfirmed bitcoin deposits #############
  #Returns JSON list of unconfirmed bitcoin transactions. Each transaction is represented as dictionary:
    #amount - bitcoin amount
    #address - deposit address used
    #confirmations - number of confirmations
  def unconfirmed_btc
    private_request 'unconfirmed_btc'
  end

  ############ ripple withdrawal #############
  #Returns true if successful.
  #Params:
    #amount - currency amount
    #address - bitcoin address
    #currency - currency
  def ripple_withdrawal params
    private_request 'ripple_withdrawal', params
  end

  ############ ripple deposit address #############
  #Returns your ripple deposit address.
  def ripple_address
    private_request 'ripple_withdrawal'
  end

end

class String
  def is_json?
    begin
      !!JSON.parse(self)
    rescue
      false
    end
  end
end
