# frozen_string_literal: true

##
# Tests for the php2shell exposure scanner (CVE-2026-109618 / CVE-2026-109619).
#
# These specs drive the real module through a local, in-process mock HTTP server
# (a plain TCPServer), so no external network access is required and no
# potentially vulnerable system is contacted.
#
# Run from the Metasploit Framework source tree, e.g.:
#
#   cd /usr/share/metasploit-framework   # or your MSF root
#   bundle exec rspec spec/modules/auxiliary/scanner/http/php2shell_exposure_spec.rb
#
# The module must be installed first (see install.sh / Notes.txt).
##

require 'spec_helper'
require 'socket'

RSpec.describe 'php2shell exposure scanner' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:mod) do
    instance = load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'scanner/http/php2shell_exposure'
    )

    # Keep the specs independent of any database connection.
    allow(instance).to receive(:report_service)
    allow(instance).to receive(:report_note)
    allow(instance).to receive(:report_vuln)

    instance
  end

  # A tiny single-response HTTP/1.1 mock server. It answers every request with
  # the same canned response, which is enough to exercise the fingerprint logic
  # (the module issues the TARGETURI and, at most, the site root).
  def start_mock_server(headers:, body: '', status: 200, reason: 'OK')
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]

    thread = Thread.new do
      loop do
        client = server.accept
        begin
          # Read the request line and drain headers up to the blank line.
          while (line = client.gets)
            break if line == "\r\n"
          end

          header_block = headers.map { |k, v| "#{k}: #{v}\r\n" }.join
          response = "HTTP/1.1 #{status} #{reason}\r\n" \
                     "#{header_block}" \
                     "Content-Length: #{body.bytesize}\r\n" \
                     "Connection: close\r\n\r\n" \
                     "#{body}"
          client.write(response)
        rescue StandardError
          # Client went away early; keep serving.
        ensure
          client.close
        end
      end
    end

    [server, port, thread]
  end

  around do |example|
    @servers = []
    example.run
  ensure
    @servers.each do |server, thread|
      server.close
      thread.kill
    end
  end

  def with_mock(headers:, body: '', status: 200)
    server, port, thread = start_mock_server(headers: headers, body: body, status: status)
    @servers << [server, thread]
    yield port
  end

  # Run the module against the mock server and return the CheckCode name as a
  # String. Older frameworks expose the code as a Symbol, newer ones as a String,
  # so #to_s normalises both.
  def scan(mod, port, target_uri: '/')
    mod.datastore['RHOST'] = '127.0.0.1'
    mod.datastore['RPORT'] = port
    mod.datastore['SSL'] = false
    mod.datastore['TARGETURI'] = target_uri
    mod.datastore['CONNECT_TIMEOUT'] = 5
    mod.datastore['READ_TIMEOUT'] = 5
    mod.setup

    mod.check_host('127.0.0.1').first.to_s
  end

  # -- Version classification (pure, no I/O) ----------------------------------

  describe '::classify_version' do
    {
      '8.2.29' => :affected,
      '8.2.35' => :fixed,
      '8.3.10' => :affected,
      '8.3.36' => :fixed,
      '8.4.26' => :affected,
      '8.4.27' => :fixed,
      '8.5.11' => :affected,
      '8.5.12' => :fixed,
      '8.1.99' => :affected,  # EOL branch, affected
      '7.4.33' => :affected,  # EOL branch, affected (source backport exists)
      '8.2.29-1ubuntu2' => :affected, # distro suffix stripped; still < 8.2.35
      'garbage' => :unknown,
      nil => :unknown
    }.each do |input, expected|
      it "classifies #{input.inspect} as #{expected}" do
        expect(mod.class.classify_version(input)).to eq(expected)
      end
    end
  end

  describe '::extract_versions' do
    it 'extracts a version from X-Powered-By' do
      headers = { 'x-powered-by' => 'PHP/8.2.29' }
      expect(mod.class.extract_versions(headers)).to eq([
        { source: 'X-Powered-By', value: '8.2.29', raw: 'PHP/8.2.29' }
      ])
    end

    it 'extracts a version embedded in a Server header' do
      headers = { 'server' => 'Apache/2.4.62 (Debian) PHP/8.4.10' }
      expect(mod.class.extract_versions(headers).map { |e| e[:value] }).to eq(['8.4.10'])
    end

    it 'returns nothing when no version is disclosed' do
      expect(mod.class.extract_versions({ 'x-powered-by' => 'PHP' })).to be_empty
    end
  end

  # -- End-to-end fingerprinting against the mock server ----------------------

  describe '#check_host' do
    it 'reports Detected for a disclosed affected version (X-Powered-By)' do
      # Regression: report_service must use a transport proto ('tcp'), not the
      # HTTP scheme; otherwise the database validation rejects the finding.
      expect(mod).to receive(:report_service).with(hash_including(proto: 'tcp', name: 'http'))
      with_mock(headers: { 'X-Powered-By' => 'PHP/8.2.29' }) do |port|
        expect(scan(mod, port)).to eq('detected')
      end
    end

    it 'reports Safe for a disclosed patched version' do
      with_mock(headers: { 'X-Powered-By' => 'PHP/8.5.12' }) do |port|
        expect(scan(mod, port)).to eq('safe')
      end
    end

    it 'reports Detected (inconclusive) when PHP is present but the version is hidden' do
      with_mock(headers: { 'Set-Cookie' => 'PHPSESSID=abc123; path=/' }) do |port|
        expect(scan(mod, port)).to eq('detected')
      end
    end

    it 'reports Safe when no PHP indicators are present' do
      with_mock(headers: { 'Server' => 'nginx/1.24.0' }, body: '<html>hello</html>') do |port|
        expect(scan(mod, port)).to eq('safe')
      end
    end

    it 'reports Detected for a version embedded in the Server header' do
      with_mock(headers: { 'Server' => 'Apache/2.4.62 (Debian) PHP/8.4.10' }) do |port|
        expect(scan(mod, port)).to eq('detected')
      end
    end
  end
end
