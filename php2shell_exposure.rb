##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rubygems'

# Auxiliary scanner that assesses *exposure* to the PHP "php2shell" pair of
# critical vulnerabilities:
#
#   * CVE-2026-109618 - RCE via out-of-memory (OOM) handling memory corruption.
#                      Vendor advisory: GHSA-w8hw-w9fx-j79w
#   * CVE-2026-109619 - RCE via stale request-owned global state (use-after-free).
#                      Vendor advisory: GHSA-6wmf-4rv5-p3rp
#
# IMPORTANT SCOPE STATEMENT
# -------------------------
# This module performs a safe, purely passive fingerprint of an authorised HTTP
# service and compares *disclosed* PHP version evidence against the vendor's
# published affected/fixed version matrix. It deliberately does NOT:
#
#   * execute commands, deliver payloads, or open reverse shells
#   * trigger memory corruption, use-after-free, or OOM conditions
#   * send multipart/oversized requests intended to cause resource exhaustion
#   * perform any destructive or denial-of-service style test
#
# Consequently the module can NEVER prove remote code execution. A finding of
# "possibly exposed" is *version evidence only* and must be confirmed locally on
# the target host (package/build level), because:
#
#   * `X-Powered-By` / `Server` headers are self-reported and may be altered,
#     suppressed (expose_php=Off) or synthesised by an intermediate reverse proxy
#   * Linux distributions and LTS vendors ship backported fixes that keep the
#     upstream version string, so an "old" version may already be patched
#   * a concealed version must not be interpreted as either patched or vulnerable
#
# See Notes.txt (shipped alongside this module) for installation and usage.
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # Upstream vendor-fixed release per PHP 8.x minor branch, taken verbatim from
  # the vendor advisories and the Rapid7 / NCSC-NL / NHS England advisories:
  #
  #   PHP 8.2 -> 8.2.35
  #   PHP 8.3 -> 8.3.36
  #   PHP 8.4 -> 8.4.27
  #   PHP 8.5 -> 8.5.12
  #
  # PHP 8.1 and every older branch are end-of-life and were also affected; the
  # PHP project published limited source backports for 7.4, 8.0 and 8.1.
  UPSTREAM_FIXED = {
    2 => '8.2.35',
    3 => '8.3.36',
    4 => '8.4.27',
    5 => '8.5.12'
  }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'PHP php2shell Exposure Scanner (CVE-2026-109618 / CVE-2026-109619)',
        'Description' => %q{
          Safely fingerprints an authorised HTTP service and assesses *exposure*
          to the PHP "php2shell" vulnerabilities:

            CVE-2026-109618 - remote code execution via out-of-memory handling
                              memory corruption (GHSA-w8hw-w9fx-j79w).
            CVE-2026-109619 - remote code execution via stale request-owned
                              global state / use-after-free
                              (GHSA-6wmf-4rv5-p3rp).

          The module issues at most two benign HTTP GET requests, collects server
          version evidence (X-Powered-By / Server response headers, PHPSESSID
          cookies), and compares any *disclosed* PHP version against the vendor's
          published affected/fixed matrix.

          This module is a version-evidence check ONLY. It does not exploit the
          vulnerabilities, does not deliver payloads, and does not perform any
          destructive, resource-exhausting, memory-corruption or denial-of-service
          test. It cannot confirm remote code execution. Because distro backports,
          reverse proxies and header suppression can invalidate remote version
          evidence, results must be confirmed on the target host before any
          patched/vulnerable conclusion is drawn. A concealed version is reported
          as INCONCLUSIVE and is never assumed to be patched or vulnerable.
        },
        'Author' => [
          'OpenCode AI assistant (reviewed by the requesting operator)'
        ],
        'References' => [
          ['CVE', '2026-109618'],
          ['CVE', '2026-109619'],
          ['URL', 'https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w'],
          ['URL', 'https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp'],
          ['URL', 'https://www.php.net/archive/2026.php#2026-10-21-5'],
          ['URL', 'https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php/'],
          ['URL', 'https://github.com/NCSC-NL/php2shell'],
          ['URL', 'https://digital.nhs.uk/cyber-alerts/2026/cc-4875'],
          ['URL', 'https://cert.europa.eu/publications/security-advisories/2026-018/']
        ],
        'DisclosureDate' => '2026-10-21',
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'RPORT' => 80,
          'SSL' => false
        },
        'Notes' => {
          # We only read HTTP responses; nothing is written or crashed.
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Base path of the PHP application to assess', '/']),
        OptInt.new('CONNECT_TIMEOUT', [true, 'Seconds to wait for the HTTP connection to be established', 10]),
        OptInt.new('READ_TIMEOUT', [true, 'Seconds to wait for an HTTP response', 20])
      ]
    )
  end

  def setup
    # Preserve the framework's HTTP client / auxiliary setup (fingerprint check,
    # user alert, etc.).
    super

    @connect_timeout = datastore['CONNECT_TIMEOUT'].to_i
    @read_timeout = datastore['READ_TIMEOUT'].to_i

    fail_with(Msf::Exploit::Failure::BadConfig, 'CONNECT_TIMEOUT must be a positive integer') if @connect_timeout <= 0
    fail_with(Msf::Exploit::Failure::BadConfig, 'READ_TIMEOUT must be a positive integer') if @read_timeout <= 0
  end

  # Entry point used by `exploit` / `run`.
  def run_host(ip)
    status = check_host(ip)
    message = check_code_message(status)

    case check_code_name(status)
    when 'vulnerable', 'appears', 'detected'
      print_good("#{peer} #{message}")
    when 'safe'
      print_status("#{peer} #{message}")
    else
      vprint_status("#{peer} #{message}")
    end
  end

  # Entry point used by the `check` command. Returns an Msf::Exploit::CheckCode.
  def check_host(_ip)
    res = fetch_target

    unless res
      return Msf::Exploit::CheckCode::Unknown('No HTTP response received')
    end

    headers = normalized_headers(res)
    versions = self.class.extract_versions(headers)
    php_seen = self.class.php_indicators?(headers, res.body)

    # Always record the observed HTTP service so the host is catalogued even when
    # no PHP indicators are present.
    report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: (ssl ? 'https' : 'http'),
      info: service_banner(headers)
    )

    unless php_seen
      vprint_status("#{peer} no PHP indicators observed at #{full_uri}")
      # No PHP is visible on this endpoint, so it is not applicable to these CVEs.
      return Msf::Exploit::CheckCode::Safe('No PHP indicators in the HTTP response')
    end

    report_note(
      host: rhost,
      port: rport,
      proto: 'tcp',
      type: 'php2shell.exposure',
      data: {
        uri: full_uri,
        php_detected: true,
        disclosed_versions: versions.map { |v| v[:value] },
        version_sources: versions.map { |v| v[:source] },
        confidence: versions.empty? ? 'low' : 'medium',
        note: 'Version evidence only; exploitability not remotely confirmed.'
      }
    )

    if versions.empty?
      # We saw PHP but the version is hidden. Never infer patched or vulnerable.
      print_warning("#{peer} PHP detected but the version is concealed -> INCONCLUSIVE " \
                    '(cannot determine patched or vulnerable from this response)')
      return Msf::Exploit::CheckCode::Detected(
        'PHP detected; version concealed; exposure INCONCLUSIVE (confirm locally)'
      )
    end

    # Report each distinct piece of version evidence with its classification.
    versions.each do |entry|
      case self.class.classify_version(entry[:value])
      when :affected
        print_status("#{peer} PHP #{entry[:value]} disclosed via #{entry[:source]} - " \
                     'within vendor-affected range (version evidence)')
      when :fixed
        print_status("#{peer} PHP #{entry[:value]} disclosed via #{entry[:source]} - " \
                     'at or above the vendor-fixed release (version evidence)')
      else
        print_status("#{peer} PHP #{entry[:value]} disclosed via #{entry[:source]} - " \
                     'classification unknown')
      end
    end

    affected = versions.select { |v| self.class.classify_version(v[:value]) == :affected }

    if affected.any?
      # Version-based finding: record a vulnerability entry, but be explicit that
      # exploitability has NOT been confirmed remotely.
      report_vuln(
        host: rhost,
        port: rport,
        proto: 'tcp',
        name: "#{name} (version-based, exploitability unconfirmed)",
        info: vuln_info(versions, affected),
        refs: references
      )

      print_good("#{peer} POSSIBLY EXPOSED: disclosed PHP version(s) fall within the " \
                 'vendor-affected range. This is version evidence only - confirm the ' \
                 'installed patch level locally (backports may already be fixed).')
      return Msf::Exploit::CheckCode::Detected(
        'PHP version within vendor-affected range (version-based; exploitability unconfirmed)'
      )
    end

    print_status("#{peer} disclosed PHP version is at or above the vendor-fixed release. " \
                 'Remote version evidence suggests patched - confirm locally as proxies ' \
                 'and backports can alter this.')
    Msf::Exploit::CheckCode::Safe(
      'Disclosed PHP version at or above the vendor-fixed release (version evidence)'
    )
  end

  private

  # The CheckCode representation differs across framework versions: older
  # releases use an Array-like [code, message] pair, newer releases use a Struct
  # exposing #code and #message. These helpers normalise both.
  def check_code_name(status)
    return status.code.to_s if status.respond_to?(:code)

    Array(status).first.to_s
  end

  def check_code_message(status)
    return status.message.to_s if status.respond_to?(:message)

    Array(status)[1].to_s
  end

  # Fetch the target. At most two benign GET requests are issued: the configured
  # TARGETURI, and, only if the first shows no PHP indicators, the site root.
  # Redirects are never followed, so we cannot be led to an unrelated host.
  def fetch_target
    primary = normalize_uri(target_uri.path.to_s)
    primary = '/' if primary.to_s.empty?

    res = http_get(primary)
    return unless res

    if primary != '/' && !self.class.php_indicators?(normalized_headers(res), res.body)
      fallback = http_get('/')
      res = fallback if fallback
    end

    res
  end

  # Issue a single GET request. CONNECT_TIMEOUT bounds connection establishment
  # and READ_TIMEOUT bounds the response read. The socket is always closed.
  def http_get(uri)
    client = connect
    # Establish the socket eagerly so CONNECT_TIMEOUT is honoured (the default
    # HttpClient connect defers the socket until the first request).
    client.connect(@connect_timeout) unless client.conn

    send_request_cgi(
      {
        'method' => 'GET',
        'uri' => uri,
        'client' => client,
        'headers' => { 'Accept' => '*/*' }
      },
      @read_timeout,
      false
    )
  rescue Rex::ConnectionError, ::Timeout::Error, ::Errno::EPIPE, ::EOFError, ::SocketError => e
    vprint_error("#{peer} #{e.class}: #{e.message}")
    nil
  ensure
    disconnect
  end

  # Convert Rex response headers into a plain, lower-cased, string-valued hash so
  # the classification helpers stay framework independent and unit testable.
  def normalized_headers(res)
    out = {}
    (res.headers || {}).each do |k, v|
      out[k.to_s.downcase] = Array(v).join(', ')
    end
    out
  end

  def service_banner(headers)
    banner = []
    banner << "Server: #{headers['server']}" if headers['server']
    banner << "X-Powered-By: #{headers['x-powered-by']}" if headers['x-powered-by']
    banner.empty? ? 'HTTP service' : banner.join('; ')
  end

  def vuln_info(versions, affected)
    <<~INFO.strip
      PHP php2shell exposure (CVE-2026-109618 / CVE-2026-109619) - version evidence only.
      Affected upstream branches: < 8.2.35, < 8.3.36, < 8.4.27, < 8.5.12 (and EOL <= 8.1).
      Disclosed version(s): #{versions.map { |v| "#{v[:value]} (#{v[:source]})" }.join(', ')}.
      In affected range: #{affected.map { |v| v[:value] }.join(', ')}.
      CONFIDENCE: medium - headers are self-reported and distro backports, reverse
      proxies or expose_php=Off can invalidate this evidence. Exploitability was NOT
      confirmed; no exploitation was attempted by this module.
    INFO
  end

  # ---------------------------------------------------------------------------
  # Pure classification helpers (no framework state; exercised by the spec file)
  # ---------------------------------------------------------------------------

  # Does the response contain any PHP indicator at all (with or without version)?
  def self.php_indicators?(headers, body = nil)
    powered_by = headers['x-powered-by'].to_s.downcase
    server = headers['server'].to_s.downcase
    cookies = headers.select { |k, _| k == 'set-cookie' }.values.join(' ').downcase

    return true if powered_by.include?('php')
    return true if server.include?('php')
    return true if cookies.include?('phpsessid')
    return true if headers.values.any? { |v| v.to_s.downcase.include?('php/') }
    return true if body.to_s.match?(/\bPHP\/\d/)

    false
  end

  # Extract disclosed PHP versions from response headers. Returns an array of
  # { source:, value:, raw: } hashes (de-duplicated by version string).
  def self.extract_versions(headers)
    found = []

    add = lambda do |source, value|
      value.to_s.scan(/PHP[\/ ]?v?(\d+\.\d+(?:\.\d+){0,2})/i) do |match|
        found << { source: source, value: match.first, raw: value.to_s.strip }
      end
    end

    add.call('X-Powered-By', headers['x-powered-by'])
    add.call('Server', headers['server'])

    headers.each do |key, value|
      next if %w[x-powered-by server].include?(key)

      add.call("header:#{key}", value) if value.to_s.downcase.include?('php/')
    end

    found.uniq { |entry| entry[:value] }
  end

  # Classify a disclosed upstream PHP version string against the vendor matrix.
  # Returns :affected, :fixed or :unknown. Distro/LTS suffixes are ignored; the
  # remaining uncertainty is documented as a limitation, never resolved by guess.
  def self.classify_version(version)
    return :unknown if version.nil?

    match = version.to_s.match(/\A\s*(\d+)\.(\d+)(?:\.(\d+))?/)
    return :unknown unless match

    major = match[1].to_i
    minor = match[2].to_i
    patch = match[3].to_i

    # The advisories cover PHP 8.x and state that 8.1 and older were affected.
    return :affected if major < 8
    return :unknown if major > 8

    observed = Gem::Version.new("#{major}.#{minor}.#{patch}")
    fixed = UPSTREAM_FIXED[minor]

    # 8.0 / 8.1 are end-of-life and were affected; no fixed minor threshold exists.
    return :affected if fixed.nil?

    observed >= Gem::Version.new(fixed) ? :fixed : :affected
  end
end
