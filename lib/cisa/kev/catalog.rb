# frozen_string_literal: true

require_relative 'vulnerability'

require 'net/https'
require 'json'
require 'time'

module CISA
  module KEV
    #
    # Represents the parsed [CISA KEV] catalog.
    #
    # [CISA KEV]: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    #
    # ## Example
    #
    #     catalog = CISA::KEV::Catalog.load
    #     catalog.select(&:known_ransomware_campaign_use).sort_by(&:date_added)
    #     # =>
    #     # [
    #     #   ...
    #     #  #<CISA::KEV::Vulnerability:0x00007fc0a6e715f8
    #     #   @cve_id="CVE-2023-24955",
    #     #   @date_added=#<Date: 2024-03-26 ((2460396j,0s,0n),+0s,2299161j)>,
    #     #   @due_date=#<Date: 2024-04-16 ((2460417j,0s,0n),+0s,2299161j)>,
    #     #   @known_ransomware_campaign_use=true,
    #     #   @notes="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24955",
    #     #   @product="SharePoint Server",
    #     #   @required_action=
    #     #    "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
    #     #   @short_description=
    #     #    "Microsoft SharePoint Server contains a code injection vulnerability that allows an authenticated attacker with Site Owner privileges to execute code remotely.",
    #     #   @vendor_project="Microsoft",
    #     #   @vulnerability_name="Microsoft SharePoint Server Code Injection Vulnerability">]
    #
    class Catalog

      include Enumerable

      # Catalog title attribute.
      #
      # @return [String]
      attr_reader :title

      # Catalog version string.
      #
      # @return [String]
      attr_reader :catalog_version
      alias version catalog_version

      # Time that the catalog was last updated.
      #
      # @return [Time]
      attr_reader :date_released

      # Number of vulnerabilities current in the catalog.
      #
      # @return [Integer]
      attr_reader :count
      alias size count
      alias length count

      # Vulnerabilities in the catalog.
      #
      # @return [Array<Vulnerability>]
      attr_reader :vulnerabilities
      alias vulns vulnerabilities

      #
      # Initializes the CISA KEV catalog.
      #
      # @param [String] title
      #   The catalog title attribute.
      #
      # @param [String] catalog_version
      #   The catalog version string.
      #
      # @param [Time] date_released
      #   The time that the catalog was last updated.
      #
      # @param [Integer] count
      #   The number of vulnerabilities in the catalog.
      #
      # @param [Array<Vulnerability>] vulnerabilities
      #   The parsed vulnerabilities.
      #
      # @api private
      #
      def initialize(title:           ,
                     catalog_version: ,
                     date_released:   ,
                     count:           ,
                     vulnerabilities: )
        @title           = title
        @catalog_version = catalog_version
        @date_released   = date_released
        @count           = count

        @vulnerabilities = vulnerabilities
      end

      # The CISA KEV catalog in JSON format.
      URL = URI.parse('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')

      #
      # Performs an HTTP request for the CISA KEV catalog JSON file.
      #
      # @return [String]
      #   The response body containing the CISA KEV catalog JSON.
      #
      # @api public
      #
      def self.request
        Net::HTTP.get(URL)
      end

      #
      # Loads the CISA KEV list.
      #
      # @return [Catalog]
      #   The loaded catalog.
      #
      # @api public
      #
      # @note This method will perform a HTTP request to {URL}.
      #
      def self.load
        parse(request)
      end

      #
      # Parses a previously downloaded CISA KEV catalog.
      #
      # @param [String] path
      #   The file to parse.
      #
      # @return [Catalog]
      #   The parsed catalog.
      #
      # @api public
      #
      def self.open(path)
        parse(File.open(path).read)
      end

      #
      # Parses the CISA KEV JSON contents.
      #
      # @param [String] contents
      #
      # @return [Catalog]
      #
      # @api private
      #
      def self.parse(contents)
        json = JSON.parse(contents)

        title           = json.fetch('title')
        catalog_version = json.fetch('catalogVersion')
        date_released   = Time.parse(json.fetch('dateReleased'))
        count           = json.fetch('count').to_i

        vulnerabilities = json.fetch('vulnerabilities').map do |attributes|
          Vulnerability.from_json(attributes)
        end

        return new(
          title:           title,
          catalog_version: catalog_version,
          date_released:   date_released,
          count:           count,
          vulnerabilities: vulnerabilities
        )
      end

      #
      # Enumerates over each vulnerability in the CISA KEV list.
      #
      # @yield [vuln]
      #   If a block is given, it will be passed every vulnerability in the
      #   catalog.
      #
      # @yieldparam [Vulnerability] vuln
      #   A parsed vulnerability in the catalog.
      #
      # @return [Enumerator]
      #
      def each(&block)
        @vulnerabilities.each(&block)
      end

      #
      # Converts the list to a String.
      #
      # @return [String]
      #   The string containing the title and date released attributes.
      #
      def to_s
        "#{@title} (#{@date_released})"
      end

    end
  end
end
