require 'spec_helper'
require 'webmock/rspec'
require 'cisa/kev/catalog'

describe CISA::KEV::Catalog do
  let(:fixtures_dir) { File.join(__dir__,'fixtures') }
  let(:json_file)    { File.join(fixtures_dir,'known_exploited_vulnerabilities.json') }
  let(:raw_json)     { File.read(json_file) }
  let(:json)         { JSON.parse(raw_json) }

  before { WebMock.disable_net_connect! }

  describe ".request" do
    subject { described_class }

    it "must return JSON data" do
      stub_request(:get, 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')

      subject.request
    end
  end

  describe ".load" do
    subject { described_class.load }

    it "must return a parsed #{described_class} object" do
      stub_request(:get, 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json').to_return(body: raw_json)

      expect(subject).to be_kind_of(described_class)
      expect(subject.title).to eq(json.fetch('title'))
      expect(subject.catalog_version).to eq(json.fetch('catalogVersion'))
      expect(subject.date_released).to eq(Time.parse(json.fetch('dateReleased')))
      expect(subject.count).to eq(json.fetch('count').to_i)
      expect(subject.vulnerabilities).to_not be_empty
      expect(subject.vulnerabilities).to all(be_kind_of(CISA::KEV::Vulnerability))
    end
  end

  describe ".open" do
    subject { described_class.open(json_file) }

    it "must read the file and return a parsed #{described_class}" do
      expect(subject).to be_kind_of(described_class)
      expect(subject.catalog_version).to eq(json.fetch('catalogVersion'))
      expect(subject.date_released).to eq(Time.parse(json.fetch('dateReleased')))
      expect(subject.count).to eq(json.fetch('count').to_i)
      expect(subject.vulnerabilities).to_not be_empty
      expect(subject.vulnerabilities).to all(be_kind_of(CISA::KEV::Vulnerability))
    end
  end

  describe ".parse" do
    subject { described_class.parse(raw_json) }

    it "must parse the JSON and return a parsed #{described_class}" do
      expect(subject).to be_kind_of(described_class)
      expect(subject.catalog_version).to eq(json.fetch('catalogVersion'))
      expect(subject.date_released).to eq(Time.parse(json.fetch('dateReleased')))
      expect(subject.count).to eq(json.fetch('count').to_i)
      expect(subject.vulnerabilities).to_not be_empty
      expect(subject.vulnerabilities).to all(be_kind_of(CISA::KEV::Vulnerability))
    end
  end

  subject { described_class.open(json_file) }

  describe "#each" do
    context "when given a block" do
      it "must yield every CISA::KEV::Vulnerability in #vulnerabilities" do
        expect { |b|
          subject.each(&b)
        }.to yield_successive_args(*subject.vulnerabilities)
      end
    end

    context "when no block is given" do
      it "must return an Enumerator" do
        expect(subject.each.to_a).to eq(subject.vulnerabilities)
      end
    end
  end

  describe "#to_s" do
    it "must return a String containing the #title and #date_released" do
      expect(subject.to_s).to eq("#{subject.title} (#{subject.date_released})")
    end
  end
end
