# cisa-kev

[![CI](https://github.com/postmodern/cisa-kev.rb/actions/workflows/ruby.yml/badge.svg)](https://github.com/postmodern/cisa-kev.rb/actions/workflows/ruby.yml)
[![Code Climate](https://codeclimate.com/github/postmodern/cisa-kev.rb.svg)](https://codeclimate.com/github/postmodern/cisa-kev.rb)

* [Homepage](https://github.com/postmodern/cisa-kev.rb#readme)
* [Issues](https://github.com/postmodern/cisa-kev.rb/issues)
* [Documentation](http://rubydoc.info/gems/cisa-kev/frames)

## Description

A simple Ruby library for fetching and parsing the [CISA KEV] catalog.

## Features

* Supports requesting the CISA KEV catalog via HTTP(s).
* Supports parsing previously downloaded JSON files.

## Examples

```ruby
require 'cisa/kev'

catalog = CISA::KEV::Catalog.load
catalog.select(&:known_ransomware_campaign_use).sort_by(&:date_added)
# =>
# [
#   ...
#  #<CISA::KEV::Vulnerability:0x00007fc0a6e715f8
#   @cve_id="CVE-2023-24955",
#   @date_added=#<Date: 2024-03-26 ((2460396j,0s,0n),+0s,2299161j)>,
#   @due_date=#<Date: 2024-04-16 ((2460417j,0s,0n),+0s,2299161j)>,
#   @known_ransomware_campaign_use=true,
#   @notes="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24955",
#   @product="SharePoint Server",
#   @required_action=
#    "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
#   @short_description=
#    "Microsoft SharePoint Server contains a code injection vulnerability that allows an authenticated attacker with Site Owner privileges to execute code remotely.",
#   @vendor_project="Microsoft",
#   @vulnerability_name="Microsoft SharePoint Server Code Injection Vulnerability">]
```

## Requirements

* [ruby] >= 3.0.0

## Install

```shell
gem install cisa-kev
```

### Gemfile

```ruby
gem 'cisa-kev', '~> 0.1'
```

## Copyright

Copyright (c) 2024 Hal Brodigan

See {file:LICENSE.txt} for details.

[CISA KEV]: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
[ruby]: https://www.ruby-lang.org/
