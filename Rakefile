require "bundler/gem_tasks"

require 'rake/testtask'

desc "runs gateway & merchant in test"
# task :test ["test:gateway", "test:merchant"]

namespace :test do
  desc "Run the remote tests for iDEAL gateway"
  Rake::TestTask.new(:remote) do |test|
    test.libs << 'test'
    test.test_files = FileList['test/remote_test.rb']
    test.verbose = true
  end

  desc "Run the tests for iDEAL gateway"
  Rake::TestTask.new(:gateway) do |test|
    test.libs << 'test'
    test.test_files = FileList['test/gateway_test.rb']
    test.verbose = true
  end

  desc "Run the merchant tests for iDEAL gateway"
  Rake::TestTask.new(:merchant) do |test|
    test.libs << 'test'
    test.test_files = FileList['test/merchant_test.rb']
    test.verbose = true
  end

  task :all => [:remote, :gateway, :merchant]

end

