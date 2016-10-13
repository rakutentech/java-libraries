require 'spec_helper'


describe 'java-libraries' do

  context 'it should install custom certificates into a java keystore' do
    subject { command('/usr/lib/jvm/java/bin/keytool -list -storepass changeit -keystore /usr/lib/jvm/java/jre/lib/security/cacerts -alias java_certificate_test') }
    its(:exit_status) { should eq 0 }
    its(:stdout) { should match /^Certificate fingerprint \(MD5\): D4:5B:B9:3E:BB:B4:64:4D:E4:A1:78:15:C4:EE:A8:DF$/ }
  end

end
