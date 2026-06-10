Pod::Spec.new do |s|
  s.name             = 'uacryptex'
  s.version          = '0.1.0'
  s.summary          = 'uacryptex FFI for Flutter'
  s.homepage         = 'https://github.com/your-org/uacryptex'
  s.license          = { :file => '../../LICENSE' }
  s.author           = { 'uacryptex' => 'acsk@privatbank.ua' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '12.0'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
end
