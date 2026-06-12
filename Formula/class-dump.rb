class ClassDump < Formula
  desc "Generate Objective-C headers from Mach-O files (modern fork)"
  homepage "https://github.com/andy-sheng/class-dump"
  url "https://github.com/andy-sheng/class-dump/archive/refs/tags/v3.5.1.tar.gz"
  sha256 "f68886db284abb963153ed7e14be2a7886ecf4b29cf3e4bb9f41abf41bcccd24"
  license "GPL-2.0-or-later"
  head "https://github.com/andy-sheng/class-dump.git", branch: "master"

  depends_on xcode: :build
  depends_on :macos

  def install
    xcodebuild "-project", "class-dump.xcodeproj",
               "-scheme", "class-dump",
               "-configuration", "Release",
               "-derivedDataPath", "build",
               "ARCHS=arm64 x86_64",
               "ONLY_ACTIVE_ARCH=NO",
               "MACOSX_DEPLOYMENT_TARGET=10.13",
               "build"
    bin.install "build/Build/Products/Release/class-dump"
  end

  test do
    # Compile a tiny Objective-C binary and confirm class-dump parses it.
    (testpath/"smoke.m").write <<~OBJC
      #import <Foundation/Foundation.h>
      @interface CDSmokeObject : NSObject
      - (void)smokeMethod;
      @end
      @implementation CDSmokeObject
      - (void)smokeMethod {}
      @end
      int main(void) { return 0; }
    OBJC
    system ENV.cc, "-fobjc-arc", "-framework", "Foundation",
           "smoke.m", "-o", "smoke"
    output = shell_output("#{bin}/class-dump smoke")
    assert_match "@interface CDSmokeObject : NSObject", output
    assert_match "smokeMethod", output
  end
end
