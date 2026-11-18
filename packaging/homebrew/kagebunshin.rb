# A template for a Homebrew tap. Fill it in from a published release's
# SHA256SUMS:
#
#   v=0.1.0; gh release download "v$v" -p SHA256SUMS -R oorestisime/kagebunshin
#   sed -e "s/@VERSION@/$v/g" \
#       -e "s/@SHA_MACOS_ARM64@/$(awk '/kagebunshin-[0-9].*aarch64-apple-darwin/ {print $1}' SHA256SUMS)/" \
#       -e "s/@SHA_LINUX_ARM64@/$(awk '/kagebunshin-[0-9].*aarch64-unknown-linux-gnu/ {print $1}' SHA256SUMS)/" \
#       -e "s/@SHA_LINUX_X86_64@/$(awk '/kagebunshin-[0-9].*x86_64-unknown-linux-gnu/ {print $1}' SHA256SUMS)/" \
#       packaging/homebrew/kagebunshin.rb > Formula/kagebunshin.rb
#
# The daemon is not a `brew services` service: `kagebunshin daemon install`
# writes its own launchd agent or systemd unit.
class Kagebunshin < Formula
  desc "Local secrets broker giving each coding agent a scoped clone of your secrets"
  homepage "https://github.com/oorestisime/kagebunshin"
  version "@VERSION@"
  license "MIT"

  base = "https://github.com/oorestisime/kagebunshin/releases/download/v#{version}"

  on_macos do
    on_arm do
      url "#{base}/kagebunshin-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "@SHA_MACOS_ARM64@"
    end
  end

  on_linux do
    on_arm do
      url "#{base}/kagebunshin-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "@SHA_LINUX_ARM64@"
    end
    on_intel do
      url "#{base}/kagebunshin-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "@SHA_LINUX_X86_64@"
    end
  end

  def install
    bin.install "kagebunshin"
  end

  test do
    assert_equal "kagebunshin #{version}", shell_output("#{bin}/kagebunshin --version").strip
  end
end
