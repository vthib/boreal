#!/usr/bin/env bash
#
# Retrieve assets used in benches

set -e

mkdir assets

checkout() {
    echo "retrieving $2..."
    git clone -q $1 assets/$2
    pushd assets/$2
    git checkout -q $3
    popd
}

# Checkout sources of yara rules

checkout git@github.com:Neo23x0/panopticon.git panopticon f3aee9296deb4b09cbce75450526883e04add529
checkout git@github.com:Neo23x0/signature-base.git signature-base 459fe4de6ddadfe975ad6d2e7e61b97a45eaaaa5
checkout git@github.com:StrangerealIntel/Orion.git orion cbdebf8116cb017f944123438b700d562c388b02
checkout git@github.com:Yara-Rules/rules.git yara-rules 0f93570194a80d2f2032869055808b0ddcdfb360
# Remove one rule that depends on the cuckoo module
sed -ie 's!include "./malware/MALW_AZORULT.yar"!!' assets/yara-rules/index.yar
checkout git@github.com:reversinglabs/reversinglabs-yara-rules.git reversinglabs 6aacf65eb2648ca7e6bc8767ffb2fdf032951dd6
checkout git@github.com:advanced-threat-research/Yara-Rules.git atr 4e29051f9c6d80a2d9f4b33ada7f7b377a8d9f4f
checkout git@github.com:SupportIntelligence/Icewater.git icewater 71e327039a6cfeee4bcfc045f3c6d5d039ffee78
checkout git@github.com:Crypt-0n/C0-FF-EE.git c0ffee 4704222f828278eeec665234ea0d2166afe964ca

# Retrieve binaries to scan against
wget https://storage.googleapis.com/chromium-browser-snapshots/Win/1061148/chrome-win.zip
unzip chrome-win.zip
mkdir -p assets/pes
# One small file, 737KB
cp chrome-win/vulkan-1.dll assets/pes
# One bigger file, 5.5MB
cp chrome-win/libGLESv2.dll assets/pes
# One huge file, 157M
cp chrome-win/interactive_ui_tests.exe assets/pes
rm -rf chrome-win chrome-win.zip

wget "https://download-installer.cdn.mozilla.net/pub/firefox/releases/107.0/win64/en-US/Firefox Setup 107.0.msi"
mv "Firefox Setup 107.0.msi" assets/pes/firefox.msi
