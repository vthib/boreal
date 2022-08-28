#!/usr/bin/env sh
#
# Retrieve assets used in benches

set -ex

git clone git@github.com:Neo23x0/panopticon.git assets/panopticon
cd assets/panopticon && git checkout f3aee9296deb4b09cbce75450526883e04add529 && cd ../..

git clone git@github.com:Neo23x0/signature-base.git assets/signature-base
cd assets/signature-base && git checkout 459fe4de6ddadfe975ad6d2e7e61b97a45eaaaa5 && cd ../..
