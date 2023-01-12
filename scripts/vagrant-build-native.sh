vagrant up
# `vagrant up` will mount the current directory under `/vagrant` in read-write mode
vagrant ssh -c "/vagrant/scripts/build-native.sh"
