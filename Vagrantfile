# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-22.04"
  # Only using password because there seems to be a bug with this image, and vagrant is unable to
  # connect over SSH after first login using a private key.
  config.ssh.password = "vagrant"

  # Run once when provisioned
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y \
      build-essential \
      libstdc++-10-dev \
      cmake \
      openjdk-11-jdk-headless \
      kmod
  SHELL

  # Run on startup every time
  config.vm.provision "shell", inline: "modprobe tls", run: "always"
end
