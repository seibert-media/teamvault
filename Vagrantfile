VAGRANTFILE_API_VERSION = "2"

required_plugins = %w( vagrant-bundlewrap vagrant-hostsupdater )
required_plugins.each do |plugin|
  unless Vagrant.has_plugin? plugin
    raise "vagrant plugin '#{plugin}' is missing, install with 'vagrant plugin install #{plugin}'"
  end
end

VM_NAME = 'teamvault'
VM_IP = '192.168.47.47'

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "ubuntu/trusty64"
  config.vm.define VM_NAME do |node|
    node.vm.network :private_network, ip: VM_IP
    node.vm.hostname = VM_NAME
    node.vm.synced_folder ".", "/teamvault"

    node.vm.provision :bundlewrap do |bw|
      bw.node_name = VM_NAME
      bw.node_host = VM_NAME
    end
  end
end
