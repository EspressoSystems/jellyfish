# Test nix-shell in vagrant VMs

Set up a vagrant guest VM, and test the dev environment inside the guest.

- Only tested on nixos host with _libvirt_ virtualization provider.
- Assumes that the host has an SSH agent. The agent is used for SSH auth inside
  the guest.
- Upon creation (`vagrant up`) a copy of this local repo is rsynced to the
  `/jellyfish` directory in the guest. The tests are run against these files. To
  see changes made to the code on the host run `vagrant reload` to re-sync the
  source code from host to guest.

## Available vagrant boxes
The following boxes are available:

  - `ubuntu`: `ubuntu20.04` + `nix`
  - `ubuntu_rustup`: `ubuntu20.04` + `nix` + `rustup`

More OSes/VMs can be added in the `Vagrantfile`.

Append name of box after vagrant command to apply to a single box only

    vagrant up ubuntu_rustup
    vagrant ssh ubuntu_rustup

## Usage
Enable `libvrtd` on your host:
[ubuntu](https://ubuntu.com/server/docs/virtualization-libvirt),
[nixos](https://nixos.wiki/wiki/Libvirt).

Make sure we are in the `libvirtd` group.

Install `libvirt` vagrant plugin (not needed on nixos):

    vagrant plugin install vagrant-libvirt

Activate nix-shell in this directory (or ensure vagrant is installed):

    nix-shell

Start vm:

    vagrant up ubuntu

There is a password prompt to add the insecure vagrant key to the agent. One can
supply an empty password once or cancel the prompt each time one runs `vagrant
ssh`.

Run formatter, linter, tests inside a nix-shell environment inside the `ubuntu`
guest:

    vagrant ssh ubuntu -- -t /vagrant/test-nix-shell-guest

This runs the `test-nix-shell-guest` script in this directory inside the vagrant
guest.

Clean up with

    vagrant destroy ubuntu

## Notes

- After editing the Vagrantfile, `vagrant reload` will apply the changes.
- When making substantial changes or changing names of vagrant boxes I usually
  have more luck with running `vagrant destroy` with the previous `Vagrantfile`
  and then `vagrant up` again with the new `Vagrantfile`.
