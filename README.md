# Hello, malware junkies

Thank you for helping me to test my sandbox. Currently this has only been tested with 64-bit Debian Stretch, and a guest VM OS of Windows 7 SP 1 x86-64; if you want to adapt it to anything else you are welcome to try but I make no guarantees!

At this stage I have not chosen a license. Please do not distribute code that is © myself at this time.

This is super pre-alpha code and is likely to be broken in all sorts of ways I have not yet discovered. I am hoping that your testing can help me make it only moderately broken before opening it up to the rest of the world.

## CREDITS
Much of this process was only possible with the help of Sean Whalen's Cuckoo sandbox guide. 

I have borrowed heavily from it and these instructions will refer to it in a number of cases rather than reproduce the content here.

Please find it at https://infosecspeakeasy.org/t/howto-build-a-cuckoo-sandbox/27/1

SwiftOnSecurity's Decent Security advice for updating Windows and Sysmon config were also pretty handy.

Far too many web guides and IRC channels to list individually.

And last but definitely not least my boss, who knows a thing or two about malware.

## INSTALLATION

If you are installing this system into a VM, give the VM at least two processors, and enable hardware assisted virtualization.

To install, perform the steps below:

- Clone this repository to your sandbox host and execute the *install.sh* script as root.
- The script requires access to the internet via HTTP, HTTPS and NTP. Please ensure this access is available before running the installer.
- Run install.sh and enter the desired parameters. Installation involves compiling libvirt and Suricata from source, and generating Diffie-Hellman parameters. Go play outside for a bit.

## SETUP

### Libvirt/guest VMs

- Check libvirtd is running and the libvirt socket files at /usr/local/var/run/libvirt/ have ownership of root:libvirt-qemu.
- If they do not, contact me and I can provide the steps to make sure this is fixed
- Start virt-manager. Verify that the network details you specified in the install script have been set correctly. Create a new virtual machine - I recommend at least 2 CPUs and 2GB RAM
- __MAKE SURE__ to customise the VM before install:
  - Change the display type to VNC
  - Change the Video type to Cirrus (actually we want it to be VMVGA, but there's a bug with the virtualisation that makes the installer fail to boot with that setting)
  - Save the config and halt the VM
  - Set the disk cache mode to writethrough
  - I set my VMs up with UK keyboard layouts. You must also set the keymap in the VM configuration. I believe this should work with other combinations, provided the Libvirt keymap reflects the guest VM's, but I have not tested this yet.
- Move the virtual disk file to /mnt/images
- Set ownership to root:libvirt-qemu and chmod g+rw

### VM cloaking/obfuscation

#### BASIC CLOAKING
 After rewriting this section many times due to finding clues and scraps in many corners of the internet, I finally found a post which covers much of it in much better detail than I had written.
__BEFORE__ installing the OS:
- Edit your VM XML (virsh edit vmname) and do the following
  - In the main `<domain>` section add a new element 'sysinfo', and create entries with fake BIOS data; I have given an example below. The uuid value __must__ match the content of the main `<uuid>` tag at the top of your VM XML.
`<sysinfo type='smbios'>
  <bios>
    <entry name='vendor'>Phoenix</entry>
    <entry name='version'>1707</entry>
  </bios>
  <system>
    <entry name='manufacturer'>ACER</entry>
    <entry name='product'>Phoenix</entry>
    <entry name='version'>17.07</entry>
    <entry name='serial'>PH756011-L</entry>
    <entry name='uuid'>REPLACE\_ME</entry>
    <entry name='sku'>PHB-1707-R3</entry>
    <entry name='family'>PHB_BIOS</entry>
  </system>
  <baseBoard>
    <entry name='version'>ALASKA-1072009</entry>
  </baseBoard>
</sysinfo>`
  - Within `<features>`, add
`<kvm>
  <hidden state='on'/>
</kvm>`
  - Within `<cpu>`, specify `<feature policy='disable' name='hypervisor'/>`
  - In `<clock>`, change `<timer name='rtc' tickpolicy='catchup'/>` to `<timer name='rtc' track='wall'/>`
  - Add the following elements to `<os>`: 
    - `<loader readonly='yes' type='rom'>/usr/local/unsafehex/REPLACE\_ME/bios.bin</loader>` (replacing with your sandbox name)
    - `<smbios mode='sysinfo'/>`
  - Update the path to the disk file so it points to the new location in /mnt/images
  
#### ADVANCED CLOAKING
_this section to later be rewritten as part of the install script_
- Please start with the excellent [guide by D00m3dR4v3n](http://www.doomedraven.com/2016/05/kvm.html#why-cant-i-connect-to-a-local-uri-eg-qemusystem). Using the script for installing QEMU and SeaBios as a reference, [obtain the source code for QEMU](https://download.qemu.org/) - version 2.8.1 should be appropriate if you are using Debian Stretch.
- After unzipping, identify the files/values mentioned in qemu_func and replace as indicated in D00m3dR4v3n's script with the exception of the 'KVMKVMKVM' string - for this one, replace the value with "GenuineIntel" or "AuthenticAMD" (depending on what you have selected for your VM).
- I have not yet isolated the exact ./configure options required for this setup, but the following definitely works:
`./configure --enable-virtfs --enable-kvm --enable-vnc --enable-spice --enable-libnfs --enable-cap-ng --enable-libssh2 --enable-sdl --enable-gtk --enable-vte --enable-kvm --enable-bzip2 --enable-linux-user --enable-docs --enable-gnutls --enable-nettle --enable-modules --enable-curl --enable-fdt --enable-rdma --enable-uuid --enable-linux-aio --enable-attr --enable-vhost-net --enable-spice --enable-rbd --enable-libiscsi --enable-smartcard --enable-libusb --enable-usb-redir --enable-lzo --enable-snappy --enable-seccomp --enable-coroutine-pool --enable-tpm --enable-vhdx --enable-tcmalloc`
- Compile and install QEMU
- The instructions for configuring networking in his guide are also relevant, but optional

### Network, proxy, IDS config

- Install your guest OS and configure it with the correct network settings to match what was chosen when running install.sh
- Configure the main nginx reverse proxy to serve on the host's external IP. Fill in the `REPLACE_ME` sections with your external IP and sandbox name as applicable 
- I have included an example Suricata config and service file in the res/ directory. If you feel comfortable rolling your own, go ahead!
- Make sure that the file permissions for the eve.json output allow reading by all, OR that you manually change them once it is created.
- The install.sh script has already configured automatic updates of the Emerging Threats signature list which I find works pretty well - add more if you like though
- Start nginx

### Guest VM setup

- Register your VM in the database by running /usr/local/unsafehex/$SBXNAME/runmanager/register_vm.py
- Change the display type to VMVGA now that installation is done.
- I have collected some resources for preparing the VM, but for practical reasons (size) they are not within the git repository.
  - They can be download from their respective sources for free, though this can be very time consuming
  - They are available from https://dl.hexistentialist.com with a username and password I will provide on request, for convenience
- Copy the file to /usr/local/unsafehex/$SBXNAME/www/public/downloads.
- On the guest OS, navigate to http://your_gateway_ip:28082 and download the file `start_bundle.zip`
- Run the following installers in this order - IMPORTANT! Windows 7 can be a massive pain to update purely from Windows Update and MS' website. Doing things in this order will vastly reduce the headache.
  - `Windows6.1-KB3020369-x64.msu` (Prerequisite, April 2015 servicing stack update)
  - `Windows6.1-KB3172605-x64.msu` (Includes latest Windows Update client)
  - `windows6.1-kb3125574-v4-x64_2dafb1d203c8964239af3048b5dd4b1264cd93b9.msu` (May 2016 hotfix rollup)
  - `NDP462-KB3151800-x86-x64-AllOS-ENU.exe` (.NET Framework 4.6.2)
  - `EIE11_EN-US_MCM_WIN764.EXE` (IE 11)
- Please install sysmon with the config file provided, `Sysmon64.exe -i sysmon.xml`.
  - Newer versions of Sysmon support renaming the service and driver. This will not impact the operation of the sandbox - feel free to do this.
- I have included some vintage software to make it a nice and juicy target:
  - Flash Player 20.0.0.286
  - Java Runtime Environment v6
  - Adobe Reader 10.0
- Also included are some generic documents and a desktop background.
- The presence of Microsoft Office is assumed. You might see some odd behaviour if it is not installed; for instance, not being able to test any macro-laden documents.
- Currently I run the user interface and sandbox scripts in screen sessions and suggest the same for your testing
  - UI: from /usr/local/unsafehex/$SBXNAME/www/, run 'nodemon'
  - VM-facing API: /usr/local/unsafehex/$SBXNAME/api/, run 'nodemon'
  - sandbox manager: from /usr/local/unsafehex/$SBXNAME/runmanager/, run 'python3 runmanager.py runmanager.conf'
- Once the API is running you should run the 'TeaService Setup.msi' file from the resource directory mentioned above. This will register the VM with the manager and act as the agent which executes your suspect files.
- The sandbox executes malware by copying it to the destkop and double clicking it. It requires the position of the malware to be given. To obtain this, download the file MousePos.exe from the link given above, place it on the desktop and run it. Use this to provide the co-ordinates, then delete it from the desktop. Malware samples will appear in the same location and be double clicked by the sandbox.
- A snapshot in which the guest VM is paused is required. __DO NOT FORGET THIS!__
- It is __STRONGLY__ recommended that you also create an offline snapshot. Some situations can cause running snapshots to fail to restore to a clean state. The offline snapshot is your get-out-of-jail-free card for this situation.

### Final setup

- The sandbox is configured to start testing a sample by restoring the VM to the most recent snapshot and unpausing it, then controlling via VNC. When starting a sample you will need to not have the guest open in virt-manager or it will block the initial stages of the run
- Run /usr/local/unsafehex/$SBXNAME/runmanager/toron.sh as root to enable the tor service and tunnel the VM's internet traffic via tor. If you do not do this, all outbound connections should fail provided you set the virtual network up as isolated/host only.
- Test the connectivity if you wish; this is also a good stage to verify that Suricata is inspecting traffic and logging as expected
- Check that ClamAV is listening on port 9999
- Access the UI at https://yourhost/ and run some malware!

## Contact/help

You can contact me on twitter at @http_error_418 - I might respond faster there than on github.
