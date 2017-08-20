# Hello, guinea pigs

Thank you for helping me to test my sandbox. Currently this has only been tested with 64-bit Debian Jessie, and a guest VM OS of Windows 7 SP 1 x86-64; if you want to adapt it to anything else you are welcome to try but I make no guarantees!

At this stage I have not chosen a license. Please do not distribute code that is © myself at this time.

## CREDITS
Much of this process was only possible with the help of Sean Whalen's Cuckoo sandbox guide. 

I have borrowed heavily from it and these instructions will refer to it in a number of cases rather than reproduce the content here.

Please find it at https://infosecspeakeasy.org/t/howto-build-a-cuckoo-sandbox/27/1

SwiftOnSecurity's Decent Security advice for updating Windows and Sysmon config were also invaluable

Far too many web guides and IRC channels to list individually

## INSTALLATION

If you are installing this system into a VM, give the VM at least two processors, and enable hardware assisted virtualization.

To install, perform the steps below:

- Clone this repository to your sandbox host and execute the *install.sh* script as root.
- The script requires access to the internet via HTTP, HTTPS, and git (TCP 9418). Please ensure this access is available before running the installer.
- Run install.sh and enter the desired parameters. Installation involves compiling libvirt and Suricata from source, and generating Diffie-Hellman parameters. Go play outside for a bit.

At the minute my script is hard coded to expect 192.168.43.0/24 so please use that; I will make this dynamic later.

## SETUP

### Libvirt/guest VMs

- Check libvirtd is running and the libvirt socket files at /usr/local/var/run/libvirt/ have ownership of root:libvirt-qemu.
- If they do not, contact me and I can provide the steps to make sure this is fixed
- Start virt-manager. The script should remove the virtual network 'default' and create a new one 'vneta' with gateway IP of 192.168.43.1, if this has not happened do it via virt-manager
- Create a new virtual machine - recommend at least 2 CPUs and 2GB RAM
- __MAKE SURE__ to customise the VM before install:
  - Change the display type to VNC
  - Change the Video type to VMVGA
  - Save the config and halt the VM
- Move the virtual disk file to /mnt/images
- Set ownership to root:libvirt-qemu and chmod g+rw

### VM cloaking/obfuscation

- Edit your VM XML (virsh edit vmname) and do the following
  - Within `<features>`, add `<kvm><hidden state='on'/></kvm>`
  - Within `<cpu>`, specify `<feature policy='disable' name='hypervisor'/>`
  - In `<clock>`, change `<timer name='rtc' tickpolicy='catchup'/>` to `<timer name='rtc' track='wall'/>`
  - Add the following elements to `<os>`: 
    - `<loader readonly='yes' type='rom'>/usr/local/unsafehex/REPLACE\_ME/bios.bin</loader>` (replacing with your sandbox name)
    - `<smbios mode='sysinfo'/>`
  - Update the path to the disk file so it points to the new location in /mnt/images
- Save the XML and go back to virt-manager;

### Network, proxy, IDS config

- Install your guest OS and configure it with a static IP address in the 192.168.43.0/24 range, with 192.168.43.1 as the gateway
- Configure the main nginx reverse proxy to serve on the host's external IP. Fill in the `REPLACE_ME` sections with your external IP and sandbox name as applicable
- Set Suricata up using the Cuckoo guide (unless you are comfortable enough to roll your own!)
- The install.sh script has already configured automatic updates of the Emerging Threats signature list which I find works pretty well - add more if you like though
- Start nginx

### Guest VM setup

- Please configure the display resolution at 1680x1050. I appreciate this might be awkward on screens smaller than 1980x1200; I have not yet looked at how to adapt to different resolutions.
- I have collected some resources for preparing the VM, but for practical reasons they are not within the git repository.
- Please download them from https://dl.hexistentialist.com with the username/password I have provided to you
- Copy the file to /usr/local/unsafehex/$SBXNAME/www/$SBXNAME/public/downloads
- On the guest OS, navigate to http://192.168.43.1:8080 and download the file `start_bundle.zip`
- Run the following installers in this order - IMPORTANT! Windows 7 can be a massive pain to update purely from Windows Update and MS' website. Doing things in this order will vastly reduce the headache.
  - `Windows6.1-KB3020369-x64.msu` (Prerequisite, April 2015 servicing stack update)
  - `Windows6.1-KB3172605-x64.msu` (Includes latest Windows Update client)
  - `windows6.1-kb3125574-v4-x64_2dafb1d203c8964239af3048b5dd4b1264cd93b9.msu` (May 2016 hotfix rollup)
  - `NDP462-KB3151800-x86-x64-AllOS-ENU.exe` (.NET Framework 4.6.2)
  - `EIE11_EN-US_MCM_WIN764.EXE` (IE 11)
- Please install sysmon with the config file provided, `sysmon.exe -i sysmon.xml`
- Place the run.ps1 script in C:\Program Files\
- I have included some vintage software to make it a nice and juicy target:
  - Flash Player 20.0.0.286
  - Java Runtime Environment v6
  - Adobe Reader 10.0
- Also included are some generic documents and a desktop background
- The presence of Microsoft Office is assumed. Please configure it to automatically run macros.
- Pause the guest VM and create a snapshot. __DO NOT FORGET THIS!__

### Final setup

- The sandbox is configured to start testing a sample by restoring the VM to the most recent snapshot and unpausing it, then controlling via VNC. When starting a sample you will need to not have the guest open in virt-manager or it will block the initial stages of the run
- Add your VM to the database with `/usr/local/unsafehex/$SBXNAME/runmanager/register_vm.py`
- Run /usr/local/unsafehex/$SBXNAME/runmanager/toron.sh as root to enable the tor service and tunnel the VM's internet traffic via tor. If you do not do this, all outbound connections should fail provided you set the virtual network up as isolated/host only.
- Test the connectivity if you wish; this is also a good stage to verify that Suricata is inspecting traffic and logging as expected
- Check that ClamAV is listening on port 9999
- Currently I run the user interface and sandbox scripts in screen sessions and suggest the same for your testing
  - UI: from /usr/local/unsafehex/$SBXNAME/www/$SBXNAME/, run 'nodemon bin/www start'
  - sandbox manager: from /usr/local/unsafehex/$SBXNAME/runmanager/, run 'python runmanager.py runmanager.conf'
- Access the UI at https://yourhost/ and run some malware!

## Contact/help

Everyone reading this right now has at least one method of contacting me, but you can also use `http_error_418@unsafehex.com`
