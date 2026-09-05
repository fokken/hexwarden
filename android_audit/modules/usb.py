CATEGORY = 'interfaces'

def run(c):
    c.shell('dumpsys usb', 'usb')
    for key in ('sys.usb.config', 'sys.usb.state', 'persist.sys.usb.config'):
        c.prop(key)
    c.shell('ls -lZ /sys/bus/usb/devices', 'usb_devices')
    c.shell('for d in /sys/bus/usb/devices/*; do for a in idVendor idProduct bDeviceClass bInterfaceClass product manufacturer; do if [ -r "$d/$a" ]; then echo "$d/$a"; cat "$d/$a"; fi; done; done', 'usb_classes')
    c.shell('cat /proc/bus/input/devices', 'input_devices')
    c.shell('cat /proc/partitions', 'storage')
    c.note('USB class evidence covers attached interfaces (03 HID, 08 storage, 02 communications, 0a CDC data, e0 wireless controller). Acceptance of new device types requires physical test devices; no HID injection is performed.')
