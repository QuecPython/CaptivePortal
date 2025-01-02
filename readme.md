# CaptivePortal lib for QuecPython

## Overview

**Captive Portal** is a network access control mechanism commonly used in public Wi-Fi networks. When users connect to a network requiring authentication, they are automatically redirected to a webpage where they must enter a username and password or accept the terms of use. In addition to authentication, Captive Portals can also be used for displaying advertisements, informing users of network usage policies, and more.

Integrating **Captive Portal functionality into a USB dongle** allows you to manage devices connected to your network more conveniently and provide a personalized network experience. This feature can enhance security, enable user interaction through customized portals, and facilitate the deployment of network usage policies, advertisements, or service announcements.

**QuecPython** provides an implementation of the Captive Portal technology, allowing users to specify the webpage they want the Captive Portal to redirect to. This enables users to implement their own network management strategies effectively.

## Example

For demonstration purposes, this example specifies **https://python.quectel.com** as the target page for Captive Portal redirection.

```python
# Example
if __name__ == "__main__":
    # Windows: Type_RNDIS
    # Linux/Android/IOS: Type_ECM
    if (USBNET.get_worktype() != USBNET.Type_RNDIS):
        USBNET.set_worktype(USBNET.Type_RNDIS)
        Power.powerRestart()
    
    portal = CaptivePortal(
        target_url="https://python.quectel.com/",
        dns_whitelist=["www.python.quectel.com", "python.quectel.com"]
    )
    portal.start()
    
    cnt = 0
    while True:
        utime.sleep(1)
        ret = USBNET.open()
        cnt = cnt + 1
        if ret == 0:
            print("USBNET status: ",USBNET.get_status())
            print("USBNET type: ",USBNET.get_worktype())
            break
        if cnt == 60:
            print("USBNET open fail!")
            portal.stop()
            break
```
