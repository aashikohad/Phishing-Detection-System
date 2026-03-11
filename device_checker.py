known_devices = {
    1: ["android-SM_G991B-8f3a92d1", "macbook-pro-M1-7A91BC23"]
}


def check_device(user_id, device_id):

    if user_id in known_devices:

        if device_id in known_devices[user_id]:
            return 0.2, False

    return 0.7, True