from database import device_exists, add_device


def check_device(user_id, device_id):

    # If device already known → low risk
    if device_exists(user_id, device_id):
        return 0.2, False

    # If new device → store it
    add_device(user_id, device_id)

    return 0.7, True