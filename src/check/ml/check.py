# duration is in seconds
def ml_check_packet(
    proto: str, flag: str, service: str, duration: int, src_bytes: int, dst_bytes: int
):
    # TODO: add the actual ML checks
    print(
        f"Checking connection proto {proto}, flag {flag}, service {service}, duration {duration}, src_bytes {src_bytes}, dst_bytes {dst_bytes}"
    )
