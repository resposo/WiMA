
import struct
import re
from datetime import datetime


def convert_filetime_to_unix_epoch(filetime):
    EPOCH_AS_FILETIME = 116444736000000000
    HUNDREDS_OF_NANOSECONDS = 10000000

    if filetime == 0:
        return "N/A"

    unix_time = (filetime - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS
    try:
        return datetime.utcfromtimestamp(unix_time)
    except (OSError, ValueError):
        return "N/A"

def read_and_find_image_filename(file_path):
    # 기존 패턴 및 eprocess 서명 패턴
    pattern = re.compile(b'\x02\x50\x72\x6F\x63.{8}')  # 기존 패턴
    eprocess_signature = re.compile(b'\x03\x00\x00\x00.{1}\x00\x00\x00.{8}')  # eprocess 서명

    # eprocess 구조체의 각 필드 오프셋
    pid_offset = 0x440
    pid_length = 8

    active_process_links_offset = 0x448 - 3
    active_process_links_length = 16

    create_time_offset = 0x468 - 3
    create_time_length = 8

    inherited_from_unique_process_id_offset = 0x540 - 3
    inherited_from_unique_process_id_length = 8

    image_file_name_offset = 0x5A8
    image_file_name_length = 15  # 정확한 크기

    exit_time_offset = 0x840 - 3
    exit_time_length = 8

    try:
        with open(file_path, "rb") as file:
            content = file.read()
    except FileNotFoundError:
        print("파일이 존재하지 않음.")
        return
    except Exception as e:
        print(f"파일을 읽는 도중 오류가 발생: {e}")
        return

    index = 0
    while True:
        match = pattern.search(content, index)
        if not match:
            break

        index = match.start()
        block_size_byte = content[index - 1] if index >= 1 else None
        if block_size_byte is None:
            print("블록 사이즈를 읽을 수 없음")
            break

        if block_size_byte == 0xE8:
            eprocess_offset = 0x80
        elif block_size_byte == 0xE0:
            eprocess_offset = 0x40
        elif block_size_byte == 0xD0:
            eprocess_offset = 0x80
        elif block_size_byte == 0xD8:
            eprocess_offset = 0x40    
        elif block_size_byte == 0xC8 :
            eprocess_offset = 0x70
        else:
            index += 1
            continue

        base_index = index + eprocess_offset
        pid_index = base_index + pid_offset
        active_process_links_index = base_index + active_process_links_offset
        create_time_index = base_index + create_time_offset
        inherited_from_unique_process_id_index = base_index + inherited_from_unique_process_id_offset

        image_file_name_index = base_index + image_file_name_offset
        exit_time_index = base_index + exit_time_offset

        if exit_time_index + exit_time_length > len(content):
            print(f"파일이 너무 짧아 {hex(index)} 위치에서 PID 또는 ImageFileName 데이터를 가져올 수 없음.")
            index += 1
            continue

        # 필드 값을 추출
        pid = struct.unpack('<Q', content[pid_index:pid_index + pid_length])[0]
        active_process_links = struct.unpack('<QQ', content[active_process_links_index:active_process_links_index + active_process_links_length])
        create_time_bytes = content[create_time_index:create_time_index + create_time_length]
        exit_time_bytes = content[exit_time_index:exit_time_index + exit_time_length]
        inherited_from_unique_process_id = struct.unpack('<Q', content[inherited_from_unique_process_id_index:inherited_from_unique_process_id_index + inherited_from_unique_process_id_length])[0]

        # 바이너리 데이터를 역순으로 변환
        create_time_filetime = int.from_bytes(create_time_bytes[::-1], byteorder='big')
        exit_time_filetime = int.from_bytes(exit_time_bytes[::-1], byteorder='big')

        # FILETIME을 Unix 시간으로 변환
        create_time_unix = convert_filetime_to_unix_epoch(create_time_filetime)
        exit_time_unix = convert_filetime_to_unix_epoch(exit_time_filetime)

        # PID가 0 또는 4294967295 이상인 경우 eprocess_signature를 통해 시작 지점을 재탐색
        if pid == 0 or pid > 4294967295:
            signature_index = index
            while signature_index < len(content):
                signature_match = eprocess_signature.search(content, signature_index)
                if not signature_match:
                    signature_index += 16  # 16바이트씩 이동
                    continue

                new_base_index = signature_match.start()
                pid_index = new_base_index + pid_offset
                image_file_name_index = new_base_index + image_file_name_offset
                create_time_index = new_base_index + create_time_offset
                exit_time_index = new_base_index + exit_time_offset
                pid = struct.unpack('<Q', content[pid_index:pid_index + pid_length])[0]

                # 유효한 PID 확인
                if 0 < pid <= 4294967295:
                    break
                else:
                    signature_index += 16

            if signature_index >= len(content) or not signature_match:
                print(f"유효한 eprocess_signature를 찾을 수 없음: {hex(base_index)}")
                index += 1
                continue

        # ImageFileName 필드 값을 추출
        image_file_name_data = content[image_file_name_index:image_file_name_index + image_file_name_length]
        image_file_name = image_file_name_data.split(b'\x00', 1)[0].decode('ascii', errors='ignore')

        # DKOM 탐지
        dkom_detect = "*******DKOM DETECT!*******" if active_process_links[0] == active_process_links[1] else ""

        # 결과 출력
        print(f"Pool_header offset {hex(index)}, PID: {pid}, ImageFileName: {image_file_name}")
        print(f"  PID: {pid} (Offset: {hex(pid_index)})")
        print(f"  InheritedFromUniqueProcessId: {inherited_from_unique_process_id} (Offset: {hex(inherited_from_unique_process_id_index)})")
        print(f"  ActiveProcessLinks: {hex(active_process_links[0])}, {hex(active_process_links[1])} (Offset: {hex(active_process_links_index)}) {dkom_detect}")
        print(f"  CreateTime: {create_time_unix} (Offset: {hex(create_time_index)})")
        print(f"  ExitTime: {exit_time_unix} (Offset: {hex(exit_time_index)})")
        print("*"*100)

        index += 1  # 무한 루프를 피하기 위해 인덱스를 1만큼 증가

file_path = input("메모리 덤프파일: ")
read_and_find_image_filename(file_path)
