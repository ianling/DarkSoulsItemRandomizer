import struct
import sys

def consume_byte(content, offset, byte, length=1):
    """Consume length bytes from content, starting at offset. If they
     are not all byte, raises a ValueError.
    """
    
    for i in range(length-1):
        if content[offset + i:offset + i+1] != byte:
            raise ValueError(("Expected byte '0x%s' at offset " + 
             "0x%x but received byte '0x%s'.") % (byte.hex(), offset+i, 
             content[offset + i:offset + i+1].hex()))
    return offset + length
       
def extract_strz(content, offset):
    extracted = b''
    while content[offset:offset+1] != b'\x00':
        extracted = extracted + content[offset:offset+1]
        offset += 1
    # return extracted.decode('utf-8')
    return extracted.decode('cp932')  # SHIFT-JIS
    
def appears_bnd(content):
    """Checks if the magic bytes at the start of content indicate that it
    is a BND3-packed file.
    """
    return content[0:4] == "BND3"

def unpack_bnd(content):
    """Unpacks the *bnd file content from a BND3-packed file.
    
    Returns a list of triples (file_id, filepath, filedata)
    """
       
    master_offset = 0
    master_offset = consume_byte(content, master_offset, b'B', 1)
    master_offset = consume_byte(content, master_offset, b'N', 1)
    master_offset = consume_byte(content, master_offset, b'D', 1)
    master_offset = consume_byte(content, master_offset, b'3', 1)
    
    # Skip the version number.
    master_offset = 0x0c
    (magic_flag, num_of_records, filename_end_offset) = struct.unpack_from("<III", content, offset=master_offset)
    master_offset += struct.calcsize("<III")
    if not (magic_flag == 0x74 or magic_flag == 0x54 or magic_flag == 0x70 or magic_flag == 0x78 or magic_flag == 0x7c or magic_flag == 0x5c):
        raise ValueError("File has unknown BND3 magic flag: " + hex(magic_flag))
    # Nintendo Switch files are handled in a special way.
    is_nintendo_switch = (magic_flag == 0x7c or magic_flag == 0x5c)
    
    # Skip to the records.
    master_offset = 0x20

    return_list = []
    for _ in range(num_of_records):
        if magic_flag == 0x74 or magic_flag == 0x54:
            (record_sep, filedata_size, filedata_offset, file_id, 
             filename_offset, dummy_filedata_size) = struct.unpack_from("<IIIIII", content, offset=master_offset)
            master_offset += struct.calcsize("<IIIIII")
            if filedata_size != dummy_filedata_size:
                raise ValueError("File has malformed record structure. File data size " + 
                 str(filedata_size) + " does not match dummy file data size " + 
                 str(dummy_filedata_size) + ".")
        elif is_nintendo_switch:
            # Everything is the same, except filedata_offset is 64-bit instead of 32-bit
            (record_sep, filedata_size, filedata_offset, file_id, 
             filename_offset, dummy_filedata_size) = struct.unpack_from("<IIQIII", content, offset=master_offset)
            master_offset += struct.calcsize("<IIQIII")
        else: # magic_flag == 0x70 or magic_flag == 0x78
            (record_sep, filedata_size, filedata_offset, file_id, 
             filename_offset) = struct.unpack_from("<IIIII", content, offset=master_offset)
            master_offset += struct.calcsize("<IIIII")
        
        if record_sep != 0x40:
            raise ValueError("File has malformed record structure. Record" + 
            " has unknown record separator " + hex(record_sep))
            
        filename = extract_strz(content, filename_offset)
        filedata = content[filedata_offset:filedata_offset + filedata_size]
        
        return_list.append((file_id, filename, filedata))
            
    return return_list
    
def offset_to_next_multiple(num, mult):
    """Calculates the amount needed to round num upward to the next multiple of mult. 
    If num is divisible by mult, then this returns 0, not mult.
    """
    
    if mult == 0:
        return 0
    else:
        offset = mult - (num % mult)
        if offset == mult:
            offset = 0
        return offset
    
def repack_bnd(content_list, nintendo_switch_format=False):
    """Packs a list of data triples of the format (file_id, filepath, filedata)
    into a BND3 archive file content.
    
    The exact format matches the GameParam.parambnd format specifically.
    """
    
    RECORD_SEP = 0x40
    HEADER_SIZE = 0x20
    
    if nintendo_switch_format:
        RECORD_SIZE = 0x1c
        magic_flag = 0x7c
        packed_record_format = "<IIQIII"
    else:
        RECORD_SIZE = 0x18
        magic_flag = 0x74
        packed_record_format = "<IIIIII"

    num_of_records = len(content_list)
    
    # Compute total size taken up by all filenames, including the null-termination byte.
    total_filedata_size = sum([len(entry[1]) + 1 for entry in content_list])
    
    filename_offset = HEADER_SIZE + RECORD_SIZE * num_of_records
    filename_end_offset = filename_offset + total_filedata_size
    filedata_offset = filename_end_offset
    
    HEADER = b"BND307D7R6\x00\x00" + struct.pack("<IIIII", magic_flag, num_of_records, filename_end_offset, 0, 0)
    
    packed_records = b''
    packed_filenames = b''
    packed_filedata = b''
    
    for (file_id, filepath, filedata) in content_list:
        # Pad each filedata to the nearest multiple of 16, to match the
        #  format of the original file.
        size_of_pad = offset_to_next_multiple(filedata_offset, 16)
        packed_filedata += b"\x00" * size_of_pad
        filedata_offset += size_of_pad
        
        packed_records += struct.pack(packed_record_format, RECORD_SEP, len(filedata), 
         filedata_offset, file_id, filename_offset, len(filedata))
        # packed_filenames += filepath.encode('utf-8') + b"\x00"
        packed_filenames += filepath.encode('cp932') + b"\x00"
        filename_offset += len(filepath) + 1
        packed_filedata += filedata
        filedata_offset += len(filedata)
    return HEADER + packed_records + packed_filenames + packed_filedata


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: " + str(sys.argv[0]) + "<BND File>")
    else:
        filename = sys.argv[1]
        with open(filename, "rb") as f:
            file_content = f.read()
            contents = unpack_bnd(file_content)
            repack_bnd(contents, True)


