"""
Copyright 2024, CCL Forensics

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

# See: https://sqlite.org/jsonb.html

from typing import Optional, Union, Tuple
import struct
import enum

__version__ = "0.2"
__description__ = "Module for reading the SQLite 'jsonb' binary JSON format."
__contact__ = "Alex Caithness"


# NB TextJ and Text5 values are not currently supported. There is code in this source that most likely works but at the
# moment they raise a NotImplementedError as I haven't been able to generate test data to check. I currently believe
# that those record types are only used internally and Text/TextRaw are used for serialization.

class JsonbType(enum.IntEnum):
    Null = 0x0
    Bool_True = 0x1
    Bool_False = 0x2
    Int = 0x3
    Int5 = 0x4
    Float = 0x5
    Float5 = 0x6
    Text = 0x7
    TextJ = 0x8  # NB Not supported currently as I cannot generate test data - the code is probably fine though.
    Text5 = 0x9  # NB Not supported currently as I cannot generate test data - the code is probably fine though.
    TextRaw = 0xA
    Array = 0xB
    Object = 0xC
    RESERVED_13 = 0xD
    RESERVED_14 = 0xE
    RESERVED_15 = 0xF


def _read_jsonb(jsonb_data: bytes) -> Tuple[Optional[Union[bool, int, float, str, dict, list]], int]:
    if len(jsonb_data) == 0:
        raise ValueError("Input buffer is empty")
    size = (jsonb_data[0] & 0xf0) >> 4
    json_type = JsonbType(jsonb_data[0] & 0x0f)

    if size <= 11:
        data_start_offset = 1
    elif size == 12:
        size = jsonb_data[1]
        data_start_offset = 2
    elif size == 13:
        size, = struct.unpack(">H", jsonb_data[1:3])
        data_start_offset = 3
    elif size == 14:
        size, = struct.unpack(">I", jsonb_data[1:5])
        data_start_offset = 5
    elif size == 15:
        size, = struct.unpack(">Q", jsonb_data[1:9])
        data_start_offset = 9
    else:
        raise ValueError("Unexpected size value")  # should be impossible because of maths

    if json_type == JsonbType.Null:
        if size != 0:
            raise ValueError("Null with non-zero size")
        result = None
    elif json_type == JsonbType.Bool_True:
        if size != 0:
            raise ValueError("Bool with non-zero size")
        result = True
    elif json_type == JsonbType.Bool_False:
        if size != 0:
            raise ValueError("Bool with non-zero size")
        result = False
    elif json_type == JsonbType.Int:
        result = int(jsonb_data[data_start_offset:data_start_offset + size].decode("ascii"))
    elif json_type == JsonbType.Int5:
        if jsonb_data[data_start_offset:data_start_offset + 2] == b"0x":
            result = int(jsonb_data[data_start_offset + 2: data_start_offset + size].decode("ascii"), 16)
        else:
            result = int(jsonb_data[data_start_offset:data_start_offset + size].decode("ascii"))
    elif json_type in (JsonbType.Float, JsonbType.Float5):
        result = float(jsonb_data[data_start_offset:data_start_offset + size].decode("ascii"))
    elif json_type in (JsonbType.Text, JsonbType.TextRaw):
        result = jsonb_data[data_start_offset:data_start_offset + size].decode("utf-8")
    elif json_type == JsonbType.TextJ:
        raise NotImplementedError("TextJ records not currently supported - see comments in code")
        raw_string = jsonb_data[data_start_offset:data_start_offset + size].decode('utf-8')
        result = json.loads(f"\"{raw_string}\"")
    elif json_type == JsonbType.Text5:
        raise NotImplementedError("Text5 records not currently supported - see comments in code")
        # this is incomplete, there are escape rules that JSON5 allows that aren't accounted for here
        # however I am unconvinced that these TextJ and Text5 actually get serialized at the moment as
        # I've been unable to generate a test case where they are.
        # This should raise a json.decoder.JSONDecodeError on encountering an un-handled escape sequence.
        raw_string = jsonb_data[data_start_offset:data_start_offset + size].decode('utf-8')
        raw_string = raw_string.replace("\\\n", "\\n")
        result = json.loads(f"\"{raw_string}\"")
    elif json_type == JsonbType.Array:
        result = []
        inner_data = jsonb_data[data_start_offset:data_start_offset + size]
        bytes_consumed = 0
        while bytes_consumed < size:
            element, element_size = _read_jsonb(inner_data[bytes_consumed:])
            result.append(element)
            bytes_consumed += element_size
    elif json_type == JsonbType.Object:
        result = {}
        inner_data = jsonb_data[data_start_offset:data_start_offset + size]
        bytes_consumed = 0
        while bytes_consumed < size:
            key, key_size = _read_jsonb(inner_data[bytes_consumed:])
            bytes_consumed += key_size
            if bytes_consumed >= size:
                raise ValueError("Ran out of data while reading an object (no more space to read property value)")

            value, value_size = _read_jsonb(inner_data[bytes_consumed:])
            if key in result:
                raise KeyError(f"Key already in object: {key}")
            bytes_consumed += value_size

            result[key] = value
    else:
        raise ValueError(f"Unexpected json type: {JsonbType.name}")

    return result, data_start_offset + size


def read_jsonb(jsonb_data: bytes) -> Optional[Union[bool, int, float, str, dict, list]]:
    return _read_jsonb(jsonb_data)[0]


if __name__ == '__main__':
    import sys
    import pathlib
    import json

    if len(sys.argv) < 2:
        print(f"USAGE: {pathlib.Path(sys.argv[0])} <in data path>")
        exit(1)
    in_path = pathlib.Path(sys.argv[1])
    with in_path.open("rb") as f:
        buff = f.read()

    print(json.dumps(read_jsonb(buff)))
