import base64
import json
import pprint
import zlib
from enum import Enum

import biplist
from blackboxprotobuf import decode_message

from mitmproxy.contentviews._api import Contentview, Metadata


class MagicEnum(Enum):
    BPLIST = '020000'
    SEQUENCE_NUMBER = '030000'


class ACERecording:
    def __init__(self, frames):
        self.frames = frames
    
    @staticmethod
    def _resolve_context(frame):
        result = frame.copy()
        if 'context' in result:
            result['context'] = json.loads(result['context'])
            if 'conversationStateAttachments' in result['context']:
                attachments = []
                for attachment in result['context']['conversationStateAttachments']:
                    if 'base64EncodedIntent' in attachment:
                        attachment['base64EncodedIntent'] = decode_message(base64.b64decode(attachment['base64EncodedIntent']))
                    if 'stepResults' in attachment:
                        for stepResult in attachment['stepResults']:
                            if 'base64EncodedProtobufMessage' in stepResult:
                                stepResult['base64EncodedProtobufMessage'] = decode_message(base64.b64decode(stepResult['base64EncodedProtobufMessage']))
                    attachments.append(attachment)
                result['context']['conversationStateAttachments'] = attachments
        return result

    @classmethod
    def parse(cls, content):
        index = 0
        results = []
        while index < len(content):
            signature = content[index:index+3]
            if signature.hex() == MagicEnum.BPLIST.value:
                size = int.from_bytes(content[index+3:index+5], byteorder='big')
                frame = content[index+5:index+5+size]
                parsed_frame = biplist.readPlistFromString(frame)
                if '$class' in parsed_frame and parsed_frame['$class'] in ('ProvideContext', 'SpokenNotificationProvideContext'):
                    resolved_frame = cls._resolve_context(parsed_frame)
                    results.append(resolved_frame)
                else:
                    results.append(parsed_frame)
                index += 5 + size
            elif signature.hex() == MagicEnum.SEQUENCE_NUMBER.value:
                sequence_number = int.from_bytes(content[index+3:index+5], byteorder='big')
                results.append({'Sequence Number': sequence_number})
                index += 5
            else:
                results.append({'unknown_signature': signature})
                index += 3
        return cls(results)
    
    @classmethod
    def parse_ace(cls, hex_content):
        signature = hex_content[:4]
        if signature == b'\xaa\xcc\xee\x02':
            zlib_decoder = zlib.decompressobj()
            decompressed_data = zlib_decoder.decompress(hex_content[4:])
            return cls.parse(decompressed_data)
        else:
            raise ValueError(f"Unknown signature: {signature}")



class ACEContentview(Contentview):
    syntax_highlight = "yaml"

    def prettify(self, data: bytes, metadata: Metadata) -> str:
        return pprint.pformat(ACERecording.parse_ace(data).frames)

    def render_priority(self, data: bytes, metadata: Metadata) -> float:
        if metadata.http_message.method == "ACE":
            return 1
        return 0


ace_view = ACEContentview()
