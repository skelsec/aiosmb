import re
from typing import Optional, Tuple

pattern = re.compile(
    r'^(?P<basename>.+)\@(?P<gmt>GMT-\d{4}\.\d{2}\.\d{2}-\d{2}\.\d{2}\.\d{2})$'
)

def tssplit(path: str) -> Tuple[str, Optional[str]]:
    filename = path
    vstimestamp = None
    match = pattern.match(path)
    if match:
        filename = match.group('basename')
        vstimestamp = match.group('gmt')
        vstimestamp = vstimestamp.replace('GMT-', '@GMT-')
    return filename, vstimestamp