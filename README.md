# ICQ-New-Explorer
ICQ Explorer - turns an ICQ New profile folder (...\ICQ\0001) into ONE self-contained HTML file: all conversations, avatars, global search, date jump, export.

Made entirely by Anthropic's Claude AI with my help. Not affiliated with ICQ or VK/Mail.ru
Requires Python. Only tested on Windows, may NOT work on other systems

Usage:
    python icq_explorer.py                      (folder picker: choose ...\ICQ\0001)
    python icq_explorer.py "C:\\...\\ICQ\\0001"
    python icq_explorer.py path\\to\\_db6        (a single conversation)
Options:  --my-uin 123456789   --out file.html   --no-open
