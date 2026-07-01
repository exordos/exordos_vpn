#    Copyright 2025 Genesis Corporation.
#
#    All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from pbincli.api import PrivateBin
from pbincli.format import Paste


class _MultiFilePaste(Paste):
    """Paste subclass that supports multiple file attachments.

    The parent class stores a single attachment as a string; this subclass
    stores them as lists, which serialise to a JSON array in the ciphertext —
    matching the protocol change proposed in PR #55.
    """

    def __init__(self, debug=False):
        super().__init__(debug)
        self._attachment = []
        self._attachment_name = []

    def addAttachment(self, name, data):
        from base64 import b64encode
        from mimetypes import guess_type

        mime = guess_type(name, strict=False)[0] or "application/octet-stream"
        self._attachment.append("data:" + mime + ";base64," + b64encode(data).decode())
        self._attachment_name.append(name)


def create_paste(
    server,
    files=None,
    text="",
    password="",
    expiration="1week",
    formatter="markdown",
    burn=False,
    discussion=False,
    compression="zlib",
    settings=None,
):
    """Create a paste, optionally with one or more file attachments.

    Args:
        server:      PrivateBin instance URL, e.g. "https://privatebin.net/"
        files:       list of (filename, bytes) tuples to attach (optional)
        text:        paste text body (optional when files is set)
        password:    extra password to protect the paste (optional)
        expiration:  "5min","10min","1hour","1day","1week","1month","1year","never"
        formatter:   "plaintext", "markdown", "syntaxhighlighting"
        burn:        delete after first read
        discussion:  allow comments
        compression: "zlib" or "none"
        settings:    extra PrivateBin settings dict (proxy, auth, etc.)

    Returns:
        dict with keys: id, passphrase, delete_token, url, delete_url

    Raises:
        ValueError: when neither text nor files is given, or on API error
    """
    if not text and not files:
        raise ValueError("Provide at least text or files")

    cfg = {"server": server}
    if settings:
        cfg.update(settings)

    api = PrivateBin(cfg)

    paste = _MultiFilePaste()
    paste.setVersion(api.getVersion())
    paste.setCompression(compression)
    paste.setText(text)

    if password:
        paste.setPassword(password)

    if files:
        for name, data in files:
            paste.addAttachment(name, data)

    paste.encrypt(
        formatter=formatter,
        burnafterreading=burn,
        discussion=discussion,
        expiration=expiration,
    )

    result = api.post(paste.getJSON())

    if result.get("status"):
        raise ValueError("Server error: {}".format(result.get("message", "unknown")))

    paste_id = result["id"]
    passphrase = paste.getHash()

    return {
        "id": paste_id,
        "passphrase": passphrase,
        "delete_token": result["deletetoken"],
        "url": "{}?{}#{}".format(server.rstrip("/"), paste_id, passphrase),
        "delete_url": "{}?pasteid={}&deletetoken={}".format(
            server.rstrip("/"), paste_id, result["deletetoken"]
        ),
    }
