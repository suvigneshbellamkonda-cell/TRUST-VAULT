"""Checks on an uploaded file, before anything is stored."""
import io
import os
import re
import zipfile

MAX_BYTES = 10 * 1024 * 1024   # 10 MB per file
MAX_FILES = 10                 # files in one upload
MAX_BATCH_BYTES = 30 * 1024 * 1024   # all files in one upload together

# extension -> type we will serve it as. We never trust the type the
# browser claims.
ALLOWED_TYPES = {
    "pdf":  "application/pdf",
    "png":  "image/png",
    "jpg":  "image/jpeg",
    "jpeg": "image/jpeg",
    "txt":  "text/plain; charset=utf-8",
    "csv":  "text/plain; charset=utf-8",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


class UploadError(Exception):
    """The message is safe to show to the user."""


def _zip_has(data, folder):
    try:
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
    except zipfile.BadZipFile:
        return False
    return "[Content_Types].xml" in names and any(n.startswith(folder) for n in names)


def _content_matches(ext, data):
    """The first bytes of the file must really be the type its name claims."""
    if ext == "pdf":
        return data.startswith(b"%PDF-")
    if ext == "png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in ("jpg", "jpeg"):
        return data.startswith(b"\xff\xd8\xff")
    if ext == "docx":
        return _zip_has(data, "word/")
    if ext == "xlsx":
        return _zip_has(data, "xl/")
    if ext in ("txt", "csv"):
        if b"\x00" in data:
            return False
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True
    return False


def clean_filename(name, ext):
    """Keep only safe characters and drop any folder part (path traversal)."""
    base = name.replace("\\", "/").split("/")[-1]
    base = os.path.splitext(base)[0]
    base = re.sub(r"[^A-Za-z0-9._ -]", "_", base).strip(" .")[:80] or "file"
    return f"{base}.{ext}"


def check_upload(file_storage):
    """Return (clean_filename, mime_type, bytes) or raise UploadError."""
    if file_storage is None or not file_storage.filename:
        raise UploadError("Choose a file to upload.")

    original = file_storage.filename
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
    if ext not in ALLOWED_TYPES:
        raise UploadError("That file type is not allowed. Allowed: "
                          + ", ".join(sorted(ALLOWED_TYPES)) + ".")

    data = file_storage.stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise UploadError("That file is larger than 10 MB.")
    if not data:
        raise UploadError("That file is empty.")
    if not _content_matches(ext, data):
        raise UploadError("The file contents do not match its type (.%s)." % ext)

    return clean_filename(original, ext), ALLOWED_TYPES[ext], data