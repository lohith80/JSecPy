# file_io.py

from pathlib import Path

def read_file(file_path: Path) -> str:
    """
    Reads the content of a file and returns it as a string.

    :param file_path: The path of the file to read
    :return: The content of the file as a string
    """
    with file_path.open("r") as file:
        content = file.read()
    return content

def write_file(file_path: Path, content: str) -> None:
    """
    Writes the given content to a file.

    :param file_path: The path of the file to write
    :param content: The content to write to the file
    """
    with file_path.open("w") as file:
        file.write(content)
