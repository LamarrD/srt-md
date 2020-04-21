"""
Creates readable text file from SRT file.
"""
import re, sys
import os
import glob


# Modified from https://gist.github.com/ndunn219/62263ce1fb59fda08656be7369ce329b


def is_time_stamp(l):
    if l[:2].isnumeric() and l[2] == ":":
        return True
    return False


def has_letters(line):
    if re.search("[a-zA-Z]", line):
        return True
    return False


def has_no_text(line):
    l = line.strip()
    if not len(l):
        return True
    if l.isnumeric():
        return True
    if is_time_stamp(l):
        return True
    if l[0] == "(" and l[-1] == ")":
        return True
    if not has_letters(line):
        return True
    return False


def is_lowercase_letter_or_comma(letter):
    if letter.isalpha() and letter.lower() == letter:
        return True
    if letter == ",":
        return True
    return False


def clean_up(lines):
    """
  Get rid of all non-text lines and
  try to combine text broken into multiple lines
  """
    new_lines = []
    for line in lines[1:]:
        if has_no_text(line):
            continue
        elif len(new_lines) and is_lowercase_letter_or_comma(line[0]):
            # combine with previous line
            new_lines[-1] = new_lines[-1].strip() + " " + line
        else:
            # append line
            new_lines.append(line)
    return new_lines


def main(args):
    file_encoding = "utf-8" if len(args) < 3 else args[2]
    output_file = open("Notes.md", "w")
    for root, dirs, files in os.walk("data"):
        for dir in sorted(dirs):
            output_file.write(f"## {dir}\n\n")
            for c_root, c_dirs, c_files in os.walk(f"data/{dir}"):
                for file_name in sorted(c_files):
                    with open(
                        f"data/{dir}/{file_name}",
                        encoding=file_encoding,
                        errors="replace",
                    ) as f:
                        file_heading = file_name.split("-")[1].strip()
                        output_file.write(f"### {file_heading}\n")
                        lines = f.readlines()
                        new_lines = clean_up(lines)
                        output_file.writelines(new_lines)
            output_file.write("\n---\n")
            output_file.write("&nbsp; \pagebreak\n")


if __name__ == "__main__":
    main(sys.argv)
